//! Triage policy and exclusion types used by the event matching engine.

use std::{
    cmp::Ordering,
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::{BitAnd, RangeInclusive},
};

use anyhow::{Result, anyhow};
use attrievent::attribute::RawEventKind;
use chrono::{DateTime, Utc};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::types::{EventCategory, HostNetworkGroup};

const IP_V4_MAX_PREFIX_LEN: u8 = 32;
const IP_V6_MAX_PREFIX_LEN: u8 = 128;

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
pub enum ValueKind {
    String,
    Integer,  // range: i64::MAX
    UInteger, // range: u64::MAX
    Vector,
    Float,
    IpAddr,
    Bool,
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
pub enum AttrCmpKind {
    Less,
    Equal,
    Greater,
    LessOrEqual,
    GreaterOrEqual,
    Contain,
    OpenRange,
    CloseRange,
    LeftOpenRange,
    RightOpenRange,
    NotEqual,
    NotContain,
    NotOpenRange,
    NotCloseRange,
    NotLeftOpenRange,
    NotRightOpenRange,
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
pub enum ResponseKind {
    Manual,
    Blacklist,
    Whitelist,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum ExclusionReason {
    IpAddress(HostNetworkGroup),
    Domain(Vec<String>),
    Hostname(Vec<String>),
    Uri(Vec<String>),
}

impl Eq for ExclusionReason {}

impl PartialOrd for ExclusionReason {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[allow(clippy::match_same_arms)]
impl Ord for ExclusionReason {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (ExclusionReason::IpAddress(a), ExclusionReason::IpAddress(b)) => a.cmp(b),
            (ExclusionReason::Domain(a), ExclusionReason::Domain(b)) => a.cmp(b),
            (ExclusionReason::Hostname(a), ExclusionReason::Hostname(b)) => a.cmp(b),
            (ExclusionReason::Uri(a), ExclusionReason::Uri(b)) => a.cmp(b),
            (ExclusionReason::IpAddress(_), _) => Ordering::Less,
            (ExclusionReason::Domain(_), ExclusionReason::IpAddress(_)) => Ordering::Greater,
            (ExclusionReason::Domain(_), _) => Ordering::Less,
            (
                ExclusionReason::Hostname(_),
                ExclusionReason::IpAddress(_) | ExclusionReason::Domain(_),
            ) => Ordering::Greater,
            (ExclusionReason::Hostname(_), _) => Ordering::Less,
            (ExclusionReason::Uri(_), _) => Ordering::Greater,
        }
    }
}

#[derive(Clone, Debug)]
pub enum CompareIp {
    Network(IpNet),
    Iprange(RangeInclusive<IpAddr>),
}

impl CompareIp {
    fn detect(&self, ip: IpAddr) -> bool {
        match self {
            CompareIp::Network(net) => net.contains(&ip),
            CompareIp::Iprange(range) => range.contains(&ip),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct NetworkFilter {
    netmask_v4: Option<IpAddr>,
    netmask_v6: Option<IpAddr>,
    tree: HashMap<IpAddr, Vec<CompareIp>>,
}

impl NetworkFilter {
    /// Creates a new `NetworkFilter` from a `HostNetworkGroup`.
    ///
    /// # Errors
    ///
    /// Returns an error if network construction fails due to invalid IP addresses or network configurations.
    pub fn new(host_network_group: &mut HostNetworkGroup) -> Result<Self> {
        let mut networks = Vec::new();
        network_by_hosts_network_group(host_network_group, &mut networks)?;

        let (mut v4_networks, mut v6_networks): (Vec<_>, Vec<_>) = networks
            .into_iter()
            .partition(|(net, _)| net.addr().is_ipv4());

        v4_networks.sort_unstable_by_key(|(net, _)| net.prefix_len());
        v6_networks.sort_unstable_by_key(|(net, _)| net.prefix_len());

        let netmask_v4 = min_netmask_for_family(&v4_networks)?;
        let netmask_v6 = min_netmask_for_family(&v6_networks)?;

        let mut compare_tree: HashMap<IpAddr, Vec<CompareIp>> = HashMap::new();
        if let Some(netmask) = netmask_v4 {
            insert_networks_into_tree(&mut compare_tree, v4_networks, netmask)?;
        }
        if let Some(netmask) = netmask_v6 {
            insert_networks_into_tree(&mut compare_tree, v6_networks, netmask)?;
        }

        Ok(Self {
            netmask_v4,
            netmask_v6,
            tree: compare_tree,
        })
    }

    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        let Some(netmask) = (match ip {
            IpAddr::V4(_) => self.netmask_v4,
            IpAddr::V6(_) => self.netmask_v6,
        }) else {
            return false;
        };
        let Some(key) = netmask_by_ipaddr(ip, netmask) else {
            return false;
        };
        let Some(networks) = self.tree.get(&key) else {
            return false;
        };
        networks.iter().any(|net| net.detect(ip))
    }
}

#[derive(Clone)]
pub enum TriageExclusion {
    IpAddress(NetworkFilter),
    Domain(regex::RegexSet),
    Hostname(Vec<String>),
    Uri(Vec<String>),
}

impl From<ExclusionReason> for TriageExclusion {
    fn from(reason: ExclusionReason) -> Self {
        match reason {
            ExclusionReason::IpAddress(mut group) => {
                TriageExclusion::IpAddress(match NetworkFilter::new(&mut group) {
                    Ok(filter) => filter,
                    Err(error) => {
                        warn!("Failed to build IP triage exclusion filter: {error}");
                        NetworkFilter::default()
                    }
                })
            }
            ExclusionReason::Domain(domains) => {
                // Create regex patterns for domain matching
                // Supports both exact domain matches and subdomain matches
                let patterns: Vec<String> = if domains.is_empty() {
                    vec![String::from("(?!)")] // Never match pattern
                } else {
                    domains
                        .iter()
                        .map(|domain| {
                            // Escape special regex characters in domain
                            let escaped = regex::escape(domain);
                            // Pattern to match exact domain or subdomain
                            format!(r"(^{escaped}$|\.{escaped}$)")
                        })
                        .collect()
                };
                let regex_set =
                    regex::RegexSet::new(&patterns).expect("Valid regex patterns for domains");
                TriageExclusion::Domain(regex_set)
            }
            ExclusionReason::Hostname(hostnames) => TriageExclusion::Hostname(hostnames),
            ExclusionReason::Uri(uris) => TriageExclusion::Uri(uris),
        }
    }
}

#[derive(Clone)]
pub struct TriagePolicyInput {
    pub id: u32,
    pub name: String,
    pub creation_time: DateTime<Utc>,
    pub triage_exclusion: Vec<TriageExclusion>,
    pub packet_attr: Vec<PacketAttr>,
    pub confidence: Vec<Confidence>,
    pub response: Vec<Response>,
}

#[derive(Clone, PartialEq, Deserialize, Serialize)]
pub struct PacketAttr {
    pub raw_event_kind: RawEventKind,
    pub attr_name: String,
    pub value_kind: ValueKind,
    pub cmp_kind: AttrCmpKind,
    pub first_value: Vec<u8>,
    pub second_value: Option<Vec<u8>>,
    pub weight: Option<f64>,
}

impl Eq for PacketAttr {}

impl PartialOrd for PacketAttr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PacketAttr {
    fn cmp(&self, other: &Self) -> Ordering {
        let first = self.attr_name.cmp(&other.attr_name);
        if first != Ordering::Equal {
            return first;
        }
        let second = self.value_kind.cmp(&other.value_kind);
        if second != Ordering::Equal {
            return second;
        }
        let third = self.cmp_kind.cmp(&other.cmp_kind);
        if third != Ordering::Equal {
            return third;
        }
        let fourth = self.first_value.cmp(&other.first_value);
        if fourth != Ordering::Equal {
            return fourth;
        }
        let fifth = self.second_value.cmp(&other.second_value);
        if fifth != Ordering::Equal {
            return fifth;
        }
        match (self.weight, other.weight) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(s), Some(o)) => s.total_cmp(&o),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Confidence {
    pub threat_category: Option<EventCategory>,
    pub threat_kind: String,
    pub confidence: f64,
    pub weight: Option<f64>,
}

impl Eq for Confidence {}

impl PartialOrd for Confidence {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Confidence {
    fn cmp(&self, other: &Self) -> Ordering {
        let first = self.threat_category.cmp(&other.threat_category);
        if first != Ordering::Equal {
            return first;
        }
        let second = self.threat_kind.cmp(&other.threat_kind);
        if second != Ordering::Equal {
            return second;
        }
        let third = self.confidence.total_cmp(&other.confidence);
        if third != Ordering::Equal {
            return third;
        }
        match (self.weight, other.weight) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(s), Some(o)) => s.total_cmp(&o),
        }
    }
}

#[derive(Clone, PartialEq, Deserialize, Serialize)]
pub struct Response {
    pub minimum_score: f64,
    pub kind: ResponseKind,
}

impl Eq for Response {}

impl PartialOrd for Response {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Response {
    fn cmp(&self, other: &Self) -> Ordering {
        let first = self.minimum_score.total_cmp(&other.minimum_score);
        if first != Ordering::Equal {
            return first;
        }
        self.kind.cmp(&other.kind)
    }
}

fn network_by_hosts_network_group(
    host_network_group: &mut HostNetworkGroup,
    networks: &mut Vec<(IpNet, CompareIp)>,
) -> Result<()> {
    for host in host_network_group.hosts() {
        let host_net = match host {
            IpAddr::V4(ipv4) => IpNet::V4(Ipv4Net::new(*ipv4, IP_V4_MAX_PREFIX_LEN)?),
            IpAddr::V6(ipv6) => IpNet::V6(Ipv6Net::new(*ipv6, IP_V6_MAX_PREFIX_LEN)?),
        };
        networks.push((host_net, CompareIp::Network(host_net)));
    }

    let network: Vec<_> = host_network_group
        .networks()
        .iter()
        .map(|net| (*net, CompareIp::Network(*net)))
        .collect();
    networks.extend_from_slice(&network);

    for range in host_network_group.ip_ranges() {
        let super_net: IpNet = match (range.start(), range.end()) {
            (IpAddr::V4(start_ipv4), IpAddr::V4(end_ipv4)) => {
                let mut supernet = Ipv4Net::new(*start_ipv4, IP_V4_MAX_PREFIX_LEN)?;
                loop {
                    let Some(s) = supernet.supernet() else {
                        return Err(anyhow!("Failed to generate ipv4's super net."));
                    };
                    if s.contains(end_ipv4) {
                        break s.into();
                    }
                    supernet = s;
                }
            }
            (IpAddr::V6(start_ipv6), IpAddr::V6(end_ipv6)) => {
                let mut supernet = Ipv6Net::new(*start_ipv6, IP_V6_MAX_PREFIX_LEN)?;
                loop {
                    let Some(s) = supernet.supernet() else {
                        return Err(anyhow!("Failed to generate ipv6's super net."));
                    };
                    if s.contains(end_ipv6) {
                        break s.into();
                    }
                    supernet = s;
                }
            }
            _ => return Err(anyhow!("Invalid ip address format")),
        };
        networks.push((super_net, CompareIp::Iprange(range.clone())));
    }

    Ok(())
}

fn min_netmask_for_family(networks: &[(IpNet, CompareIp)]) -> Result<Option<IpAddr>> {
    let Some((first, _)) = networks.first() else {
        return Ok(None);
    };
    let min_prefix_len = first.prefix_len();
    let netmask = match first {
        IpNet::V4(_) => Ipv4Net::new(Ipv4Addr::UNSPECIFIED, min_prefix_len)
            .map(|net| IpNet::V4(net).netmask())?,
        IpNet::V6(_) => Ipv6Net::new(Ipv6Addr::UNSPECIFIED, min_prefix_len)
            .map(|net| IpNet::V6(net).netmask())?,
    };
    Ok(Some(netmask))
}

fn insert_networks_into_tree(
    tree: &mut HashMap<IpAddr, Vec<CompareIp>>,
    networks: Vec<(IpNet, CompareIp)>,
    netmask: IpAddr,
) -> Result<()> {
    for (net, compare_ip) in networks {
        let masked = netmask_by_ipnet(&net, netmask).ok_or_else(|| {
            anyhow!("IP family mismatch inserting network {net} with netmask {netmask}")
        })?;
        tree.entry(masked).or_default().push(compare_ip);
    }
    Ok(())
}

fn netmask_by_ipnet(ipnet: &IpNet, netmask: IpAddr) -> Option<IpAddr> {
    match (ipnet, netmask) {
        (IpNet::V4(x), IpAddr::V4(y)) => Some(IpAddr::V4(x.addr().bitand(y))),
        (IpNet::V6(x), IpAddr::V6(y)) => Some(IpAddr::V6(x.addr().bitand(y))),
        _ => None,
    }
}

fn netmask_by_ipaddr(ipaddr: IpAddr, netmask: IpAddr) -> Option<IpAddr> {
    match (ipaddr, netmask) {
        (IpAddr::V4(x), IpAddr::V4(y)) => Some(IpAddr::V4(x.bitand(y))),
        (IpAddr::V6(x), IpAddr::V6(y)) => Some(IpAddr::V6(x.bitand(y))),
        _ => None,
    }
}

#[cfg(test)]
mod test {
    // =========================================================================
    // Confidence: serialization, ordering, and optional threat_category tests
    // =========================================================================

    use crate::{Confidence, EventCategory};

    fn make_confidence(
        category: Option<EventCategory>,
        kind: &str,
        confidence: f64,
        weight: Option<f64>,
    ) -> Confidence {
        Confidence {
            threat_category: category,
            threat_kind: kind.to_string(),
            confidence,
            weight,
        }
    }

    #[test]
    fn confidence_bincode_roundtrip_some() {
        use bincode::Options;

        let conf = make_confidence(
            Some(EventCategory::Reconnaissance),
            "brute_force",
            0.9,
            Some(2.0),
        );
        let bytes = bincode::DefaultOptions::new().serialize(&conf).unwrap();
        let back: Confidence = bincode::DefaultOptions::new().deserialize(&bytes).unwrap();
        assert_eq!(conf, back);
    }

    #[test]
    fn confidence_bincode_roundtrip_none() {
        use bincode::Options;

        let conf = make_confidence(None, "unknown", 0.5, None);
        let bytes = bincode::DefaultOptions::new().serialize(&conf).unwrap();
        let back: Confidence = bincode::DefaultOptions::new().deserialize(&bytes).unwrap();
        assert_eq!(conf, back);
    }

    #[test]
    fn confidence_ordering_none_less_than_some() {
        let none_conf = make_confidence(None, "a", 0.5, None);
        let some_conf = make_confidence(Some(EventCategory::Reconnaissance), "a", 0.5, None);
        assert!(none_conf < some_conf);
        assert!(some_conf > none_conf);
    }

    #[test]
    fn confidence_ordering_some_vs_some_preserves_category_order() {
        let recon = make_confidence(Some(EventCategory::Reconnaissance), "a", 0.5, None);
        let exec = make_confidence(Some(EventCategory::Execution), "a", 0.5, None);
        // EventCategory derives Ord from repr(u8) order:
        // Reconnaissance = 1, Execution = 3
        assert!(recon < exec);
    }

    #[test]
    fn confidence_ordering_none_vs_none_falls_through_to_kind() {
        let a = make_confidence(None, "alpha", 0.5, None);
        let b = make_confidence(None, "beta", 0.5, None);
        assert!(a < b);
    }

    // =========================================================================
    // NetworkFilter: mixed IPv4/IPv6 exclusion tests
    // =========================================================================

    use std::net::IpAddr;

    use ipnet::IpNet;

    use crate::{HostNetworkGroup, NetworkFilter};

    #[test]
    fn network_filter_matches_both_families_when_ipv4_has_shorter_prefix() {
        let networks: Vec<IpNet> = vec![
            "10.0.0.0/8".parse().unwrap(),
            "2001:db8::/32".parse().unwrap(),
        ];
        let mut group = HostNetworkGroup::new(Vec::new(), networks, Vec::new());
        let filter = NetworkFilter::new(&mut group).unwrap();

        assert!(filter.contains("10.1.2.3".parse::<IpAddr>().unwrap()));
        assert!(filter.contains("2001:db8::1".parse::<IpAddr>().unwrap()));
        assert!(!filter.contains("11.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(!filter.contains("2002:db8::1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn network_filter_matches_both_families_when_ipv6_has_shorter_prefix() {
        let networks: Vec<IpNet> = vec![
            "192.0.2.0/24".parse().unwrap(),
            "2001::/16".parse().unwrap(),
        ];
        let mut group = HostNetworkGroup::new(Vec::new(), networks, Vec::new());
        let filter = NetworkFilter::new(&mut group).unwrap();

        assert!(filter.contains("2001:db8::1".parse::<IpAddr>().unwrap()));
        assert!(filter.contains("192.0.2.10".parse::<IpAddr>().unwrap()));
        assert!(!filter.contains("192.0.3.1".parse::<IpAddr>().unwrap()));
        assert!(!filter.contains("2002::1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn network_filter_matches_mixed_family_hosts() {
        let hosts: Vec<IpAddr> = vec!["10.0.0.1".parse().unwrap(), "2001:db8::1".parse().unwrap()];
        let mut group = HostNetworkGroup::new(hosts, Vec::new(), Vec::new());
        let filter = NetworkFilter::new(&mut group).unwrap();

        assert!(filter.contains("10.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(filter.contains("2001:db8::1".parse::<IpAddr>().unwrap()));
        assert!(!filter.contains("10.0.0.2".parse::<IpAddr>().unwrap()));
        assert!(!filter.contains("2001:db8::2".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn network_filter_matches_mixed_family_ranges() {
        use std::ops::RangeInclusive;

        let ip_ranges: Vec<RangeInclusive<IpAddr>> = vec![
            RangeInclusive::new("192.0.2.1".parse().unwrap(), "192.0.2.10".parse().unwrap()),
            RangeInclusive::new(
                "2001:db8::1".parse().unwrap(),
                "2001:db8::10".parse().unwrap(),
            ),
        ];
        let mut group = HostNetworkGroup::new(Vec::new(), Vec::new(), ip_ranges);
        let filter = NetworkFilter::new(&mut group).unwrap();

        assert!(filter.contains("192.0.2.5".parse::<IpAddr>().unwrap()));
        assert!(filter.contains("2001:db8::5".parse::<IpAddr>().unwrap()));
        assert!(!filter.contains("192.0.2.11".parse::<IpAddr>().unwrap()));
        assert!(!filter.contains("2001:db8::11".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn network_filter_single_family_unchanged() {
        let networks: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let mut group = HostNetworkGroup::new(Vec::new(), networks, Vec::new());
        let filter = NetworkFilter::new(&mut group).unwrap();

        assert!(filter.contains("10.1.2.3".parse::<IpAddr>().unwrap()));
        assert!(!filter.contains("11.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(!filter.contains("2001:db8::1".parse::<IpAddr>().unwrap()));
    }
}
