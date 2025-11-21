//! The `TriagePolicy` table.

use std::{
    borrow::Cow,
    cmp::Ordering,
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::{BitAnd, RangeInclusive},
};

use anyhow::{Result, anyhow};
use attrievent::attribute::RawEventKind;
use chrono::{DateTime, Utc};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use super::UniqueKey;
use crate::{
    Indexable, IndexedMap, IndexedMapUpdate, IndexedTable,
    collections::Indexed,
    types::{EventCategory, FromKeyValue, HostNetworkGroup},
};

const IP_V4_MAX_PREFIX_LEN: u8 = 32;
const IP_V6_MAX_PREFIX_LEN: u8 = 128;

#[derive(Clone, Deserialize, Serialize)]
pub struct TriagePolicy {
    pub id: u32,
    pub name: String,
    pub ti_db: Vec<TriageExclusionReason>,
    pub packet_attr: Vec<PacketAttr>,
    pub confidence: Vec<Confidence>,
    pub response: Vec<Response>,
    pub creation_time: DateTime<Utc>,
    pub customer_ids: Option<Vec<u32>>,
}

impl FromKeyValue for TriagePolicy {
    fn from_key_value(_key: &[u8], value: &[u8]) -> Result<Self> {
        super::deserialize(value)
    }
}

impl UniqueKey for TriagePolicy {
    type AsBytes<'a> = &'a [u8];

    fn unique_key(&self) -> &[u8] {
        self.name.as_bytes()
    }
}

impl Indexable for TriagePolicy {
    fn key(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.name.as_bytes())
    }
    fn index(&self) -> u32 {
        self.id
    }
    fn make_indexed_key(key: Cow<[u8]>, _index: u32) -> Cow<[u8]> {
        key
    }
    fn value(&self) -> Vec<u8> {
        super::serialize(self).expect("serializable")
    }

    fn set_index(&mut self, index: u32) {
        self.id = index;
    }
}

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

#[derive(Clone, PartialEq, Deserialize, Serialize)]
pub enum TriageExclusionReason {
    IpAddress(HostNetworkGroup),
    Domain(Vec<String>),
    Hostname(Vec<String>),
    Uri(Vec<String>),
}

impl Eq for TriageExclusionReason {}

impl PartialOrd for TriageExclusionReason {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[allow(clippy::match_same_arms)]
impl Ord for TriageExclusionReason {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (TriageExclusionReason::IpAddress(a), TriageExclusionReason::IpAddress(b)) => a.cmp(b),
            (TriageExclusionReason::Domain(a), TriageExclusionReason::Domain(b)) => a.cmp(b),
            (TriageExclusionReason::Hostname(a), TriageExclusionReason::Hostname(b)) => a.cmp(b),
            (TriageExclusionReason::Uri(a), TriageExclusionReason::Uri(b)) => a.cmp(b),
            (TriageExclusionReason::IpAddress(_), _) => Ordering::Less,
            (TriageExclusionReason::Domain(_), TriageExclusionReason::IpAddress(_)) => {
                Ordering::Greater
            }
            (TriageExclusionReason::Domain(_), _) => Ordering::Less,
            (
                TriageExclusionReason::Hostname(_),
                TriageExclusionReason::IpAddress(_) | TriageExclusionReason::Domain(_),
            ) => Ordering::Greater,
            (TriageExclusionReason::Hostname(_), _) => Ordering::Less,
            (TriageExclusionReason::Uri(_), _) => Ordering::Greater,
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

#[derive(Clone, Debug)]
pub struct NetworkFilter {
    netmask: IpAddr,
    tree: HashMap<IpAddr, Vec<CompareIp>>,
}

impl Default for NetworkFilter {
    fn default() -> Self {
        Self {
            // This ipv4 is always parsable.
            netmask: Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0)
                .map(|net| IpNet::V4(net).netmask())
                .expect("Failed to parse default ip address"),
            tree: HashMap::new(),
        }
    }
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

        networks.sort_by_key(|(net, _)| net.prefix_len());
        let min_netmask = if let Some((first, _)) = networks.first() {
            let min_prefix_len = first.prefix_len();
            if first.addr().is_ipv4() {
                Ipv4Net::new(Ipv4Addr::UNSPECIFIED, min_prefix_len)
                    .map(|net| IpNet::V4(net).netmask())?
            } else {
                Ipv6Net::new(Ipv6Addr::UNSPECIFIED, min_prefix_len)
                    .map(|net| IpNet::V6(net).netmask())?
            }
        } else {
            Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).map(|net| IpNet::V4(net).netmask())?
        };

        let networks: Vec<_> = networks
            .into_iter()
            .filter_map(|(net, compare_ip)| {
                netmask_by_ipnet(&net, min_netmask).map(|netmask| (netmask, compare_ip))
            })
            .collect();

        let mut compare_tree: HashMap<IpAddr, Vec<CompareIp>> = HashMap::new();
        for (netmask, compare_ip) in networks {
            compare_tree
                .entry(netmask)
                .and_modify(|v| v.push(compare_ip.clone()))
                .or_insert_with(|| vec![compare_ip]);
        }
        Ok(Self {
            netmask: min_netmask,
            tree: compare_tree,
        })
    }

    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        let Some(key) = netmask_by_ipaddr(ip, self.netmask) else {
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

impl From<TriageExclusionReason> for TriageExclusion {
    fn from(reason: TriageExclusionReason) -> Self {
        match reason {
            TriageExclusionReason::IpAddress(mut group) => {
                TriageExclusion::IpAddress(NetworkFilter::new(&mut group).unwrap_or_default())
            }
            TriageExclusionReason::Domain(domains) => {
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
            TriageExclusionReason::Hostname(hostnames) => TriageExclusion::Hostname(hostnames),
            TriageExclusionReason::Uri(uris) => TriageExclusion::Uri(uris),
        }
    }
}

#[derive(Clone)]
pub struct TriagePolicyInput {
    pub id: u32,
    pub name: String,
    pub creation_time: DateTime<Utc>,
    pub ti_db: Vec<TriageExclusion>,
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

#[derive(Clone, PartialEq, Deserialize, Serialize)]
pub struct Confidence {
    pub threat_category: EventCategory,
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

/// Functions for the `triage_policy` indexed map.
impl<'d> IndexedTable<'d, TriagePolicy> {
    /// Opens the `triage_policy` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        IndexedMap::new(db, super::TRIAGE_POLICY)
            .map(IndexedTable::new)
            .ok()
    }

    /// Updates the `TriagePolicy` from `old` to `new`, given `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `id` is invalid or the database operation fails.
    pub fn update(&mut self, id: u32, old: &Update, new: &Update) -> Result<()> {
        self.indexed_map.update(id, old, new)
    }
}

#[derive(Clone)]
pub struct Update {
    pub name: String,
    pub ti_db: Vec<TriageExclusionReason>,
    pub packet_attr: Vec<PacketAttr>,
    pub confidence: Vec<Confidence>,
    pub response: Vec<Response>,
    pub customer_ids: Option<Vec<u32>>,
}

impl IndexedMapUpdate for Update {
    type Entry = TriagePolicy;

    fn key(&self) -> Option<Cow<'_, [u8]>> {
        Some(Cow::Borrowed(self.name.as_bytes()))
    }

    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry, anyhow::Error> {
        value.name.clear();
        value.name.push_str(&self.name);
        let mut ti_db = self.ti_db.clone();
        ti_db.sort_unstable();
        value.ti_db = ti_db;

        let mut packet_attr: Vec<PacketAttr> = self.packet_attr.clone();
        packet_attr.sort_unstable();
        value.packet_attr = packet_attr;

        let mut confidence = self.confidence.clone();
        confidence.sort_unstable();
        value.confidence = confidence;

        let mut response = self.response.clone();
        response.sort_unstable();
        value.response = response;

        value.customer_ids = self.customer_ids.clone().map(|mut ids| {
            ids.sort_unstable();
            ids
        });

        Ok(value)
    }

    fn verify(&self, value: &Self::Entry) -> bool {
        if self.name != value.name {
            return false;
        }
        let mut ti_db = self.ti_db.clone();
        ti_db.sort_unstable();
        if ti_db != value.ti_db {
            return false;
        }
        let mut packet_attr = self.packet_attr.clone();
        packet_attr.sort_unstable();
        if packet_attr != value.packet_attr {
            return false;
        }

        let mut confidence = self.confidence.clone();
        confidence.sort_unstable();
        if confidence != value.confidence {
            return false;
        }

        let mut response = self.response.clone();
        response.sort_unstable();
        if response != value.response {
            return false;
        }

        let customer_ids = self.customer_ids.clone().map(|mut ids| {
            ids.sort_unstable();
            ids
        });
        if customer_ids != value.customer_ids {
            return false;
        }

        true
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
    use std::sync::Arc;

    use chrono::Utc;

    use crate::{Store, TriagePolicy, TriagePolicyUpdate};

    #[test]
    fn update() {
        let store = setup_store();
        let mut table = store.triage_policy_map();

        let entry = create_entry("a");
        let id = table.put(entry.clone()).unwrap();

        let old = create_update("a");

        let update = create_update("b");

        assert!(table.update(id, &old, &update).is_ok());
        assert_eq!(table.count().unwrap(), 1);
        let entry = table.get_by_id(id).unwrap();
        assert_eq!(entry.map(|e| e.name), Some("b".to_string()));
    }

    fn setup_store() -> Arc<Store> {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap())
    }

    fn create_entry(name: &str) -> TriagePolicy {
        TriagePolicy {
            id: u32::MAX,
            name: name.to_string(),
            ti_db: vec![],
            packet_attr: vec![],
            response: vec![],
            confidence: vec![],
            creation_time: Utc::now(),
            customer_ids: None,
        }
    }

    fn create_update(name: &str) -> TriagePolicyUpdate {
        TriagePolicyUpdate {
            name: name.to_string(),
            ti_db: vec![],
            packet_attr: vec![],
            confidence: vec![],
            response: vec![],
            customer_ids: None,
        }
    }
}
