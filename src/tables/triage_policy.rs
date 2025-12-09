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
    pub triage_exclusion_id: Vec<u32>,
    pub packet_attr: Vec<PacketAttr>,
    pub confidence: Vec<Confidence>,
    pub response: Vec<Response>,
    pub creation_time: DateTime<Utc>,
    pub customer_id: Option<u32>,
}

/// Creates a composite key from `customer_id` and `name` for `TriagePolicy`.
///
/// The key format is: `customer_id` (4 bytes, big-endian) + `name` (UTF-8 bytes).
/// - If `customer_id` is `Some(id)`, the `id` value is used.
/// - If `customer_id` is `None` (applies to all customers), `u32::MAX` is used.
fn triage_policy_key(customer_id: Option<u32>, name: &str) -> Vec<u8> {
    let customer_id_value = customer_id.unwrap_or(u32::MAX);
    let mut key = Vec::with_capacity(4 + name.len());
    key.extend_from_slice(&customer_id_value.to_be_bytes());
    key.extend_from_slice(name.as_bytes());
    key
}

impl FromKeyValue for TriagePolicy {
    fn from_key_value(_key: &[u8], value: &[u8]) -> Result<Self> {
        super::deserialize(value)
    }
}

impl UniqueKey for TriagePolicy {
    type AsBytes<'a> = Vec<u8>;

    fn unique_key(&self) -> Vec<u8> {
        triage_policy_key(self.customer_id, &self.name)
    }
}

impl Indexable for TriagePolicy {
    fn key(&self) -> Cow<'_, [u8]> {
        Cow::Owned(triage_policy_key(self.customer_id, &self.name))
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

impl TriagePolicy {
    /// Converts `TriagePolicy` into `TriagePolicyInput` with the given exclusion reasons.
    ///
    /// Applications using `review-database` must fetch `ExclusionReason` values from the
    /// `triage_exclusion_map` using the `triage_exclusion_id`s stored in `TriagePolicy`
    /// and pass them to this method.
    #[must_use]
    pub fn into_input_with_exclusion_reason(
        self,
        exclusion_reason: Vec<ExclusionReason>,
    ) -> TriagePolicyInput {
        TriagePolicyInput {
            id: self.id,
            name: self.name,
            creation_time: self.creation_time,
            triage_exclusion: exclusion_reason.into_iter().map(Into::into).collect(),
            packet_attr: self.packet_attr,
            confidence: self.confidence,
            response: self.response,
        }
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

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum ExclusionReason {
    IpAddress(HostNetworkGroup),
    Domain(Vec<String>),
    Hostname(Vec<String>),
    Uri(Vec<String>),
}

impl Eq for ExclusionReason {}

/// A triage exclusion reason stored in the `triage_exclusion_map`.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct TriageExclusionReason {
    pub id: u32,
    pub name: String,
    pub exclusion_reason: ExclusionReason,
    pub description: String,
}

impl Eq for TriageExclusionReason {}

impl FromKeyValue for TriageExclusionReason {
    fn from_key_value(_key: &[u8], value: &[u8]) -> Result<Self> {
        super::deserialize(value)
    }
}

impl UniqueKey for TriageExclusionReason {
    type AsBytes<'a> = &'a [u8];

    fn unique_key(&self) -> &[u8] {
        self.name.as_bytes()
    }
}

impl Indexable for TriageExclusionReason {
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

impl PartialOrd for TriageExclusionReason {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TriageExclusionReason {
    fn cmp(&self, other: &Self) -> Ordering {
        let ord = self.name.cmp(&other.name);
        match ord {
            Ordering::Equal => self.id.cmp(&other.id),
            _ => ord,
        }
    }
}

#[derive(Clone)]
pub struct TriageExclusionReasonUpdate {
    pub name: String,
    pub exclusion_reason: ExclusionReason,
    pub description: String,
}

impl IndexedMapUpdate for TriageExclusionReasonUpdate {
    type Entry = TriageExclusionReason;

    fn key(&self) -> Option<Cow<'_, [u8]>> {
        Some(Cow::Borrowed(self.name.as_bytes()))
    }

    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry, anyhow::Error> {
        value.name.clear();
        value.name.push_str(&self.name);
        value.exclusion_reason = self.exclusion_reason.clone();
        value.description.clear();
        value.description.push_str(&self.description);
        Ok(value)
    }

    fn verify(&self, value: &Self::Entry) -> bool {
        self.name == value.name
            && self.exclusion_reason == value.exclusion_reason
            && self.description == value.description
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

impl From<ExclusionReason> for TriageExclusion {
    fn from(reason: ExclusionReason) -> Self {
        match reason {
            ExclusionReason::IpAddress(mut group) => {
                TriageExclusion::IpAddress(NetworkFilter::new(&mut group).unwrap_or_default())
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

/// Functions for the `triage_exclusion_reason` indexed map.
impl<'d> IndexedTable<'d, TriageExclusionReason> {
    /// Opens the `triage_exclusion_reason` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        IndexedMap::new(db, super::TRIAGE_EXCLUSION_REASON)
            .map(IndexedTable::new)
            .ok()
    }

    /// Updates the `TriageExclusionReason` from `old` to `new`, given `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `id` is invalid or the database operation fails.
    pub fn update(
        &mut self,
        id: u32,
        old: &TriageExclusionReasonUpdate,
        new: &TriageExclusionReasonUpdate,
    ) -> Result<()> {
        self.indexed_map.update(id, old, new)
    }
}

#[derive(Clone)]
pub struct Update {
    pub name: String,
    pub triage_exclusion_id: Vec<u32>,
    pub packet_attr: Vec<PacketAttr>,
    pub confidence: Vec<Confidence>,
    pub response: Vec<Response>,
    pub customer_id: Option<u32>,
}

impl IndexedMapUpdate for Update {
    type Entry = TriagePolicy;

    fn key(&self) -> Option<Cow<'_, [u8]>> {
        Some(Cow::Owned(triage_policy_key(self.customer_id, &self.name)))
    }

    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry, anyhow::Error> {
        value.name.clear();
        value.name.push_str(&self.name);
        let mut triage_exclusion_id = self.triage_exclusion_id.clone();
        triage_exclusion_id.sort_unstable();
        value.triage_exclusion_id = triage_exclusion_id;

        let mut packet_attr: Vec<PacketAttr> = self.packet_attr.clone();
        packet_attr.sort_unstable();
        value.packet_attr = packet_attr;

        let mut confidence = self.confidence.clone();
        confidence.sort_unstable();
        value.confidence = confidence;

        let mut response = self.response.clone();
        response.sort_unstable();
        value.response = response;

        value.customer_id = self.customer_id;

        Ok(value)
    }

    fn verify(&self, value: &Self::Entry) -> bool {
        if self.name != value.name {
            return false;
        }
        let mut triage_exclusion_id = self.triage_exclusion_id.clone();
        triage_exclusion_id.sort_unstable();
        if triage_exclusion_id != value.triage_exclusion_id {
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

        if self.customer_id != value.customer_id {
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

    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{
        ExclusionReason, Store, TriageExclusionReason, TriageExclusionReasonUpdate, TriagePolicy,
        TriagePolicyUpdate,
    };

    #[test]
    fn update() {
        let (_permit, store) = setup_store();
        let mut table = store.triage_policy_map();

        let entry = create_entry("a", None);
        let id = table.put(entry.clone()).unwrap();

        let old = create_update("a", None);

        let update = create_update("b", None);

        assert!(table.update(id, &old, &update).is_ok());
        assert_eq!(table.count().unwrap(), 1);
        let entry = table.get_by_id(id).unwrap();
        assert_eq!(entry.map(|e| e.name), Some("b".to_string()));
    }

    #[test]
    fn same_name_different_customer() {
        let (_permit, store) = setup_store();
        let table = store.triage_policy_map();

        // Create a policy for customer 1
        let entry1 = create_entry("policy", Some(1));
        let id1 = table.put(entry1).unwrap();

        // Create a policy with the same name for customer 2
        let entry2 = create_entry("policy", Some(2));
        let id2 = table.put(entry2).unwrap();

        // Create a policy with the same name for all customers (customer_id = None)
        let entry3 = create_entry("policy", None);
        let id3 = table.put(entry3).unwrap();

        // All three should coexist
        assert_eq!(table.count().unwrap(), 3);

        // Verify each entry exists and has correct customer_id
        let retrieved1 = table.get_by_id(id1).unwrap().unwrap();
        assert_eq!(retrieved1.name, "policy");
        assert_eq!(retrieved1.customer_id, Some(1));

        let retrieved2 = table.get_by_id(id2).unwrap().unwrap();
        assert_eq!(retrieved2.name, "policy");
        assert_eq!(retrieved2.customer_id, Some(2));

        let retrieved3 = table.get_by_id(id3).unwrap().unwrap();
        assert_eq!(retrieved3.name, "policy");
        assert_eq!(retrieved3.customer_id, None);
    }

    #[test]
    fn update_exclusion_reason() {
        let (_permit, store) = setup_store();
        let mut table = store.triage_exclusion_reason_map();

        let entry = create_exclusion_reason_entry("a");
        let id = table.put(entry).unwrap();

        let old = create_exclusion_reason_update("a", "test description");
        let new = create_exclusion_reason_update("b", "new description");

        assert!(table.update(id, &old, &new).is_ok());
        assert_eq!(table.count().unwrap(), 1);
        let entry = table.get_by_id(id).unwrap().unwrap();
        assert_eq!(entry.name, "b");
        assert_eq!(entry.description, "new description");
    }

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        (permit, store)
    }

    fn create_entry(name: &str, customer_id: Option<u32>) -> TriagePolicy {
        TriagePolicy {
            id: u32::MAX,
            name: name.to_string(),
            triage_exclusion_id: vec![],
            packet_attr: vec![],
            response: vec![],
            confidence: vec![],
            creation_time: Utc::now(),
            customer_id,
        }
    }

    fn create_update(name: &str, customer_id: Option<u32>) -> TriagePolicyUpdate {
        TriagePolicyUpdate {
            name: name.to_string(),
            triage_exclusion_id: vec![],
            packet_attr: vec![],
            confidence: vec![],
            response: vec![],
            customer_id,
        }
    }

    fn create_exclusion_reason_entry(name: &str) -> TriageExclusionReason {
        TriageExclusionReason {
            id: u32::MAX,
            name: name.to_string(),
            exclusion_reason: ExclusionReason::Domain(vec!["example.com".to_string()]),
            description: "test description".to_string(),
        }
    }

    fn create_exclusion_reason_update(
        name: &str,
        description: &str,
    ) -> TriageExclusionReasonUpdate {
        TriageExclusionReasonUpdate {
            name: name.to_string(),
            exclusion_reason: ExclusionReason::Domain(vec!["example.com".to_string()]),
            description: description.to_string(),
        }
    }
}
