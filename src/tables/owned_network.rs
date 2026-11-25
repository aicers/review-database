//! The `customer networks` table.
//!
//! Each row holds the networks one customer owns, as an operator defined them
//! outside this database, keyed by the customer ID alone. The table keeps no other
//! customer data: the ID is only a key.

use std::{
    collections::{BTreeMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::RangeInclusive,
};

use anyhow::{Context, Result, anyhow, bail};
use ipnet::IpNet;
use jiff::Timestamp;
use rocksdb::{IteratorMode, OptimisticTransactionDB, Transaction};
use serde::{Deserialize, Serialize};

use crate::{EXCLUSIVE, HostNetworkGroup, Map, event::NetworkType};

/// The networks a customer owns, as last replaced.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OwnedNetworkSet {
    /// The writer's revision of this set. A replacement with a lower revision
    /// is refused.
    pub revision: u64,
    pub networks: Vec<OwnedNetwork>,
    /// When the set was last written.
    #[serde(with = "crate::timestamp::ts_nanoseconds_saturating")]
    pub updated_at: Timestamp,
}

impl OwnedNetworkSet {
    /// Returns the addresses internal to the customer, by the narrowest
    /// owned network that contains each of them, as one group.
    ///
    /// An address is internal when, among the networks that have an entry
    /// containing it, the deciding networks are all `Intranet` or `Gateway`
    /// networks. The deciding networks are the ones whose narrowest entry
    /// containing the address is the narrowest of all; if one of them is an
    /// `Extranet` network, the address is not internal. An address no network
    /// contains is not internal. A host entry covers its one address, a
    /// network entry `network()` through `broadcast()` whatever host bits it
    /// was stored with, and a range entry its start through its end; an
    /// entry's width is its last address minus its first. `IPv4` and `IPv6`
    /// are decided separately, and an `IPv4`-mapped `IPv6` address is an
    /// `IPv6` address. A range whose ends differ in family, or whose start is
    /// after its end, covers no address.
    ///
    /// An entry of an `Intranet` or `Gateway` network that holds no address
    /// decided as not internal is kept as it is. The internal addresses of
    /// every other such entry are added as ranges, one per maximal run of
    /// consecutive internal addresses lying in one of those entries. The
    /// group is sorted and deduplicated, so a set in which no `Extranet`
    /// entry overlaps an `Intranet` or `Gateway` entry gives the merge of
    /// its `Intranet` and `Gateway` groups.
    #[must_use]
    pub fn internal_group(&self) -> HostNetworkGroup {
        let mut sweeps = ByFamily::<Vec<(Span, bool)>>::default();
        let mut candidates = Vec::new();
        for network in &self.networks {
            let internal = is_internal_type(network.network_type);
            let group = &network.group;
            let entries = group
                .hosts()
                .iter()
                .map(|host| (Span::host(*host), Entry::Host(*host)))
                .chain(group.networks().iter().map(|net| {
                    (
                        Span::of_range(net.network(), net.broadcast()),
                        Entry::Network(net),
                    )
                }))
                .chain(group.ip_ranges().iter().map(|range| {
                    (
                        Span::of_range(*range.start(), *range.end()),
                        Entry::Range(range),
                    )
                }));
            for (span, entry) in entries {
                let Some(span) = span else { continue };
                sweeps.get_mut(span.family).push((span, internal));
                if internal {
                    candidates.push((span, entry));
                }
            }
        }
        let decisions = ByFamily {
            v4: decide(&sweeps.v4),
            v6: decide(&sweeps.v6),
        };

        let mut hosts = Vec::new();
        let mut networks = Vec::new();
        let mut ip_ranges = Vec::new();
        let mut dropped = ByFamily::<Vec<(u128, u128)>>::default();
        for (span, entry) in candidates {
            if overlaps(&decisions.get(span.family).external, span.start, span.end) {
                dropped.get_mut(span.family).push((span.start, span.end));
            } else {
                match entry {
                    Entry::Host(host) => hosts.push(host),
                    Entry::Network(net) => networks.push(*net),
                    Entry::Range(range) => ip_ranges.push(range.clone()),
                }
            }
        }
        for family in [Family::V4, Family::V6] {
            let dropped = dropped.get_mut(family);
            dropped.sort_unstable();
            let dropped = merge_runs(dropped);
            ip_ranges.extend(
                intersect(&dropped, &decisions.get(family).internal)
                    .into_iter()
                    .map(|(start, end)| family.addr(start)..=family.addr(end)),
            );
        }
        HostNetworkGroup::new(hosts, networks, ip_ranges)
    }

    /// Returns the addresses internal to the customer as groups: the
    /// [`internal_group`](Self::internal_group) alone, or none if it is
    /// empty.
    ///
    /// An address is internal when the narrowest owned network containing it
    /// is an `Intranet` or `Gateway` network, and no `Extranet` network
    /// contains it as narrowly.
    #[must_use]
    pub fn internal_groups(&self) -> Vec<HostNetworkGroup> {
        let group = self.internal_group();
        if is_empty(&group) {
            Vec::new()
        } else {
            vec![group]
        }
    }

    /// Returns one group holding the hosts, networks and ranges of every
    /// network, whatever its type, sorted and deduplicated.
    #[must_use]
    pub fn merged_group(&self) -> HostNetworkGroup {
        merge_groups(self.networks.iter().map(|network| &network.group))
    }
}

/// Returns one group holding the hosts, networks and ranges of every group in
/// `groups`, sorted and deduplicated.
pub(super) fn merge_groups<'a>(
    groups: impl IntoIterator<Item = &'a HostNetworkGroup>,
) -> HostNetworkGroup {
    let mut hosts = Vec::new();
    let mut networks = Vec::new();
    let mut ip_ranges = Vec::new();
    for group in groups {
        hosts.extend_from_slice(group.hosts());
        networks.extend_from_slice(group.networks());
        ip_ranges.extend_from_slice(group.ip_ranges());
    }
    HostNetworkGroup::new(hosts, networks, ip_ranges)
}

/// Returns whether a network of `network_type` holds addresses inside the
/// customer's own space.
fn is_internal_type(network_type: NetworkType) -> bool {
    matches!(network_type, NetworkType::Intranet | NetworkType::Gateway)
}

/// Returns whether `group` holds no host, network or range.
fn is_empty(group: &HostNetworkGroup) -> bool {
    group.hosts().is_empty() && group.networks().is_empty() && group.ip_ranges().is_empty()
}

/// An address family, decided separately from the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

impl Family {
    /// Returns the address of this family whose number is `value`.
    fn addr(self, value: u128) -> IpAddr {
        match self {
            Self::V4 => IpAddr::V4(Ipv4Addr::from(
                u32::try_from(value).expect("an IPv4 sweep holds only IPv4 address numbers"),
            )),
            Self::V6 => IpAddr::V6(Ipv6Addr::from(value)),
        }
    }
}

/// One value per address family.
#[derive(Default)]
struct ByFamily<T> {
    v4: T,
    v6: T,
}

impl<T> ByFamily<T> {
    fn get(&self, family: Family) -> &T {
        match family {
            Family::V4 => &self.v4,
            Family::V6 => &self.v6,
        }
    }

    fn get_mut(&mut self, family: Family) -> &mut T {
        match family {
            Family::V4 => &mut self.v4,
            Family::V6 => &mut self.v6,
        }
    }
}

/// Returns the family of `addr` and its number.
fn number(addr: IpAddr) -> (Family, u128) {
    match addr {
        IpAddr::V4(addr) => (Family::V4, u128::from(u32::from(addr))),
        IpAddr::V6(addr) => (Family::V6, u128::from(addr)),
    }
}

/// The addresses an entry covers, `start` through `end` of one family.
#[derive(Clone, Copy, Debug)]
struct Span {
    family: Family,
    start: u128,
    end: u128,
}

impl Span {
    fn host(addr: IpAddr) -> Option<Self> {
        Self::of_range(addr, addr)
    }

    /// Returns the span of `start` through `end`, or `None` if they differ
    /// in family or `start` is after `end`.
    fn of_range(start: IpAddr, end: IpAddr) -> Option<Self> {
        let (family, start) = number(start);
        let (end_family, end) = number(end);
        (family == end_family && start <= end).then_some(Self { family, start, end })
    }

    /// Returns the width of the span, its last address minus its first.
    fn width(&self) -> u128 {
        self.end - self.start
    }
}

/// An entry of an `Intranet` or `Gateway` network, kept as it is if it holds
/// no address decided as not internal.
enum Entry<'a> {
    Host(IpAddr),
    Network(&'a IpNet),
    Range(&'a RangeInclusive<IpAddr>),
}

/// The covered addresses of one family, split by the decision: each list is
/// sorted, and its runs neither overlap nor touch.
#[derive(Default)]
struct Decision {
    internal: Vec<(u128, u128)>,
    external: Vec<(u128, u128)>,
}

/// Decides every address the `spans` of one family cover, each span marked
/// whether its network is an `Intranet` or `Gateway` network.
///
/// It sweeps over the starts and the ends of the spans, keeping the active
/// spans counted by width, so between two boundaries the narrowest active
/// spans decide every address alike.
fn decide(spans: &[(Span, bool)]) -> Decision {
    let mut events = Vec::with_capacity(spans.len() * 2);
    for (span, internal) in spans {
        events.push((span.start, true, span.width(), *internal));
        if let Some(after) = span.end.checked_add(1) {
            events.push((after, false, span.width(), *internal));
        }
    }
    events.sort_unstable_by_key(|event| event.0);

    // The active spans by width: how many of `Intranet` or `Gateway`
    // networks, and how many of `Extranet` networks.
    let mut active: BTreeMap<u128, (usize, usize)> = BTreeMap::new();
    let mut decision = Decision::default();
    let mut events = events.into_iter().peekable();
    while let Some(&(position, ..)) = events.peek() {
        while let Some((_, starts, width, internal)) = events.next_if(|event| event.0 == position) {
            let counts = active.entry(width).or_default();
            let count = if internal {
                &mut counts.0
            } else {
                &mut counts.1
            };
            if starts {
                *count += 1;
            } else {
                *count -= 1;
            }
            if *counts == (0, 0) {
                active.remove(&width);
            }
        }
        let Some((_, &(_, external))) = active.first_key_value() else {
            continue;
        };
        let end = events.peek().map_or(u128::MAX, |next| next.0 - 1);
        let runs = if external == 0 {
            &mut decision.internal
        } else {
            &mut decision.external
        };
        push_run(runs, position, end);
    }
    decision
}

/// Appends `start..=end`, which is after every run of `runs`, merging it into
/// the last run if they overlap or touch.
fn push_run(runs: &mut Vec<(u128, u128)>, start: u128, end: u128) {
    if let Some(last) = runs.last_mut()
        && last.1.checked_add(1).is_none_or(|after| after >= start)
    {
        last.1 = last.1.max(end);
        return;
    }
    runs.push((start, end));
}

/// Returns `spans`, sorted by start, merged into runs that neither overlap
/// nor touch.
fn merge_runs(spans: &[(u128, u128)]) -> Vec<(u128, u128)> {
    let mut runs = Vec::with_capacity(spans.len());
    for &(start, end) in spans {
        push_run(&mut runs, start, end);
    }
    runs
}

/// Returns whether any of the sorted, disjoint `runs` overlaps
/// `start..=end`.
fn overlaps(runs: &[(u128, u128)], start: u128, end: u128) -> bool {
    let first = runs.partition_point(|run| run.1 < start);
    runs.get(first).is_some_and(|run| run.0 <= end)
}

/// Returns the addresses in both `a` and `b`, two lists of runs that are
/// sorted and neither overlap nor touch, as runs of the same kind.
fn intersect(a: &[(u128, u128)], b: &[(u128, u128)]) -> Vec<(u128, u128)> {
    let mut result = Vec::new();
    let (mut a, mut b) = (a.iter().peekable(), b.iter().peekable());
    while let (Some(&&(a_start, a_end)), Some(&&(b_start, b_end))) = (a.peek(), b.peek()) {
        let start = a_start.max(b_start);
        let end = a_end.min(b_end);
        if start <= end {
            result.push((start, end));
        }
        if a_end < b_end {
            a.next();
        } else {
            b.next();
        }
    }
    result
}

/// A network a customer owns.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OwnedNetwork {
    /// The name of the network, unique within its customer's set.
    pub name: String,
    pub network_type: NetworkType,
    pub group: HostNetworkGroup,
}

/// The result of [`OwnedNetworkTable::replace`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ReplaceOutcome {
    /// The set was written. `previous` is the row that was overwritten, read in
    /// the same transaction, or `None` if there was none.
    Written { previous: Option<OwnedNetworkSet> },
    /// Nothing was written, because the stored row has the higher revision
    /// `stored`.
    Stale { stored: u64 },
}

/// The `customer networks` table, holding one [`OwnedNetworkSet`] per
/// customer.
///
/// A row is keyed by the customer ID in big-endian byte order, so the table
/// iterates in ascending customer ID order.
#[derive(Clone)]
pub struct OwnedNetworkTable<'d> {
    map: Map<'d>,
}

impl<'d> OwnedNetworkTable<'d> {
    /// Opens the `customer networks` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::CUSTOMER_NETWORKS).map(|map| Self { map })
    }

    /// Returns the networks owned by the customer `customer_id`, or `None` if
    /// none were stored for it.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails or the stored row cannot
    /// be decoded.
    pub fn get(&self, customer_id: u32) -> Result<Option<OwnedNetworkSet>> {
        self.map
            .get(&customer_id.to_be_bytes())?
            .map(|value| decode(customer_id, value.as_ref()))
            .transpose()
    }

    /// Returns the networks owned by the customer `customer_id` as `txn` sees
    /// them, or `None` if none were stored for it. The row is read for
    /// update, so a concurrent replacement or removal conflicts with `txn`.
    pub(crate) fn get_in_transaction(
        &self,
        txn: &Transaction<'_, OptimisticTransactionDB>,
        customer_id: u32,
    ) -> Result<Option<OwnedNetworkSet>> {
        txn.get_for_update_cf(self.map.cf, customer_id.to_be_bytes(), EXCLUSIVE)
            .with_context(|| format!("failed to read networks of customer {customer_id}"))?
            .map(|stored| decode(customer_id, &stored))
            .transpose()
    }

    /// Returns the networks owned by the customer `customer_id` as `reader`
    /// sees them, without reading them for update, or `None` if none were
    /// stored for it.
    pub(crate) fn get_with(
        &self,
        reader: &(impl super::DaiRead + ?Sized),
        customer_id: u32,
    ) -> Result<Option<OwnedNetworkSet>> {
        reader
            .value(&self.map, &customer_id.to_be_bytes())
            .with_context(|| format!("failed to read networks of customer {customer_id}"))?
            .map(|stored| decode(customer_id, &stored))
            .transpose()
    }

    /// Replaces the networks owned by the customer `customer_id` with
    /// `networks`, recorded at `revision` and the current time.
    ///
    /// A stored row with a higher revision is left as it is, and
    /// [`ReplaceOutcome::Stale`] reports its revision. Otherwise the row is
    /// written, including when the stored revision is equal, so resending the
    /// same revision is idempotent. The comparison and the write are one
    /// transaction, retried on a conflicting write, so of two concurrent
    /// replacements the higher revision is the one that ends up stored.
    ///
    /// # Errors
    ///
    /// Returns an error if two networks in `networks` share a name, compared
    /// exactly, in which case nothing is written; if the stored row cannot be
    /// decoded; or if the database operation fails.
    pub fn replace(
        &self,
        customer_id: u32,
        revision: u64,
        networks: Vec<OwnedNetwork>,
    ) -> Result<ReplaceOutcome> {
        let mut names = HashSet::with_capacity(networks.len());
        if let Some(duplicate) = networks
            .iter()
            .find(|network| !names.insert(network.name.as_str()))
        {
            bail!(
                "duplicate network name {:?} for customer {customer_id}",
                duplicate.name
            );
        }

        let set = OwnedNetworkSet {
            revision,
            networks,
            updated_at: Timestamp::now(),
        };
        let value = super::serialize(&set).context("failed to serialize customer networks")?;
        loop {
            let txn = self.map.db.transaction();
            let outcome = self.replace_in(&txn, customer_id, revision, &value)?;
            if let ReplaceOutcome::Stale { .. } = outcome {
                return Ok(outcome);
            }
            match txn.commit() {
                Ok(()) => return Ok(outcome),
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).with_context(|| {
                            format!("failed to replace networks of customer {customer_id}")
                        });
                    }
                }
            }
        }
    }

    /// Reads the row of `customer_id` for update within `txn` and, unless its
    /// revision is higher than `revision`, writes `value` over it.
    fn replace_in(
        &self,
        txn: &Transaction<'_, OptimisticTransactionDB>,
        customer_id: u32,
        revision: u64,
        value: &[u8],
    ) -> Result<ReplaceOutcome> {
        let key = customer_id.to_be_bytes();
        let previous = txn
            .get_for_update_cf(self.map.cf, key, EXCLUSIVE)
            .with_context(|| format!("failed to read networks of customer {customer_id}"))?
            .map(|stored| decode(customer_id, &stored))
            .transpose()?;
        if let Some(stored) = &previous
            && revision < stored.revision
        {
            return Ok(ReplaceOutcome::Stale {
                stored: stored.revision,
            });
        }
        txn.put_cf(self.map.cf, key, value)
            .with_context(|| format!("failed to write networks of customer {customer_id}"))?;
        Ok(ReplaceOutcome::Written { previous })
    }

    /// Removes the networks owned by the customer `customer_id`.
    ///
    /// Returns whether a row existed. Removing a missing row is not an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn remove(&self, customer_id: u32) -> Result<bool> {
        let key = customer_id.to_be_bytes();
        loop {
            let txn = self.map.db.transaction();
            let existed = txn
                .get_for_update_cf(self.map.cf, key, EXCLUSIVE)
                .with_context(|| format!("failed to read networks of customer {customer_id}"))?
                .is_some();
            if !existed {
                return Ok(false);
            }
            txn.delete_cf(self.map.cf, key)
                .with_context(|| format!("failed to remove networks of customer {customer_id}"))?;
            match txn.commit() {
                Ok(()) => return Ok(true),
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).with_context(|| {
                            format!("failed to remove networks of customer {customer_id}")
                        });
                    }
                }
            }
        }
    }

    /// Returns an iterator over every row, in ascending customer ID order.
    pub fn iter(&self) -> impl Iterator<Item = Result<(u32, OwnedNetworkSet)>> + '_ {
        self.map
            .db
            .iterator_cf(self.map.cf, IteratorMode::Start)
            .map(|entry| {
                let (key, value) = entry.context("failed to read customer networks")?;
                let key = <[u8; 4]>::try_from(key.as_ref()).map_err(|_| {
                    anyhow!(
                        "invalid customer networks key {}",
                        data_encoding::HEXLOWER.encode(&key)
                    )
                })?;
                let customer_id = u32::from_be_bytes(key);
                Ok((customer_id, decode(customer_id, &value)?))
            })
    }
}

/// Decodes the stored row of `customer_id`.
fn decode(customer_id: u32, value: &[u8]) -> Result<OwnedNetworkSet> {
    super::deserialize(value)
        .with_context(|| format!("failed to decode networks of customer {customer_id}"))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::Store;
    use crate::test::{DbGuard, acquire_db_permit};

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path(), None).unwrap());
        (permit, store)
    }

    fn network(name: &str, network_type: NetworkType, cidr: &str) -> OwnedNetwork {
        OwnedNetwork {
            name: name.to_string(),
            network_type,
            group: HostNetworkGroup::new(Vec::new(), vec![cidr.parse().unwrap()], Vec::new()),
        }
    }

    fn raw(table: &OwnedNetworkTable, customer_id: u32) -> Option<Vec<u8>> {
        table
            .map
            .get(&customer_id.to_be_bytes())
            .unwrap()
            .map(|value| value.as_ref().to_vec())
    }

    fn written(previous: Option<OwnedNetworkSet>) -> ReplaceOutcome {
        ReplaceOutcome::Written { previous }
    }

    #[test]
    fn fresh_store_has_an_empty_table() {
        let (_permit, store) = setup_store();
        let table = store.customer_networks_map();
        assert_eq!(table.iter().count(), 0);
        assert_eq!(table.get(0).unwrap(), None);
    }

    #[test]
    fn replace_and_get() {
        let (_permit, store) = setup_store();
        let table = store.customer_networks_map();
        assert_eq!(table.get(7).unwrap(), None);

        let networks = vec![
            network("office", NetworkType::Intranet, "10.0.0.0/8"),
            network("edge", NetworkType::Gateway, "192.168.0.0/24"),
            network("partner", NetworkType::Extranet, "172.16.0.0/12"),
        ];
        let before = jiff::Timestamp::now();
        assert_eq!(
            table.replace(7, 3, networks.clone()).unwrap(),
            written(None)
        );
        let after = jiff::Timestamp::now();

        let stored = table.get(7).unwrap().unwrap();
        assert_eq!(stored.revision, 3);
        assert_eq!(stored.networks, networks);
        assert!(before <= stored.updated_at && stored.updated_at <= after);

        // The key is the big-endian customer ID and nothing else.
        let keys: Vec<Vec<u8>> = table
            .map
            .db
            .iterator_cf(table.map.cf, IteratorMode::Start)
            .map(|entry| entry.unwrap().0.to_vec())
            .collect();
        assert_eq!(keys, vec![7u32.to_be_bytes().to_vec()]);
    }

    #[test]
    fn revision_zero_on_missing_row_is_accepted() {
        let (_permit, store) = setup_store();
        let table = store.customer_networks_map();

        assert_eq!(table.replace(1, 0, Vec::new()).unwrap(), written(None));
        assert_eq!(table.get(1).unwrap().unwrap().revision, 0);
    }

    #[test]
    fn lower_revision_is_stale_and_writes_nothing() {
        let (_permit, store) = setup_store();
        let table = store.customer_networks_map();

        let networks = vec![network("office", NetworkType::Intranet, "10.0.0.0/8")];
        table.replace(1, 5, networks).unwrap();
        let before = raw(&table, 1).unwrap();

        let outcome = table
            .replace(
                1,
                4,
                vec![network("other", NetworkType::Gateway, "10.1.0.0/16")],
            )
            .unwrap();
        assert_eq!(outcome, ReplaceOutcome::Stale { stored: 5 });
        assert_eq!(raw(&table, 1).unwrap(), before);
    }

    #[test]
    fn equal_or_higher_revision_overwrites_and_returns_previous() {
        let (_permit, store) = setup_store();
        let table = store.customer_networks_map();

        let first = vec![network("office", NetworkType::Intranet, "10.0.0.0/8")];
        table.replace(1, 5, first).unwrap();
        let stored_first = table.get(1).unwrap().unwrap();

        // An equal revision overwrites: a retried send is idempotent.
        let outcome = table.replace(1, 5, stored_first.networks.clone()).unwrap();
        assert_eq!(outcome, written(Some(stored_first.clone())));
        let stored_again = table.get(1).unwrap().unwrap();
        assert_eq!(stored_again.revision, 5);
        assert_eq!(stored_again.networks, stored_first.networks);

        let second = vec![network("lab", NetworkType::Gateway, "10.2.0.0/16")];
        let outcome = table.replace(1, 6, second.clone()).unwrap();
        assert_eq!(outcome, written(Some(stored_again)));
        let stored_second = table.get(1).unwrap().unwrap();
        assert_eq!(stored_second.revision, 6);
        assert_eq!(stored_second.networks, second);
    }

    #[test]
    fn duplicate_names_are_rejected_and_nothing_is_written() {
        let (_permit, store) = setup_store();
        let table = store.customer_networks_map();

        let duplicates = vec![
            network("office", NetworkType::Intranet, "10.0.0.0/8"),
            network("office", NetworkType::Gateway, "10.1.0.0/16"),
        ];
        assert!(table.replace(1, 1, duplicates.clone()).is_err());
        assert_eq!(raw(&table, 1), None);

        table.replace(1, 1, Vec::new()).unwrap();
        let before = raw(&table, 1).unwrap();
        assert!(table.replace(1, 2, duplicates).is_err());
        assert_eq!(raw(&table, 1).unwrap(), before);

        // Names are compared exactly, so differing case is not a duplicate.
        let distinct = vec![
            network("office", NetworkType::Intranet, "10.0.0.0/8"),
            network("Office", NetworkType::Gateway, "10.1.0.0/16"),
        ];
        table.replace(1, 3, distinct).unwrap();
    }

    #[test]
    fn empty_network_list_is_stored() {
        let (_permit, store) = setup_store();
        let table = store.customer_networks_map();

        table
            .replace(
                1,
                1,
                vec![network("office", NetworkType::Intranet, "10.0.0.0/8")],
            )
            .unwrap();
        table.replace(1, 2, Vec::new()).unwrap();
        let stored = table.get(1).unwrap().unwrap();
        assert_eq!(stored.revision, 2);
        assert_eq!(stored.networks, Vec::new());
    }

    #[test]
    fn remove_reports_whether_a_row_existed() {
        let (_permit, store) = setup_store();
        let table = store.customer_networks_map();

        table.replace(1, 1, Vec::new()).unwrap();
        table.replace(2, 1, Vec::new()).unwrap();
        assert!(table.remove(1).unwrap());
        assert!(!table.remove(1).unwrap());
        assert_eq!(table.get(1).unwrap(), None);
        assert!(table.get(2).unwrap().is_some());
        assert!(!table.remove(3).unwrap());
    }

    #[test]
    fn iter_is_in_ascending_customer_id_order() {
        let (_permit, store) = setup_store();
        let table = store.customer_networks_map();

        // Little-endian keys would order these 16_777_216, 256, 1, u32::MAX.
        let ids = [u32::MAX, 16_777_216, 1, 256, 0x00FF_FFFF];
        for (revision, id) in (1..).zip(ids) {
            table.replace(id, revision, Vec::new()).unwrap();
        }

        let rows: Vec<(u32, u64)> = table
            .iter()
            .map(|row| {
                let (id, set) = row.unwrap();
                (id, set.revision)
            })
            .collect();
        assert_eq!(
            rows,
            vec![
                (1, 3),
                (256, 4),
                (0x00FF_FFFF, 5),
                (16_777_216, 2),
                (u32::MAX, 1)
            ]
        );
    }

    #[test]
    fn ipv6_groups_round_trip() {
        let (_permit, store) = setup_store();
        let table = store.customer_networks_map();

        let start = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1));
        let end = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0xff));
        let networks = vec![OwnedNetwork {
            name: "v6".to_string(),
            network_type: NetworkType::Intranet,
            group: HostNetworkGroup::new(
                vec![
                    IpAddr::V6(Ipv6Addr::LOCALHOST),
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                ],
                vec!["2001:db8::/32".parse().unwrap()],
                vec![start..=end],
            ),
        }];
        table.replace(1, 1, networks.clone()).unwrap();
        assert_eq!(table.get(1).unwrap().unwrap().networks, networks);
    }

    /// A replacement whose read is overtaken by another committed write fails
    /// to commit, so the retry in `replace` reads the row again.
    #[test]
    fn conflicting_write_is_detected_at_commit() {
        let (_permit, store) = setup_store();
        let table = store.customer_networks_map();

        let value = super::super::serialize(&OwnedNetworkSet {
            revision: 1,
            networks: Vec::new(),
            updated_at: jiff::Timestamp::now(),
        })
        .unwrap();
        let txn = table.map.db.transaction();
        assert_eq!(table.replace_in(&txn, 1, 1, &value).unwrap(), written(None));

        table.replace(1, 2, Vec::new()).unwrap();
        let conflict = txn.commit().unwrap_err();
        assert!(conflict.as_ref().starts_with("Resource busy:"));
        assert_eq!(table.get(1).unwrap().unwrap().revision, 2);
    }

    #[test]
    fn concurrent_replacements_keep_the_higher_revision() {
        let (_permit, store) = setup_store();

        for round in 0..20 {
            let customer_id = round;
            let lower = vec![network("lower", NetworkType::Intranet, "10.0.0.0/8")];
            let higher = vec![network("higher", NetworkType::Gateway, "10.1.0.0/16")];
            std::thread::scope(|scope| {
                let low = scope.spawn(|| {
                    store
                        .customer_networks_map()
                        .replace(customer_id, 1, lower)
                        .unwrap()
                });
                let high = scope.spawn(|| {
                    store
                        .customer_networks_map()
                        .replace(customer_id, 2, higher.clone())
                        .unwrap()
                });
                let low = low.join().unwrap();
                let high = high.join().unwrap();
                // Whichever ran second saw the other's row.
                match low {
                    ReplaceOutcome::Stale { stored } => assert_eq!(stored, 2),
                    ReplaceOutcome::Written { previous } => assert_eq!(previous, None),
                }
                if let ReplaceOutcome::Written {
                    previous: Some(previous),
                } = high
                {
                    assert_eq!(previous.revision, 1);
                }
            });

            let stored = store
                .customer_networks_map()
                .get(customer_id)
                .unwrap()
                .unwrap();
            assert_eq!(stored.revision, 2);
            assert_eq!(stored.networks, higher);
        }
    }

    #[test]
    fn internal_groups_merge_intranet_and_gateway() {
        let intranet = network("office", NetworkType::Intranet, "10.0.0.0/8");
        let gateway = network("edge", NetworkType::Gateway, "192.168.0.0/24");
        let extranet = network("partner", NetworkType::Extranet, "172.16.0.0/12");
        let set = set_of(vec![intranet, extranet, gateway]);
        assert_eq!(
            set.internal_groups(),
            vec![HostNetworkGroup::new(
                vec![],
                vec![
                    "10.0.0.0/8".parse().unwrap(),
                    "192.168.0.0/24".parse().unwrap()
                ],
                vec![],
            )]
        );
    }

    fn set_of(networks: Vec<OwnedNetwork>) -> OwnedNetworkSet {
        OwnedNetworkSet {
            revision: 1,
            networks,
            updated_at: jiff::Timestamp::now(),
        }
    }

    fn ip(addr: &str) -> IpAddr {
        addr.parse().unwrap()
    }

    fn range(start: &str, end: &str) -> RangeInclusive<IpAddr> {
        ip(start)..=ip(end)
    }

    fn owned(name: &str, network_type: NetworkType, group: HostNetworkGroup) -> OwnedNetwork {
        OwnedNetwork {
            name: name.to_string(),
            network_type,
            group,
        }
    }

    fn range_network(
        name: &str,
        network_type: NetworkType,
        start: &str,
        end: &str,
    ) -> OwnedNetwork {
        owned(
            name,
            network_type,
            HostNetworkGroup::new(Vec::new(), Vec::new(), vec![range(start, end)]),
        )
    }

    fn ranges(ranges: &[(&str, &str)]) -> HostNetworkGroup {
        HostNetworkGroup::new(
            Vec::new(),
            Vec::new(),
            ranges
                .iter()
                .map(|(start, end)| range(start, end))
                .collect(),
        )
    }

    fn internal(networks: Vec<OwnedNetwork>) -> HostNetworkGroup {
        set_of(networks).internal_group()
    }

    #[test]
    fn an_extranet_network_inside_an_intranet_network_is_not_internal() {
        let group = internal(vec![
            network("office", NetworkType::Intranet, "10.0.0.0/8"),
            network("partner", NetworkType::Extranet, "10.200.0.0/16"),
        ]);
        assert_eq!(
            group,
            ranges(&[
                ("10.0.0.0", "10.199.255.255"),
                ("10.201.0.0", "10.255.255.255")
            ])
        );
        assert_eq!(group.hosts(), &[] as &[IpAddr]);
        assert_eq!(group.networks(), &[] as &[IpNet]);
        assert!(group.contains(ip("10.1.2.3")));
        assert!(!group.contains(ip("10.200.1.5")));
        assert!(group.contains(ip("10.199.255.255")));
        assert!(!group.contains(ip("10.200.0.0")));
        assert!(!group.contains(ip("10.200.255.255")));
        assert!(group.contains(ip("10.201.0.0")));
    }

    #[test]
    fn a_network_entry_covers_its_network_whatever_its_host_bits() {
        let group = internal(vec![
            network("office", NetworkType::Intranet, "10.1.2.3/8"),
            network("partner", NetworkType::Extranet, "10.200.0.0/16"),
        ]);
        assert_eq!(
            group,
            ranges(&[
                ("10.0.0.0", "10.199.255.255"),
                ("10.201.0.0", "10.255.255.255")
            ])
        );

        // Kept as it was stored, when nothing narrower decides against it.
        let group = internal(vec![network("office", NetworkType::Intranet, "10.1.2.3/8")]);
        assert_eq!(group.networks(), &["10.1.2.3/8".parse::<IpNet>().unwrap()]);
    }

    #[test]
    fn an_intranet_host_inside_an_extranet_network_is_kept_as_a_host() {
        let group = internal(vec![
            network("partner", NetworkType::Extranet, "198.51.100.0/24"),
            owned(
                "printer",
                NetworkType::Intranet,
                HostNetworkGroup::new(vec![ip("198.51.100.10")], Vec::new(), Vec::new()),
            ),
        ]);
        assert_eq!(
            group,
            HostNetworkGroup::new(vec![ip("198.51.100.10")], Vec::new(), Vec::new())
        );
        assert!(!group.contains(ip("198.51.100.11")));
    }

    #[test]
    fn without_overlap_the_internal_group_merges_intranet_and_gateway_groups() {
        let intranet = owned(
            "office",
            NetworkType::Intranet,
            HostNetworkGroup::new(
                vec![ip("10.0.0.9"), ip("192.168.0.1")],
                vec!["10.0.0.0/8".parse().unwrap()],
                vec![range("10.2.0.1", "10.2.0.9")],
            ),
        );
        let gateway = owned(
            "edge",
            NetworkType::Gateway,
            HostNetworkGroup::new(
                vec![ip("192.168.0.1")],
                vec!["192.168.0.0/24".parse().unwrap()],
                vec![range("2001:db8::1", "2001:db8::9")],
            ),
        );
        let extranet = owned(
            "partner",
            NetworkType::Extranet,
            HostNetworkGroup::new(
                vec![ip("192.0.2.1")],
                vec!["172.16.0.0/12".parse().unwrap()],
                vec![range("198.51.100.1", "198.51.100.9")],
            ),
        );
        let expected = merge_groups([&intranet.group, &gateway.group]);
        let group = internal(vec![intranet, extranet, gateway]);
        assert_eq!(group, expected);
    }

    #[test]
    fn an_internal_network_inside_an_extranet_network_is_internal() {
        for network_type in [NetworkType::Gateway, NetworkType::Intranet] {
            let group = internal(vec![
                network("partner", NetworkType::Extranet, "10.0.0.0/8"),
                network("edge", network_type, "10.1.0.0/16"),
            ]);
            assert_eq!(
                group,
                HostNetworkGroup::new(Vec::new(), vec!["10.1.0.0/16".parse().unwrap()], Vec::new()),
                "{network_type:?}"
            );
            assert!(!group.contains(ip("10.2.0.1")));
        }
    }

    #[test]
    fn a_tie_with_an_extranet_network_is_not_internal() {
        // A network and a range of the same width.
        let set = set_of(vec![
            network("office", NetworkType::Intranet, "192.0.2.0/24"),
            range_network("partner", NetworkType::Extranet, "192.0.2.0", "192.0.2.255"),
        ]);
        assert_eq!(set.internal_group(), HostNetworkGroup::default());
        assert_eq!(set.internal_groups(), Vec::new());

        // The same entry in an Intranet and an Extranet network.
        let set = set_of(vec![
            network("office", NetworkType::Intranet, "172.16.0.0/12"),
            network("partner", NetworkType::Extranet, "172.16.0.0/12"),
        ]);
        assert_eq!(set.internal_group(), HostNetworkGroup::default());

        // The same host.
        let host = || HostNetworkGroup::new(vec![ip("10.0.0.1")], Vec::new(), Vec::new());
        let set = set_of(vec![
            owned("office", NetworkType::Intranet, host()),
            owned("partner", NetworkType::Extranet, host()),
        ]);
        assert_eq!(set.internal_group(), HostNetworkGroup::default());

        // Two internal networks with the same entry stay internal.
        let set = set_of(vec![
            network("office", NetworkType::Intranet, "172.16.0.0/12"),
            network("lab", NetworkType::Intranet, "172.16.0.0/12"),
        ]);
        assert_eq!(
            set.internal_group(),
            HostNetworkGroup::new(
                Vec::new(),
                vec!["172.16.0.0/12".parse().unwrap()],
                Vec::new()
            )
        );
    }

    #[test]
    fn a_partial_overlap_is_decided_by_the_narrower_entry() {
        // The Intranet range is the narrower one where they overlap.
        let group = internal(vec![
            range_network("office", NetworkType::Intranet, "10.0.0.0", "10.0.0.255"),
            range_network("partner", NetworkType::Extranet, "10.0.0.128", "10.0.1.255"),
        ]);
        assert_eq!(group, ranges(&[("10.0.0.0", "10.0.0.255")]));

        // The Extranet network is.
        let group = internal(vec![
            range_network("office", NetworkType::Intranet, "10.0.0.0", "10.0.1.255"),
            network("partner", NetworkType::Extranet, "10.0.1.0/24"),
        ]);
        assert_eq!(group, ranges(&[("10.0.0.0", "10.0.0.255")]));
    }

    #[test]
    fn the_internal_addresses_of_dropped_entries_merge() {
        let group = internal(vec![
            network("office", NetworkType::Intranet, "10.0.0.0/16"),
            range_network("lab", NetworkType::Intranet, "10.0.0.0", "10.0.255.255"),
            network("partner", NetworkType::Extranet, "10.0.1.0/24"),
        ]);
        assert_eq!(
            group,
            ranges(&[("10.0.0.0", "10.0.0.255"), ("10.0.2.0", "10.0.255.255")])
        );
        assert_eq!(group.ip_ranges().len(), 2);

        // Adjacent dropped entries give one run.
        let group = internal(vec![
            range_network("a", NetworkType::Intranet, "10.0.0.0", "10.0.0.127"),
            range_network("b", NetworkType::Gateway, "10.0.0.128", "10.0.0.255"),
            range_network("partner", NetworkType::Extranet, "10.0.0.100", "10.0.0.150"),
        ]);
        assert_eq!(
            group,
            ranges(&[("10.0.0.0", "10.0.0.99"), ("10.0.0.151", "10.0.0.255")])
        );

        // A run of one address is still a range.
        let group = internal(vec![
            range_network("office", NetworkType::Intranet, "10.0.0.0", "10.0.0.2"),
            range_network("partner", NetworkType::Extranet, "10.0.0.0", "10.0.0.1"),
        ]);
        assert_eq!(group, ranges(&[("10.0.0.2", "10.0.0.2")]));
    }

    #[test]
    fn only_the_narrowest_entry_of_a_network_counts() {
        // The Extranet network's /24 is narrower than the Intranet /16, its /8
        // is wider.
        let group = internal(vec![
            network("office", NetworkType::Intranet, "10.1.0.0/16"),
            owned(
                "partner",
                NetworkType::Extranet,
                HostNetworkGroup::new(
                    Vec::new(),
                    vec![
                        "10.0.0.0/8".parse().unwrap(),
                        "10.1.5.0/24".parse().unwrap(),
                    ],
                    Vec::new(),
                ),
            ),
        ]);
        assert_eq!(
            group,
            ranges(&[("10.1.0.0", "10.1.4.255"), ("10.1.6.0", "10.1.255.255")])
        );
    }

    #[test]
    fn ipv6_is_decided_by_the_same_rule() {
        let group = internal(vec![
            network("office", NetworkType::Intranet, "2001:db8::/32"),
            network("partner", NetworkType::Extranet, "2001:db8:1::/48"),
        ]);
        assert_eq!(
            group,
            ranges(&[
                ("2001:db8::", "2001:db8:0:ffff:ffff:ffff:ffff:ffff"),
                ("2001:db8:2::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"),
            ])
        );

        // The whole space neither overflows a width nor an end.
        let group = internal(vec![
            network("everything", NetworkType::Intranet, "::/0"),
            network("partner", NetworkType::Extranet, "2001:db8::/32"),
        ]);
        assert_eq!(
            group,
            ranges(&[
                ("::", "2001:db7:ffff:ffff:ffff:ffff:ffff:ffff"),
                ("2001:db9::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            ])
        );

        // An extranet network at the end of an intranet network leaves only
        // the run before it.
        let group = internal(vec![
            network("office", NetworkType::Intranet, "fc00::/7"),
            network("partner", NetworkType::Extranet, "fdff::/16"),
        ]);
        assert_eq!(
            group,
            ranges(&[("fc00::", "fdfe:ffff:ffff:ffff:ffff:ffff:ffff:ffff")])
        );
        let group = internal(vec![
            network("office", NetworkType::Intranet, "10.0.0.0/8"),
            network("partner", NetworkType::Extranet, "10.255.255.0/24"),
        ]);
        assert_eq!(group, ranges(&[("10.0.0.0", "10.255.254.255")]));

        // Hosts and ranges.
        let group = internal(vec![
            owned(
                "office",
                NetworkType::Intranet,
                HostNetworkGroup::new(
                    vec![ip("2001:db8::1"), ip("2001:db8:1::5")],
                    Vec::new(),
                    vec![range("2001:db8::100", "2001:db8::1ff")],
                ),
            ),
            range_network(
                "partner",
                NetworkType::Extranet,
                "2001:db8::180",
                "2001:db8::1ff",
            ),
            network("lab", NetworkType::Extranet, "2001:db8:1::/48"),
        ]);
        assert_eq!(
            group,
            HostNetworkGroup::new(
                vec![ip("2001:db8::1"), ip("2001:db8:1::5")],
                Vec::new(),
                vec![range("2001:db8::100", "2001:db8::17f")],
            )
        );
    }

    #[test]
    fn the_families_are_decided_separately() {
        let v6 = network("office", NetworkType::Intranet, "2001:db8::/32");
        let group = internal(vec![
            v6.clone(),
            network("partner", NetworkType::Extranet, "10.0.0.0/8"),
        ]);
        assert_eq!(group, v6.group);

        let v4 = network("office", NetworkType::Intranet, "10.0.0.0/8");
        let group = internal(vec![
            v4.clone(),
            network("partner", NetworkType::Extranet, "fc00::/7"),
        ]);
        assert_eq!(group, v4.group);

        // An IPv4-mapped IPv6 address is an IPv6 address.
        let group = internal(vec![
            v4.clone(),
            network("partner", NetworkType::Extranet, "::ffff:10.0.0.0/104"),
        ]);
        assert_eq!(group, v4.group);
        let group = internal(vec![
            network("office", NetworkType::Intranet, "::ffff:10.0.0.0/104"),
            network("partner", NetworkType::Extranet, "10.0.0.0/16"),
        ]);
        assert_eq!(
            group.networks(),
            &["::ffff:10.0.0.0/104".parse::<IpNet>().unwrap()]
        );
    }

    #[test]
    fn a_malformed_range_covers_no_address() {
        let malformed = || {
            vec![
                ip("10.0.0.255")..=ip("10.0.0.0"),
                ip("10.0.0.0")..=ip("2001:db8::1"),
            ]
        };
        let set = set_of(vec![owned(
            "office",
            NetworkType::Intranet,
            HostNetworkGroup::new(Vec::new(), Vec::new(), malformed()),
        )]);
        assert_eq!(set.internal_group(), HostNetworkGroup::default());
        assert_eq!(set.internal_groups(), Vec::new());

        let office = network("office", NetworkType::Intranet, "10.0.0.0/24");
        let group = internal(vec![
            office.clone(),
            owned(
                "partner",
                NetworkType::Extranet,
                HostNetworkGroup::new(Vec::new(), Vec::new(), malformed()),
            ),
        ]);
        assert_eq!(group, office.group);
    }

    #[test]
    fn internal_groups_hold_the_internal_group_or_nothing() {
        let set = set_of(vec![
            network("office", NetworkType::Intranet, "10.0.0.0/8"),
            network("partner", NetworkType::Extranet, "10.200.0.0/16"),
        ]);
        assert_eq!(set.internal_groups(), vec![set.internal_group()]);

        for networks in [
            Vec::new(),
            vec![network("partner", NetworkType::Extranet, "10.0.0.0/8")],
            vec![owned(
                "office",
                NetworkType::Intranet,
                HostNetworkGroup::default(),
            )],
            vec![
                network("office", NetworkType::Intranet, "10.0.0.0/24"),
                range_network("partner", NetworkType::Extranet, "10.0.0.0", "10.0.0.255"),
            ],
        ] {
            assert_eq!(
                set_of(networks.clone()).internal_groups(),
                Vec::new(),
                "{networks:?}"
            );
        }
    }

    /// Returns the `IPv4` entries of `group` as `(first, last)` numbers.
    fn v4_entries(group: &HostNetworkGroup) -> Vec<(u32, u32)> {
        let span = |start: IpAddr, end: IpAddr| match (start, end) {
            (IpAddr::V4(start), IpAddr::V4(end)) => (u32::from(start), u32::from(end)),
            _ => unreachable!("only IPv4 entries are generated"),
        };
        group
            .hosts()
            .iter()
            .map(|host| span(*host, *host))
            .chain(
                group
                    .networks()
                    .iter()
                    .map(|net| span(net.network(), net.broadcast())),
            )
            .chain(
                group
                    .ip_ranges()
                    .iter()
                    .map(|range| span(*range.start(), *range.end())),
            )
            .collect()
    }

    /// Decides `addr` by the rule, address by address.
    fn decided_internal(set: &OwnedNetworkSet, addr: u32) -> bool {
        let narrowest: Vec<(u32, bool)> = set
            .networks
            .iter()
            .filter_map(|network| {
                v4_entries(&network.group)
                    .into_iter()
                    .filter(|(start, end)| *start <= addr && addr <= *end)
                    .map(|(start, end)| end - start)
                    .min()
                    .map(|width| (width, is_internal_type(network.network_type)))
            })
            .collect();
        let Some(width) = narrowest.iter().map(|(width, _)| *width).min() else {
            return false;
        };
        narrowest
            .iter()
            .filter(|(w, _)| *w == width)
            .all(|(_, internal)| *internal)
    }

    /// Returns a random set of up to five networks, each with up to three
    /// entries in the 64 addresses from `base`.
    fn random_set(base: u32, next: &mut impl FnMut(u32) -> u32) -> OwnedNetworkSet {
        let addr = |offset: u32| IpAddr::V4(Ipv4Addr::from(base + offset));
        let mut networks = Vec::new();
        for n in 0..=next(4) {
            let network_type = match next(3) {
                0 => NetworkType::Intranet,
                1 => NetworkType::Gateway,
                _ => NetworkType::Extranet,
            };
            let mut hosts = Vec::new();
            let mut nets = Vec::new();
            let mut ip_ranges = Vec::new();
            for _ in 0..=next(2) {
                match next(3) {
                    0 => hosts.push(addr(next(64))),
                    1 => {
                        let prefix = 26 + u8::try_from(next(7)).unwrap();
                        nets.push(IpNet::new(addr(next(64)), prefix).unwrap());
                    }
                    _ => {
                        let start = next(64);
                        let end = start + next(64 - start);
                        ip_ranges.push(addr(start)..=addr(end));
                    }
                }
            }
            networks.push(owned(
                &format!("n{n}"),
                network_type,
                HostNetworkGroup::new(hosts, nets, ip_ranges),
            ));
        }
        set_of(networks)
    }

    /// Compares the internal group of random sets of entries with the rule
    /// applied to every address of a small space.
    #[test]
    fn the_internal_group_holds_exactly_the_addresses_the_rule_decides() {
        // The window and the addresses past either end stay inside 10/8.
        let base = u32::from(Ipv4Addr::new(10, 0, 1, 0));
        let mut state = 0x2545_f491_u32;
        let mut next = |bound: u32| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state % bound
        };

        for round in 0..500 {
            let set = random_set(base, &mut next);
            let group = set.internal_group();
            // A few addresses past either end, which no entry covers.
            for addr in base - 2..base + 66 {
                assert_eq!(
                    group.contains(IpAddr::V4(Ipv4Addr::from(addr))),
                    decided_internal(&set, addr),
                    "round {round}, {}: {set:?} gave {group:?}",
                    Ipv4Addr::from(addr)
                );
            }
            // An internal entry is kept exactly when all its addresses are
            // internal; a range may also be the run of a dropped entry.
            for network in &set.networks {
                if !is_internal_type(network.network_type) {
                    continue;
                }
                let all_internal =
                    |net: &(u32, u32)| (net.0..=net.1).all(|addr| decided_internal(&set, addr));
                for host in network.group.hosts() {
                    let IpAddr::V4(addr) = host else {
                        unreachable!("only IPv4 entries are generated")
                    };
                    assert_eq!(
                        group.contains_host(*host),
                        decided_internal(&set, u32::from(*addr)),
                        "round {round}: {host}"
                    );
                }
                for net in network.group.networks() {
                    let span = v4_entries(&HostNetworkGroup::new(vec![], vec![*net], vec![]));
                    assert_eq!(
                        group.contains_network(net),
                        span.iter().all(all_internal),
                        "round {round}: {net}"
                    );
                }
                for range in network.group.ip_ranges() {
                    let span =
                        v4_entries(&HostNetworkGroup::new(vec![], vec![], vec![range.clone()]));
                    if span.iter().all(all_internal) {
                        assert!(group.contains_ip_range(range), "round {round}: {range:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn merged_group_includes_every_type_sorted_and_deduplicated() {
        let host_a: IpAddr = "10.0.0.2".parse().unwrap();
        let host_b: IpAddr = "10.0.0.1".parse().unwrap();
        let range_a = "10.9.0.5".parse().unwrap()..="10.9.0.9".parse().unwrap();
        let range_b = "10.8.0.1".parse().unwrap()..="10.8.0.3".parse().unwrap();
        let set = OwnedNetworkSet {
            revision: 1,
            networks: vec![
                OwnedNetwork {
                    name: "a".to_string(),
                    network_type: NetworkType::Extranet,
                    group: HostNetworkGroup::new(
                        vec![host_a, host_b],
                        vec!["172.16.0.0/12".parse().unwrap()],
                        vec![range_a.clone()],
                    ),
                },
                OwnedNetwork {
                    name: "b".to_string(),
                    network_type: NetworkType::Intranet,
                    group: HostNetworkGroup::new(
                        vec![host_a],
                        vec![
                            "10.0.0.0/8".parse().unwrap(),
                            "172.16.0.0/12".parse().unwrap(),
                        ],
                        vec![range_b.clone(), range_a.clone()],
                    ),
                },
                OwnedNetwork {
                    name: "c".to_string(),
                    network_type: NetworkType::Gateway,
                    group: HostNetworkGroup::new(Vec::new(), Vec::new(), Vec::new()),
                },
            ],
            updated_at: jiff::Timestamp::now(),
        };

        let merged = set.merged_group();
        assert_eq!(merged.hosts(), &[host_b, host_a]);
        assert_eq!(
            merged.networks(),
            &[
                "10.0.0.0/8".parse().unwrap(),
                "172.16.0.0/12".parse().unwrap()
            ]
        );
        assert_eq!(merged.ip_ranges(), &[range_b, range_a]);
    }
}
