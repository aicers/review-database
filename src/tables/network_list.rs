//! The `network lists` table.
//!
//! Each row holds one customer's allowlist and blocklist, as the writer defined
//! them outside this database, keyed by the customer ID alone. The table keeps
//! no other customer data: the ID is only a key.

use std::collections::HashSet;

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use rocksdb::{IteratorMode, OptimisticTransactionDB, Transaction};
use serde::{Deserialize, Serialize};

use super::owned_network::merge_groups;
use crate::{EXCLUSIVE, HostNetworkGroup, Map};

/// A customer's allowlist and blocklist, as last replaced.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NetworkListSet {
    /// The writer's revision of this set. A replacement with a lower revision
    /// is refused.
    pub revision: u64,
    pub allowlist: Vec<NetworkListEntry>,
    pub blocklist: Vec<NetworkListEntry>,
    /// When the set was last written.
    pub updated_at: DateTime<Utc>,
}

impl NetworkListSet {
    /// Returns one group holding the hosts, networks and ranges of every
    /// allowlist entry, sorted and deduplicated.
    #[must_use]
    pub fn merged_allowlist(&self) -> HostNetworkGroup {
        merge_groups(self.allowlist.iter().map(|entry| &entry.group))
    }

    /// Returns one group holding the hosts, networks and ranges of every
    /// blocklist entry, sorted and deduplicated.
    #[must_use]
    pub fn merged_blocklist(&self) -> HostNetworkGroup {
        merge_groups(self.blocklist.iter().map(|entry| &entry.group))
    }
}

/// One allowlist or blocklist entry of a customer.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NetworkListEntry {
    /// The name of the entry, unique within its list.
    pub name: String,
    pub group: HostNetworkGroup,
}

/// The result of [`NetworkListTable::replace`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum NetworkListReplaceOutcome {
    /// The set was written. `previous` is the row that was overwritten, read in
    /// the same transaction, or `None` if there was none.
    Written { previous: Option<NetworkListSet> },
    /// Nothing was written, because the stored row has the higher revision
    /// `stored`.
    Stale { stored: u64 },
}

/// The `network lists` table, holding one [`NetworkListSet`] per customer.
///
/// A row is keyed by the customer ID in big-endian byte order, so the table
/// iterates in ascending customer ID order.
#[derive(Clone)]
pub struct NetworkListTable<'d> {
    map: Map<'d>,
}

impl<'d> NetworkListTable<'d> {
    /// Opens the `network lists` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::NETWORK_LISTS).map(|map| Self { map })
    }

    /// Returns the allowlist and blocklist of the customer `customer_id`, or
    /// `None` if none were stored for it.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails or the stored row cannot
    /// be decoded.
    pub fn get(&self, customer_id: u32) -> Result<Option<NetworkListSet>> {
        self.map
            .get(&customer_id.to_be_bytes())?
            .map(|value| decode(customer_id, value.as_ref()))
            .transpose()
    }

    /// Replaces the allowlist and blocklist of the customer `customer_id` with
    /// `allowlist` and `blocklist`, recorded at `revision` and the current
    /// time.
    ///
    /// A stored row with a higher revision is left as it is, and
    /// [`NetworkListReplaceOutcome::Stale`] reports its revision. Otherwise the
    /// row is written, including when the stored revision is equal, so
    /// resending the same revision is idempotent. The comparison and the write
    /// are one transaction, retried on a conflicting write, so of two
    /// concurrent replacements the higher revision is the one that ends up
    /// stored.
    ///
    /// # Errors
    ///
    /// Returns an error if two entries in `allowlist`, or two in `blocklist`,
    /// share a name, compared exactly, in which case nothing is written; if the
    /// stored row cannot be decoded; or if the database operation fails.
    pub fn replace(
        &self,
        customer_id: u32,
        revision: u64,
        allowlist: Vec<NetworkListEntry>,
        blocklist: Vec<NetworkListEntry>,
    ) -> Result<NetworkListReplaceOutcome> {
        check_unique_names(customer_id, "allowlist", &allowlist)?;
        check_unique_names(customer_id, "blocklist", &blocklist)?;

        let set = NetworkListSet {
            revision,
            allowlist,
            blocklist,
            updated_at: Utc::now(),
        };
        let value = super::serialize(&set).context("failed to serialize network lists")?;
        loop {
            let txn = self.map.db.transaction();
            let outcome = self.replace_in(&txn, customer_id, revision, &value)?;
            if let NetworkListReplaceOutcome::Stale { .. } = outcome {
                return Ok(outcome);
            }
            match txn.commit() {
                Ok(()) => return Ok(outcome),
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).with_context(|| {
                            format!("failed to replace network lists of customer {customer_id}")
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
    ) -> Result<NetworkListReplaceOutcome> {
        let key = customer_id.to_be_bytes();
        let previous = txn
            .get_for_update_cf(self.map.cf, key, EXCLUSIVE)
            .with_context(|| format!("failed to read network lists of customer {customer_id}"))?
            .map(|stored| decode(customer_id, &stored))
            .transpose()?;
        if let Some(stored) = &previous
            && revision < stored.revision
        {
            return Ok(NetworkListReplaceOutcome::Stale {
                stored: stored.revision,
            });
        }
        txn.put_cf(self.map.cf, key, value)
            .with_context(|| format!("failed to write network lists of customer {customer_id}"))?;
        Ok(NetworkListReplaceOutcome::Written { previous })
    }

    /// Removes the allowlist and blocklist of the customer `customer_id`.
    ///
    /// Returns the removed set, read in the same transaction as the deletion,
    /// or `None` if there was no row. Removing a missing row is not an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored row cannot be decoded, in which case it
    /// is not removed, or if the database operation fails.
    pub fn remove(&self, customer_id: u32) -> Result<Option<NetworkListSet>> {
        let key = customer_id.to_be_bytes();
        loop {
            let txn = self.map.db.transaction();
            let Some(removed) = txn
                .get_for_update_cf(self.map.cf, key, EXCLUSIVE)
                .with_context(|| format!("failed to read network lists of customer {customer_id}"))?
                .map(|stored| decode(customer_id, &stored))
                .transpose()?
            else {
                return Ok(None);
            };
            txn.delete_cf(self.map.cf, key).with_context(|| {
                format!("failed to remove network lists of customer {customer_id}")
            })?;
            match txn.commit() {
                Ok(()) => return Ok(Some(removed)),
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).with_context(|| {
                            format!("failed to remove network lists of customer {customer_id}")
                        });
                    }
                }
            }
        }
    }

    /// Returns an iterator over every row, in ascending customer ID order.
    pub fn iter(&self) -> impl Iterator<Item = Result<(u32, NetworkListSet)>> + '_ {
        self.map
            .db
            .iterator_cf(self.map.cf, IteratorMode::Start)
            .map(|entry| {
                let (key, value) = entry.context("failed to read network lists")?;
                let key = <[u8; 4]>::try_from(key.as_ref()).map_err(|_| {
                    anyhow!(
                        "invalid network lists key {}",
                        data_encoding::HEXLOWER.encode(&key)
                    )
                })?;
                let customer_id = u32::from_be_bytes(key);
                Ok((customer_id, decode(customer_id, &value)?))
            })
    }
}

/// Returns an error naming `list` and the name if two of its `entries` share a
/// name, compared exactly.
fn check_unique_names(customer_id: u32, list: &str, entries: &[NetworkListEntry]) -> Result<()> {
    let mut names = HashSet::with_capacity(entries.len());
    if let Some(duplicate) = entries
        .iter()
        .find(|entry| !names.insert(entry.name.as_str()))
    {
        bail!(
            "duplicate {list} entry name {:?} for customer {customer_id}",
            duplicate.name
        );
    }
    Ok(())
}

/// Decodes the stored row of `customer_id`.
fn decode(customer_id: u32, value: &[u8]) -> Result<NetworkListSet> {
    super::deserialize(value)
        .with_context(|| format!("failed to decode network lists of customer {customer_id}"))
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        sync::Arc,
    };

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

    fn entry(name: &str, cidr: &str) -> NetworkListEntry {
        NetworkListEntry {
            name: name.to_string(),
            group: HostNetworkGroup::new(Vec::new(), vec![cidr.parse().unwrap()], Vec::new()),
        }
    }

    fn raw(table: &NetworkListTable, customer_id: u32) -> Option<Vec<u8>> {
        table
            .map
            .get(&customer_id.to_be_bytes())
            .unwrap()
            .map(|value| value.as_ref().to_vec())
    }

    fn written(previous: Option<NetworkListSet>) -> NetworkListReplaceOutcome {
        NetworkListReplaceOutcome::Written { previous }
    }

    #[test]
    fn fresh_store_has_an_empty_table() {
        let (_permit, store) = setup_store();
        let table = store.network_lists_map();
        assert_eq!(table.iter().count(), 0);
        assert_eq!(table.get(0).unwrap(), None);
    }

    #[test]
    fn replace_and_get() {
        let (_permit, store) = setup_store();
        let table = store.network_lists_map();
        assert_eq!(table.get(7).unwrap(), None);

        let allowlist = vec![
            entry("office", "10.0.0.0/8"),
            entry("edge", "192.168.0.0/24"),
        ];
        let blocklist = vec![entry("attacker", "203.0.113.0/24")];
        let before = Utc::now();
        assert_eq!(
            table
                .replace(7, 3, allowlist.clone(), blocklist.clone())
                .unwrap(),
            written(None)
        );
        let after = Utc::now();

        let stored = table.get(7).unwrap().unwrap();
        assert_eq!(stored.revision, 3);
        assert_eq!(stored.allowlist, allowlist);
        assert_eq!(stored.blocklist, blocklist);
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
        let table = store.network_lists_map();

        assert_eq!(
            table.replace(1, 0, Vec::new(), Vec::new()).unwrap(),
            written(None)
        );
        assert_eq!(table.get(1).unwrap().unwrap().revision, 0);
    }

    #[test]
    fn lower_revision_is_stale_and_writes_nothing() {
        let (_permit, store) = setup_store();
        let table = store.network_lists_map();

        table
            .replace(
                1,
                5,
                vec![entry("office", "10.0.0.0/8")],
                vec![entry("attacker", "203.0.113.0/24")],
            )
            .unwrap();
        let before = raw(&table, 1).unwrap();

        let outcome = table
            .replace(
                1,
                4,
                vec![entry("other", "10.1.0.0/16")],
                vec![entry("other", "198.51.100.0/24")],
            )
            .unwrap();
        assert_eq!(outcome, NetworkListReplaceOutcome::Stale { stored: 5 });
        assert_eq!(raw(&table, 1).unwrap(), before);
    }

    #[test]
    fn equal_or_higher_revision_overwrites_and_returns_previous() {
        let (_permit, store) = setup_store();
        let table = store.network_lists_map();

        table
            .replace(
                1,
                5,
                vec![entry("office", "10.0.0.0/8")],
                vec![entry("attacker", "203.0.113.0/24")],
            )
            .unwrap();
        let stored_first = table.get(1).unwrap().unwrap();

        // An equal revision overwrites: a retried send is idempotent.
        let outcome = table
            .replace(
                1,
                5,
                stored_first.allowlist.clone(),
                stored_first.blocklist.clone(),
            )
            .unwrap();
        assert_eq!(outcome, written(Some(stored_first.clone())));
        let stored_again = table.get(1).unwrap().unwrap();
        assert_eq!(stored_again.revision, 5);
        assert_eq!(stored_again.allowlist, stored_first.allowlist);
        assert_eq!(stored_again.blocklist, stored_first.blocklist);

        let allowlist = vec![entry("lab", "10.2.0.0/16")];
        let blocklist = vec![entry("scanner", "198.51.100.0/24")];
        let outcome = table
            .replace(1, 6, allowlist.clone(), blocklist.clone())
            .unwrap();
        assert_eq!(outcome, written(Some(stored_again)));
        let stored_second = table.get(1).unwrap().unwrap();
        assert_eq!(stored_second.revision, 6);
        assert_eq!(stored_second.allowlist, allowlist);
        assert_eq!(stored_second.blocklist, blocklist);
    }

    #[test]
    fn duplicate_allowlist_names_are_rejected_and_nothing_is_written() {
        let (_permit, store) = setup_store();
        let table = store.network_lists_map();

        let duplicates = vec![
            entry("office", "10.0.0.0/8"),
            entry("office", "10.1.0.0/16"),
        ];
        let err = table
            .replace(1, 1, duplicates.clone(), Vec::new())
            .unwrap_err()
            .to_string();
        assert!(err.contains("allowlist"), "{err}");
        assert!(err.contains("\"office\""), "{err}");
        assert_eq!(raw(&table, 1), None);

        table.replace(1, 1, Vec::new(), Vec::new()).unwrap();
        let before = raw(&table, 1).unwrap();
        assert!(table.replace(1, 2, duplicates, Vec::new()).is_err());
        assert_eq!(raw(&table, 1).unwrap(), before);

        // Names are compared exactly, so differing case is not a duplicate.
        let distinct = vec![
            entry("office", "10.0.0.0/8"),
            entry("Office", "10.1.0.0/16"),
        ];
        table.replace(1, 3, distinct, Vec::new()).unwrap();
    }

    #[test]
    fn duplicate_blocklist_names_are_rejected_and_nothing_is_written() {
        let (_permit, store) = setup_store();
        let table = store.network_lists_map();

        let duplicates = vec![
            entry("attacker", "203.0.113.0/24"),
            entry("attacker", "198.51.100.0/24"),
        ];
        let err = table
            .replace(1, 1, Vec::new(), duplicates.clone())
            .unwrap_err()
            .to_string();
        assert!(err.contains("blocklist"), "{err}");
        assert!(err.contains("\"attacker\""), "{err}");
        assert_eq!(raw(&table, 1), None);

        table.replace(1, 1, Vec::new(), Vec::new()).unwrap();
        let before = raw(&table, 1).unwrap();
        assert!(table.replace(1, 2, Vec::new(), duplicates).is_err());
        assert_eq!(raw(&table, 1).unwrap(), before);

        // Names are compared exactly, so differing case is not a duplicate.
        let distinct = vec![
            entry("attacker", "203.0.113.0/24"),
            entry("Attacker", "198.51.100.0/24"),
        ];
        table.replace(1, 3, Vec::new(), distinct).unwrap();
    }

    #[test]
    fn same_name_in_both_lists_is_accepted() {
        let (_permit, store) = setup_store();
        let table = store.network_lists_map();

        let allowlist = vec![entry("shared", "10.0.0.0/8")];
        let blocklist = vec![entry("shared", "203.0.113.0/24")];
        table
            .replace(1, 1, allowlist.clone(), blocklist.clone())
            .unwrap();
        let stored = table.get(1).unwrap().unwrap();
        assert_eq!(stored.allowlist, allowlist);
        assert_eq!(stored.blocklist, blocklist);
    }

    #[test]
    fn empty_network_list_is_stored() {
        let (_permit, store) = setup_store();
        let table = store.network_lists_map();

        table
            .replace(
                1,
                1,
                vec![entry("office", "10.0.0.0/8")],
                vec![entry("attacker", "203.0.113.0/24")],
            )
            .unwrap();
        table.replace(1, 2, Vec::new(), Vec::new()).unwrap();
        let stored = table.get(1).unwrap().unwrap();
        assert_eq!(stored.revision, 2);
        assert_eq!(stored.allowlist, Vec::new());
        assert_eq!(stored.blocklist, Vec::new());
    }

    #[test]
    fn remove_returns_the_removed_set() {
        let (_permit, store) = setup_store();
        let table = store.network_lists_map();

        table
            .replace(
                1,
                1,
                vec![entry("office", "10.0.0.0/8")],
                vec![entry("attacker", "203.0.113.0/24")],
            )
            .unwrap();
        table.replace(2, 1, Vec::new(), Vec::new()).unwrap();
        let stored = table.get(1).unwrap().unwrap();

        assert_eq!(table.remove(1).unwrap(), Some(stored));
        assert_eq!(table.remove(1).unwrap(), None);
        assert_eq!(table.get(1).unwrap(), None);
        assert!(table.get(2).unwrap().is_some());
        assert_eq!(table.remove(3).unwrap(), None);
    }

    #[test]
    fn undecodable_row_is_not_removed() {
        let (_permit, store) = setup_store();
        let table = store.network_lists_map();

        table
            .map
            .db
            .put_cf(table.map.cf, 1u32.to_be_bytes(), [0xff; 3])
            .unwrap();
        assert!(table.remove(1).is_err());
        assert_eq!(raw(&table, 1), Some(vec![0xff; 3]));
    }

    #[test]
    fn iter_is_in_ascending_customer_id_order() {
        let (_permit, store) = setup_store();
        let table = store.network_lists_map();

        // Little-endian keys would order these 16_777_216, 256, 1, u32::MAX.
        let ids = [u32::MAX, 16_777_216, 1, 256, 0x00FF_FFFF];
        for (revision, id) in (1..).zip(ids) {
            table.replace(id, revision, Vec::new(), Vec::new()).unwrap();
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
        let table = store.network_lists_map();

        let start = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1));
        let end = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0xff));
        let allowlist = vec![NetworkListEntry {
            name: "v6".to_string(),
            group: HostNetworkGroup::new(
                vec![
                    IpAddr::V6(Ipv6Addr::LOCALHOST),
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                ],
                vec!["2001:db8::/32".parse().unwrap()],
                vec![start..=end],
            ),
        }];
        let blocklist = vec![NetworkListEntry {
            name: "v6".to_string(),
            group: HostNetworkGroup::new(
                Vec::new(),
                vec!["2001:db8:ffff::/48".parse().unwrap()],
                Vec::new(),
            ),
        }];
        table
            .replace(1, 1, allowlist.clone(), blocklist.clone())
            .unwrap();
        let stored = table.get(1).unwrap().unwrap();
        assert_eq!(stored.allowlist, allowlist);
        assert_eq!(stored.blocklist, blocklist);
    }

    /// A replacement whose read is overtaken by another committed write fails
    /// to commit, so the retry in `replace` reads the row again.
    #[test]
    fn conflicting_write_is_detected_at_commit() {
        let (_permit, store) = setup_store();
        let table = store.network_lists_map();

        let value = super::super::serialize(&NetworkListSet {
            revision: 1,
            allowlist: Vec::new(),
            blocklist: Vec::new(),
            updated_at: Utc::now(),
        })
        .unwrap();
        let txn = table.map.db.transaction();
        assert_eq!(table.replace_in(&txn, 1, 1, &value).unwrap(), written(None));

        table.replace(1, 2, Vec::new(), Vec::new()).unwrap();
        let conflict = txn.commit().unwrap_err();
        assert!(conflict.as_ref().starts_with("Resource busy:"));
        assert_eq!(table.get(1).unwrap().unwrap().revision, 2);
    }

    #[test]
    fn concurrent_replacements_keep_the_higher_revision() {
        let (_permit, store) = setup_store();

        for round in 0..20 {
            let customer_id = round;
            let lower = vec![entry("lower", "10.0.0.0/8")];
            let higher = vec![entry("higher", "10.1.0.0/16")];
            std::thread::scope(|scope| {
                let low = scope.spawn(|| {
                    store
                        .network_lists_map()
                        .replace(customer_id, 1, lower.clone(), lower)
                        .unwrap()
                });
                let high = scope.spawn(|| {
                    store
                        .network_lists_map()
                        .replace(customer_id, 2, higher.clone(), higher.clone())
                        .unwrap()
                });
                let low = low.join().unwrap();
                let high = high.join().unwrap();
                // Whichever ran second saw the other's row.
                match low {
                    NetworkListReplaceOutcome::Stale { stored } => assert_eq!(stored, 2),
                    NetworkListReplaceOutcome::Written { previous } => {
                        assert_eq!(previous, None);
                    }
                }
                if let NetworkListReplaceOutcome::Written {
                    previous: Some(previous),
                } = high
                {
                    assert_eq!(previous.revision, 1);
                }
            });

            let stored = store.network_lists_map().get(customer_id).unwrap().unwrap();
            assert_eq!(stored.revision, 2);
            assert_eq!(stored.allowlist, higher);
            assert_eq!(stored.blocklist, higher);
        }
    }

    #[test]
    fn merged_lists_are_separate_sorted_and_deduplicated() {
        let host_a: IpAddr = "10.0.0.2".parse().unwrap();
        let host_b: IpAddr = "10.0.0.1".parse().unwrap();
        let blocked_host: IpAddr = "203.0.113.7".parse().unwrap();
        let range_a = "10.9.0.5".parse().unwrap()..="10.9.0.9".parse().unwrap();
        let range_b = "10.8.0.1".parse().unwrap()..="10.8.0.3".parse().unwrap();
        let blocked_range = "198.51.100.1".parse().unwrap()..="198.51.100.9".parse().unwrap();
        let set = NetworkListSet {
            revision: 1,
            allowlist: vec![
                NetworkListEntry {
                    name: "a".to_string(),
                    group: HostNetworkGroup::new(
                        vec![host_a, host_b],
                        vec!["172.16.0.0/12".parse().unwrap()],
                        vec![range_a.clone()],
                    ),
                },
                NetworkListEntry {
                    name: "b".to_string(),
                    group: HostNetworkGroup::new(
                        vec![host_a],
                        vec![
                            "10.0.0.0/8".parse().unwrap(),
                            "172.16.0.0/12".parse().unwrap(),
                        ],
                        vec![range_b.clone(), range_a.clone()],
                    ),
                },
                NetworkListEntry {
                    name: "c".to_string(),
                    group: HostNetworkGroup::new(Vec::new(), Vec::new(), Vec::new()),
                },
            ],
            blocklist: vec![
                NetworkListEntry {
                    name: "a".to_string(),
                    group: HostNetworkGroup::new(
                        vec![blocked_host],
                        vec!["203.0.113.0/24".parse().unwrap()],
                        Vec::new(),
                    ),
                },
                NetworkListEntry {
                    name: "b".to_string(),
                    group: HostNetworkGroup::new(
                        vec![blocked_host],
                        Vec::new(),
                        vec![blocked_range.clone()],
                    ),
                },
            ],
            updated_at: Utc::now(),
        };

        let allowlist = set.merged_allowlist();
        assert_eq!(allowlist.hosts(), &[host_b, host_a]);
        assert_eq!(
            allowlist.networks(),
            &[
                "10.0.0.0/8".parse().unwrap(),
                "172.16.0.0/12".parse().unwrap()
            ]
        );
        assert_eq!(allowlist.ip_ranges(), &[range_b, range_a]);
        assert!(!allowlist.contains(blocked_host));

        let blocklist = set.merged_blocklist();
        assert_eq!(blocklist.hosts(), &[blocked_host]);
        assert_eq!(blocklist.networks(), &["203.0.113.0/24".parse().unwrap()]);
        assert_eq!(blocklist.ip_ranges(), &[blocked_range]);
        assert!(!blocklist.contains(host_a));
        assert!(!blocklist.contains(host_b));
    }
}
