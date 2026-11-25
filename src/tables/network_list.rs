//! The `network lists` table.
//!
//! Each row holds one customer's exclusion list and watchlist, as the writer
//! defined them outside this database, keyed by the customer ID alone. The
//! table keeps no other customer data: the ID is only a key.

use std::collections::HashSet;

use anyhow::{Context, Result, anyhow, bail};
use jiff::Timestamp;
use rocksdb::{IteratorMode, OptimisticTransactionDB, Transaction};
use serde::{Deserialize, Serialize};

use crate::{EXCLUSIVE, HostNetworkGroup, Map};

/// A customer's exclusion list and watchlist, as last replaced.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NetworkListSet {
    /// The writer's revision of this set. A replacement with a lower revision
    /// is refused.
    pub revision: u64,
    pub exclusion_list: Vec<NetworkListEntry>,
    pub watchlist: Vec<NetworkListEntry>,
    /// When the set was last written.
    #[serde(with = "crate::timestamp::ts_nanoseconds_saturating")]
    pub updated_at: Timestamp,
}

/// One exclusion list or watchlist entry of a customer.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NetworkListEntry {
    /// The writer's ID of the entry, stored as given.
    ///
    /// The writer assigns it when the entry is created, keeps it across every
    /// later replacement, even when the entry is renamed, and never reuses it
    /// after the entry is deleted. This table neither assigns nor checks it.
    pub id: u64,
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

    /// Returns the exclusion list and watchlist of the customer
    /// `customer_id`, or `None` if none were stored for it.
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

    /// Returns the exclusion list entries of the customer `customer_id`, with
    /// their IDs, names and groups, in the order of the last accepted
    /// replacement.
    ///
    /// Returns an empty vector if no row is stored for the customer.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails or the stored row cannot
    /// be decoded.
    pub fn exclusion_list_items(&self, customer_id: u32) -> Result<Vec<NetworkListEntry>> {
        Ok(self
            .get(customer_id)?
            .map_or_default(|set| set.exclusion_list))
    }

    /// Returns the watchlist entries of the customer `customer_id`, with their
    /// IDs, names and groups, in the order of the last accepted replacement.
    ///
    /// Returns an empty vector if no row is stored for the customer.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails or the stored row cannot
    /// be decoded.
    pub fn watchlist_items(&self, customer_id: u32) -> Result<Vec<NetworkListEntry>> {
        Ok(self.get(customer_id)?.map_or_default(|set| set.watchlist))
    }

    /// Replaces the exclusion list and watchlist of the customer
    /// `customer_id` with `exclusion_list` and `watchlist`, recorded at
    /// `revision` and the current time.
    ///
    /// Each entry is stored with its `id` exactly as given: the table never
    /// assigns, renumbers or checks IDs, so a replacement that carries an
    /// entry under the same ID stores that ID with the name and group that
    /// come with it.
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
    /// Returns an error if two entries in `exclusion_list`, or two in
    /// `watchlist`, share a name, compared exactly, in which case nothing is
    /// written; if the stored row cannot be decoded; or if the database
    /// operation fails.
    pub fn replace(
        &self,
        customer_id: u32,
        revision: u64,
        exclusion_list: Vec<NetworkListEntry>,
        watchlist: Vec<NetworkListEntry>,
    ) -> Result<NetworkListReplaceOutcome> {
        check_unique_names(customer_id, "exclusion list", &exclusion_list)?;
        check_unique_names(customer_id, "watchlist", &watchlist)?;

        let set = NetworkListSet {
            revision,
            exclusion_list,
            watchlist,
            updated_at: Timestamp::now(),
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

    /// Removes the exclusion list and watchlist of the customer `customer_id`.
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

    fn entry(id: u64, name: &str, cidr: &str) -> NetworkListEntry {
        NetworkListEntry {
            id,
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

        let exclusion_list = vec![
            entry(1, "office", "10.0.0.0/8"),
            entry(2, "edge", "192.168.0.0/24"),
        ];
        let watchlist = vec![entry(3, "attacker", "203.0.113.0/24")];
        let before = jiff::Timestamp::now();
        assert_eq!(
            table
                .replace(7, 3, exclusion_list.clone(), watchlist.clone())
                .unwrap(),
            written(None)
        );
        let after = jiff::Timestamp::now();

        let stored = table.get(7).unwrap().unwrap();
        assert_eq!(stored.revision, 3);
        assert_eq!(stored.exclusion_list, exclusion_list);
        assert_eq!(stored.watchlist, watchlist);
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
                vec![entry(1, "office", "10.0.0.0/8")],
                vec![entry(2, "attacker", "203.0.113.0/24")],
            )
            .unwrap();
        let before = raw(&table, 1).unwrap();

        let outcome = table
            .replace(
                1,
                4,
                vec![entry(3, "other", "10.1.0.0/16")],
                vec![entry(4, "other", "198.51.100.0/24")],
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
                vec![entry(1, "office", "10.0.0.0/8")],
                vec![entry(2, "attacker", "203.0.113.0/24")],
            )
            .unwrap();
        let stored_first = table.get(1).unwrap().unwrap();

        // An equal revision overwrites: a retried send is idempotent.
        let outcome = table
            .replace(
                1,
                5,
                stored_first.exclusion_list.clone(),
                stored_first.watchlist.clone(),
            )
            .unwrap();
        assert_eq!(outcome, written(Some(stored_first.clone())));
        let stored_again = table.get(1).unwrap().unwrap();
        assert_eq!(stored_again.revision, 5);
        assert_eq!(stored_again.exclusion_list, stored_first.exclusion_list);
        assert_eq!(stored_again.watchlist, stored_first.watchlist);

        let exclusion_list = vec![entry(3, "lab", "10.2.0.0/16")];
        let watchlist = vec![entry(4, "scanner", "198.51.100.0/24")];
        let outcome = table
            .replace(1, 6, exclusion_list.clone(), watchlist.clone())
            .unwrap();
        assert_eq!(outcome, written(Some(stored_again)));
        let stored_second = table.get(1).unwrap().unwrap();
        assert_eq!(stored_second.revision, 6);
        assert_eq!(stored_second.exclusion_list, exclusion_list);
        assert_eq!(stored_second.watchlist, watchlist);
    }

    #[test]
    fn duplicate_exclusion_list_names_are_rejected_and_nothing_is_written() {
        let (_permit, store) = setup_store();
        let table = store.network_lists_map();

        let duplicates = vec![
            entry(1, "office", "10.0.0.0/8"),
            entry(2, "office", "10.1.0.0/16"),
        ];
        let err = table
            .replace(1, 1, duplicates.clone(), Vec::new())
            .unwrap_err()
            .to_string();
        assert!(err.contains("exclusion list"), "{err}");
        assert!(!err.contains("watchlist"), "{err}");
        assert!(err.contains("\"office\""), "{err}");
        assert_eq!(raw(&table, 1), None);

        table.replace(1, 1, Vec::new(), Vec::new()).unwrap();
        let before = raw(&table, 1).unwrap();
        assert!(table.replace(1, 2, duplicates, Vec::new()).is_err());
        assert_eq!(raw(&table, 1).unwrap(), before);

        // Names are compared exactly, so differing case is not a duplicate.
        let distinct = vec![
            entry(3, "office", "10.0.0.0/8"),
            entry(4, "Office", "10.1.0.0/16"),
        ];
        table.replace(1, 3, distinct, Vec::new()).unwrap();
    }

    #[test]
    fn duplicate_watchlist_names_are_rejected_and_nothing_is_written() {
        let (_permit, store) = setup_store();
        let table = store.network_lists_map();

        let duplicates = vec![
            entry(1, "attacker", "203.0.113.0/24"),
            entry(2, "attacker", "198.51.100.0/24"),
        ];
        let err = table
            .replace(1, 1, Vec::new(), duplicates.clone())
            .unwrap_err()
            .to_string();
        assert!(err.contains("watchlist"), "{err}");
        assert!(!err.contains("exclusion list"), "{err}");
        assert!(err.contains("\"attacker\""), "{err}");
        assert_eq!(raw(&table, 1), None);

        table.replace(1, 1, Vec::new(), Vec::new()).unwrap();
        let before = raw(&table, 1).unwrap();
        assert!(table.replace(1, 2, Vec::new(), duplicates).is_err());
        assert_eq!(raw(&table, 1).unwrap(), before);

        // Names are compared exactly, so differing case is not a duplicate.
        let distinct = vec![
            entry(3, "attacker", "203.0.113.0/24"),
            entry(4, "Attacker", "198.51.100.0/24"),
        ];
        table.replace(1, 3, Vec::new(), distinct).unwrap();
    }

    #[test]
    fn same_name_in_both_lists_is_accepted() {
        let (_permit, store) = setup_store();
        let table = store.network_lists_map();

        let exclusion_list = vec![entry(1, "shared", "10.0.0.0/8")];
        let watchlist = vec![entry(2, "shared", "203.0.113.0/24")];
        table
            .replace(1, 1, exclusion_list.clone(), watchlist.clone())
            .unwrap();
        let stored = table.get(1).unwrap().unwrap();
        assert_eq!(stored.exclusion_list, exclusion_list);
        assert_eq!(stored.watchlist, watchlist);
    }

    #[test]
    fn empty_network_list_is_stored() {
        let (_permit, store) = setup_store();
        let table = store.network_lists_map();

        table
            .replace(
                1,
                1,
                vec![entry(1, "office", "10.0.0.0/8")],
                vec![entry(2, "attacker", "203.0.113.0/24")],
            )
            .unwrap();
        table.replace(1, 2, Vec::new(), Vec::new()).unwrap();
        let stored = table.get(1).unwrap().unwrap();
        assert_eq!(stored.revision, 2);
        assert_eq!(stored.exclusion_list, Vec::new());
        assert_eq!(stored.watchlist, Vec::new());
    }

    #[test]
    fn remove_returns_the_removed_set() {
        let (_permit, store) = setup_store();
        let table = store.network_lists_map();

        table
            .replace(
                1,
                1,
                vec![entry(1, "office", "10.0.0.0/8")],
                vec![entry(2, "attacker", "203.0.113.0/24")],
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
        let exclusion_list = vec![NetworkListEntry {
            id: 1,
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
        let watchlist = vec![NetworkListEntry {
            id: 2,
            name: "v6".to_string(),
            group: HostNetworkGroup::new(
                Vec::new(),
                vec!["2001:db8:ffff::/48".parse().unwrap()],
                Vec::new(),
            ),
        }];
        table
            .replace(1, 1, exclusion_list.clone(), watchlist.clone())
            .unwrap();
        let stored = table.get(1).unwrap().unwrap();
        assert_eq!(stored.exclusion_list, exclusion_list);
        assert_eq!(stored.watchlist, watchlist);
    }

    /// A replacement whose read is overtaken by another committed write fails
    /// to commit, so the retry in `replace` reads the row again.
    #[test]
    fn conflicting_write_is_detected_at_commit() {
        let (_permit, store) = setup_store();
        let table = store.network_lists_map();

        let value = super::super::serialize(&NetworkListSet {
            revision: 1,
            exclusion_list: Vec::new(),
            watchlist: Vec::new(),
            updated_at: jiff::Timestamp::now(),
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
            let lower = vec![entry(1, "lower", "10.0.0.0/8")];
            let higher = vec![entry(2, "higher", "10.1.0.0/16")];
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
            assert_eq!(stored.exclusion_list, higher);
            assert_eq!(stored.watchlist, higher);
        }
    }

    /// A row written before the lists were renamed, under the earlier field
    /// names in the positions the exclusion list and the watchlist hold now,
    /// decodes to the same entries under the new names.
    #[test]
    fn a_row_stored_before_the_rename_decodes_under_the_new_names() {
        let (_permit, store) = setup_store();
        let table = store.network_lists_map();

        // Revision 3; the first list holds "office" (10.0.0.0/8, id 1), the
        // second "attacker" (203.0.113.0/24, id 2); written at second
        // 1_700_000_000.
        let stored = data_encoding::HEXLOWER
            .decode(
                b"030101066f66666963650001000a000000080001020861747461636b6572000100cb00\
                  71001800fd0000546cfc392f2f",
            )
            .unwrap();
        table
            .map
            .db
            .put_cf(table.map.cf, 1u32.to_be_bytes(), &stored)
            .unwrap();

        let set = table.get(1).unwrap().unwrap();
        assert_eq!(set.revision, 3);
        assert_eq!(set.exclusion_list, vec![entry(1, "office", "10.0.0.0/8")]);
        assert_eq!(set.watchlist, vec![entry(2, "attacker", "203.0.113.0/24")]);
        assert_eq!(
            set.updated_at,
            jiff::Timestamp::from_second(1_700_000_000).unwrap()
        );
        assert_eq!(
            table.exclusion_list_items(1).unwrap(),
            vec![entry(1, "office", "10.0.0.0/8")]
        );
        assert_eq!(
            table.watchlist_items(1).unwrap(),
            vec![entry(2, "attacker", "203.0.113.0/24")]
        );
        assert_eq!(super::super::serialize(&set).unwrap(), stored);
    }

    #[test]
    fn ids_round_trip() {
        let (_permit, store) = setup_store();
        let table = store.network_lists_map();

        // Ids past 2^53 are not exact in a double, so they must not pass
        // through one anywhere on the way.
        let above_double = (1u64 << 53) + 1;
        let exclusion_list = vec![
            entry(u64::MAX, "max", "10.0.0.0/8"),
            entry(0, "zero", "10.1.0.0/16"),
            entry(above_double, "above", "10.2.0.0/16"),
        ];
        let watchlist = vec![
            entry(u64::MAX - 1, "near-max", "203.0.113.0/24"),
            entry(1u64 << 53, "power", "198.51.100.0/24"),
        ];
        table
            .replace(1, 1, exclusion_list.clone(), watchlist.clone())
            .unwrap();

        let ids = |entries: &[NetworkListEntry]| -> Vec<u64> {
            entries.iter().map(|entry| entry.id).collect()
        };
        let stored = table.get(1).unwrap().unwrap();
        assert_eq!(ids(&stored.exclusion_list), [u64::MAX, 0, above_double]);
        assert_eq!(ids(&stored.watchlist), [u64::MAX - 1, 1u64 << 53]);
        assert_eq!(stored.exclusion_list, exclusion_list);
        assert_eq!(stored.watchlist, watchlist);

        let rows: Vec<(u32, NetworkListSet)> = table.iter().map(Result::unwrap).collect();
        assert_eq!(rows.len(), 1);
        let (customer_id, iterated) = &rows[0];
        assert_eq!(*customer_id, 1);
        assert_eq!(iterated.exclusion_list, exclusion_list);
        assert_eq!(iterated.watchlist, watchlist);

        let removed = table.remove(1).unwrap().unwrap();
        assert_eq!(removed.exclusion_list, exclusion_list);
        assert_eq!(removed.watchlist, watchlist);
    }

    #[test]
    fn ids_are_kept_across_replacements() {
        let (_permit, store) = setup_store();
        let table = store.network_lists_map();

        let first_exclusion_list = vec![
            entry(10, "office", "10.0.0.0/8"),
            entry(20, "edge", "192.168.0.0/24"),
        ];
        let first_watchlist = vec![entry(30, "attacker", "203.0.113.0/24")];
        table
            .replace(1, 1, first_exclusion_list.clone(), first_watchlist.clone())
            .unwrap();
        let first = table.get(1).unwrap().unwrap();

        // Entry 10 is renamed and entry 20 regrouped, both under the same id;
        // entry 30 is regrouped and entry 40 is new.
        let second_exclusion_list = vec![
            entry(10, "headquarters", "10.0.0.0/8"),
            entry(20, "edge", "192.168.1.0/24"),
        ];
        let second_watchlist = vec![
            entry(40, "scanner", "198.51.100.0/24"),
            entry(30, "attacker", "203.0.113.128/25"),
        ];
        let outcome = table
            .replace(
                1,
                2,
                second_exclusion_list.clone(),
                second_watchlist.clone(),
            )
            .unwrap();

        let NetworkListReplaceOutcome::Written {
            previous: Some(previous),
        } = outcome
        else {
            panic!("expected a write over the first set, got {outcome:?}");
        };
        assert_eq!(previous, first);
        assert_eq!(previous.exclusion_list, first_exclusion_list);
        assert_eq!(previous.watchlist, first_watchlist);

        let stored = table.get(1).unwrap().unwrap();
        assert_eq!(stored.exclusion_list, second_exclusion_list);
        assert_eq!(stored.watchlist, second_watchlist);
        let office = &stored.exclusion_list[0];
        assert_eq!((office.id, office.name.as_str()), (10, "headquarters"));
        let edge = &stored.exclusion_list[1];
        assert_eq!(edge.id, 20);
        assert_eq!(edge.group.networks(), &["192.168.1.0/24".parse().unwrap()]);
    }

    #[test]
    fn duplicate_ids_are_stored_as_given() {
        let (_permit, store) = setup_store();
        let table = store.network_lists_map();

        // Refusing duplicate ids is the writer's job, so the table stores them.
        let exclusion_list = vec![entry(7, "a", "10.0.0.0/8"), entry(7, "b", "10.1.0.0/16")];
        table
            .replace(1, 1, exclusion_list.clone(), Vec::new())
            .unwrap();
        assert_eq!(table.exclusion_list_items(1).unwrap(), exclusion_list);
    }

    #[test]
    fn item_readers_return_their_own_list_in_stored_order() {
        let (_permit, store) = setup_store();
        let table = store.network_lists_map();

        // Neither the ids nor the names are in order, so a sort by either
        // would show.
        let exclusion_list = vec![
            entry(30, "bravo", "10.3.0.0/16"),
            entry(10, "charlie", "10.1.0.0/16"),
            entry(20, "alpha", "10.2.0.0/16"),
        ];
        let watchlist = vec![
            entry(5, "zulu", "203.0.113.0/24"),
            entry(50, "yankee", "198.51.100.0/24"),
            entry(1, "xray", "192.0.2.0/24"),
        ];
        table
            .replace(1, 1, exclusion_list.clone(), watchlist.clone())
            .unwrap();
        table
            .replace(2, 1, vec![entry(99, "other", "10.9.0.0/16")], Vec::new())
            .unwrap();

        assert_eq!(table.exclusion_list_items(1).unwrap(), exclusion_list);
        assert_eq!(table.watchlist_items(1).unwrap(), watchlist);
        assert_eq!(table.watchlist_items(2).unwrap(), Vec::new());

        // A later replacement's order is the one returned.
        let reordered: Vec<NetworkListEntry> = exclusion_list.iter().rev().cloned().collect();
        table
            .replace(1, 2, reordered.clone(), watchlist.clone())
            .unwrap();
        assert_eq!(table.exclusion_list_items(1).unwrap(), reordered);
        assert_eq!(table.watchlist_items(1).unwrap(), watchlist);
    }

    #[test]
    fn item_readers_return_empty_for_a_missing_customer() {
        let (_permit, store) = setup_store();
        let table = store.network_lists_map();

        table
            .replace(
                1,
                1,
                vec![entry(1, "office", "10.0.0.0/8")],
                vec![entry(2, "attacker", "203.0.113.0/24")],
            )
            .unwrap();
        assert_eq!(table.exclusion_list_items(2).unwrap(), Vec::new());
        assert_eq!(table.watchlist_items(2).unwrap(), Vec::new());
    }

    #[test]
    fn item_readers_fail_on_an_undecodable_row() {
        let (_permit, store) = setup_store();
        let table = store.network_lists_map();

        table
            .map
            .db
            .put_cf(table.map.cf, 1u32.to_be_bytes(), [0xff; 3])
            .unwrap();
        assert!(table.exclusion_list_items(1).is_err());
        assert!(table.watchlist_items(1).is_err());
    }

    #[test]
    fn item_readers_keep_the_stored_items_after_a_refused_replacement() {
        let (_permit, store) = setup_store();
        let table = store.network_lists_map();

        let exclusion_list = vec![
            entry(2, "office", "10.0.0.0/8"),
            entry(1, "edge", "192.168.0.0/24"),
        ];
        let watchlist = vec![entry(3, "attacker", "203.0.113.0/24")];
        table
            .replace(1, 5, exclusion_list.clone(), watchlist.clone())
            .unwrap();

        let stale = table
            .replace(
                1,
                4,
                vec![entry(2, "renamed", "10.0.0.0/8")],
                vec![entry(4, "scanner", "198.51.100.0/24")],
            )
            .unwrap();
        assert_eq!(stale, NetworkListReplaceOutcome::Stale { stored: 5 });
        assert_eq!(table.exclusion_list_items(1).unwrap(), exclusion_list);
        assert_eq!(table.watchlist_items(1).unwrap(), watchlist);

        let duplicate = vec![
            entry(5, "twin", "10.5.0.0/16"),
            entry(6, "twin", "10.6.0.0/16"),
        ];
        assert!(table.replace(1, 6, duplicate.clone(), Vec::new()).is_err());
        assert!(table.replace(1, 6, Vec::new(), duplicate).is_err());
        assert_eq!(table.exclusion_list_items(1).unwrap(), exclusion_list);
        assert_eq!(table.watchlist_items(1).unwrap(), watchlist);
    }
}
