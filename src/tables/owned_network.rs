//! The `customer networks` table.
//!
//! Each row holds the networks one customer owns, as an operator defined them
//! outside this database, keyed by the customer ID alone. The table keeps no other
//! customer data: the ID is only a key.

use std::collections::HashSet;

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
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
    pub updated_at: DateTime<Utc>,
}

impl OwnedNetworkSet {
    /// Returns the groups of the `Intranet` and `Gateway` networks, the ones
    /// whose addresses count as internal to the customer.
    #[must_use]
    pub fn internal_groups(&self) -> Vec<HostNetworkGroup> {
        self.networks
            .iter()
            .filter(|network| {
                matches!(
                    network.network_type,
                    NetworkType::Intranet | NetworkType::Gateway
                )
            })
            .map(|network| network.group.clone())
            .collect()
    }

    /// Returns one group holding the hosts, networks and ranges of every
    /// network, whatever its type, sorted and deduplicated.
    #[must_use]
    pub fn merged_group(&self) -> HostNetworkGroup {
        let mut hosts = Vec::new();
        let mut networks = Vec::new();
        let mut ip_ranges = Vec::new();
        for network in &self.networks {
            hosts.extend_from_slice(network.group.hosts());
            networks.extend_from_slice(network.group.networks());
            ip_ranges.extend_from_slice(network.group.ip_ranges());
        }
        HostNetworkGroup::new(hosts, networks, ip_ranges)
    }
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
            updated_at: Utc::now(),
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
        let before = Utc::now();
        assert_eq!(
            table.replace(7, 3, networks.clone()).unwrap(),
            written(None)
        );
        let after = Utc::now();

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
            updated_at: Utc::now(),
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
    fn internal_groups_exclude_extranet() {
        let intranet = network("office", NetworkType::Intranet, "10.0.0.0/8");
        let gateway = network("edge", NetworkType::Gateway, "192.168.0.0/24");
        let extranet = network("partner", NetworkType::Extranet, "172.16.0.0/12");
        let set = OwnedNetworkSet {
            revision: 1,
            networks: vec![intranet.clone(), extranet, gateway.clone()],
            updated_at: Utc::now(),
        };
        assert_eq!(set.internal_groups(), vec![intranet.group, gateway.group]);
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
            updated_at: Utc::now(),
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
