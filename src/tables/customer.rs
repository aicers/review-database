//! The `customer` table.

use std::{borrow::Cow, net::IpAddr};

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use super::UniqueKey;
use crate::{
    HostNetworkGroup, Indexable, IndexedMap, IndexedMapUpdate, IndexedTable, collections::Indexed,
    event::NetworkType, types::FromKeyValue,
};

#[derive(Clone, Deserialize, Serialize)]
pub struct Customer {
    pub id: u32,
    pub name: String,
    pub description: String,
    pub networks: Vec<Network>,
    pub creation_time: DateTime<Utc>,
}

impl FromKeyValue for Customer {
    fn from_key_value(_key: &[u8], value: &[u8]) -> Result<Self> {
        super::deserialize(value)
    }
}

impl UniqueKey for Customer {
    type AsBytes<'a> = &'a [u8];

    fn unique_key(&self) -> &[u8] {
        self.name.as_bytes()
    }
}

impl Indexable for Customer {
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

impl Customer {
    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        self.networks.iter().any(|n| n.contains(addr))
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq)]
pub struct Network {
    pub name: String,
    pub description: String,
    pub network_type: NetworkType,
    pub network_group: HostNetworkGroup,
}

impl Network {
    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        self.network_group.contains(addr)
    }
}

#[derive(Clone)]
pub struct Update {
    pub name: Option<String>,
    pub description: Option<String>,
    pub networks: Option<Vec<Network>>,
}

/// Returns an error if a duplicate `network_group` exists in the provided list.
fn check_duplicate_network_group(networks: &[Network]) -> Result<()> {
    for (i, network) in networks.iter().enumerate() {
        for other in networks.iter().skip(i + 1) {
            if network.network_group == other.network_group {
                bail!(
                    "network range already exists for this customer: {}",
                    other.name
                );
            }
        }
    }
    Ok(())
}

impl IndexedMapUpdate for Update {
    type Entry = Customer;

    fn key(&self) -> Option<Cow<'_, [u8]>> {
        self.name.as_deref().map(str::as_bytes).map(Cow::Borrowed)
    }

    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry> {
        if let Some(name) = self.name.as_deref() {
            value.name.clear();
            value.name.push_str(name);
        }
        if let Some(description) = self.description.as_deref() {
            value.description.clear();
            value.description.push_str(description);
        }
        if let Some(networks) = self.networks.as_deref() {
            check_duplicate_network_group(networks)?;
            value.networks.clear();
            value.networks.extend(networks.iter().cloned());
        }
        Ok(value)
    }

    fn verify(&self, value: &Self::Entry) -> bool {
        if let Some(v) = self.name.as_deref()
            && v != value.name
        {
            return false;
        }
        if let Some(v) = self.description.as_deref()
            && v != value.description
        {
            return false;
        }
        if let Some(v) = self.networks.as_deref() {
            if v.len() != value.networks.len() {
                return false;
            }
            if !v
                .iter()
                .zip(value.networks.iter())
                .all(|(lhs, rhs)| lhs == rhs)
            {
                return false;
            }
        }
        true
    }
}

/// Functions for the `customer` indexed map.
impl<'d> IndexedTable<'d, Customer> {
    /// Opens the `customer` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        IndexedMap::new(db, super::CUSTOMERS)
            .map(IndexedTable::new)
            .ok()
    }

    /// Inserts a new customer after validating that there are no duplicate network
    /// ranges within its networks list.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The customer has duplicate network ranges (same `network_group` value)
    /// * A customer with the same name already exists
    /// * The database operation fails
    pub fn insert(&self, entry: Customer) -> Result<u32> {
        check_duplicate_network_group(&entry.networks)?;
        self.indexed_map.insert(entry)
    }

    /// Updates the `Cutomer` from `old` to `new`, given `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `id` is invalid or the database operation fails.
    pub fn update(&mut self, id: u32, old: &Update, new: &Update) -> Result<()> {
        self.indexed_map.update(id, old, new)
    }
}

#[cfg(test)]
mod test {
    use std::{net::IpAddr, sync::Arc};

    use crate::event::NetworkType;
    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{Customer, CustomerNetwork, CustomerUpdate, HostNetworkGroup, Store};

    #[test]
    fn update() {
        let (_permit, store) = setup_store();
        let mut table = store.customer_map();

        let entry = create_entry("a");
        let id = table.put(entry.clone()).unwrap();

        let old = CustomerUpdate {
            name: Some("a".to_string()),
            description: None,
            networks: None,
        };

        let update = CustomerUpdate {
            name: Some("b".to_string()),
            description: None,
            networks: None,
        };

        assert!(table.update(id, &old, &update).is_ok());
        assert_eq!(table.count().unwrap(), 1);
        let entry = table.get_by_id(id).unwrap();
        assert_eq!(entry.map(|e| e.name), Some("b".to_string()));
    }

    #[test]
    fn insert_with_duplicate_network_range_fails() {
        let (_permit, store) = setup_store();
        let table = store.customer_map();

        let network_group = HostNetworkGroup::new(
            vec!["192.168.1.1".parse::<IpAddr>().unwrap()],
            vec![],
            vec![],
        );

        let networks = vec![
            CustomerNetwork {
                name: "network1".to_string(),
                description: "First network".to_string(),
                network_type: NetworkType::Intranet,
                network_group: network_group.clone(),
            },
            CustomerNetwork {
                name: "network2".to_string(),
                description: "Second network with same range".to_string(),
                network_type: NetworkType::Intranet,
                network_group: network_group.clone(),
            },
        ];

        let entry = Customer {
            id: u32::MAX,
            name: "customer_with_dup".to_string(),
            description: "description".to_string(),
            networks,
            creation_time: chrono::Utc::now(),
        };

        let result = table.insert(entry);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("network range already exists"),
            "Expected error about duplicate network range, got: {err_msg}"
        );
    }

    #[test]
    fn insert_with_different_network_ranges_succeeds() {
        let (_permit, store) = setup_store();
        let table = store.customer_map();

        let network_group1 = HostNetworkGroup::new(
            vec!["192.168.1.1".parse::<IpAddr>().unwrap()],
            vec![],
            vec![],
        );
        let network_group2 = HostNetworkGroup::new(
            vec!["192.168.1.2".parse::<IpAddr>().unwrap()],
            vec![],
            vec![],
        );

        let networks = vec![
            CustomerNetwork {
                name: "network1".to_string(),
                description: "First network".to_string(),
                network_type: NetworkType::Intranet,
                network_group: network_group1,
            },
            CustomerNetwork {
                name: "network2".to_string(),
                description: "Second network with different range".to_string(),
                network_type: NetworkType::Intranet,
                network_group: network_group2,
            },
        ];

        let entry = Customer {
            id: u32::MAX,
            name: "customer_with_diff_networks".to_string(),
            description: "description".to_string(),
            networks,
            creation_time: chrono::Utc::now(),
        };

        let result = table.insert(entry);
        assert!(result.is_ok());
    }

    #[test]
    fn update_with_duplicate_network_range_fails() {
        let (_permit, store) = setup_store();
        let mut table = store.customer_map();

        // Create customer with no networks
        let entry = create_entry("customer_for_update");
        let id = table.put(entry.clone()).unwrap();

        let network_group =
            HostNetworkGroup::new(vec!["10.0.0.1".parse::<IpAddr>().unwrap()], vec![], vec![]);

        let duplicate_networks = vec![
            CustomerNetwork {
                name: "net_a".to_string(),
                description: "Network A".to_string(),
                network_type: NetworkType::Intranet,
                network_group: network_group.clone(),
            },
            CustomerNetwork {
                name: "net_b".to_string(),
                description: "Network B with same range".to_string(),
                network_type: NetworkType::Intranet,
                network_group: network_group.clone(),
            },
        ];

        let old = CustomerUpdate {
            name: Some("customer_for_update".to_string()),
            description: Some("description".to_string()),
            networks: Some(vec![]),
        };

        let update = CustomerUpdate {
            name: Some("customer_for_update".to_string()),
            description: Some("description".to_string()),
            networks: Some(duplicate_networks),
        };

        let result = table.update(id, &old, &update);
        assert!(result.is_err());
        // The error chain includes the root cause; check the full error chain
        let err = result.unwrap_err();
        let full_err = format!("{err:#}");
        assert!(
            full_err.contains("network range already exists"),
            "Expected error about duplicate network range, got: {full_err}"
        );
    }

    #[test]
    fn update_with_different_network_ranges_succeeds() {
        let (_permit, store) = setup_store();
        let mut table = store.customer_map();

        // Create customer with no networks
        let entry = create_entry("customer_update_ok");
        let id = table.put(entry.clone()).unwrap();

        let network_group1 =
            HostNetworkGroup::new(vec!["10.0.0.1".parse::<IpAddr>().unwrap()], vec![], vec![]);
        let network_group2 =
            HostNetworkGroup::new(vec!["10.0.0.2".parse::<IpAddr>().unwrap()], vec![], vec![]);

        let networks = vec![
            CustomerNetwork {
                name: "net_a".to_string(),
                description: "Network A".to_string(),
                network_type: NetworkType::Intranet,
                network_group: network_group1,
            },
            CustomerNetwork {
                name: "net_b".to_string(),
                description: "Network B".to_string(),
                network_type: NetworkType::Intranet,
                network_group: network_group2,
            },
        ];

        let old = CustomerUpdate {
            name: Some("customer_update_ok".to_string()),
            description: Some("description".to_string()),
            networks: Some(vec![]),
        };

        let update = CustomerUpdate {
            name: Some("customer_update_ok".to_string()),
            description: Some("description".to_string()),
            networks: Some(networks),
        };

        let result = table.update(id, &old, &update);
        assert!(result.is_ok());

        // Verify the networks were saved
        let saved = table.get_by_id(id).unwrap().unwrap();
        assert_eq!(saved.networks.len(), 2);
    }

    #[test]
    fn different_customers_can_have_same_network_range() {
        let (_permit, store) = setup_store();
        let table = store.customer_map();

        let network_group = HostNetworkGroup::new(
            vec!["172.16.0.1".parse::<IpAddr>().unwrap()],
            vec![],
            vec![],
        );

        // Create first customer with the network
        let networks1 = vec![CustomerNetwork {
            name: "shared_range".to_string(),
            description: "Shared network range".to_string(),
            network_type: NetworkType::Intranet,
            network_group: network_group.clone(),
        }];

        let customer1 = Customer {
            id: u32::MAX,
            name: "customer1".to_string(),
            description: "First customer".to_string(),
            networks: networks1,
            creation_time: chrono::Utc::now(),
        };

        let result1 = table.insert(customer1);
        assert!(result1.is_ok());

        // Create second customer with the same network range
        let networks2 = vec![CustomerNetwork {
            name: "shared_range".to_string(),
            description: "Same network range, different customer".to_string(),
            network_type: NetworkType::Intranet,
            network_group: network_group.clone(),
        }];

        let customer2 = Customer {
            id: u32::MAX,
            name: "customer2".to_string(),
            description: "Second customer".to_string(),
            networks: networks2,
            creation_time: chrono::Utc::now(),
        };

        // This should succeed because the duplicate check is per-customer
        let result2 = table.insert(customer2);
        assert!(result2.is_ok());
    }

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        (permit, store)
    }

    fn create_entry(name: &str) -> Customer {
        Customer {
            id: u32::MAX,
            name: name.to_string(),
            description: "description".to_string(),
            networks: Vec::new(),
            creation_time: chrono::Utc::now(),
        }
    }
}
