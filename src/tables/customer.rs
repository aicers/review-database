//! The `customer` table.

use std::{borrow::Cow, net::IpAddr};

use anyhow::Result;
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
    use std::sync::Arc;

    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{Customer, CustomerUpdate, Store};

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
