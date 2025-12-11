//! The `allow_network` table.

use std::borrow::Cow;

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use super::UniqueKey;
use crate::{
    HostNetworkGroup, Indexable, IndexedMap, IndexedMapUpdate, IndexedTable, collections::Indexed,
    types::FromKeyValue,
};

/// The externally exposed struct representing an allow network entry.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct AllowNetwork {
    pub id: u32,
    pub name: String,
    pub networks: HostNetworkGroup,
    pub description: String,
    pub customer_id: u32,
}

/// The internal struct for DB value storage.
#[derive(Deserialize, Serialize)]
struct Value {
    id: u32,
    networks: HostNetworkGroup,
    description: String,
}

impl AllowNetwork {
    /// Creates a composite key from `customer_id` and name.
    fn composite_key(customer_id: u32, name: &str) -> Vec<u8> {
        let mut key = Vec::with_capacity(4 + name.len());
        key.extend_from_slice(&customer_id.to_be_bytes());
        key.extend_from_slice(name.as_bytes());
        key
    }

    /// Parses a composite key back into `customer_id` and name.
    fn parse_composite_key(key: &[u8]) -> Option<(u32, &str)> {
        if key.len() < 4 {
            return None;
        }
        let customer_id = u32::from_be_bytes(key[..4].try_into().ok()?);
        let name = std::str::from_utf8(&key[4..]).ok()?;
        Some((customer_id, name))
    }
}

impl FromKeyValue for AllowNetwork {
    fn from_key_value(key: &[u8], value: &[u8]) -> anyhow::Result<Self> {
        let (customer_id, name) =
            Self::parse_composite_key(key).ok_or_else(|| anyhow::anyhow!("invalid key format"))?;
        let v: Value = super::deserialize(value)?;
        Ok(Self {
            id: v.id,
            name: name.to_string(),
            networks: v.networks,
            description: v.description,
            customer_id,
        })
    }
}

impl UniqueKey for AllowNetwork {
    type AsBytes<'a> = Vec<u8>;

    fn unique_key(&self) -> Vec<u8> {
        Self::composite_key(self.customer_id, &self.name)
    }
}

impl Indexable for AllowNetwork {
    fn key(&self) -> Cow<'_, [u8]> {
        Cow::Owned(Self::composite_key(self.customer_id, &self.name))
    }

    fn index(&self) -> u32 {
        self.id
    }

    fn make_indexed_key(key: Cow<[u8]>, _index: u32) -> Cow<[u8]> {
        key
    }

    fn value(&self) -> Vec<u8> {
        let v = Value {
            id: self.id,
            networks: self.networks.clone(),
            description: self.description.clone(),
        };
        super::serialize(&v).expect("serializable")
    }

    fn set_index(&mut self, index: u32) {
        self.id = index;
    }
}

pub struct Update {
    pub name: Option<String>,
    pub networks: Option<HostNetworkGroup>,
    pub description: Option<String>,
    pub customer_id: Option<u32>,
}

impl IndexedMapUpdate for Update {
    type Entry = AllowNetwork;

    fn key(&self) -> Option<Cow<'_, [u8]>> {
        match (&self.customer_id, &self.name) {
            (Some(customer_id), Some(name)) => {
                Some(Cow::Owned(AllowNetwork::composite_key(*customer_id, name)))
            }
            _ => None,
        }
    }

    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry, anyhow::Error> {
        if let Some(name) = self.name.as_deref() {
            value.name.clear();
            value.name.push_str(name);
        }
        if let Some(networks) = self.networks.as_ref() {
            networks.clone_into(&mut value.networks);
        }
        if let Some(description) = self.description.as_deref() {
            value.description.clear();
            value.description.push_str(description);
        }
        if let Some(customer_id) = self.customer_id {
            value.customer_id = customer_id;
        }
        Ok(value)
    }

    fn verify(&self, value: &Self::Entry) -> bool {
        if let Some(v) = self.name.as_deref()
            && v != value.name
        {
            return false;
        }
        if let Some(v) = self.networks.as_ref()
            && *v != value.networks
        {
            return false;
        }
        if let Some(v) = self.description.as_deref()
            && v != value.description
        {
            return false;
        }
        if let Some(v) = self.customer_id
            && v != value.customer_id
        {
            return false;
        }
        true
    }
}

/// Functions for the `allow_network` indexed map.
impl<'d> IndexedTable<'d, AllowNetwork> {
    /// Opens the `allow_network` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        IndexedMap::new(db, super::ALLOW_NETWORKS)
            .map(IndexedTable::new)
            .ok()
    }

    /// Updates the `AllowNetwork` from `old` to `new`, given `id`.
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

    use rocksdb::Direction;

    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{AllowNetwork, HostNetworkGroup, Iterable, Store};

    #[test]
    fn put_and_get() {
        let (_permit, store) = setup_store();
        let table = store.allow_network_map();

        let a = create_allow_network(1, "a", "TestDescription");
        let inserted_id = table.put(a.clone()).unwrap();

        let retrieved_allow_network = table.get_by_id(inserted_id).unwrap().unwrap();
        assert_eq!(retrieved_allow_network, a);

        assert!(table.put(a).is_err());

        let b = create_allow_network(1, "b", "TestDescription");
        let b_id = table.put(b).unwrap();
        assert!(b_id != inserted_id);

        assert_eq!(2, table.iter(Direction::Forward, None).count());
    }

    #[test]
    fn put_same_name_different_customer() {
        let (_permit, store) = setup_store();
        let table = store.allow_network_map();

        // Same name but different customer_id should be allowed
        let a1 = create_allow_network(1, "shared_name", "Customer1");
        let id1 = table.put(a1.clone()).unwrap();

        let a2 = create_allow_network(2, "shared_name", "Customer2");
        let id2 = table.put(a2.clone()).unwrap();

        assert!(id1 != id2);

        let retrieved1 = table.get_by_id(id1).unwrap().unwrap();
        assert_eq!(retrieved1.customer_id, 1);
        assert_eq!(retrieved1.name, "shared_name");

        let retrieved2 = table.get_by_id(id2).unwrap().unwrap();
        assert_eq!(retrieved2.customer_id, 2);
        assert_eq!(retrieved2.name, "shared_name");

        assert_eq!(2, table.iter(Direction::Forward, None).count());
    }

    #[test]
    fn update() {
        let (_permit, store) = setup_store();
        let mut table = store.allow_network_map();

        let allow_network = create_allow_network(1, "AllowNetwork1", "Description1");
        let inserted_id = table.put(allow_network.clone()).unwrap();
        let old = super::Update {
            name: Some(allow_network.name.clone()),
            networks: Some(allow_network.networks.clone()),
            description: Some(allow_network.description.clone()),
            customer_id: Some(allow_network.customer_id),
        };

        let updated_allow_network =
            create_allow_network(1, "UpdatedAllowNetwork", "UpdatedDescription");
        let update = super::Update {
            name: Some(updated_allow_network.name.clone()),
            networks: Some(updated_allow_network.networks.clone()),
            description: Some(updated_allow_network.description.clone()),
            customer_id: Some(updated_allow_network.customer_id),
        };

        table.update(inserted_id, &old, &update).unwrap();

        let retrieved_allow_network = table.get_by_id(inserted_id).unwrap().unwrap();
        assert_eq!(retrieved_allow_network, updated_allow_network);
    }

    #[test]
    fn update_key() {
        let (_permit, store) = setup_store();
        let mut table = store.allow_network_map();

        let mut a = create_allow_network(1, "a", "a");
        a.id = table.put(a.clone()).unwrap();
        let a_update = super::Update {
            name: Some(a.name.clone()),
            networks: Some(a.networks.clone()),
            description: Some(a.description.clone()),
            customer_id: Some(a.customer_id),
        };
        let mut b = create_allow_network(1, "b", "b");
        b.id = table.put(b.clone()).unwrap();
        let b_update = super::Update {
            name: Some(b.name.clone()),
            networks: Some(b.networks.clone()),
            description: Some(b.description.clone()),
            customer_id: Some(b.customer_id),
        };

        let c_update = super::Update {
            name: Some("c".to_string()),
            networks: Some(HostNetworkGroup::default()),
            description: Some("c".to_string()),
            customer_id: Some(1),
        };

        assert!(table.update(a.id, &a_update, &c_update).is_ok());
        assert_eq!(table.iter(Direction::Reverse, None).count(), 2);

        // Old entry must match existing entry
        assert!(table.update(0, &a_update, &c_update).is_err());
        assert_eq!(table.iter(Direction::Reverse, None).count(), 2);

        // No duplicated keys
        assert!(table.update(0, &c_update, &b_update).is_err());
        assert_eq!(table.iter(Direction::Reverse, None).count(), 2);
    }

    // Helper functions

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        (permit, store)
    }

    fn create_allow_network(customer_id: u32, name: &str, description: &str) -> AllowNetwork {
        AllowNetwork {
            id: 0,
            name: name.to_string(),
            networks: HostNetworkGroup::default(),
            description: description.to_string(),
            customer_id,
        }
    }
}
