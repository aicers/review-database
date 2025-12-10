//! The `network` table.

use std::borrow::Cow;

use anyhow::Result;
use chrono::{DateTime, Utc};
use rocksdb::{Direction, OptimisticTransactionDB};
use serde::{Deserialize, Serialize};

use super::UniqueKey;
use crate::{
    HostNetworkGroup, Indexable, IndexedMap, IndexedMapUpdate, IndexedTable, Iterable,
    collections::Indexed, types::FromKeyValue,
};

#[derive(Clone, PartialEq, Debug)]
pub struct Network {
    pub id: u32,
    pub name: String,
    pub description: String,
    pub networks: HostNetworkGroup,
    tag_ids: Vec<u32>,
    pub creation_time: DateTime<Utc>,
}

impl Network {
    #[must_use]
    pub fn new(
        name: String,
        description: String,
        networks: HostNetworkGroup,
        tag_ids: Vec<u32>,
    ) -> Self {
        Self {
            id: 0,
            name,
            description,
            networks,
            tag_ids: Self::clean_up(tag_ids),
            creation_time: Utc::now(),
        }
    }

    #[must_use]
    pub fn tag_ids(&self) -> &[u32] {
        &self.tag_ids
    }

    fn contains_tag(&self, tag: u32) -> Result<usize> {
        self.tag_ids
            .binary_search(&tag)
            .map_err(|idx| anyhow::anyhow!("{idx}"))
    }

    fn clean_up(mut tag_ids: Vec<u32>) -> Vec<u32> {
        tag_ids.sort_unstable();
        tag_ids.dedup();
        tag_ids
    }
}

impl FromKeyValue for Network {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let value: Value = super::deserialize(value)?;
        let name = std::str::from_utf8(key)?.to_owned();
        Ok(Self {
            id: value.id,
            name,
            description: value.description,
            networks: value.networks,
            tag_ids: value.tag_ids,
            creation_time: value.creation_time,
        })
    }
}

impl UniqueKey for Network {
    type AsBytes<'a> = &'a [u8];

    fn unique_key(&self) -> &[u8] {
        self.name.as_bytes()
    }
}

impl Indexable for Network {
    fn key(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.name.as_bytes())
    }

    fn index(&self) -> u32 {
        self.id
    }

    /// Returns the key based solely on the name. This enforces global uniqueness by name.
    fn make_indexed_key(key: Cow<[u8]>, _index: u32) -> Cow<[u8]> {
        key
    }

    fn indexed_key(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.name.as_bytes())
    }

    fn value(&self) -> Vec<u8> {
        let value = Value {
            id: self.id,
            description: self.description.clone(),
            networks: self.networks.clone(),
            tag_ids: self.tag_ids.clone(),
            creation_time: self.creation_time,
        };
        super::serialize(&value).expect("serialization error")
    }

    fn set_index(&mut self, index: u32) {
        self.id = index;
    }
}

#[derive(Deserialize, Serialize)]
struct Value {
    id: u32,
    description: String,
    networks: HostNetworkGroup,
    tag_ids: Vec<u32>,
    creation_time: DateTime<Utc>,
}

/// Functions for the `network` indexed map.
impl<'d> IndexedTable<'d, Network> {
    /// Opens the `network` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        IndexedMap::new(db, super::NETWORKS)
            .map(IndexedTable::new)
            .ok()
    }

    /// Inserts a network into the table and returns the ID of the newly added
    /// network.
    ///
    /// # Errors
    ///
    /// Returns an error if the table already has a category with the same name.
    pub fn insert(&self, entry: Network) -> Result<u32> {
        self.indexed_map.insert(entry)
    }

    /// Removes `tag_id` in all the related entries
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub fn remove_tag(&self, tag_id: u32) -> Result<()> {
        let iter = self.iter(Direction::Forward, None);
        for entry in iter {
            let mut network = entry?;
            if let Ok(idx) = network.contains_tag(tag_id) {
                network.tag_ids.remove(idx);
                let old = Update::new(None, None, None, None);
                let new = Update::new(None, None, None, Some(network.tag_ids));
                self.indexed_map.update(network.id, &old, &new)?;
            }
        }
        Ok(())
    }

    /// Updates the `Network` from `old` to `new`, given `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `id` is invalid or the database operation fails.
    pub fn update(&mut self, id: u32, old: &Update, new: &Update) -> Result<()> {
        self.indexed_map.update(id, old, new)
    }
}

pub struct Update {
    name: Option<String>,
    description: Option<String>,
    networks: Option<HostNetworkGroup>,
    tag_ids: Option<Vec<u32>>,
}

impl Update {
    #[must_use]
    pub fn new(
        name: Option<String>,
        description: Option<String>,
        networks: Option<HostNetworkGroup>,
        tag_ids: Option<Vec<u32>>,
    ) -> Self {
        let tag_ids = tag_ids.map(Network::clean_up);
        Self {
            name,
            description,
            networks,
            tag_ids,
        }
    }
}

impl IndexedMapUpdate for Update {
    type Entry = Network;

    fn key(&self) -> Option<Cow<'_, [u8]>> {
        self.name.as_deref().map(|n| Cow::Borrowed(n.as_bytes()))
    }

    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry> {
        if let Some(v) = self.name.as_deref() {
            value.name.clear();
            value.name.push_str(v);
        }

        if let Some(v) = self.description.as_deref() {
            value.description.clear();
            value.description.push_str(v);
        }

        if let Some(v) = &self.networks {
            value.networks = v.clone();
        }

        if let Some(tag_ids) = self.tag_ids.as_deref() {
            value.tag_ids = Network::clean_up(tag_ids.to_vec());
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
        if let Some(v) = &self.networks
            && v != &value.networks
        {
            return false;
        }
        if let Some(v) = self.tag_ids.as_deref()
            && v != value.tag_ids
        {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use rocksdb::Direction;

    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{Iterable, Network, Store, types::HostNetworkGroup};

    #[test]
    fn insert_and_get() {
        let (_permit, store) = setup_store();
        let table = store.network_map();

        let mut network = create_network("TestNetwork", "TestDescription", vec![1, 2]);
        let inserted_id1 = table.insert(network.clone()).unwrap();
        network.id = inserted_id1;

        let retrieved_network = table.get_by_id(inserted_id1).unwrap().unwrap();
        assert_eq!(retrieved_network, network);

        // Inserting the same network name again should fail (global uniqueness)
        assert!(table.insert(network.clone()).is_err());
    }

    #[test]
    fn remove() {
        let (_permit, store) = setup_store();
        let table = store.network_map();

        let mut network1 = create_network("Network1", "Description1", vec![1, 2]);
        let mut network2 = create_network("Network2", "Description2", vec![2]);
        let mut network3 = create_network("Network3", "Description3", vec![3, 1]);

        network1.id = table.insert(network1.clone()).unwrap();
        network2.id = table.insert(network2.clone()).unwrap();
        network3.id = table.insert(network3.clone()).unwrap();

        let iter = table.iter(Direction::Forward, None);
        assert_eq!(iter.count(), 3);

        assert!(table.remove(network2.id).is_ok());
        let iter = table.iter(Direction::Reverse, None);
        assert_eq!(iter.count(), 2);

        let ids: Vec<_> = table
            .iter(Direction::Reverse, None)
            .filter_map(std::result::Result::ok)
            .map(|e| e.id)
            .collect();

        assert_eq!(ids, vec![network3.id, network1.id]);
    }

    #[test]
    fn remove_tag() {
        let (_permit, store) = setup_store();
        let table = store.network_map();

        let mut network1 = create_network("Network1", "Description1", vec![1, 2]);
        let mut network2 = create_network("Network2", "Description2", vec![2]);
        let mut network3 = create_network("Network3", "Description3", vec![3, 1]);

        network1.id = table.insert(network1.clone()).unwrap();
        network2.id = table.insert(network2.clone()).unwrap();
        network3.id = table.insert(network3.clone()).unwrap();

        table.remove_tag(2).unwrap();

        assert_eq!(
            table.get_by_id(network1.id).unwrap().unwrap().tag_ids(),
            &[1]
        );
        assert_eq!(
            table.get_by_id(network2.id).unwrap().unwrap().tag_ids(),
            &[] as &[u32]
        );
        assert_eq!(
            table.get_by_id(network3.id).unwrap().unwrap().tag_ids(),
            &[1, 3]
        );
    }

    #[test]
    fn update() {
        let (_permit, store) = setup_store();
        let mut table = store.network_map();

        let mut network = create_network("Network1", "Description1", vec![1, 2]);
        network.id = table.insert(network.clone()).unwrap();
        let old = super::Update::new(
            Some(network.name.clone()),
            Some(network.description.clone()),
            Some(network.networks.clone()),
            Some(network.tag_ids().to_vec()),
        );

        let mut updated_network = create_network("UpdatedNetwork", "UpdatedDescription", vec![3]);
        updated_network.creation_time = network.creation_time;
        let update = super::Update::new(
            Some(updated_network.name.clone()),
            Some(updated_network.description.clone()),
            Some(updated_network.networks.clone()),
            Some(updated_network.tag_ids().to_vec()),
        );

        table.update(network.id, &old, &update).unwrap();

        let retrieved_network = table.get_by_id(network.id).unwrap().unwrap();
        assert_eq!(retrieved_network, updated_network);

        let iter = table.iter(Direction::Forward, None);
        assert_eq!(iter.count(), 1);
    }

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        (permit, store)
    }

    fn create_network(name: &str, description: &str, tag_ids: Vec<u32>) -> Network {
        Network::new(
            name.to_string(),
            description.to_string(),
            HostNetworkGroup::default(),
            tag_ids,
        )
    }
}
