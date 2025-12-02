//! The `DataSource` table.

use std::{borrow::Cow, net::SocketAddr};

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use super::UniqueKey;
use crate::{
    Indexable, IndexedMap, IndexedMapUpdate, IndexedTable, collections::Indexed,
    types::FromKeyValue,
};

#[derive(Clone, Deserialize, Serialize)]
pub struct DataSource {
    pub id: u32,
    pub name: String,

    pub server_name: String,
    pub address: SocketAddr,

    pub data_type: DataType,
    pub source: String,
    pub kind: Option<String>,

    pub description: String,
}

impl FromKeyValue for DataSource {
    fn from_key_value(_key: &[u8], value: &[u8]) -> Result<Self> {
        super::deserialize(value)
    }
}

impl UniqueKey for DataSource {
    type AsBytes<'a> = &'a [u8];

    fn unique_key(&self) -> &[u8] {
        self.name.as_bytes()
    }
}

impl Indexable for DataSource {
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

/// Data type of `DataSource`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum DataType {
    /// comma-separated values
    Csv,
    /// line-based text data
    Log,
    /// time series data
    TimeSeries,
}

/// Functions for the `data_source` indexed map.
impl<'d> IndexedTable<'d, DataSource> {
    /// Opens the `data_source` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        IndexedMap::new(db, super::DATA_SOURCES)
            .map(IndexedTable::new)
            .ok()
    }

    /// Gets the `DataSource`, given `name`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `id` is invalid or the database operation fails.
    pub fn get(&self, name: &str) -> Result<Option<DataSource>> {
        let res = self.indexed_map.get_by_key(name.as_bytes())?;
        res.map(|value| DataSource::from_key_value(name.as_bytes(), value.as_ref()))
            .transpose()
    }

    /// Updates the `DataSource` from `old` to `new`, given `id`.
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
    pub name: Option<String>,
    pub server_name: Option<String>,
    pub address: Option<String>,
    pub data_type: Option<DataType>,
    pub source: Option<String>,
    pub kind: Option<String>,
    pub description: Option<String>,
}

impl IndexedMapUpdate for Update {
    type Entry = DataSource;

    fn key(&self) -> Option<Cow<'_, [u8]>> {
        self.name.as_deref().map(str::as_bytes).map(Cow::Borrowed)
    }

    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry, anyhow::Error> {
        if let Some(v) = self.name.as_deref() {
            value.name.clear();
            value.name.push_str(v);
        }

        if let Some(v) = self.server_name.as_deref() {
            value.server_name.clear();
            value.server_name.push_str(v);
        }
        if let Some(v) = self.address.as_deref() {
            let addr = v.parse()?;
            value.address = addr;
        }

        if let Some(v) = self.data_type {
            value.data_type = v;
        }

        if let Some(v) = self.source.as_deref() {
            value.source.clear();
            value.source.push_str(v);
        }
        if let Some(v) = self.kind.as_deref()
            && value.data_type != DataType::TimeSeries
            && let Some(s) = value.kind.as_mut()
        {
            s.clear();
            s.push_str(v);
        }

        if let Some(v) = self.description.as_deref() {
            value.description.clear();
            value.description.push_str(v);
        }

        Ok(value)
    }

    fn verify(&self, value: &Self::Entry) -> bool {
        if let Some(v) = self.name.as_deref()
            && value.name != v
        {
            return false;
        }
        if let Some(v) = self.server_name.as_deref()
            && value.server_name != v
        {
            return false;
        }
        if let Some(v) = self.address.as_deref() {
            if let Ok(v) = v.parse() {
                if value.address != v {
                    return false;
                }
            } else {
                return false;
            }
        }
        if let Some(v) = self.data_type
            && value.data_type != v
        {
            return false;
        }

        if let Some(v) = self.source.as_deref()
            && value.source != v
        {
            return false;
        }
        if value.kind.as_deref() != self.kind.as_deref() {
            return false;
        }
        if let Some(v) = self.description.as_deref()
            && value.description != v
        {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{DataSource, DataSourceUpdate, DataType, Store};

    #[test]
    fn get() {
        let (_permit, store) = setup_store();
        let table = store.data_source_map();

        let entry = create_entry("a");
        let id = table.put(entry.clone()).unwrap();

        let entry = table.get("a").unwrap();
        assert_eq!(Some(id), entry.map(|e| e.id));

        let entry = table.get("b").unwrap();
        assert!(entry.is_none());
    }

    #[test]
    fn update() {
        let (_permit, store) = setup_store();
        let mut table = store.data_source_map();

        let entry = create_entry("a");
        let id = table.put(entry.clone()).unwrap();

        let old = create_update("a");

        let update = create_update("b");

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

    fn create_entry(name: &str) -> DataSource {
        DataSource {
            id: u32::MAX,
            name: name.to_string(),
            server_name: String::new(),
            address: "127.0.0.1:8080".parse().unwrap(),
            data_type: DataType::Log,
            source: String::new(),
            kind: None,
            description: String::new(),
        }
    }

    fn create_update(name: &str) -> DataSourceUpdate {
        DataSourceUpdate {
            name: Some(name.to_string()),
            server_name: None,
            address: None,
            data_type: None,
            source: None,
            kind: None,
            description: None,
        }
    }
}
