//! The `model_indicator` map.

use std::{
    collections::HashSet,
    io::{BufReader, Read},
};

use anyhow::Result;
use chrono::{DateTime, Utc, serde::ts_seconds};
use data_encoding::BASE64;
use flate2::read::GzDecoder;
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use crate::{Map, Table, types::FromKeyValue};

#[derive(Default)]
pub struct ModelIndicator {
    pub name: String,
    pub description: String,
    pub model_id: u32,
    pub tokens: HashSet<Vec<String>>,
    pub last_modification_time: DateTime<Utc>,
}

impl ModelIndicator {
    /// Creates a new `ModelIndicator` from the given data.
    ///
    /// # Errors
    ///
    /// Returns an error if the given data is invalid.
    pub fn new(name: &str, data: &str) -> Result<Self> {
        let data = BASE64.decode(data.as_bytes())?;
        let decoder = GzDecoder::new(&data[..]);
        let mut buf = Vec::new();
        let mut reader = BufReader::new(decoder);
        reader.read_to_end(&mut buf)?;

        Self::from_key_value(name.as_bytes(), &buf)
    }

    fn into_key_value(self) -> Result<(Vec<u8>, Vec<u8>)> {
        let key = self.name.into_bytes();
        let value = Value {
            description: self.description,
            model_id: i32::try_from(self.model_id)?,
            tokens: self.tokens,
            last_modification_time: self.last_modification_time,
        };
        Ok((key, super::serialize(&value)?))
    }
}

#[derive(Deserialize, Serialize)]
struct Value {
    description: String,
    model_id: i32,
    tokens: HashSet<Vec<String>>,
    #[serde(with = "ts_seconds")]
    last_modification_time: DateTime<Utc>,
}

impl FromKeyValue for ModelIndicator {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let name = std::str::from_utf8(key)?.to_string();
        let value: Value = super::deserialize(value)?;
        Ok(Self {
            name,
            description: value.description,
            model_id: u32::try_from(value.model_id)?,
            tokens: value.tokens,
            last_modification_time: value.last_modification_time,
        })
    }
}

/// Functions for the `model_indicator` map.
impl<'d> Table<'d, ModelIndicator> {
    /// Opens the  `model_indicator` map in the database.
    ///
    /// Returns `None` if the map does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::MODEL_INDICATORS).map(Table::new)
    }

    /// Returns the `ModelIndicator` with the given name.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub fn get(&self, name: &str) -> Result<Option<ModelIndicator>> {
        self.map
            .get(name.as_bytes())?
            .map(|v| ModelIndicator::from_key_value(name.as_bytes(), v.as_ref()))
            .transpose()
    }

    /// Inserts the `ModelIndicator` into the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the serialization fails or the database operation fails.
    pub fn insert(&self, indicator: ModelIndicator) -> Result<()> {
        let (key, value) = indicator.into_key_value()?;
        self.map.put(&key, &value)
    }

    /// Removes the `ModelIndicator`s with the given names. The removed names are returned.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn remove<'a>(&self, names: impl Iterator<Item = &'a str>) -> Result<Vec<String>> {
        let mut removed = vec![];
        for name in names {
            self.map.delete(name.as_bytes())?;
            removed.push(name.to_string());
        }
        Ok(removed)
    }

    /// Updates the `ModelIndicator` in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the serialization fails or the database operation fails.
    pub fn update(&self, indicator: ModelIndicator) -> Result<()> {
        self.remove(std::iter::once(indicator.name.as_str()))?;
        self.insert(indicator)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{ModelIndicator, Store};

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        (permit, store)
    }

    #[test]
    fn serde() {
        use std::collections::HashSet;
        use std::io::{Cursor, Read};

        use chrono::Utc;
        use data_encoding::BASE64;
        use flate2::{Compression, bufread::GzEncoder};

        let name = "mi_1";
        let value = super::Value {
            description: "test".to_owned(),
            model_id: 123,
            tokens: HashSet::new(),
            last_modification_time: Utc::now(),
        };
        let serialized = crate::tables::serialize(&value).unwrap();
        let cursor = Cursor::new(serialized);

        let mut gz = GzEncoder::new(cursor, Compression::fast());
        let mut zipped = Vec::new();
        gz.read_to_end(&mut zipped).unwrap();
        let encoded = BASE64.encode(&zipped);
        let res = super::ModelIndicator::new(name, &encoded);

        assert!(res.is_ok());
        let indicator = res.unwrap();
        assert_eq!(indicator.name, "mi_1");
        assert_eq!(indicator.description, "test");
    }

    #[test]
    fn operations() {
        use crate::Iterable;
        let (_permit, store) = setup_store();
        let table = store.model_indicator_map();

        let tester = &["1", "2", "3"];
        for &name in tester {
            let mi = ModelIndicator {
                name: name.to_string(),
                ..Default::default()
            };
            assert!(table.insert(mi).is_ok());
        }

        for &name in tester {
            let res = table.get(name).unwrap().map(|mi| mi.name);
            assert_eq!(Some(name.to_string()), res);
        }

        let res: anyhow::Result<Vec<_>> = table
            .iter(rocksdb::Direction::Forward, None)
            .map(|r| r.map(|mi| mi.name))
            .collect();
        assert!(res.is_ok());
        let list = res.unwrap();
        assert_eq!(
            tester.to_vec(),
            list.iter().map(String::as_str).collect::<Vec<_>>()
        );

        let res = table.remove(list.iter().map(String::as_str));
        assert!(res.is_ok());
        let removed = res.unwrap();
        assert_eq!(removed, list);
    }
}
