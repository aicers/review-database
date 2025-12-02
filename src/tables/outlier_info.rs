//! The `outlier_info` map.

use std::mem::size_of;

use anyhow::{Result, bail};
use rocksdb::{Direction, OptimisticTransactionDB};
use serde::{Deserialize, Serialize};

use super::TableIter;
use crate::{Iterable, Map, Table, UniqueKey, tables::Value as ValueTrait, types::FromKeyValue};

#[derive(Debug, PartialEq)]
pub struct OutlierInfo {
    pub model_id: u32,
    pub timestamp: i64,
    pub rank: i64,
    pub id: i64,
    pub sensor: String,
    pub distance: f64,
    pub is_saved: bool,
}

impl FromKeyValue for OutlierInfo {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let key = Key::from_be_bytes(key)?;

        let value: Value = super::deserialize(value)?;

        Ok(Self {
            model_id: key.model_id,
            timestamp: key.timestamp,
            rank: key.rank,
            id: key.id,
            sensor: key.sensor,
            distance: value.distance,
            is_saved: value.is_saved,
        })
    }
}

impl UniqueKey for OutlierInfo {
    type AsBytes<'a> = Vec<u8>;

    fn unique_key(&self) -> Vec<u8> {
        let mut buf = vec![];
        buf.extend(self.model_id.to_be_bytes());
        buf.extend(self.timestamp.to_be_bytes());
        buf.extend(self.rank.to_be_bytes());
        buf.extend(self.id.to_be_bytes());
        buf.extend(self.sensor.as_bytes());
        buf
    }
}

impl ValueTrait for OutlierInfo {
    type AsBytes<'a> = Vec<u8>;

    fn value(&self) -> Vec<u8> {
        super::serialize(&Value {
            distance: self.distance,
            is_saved: self.is_saved,
        })
        .expect("serializable")
    }
}

#[derive(Debug, PartialEq)]
pub struct Key {
    pub model_id: u32,
    pub timestamp: i64,
    pub rank: i64,
    pub id: i64,
    pub sensor: String,
}

impl Key {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let capacity = size_of::<u32>() + size_of::<i64>() * 3 + self.sensor.len();

        let mut buf = Vec::with_capacity(capacity);
        buf.extend(self.model_id.to_be_bytes());
        buf.extend(self.timestamp.to_be_bytes());
        buf.extend(self.rank.to_be_bytes());
        buf.extend(self.id.to_be_bytes());
        buf.extend(self.sensor.as_bytes());
        buf
    }

    ///  # Errors
    ///
    /// Returns an error if deserialization from bytes fails.
    pub fn from_be_bytes(buf: &[u8]) -> Result<Self> {
        let (val, rest) = buf.split_at(size_of::<u32>());

        let mut buf = [0; size_of::<u32>()];
        buf.copy_from_slice(val);
        let model_id = u32::from_be_bytes(buf);

        let (val, rest) = rest.split_at(size_of::<i64>());
        let mut buf = [0; size_of::<i64>()];
        buf.copy_from_slice(val);
        let timestamp = i64::from_be_bytes(buf);

        let (val, rest) = rest.split_at(size_of::<i64>());
        let mut buf = [0; size_of::<i64>()];
        buf.copy_from_slice(val);
        let rank = i64::from_be_bytes(buf);

        let (val, rest) = rest.split_at(size_of::<i64>());
        let mut buf = [0; size_of::<i64>()];
        buf.copy_from_slice(val);
        let id = i64::from_be_bytes(buf);

        let sensor = std::str::from_utf8(rest)?.to_owned();

        Ok(Self {
            model_id,
            timestamp,
            rank,
            id,
            sensor,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct Value {
    pub distance: f64,
    pub is_saved: bool,
}

/// Functions for the `outlier_info` map.
impl<'d> Table<'d, OutlierInfo> {
    /// Opens the  `outlier_info` map in the database.
    ///
    /// Returns `None` if the map does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::OUTLIERS).map(Table::new)
    }

    #[must_use]
    pub fn get(
        &self,
        model: u32,
        timestamp: Option<i64>,
        direction: Direction,
        from: Option<&[u8]>,
    ) -> TableIter<'_, OutlierInfo> {
        let mut prefix = model.to_be_bytes().to_vec();
        if let Some(ts) = timestamp {
            prefix.extend(ts.to_be_bytes());
        }
        self.prefix_iter(direction, from, &prefix)
    }

    /// # Errors
    ///
    /// Returns an error if the `entry` key is invalid or the database operation fails.
    pub fn remove(&self, entry: &OutlierInfo) -> Result<()> {
        self.map.delete(&entry.unique_key())
    }

    /// Returns `true` if update is executed, or `false` if update is not needed.
    ///
    /// # Errors
    ///
    /// Returns an error if the `key` is invalid or the database operation fails.
    pub fn update_is_saved(&self, key: &Key) -> Result<bool> {
        let key = key.to_bytes();
        let Some(old_value) = self.map.get(&key)? else {
            bail!("key doesn't exist");
        };
        let mut value: Value = super::deserialize(old_value.as_ref())?;
        if value.is_saved {
            return Ok(false);
        }
        value.is_saved = true;
        let new_value = super::serialize(&value)?;
        self.map
            .update((&key, old_value.as_ref()), (&key, &new_value))?;
        Ok(true)
    }

    #[allow(unused)]
    pub(crate) fn raw(&self) -> &Map<'_> {
        &self.map
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rocksdb::Direction;

    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{Iterable, OutlierInfo, Store, UniqueKey, tables::Value, types::FromKeyValue};

    #[test]
    fn serde() {
        let entry = create_entry(123, 456, 789, 0, "some sensor", 0.2, true);
        let key = entry.unique_key();

        let res = super::Key::from_be_bytes(&key);
        assert!(res.is_ok());
        let serialized_key = res.unwrap().to_bytes();
        assert_eq!(serialized_key, key);

        let value = entry.value();
        let reassembled = OutlierInfo::from_key_value(&key, &value);
        assert!(reassembled.is_ok());
        assert_eq!(entry, reassembled.unwrap());
    }

    #[test]
    fn put_and_remove() {
        let (_permit, store) = setup_store();
        let table = store.outlier_map();

        let entries = create_entries();
        for entry in &entries {
            assert!(table.put(entry).is_ok());
        }
        assert_eq!(table.iter(Direction::Reverse, None).count(), entries.len());

        for entry in entries {
            assert!(table.remove(&entry).is_ok());
        }
        assert_eq!(table.iter(Direction::Reverse, None).count(), 0);
    }

    #[test]
    fn get() {
        let (_permit, store) = setup_store();
        let table = store.outlier_map();

        let entries = create_entries();
        for entry in &entries {
            assert!(table.put(entry).is_ok());
        }

        let all_entries: anyhow::Result<Vec<_>> =
            table.get(123, None, Direction::Forward, None).collect();
        assert_eq!(&entries, &all_entries.unwrap());

        let partial: anyhow::Result<Vec<_>> =
            table.get(123, Some(2), Direction::Forward, None).collect();
        assert_eq!(&entries[2..], &partial.unwrap());
    }

    #[test]
    fn update_is_saved() {
        let (_permit, store) = setup_store();
        let table = store.outlier_map();

        let entries = create_entries();
        for entry in &entries {
            assert!(table.put(entry).is_ok());
        }

        for entry in &entries {
            let key = super::Key::from_be_bytes(&entry.unique_key()).unwrap();
            assert!(table.update_is_saved(&key).unwrap());
        }
        let new = create_entry(345, 0, 0, 0, "some sensor", 0., false);
        let new_key = super::Key::from_be_bytes(&new.unique_key()).unwrap();
        assert!(table.update_is_saved(&new_key).is_err());

        for entry in &entries {
            let updated_key = super::Key::from_be_bytes(&entry.unique_key()).unwrap();
            assert!(!table.update_is_saved(&updated_key).unwrap());
        }
    }

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        (permit, store)
    }

    fn create_entries() -> Vec<OutlierInfo> {
        let model_id = 123;
        let sensor = "some sensor";
        let distance = 0.3;
        let is_saved = false;
        (1..3)
            .flat_map(|timestamp| {
                (2..4).map(move |rank| {
                    create_entry(model_id, timestamp, rank, rank, sensor, distance, is_saved)
                })
            })
            .collect()
    }

    fn create_entry(
        model_id: i32,
        timestamp: i64,
        rank: i64,
        id: i64,
        sensor: &str,
        distance: f64,
        is_saved: bool,
    ) -> OutlierInfo {
        OutlierInfo {
            model_id: model_id.try_into().unwrap(),
            timestamp,
            rank,
            id,
            sensor: sensor.to_owned(),
            distance,
            is_saved,
        }
    }
}
