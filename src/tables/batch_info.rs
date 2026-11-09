//! The `batch_info` table.

use std::mem::size_of;

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;

use crate::{Iterable, Map, Table, batch_info::BatchInfo, types::FromKeyValue};

impl FromKeyValue for BatchInfo {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        anyhow::ensure!(
            key.len() == 12,
            "invalid BatchInfo key length: {}",
            key.len()
        );
        let mut model = [0; size_of::<u32>()];
        model.copy_from_slice(&key[..size_of::<u32>()]);
        let model = u32::from_be_bytes(model);

        let inner = super::deserialize(value)?;

        Ok(Self::new(model, inner))
    }
}

impl<'d> Table<'d, crate::batch_info::BatchInfo> {
    /// Opens the batch info table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::BATCH_INFO).map(Table::new)
    }

    /// Returns all `batch_info` with the given model id.
    ///
    /// # Errors
    ///
    /// Returns an error if the record with given model id does not exist
    /// or the database operation fails.
    pub fn get_all_for(&self, model: u32) -> Result<Vec<BatchInfo>> {
        let prefix = model.to_be_bytes();
        self.prefix_iter(rocksdb::Direction::Forward, None, &prefix)
            .collect()
    }

    /// Returns the count of `batch_info` with the given model id.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or a stored record cannot be decoded.
    pub fn count(&self, model: u32) -> Result<usize> {
        let prefix = model.to_be_bytes();
        self.prefix_iter(rocksdb::Direction::Forward, None, &prefix)
            .try_fold(0, |count, item| item.map(|_| count + 1))
    }

    /// Returns the `batch_info` with the given `model_id` and `batch_ts`.
    ///
    /// # Errors
    ///
    /// Returns an error if the record with given `model_id` and `batch_ts` does not exist
    /// or the database operation fails.
    pub fn get(&self, model_id: u32, batch_ts: i64) -> Result<Option<BatchInfo>> {
        let mut key = model_id.to_be_bytes().to_vec();
        key.extend(batch_ts.to_be_bytes());
        let Some(value) = self.map.get(&key)? else {
            return Ok(None);
        };
        let inner = super::deserialize(value.as_ref())?;
        Ok(Some(BatchInfo::new(model_id, inner)))
    }

    /// Deletes all `batch_info`s with the given model id.
    ///
    /// # Errors
    ///
    /// Returns an error if any of deletion operation fails.
    pub fn delete_all_for(&self, model: u32) -> Result<usize> {
        let prefix = model.to_be_bytes();
        let mut options = rocksdb::ReadOptions::default();
        options.set_iterate_range(rocksdb::PrefixRange(&prefix));
        let iter = self
            .map
            .db
            .iterator_cf_opt(self.map.cf, options, rocksdb::IteratorMode::Start);
        let mut deleted = 0;
        for item in iter {
            let (key, _) = item?;
            self.map.delete(&key)?;
            deleted += 1;
        }
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn malformed_keys_and_values_are_counted_and_deleted_correctly() {
        use crate::{UniqueKey, types::FromKeyValue};
        for len in [0, 11, 13] {
            assert!(BatchInfo::from_key_value(&vec![0; len], &[0; 3]).is_err());
        }
        let (_permit, store) = setup_store();
        let table = store.batch_info_map();
        let entries = entries();
        for entry in &entries {
            table.put(entry).unwrap();
        }
        let mut corrupt = 1_u32.to_be_bytes().to_vec();
        corrupt.extend(123_i64.to_be_bytes());
        table.map.put(&corrupt, &[0; 3]).unwrap();
        assert!(table.count(1).is_err());
        let mut short = 1_u32.to_be_bytes().to_vec();
        short.push(7);
        table.map.put(&short, &[0; 3]).unwrap();
        assert_eq!(table.delete_all_for(1).unwrap(), 4);
        assert!(table.map.get(&short).unwrap().is_none());
        assert!(table.map.get(&entries[2].unique_key()).unwrap().is_some());
    }

    use std::sync::Arc;

    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{Store, batch_info::BatchInfo, types::ModelBatchInfo};

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path(), None).unwrap());
        (permit, store)
    }

    fn entries() -> Vec<BatchInfo> {
        let entry1 = BatchInfo::new(
            1,
            ModelBatchInfo {
                id: 321,
                earliest: 1,
                latest: 2,
                size: 1,
                sensors: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            },
        );
        let entry2 = BatchInfo::new(
            1,
            ModelBatchInfo {
                id: 121,
                earliest: 1,
                latest: 2,
                size: 1,
                sensors: vec!["a".to_string(), "b".to_string()],
            },
        );
        let entry3 = BatchInfo::new(
            2,
            ModelBatchInfo {
                id: 123,
                earliest: 1,
                latest: 2,
                size: 1,
                sensors: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            },
        );
        vec![entry1, entry2, entry3]
    }

    #[test]
    fn put_delete() {
        let (_permit, store) = setup_store();
        let table = store.batch_info_map();

        assert_eq!(table.get_all_for(1).unwrap().len(), 0);
        assert_eq!(table.get_all_for(2).unwrap().len(), 0);

        let entries = entries();

        for entry in &entries {
            assert!(table.put(entry).is_ok());
        }

        assert!(table.put(&entries[1]).is_ok());
        assert!(table.insert(&entries[1]).is_err());

        let res = table.get_all_for(1).unwrap();
        assert_eq!(res.len(), 2);
        for (r, e) in res.into_iter().zip(vec![&entries[1], &entries[0]]) {
            assert_eq!(&r, e);
        }

        assert_eq!(2, table.delete_all_for(1).unwrap());
        assert_eq!(1, table.delete_all_for(2).unwrap());

        assert_eq!(table.get_all_for(1).unwrap().len(), 0);
        assert_eq!(table.get_all_for(2).unwrap().len(), 0);
    }

    #[test]
    fn get() {
        let (_permit, store) = setup_store();
        let table = store.batch_info_map();

        assert_eq!(table.get_all_for(1).unwrap().len(), 0);
        assert_eq!(table.get_all_for(2).unwrap().len(), 0);

        let entries = entries();
        for entry in &entries {
            assert!(table.put(entry).is_ok());
        }

        let count = table.count(1).unwrap();
        assert_eq!(count, 2);

        let count = table.count(2).unwrap();
        assert_eq!(count, 1);

        let entry = table.get(2, 123).unwrap();
        assert_eq!(entry.as_ref(), Some(&entries[2]));

        let entry = table.get(2, 321).unwrap();
        assert!(entry.is_none());
    }
}
