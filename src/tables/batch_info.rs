//! The `batch_info` table.

use std::mem::size_of;

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;

use crate::{Iterable, Map, Table, UniqueKey, batch_info::BatchInfo, types::FromKeyValue};

impl FromKeyValue for BatchInfo {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
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
    /// Returns an error if the record with given model id does not exist
    /// or the database operation fails.
    pub fn count(&self, model: u32) -> Result<usize> {
        let prefix = model.to_be_bytes();
        Ok(self
            .prefix_iter(rocksdb::Direction::Forward, None, &prefix)
            .count())
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
        let mut deleted = 0;
        let prefix = model.to_be_bytes();
        for res in self.prefix_iter(rocksdb::Direction::Reverse, None, &prefix) {
            let entry = res?;
            match self.map.delete(&entry.unique_key()) {
                Ok(()) => deleted += 1,
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "Deleted: {deleted}\nDeletion ended due to: {e}"
                    ));
                }
            }
        }
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{Store, batch_info::BatchInfo, types::ModelBatchInfo};

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
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
        for (r, e) in res
            .into_iter()
            .zip(vec![&entries[1], &entries[0]].into_iter())
        {
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
