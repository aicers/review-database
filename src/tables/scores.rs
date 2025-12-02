//! The `scores` table.

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;

use crate::{Map, Table, scores::Scores};

impl<'d> Table<'d, Scores> {
    /// Opens the scores table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::SCORES).map(Table::new)
    }

    /// Deletes an scores with the given model id.
    ///
    /// # Errors
    ///
    /// Returns an error if the account does not exist or the database operation fails.
    pub fn delete(&self, model: u32) -> Result<()> {
        let key = super::serialize(&model)?;
        self.map.delete(&key)
    }

    /// Returns a scores with the given model id.
    ///
    /// # Errors
    ///
    /// Returns an error if the scores does not exist or the database operation fails.
    pub fn get(&self, model: u32) -> Result<Option<Scores>> {
        let key = super::serialize(&model)?;
        let Some(value) = self.map.get(&key)? else {
            return Ok(None);
        };
        let value = super::deserialize(value.as_ref())?;
        let scores = Scores::new(model, value);
        Ok(Some(scores))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{Store, scores::Scores, types::ModelScores};

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        (permit, store)
    }

    #[test]
    fn put_delete() {
        let (_permit, store) = setup_store();
        let table = store.scores_map();

        let entry1 = Scores::new(1, ModelScores::default());
        let entry2 = Scores::new(2, vec![(1, 0.), (2, 1.)].into_iter().collect());
        let entry3 = Scores::new(3, vec![(1, 0.), (2, 1.)].into_iter().collect());

        let entries = vec![(1, entry1), (2, entry2), (3, entry3)];

        for (id, _entry) in &entries {
            assert_eq!(table.get(*id).unwrap(), None);
        }

        for (_, entry) in &entries {
            assert!(table.put(entry).is_ok());
        }

        assert!(table.put(&entries[1].1).is_ok());
        assert!(table.insert(&entries[1].1).is_err());

        for (id, entry) in &entries {
            assert_eq!(table.get(*id).unwrap().as_ref(), Some(entry));
        }

        for (id, _) in &entries {
            assert!(table.delete(*id).is_ok());
        }

        for (id, _entry) in &entries {
            assert_eq!(table.get(*id).unwrap(), None);
        }
    }
}
