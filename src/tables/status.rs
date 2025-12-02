//! The `status` table.
use std::borrow::Cow;

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;

use super::UniqueKey;
use crate::{
    Indexable, IndexedMap, IndexedMapUpdate, IndexedTable,
    collections::Indexed,
    types::{FromKeyValue, Status},
};

// The following will be used when PostgreSQL status table is deleted
const DEFAULT_ENTRIES: [(u32, &str); 3] = [(1, "reviewed"), (2, "pending review"), (3, "disabled")];

impl FromKeyValue for Status {
    fn from_key_value(_key: &[u8], value: &[u8]) -> Result<Self> {
        super::deserialize(value)
    }
}

impl UniqueKey for Status {
    type AsBytes<'a> = &'a [u8];

    fn unique_key(&self) -> &[u8] {
        self.description.as_bytes()
    }
}

impl Indexable for Status {
    fn key(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.description.as_bytes())
    }

    fn index(&self) -> u32 {
        self.id
    }

    fn make_indexed_key(key: Cow<[u8]>, _index: u32) -> Cow<[u8]> {
        key
    }

    fn value(&self) -> Vec<u8> {
        use bincode::Options;

        bincode::DefaultOptions::new()
            .serialize(self)
            .expect("serializable")
    }

    fn set_index(&mut self, index: u32) {
        self.id = index;
    }
}

impl IndexedMapUpdate for Status {
    type Entry = Status;

    fn key(&self) -> Option<Cow<'_, [u8]>> {
        if self.description.is_empty() {
            None
        } else {
            Some(Cow::Borrowed(self.description.as_bytes()))
        }
    }

    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry, anyhow::Error> {
        value.description.clear();
        value.description.push_str(&self.description);

        Ok(value)
    }

    fn verify(&self, value: &Self::Entry) -> bool {
        self.description == value.description
    }
}

impl<'d> IndexedTable<'d, Status> {
    /// Opens the status table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        let table = IndexedMap::new(db, super::STATUSES)
            .map(IndexedTable::new)
            .ok()?;
        table.setup().ok()?;
        Some(table)
    }

    /// Inserts a status into the table and returns the ID of the newly added
    /// status.
    ///
    /// # Errors
    ///
    /// Returns an error if the table already has a status with the same name.
    pub fn insert(&self, description: &str) -> Result<u32> {
        let entry = Status {
            id: u32::MAX,
            description: description.to_string(),
        };
        self.indexed_map.insert(entry)
    }

    /// Update the status name from `old` to `new`, given `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `id` is invalid or the database operation fails.
    pub fn update(&mut self, id: u32, old: &str, new: &str) -> Result<()> {
        let new = Status {
            id: u32::MAX,
            description: new.to_string(),
        };
        let old = Status {
            id: u32::MAX,
            description: old.to_string(),
        };
        self.indexed_map.update(id, &old, &new)
    }

    /// Try adding default entries into the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    // The following will be used when PostgreSQL status table is deleted
    #[allow(dead_code)]
    fn setup(&self) -> Result<()> {
        if self.indexed_map.count()? > 0 {
            return Ok(());
        }
        let added = self.insert("dummy")?;
        if added != 0 {
            self.remove(added)?; // so that `added` could be re-used as id.
            return Ok(());
        }
        self.deactivate(added)?; // 0 is deactivated as id for `status`.

        for (id, name) in DEFAULT_ENTRIES {
            let added = self.insert(name)?;
            if added != id {
                self.remove(added)?; // so that `added` could be re-used as id.
                return Ok(());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::DEFAULT_ENTRIES;
    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{Store, types::Status};

    fn set_up_db() -> (DbGuard<'static>, Arc<Store>, Vec<Status>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let table = store.status_map();

        let testers = &["c", "a", "b", "d"];
        let mut entries: Vec<_> = DEFAULT_ENTRIES
            .iter()
            .map(|&(i, d)| Status {
                id: i,
                description: d.to_string(),
            })
            .chain(testers.iter().map(|&d| Status {
                id: u32::MAX,
                description: d.to_string(),
            }))
            .collect();

        for e in entries.iter_mut().skip(DEFAULT_ENTRIES.len()) {
            let added = table.insert(&e.description).unwrap();
            e.id = added as u32;
        }

        entries.sort_unstable_by_key(|v| v.description.clone());

        (permit, store, entries)
    }

    #[test]
    fn add() {
        let (_permit, store, entries) = set_up_db();
        let table = store.status_map();

        assert_eq!(table.count().unwrap(), entries.len());
    }

    #[test]
    fn get() {
        let (_permit, store, entries) = set_up_db();
        let table = store.status_map();

        for entry in entries {
            assert_eq!(table.get_by_id(entry.id).unwrap(), Some(entry));
        }
    }

    #[test]
    fn update_for_new_existing_key() {
        let (_permit, store, entries) = set_up_db();
        let mut table = store.status_map();

        assert!(
            table
                .update(
                    entries
                        .iter()
                        .find_map(|v| {
                            if v.description == "a" {
                                Some(v.id)
                            } else {
                                None
                            }
                        })
                        .unwrap(),
                    "a",
                    "b"
                )
                .is_err()
        );

        assert_eq!(table.count().unwrap(), entries.len());
    }
}
