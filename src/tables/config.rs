//! The `configs` map.

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;

use crate::{Map, Table};

/// Functions for the `configs` map.
impl<'d> Table<'d, String> {
    /// Opens the  `configs` map in the database.
    ///
    /// Returns `None` if the map does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::CONFIGS).map(Table::new)
    }

    /// Initializes the account policy expiry period.
    ///
    /// # Errors
    ///
    /// Returns an error if it has already been initialized or
    /// if database operation fails.
    pub fn init(&self, key: &str, value: &str) -> Result<()> {
        self.map.insert(key.as_bytes(), value.as_bytes())
    }

    /// Updates or initializes the account policy expiry period.
    ///
    /// # Errors
    ///
    /// Returns an error if database operation fails.
    pub fn update(&self, key: &str, value: &str) -> Result<()> {
        if let Some(old) = self.map.get(key.as_bytes())? {
            self.map.update(
                (key.as_bytes(), old.as_ref()),
                (key.as_bytes(), value.as_bytes()),
            )
        } else {
            self.init(key, value)
        }
    }

    /// Returns the current account policy expiry period,
    /// or `None` if it hasn't been initialized.
    ///
    /// # Errors
    ///
    /// Returns an error if database operation fails.
    pub fn current(&self, key: &str) -> Result<Option<String>> {
        use anyhow::anyhow;

        self.map
            .get(key.as_bytes())?
            .map(|p| String::from_utf8(p.as_ref().to_owned()).map_err(|e| anyhow!("{e}")))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::Store;
    use crate::test::{DbGuard, acquire_db_permit};

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        (permit, store)
    }

    #[test]
    fn operations() {
        let (_permit, store) = setup_store();
        let table = store.config_map();

        assert!(table.update("test", "10").is_ok());
        assert_eq!(table.current("test").unwrap(), Some("10".to_string()));
        assert!(table.update("test", "20").is_ok());
        assert_eq!(table.current("test").unwrap(), Some("20".to_string()));
    }
}
