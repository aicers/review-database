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

    /// Updates a config value with compare-and-swap semantics.
    ///
    /// This method ensures that the old value matches the current value in the
    /// database before updating, preventing concurrent modification issues.
    ///
    /// # Errors
    ///
    /// Returns an error if the old value does not match the value in the
    /// database, the key does not exist, or the database operation fails.
    pub fn update_compare(&self, key: &str, old_value: &str, new_value: &str) -> Result<()> {
        self.map.update(
            (key.as_bytes(), old_value.as_bytes()),
            (key.as_bytes(), new_value.as_bytes()),
        )
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

    #[test]
    fn operations() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let table = store.config_map();

        assert!(table.update("test", "10").is_ok());
        assert_eq!(table.current("test").unwrap(), Some("10".to_string()));
        assert!(table.update("test", "20").is_ok());
        assert_eq!(table.current("test").unwrap(), Some("20".to_string()));
    }

    #[test]
    fn update_compare_success() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let table = store.config_map();

        // Initialize with a value
        assert!(table.init("test_key", "initial").is_ok());
        assert_eq!(
            table.current("test_key").unwrap(),
            Some("initial".to_string())
        );

        // Update with correct old value
        assert!(
            table
                .update_compare("test_key", "initial", "updated")
                .is_ok()
        );
        assert_eq!(
            table.current("test_key").unwrap(),
            Some("updated".to_string())
        );
    }

    #[test]
    fn update_compare_wrong_old_value() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let table = store.config_map();

        // Initialize with a value
        assert!(table.init("test_key", "initial").is_ok());

        // Try to update with wrong old value - should fail
        assert!(
            table
                .update_compare("test_key", "wrong", "updated")
                .is_err()
        );

        // Value should remain unchanged
        assert_eq!(
            table.current("test_key").unwrap(),
            Some("initial".to_string())
        );
    }

    #[test]
    fn update_compare_nonexistent_key() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let table = store.config_map();

        // Try to update a key that doesn't exist - should fail
        assert!(table.update_compare("nonexistent", "old", "new").is_err());
    }

    #[test]
    fn init_account_policy() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());

        // Initialize account policy with default values
        assert!(store.init_account_policy(3600, 5, 1800, 10).is_ok());

        // Verify all values were stored correctly
        let config = store.config_map();
        assert_eq!(
            config.current("expiry_period_in_secs").unwrap(),
            Some("3600".to_string())
        );
        assert_eq!(
            config.current("lockout_threshold").unwrap(),
            Some("5".to_string())
        );
        assert_eq!(
            config.current("lockout_duration_in_secs").unwrap(),
            Some("1800".to_string())
        );
        assert_eq!(
            config.current("suspension_threshold").unwrap(),
            Some("10".to_string())
        );
    }

    #[test]
    fn init_account_policy_already_exists() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());

        // Initialize account policy
        assert!(store.init_account_policy(3600, 5, 1800, 10).is_ok());

        // Try to initialize again - should fail
        assert!(store.init_account_policy(7200, 3, 900, 5).is_err());
    }

    #[test]
    fn update_account_policy_all_fields() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());

        // Initialize account policy
        assert!(store.init_account_policy(3600, 5, 1800, 10).is_ok());

        // Update all fields
        assert!(
            store
                .update_account_policy(3600, 5, 1800, 10, Some(7200), Some(3), Some(900), Some(5),)
                .is_ok()
        );

        // Verify all values were updated
        let config = store.config_map();
        assert_eq!(
            config.current("expiry_period_in_secs").unwrap(),
            Some("7200".to_string())
        );
        assert_eq!(
            config.current("lockout_threshold").unwrap(),
            Some("3".to_string())
        );
        assert_eq!(
            config.current("lockout_duration_in_secs").unwrap(),
            Some("900".to_string())
        );
        assert_eq!(
            config.current("suspension_threshold").unwrap(),
            Some("5".to_string())
        );
    }

    #[test]
    fn update_account_policy_partial() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());

        // Initialize account policy
        assert!(store.init_account_policy(3600, 5, 1800, 10).is_ok());

        // Update only some fields (expiry_period and lockout_threshold)
        assert!(
            store
                .update_account_policy(3600, 5, 1800, 10, Some(7200), Some(3), None, None,)
                .is_ok()
        );

        // Verify updated values changed and others remained the same
        let config = store.config_map();
        assert_eq!(
            config.current("expiry_period_in_secs").unwrap(),
            Some("7200".to_string())
        );
        assert_eq!(
            config.current("lockout_threshold").unwrap(),
            Some("3".to_string())
        );
        assert_eq!(
            config.current("lockout_duration_in_secs").unwrap(),
            Some("1800".to_string())
        );
        assert_eq!(
            config.current("suspension_threshold").unwrap(),
            Some("10".to_string())
        );
    }

    #[test]
    fn update_account_policy_wrong_old_value() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());

        // Initialize account policy
        assert!(store.init_account_policy(3600, 5, 1800, 10).is_ok());

        // Try to update with wrong old values - should fail
        assert!(
            store
                .update_account_policy(
                    9999, // wrong old value
                    5,
                    1800,
                    10,
                    Some(7200),
                    None,
                    None,
                    None,
                )
                .is_err()
        );

        // Verify values remained unchanged
        let config = store.config_map();
        assert_eq!(
            config.current("expiry_period_in_secs").unwrap(),
            Some("3600".to_string())
        );
    }

    #[test]
    fn update_account_policy_no_changes() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());

        // Initialize account policy
        assert!(store.init_account_policy(3600, 5, 1800, 10).is_ok());

        // Update with no changes (all None)
        assert!(
            store
                .update_account_policy(3600, 5, 1800, 10, None, None, None, None,)
                .is_ok()
        );

        // Verify values remained unchanged
        let config = store.config_map();
        assert_eq!(
            config.current("expiry_period_in_secs").unwrap(),
            Some("3600".to_string())
        );
        assert_eq!(
            config.current("lockout_threshold").unwrap(),
            Some("5".to_string())
        );
    }
}
