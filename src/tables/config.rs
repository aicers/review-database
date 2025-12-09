//! The `configs` map.

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;

use crate::{Map, Table};

pub const KEY_EXPIRY_PERIOD: &str = "expiry_period_in_secs";
pub const KEY_LOCKOUT_THRESHOLD: &str = "lockout_threshold";
pub const KEY_LOCKOUT_DURATION: &str = "lockout_duration_in_secs";
pub const KEY_SUSPENSION_THRESHOLD: &str = "suspension_threshold";

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

    /// Initializes multiple config values atomically.
    ///
    /// # Errors
    ///
    /// Returns an error if any parameter already exists or
    /// if database operation fails.
    pub fn init_multi(&self, updates: &[(&str, &str)]) -> Result<()> {
        let updates: Vec<_> = updates
            .iter()
            .map(|(k, v)| (k.as_bytes(), v.as_bytes()))
            .collect();
        self.map.insert_multi(&updates)
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

    /// Updates multiple config values with compare-and-swap semantics atomically.
    ///
    /// # Errors
    ///
    /// Returns an error if any old value does not match, any key does not exist,
    /// or database operation fails.
    pub fn update_compare_multi(&self, updates: &[(&str, &str, &str)]) -> Result<()> {
        let updates: Vec<_> = updates
            .iter()
            .map(|(k, o, n)| (k.as_bytes(), o.as_bytes(), n.as_bytes()))
            .collect();
        self.map.update_compare_multi(&updates)
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

    use crate::tables::config::{
        KEY_EXPIRY_PERIOD, KEY_LOCKOUT_DURATION, KEY_LOCKOUT_THRESHOLD, KEY_SUSPENSION_THRESHOLD,
    };
    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{AccountPolicy, AccountPolicyUpdate, Store};

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

    #[test]
    fn update_compare_success() {
        let (_permit, store) = setup_store();
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
        let (_permit, store) = setup_store();
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
        let (_permit, store) = setup_store();
        let table = store.config_map();

        // Try to update a key that doesn't exist - should fail
        assert!(table.update_compare("nonexistent", "old", "new").is_err());
    }

    #[test]
    fn init_account_policy_test() {
        let (_permit, store) = setup_store();

        let policy = AccountPolicy {
            expiry_period_in_secs: 3600,
            lockout_threshold: 5,
            lockout_duration_in_secs: 1800,
            suspension_threshold: 10,
        };

        // Initialize account policy with default values
        assert!(store.init_account_policy(&policy).is_ok());

        // Verify all values were stored correctly
        let config = store.config_map();
        assert_eq!(
            config.current(KEY_EXPIRY_PERIOD).unwrap(),
            Some("3600".to_string())
        );
        assert_eq!(
            config.current(KEY_LOCKOUT_THRESHOLD).unwrap(),
            Some("5".to_string())
        );
        assert_eq!(
            config.current(KEY_LOCKOUT_DURATION).unwrap(),
            Some("1800".to_string())
        );
        assert_eq!(
            config.current(KEY_SUSPENSION_THRESHOLD).unwrap(),
            Some("10".to_string())
        );
    }

    #[test]
    fn init_account_policy_already_exists() {
        let (_permit, store) = setup_store();

        let policy = AccountPolicy {
            expiry_period_in_secs: 3600,
            lockout_threshold: 5,
            lockout_duration_in_secs: 1800,
            suspension_threshold: 10,
        };

        // Initialize account policy
        assert!(store.init_account_policy(&policy).is_ok());

        let new_policy = AccountPolicy {
            expiry_period_in_secs: 7200,
            lockout_threshold: 3,
            lockout_duration_in_secs: 900,
            suspension_threshold: 5,
        };

        // Try to initialize again - should fail
        assert!(store.init_account_policy(&new_policy).is_err());
    }

    #[test]
    fn update_account_policy_all_fields() {
        let (_permit, store) = setup_store();

        let policy = AccountPolicy {
            expiry_period_in_secs: 3600,
            lockout_threshold: 5,
            lockout_duration_in_secs: 1800,
            suspension_threshold: 10,
        };

        // Initialize account policy
        assert!(store.init_account_policy(&policy).is_ok());

        let update = AccountPolicyUpdate {
            expiry_period_in_secs: Some(7200),
            lockout_threshold: Some(3),
            lockout_duration_in_secs: Some(900),
            suspension_threshold: Some(5),
        };

        // Update all fields
        assert!(store.update_account_policy(&policy, &update).is_ok());

        // Verify all values were updated
        let config = store.config_map();
        assert_eq!(
            config.current(KEY_EXPIRY_PERIOD).unwrap(),
            Some("7200".to_string())
        );
        assert_eq!(
            config.current(KEY_LOCKOUT_THRESHOLD).unwrap(),
            Some("3".to_string())
        );
        assert_eq!(
            config.current(KEY_LOCKOUT_DURATION).unwrap(),
            Some("900".to_string())
        );
        assert_eq!(
            config.current(KEY_SUSPENSION_THRESHOLD).unwrap(),
            Some("5".to_string())
        );
    }

    #[test]
    fn update_account_policy_partial() {
        let (_permit, store) = setup_store();

        let policy = AccountPolicy {
            expiry_period_in_secs: 3600,
            lockout_threshold: 5,
            lockout_duration_in_secs: 1800,
            suspension_threshold: 10,
        };

        // Initialize account policy
        assert!(store.init_account_policy(&policy).is_ok());

        let update = AccountPolicyUpdate {
            expiry_period_in_secs: Some(7200),
            lockout_threshold: Some(3),
            ..Default::default()
        };

        // Update only some fields (expiry_period and lockout_threshold)
        assert!(store.update_account_policy(&policy, &update).is_ok());

        // Verify updated values changed and others remained the same
        let config = store.config_map();
        assert_eq!(
            config.current(KEY_EXPIRY_PERIOD).unwrap(),
            Some("7200".to_string())
        );
        assert_eq!(
            config.current(KEY_LOCKOUT_THRESHOLD).unwrap(),
            Some("3".to_string())
        );
        assert_eq!(
            config.current(KEY_LOCKOUT_DURATION).unwrap(),
            Some("1800".to_string())
        );
        assert_eq!(
            config.current(KEY_SUSPENSION_THRESHOLD).unwrap(),
            Some("10".to_string())
        );
    }

    #[test]
    fn update_account_policy_wrong_old_value() {
        let (_permit, store) = setup_store();

        let policy = AccountPolicy {
            expiry_period_in_secs: 3600,
            lockout_threshold: 5,
            lockout_duration_in_secs: 1800,
            suspension_threshold: 10,
        };

        // Initialize account policy
        assert!(store.init_account_policy(&policy).is_ok());

        let wrong_policy = AccountPolicy {
            expiry_period_in_secs: 9999, // wrong old value
            ..policy
        };

        let update = AccountPolicyUpdate {
            expiry_period_in_secs: Some(7200),
            ..Default::default()
        };

        // Try to update with wrong old values - should fail
        assert!(store.update_account_policy(&wrong_policy, &update).is_err());

        // Verify values remained unchanged
        let config = store.config_map();
        assert_eq!(
            config.current(KEY_EXPIRY_PERIOD).unwrap(),
            Some("3600".to_string())
        );
    }

    #[test]
    fn update_account_policy_no_changes() {
        let (_permit, store) = setup_store();

        let policy = AccountPolicy {
            expiry_period_in_secs: 3600,
            lockout_threshold: 5,
            lockout_duration_in_secs: 1800,
            suspension_threshold: 10,
        };

        // Initialize account policy
        assert!(store.init_account_policy(&policy).is_ok());

        let update = AccountPolicyUpdate::default();

        // Update with no changes (all None)
        assert!(store.update_account_policy(&policy, &update).is_ok());

        // Verify values remained unchanged
        let config = store.config_map();
        assert_eq!(
            config.current(KEY_EXPIRY_PERIOD).unwrap(),
            Some("3600".to_string())
        );
        assert_eq!(
            config.current(KEY_LOCKOUT_THRESHOLD).unwrap(),
            Some("5".to_string())
        );
    }

    #[test]
    fn update_account_policy_atomicity() {
        let (_permit, store) = setup_store();

        let policy = AccountPolicy {
            expiry_period_in_secs: 3600,
            lockout_threshold: 5,
            lockout_duration_in_secs: 1800,
            suspension_threshold: 10,
        };

        // Initialize account policy
        assert!(store.init_account_policy(&policy).is_ok());

        // Try to update with mixed valid/invalid old values
        // expiry_period: valid old value (3600) -> new value (7200)
        // lockout_threshold: invalid old value (999) -> new value (3)
        let mixed_policy = AccountPolicy {
            lockout_threshold: 999, // incorrect
            ..policy
        };

        let update = AccountPolicyUpdate {
            expiry_period_in_secs: Some(7200),
            lockout_threshold: Some(3),
            ..Default::default()
        };

        assert!(store.update_account_policy(&mixed_policy, &update).is_err());

        // Verify NO values were updated (atomicity)
        let config = store.config_map();
        assert_eq!(
            config.current(KEY_EXPIRY_PERIOD).unwrap(),
            Some("3600".to_string()) // Should NOT be 7200
        );
        assert_eq!(
            config.current(KEY_LOCKOUT_THRESHOLD).unwrap(),
            Some("5".to_string())
        );
    }

    #[test]
    fn init_account_policy_atomicity() {
        let (_permit, store) = setup_store();

        // Pre-create ONE of the keys (simulating partial state or conflict)
        store.config_map().init(KEY_EXPIRY_PERIOD, "3600").unwrap();

        let policy = AccountPolicy {
            expiry_period_in_secs: 7200,
            lockout_threshold: 5,
            lockout_duration_in_secs: 1800,
            suspension_threshold: 10,
        };

        // 2. Try to initialize policy (should fail because one key exists)
        assert!(store.init_account_policy(&policy).is_err());

        // 3. Verify ALL other keys were NOT created (atomicity check)
        // If it wasn't atomic, "lockout_threshold" might have been created before failure
        let config = store.config_map();
        assert!(config.current(KEY_LOCKOUT_THRESHOLD).unwrap().is_none());
        assert!(config.current(KEY_LOCKOUT_DURATION).unwrap().is_none());
        assert!(config.current(KEY_SUSPENSION_THRESHOLD).unwrap().is_none());

        // Verify existing key was NOT overwritten
        assert_eq!(
            config.current(KEY_EXPIRY_PERIOD).unwrap(),
            Some("3600".to_string())
        );
    }

    #[test]
    fn init_account_policy_validation_failure() {
        let (_permit, store) = setup_store();

        // Invalid policy: lockout_threshold (10) > suspension_threshold (5)
        let policy = AccountPolicy {
            expiry_period_in_secs: 3600,
            lockout_threshold: 10,
            lockout_duration_in_secs: 1800,
            suspension_threshold: 5,
        };

        // Should return error due to validation
        assert!(store.init_account_policy(&policy).is_err());

        // Verify nothing was written
        let config = store.config_map();
        assert!(config.current(KEY_EXPIRY_PERIOD).unwrap().is_none());
    }

    #[test]
    fn update_account_policy_validation_failure() {
        let (_permit, store) = setup_store();

        let policy = AccountPolicy {
            expiry_period_in_secs: 3600,
            lockout_threshold: 5,
            lockout_duration_in_secs: 1800,
            suspension_threshold: 10,
        };
        store.init_account_policy(&policy).unwrap();

        // Try to update to an invalid state: lockout(15) > suspension(10)
        let update = AccountPolicyUpdate {
            lockout_threshold: Some(15),
            ..Default::default()
        };

        assert!(store.update_account_policy(&policy, &update).is_err());

        // Verify values remained unchanged
        let config = store.config_map();
        assert_eq!(
            config.current(KEY_LOCKOUT_THRESHOLD).unwrap(),
            Some("5".to_string())
        );
    }
}
