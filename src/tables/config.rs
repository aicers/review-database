//! The `configs` map.

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;

use crate::{Map, Table};

// Backup config keys
pub const KEY_BACKUP_DURATION: &str = "backup_duration";
pub const KEY_BACKUP_TIME: &str = "backup_time";
pub const KEY_NUM_OF_BACKUPS_TO_KEEP: &str = "num_of_backups_to_keep";

// Event retention config key
pub const KEY_EVENT_RETENTION_PERIOD_DAYS: &str = "event_retention_period_days";

// Retention config keys
pub const KEY_RETENTION_PERIOD: &str = "stats_retention_period_in_days";

/// Functions for the `configs` map.
impl<'d> Table<'d, String> {
    /// Opens the  `configs` map in the database.
    ///
    /// Returns `None` if the map does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::CONFIGS).map(Table::new)
    }

    /// Initializes a config value.
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

    /// Updates or initializes a config value.
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

    /// Deletes a config value by key.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete(&self, key: &str) -> Result<()> {
        self.map.delete(key.as_bytes())
    }

    /// Returns the current config value for `key`, or `None` if it hasn't
    /// been initialized.
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
        KEY_BACKUP_DURATION, KEY_BACKUP_TIME, KEY_EVENT_RETENTION_PERIOD_DAYS,
        KEY_NUM_OF_BACKUPS_TO_KEEP, KEY_RETENTION_PERIOD,
    };
    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{BackupConfig, BackupConfigUpdate, RetentionConfig, RetentionConfigUpdate, Store};

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path(), None).unwrap());
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

    fn assert_backup_config_values(
        store: &Store,
        duration: Option<&str>,
        time: Option<&str>,
        num_to_keep: Option<&str>,
    ) {
        let config_map = store.config_map();
        assert_eq!(
            config_map.current(KEY_BACKUP_DURATION).unwrap(),
            duration.map(ToString::to_string)
        );
        assert_eq!(
            config_map.current(KEY_BACKUP_TIME).unwrap(),
            time.map(ToString::to_string)
        );
        assert_eq!(
            config_map.current(KEY_NUM_OF_BACKUPS_TO_KEEP).unwrap(),
            num_to_keep.map(ToString::to_string)
        );
    }

    #[test]
    fn backup_config_read_returns_none_when_missing() {
        let (_permit, store) = setup_store();

        // Read should return None when no config exists
        let config = store.backup_config().unwrap();
        assert!(config.is_none());
    }

    #[test]
    fn init_backup_config_success() {
        let (_permit, store) = setup_store();

        let config = BackupConfig::new(7, "02:00:00".to_string(), 10).unwrap();

        // Initialize backup config
        assert!(store.init_backup_config(&config).is_ok());

        // Verify all values were stored correctly
        assert_backup_config_values(&store, Some("7"), Some("02:00:00"), Some("10"));

        // Read should return the initialized config
        let read_config = store.backup_config().unwrap();
        assert_eq!(read_config, Some(config));
    }

    #[test]
    fn init_backup_config_already_exists_fails_without_overwrite() {
        let (_permit, store) = setup_store();

        let config = BackupConfig::new(7, "02:00:00".to_string(), 10).unwrap();

        // Initialize backup config
        assert!(store.init_backup_config(&config).is_ok());

        let new_config = BackupConfig::new(14, "03:00:00".to_string(), 5).unwrap();

        // Try to initialize again - should fail
        assert!(store.init_backup_config(&new_config).is_err());

        // Verify existing values were NOT overwritten
        assert_backup_config_values(&store, Some("7"), Some("02:00:00"), Some("10"));
    }

    #[test]
    fn init_backup_config_validation_failure() {
        let (_permit, store) = setup_store();

        // Invalid config: backup_duration = 0
        let config = BackupConfig {
            backup_duration: 0,
            backup_time: "02:00:00".to_string(),
            num_of_backups_to_keep: 10,
        };

        // Should return error due to validation
        let result = store.init_backup_config(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("backup_duration must be >= 1")
        );

        // Verify nothing was written
        assert_backup_config_values(&store, None, None, None);
    }

    #[test]
    fn update_backup_config_all_fields() {
        let (_permit, store) = setup_store();

        let config = BackupConfig::new(7, "02:00:00".to_string(), 10).unwrap();

        // Initialize backup config
        assert!(store.init_backup_config(&config).is_ok());

        let update = BackupConfigUpdate {
            backup_duration: Some(14),
            backup_time: Some("03:30:00".to_string()),
            num_of_backups_to_keep: Some(15),
        };

        // Update all fields
        assert!(store.update_backup_config(&config, &update).is_ok());

        // Verify all values were updated
        assert_backup_config_values(&store, Some("14"), Some("03:30:00"), Some("15"));

        // Read should return the updated config
        let expected = BackupConfig::new(14, "03:30:00".to_string(), 15).unwrap();
        let read_config = store.backup_config().unwrap();
        assert_eq!(read_config, Some(expected));
    }

    #[test]
    fn update_backup_config_partial() {
        let (_permit, store) = setup_store();

        let config = BackupConfig::new(7, "02:00:00".to_string(), 10).unwrap();

        // Initialize backup config
        assert!(store.init_backup_config(&config).is_ok());

        let update = BackupConfigUpdate {
            backup_duration: Some(14),
            ..Default::default()
        };

        // Update only backup_duration
        assert!(store.update_backup_config(&config, &update).is_ok());

        // Verify only backup_duration changed
        assert_backup_config_values(&store, Some("14"), Some("02:00:00"), Some("10"));
    }

    #[test]
    fn update_backup_config_fails_on_old_value_mismatch() {
        let (_permit, store) = setup_store();

        let config = BackupConfig::new(7, "02:00:00".to_string(), 10).unwrap();

        // Initialize backup config
        assert!(store.init_backup_config(&config).is_ok());

        let wrong_config = BackupConfig {
            backup_duration: 999, // wrong old value
            ..config.clone()
        };

        let update = BackupConfigUpdate {
            backup_duration: Some(14),
            ..Default::default()
        };

        // Try to update with wrong old values - should fail
        assert!(store.update_backup_config(&wrong_config, &update).is_err());

        // Verify values remained unchanged
        assert_backup_config_values(&store, Some("7"), Some("02:00:00"), Some("10"));
    }

    #[test]
    fn update_backup_config_validation_failure() {
        let (_permit, store) = setup_store();

        let config = BackupConfig::new(7, "02:00:00".to_string(), 10).unwrap();
        store.init_backup_config(&config).unwrap();

        // Try to update to an invalid state: backup_duration = 0
        let update = BackupConfigUpdate {
            backup_duration: Some(0),
            ..Default::default()
        };

        let result = store.update_backup_config(&config, &update);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("backup_duration must be >= 1")
        );

        // Verify values remained unchanged
        assert_backup_config_values(&store, Some("7"), Some("02:00:00"), Some("10"));
    }

    #[test]
    fn update_backup_config_no_changes() {
        let (_permit, store) = setup_store();

        let config = BackupConfig::new(7, "02:00:00".to_string(), 10).unwrap();

        // Initialize backup config
        assert!(store.init_backup_config(&config).is_ok());

        let update = BackupConfigUpdate::default();

        // Update with no changes (all None)
        assert!(store.update_backup_config(&config, &update).is_ok());

        // Verify values remained unchanged
        assert_backup_config_values(&store, Some("7"), Some("02:00:00"), Some("10"));
    }

    #[test]
    fn update_backup_config_atomicity_on_mixed_old_values() {
        let (_permit, store) = setup_store();

        let config = BackupConfig::new(7, "02:00:00".to_string(), 10).unwrap();

        // Initialize backup config
        assert!(store.init_backup_config(&config).is_ok());

        // Try to update with mixed valid/invalid old values
        let mixed_config = BackupConfig {
            backup_duration: 999, // incorrect
            ..config.clone()
        };

        let update = BackupConfigUpdate {
            backup_duration: Some(14),
            backup_time: Some("03:00:00".to_string()),
            ..Default::default()
        };

        assert!(store.update_backup_config(&mixed_config, &update).is_err());

        // Verify NO values were updated (atomicity)
        assert_backup_config_values(&store, Some("7"), Some("02:00:00"), Some("10"));
    }

    #[test]
    fn init_backup_config_atomicity() {
        let (_permit, store) = setup_store();

        // Pre-create ONE of the keys (simulating partial state or conflict)
        store.config_map().init(KEY_BACKUP_DURATION, "7").unwrap();

        let config = BackupConfig::new(14, "02:00:00".to_string(), 10).unwrap();

        // Try to initialize config (should fail because one key exists)
        let result = store.init_backup_config(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("key already exists")
        );

        // Verify ALL other keys were NOT created (atomicity check)
        assert_backup_config_values(&store, Some("7"), None, None);
    }

    #[test]
    fn update_backup_config_fails_when_missing() {
        let (_permit, store) = setup_store();

        let config = BackupConfig::new(7, "02:00:00".to_string(), 10).unwrap();

        let update = BackupConfigUpdate {
            backup_duration: Some(14),
            ..Default::default()
        };

        // Try to update when no config exists - should fail
        let result = store.update_backup_config(&config, &update);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no such entry"));

        // Verify nothing was written
        assert_backup_config_values(&store, None, None, None);
    }

    #[test]
    fn backup_config_missing_keys_error_includes_keys() {
        let (_permit, store) = setup_store();
        let config_map = store.config_map();

        config_map.init(KEY_BACKUP_DURATION, "7").unwrap();

        let err = store.backup_config().unwrap_err().to_string();
        assert!(
            err.contains("incomplete backup configuration: missing keys:"),
            "error message should include missing keys prefix: {err}"
        );
        assert!(
            err.contains(KEY_BACKUP_TIME),
            "error should mention missing backup_time: {err}"
        );
        assert!(
            err.contains(KEY_NUM_OF_BACKUPS_TO_KEEP),
            "error should mention missing num_of_backups_to_keep: {err}"
        );
    }

    #[test]
    fn event_retention_default_is_none() {
        let (_permit, store) = setup_store();
        let result = store.event_retention_period().unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn set_event_retention_period_days() {
        let (_permit, store) = setup_store();

        store.set_event_retention_period(Some(365)).unwrap();
        assert_eq!(store.event_retention_period().unwrap(), Some(365));

        // Update to a different value.
        store.set_event_retention_period(Some(30)).unwrap();
        assert_eq!(store.event_retention_period().unwrap(), Some(30));
    }

    #[test]
    fn set_event_retention_unlimited() {
        let (_permit, store) = setup_store();

        // Set a value first, then switch to unlimited.
        store.set_event_retention_period(Some(90)).unwrap();
        assert_eq!(store.event_retention_period().unwrap(), Some(90));

        store.set_event_retention_period(None).unwrap();
        assert_eq!(store.event_retention_period().unwrap(), None);
    }

    #[test]
    fn set_event_retention_zero_is_rejected() {
        let (_permit, store) = setup_store();
        let err = store.set_event_retention_period(Some(0));
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("must be >= 1 day"));
    }

    #[test]
    fn event_retention_raw_value() {
        let (_permit, store) = setup_store();
        let config = store.config_map();

        // Verify the raw config key is correct.
        store.set_event_retention_period(Some(180)).unwrap();
        assert_eq!(
            config.current(KEY_EVENT_RETENTION_PERIOD_DAYS).unwrap(),
            Some("180".to_string())
        );

        // Setting unlimited removes the key entirely.
        store.set_event_retention_period(None).unwrap();
        assert_eq!(
            config.current(KEY_EVENT_RETENTION_PERIOD_DAYS).unwrap(),
            None
        );
    }

    #[test]
    fn retention_config_read_returns_none_when_missing() {
        let (_permit, store) = setup_store();
        let config = store.retention_config().unwrap();
        assert!(config.is_none());
    }

    #[test]
    fn init_retention_config_success() {
        let (_permit, store) = setup_store();

        let config = RetentionConfig::new(90).unwrap();
        assert!(store.init_retention_config(&config).is_ok());

        let config_map = store.config_map();
        assert_eq!(
            config_map.current(KEY_RETENTION_PERIOD).unwrap(),
            Some("90".to_string())
        );

        let read_config = store.retention_config().unwrap();
        assert_eq!(read_config, Some(config));
    }

    #[test]
    fn init_retention_config_already_exists() {
        let (_permit, store) = setup_store();

        let config = RetentionConfig::new(90).unwrap();
        assert!(store.init_retention_config(&config).is_ok());

        let new_config = RetentionConfig::new(180).unwrap();
        assert!(store.init_retention_config(&new_config).is_err());

        // Verify original value is unchanged
        let read_config = store.retention_config().unwrap();
        assert_eq!(read_config, Some(config));
    }

    #[test]
    fn init_retention_config_validation_failure() {
        let (_permit, store) = setup_store();

        let config = RetentionConfig { period_in_days: 0 };
        let result = store.init_retention_config(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("period_in_days must be >= 1")
        );

        // Verify nothing was written
        let config_map = store.config_map();
        assert!(config_map.current(KEY_RETENTION_PERIOD).unwrap().is_none());
    }

    #[test]
    fn update_retention_config_success() {
        let (_permit, store) = setup_store();

        let config = RetentionConfig::new(90).unwrap();
        store.init_retention_config(&config).unwrap();

        let update = RetentionConfigUpdate {
            period_in_days: Some(180),
        };
        assert!(store.update_retention_config(&config, &update).is_ok());

        let read_config = store.retention_config().unwrap();
        assert_eq!(
            read_config,
            Some(RetentionConfig {
                period_in_days: 180
            })
        );
    }

    #[test]
    fn update_retention_config_no_changes() {
        let (_permit, store) = setup_store();

        let config = RetentionConfig::new(90).unwrap();
        store.init_retention_config(&config).unwrap();

        let update = RetentionConfigUpdate::default();
        assert!(store.update_retention_config(&config, &update).is_ok());

        let read_config = store.retention_config().unwrap();
        assert_eq!(read_config, Some(config));
    }

    #[test]
    fn update_retention_config_wrong_old_value() {
        let (_permit, store) = setup_store();

        let config = RetentionConfig::new(90).unwrap();
        store.init_retention_config(&config).unwrap();

        let wrong = RetentionConfig {
            period_in_days: 999,
        };
        let update = RetentionConfigUpdate {
            period_in_days: Some(180),
        };
        assert!(store.update_retention_config(&wrong, &update).is_err());

        // Verify value unchanged
        let read_config = store.retention_config().unwrap();
        assert_eq!(read_config, Some(config));
    }

    #[test]
    fn clear_retention_config_removes_existing() {
        let (_permit, store) = setup_store();

        let config = RetentionConfig::new(90).unwrap();
        store.init_retention_config(&config).unwrap();
        assert_eq!(store.retention_config().unwrap(), Some(config.clone()));

        store.clear_retention_config().unwrap();
        assert!(store.retention_config().unwrap().is_none());

        // After clearing, re-initialization must succeed again.
        store.init_retention_config(&config).unwrap();
        assert_eq!(store.retention_config().unwrap(), Some(config));
    }

    #[test]
    fn clear_retention_config_when_unset_is_noop() {
        let (_permit, store) = setup_store();

        assert!(store.retention_config().unwrap().is_none());
        store.clear_retention_config().unwrap();
        assert!(store.retention_config().unwrap().is_none());
    }

    #[test]
    fn update_retention_config_validation_failure() {
        let (_permit, store) = setup_store();

        let config = RetentionConfig::new(90).unwrap();
        store.init_retention_config(&config).unwrap();

        let update = RetentionConfigUpdate {
            period_in_days: Some(0),
        };
        let result = store.update_retention_config(&config, &update);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("period_in_days must be >= 1")
        );

        // Verify value unchanged
        let read_config = store.retention_config().unwrap();
        assert_eq!(read_config, Some(config));
    }
}
