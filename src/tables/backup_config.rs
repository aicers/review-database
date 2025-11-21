//! The `backup_config` table.

use anyhow::{Context, Result, anyhow};
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use super::Value;
use crate::{Map, Table, UniqueKey, types::FromKeyValue};

const BACKUP_CONFIG_KEY: &str = "backup_config";
const DEFAULT_BACKUP_TIME: &str = "23:59:59"; // format: "%H:%M:%S"
const DEFAULT_BACKUP_DURATION: u16 = 1; // unit: day
const DEFAULT_NUM_OF_BACKUPS_TO_KEEP: u16 = 5;

/// Configuration for RocksDB backup settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BackupConfig {
    /// Backup interval in days (must be >= 1).
    pub backup_duration: u16,
    /// Backup time in HH:MM:SS (UTC) format.
    pub backup_time: String,
    /// Maximum number of backup snapshots to retain (must be >= 1).
    pub num_of_backups_to_keep: u16,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            backup_duration: DEFAULT_BACKUP_DURATION,
            backup_time: DEFAULT_BACKUP_TIME.to_string(),
            num_of_backups_to_keep: DEFAULT_NUM_OF_BACKUPS_TO_KEEP,
        }
    }
}

impl BackupConfig {
    /// Creates a new `BackupConfig` with the specified values.
    ///
    /// # Arguments
    ///
    /// * `backup_duration` - Backup interval in days (must be >= 1)
    /// * `backup_time` - Backup time in HH:MM:SS (UTC) format
    /// * `num_of_backups_to_keep` - Maximum number of backup snapshots to retain (must be >= 1)
    ///
    /// # Returns
    ///
    /// Returns the new `BackupConfig` on success.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * `backup_duration` is less than 1
    /// * `backup_time` does not match HH:MM:SS format
    /// * `num_of_backups_to_keep` is less than 1
    pub fn new(
        backup_duration: u16,
        backup_time: String,
        num_of_backups_to_keep: u16,
    ) -> Result<Self> {
        let config = Self {
            backup_duration,
            backup_time,
            num_of_backups_to_keep,
        };
        config.validate()?;
        Ok(config)
    }

    /// Validates the backup configuration.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * `backup_duration` is less than 1
    /// * `backup_time` does not match HH:MM:SS format
    /// * `num_of_backups_to_keep` is less than 1
    pub fn validate(&self) -> Result<()> {
        if self.backup_duration < 1 {
            return Err(anyhow!("backup_duration must be >= 1"));
        }

        // Validate backup_time format (HH:MM:SS)
        let parts: Vec<&str> = self.backup_time.split(':').collect();
        if parts.len() != 3 {
            return Err(anyhow!(
                "backup_time must be in HH:MM:SS format, got: {}",
                self.backup_time
            ));
        }

        let hours = parts[0]
            .parse::<u32>()
            .context("hours must be a valid number")?;
        let minutes = parts[1]
            .parse::<u32>()
            .context("minutes must be a valid number")?;
        let seconds = parts[2]
            .parse::<u32>()
            .context("seconds must be a valid number")?;

        if hours > 23 {
            return Err(anyhow!("hours must be between 0 and 23, got: {hours}"));
        }
        if minutes > 59 {
            return Err(anyhow!("minutes must be between 0 and 59, got: {minutes}"));
        }
        if seconds > 59 {
            return Err(anyhow!("seconds must be between 0 and 59, got: {seconds}"));
        }

        if self.num_of_backups_to_keep < 1 {
            return Err(anyhow!("num_of_backups_to_keep must be >= 1"));
        }

        Ok(())
    }
}

impl FromKeyValue for BackupConfig {
    fn from_key_value(_key: &[u8], value: &[u8]) -> Result<Self> {
        super::deserialize(value).context("failed to deserialize BackupConfig")
    }
}

impl UniqueKey for BackupConfig {
    type AsBytes<'a> = &'a [u8];

    fn unique_key(&self) -> &[u8] {
        BACKUP_CONFIG_KEY.as_bytes()
    }
}

impl Value for BackupConfig {
    type AsBytes<'a> = Vec<u8>;

    fn value(&self) -> Vec<u8> {
        super::serialize(self).expect("BackupConfig serialization should not fail")
    }
}

/// Functions for the `backup_config` map.
impl<'d> Table<'d, BackupConfig> {
    /// Opens the `backup_config` map in the database.
    ///
    /// Returns `None` if the map does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::CONFIGS).map(Table::new)
    }

    /// Saves or updates the backup configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails or the database operation fails.
    pub fn save(&self, config: &BackupConfig) -> Result<()> {
        config.validate()?;
        self.put(config)
    }

    /// Updates the backup configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails or the database operation fails.
    pub fn update_config(&self, old: &BackupConfig, new: &BackupConfig) -> Result<()> {
        new.validate()?;
        let old_value = old.value();
        let new_value = new.value();
        self.map.update(
            (old.unique_key(), old_value.as_ref()),
            (new.unique_key(), new_value.as_ref()),
        )
    }

    /// Reads the backup configuration from the database.
    ///
    /// Returns the default configuration if none exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or the data is invalid.
    pub fn read(&self) -> Result<BackupConfig> {
        match self.map.get(BACKUP_CONFIG_KEY.as_bytes())? {
            Some(value) => {
                BackupConfig::from_key_value(BACKUP_CONFIG_KEY.as_bytes(), value.as_ref())
            }
            None => Ok(BackupConfig::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::Store;

    #[test]
    fn test_default_backup_config() {
        let config = BackupConfig::default();
        assert_eq!(config.backup_duration, 1);
        assert_eq!(config.backup_time, "23:59:59");
        assert_eq!(config.num_of_backups_to_keep, 5);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_valid_backup_config() {
        let config = BackupConfig::new(7, "02:00:00".to_string(), 10).unwrap();
        assert_eq!(config.backup_duration, 7);
        assert_eq!(config.backup_time, "02:00:00");
        assert_eq!(config.num_of_backups_to_keep, 10);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validation_backup_duration_zero() {
        let result = BackupConfig::new(0, "02:00:00".to_string(), 5);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("backup_duration must be >= 1")
        );
    }

    #[test]
    fn test_validation_invalid_time_format() {
        let result = BackupConfig::new(1, "2:00".to_string(), 5);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("backup_time must be in HH:MM:SS format")
        );
    }

    #[test]
    fn test_validation_invalid_hours() {
        let result = BackupConfig::new(1, "24:00:00".to_string(), 5);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("hours must be between 0 and 23")
        );
    }

    #[test]
    fn test_validation_invalid_minutes() {
        let result = BackupConfig::new(1, "12:60:00".to_string(), 5);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("minutes must be between 0 and 59")
        );
    }

    #[test]
    fn test_validation_invalid_seconds() {
        let result = BackupConfig::new(1, "12:30:60".to_string(), 5);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("seconds must be between 0 and 59")
        );
    }

    #[test]
    fn test_validation_num_of_backups_zero() {
        let result = BackupConfig::new(1, "02:00:00".to_string(), 0);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("num_of_backups_to_keep must be >= 1")
        );
    }

    #[test]
    fn test_save_and_read() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let table = store.backup_config_map();

        // Read should return default when no config exists
        let config = table.read().unwrap();
        assert_eq!(config, BackupConfig::default());

        // Save a new config
        let new_config = BackupConfig::new(7, "02:00:00".to_string(), 10).unwrap();
        assert!(table.save(&new_config).is_ok());

        // Read should return the saved config
        let read_config = table.read().unwrap();
        assert_eq!(read_config, new_config);
    }

    #[test]
    fn test_update_config() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let table = store.backup_config_map();

        // Save initial config
        let old_config = BackupConfig::new(7, "02:00:00".to_string(), 10).unwrap();
        assert!(table.save(&old_config).is_ok());

        // Update the config
        let new_config = BackupConfig::new(14, "03:30:00".to_string(), 15).unwrap();
        assert!(table.update_config(&old_config, &new_config).is_ok());

        // Read should return the updated config
        let read_config = table.read().unwrap();
        assert_eq!(read_config, new_config);
    }

    #[test]
    fn test_save_invalid_config() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let table = store.backup_config_map();

        // Try to save an invalid config
        let invalid_config = BackupConfig {
            backup_duration: 0,
            backup_time: "02:00:00".to_string(),
            num_of_backups_to_keep: 5,
        };
        assert!(table.save(&invalid_config).is_err());
    }

    #[test]
    fn test_update_config_invalid_new_config() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let table = store.backup_config_map();

        // Save a valid initial config
        let old_config = BackupConfig::new(7, "02:00:00".to_string(), 10).unwrap();
        assert!(table.save(&old_config).is_ok());

        // Try to update with an invalid new config (backup_duration = 0)
        let invalid_new_config = BackupConfig {
            backup_duration: 0,
            backup_time: "03:30:00".to_string(),
            num_of_backups_to_keep: 15,
        };
        assert!(
            table
                .update_config(&old_config, &invalid_new_config)
                .is_err()
        );

        // Verify the original config remains unchanged
        let read_config = table.read().unwrap();
        assert_eq!(read_config, old_config);
    }
}
