//! The `backup_config` table.

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

/// Configuration for RocksDB backup settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BackupConfig {
    /// Backup interval in days (must be >= 1).
    pub backup_duration: u16,
    /// Backup time in HH:MM:SS (UTC) format (two digits per field).
    pub backup_time: String,
    /// Maximum number of backup snapshots to retain (must be >= 1).
    pub num_of_backups_to_keep: u16,
}

impl BackupConfig {
    /// Creates a new `BackupConfig` with the specified values.
    ///
    /// # Arguments
    ///
    /// * `backup_duration` - Backup interval in days (must be >= 1)
    /// * `backup_time` - Backup time in HH:MM:SS (UTC) format (two digits per field)
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
        if parts.len() != 3 || parts.iter().any(|part| part.len() != 2) {
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

/// Update struct for partial backup configuration updates.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct BackupConfigUpdate {
    /// New backup interval in days (if Some).
    pub backup_duration: Option<u16>,
    /// New backup time in HH:MM:SS (UTC) format (two digits per field, if Some).
    pub backup_time: Option<String>,
    /// New maximum number of backup snapshots to retain (if Some).
    pub num_of_backups_to_keep: Option<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_new_err(
        backup_duration: u16,
        backup_time: &str,
        num_of_backups_to_keep: u16,
        expected_msg: &str,
    ) {
        let err = BackupConfig::new(
            backup_duration,
            backup_time.to_string(),
            num_of_backups_to_keep,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains(expected_msg),
            "expected error to contain '{expected_msg}', got '{err}'"
        );
    }

    fn assert_validate_err(config: &BackupConfig, expected_msg: &str) {
        let err = config.validate().unwrap_err().to_string();
        assert!(
            err.contains(expected_msg),
            "expected error to contain '{expected_msg}', got '{err}'"
        );
    }

    #[test]
    fn test_valid_backup_config() {
        let config = BackupConfig::new(7, "02:00:00".to_string(), 10).unwrap();
        assert_eq!(config.backup_duration, 7);
        assert_eq!(config.backup_time, "02:00:00");
        assert_eq!(config.num_of_backups_to_keep, 10);
    }

    #[test]
    fn test_new_invalid_backup_duration_zero() {
        assert_new_err(0, "02:00:00", 5, "backup_duration must be >= 1");
    }

    #[test]
    fn test_new_invalid_time_format() {
        assert_new_err(1, "2:00", 5, "backup_time must be in HH:MM:SS format");
    }

    #[test]
    fn test_new_invalid_hours() {
        assert_new_err(1, "24:00:00", 5, "hours must be between 0 and 23");
    }

    #[test]
    fn test_new_invalid_minutes() {
        assert_new_err(1, "12:60:00", 5, "minutes must be between 0 and 59");
    }

    #[test]
    fn test_new_invalid_seconds() {
        assert_new_err(1, "12:30:60", 5, "seconds must be between 0 and 59");
    }

    #[test]
    fn test_new_invalid_num_of_backups_zero() {
        assert_new_err(1, "02:00:00", 0, "num_of_backups_to_keep must be >= 1");
    }

    #[test]
    fn test_valid_backup_config_min_values() {
        let config = BackupConfig::new(1, "00:00:00".to_string(), 1).unwrap();
        assert_eq!(config.backup_duration, 1);
        assert_eq!(config.backup_time, "00:00:00");
        assert_eq!(config.num_of_backups_to_keep, 1);
    }

    #[test]
    fn test_valid_backup_config_max_time_bounds() {
        let config = BackupConfig::new(1, "23:59:59".to_string(), 1).unwrap();
        assert_eq!(config.backup_time, "23:59:59");
    }

    #[test]
    fn test_invalid_time_non_numeric_hours() {
        assert_new_err(1, "aa:00:00", 1, "hours must be a valid number");
    }

    #[test]
    fn test_invalid_time_non_numeric_minutes() {
        assert_new_err(1, "00:bb:00", 1, "minutes must be a valid number");
    }

    #[test]
    fn test_invalid_time_non_numeric_seconds() {
        assert_new_err(1, "00:00:cc", 1, "seconds must be a valid number");
    }

    #[test]
    fn test_invalid_time_empty() {
        assert_new_err(1, "", 1, "backup_time must be in HH:MM:SS format");
    }

    #[test]
    fn test_invalid_time_whitespace() {
        assert_new_err(1, "   ", 1, "backup_time must be in HH:MM:SS format");
    }

    #[test]
    fn test_invalid_time_missing_field() {
        assert_new_err(1, "00:00", 1, "backup_time must be in HH:MM:SS format");
    }

    #[test]
    fn test_invalid_time_single_digit_hours() {
        assert_new_err(1, "2:03:04", 1, "backup_time must be in HH:MM:SS format");
    }

    #[test]
    fn test_invalid_time_single_digit_minutes() {
        assert_new_err(1, "02:3:04", 1, "backup_time must be in HH:MM:SS format");
    }

    #[test]
    fn test_invalid_time_single_digit_seconds() {
        assert_new_err(1, "02:03:4", 1, "backup_time must be in HH:MM:SS format");
    }

    #[test]
    fn test_invalid_time_extra_field() {
        assert_new_err(
            1,
            "00:00:00:00",
            1,
            "backup_time must be in HH:MM:SS format",
        );
    }

    #[test]
    fn test_invalid_time_leading_space() {
        assert_new_err(1, " 00:00:00", 1, "backup_time must be in HH:MM:SS format");
    }

    #[test]
    fn test_invalid_time_trailing_space() {
        assert_new_err(1, "00:00:00 ", 1, "backup_time must be in HH:MM:SS format");
    }

    #[test]
    fn test_validate_direct_success() {
        let config = BackupConfig {
            backup_duration: 7,
            backup_time: "02:00:00".to_string(),
            num_of_backups_to_keep: 10,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_direct_invalid_time_format() {
        assert_validate_err(
            &BackupConfig {
                backup_duration: 1,
                backup_time: "2:03:04".to_string(),
                num_of_backups_to_keep: 1,
            },
            "backup_time must be in HH:MM:SS format",
        );
    }

    #[test]
    fn test_validate_direct_invalid_backup_duration() {
        assert_validate_err(
            &BackupConfig {
                backup_duration: 0,
                backup_time: "02:03:04".to_string(),
                num_of_backups_to_keep: 1,
            },
            "backup_duration must be >= 1",
        );
    }

    #[test]
    fn test_validate_direct_invalid_num_of_backups_to_keep() {
        assert_validate_err(
            &BackupConfig {
                backup_duration: 1,
                backup_time: "02:03:04".to_string(),
                num_of_backups_to_keep: 0,
            },
            "num_of_backups_to_keep must be >= 1",
        );
    }
}
