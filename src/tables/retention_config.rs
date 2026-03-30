//! The `retention_config` table.

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

/// Configuration for cluster statistics retention settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetentionConfig {
    /// Retention period in days for column statistics data (must be >= 1).
    pub period_in_days: u16,
}

impl RetentionConfig {
    /// Creates a new `RetentionConfig` with the specified retention period.
    ///
    /// # Errors
    ///
    /// Returns an error if `period_in_days` is less than 1.
    pub fn new(period_in_days: u16) -> Result<Self> {
        let config = Self { period_in_days };
        config.validate()?;
        Ok(config)
    }

    /// Validates the retention configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if `period_in_days` is less than 1.
    pub fn validate(&self) -> Result<()> {
        if self.period_in_days < 1 {
            return Err(anyhow!("period_in_days must be >= 1"));
        }
        Ok(())
    }
}

/// Update struct for partial retention configuration updates.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct RetentionConfigUpdate {
    /// New retention period in days (if Some).
    pub period_in_days: Option<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_retention_config() {
        let config = RetentionConfig::new(90).unwrap();
        assert_eq!(config.period_in_days, 90);
    }

    #[test]
    fn test_valid_retention_config_min() {
        let config = RetentionConfig::new(1).unwrap();
        assert_eq!(config.period_in_days, 1);
    }

    #[test]
    fn test_invalid_zero_period() {
        let err = RetentionConfig::new(0).unwrap_err().to_string();
        assert!(
            err.contains("period_in_days must be >= 1"),
            "expected error to contain 'period_in_days must be >= 1', got '{err}'"
        );
    }

    #[test]
    fn test_validate_direct_success() {
        let config = RetentionConfig { period_in_days: 30 };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_direct_invalid() {
        let config = RetentionConfig { period_in_days: 0 };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("period_in_days must be >= 1"));
    }
}
