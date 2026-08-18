//! The `trusted_user_agent` map.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rocksdb::OptimisticTransactionDB;

use super::Value;
use crate::{Map, Table, UniqueKey, types::FromKeyValue};

pub struct TrustedUserAgent {
    pub user_agent: String,
    pub updated_at: DateTime<Utc>,
}

impl FromKeyValue for TrustedUserAgent {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let user_agent = std::str::from_utf8(key)
            .context("invalid user-agent in database")?
            .to_owned();
        let updated_at = std::str::from_utf8(value)
            .context("invalid timestamp in database")?
            .parse()
            .context("invalid timestamp in database")?;
        Ok(TrustedUserAgent {
            user_agent,
            updated_at,
        })
    }
}

impl UniqueKey for TrustedUserAgent {
    type AsBytes<'a> = &'a [u8];

    fn unique_key(&self) -> &[u8] {
        self.user_agent.as_bytes()
    }
}

impl Value for TrustedUserAgent {
    type AsBytes<'a> = Vec<u8>;

    fn value(&self) -> Vec<u8> {
        self.updated_at.to_string().into_bytes()
    }
}

/// Functions for the `trusted_user_agent` map.
impl<'d> Table<'d, TrustedUserAgent> {
    /// Opens the  `trusted_user_agent` map in the database.
    ///
    /// Returns `None` if the map does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::TRUSTED_USER_AGENTS).map(Table::new)
    }

    /// Removes a `trusted_user_agent` with the given name.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn remove(&self, name: &str) -> Result<()> {
        self.map.delete(name.as_bytes())
    }

    /// Update a `trusted_user_agent`.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn update(&self, old: &str, new: &TrustedUserAgent) -> Result<()> {
        let Some(value) = self.map.get(old.as_bytes())? else {
            return Err(anyhow::anyhow!("{old} doesn't exist in database"));
        };

        self.map.update(
            (old.as_bytes(), value.as_ref()),
            (new.unique_key(), &new.value()),
        )
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use anyhow::Result;
    use chrono::Utc;
    use rocksdb::Direction;

    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{Iterable, Store, TrustedUserAgent};

    #[test]
    fn operations() {
        let (_permit, store) = setup_store();
        let table = store.trusted_user_agent_map();

        let a = create_entry("a");
        assert!(table.put(&a).is_ok());

        let b = create_entry("b");
        assert!(table.insert(&b).is_ok());

        let c = create_entry("c");
        assert!(table.update("b", &a).is_err());
        assert!(table.update("d", &a).is_err());
        assert!(table.update("b", &c).is_ok());

        assert_eq!(table.iter(Direction::Forward, None).count(), 2);
        assert_eq!(
            table
                .iter(Direction::Forward, None)
                .collect::<Result<Vec<_>>>()
                .unwrap()
                .into_iter()
                .map(|u| u.user_agent)
                .collect::<Vec<_>>(),
            vec!["a".to_string(), "c".to_string()]
        );

        assert!(table.remove(a.user_agent.as_str()).is_ok());
        assert!(table.remove(c.user_agent.as_str()).is_ok());
        assert_eq!(table.iter(Direction::Forward, None).count(), 0);
    }

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path(), None).unwrap());
        (permit, store)
    }

    fn create_entry(name: &str) -> TrustedUserAgent {
        TrustedUserAgent {
            user_agent: name.to_string(),
            updated_at: Utc::now(),
        }
    }

    /// Baseline tests for the chrono string bytes stored in `updated_at`.
    ///
    /// These tests pin the current `DateTime<Utc>::to_string()` write format and
    /// read parsing behavior. A follow-up migration will normalize these values
    /// to `i64` epoch seconds; that migration is out of scope for this issue.
    mod timestamp_contract {
        use anyhow::Result;
        use chrono::{DateTime, NaiveDateTime, Utc};
        use rocksdb::Direction;

        use super::*;
        use crate::types::FromKeyValue;

        const WHOLE_SECOND_TS: i64 = 951_827_696;
        const FRACTIONAL_NSEC: u32 = 123_456_789;

        const WHOLE_SECOND_BYTES: &[u8] = b"2000-02-29 12:34:56 UTC";
        const FRACTIONAL_SECOND_BYTES: &[u8] = b"2000-02-29 12:34:56.123456789 UTC";

        // `from_utc` / `from_timestamp_opt` match the construction style documented in
        // issue #747; both are deprecated but still mirror production chrono usage.
        #[allow(deprecated)]
        fn whole_second_datetime() -> DateTime<Utc> {
            DateTime::from_utc(
                NaiveDateTime::from_timestamp_opt(WHOLE_SECOND_TS, 0)
                    .expect("valid whole-second timestamp"),
                Utc,
            )
        }

        #[allow(deprecated)]
        fn fractional_second_datetime() -> DateTime<Utc> {
            DateTime::from_utc(
                NaiveDateTime::from_timestamp_opt(WHOLE_SECOND_TS, FRACTIONAL_NSEC)
                    .expect("valid fractional-second timestamp"),
                Utc,
            )
        }

        #[test]
        fn test_updated_at_writer_stores_chrono_string_bytes() {
            let (_permit, store) = super::setup_store();
            let table = store.trusted_user_agent_map();

            let whole = whole_second_datetime();
            let fractional = fractional_second_datetime();

            table
                .insert(&TrustedUserAgent {
                    user_agent: "whole-second-agent".to_string(),
                    updated_at: whole,
                })
                .unwrap();
            table
                .insert(&TrustedUserAgent {
                    user_agent: "fractional-second-agent".to_string(),
                    updated_at: fractional,
                })
                .unwrap();

            let whole_value = table.map.get(b"whole-second-agent").unwrap().unwrap();
            assert_eq!(whole_value.as_ref(), WHOLE_SECOND_BYTES);

            let fractional_value = table.map.get(b"fractional-second-agent").unwrap().unwrap();
            assert_eq!(fractional_value.as_ref(), FRACTIONAL_SECOND_BYTES);
        }

        #[test]
        fn test_updated_at_reads_legacy_chrono_string_bytes() {
            let (_permit, store) = super::setup_store();
            let table = store.trusted_user_agent_map();

            let whole = whole_second_datetime();
            let fractional = fractional_second_datetime();

            table
                .map
                .put(b"whole-second-agent", WHOLE_SECOND_BYTES)
                .unwrap();
            table
                .map
                .put(b"fractional-second-agent", FRACTIONAL_SECOND_BYTES)
                .unwrap();

            let entries: Vec<_> = table
                .iter(Direction::Forward, None)
                .collect::<Result<Vec<_>>>()
                .unwrap();
            assert_eq!(entries.len(), 2);

            let whole_entry = entries
                .iter()
                .find(|entry| entry.user_agent == "whole-second-agent")
                .expect("whole-second entry");
            assert_eq!(whole_entry.updated_at, whole);

            let fractional_entry = entries
                .iter()
                .find(|entry| entry.user_agent == "fractional-second-agent")
                .expect("fractional-second entry");
            assert_eq!(fractional_entry.updated_at, fractional);

            let parsed_whole =
                TrustedUserAgent::from_key_value(b"whole-second-agent", WHOLE_SECOND_BYTES)
                    .unwrap();
            assert_eq!(parsed_whole.user_agent, "whole-second-agent");
            assert_eq!(parsed_whole.updated_at, whole);

            let parsed_fractional = TrustedUserAgent::from_key_value(
                b"fractional-second-agent",
                FRACTIONAL_SECOND_BYTES,
            )
            .unwrap();
            assert_eq!(parsed_fractional.user_agent, "fractional-second-agent");
            assert_eq!(parsed_fractional.updated_at, fractional);
        }
    }
}
