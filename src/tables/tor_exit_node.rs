//! The `tor_exit_node` table.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rocksdb::OptimisticTransactionDB;

use crate::{Map, Table, UniqueKey, types::FromKeyValue};

pub struct TorExitNode {
    pub ip_address: String,
    pub updated_at: DateTime<Utc>,
}

impl TorExitNode {
    fn into_key_value(self) -> (Vec<u8>, Vec<u8>) {
        (
            self.ip_address.into_bytes(),
            self.updated_at.to_string().into_bytes(),
        )
    }
}

impl UniqueKey for TorExitNode {
    type AsBytes<'a> = &'a [u8];

    fn unique_key(&self) -> &[u8] {
        self.ip_address.as_bytes()
    }
}

impl FromKeyValue for TorExitNode {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let ip_address =
            String::from_utf8(key.to_vec()).context("invalid IP address in database")?;
        let updated_at = String::from_utf8(value.to_vec())
            .context("invalid timestamp in database")?
            .parse()
            .context("invalid timestamp in database")?;
        Ok(TorExitNode {
            ip_address,
            updated_at,
        })
    }
}

/// Functions for the `tor_exit_node` map.
impl<'d> Table<'d, TorExitNode> {
    /// Opens the  `tor_exit_node` map in the database.
    ///
    /// Returns `None` if the map does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::TOR_EXIT_NODES).map(Table::new)
    }

    /// Deletes all existing entries and add new IP address(es)
    ///
    /// # Errors
    ///
    /// Returns an error the database operation fails.
    pub fn replace_all(&self, entries: impl Iterator<Item = TorExitNode>) -> Result<()> {
        let data: Vec<_> = entries.map(TorExitNode::into_key_value).collect();
        let entries: Vec<_> = data
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
            .collect();
        self.map.replace_all(&entries)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::Utc;
    use rocksdb::Direction;

    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{Iterable, Store, TorExitNode};

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
        let table = store.tor_exit_node_map();

        let t1 = Utc::now();
        let tester1 = TorExitNode {
            ip_address: "127.0.0.1".to_string(),
            updated_at: t1,
        };
        assert!(table.replace_all(std::iter::once(tester1)).is_ok());

        let iter = table.iter(Direction::Forward, None);
        assert_eq!(iter.count(), 1);

        let t2 = Utc::now();
        let tester2 = TorExitNode {
            ip_address: "1.0.0.127".to_string(),
            updated_at: t2,
        };
        assert!(table.replace_all(std::iter::once(tester2)).is_ok());

        let iter = table.iter(Direction::Forward, None);
        let entries: Result<Vec<_>, anyhow::Error> = iter.collect();
        assert!(entries.is_ok());
        let entries = entries.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(&entries[0].ip_address, "1.0.0.127");
        assert_eq!(entries[0].updated_at, t2);
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
            let table = store.tor_exit_node_map();

            let whole = whole_second_datetime();
            let fractional = fractional_second_datetime();

            table
                .replace_all(
                    [
                        TorExitNode {
                            ip_address: "10.0.0.1".to_string(),
                            updated_at: whole,
                        },
                        TorExitNode {
                            ip_address: "10.0.0.2".to_string(),
                            updated_at: fractional,
                        },
                    ]
                    .into_iter(),
                )
                .unwrap();

            let whole_value = table.map.get(b"10.0.0.1").unwrap().unwrap();
            assert_eq!(whole_value.as_ref(), WHOLE_SECOND_BYTES);

            let fractional_value = table.map.get(b"10.0.0.2").unwrap().unwrap();
            assert_eq!(fractional_value.as_ref(), FRACTIONAL_SECOND_BYTES);
        }

        #[test]
        fn test_updated_at_reads_legacy_chrono_string_bytes() {
            let (_permit, store) = super::setup_store();
            let table = store.tor_exit_node_map();

            let whole = whole_second_datetime();
            let fractional = fractional_second_datetime();

            table.map.put(b"10.0.0.1", WHOLE_SECOND_BYTES).unwrap();
            table.map.put(b"10.0.0.2", FRACTIONAL_SECOND_BYTES).unwrap();

            let entries: Vec<_> = table
                .iter(Direction::Forward, None)
                .collect::<Result<Vec<_>>>()
                .unwrap();
            assert_eq!(entries.len(), 2);

            let whole_entry = entries
                .iter()
                .find(|entry| entry.ip_address == "10.0.0.1")
                .expect("whole-second entry");
            assert_eq!(whole_entry.updated_at, whole);

            let fractional_entry = entries
                .iter()
                .find(|entry| entry.ip_address == "10.0.0.2")
                .expect("fractional-second entry");
            assert_eq!(fractional_entry.updated_at, fractional);

            let parsed_whole =
                TorExitNode::from_key_value(b"10.0.0.1", WHOLE_SECOND_BYTES).unwrap();
            assert_eq!(parsed_whole.ip_address, "10.0.0.1");
            assert_eq!(parsed_whole.updated_at, whole);

            let parsed_fractional =
                TorExitNode::from_key_value(b"10.0.0.2", FRACTIONAL_SECOND_BYTES).unwrap();
            assert_eq!(parsed_fractional.ip_address, "10.0.0.2");
            assert_eq!(parsed_fractional.updated_at, fractional);
        }
    }
}
