//! The `tor_exit_node` table.

use anyhow::{Context, Result};
use jiff::Timestamp;
use rocksdb::OptimisticTransactionDB;

use crate::{
    Map, Table, UniqueKey,
    timestamp::{from_i64_nanos, saturating_i64_nanos},
    types::FromKeyValue,
};

pub struct TorExitNode {
    pub ip_address: String,
    pub updated_at: Timestamp,
}

impl TorExitNode {
    fn into_key_value(self) -> (Vec<u8>, Vec<u8>) {
        let value = super::serialize(&saturating_i64_nanos(self.updated_at))
            .expect("an i64 always serializes");
        (self.ip_address.into_bytes(), value)
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
        let nanos: i64 = super::deserialize(value).context("invalid timestamp in database")?;
        let updated_at = from_i64_nanos(nanos).context("invalid timestamp in database")?;
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
    fn replacement_does_not_commit_after_corrupt_iteration() {
        let _permit = acquire_db_permit();
        let dir = tempfile::tempdir().unwrap();
        let mut options = rocksdb::Options::default();
        options.create_if_missing(true);
        options.create_missing_column_families(true);
        {
            let db: rocksdb::OptimisticTransactionDB = rocksdb::OptimisticTransactionDB::open_cf(
                &options,
                dir.path(),
                [super::super::TOR_EXIT_NODES],
            )
            .unwrap();
            let cf = db.cf_handle(super::super::TOR_EXIT_NODES).unwrap();
            for i in 0..20_000 {
                db.put_cf(
                    cf,
                    format!("{i:08}"),
                    format!("{}-{i:08}", "value".repeat(30)),
                )
                .unwrap();
            }
            let before = crate::test::sst_files(dir.path());
            db.flush_cf(cf).unwrap();
            drop(db);
            crate::test::corrupt_new_sst(dir.path(), &before);
        }
        let db: rocksdb::OptimisticTransactionDB = rocksdb::OptimisticTransactionDB::open_cf(
            &options,
            dir.path(),
            [super::super::TOR_EXIT_NODES],
        )
        .unwrap();
        let table = crate::Table::<TorExitNode>::open(&db).unwrap();
        let result = table.replace_all(std::iter::once(TorExitNode {
            ip_address: "zzzzzzzz".to_owned(),
            updated_at: jiff::Timestamp::now(),
        }));
        let error = result.unwrap_err();
        assert_eq!(
            error.downcast_ref::<rocksdb::Error>().unwrap().kind(),
            rocksdb::ErrorKind::Corruption
        );
        assert!(table.map.get(b"zzzzzzzz").unwrap().is_none());
        assert!(table.map.get(b"00000000").unwrap().is_some());
    }

    #[test]
    fn operations() {
        let (_permit, store) = setup_store();
        let table = store.tor_exit_node_map();

        let t1 = jiff::Timestamp::now();
        let tester1 = TorExitNode {
            ip_address: "127.0.0.1".to_string(),
            updated_at: t1,
        };
        assert!(table.replace_all(std::iter::once(tester1)).is_ok());

        let iter = table.iter(Direction::Forward, None);
        assert_eq!(iter.count(), 1);

        let t2 = jiff::Timestamp::now();
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

    /// Tests pinning the 0.62 bytes of `updated_at`: the whole value is an
    /// `i64` of Unix-epoch nanoseconds, encoded with `tables::serialize`.
    mod timestamp_contract {
        use anyhow::Result;
        use jiff::Timestamp;
        use rocksdb::Direction;

        use super::*;
        use crate::types::FromKeyValue;

        const WHOLE_SECOND_TS: i64 = 951_827_696;
        const FRACTIONAL_NSEC: i32 = 123_456_789;

        /// `2000-02-29T12:34:56Z` as varint `i64` nanoseconds.
        const WHOLE_SECOND_BYTES: &[u8] = &[0xfd, 0x00, 0xc0, 0xea, 0x36, 0x7e, 0x24, 0x6b, 0x1a];
        /// `2000-02-29T12:34:56.123456789Z` as varint `i64` nanoseconds.
        const FRACTIONAL_SECOND_BYTES: &[u8] =
            &[0xfd, 0x2a, 0x5a, 0xa2, 0x45, 0x7e, 0x24, 0x6b, 0x1a];
        /// [`i64::MAX`] as varint `i64` nanoseconds.
        const SATURATED_BYTES: &[u8] = &[0xfd, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        /// The 0.61 `Display` bytes, which only the 0.62 migration reads.
        const V0_61_BYTES: &[u8] = b"2000-02-29 12:34:56.123456789 UTC";

        fn whole_second_timestamp() -> Timestamp {
            crate::test::from_second(WHOLE_SECOND_TS, 0)
        }

        fn fractional_second_timestamp() -> Timestamp {
            crate::test::from_second(WHOLE_SECOND_TS, FRACTIONAL_NSEC)
        }

        #[test]
        fn updated_at_writer_stores_i64_nanosecond_bytes() {
            let (_permit, store) = super::setup_store();
            let table = store.tor_exit_node_map();

            let whole = whole_second_timestamp();
            let fractional = fractional_second_timestamp();
            let far_future: Timestamp = "2300-01-01T00:00:00Z".parse().unwrap();

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
                        TorExitNode {
                            ip_address: "10.0.0.3".to_string(),
                            updated_at: far_future,
                        },
                    ]
                    .into_iter(),
                )
                .unwrap();

            assert_eq!(
                table.map.get(b"10.0.0.1").unwrap().unwrap().as_ref(),
                WHOLE_SECOND_BYTES
            );
            assert_eq!(
                table.map.get(b"10.0.0.2").unwrap().unwrap().as_ref(),
                FRACTIONAL_SECOND_BYTES
            );
            assert_eq!(
                table.map.get(b"10.0.0.3").unwrap().unwrap().as_ref(),
                SATURATED_BYTES
            );
        }

        #[test]
        fn updated_at_reads_i64_nanosecond_bytes() {
            let (_permit, store) = super::setup_store();
            let table = store.tor_exit_node_map();

            table.map.put(b"10.0.0.1", WHOLE_SECOND_BYTES).unwrap();
            table.map.put(b"10.0.0.2", FRACTIONAL_SECOND_BYTES).unwrap();
            table.map.put(b"10.0.0.3", SATURATED_BYTES).unwrap();

            let entries: Vec<_> = table
                .iter(Direction::Forward, None)
                .collect::<Result<Vec<_>>>()
                .unwrap();
            assert_eq!(entries.len(), 3);
            let find = |name: &str| {
                entries
                    .iter()
                    .find(|entry| entry.ip_address == name)
                    .expect("entry")
                    .updated_at
            };
            assert_eq!(find("10.0.0.1"), whole_second_timestamp());
            assert_eq!(find("10.0.0.2"), fractional_second_timestamp());
            assert_eq!(
                find("10.0.0.3"),
                crate::timestamp::from_i64_nanos(i64::MAX).unwrap()
            );

            let parsed = TorExitNode::from_key_value(b"10.0.0.2", FRACTIONAL_SECOND_BYTES).unwrap();
            assert_eq!(parsed.updated_at, fractional_second_timestamp());
        }

        #[test]
        fn updated_at_rejects_v0_61_display_bytes() {
            assert!(TorExitNode::from_key_value(b"10.0.0.1", V0_61_BYTES).is_err());
        }
    }
}
