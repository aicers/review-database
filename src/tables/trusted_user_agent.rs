//! The `trusted_user_agent` map.

use anyhow::{Context, Result};
use jiff::Timestamp;
use rocksdb::OptimisticTransactionDB;

use super::Value;
use crate::{
    Map, Table, UniqueKey,
    timestamp::{from_i64_nanos, saturating_i64_nanos},
    types::FromKeyValue,
};

pub struct TrustedUserAgent {
    pub user_agent: String,
    pub updated_at: Timestamp,
}

impl FromKeyValue for TrustedUserAgent {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let user_agent = std::str::from_utf8(key)
            .context("invalid user-agent in database")?
            .to_owned();
        let nanos: i64 = super::deserialize(value).context("invalid timestamp in database")?;
        let updated_at = from_i64_nanos(nanos).context("invalid timestamp in database")?;
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
        super::serialize(&saturating_i64_nanos(self.updated_at)).expect("an i64 always serializes")
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
            updated_at: jiff::Timestamp::now(),
        }
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
            let table = store.trusted_user_agent_map();

            let whole = whole_second_timestamp();
            let fractional = fractional_second_timestamp();
            let far_future: Timestamp = "2300-01-01T00:00:00Z".parse().unwrap();

            for (name, updated_at) in [("a", whole), ("b", fractional), ("c", far_future)] {
                table
                    .put(&TrustedUserAgent {
                        user_agent: name.to_string(),
                        updated_at,
                    })
                    .unwrap();
            }

            assert_eq!(
                table.map.get(b"a").unwrap().unwrap().as_ref(),
                WHOLE_SECOND_BYTES
            );
            assert_eq!(
                table.map.get(b"b").unwrap().unwrap().as_ref(),
                FRACTIONAL_SECOND_BYTES
            );
            assert_eq!(
                table.map.get(b"c").unwrap().unwrap().as_ref(),
                SATURATED_BYTES
            );
        }

        #[test]
        fn updated_at_reads_i64_nanosecond_bytes() {
            let (_permit, store) = super::setup_store();
            let table = store.trusted_user_agent_map();

            table.map.put(b"a", WHOLE_SECOND_BYTES).unwrap();
            table.map.put(b"b", FRACTIONAL_SECOND_BYTES).unwrap();
            table.map.put(b"c", SATURATED_BYTES).unwrap();

            let entries: Vec<_> = table
                .iter(Direction::Forward, None)
                .collect::<Result<Vec<_>>>()
                .unwrap();
            assert_eq!(entries.len(), 3);
            let find = |name: &str| {
                entries
                    .iter()
                    .find(|entry| entry.user_agent == name)
                    .expect("entry")
                    .updated_at
            };
            assert_eq!(find("a"), whole_second_timestamp());
            assert_eq!(find("b"), fractional_second_timestamp());
            assert_eq!(
                find("c"),
                crate::timestamp::from_i64_nanos(i64::MAX).unwrap()
            );

            let parsed = TrustedUserAgent::from_key_value(b"b", FRACTIONAL_SECOND_BYTES).unwrap();
            assert_eq!(parsed.updated_at, fractional_second_timestamp());
        }

        #[test]
        fn updated_at_rejects_v0_61_display_bytes() {
            assert!(TrustedUserAgent::from_key_value(b"a", V0_61_BYTES).is_err());
        }
    }
}
