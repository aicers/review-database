//! The `model_indicator` map.

use std::{
    collections::HashSet,
    io::{BufReader, Read},
};

use anyhow::Result;
use data_encoding::BASE64;
use flate2::read::GzDecoder;
use jiff::Timestamp;
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use crate::{Map, Table, timestamp::ts_seconds_floor, types::FromKeyValue};

#[derive(Default)]
pub struct ModelIndicator {
    pub name: String,
    pub description: String,
    pub model_id: u32,
    pub tokens: HashSet<Vec<String>>,
    pub last_modification_time: Timestamp,
}

impl ModelIndicator {
    /// Creates a new `ModelIndicator` from the given data.
    ///
    /// # Errors
    ///
    /// Returns an error if the given data is invalid.
    pub fn new(name: &str, data: &str) -> Result<Self> {
        let data = BASE64.decode(data.as_bytes())?;
        let decoder = GzDecoder::new(&data[..]);
        let mut buf = Vec::new();
        let mut reader = BufReader::new(decoder);
        reader.read_to_end(&mut buf)?;

        Self::from_key_value(name.as_bytes(), &buf)
    }

    pub(crate) fn into_key_value(self) -> Result<(Vec<u8>, Vec<u8>)> {
        let key = self.name.into_bytes();
        let value = Value {
            description: self.description,
            model_id: self.model_id,
            tokens: self.tokens,
            last_modification_time: self.last_modification_time,
        };
        Ok((key, super::serialize(&value)?))
    }
}

#[derive(Deserialize, Serialize)]
struct Value {
    description: String,
    model_id: u32,
    tokens: HashSet<Vec<String>>,
    #[serde(with = "ts_seconds_floor")]
    last_modification_time: Timestamp,
}

impl FromKeyValue for ModelIndicator {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let name = std::str::from_utf8(key)?.to_string();
        let value: Value = super::deserialize(value)?;
        Ok(Self {
            name,
            description: value.description,
            model_id: value.model_id,
            tokens: value.tokens,
            last_modification_time: value.last_modification_time,
        })
    }
}

/// Functions for the `model_indicator` map.
impl<'d> Table<'d, ModelIndicator> {
    /// Opens the  `model_indicator` map in the database.
    ///
    /// Returns `None` if the map does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::MODEL_INDICATORS).map(Table::new)
    }

    /// Returns the `ModelIndicator` with the given name.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub fn get(&self, name: &str) -> Result<Option<ModelIndicator>> {
        self.map
            .get(name.as_bytes())?
            .map(|v| ModelIndicator::from_key_value(name.as_bytes(), v.as_ref()))
            .transpose()
    }

    /// Inserts the `ModelIndicator` into the database, overwriting one of
    /// the same name, past the guards of
    /// [`Store::insert_model_indicator`](crate::Store::insert_model_indicator).
    ///
    /// # Errors
    ///
    /// Returns an error if the serialization fails or the database operation fails.
    #[cfg(test)]
    pub(crate) fn insert(&self, indicator: ModelIndicator) -> Result<()> {
        let (key, value) = indicator.into_key_value()?;
        self.map.put(&key, &value)
    }

    /// Removes the `ModelIndicator`s with the given names. The removed names are returned.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    #[cfg(test)]
    pub(crate) fn remove<'a>(&self, names: impl Iterator<Item = &'a str>) -> Result<Vec<String>> {
        let mut removed = vec![];
        for name in names {
            self.map.delete(name.as_bytes())?;
            removed.push(name.to_string());
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Arc;

    use crate::test::{DbGuard, acquire_db_permit};
    use crate::types::FromKeyValue;
    use crate::{ModelIndicator, Store};

    const TS_SECONDS: i64 = 1_650_000_000;

    /// One day before the Unix epoch; exercises signed `i64` epoch seconds.
    const NEGATIVE_TS_SECONDS: i64 = -86_400;

    const SUBSECOND_NANOS: i32 = 500_000_000;

    const FIXTURE_NAME: &str = "baseline-mi";

    /// Pinned table-value bytes produced by the production `tables::serialize`
    /// path for a `ModelIndicator` value.
    ///
    /// `last_modification_time` is stored as `i64` epoch seconds, the format
    /// chrono's `ts_seconds` wrote and `ts_seconds_floor` keeps. This baseline
    /// is separate from the other table-value baselines because those store
    /// `i64` nanoseconds, so the timestamp encoding must be pinned on its own
    /// to catch accidental migration during future changes.
    const TABLE_VALUE_FIXTURE: &[u8] = &[
        16, 98, 97, 115, 101, 108, 105, 110, 101, 32, 102, 105, 120, 116, 117, 114, 101, 42, 1, 1,
        7, 116, 111, 107, 101, 110, 45, 97, 252, 0, 1, 178, 196,
    ];

    /// Pinned table-value bytes for a pre-1970 `last_modification_time`.
    const NEGATIVE_TABLE_VALUE_FIXTURE: &[u8] = &[
        16, 98, 97, 115, 101, 108, 105, 110, 101, 32, 102, 105, 120, 116, 117, 114, 101, 42, 1, 1,
        7, 116, 111, 107, 101, 110, 45, 97, 252, 255, 162, 2, 0,
    ];

    fn fixture_last_modification_time(ts_seconds: i64, subsec_nanos: i32) -> jiff::Timestamp {
        jiff::Timestamp::new(ts_seconds, subsec_nanos).expect("canonical timestamp must be valid")
    }

    /// Splits a timestamp into its floored seconds and nonnegative subsecond
    /// nanoseconds.
    fn seconds_and_subsec(time: jiff::Timestamp) -> (i64, i64) {
        let nanos = i64::try_from(time.as_nanosecond()).expect("in range");
        (
            nanos.div_euclid(1_000_000_000),
            nanos.rem_euclid(1_000_000_000),
        )
    }

    fn fixture_model_indicator(ts_seconds: i64, subsec_nanos: i32) -> ModelIndicator {
        let mut tokens = HashSet::new();
        tokens.insert(vec!["token-a".to_string()]);
        ModelIndicator {
            name: FIXTURE_NAME.to_string(),
            description: "baseline fixture".to_string(),
            model_id: 42,
            tokens,
            last_modification_time: fixture_last_modification_time(ts_seconds, subsec_nanos),
        }
    }

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path(), None).unwrap());
        (permit, store)
    }

    // Baseline tests for `ModelIndicator.last_modification_time` storage.

    #[test]
    fn baseline_last_modification_time_decodes_pinned_table_value_bytes() {
        let indicator =
            super::ModelIndicator::from_key_value(FIXTURE_NAME.as_bytes(), TABLE_VALUE_FIXTURE)
                .expect("production table-value decoder must accept pinned bytes");

        assert_eq!(
            seconds_and_subsec(indicator.last_modification_time).0,
            TS_SECONDS,
            "stored timestamp must be i64 epoch seconds via ts_seconds_floor"
        );
        assert_eq!(
            seconds_and_subsec(indicator.last_modification_time).1,
            0,
            "ts_seconds encoding must not preserve subsecond precision"
        );
        assert_eq!(indicator.description, "baseline fixture");
        assert_eq!(indicator.model_id, 42);
    }

    #[test]
    fn baseline_last_modification_time_encodes_pinned_table_value_bytes() {
        let indicator = fixture_model_indicator(TS_SECONDS, 0);
        let (_key, encoded) = indicator
            .into_key_value()
            .expect("production table-value encoder must succeed");

        assert_eq!(
            encoded.as_slice(),
            TABLE_VALUE_FIXTURE,
            "production encoder must match pinned bytes; nanosecond or default Jiff \
             serde would change the timestamp suffix"
        );
    }

    #[test]
    fn baseline_last_modification_time_decodes_negative_pinned_table_value_bytes() {
        let indicator = super::ModelIndicator::from_key_value(
            FIXTURE_NAME.as_bytes(),
            NEGATIVE_TABLE_VALUE_FIXTURE,
        )
        .expect("production table-value decoder must accept pinned pre-1970 bytes");

        assert_eq!(
            seconds_and_subsec(indicator.last_modification_time).0,
            NEGATIVE_TS_SECONDS,
            "stored timestamp must be signed i64 epoch seconds via ts_seconds_floor"
        );
        assert_eq!(
            seconds_and_subsec(indicator.last_modification_time).1,
            0,
            "ts_seconds encoding must not preserve subsecond precision"
        );
    }

    #[test]
    fn baseline_last_modification_time_encodes_negative_pinned_table_value_bytes() {
        let indicator = fixture_model_indicator(NEGATIVE_TS_SECONDS, 0);
        let (_key, encoded) = indicator
            .into_key_value()
            .expect("production table-value encoder must succeed");

        assert_eq!(
            encoded.as_slice(),
            NEGATIVE_TABLE_VALUE_FIXTURE,
            "production encoder must match pinned pre-1970 bytes; unsigned or nanosecond \
             serde would change the timestamp suffix"
        );
    }

    #[test]
    fn baseline_last_modification_time_encodes_truncates_subseconds_to_whole_seconds() {
        let indicator = fixture_model_indicator(TS_SECONDS, SUBSECOND_NANOS);
        let (timestamp, subsec_nanos) = seconds_and_subsec(indicator.last_modification_time);
        let (_key, encoded) = indicator
            .into_key_value()
            .expect("production table-value encoder must succeed");

        assert_eq!(
            encoded.as_slice(),
            TABLE_VALUE_FIXTURE,
            "ts_seconds must truncate subsecond precision before serialization"
        );
        assert_eq!(
            timestamp, TS_SECONDS,
            "fixture input must carry non-zero subseconds to exercise truncation"
        );
        assert_ne!(
            subsec_nanos, 0,
            "fixture input must carry non-zero subseconds to exercise truncation"
        );
    }

    /// Returns a stored value whose `last_modification_time` is `seconds`.
    fn value_with_seconds(seconds: i64) -> Vec<u8> {
        #[derive(serde::Serialize)]
        struct RawValue {
            description: String,
            model_id: u32,
            tokens: HashSet<Vec<String>>,
            last_modification_time: i64,
        }
        crate::tables::serialize(&RawValue {
            description: "out of range".to_owned(),
            model_id: 7,
            tokens: HashSet::new(),
            last_modification_time: seconds,
        })
        .unwrap()
    }

    fn upload(value: &[u8]) -> String {
        use std::io::{Cursor, Read};

        use data_encoding::BASE64;
        use flate2::{Compression, bufread::GzEncoder};

        let mut gz = GzEncoder::new(Cursor::new(value), Compression::fast());
        let mut zipped = Vec::new();
        gz.read_to_end(&mut zipped).unwrap();
        BASE64.encode(&zipped)
    }

    #[test]
    fn seconds_outside_the_timestamp_range_are_a_read_error() {
        let max = jiff::Timestamp::MAX.as_second();
        let min = jiff::Timestamp::MIN.as_second();
        for seconds in [max + 1, min - 1, i64::MAX, i64::MIN] {
            let value = value_with_seconds(seconds);
            assert!(
                super::ModelIndicator::from_key_value(FIXTURE_NAME.as_bytes(), &value).is_err(),
                "{seconds}"
            );
            assert!(
                super::ModelIndicator::new(FIXTURE_NAME, &upload(&value)).is_err(),
                "{seconds}"
            );
        }
        for seconds in [max, min] {
            let value = value_with_seconds(seconds);
            let indicator =
                super::ModelIndicator::from_key_value(FIXTURE_NAME.as_bytes(), &value).unwrap();
            assert_eq!(indicator.last_modification_time.as_second(), seconds);
            assert!(super::ModelIndicator::new(FIXTURE_NAME, &upload(&value)).is_ok());
        }
    }

    #[test]
    fn serde() {
        use std::collections::HashSet;
        use std::io::{Cursor, Read};

        use data_encoding::BASE64;
        use flate2::{Compression, bufread::GzEncoder};

        let name = "mi_1";
        let value = super::Value {
            description: "test".to_owned(),
            model_id: 123,
            tokens: HashSet::new(),
            last_modification_time: jiff::Timestamp::now(),
        };
        let serialized = crate::tables::serialize(&value).unwrap();
        let cursor = Cursor::new(serialized);

        let mut gz = GzEncoder::new(cursor, Compression::fast());
        let mut zipped = Vec::new();
        gz.read_to_end(&mut zipped).unwrap();
        let encoded = BASE64.encode(&zipped);
        let res = super::ModelIndicator::new(name, &encoded);

        assert!(res.is_ok());
        let indicator = res.unwrap();
        assert_eq!(indicator.name, "mi_1");
        assert_eq!(indicator.description, "test");
    }

    #[test]
    fn operations() {
        use crate::Iterable;
        let (_permit, store) = setup_store();
        let table = store.model_indicator_map();

        let tester = &["1", "2", "3"];
        for &name in tester {
            let mi = ModelIndicator {
                name: name.to_string(),
                ..Default::default()
            };
            assert!(table.insert(mi).is_ok());
        }

        for &name in tester {
            let res = table.get(name).unwrap().map(|mi| mi.name);
            assert_eq!(Some(name.to_string()), res);
        }

        let res: anyhow::Result<Vec<_>> = table
            .iter(rocksdb::Direction::Forward, None)
            .map(|r| r.map(|mi| mi.name))
            .collect();
        assert!(res.is_ok());
        let list = res.unwrap();
        assert_eq!(
            tester.to_vec(),
            list.iter().map(String::as_str).collect::<Vec<_>>()
        );

        let res = table.remove(list.iter().map(String::as_str));
        assert!(res.is_ok());
        let removed = res.unwrap();
        assert_eq!(removed, list);
    }
}
