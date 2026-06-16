//! The `triage_policy` table.

use std::borrow::Cow;

use anyhow::Result;
use chrono::{DateTime, Utc};
use rocksdb::{Direction, OptimisticTransactionDB};
use serde::{Deserialize, Serialize};

use super::UniqueKey;
use crate::{
    Indexable, IndexedMap, IndexedMapUpdate, IndexedTable, Iterable, collections::Indexed,
    types::FromKeyValue,
};

#[derive(Deserialize, Serialize)]
pub struct TriageResponse {
    pub id: u32,
    key: Vec<u8>,
    sensor: String,
    time: DateTime<Utc>,
    tag_ids: Vec<u32>,
    pub remarks: String,
    creation_time: DateTime<Utc>,
    last_modified_time: DateTime<Utc>,
}

impl TriageResponse {
    #[must_use]
    pub fn new(sensor: String, time: DateTime<Utc>, tag_ids: Vec<u32>, remarks: String) -> Self {
        let creation_time = Utc::now();
        let last_modified_time = creation_time;
        let tag_ids = Self::clean_up(tag_ids);
        let key = Self::create_key(&sensor, &time);

        Self {
            id: u32::MAX,
            key,
            sensor,
            time,
            tag_ids,
            remarks,
            creation_time,
            last_modified_time,
        }
    }

    #[must_use]
    pub fn tag_ids(&self) -> &[u32] {
        &self.tag_ids
    }

    fn contains_tag(&self, tag: u32) -> Result<usize> {
        self.tag_ids
            .binary_search(&tag)
            .map_err(|idx| anyhow::anyhow!("{idx}"))
    }

    fn create_key(sensor: &str, time: &DateTime<Utc>) -> Vec<u8> {
        let mut key = sensor.as_bytes().to_vec();
        key.extend_from_slice(&time.timestamp_nanos_opt().unwrap_or_default().to_be_bytes());
        key
    }

    fn clean_up(mut tag_ids: Vec<u32>) -> Vec<u32> {
        tag_ids.sort_unstable();
        tag_ids.dedup();
        tag_ids
    }
}

impl FromKeyValue for TriageResponse {
    fn from_key_value(_key: &[u8], value: &[u8]) -> Result<Self> {
        super::deserialize(value)
    }
}

impl UniqueKey for TriageResponse {
    type AsBytes<'a> = &'a [u8];

    fn unique_key(&self) -> &[u8] {
        &self.key
    }
}

impl Indexable for TriageResponse {
    fn key(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(&self.key)
    }

    fn index(&self) -> u32 {
        self.id
    }

    fn make_indexed_key(key: Cow<[u8]>, _index: u32) -> Cow<[u8]> {
        key
    }

    fn value(&self) -> Vec<u8> {
        super::serialize(self).expect("serializable")
    }

    fn set_index(&mut self, index: u32) {
        self.id = index;
    }
}

/// Functions for the `triage_response` indexed map.
impl<'d> IndexedTable<'d, TriageResponse> {
    /// Opens the `triage_response` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        IndexedMap::new(db, super::TRIAGE_RESPONSE)
            .map(IndexedTable::new)
            .ok()
    }

    /// Returns the `TriageResponse` with the given `sensor` and `time`.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub fn get(&self, sensor: &str, time: &DateTime<Utc>) -> Result<Option<TriageResponse>> {
        let key = TriageResponse::create_key(sensor, time);
        self.indexed_map
            .get_by_key(&key)?
            .map(|value| super::deserialize(value.as_ref()))
            .transpose()
    }

    /// Removes `tag_id` in all the related entries
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub fn remove_tag(&self, tag_id: u32) -> Result<()> {
        let iter = self.iter(Direction::Forward, None);
        for entry in iter {
            let mut response = entry?;
            if let Ok(idx) = response.contains_tag(tag_id) {
                response.tag_ids.remove(idx);
                let old = Update {
                    key: response.key.clone(),
                    tag_ids: None,
                    remarks: None,
                };
                let new = Update {
                    key: response.key,
                    tag_ids: Some(response.tag_ids),
                    remarks: None,
                };
                self.indexed_map.update(response.id, &old, &new)?;
            }
        }
        Ok(())
    }

    /// Updates the `TriageResponse` from `old` to `new`, given `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `id` is invalid or the database operation fails.
    pub fn update(&mut self, id: u32, old: &Update, new: &Update) -> Result<()> {
        self.indexed_map.update(id, old, new)
    }
}

pub struct Update {
    key: Vec<u8>,
    tag_ids: Option<Vec<u32>>,
    remarks: Option<String>,
}

impl Update {
    #[must_use]
    pub fn new(key: Vec<u8>, tag_ids: Option<Vec<u32>>, remarks: Option<String>) -> Self {
        let tag_ids = tag_ids.map(TriageResponse::clean_up);
        Self {
            key,
            tag_ids,
            remarks,
        }
    }
}

impl IndexedMapUpdate for Update {
    type Entry = TriageResponse;

    fn key(&self) -> Option<Cow<'_, [u8]>> {
        Some(Cow::Borrowed(&self.key))
    }

    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry> {
        if let Some(remarks) = self.remarks.as_deref() {
            value.remarks.clear();
            value.remarks.push_str(remarks);
        }

        if let Some(tag_ids) = self.tag_ids.as_deref() {
            value.tag_ids = TriageResponse::clean_up(tag_ids.to_vec());
        }

        value.last_modified_time = Utc::now();
        Ok(value)
    }

    fn verify(&self, value: &Self::Entry) -> bool {
        if self.key != value.key {
            return false;
        }
        if let Some(r) = self.remarks.as_deref()
            && r != value.remarks
        {
            return false;
        }

        if let Some(tag_ids) = self.tag_ids.as_deref()
            && tag_ids != value.tag_ids
        {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod test {
    use std::mem::size_of;
    use std::sync::Arc;

    use anyhow::Result;
    use chrono::{DateTime, NaiveDate, Utc};

    use crate::Indexable;
    use crate::test::{DbGuard, acquire_db_permit};
    use crate::types::FromKeyValue;
    use crate::{Iterable, Store, TriageResponse, TriageResponseUpdate, UniqueKey};

    const SENSOR: &str = "sensor-a";

    /// `2023-03-15T12:34:56.123456789Z` as chrono `timestamp_nanos_opt()`.
    const TIMESTAMP_2023_SUFFIX: [u8; size_of::<i64>()] =
        1_678_883_696_123_456_789i64.to_be_bytes();

    /// `1969-12-31T23:59:59.999999999Z` as chrono `timestamp_nanos_opt()`.
    const TIMESTAMP_PRE_EPOCH_SUFFIX: [u8; size_of::<i64>()] = (-1i64).to_be_bytes();

    /// Suffix substituted when chrono `timestamp_nanos_opt()` returns `None`.
    const TIMESTAMP_OUT_OF_RANGE_SUFFIX: [u8; size_of::<i64>()] = 0i64.to_be_bytes();

    /// Extracts the 8-byte timestamp suffix from a `TriageResponse` unique key.
    fn timestamp_bytes_from_key(key: &[u8], sensor: &str) -> [u8; size_of::<i64>()] {
        let offset = sensor.len();
        let suffix = key
            .get(offset..)
            .unwrap_or_else(|| panic!("key shorter than sensor prefix: {key:?}"));
        suffix
            .try_into()
            .expect("timestamp suffix must be exactly 8 bytes")
    }

    fn assert_unique_key_timestamp(
        sensor: &str,
        time: DateTime<Utc>,
        expected_suffix: [u8; size_of::<i64>()],
    ) {
        let response = TriageResponse::new(sensor.to_string(), time, Vec::new(), String::new());
        let key = response.unique_key();
        assert!(
            key.starts_with(sensor.as_bytes()),
            "unique key must begin with the sensor bytes"
        );
        let actual = timestamp_bytes_from_key(key, sensor);
        assert_eq!(
            actual, expected_suffix,
            "unique key timestamp suffix must match the pinned chrono i64 nanosecond bytes"
        );
    }

    #[test]
    fn unique_key_timestamp_nanosecond_precision() {
        let time = DateTime::parse_from_rfc3339("2023-03-15T12:34:56.123456789Z")
            .expect("valid RFC3339 timestamp")
            .with_timezone(&Utc);
        assert_unique_key_timestamp(SENSOR, time, TIMESTAMP_2023_SUFFIX);
    }

    #[test]
    fn unique_key_timestamp_pre_1970() {
        let time = DateTime::parse_from_rfc3339("1969-12-31T23:59:59.999999999Z")
            .expect("valid RFC3339 timestamp")
            .with_timezone(&Utc);
        assert_unique_key_timestamp(SENSOR, time, TIMESTAMP_PRE_EPOCH_SUFFIX);
    }

    #[test]
    fn unique_key_timestamp_out_of_range_uses_zero() {
        // Years far beyond chrono's representable i64-nanosecond range make
        // `timestamp_nanos_opt()` return `None`. The key builder currently
        // substitutes `i64::default()` (zero) rather than failing.
        let naive = NaiveDate::from_ymd_opt(3000, 1, 1)
            .expect("valid date")
            .and_hms_opt(0, 0, 0)
            .expect("valid time");
        let time = DateTime::from_naive_utc_and_offset(naive, Utc);

        let response = TriageResponse::new(SENSOR.to_string(), time, Vec::new(), String::new());
        let actual = timestamp_bytes_from_key(response.unique_key(), SENSOR);
        assert_eq!(actual, TIMESTAMP_OUT_OF_RANGE_SUFFIX);
    }

    /// Locks the on-disk bincode byte contract for the persisted `TriageResponse`
    /// record.
    ///
    /// Expected bytes come from the committed literal fixture (not from the
    /// production serializer inside this test). Timestamp fields are pinned to
    /// fixed UTC values with full nanosecond precision:
    ///
    /// - `time`: `2000-02-29T12:34:56.123456789Z`
    /// - `creation_time`: `2000-01-15T08:00:00.111111111Z`
    /// - `last_modified_time`: `2000-03-01T23:59:59.987654321Z`
    ///
    /// The fixture was captured once from the production `Indexable::value` path
    /// (`bincode::DefaultOptions`). Regenerate with
    /// `dump_triage_response_literal_fixture_bytes` if the stored layout changes.
    ///
    /// Not covered: empty `tag_ids`; unsorted `tag_ids` input (production sorts
    /// on insert); `id: u32::MAX` placeholder; empty `sensor`/`remarks`; key
    /// bytes (see issue #750).
    #[test]
    fn triage_response_literal_bytes_contract() -> Result<()> {
        const FIXTURE_BYTES: &[u8] =
            include_bytes!("../../tests/fixtures/triage_response_literal.bin");

        let decoded = TriageResponse::from_key_value(b"fixture-key", FIXTURE_BYTES)?;
        let expected = deterministic_triage_response();
        assert_eq!(decoded.id, expected.id);
        assert_eq!(decoded.key, expected.key);
        assert_eq!(decoded.sensor, expected.sensor);
        assert_eq!(decoded.time, expected.time);
        assert_eq!(decoded.tag_ids, expected.tag_ids);
        assert_eq!(decoded.remarks, expected.remarks);
        assert_eq!(decoded.creation_time, expected.creation_time);
        assert_eq!(decoded.last_modified_time, expected.last_modified_time);

        let serialized = Indexable::value(&expected);
        assert_eq!(serialized.as_slice(), FIXTURE_BYTES);

        Ok(())
    }

    #[test]
    #[ignore = "run manually to regenerate tests/fixtures/triage_response_literal.bin"]
    fn dump_triage_response_literal_fixture_bytes() {
        let bytes = deterministic_triage_response().value();
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/triage_response_literal.bin");
        std::fs::write(path, &bytes).expect("write fixture");
    }

    /// Builds a deterministic `TriageResponse` for the literal-byte contract test.
    fn deterministic_triage_response() -> TriageResponse {
        let time = DateTime::parse_from_rfc3339("2000-02-29T12:34:56.123456789Z")
            .expect("valid RFC 3339 timestamp")
            .with_timezone(&Utc);
        let creation_time = DateTime::parse_from_rfc3339("2000-01-15T08:00:00.111111111Z")
            .expect("valid RFC 3339 timestamp")
            .with_timezone(&Utc);
        let last_modified_time = DateTime::parse_from_rfc3339("2000-03-01T23:59:59.987654321Z")
            .expect("valid RFC 3339 timestamp")
            .with_timezone(&Utc);
        let sensor = "fixture-sensor".to_string();
        let key = TriageResponse::create_key(&sensor, &time);

        TriageResponse {
            id: 7,
            key,
            sensor,
            time,
            tag_ids: vec![2, 5, 11],
            remarks: "fixture remarks".to_string(),
            creation_time,
            last_modified_time,
        }
    }

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
        let mut table = store.triage_response_map();

        let time = Utc::now();
        let sensor = "sensor";
        let remarks = "remarks";
        let tag_ids = &[3, 1, 2, 1];
        let response = TriageResponse::new(
            sensor.to_string(),
            time,
            tag_ids.to_vec(),
            remarks.to_string(),
        );

        assert_eq!(response.tag_ids, vec![1, 2, 3]);
        let res = table.put(response);
        assert!(res.is_ok());
        let id = res.unwrap();

        let res = table.get(sensor, &time).ok().flatten();
        assert!(res.is_some());
        let response = res.unwrap();
        assert_eq!(&response.remarks, remarks);

        let key = &response.key;
        let old = TriageResponseUpdate::new(key.clone(), None, None);
        let new =
            TriageResponseUpdate::new(key.clone(), Some(vec![4, 3, 1, 1]), Some("nah".to_owned()));
        let res = table.update(id, &old, &new);
        assert!(res.is_ok());
        let updated = table.get(sensor, &time).unwrap().unwrap();
        assert_eq!(updated.tag_ids, vec![1, 3, 4]);
        assert_eq!(&updated.remarks, "nah");

        let iter = table.iter(rocksdb::Direction::Forward, None);
        assert_eq!(iter.count(), 1);

        let newer = TriageResponseUpdate::new(key.clone(), Some(vec![1, 2, 5]), None);
        let res = table.update(id, &new, &newer);
        assert!(res.is_ok());
        let updated = table.get(sensor, &time).unwrap().unwrap();
        assert_eq!(updated.tag_ids, vec![1, 2, 5]);
        assert_eq!(&updated.remarks, "nah");

        assert!(table.remove(id).is_ok());
        let iter = table.iter(rocksdb::Direction::Reverse, None);
        assert_eq!(iter.count(), 0);
    }
}
