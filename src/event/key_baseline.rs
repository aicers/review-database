//! Baseline contract tests for the event key.
//!
//! `EventDb::put` stores a record under a 16-byte big-endian `i128` key that
//! holds the detection event's `time` as **i64 epoch nanoseconds** in its
//! upper 64 bits and the number of its `DetectionModel` in the next 32:
//!
//! ```text
//! key = (time_ns << 64) | (detection_model << 32) | seq
//! key[0..8]  == time_ns.to_be_bytes()
//! key[8..12] == u32::from(detection_model).to_be_bytes()
//! ```
//!
//! These tests pin that layout. Expected timestamp values are pinned as
//! literal `i64` nanoseconds (not recomputed in the assertion path). On-disk
//! layout is checked via raw RocksDB key bytes as well as `EventDb::put` and
//! `EventIterator`.

use jiff::Timestamp;
use review_protocol::types::{DetectionEvent, DetectionModel};
use tempfile::tempdir;

use super::{
    fixture::{conn_event, stamp},
    timestamp,
};
use crate::Store;

/// 2020-06-15T12:30:45Z as epoch nanoseconds (pinned baseline).
const EPOCH_NANOS_2020_06_15_123045: i64 = 1_592_224_245_000_000_000;

/// 1965-10-15T12:34:56.123456789Z as epoch nanoseconds (pinned baseline).
const EPOCH_NANOS_1965_10_15_123456789: i64 = -132_924_303_876_543_211;

/// 1985-03-04T05:06:07Z as epoch nanoseconds (pinned baseline).
const EPOCH_NANOS_1985_03_04_050607: i64 = 478_760_767_000_000_000;

/// 2020-06-15T12:00:00Z as epoch nanoseconds (pinned baseline).
const EPOCH_NANOS_2020_06_15_120000: i64 = 1_592_222_400_000_000_000;

/// Returns the first eight bytes of a 16-byte big-endian event key.
fn timestamp_region(key: i128) -> [u8; 8] {
    let bytes = key.to_be_bytes();
    bytes[..8].try_into().expect("event key has 16 bytes")
}

/// Returns the timestamp region from a raw 16-byte on-disk event key.
fn timestamp_region_from_raw(key: [u8; 16]) -> [u8; 8] {
    key[..8].try_into().expect("event key has 16 bytes")
}

/// Returns the detection model region from a raw 16-byte on-disk event key.
fn model_region_from_raw(key: [u8; 16]) -> [u8; 4] {
    key[8..12].try_into().expect("event key has 16 bytes")
}

fn timestamp_from_nanos(nanos: i64) -> Timestamp {
    timestamp::from_i64_nanos(nanos).expect("pinned baseline nanoseconds must be valid")
}

fn minimal_event(time: Timestamp) -> DetectionEvent {
    let mut event = conn_event("192.0.2.1", "198.51.100.1");
    event.time = time;
    event
}

fn put_and_read_timestamp_regions(time: Timestamp) -> ([u8; 8], [u8; 8], [u8; 8]) {
    let data_dir = tempdir().expect("temp data dir");
    let backup_dir = tempdir().expect("temp backup dir");
    let store = Store::new(data_dir.path(), backup_dir.path(), None).expect("open store");
    let db = store.events();

    let key = db.put(&minimal_event(time), &stamp()).expect("put event");
    let from_put = timestamp_region(key);

    let scanned_key = db
        .iter_forward()
        .next()
        .expect("one stored event")
        .expect("valid stored event")
        .0;
    let from_scan = timestamp_region(scanned_key);

    let raw_key = db
        .first_raw_event_key()
        .expect("read raw RocksDB key")
        .expect("one stored event");
    let from_raw = timestamp_region_from_raw(raw_key);

    (from_put, from_scan, from_raw)
}

fn assert_timestamp_regions(expected: [u8; 8], regions: ([u8; 8], [u8; 8], [u8; 8])) {
    let (from_put, from_scan, from_raw) = regions;
    assert_eq!(from_put, expected, "put return key timestamp region");
    assert_eq!(
        from_scan, expected,
        "iter_forward decoded key timestamp region"
    );
    assert_eq!(from_raw, expected, "raw RocksDB key timestamp region");
}

#[test]
fn event_key_timestamp_matches_i64_epoch_nanoseconds() {
    let time = timestamp_from_nanos(EPOCH_NANOS_2020_06_15_123045);
    let expected = EPOCH_NANOS_2020_06_15_123045.to_be_bytes();
    let regions = put_and_read_timestamp_regions(time);
    assert_timestamp_regions(expected, regions);
}

#[test]
fn event_key_one_nanosecond_after_unix_epoch() {
    let time = timestamp_from_nanos(1);
    let expected = 1i64.to_be_bytes();
    let regions = put_and_read_timestamp_regions(time);
    assert_timestamp_regions(expected, regions);
}

#[test]
fn event_key_pre_1970_negative_epoch_nanoseconds() {
    let time = timestamp_from_nanos(EPOCH_NANOS_1965_10_15_123456789);
    let expected = EPOCH_NANOS_1965_10_15_123456789.to_be_bytes();
    let regions = put_and_read_timestamp_regions(time);
    assert_timestamp_regions(expected, regions);
}

#[test]
fn event_key_i64_nanosecond_range_boundaries() {
    for nanos in [i64::MIN, i64::MAX] {
        let time = timestamp_from_nanos(nanos);
        let expected = nanos.to_be_bytes();
        let regions = put_and_read_timestamp_regions(time);
        assert_timestamp_regions(expected, regions);
    }
}

#[test]
fn event_key_put_maps_out_of_range_time_to_i64_max() {
    // `EventDb::put` uses `event_key_nanos`, mapping out-of-i64 values to
    // `i64::MAX`. Both underflow and overflow therefore encode `i64::MAX`.
    let far_future =
        Timestamp::from_nanosecond(i128::from(i64::MAX) + 1).expect("valid jiff timestamp");
    let far_past =
        Timestamp::from_nanosecond(i128::from(i64::MIN) - 1).expect("valid jiff timestamp");

    let expected = i64::MAX.to_be_bytes();
    let regions = put_and_read_timestamp_regions(far_future);
    assert_timestamp_regions(expected, regions);

    let regions = put_and_read_timestamp_regions(far_past);
    assert_timestamp_regions(expected, regions);
}

#[test]
fn event_key_timestamp_is_big_endian_not_little_endian() {
    let time = timestamp_from_nanos(EPOCH_NANOS_1985_03_04_050607);
    let expected = EPOCH_NANOS_1985_03_04_050607.to_be_bytes();
    let (from_put, _, from_raw) = put_and_read_timestamp_regions(time);

    assert_eq!(from_put, expected);
    assert_eq!(from_raw, expected);
    assert_ne!(
        from_put,
        EPOCH_NANOS_1985_03_04_050607.to_le_bytes(),
        "little-endian encoding would fail this contract"
    );
}

#[test]
fn event_key_timestamp_is_not_millisecond_encoding() {
    // If milliseconds were stored instead of nanoseconds, key[0..8] would
    // differ. For 2020-06-15T12:00:00Z:
    //   nanoseconds: 1_592_222_400_000_000_000
    //   milliseconds: 1_592_222_400_000
    // The high-order bytes are completely different patterns.
    let time = timestamp_from_nanos(EPOCH_NANOS_2020_06_15_120000);
    let millis = EPOCH_NANOS_2020_06_15_120000 / 1_000_000;

    let expected = EPOCH_NANOS_2020_06_15_120000.to_be_bytes();
    let (from_put, _, from_raw) = put_and_read_timestamp_regions(time);
    assert_eq!(from_put, expected);
    assert_eq!(from_raw, expected);
    assert_ne!(
        from_put,
        millis.to_be_bytes(),
        "millisecond values must not be mistaken for nanoseconds"
    );
    assert_ne!(
        from_put,
        (millis * 1_000).to_be_bytes(),
        "microsecond scaling must not be mistaken for nanoseconds"
    );
}

/// Every detection model number lands in `key[8..12]`, under the pinned
/// time, for a positive and a pre-epoch time.
#[test]
fn event_key_holds_the_detection_model_number() {
    use review_protocol::types::Detail;

    let cases = [
        (DetectionModel::WatchlistMatch, 0_u32),
        (DetectionModel::LockyRansomware, 2),
        (DetectionModel::NonBrowser, 13),
        (DetectionModel::UnusualDestinationPattern, 17),
    ];
    for nanos in [
        EPOCH_NANOS_2020_06_15_123045,
        EPOCH_NANOS_1965_10_15_123456789,
    ] {
        for (model, number) in cases {
            let data_dir = tempdir().expect("temp data dir");
            let backup_dir = tempdir().expect("temp backup dir");
            let store = Store::new(data_dir.path(), backup_dir.path(), None).expect("open store");
            let db = store.events();

            // The key reads the header's model; the detail is not checked.
            let mut event = minimal_event(timestamp_from_nanos(nanos));
            event.detection_model = model;
            event.detail = Detail::NonBrowser;
            let key = db.put(&event, &stamp()).expect("put event");

            assert_eq!(key >> 64, i128::from(nanos), "{model:?}");
            assert_eq!((key >> 32) & 0xffff_ffff, i128::from(number), "{model:?}");
            assert_eq!(key & 0xffff_ffff, 0, "the first key of a time and model");

            let raw_key = db
                .first_raw_event_key()
                .expect("read raw RocksDB key")
                .expect("one stored event");
            assert_eq!(timestamp_region_from_raw(raw_key), nanos.to_be_bytes());
            assert_eq!(model_region_from_raw(raw_key), number.to_be_bytes());

            let (scanned_key, record) = db
                .iter_forward()
                .next()
                .expect("one stored event")
                .expect("valid stored event");
            assert_eq!(scanned_key, key);
            assert_eq!(record.event().detection_model, model);
        }
    }
}
