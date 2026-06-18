//! Baseline contract tests for the event key timestamp region.
//!
//! `EventDb::put` stores `EventMessage.time` as **i64 epoch nanoseconds** in
//! the upper 64 bits of a 16-byte big-endian `i128` key:
//!
//! ```text
//! key = (timestamp_nanos << 64) | (event_kind << 32) | random_bits
//! key[0..8] == timestamp_nanos.to_be_bytes()
//! ```
//!
//! These tests pin that layout before migrating `EventMessage.time` from chrono
//! to Jiff. Expected timestamp values are pinned as literal `i64` nanoseconds
//! (not recomputed with chrono in the assertion path). On-disk layout is checked
//! via raw RocksDB key bytes as well as `EventDb::put` and `EventIterator`.

use std::net::{IpAddr, Ipv4Addr};

use chrono::{DateTime, TimeZone, Utc};
use tempfile::tempdir;

use super::{DnsEventFields, EventKind, EventMessage};
use crate::{EventCategory, Store};

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

fn minimal_dns_message(time: DateTime<Utc>) -> EventMessage {
    let fields = DnsEventFields {
        sensor: "baseline-test".to_string(),
        orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        orig_port: 53,
        resp_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        resp_port: 53,
        proto: 17,
        start_time: 0,
        duration: 0,
        orig_pkts: 0,
        resp_pkts: 0,
        orig_l2_bytes: 0,
        resp_l2_bytes: 0,
        query: "example.com".to_string(),
        answer: vec![],
        trans_id: 1,
        rtt: 0,
        qclass: 0,
        qtype: 0,
        rcode: 0,
        aa_flag: false,
        tc_flag: false,
        rd_flag: false,
        ra_flag: false,
        ttl: vec![],
        confidence: 0.5,
        category: Some(EventCategory::CommandAndControl),
    };
    EventMessage {
        time,
        kind: EventKind::DnsCovertChannel,
        fields: bincode::serialize(&fields).expect("serializable DnsEventFields"),
    }
}

fn put_and_read_timestamp_regions(time: DateTime<Utc>) -> ([u8; 8], [u8; 8], [u8; 8]) {
    let data_dir = tempdir().expect("temp data dir");
    let backup_dir = tempdir().expect("temp backup dir");
    let store = Store::new(data_dir.path(), backup_dir.path(), None).expect("open store");
    let db = store.events();

    let key = db.put(&minimal_dns_message(time)).expect("put event");
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
    let time = Utc.with_ymd_and_hms(2020, 6, 15, 12, 30, 45).unwrap();
    let expected = EPOCH_NANOS_2020_06_15_123045.to_be_bytes();
    let regions = put_and_read_timestamp_regions(time);
    assert_timestamp_regions(expected, regions);
}

#[test]
fn event_key_one_nanosecond_after_unix_epoch() {
    let time =
        Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap() + chrono::Duration::nanoseconds(1);
    assert_eq!(time.timestamp_nanos_opt(), Some(1));

    let expected = 1i64.to_be_bytes();
    let regions = put_and_read_timestamp_regions(time);
    assert_timestamp_regions(expected, regions);
}

#[test]
fn event_key_pre_1970_negative_epoch_nanoseconds() {
    let time = DateTime::parse_from_rfc3339("1965-10-15T12:34:56.123456789Z")
        .expect("valid RFC3339")
        .with_timezone(&Utc);

    let expected = EPOCH_NANOS_1965_10_15_123456789.to_be_bytes();
    let regions = put_and_read_timestamp_regions(time);
    assert_timestamp_regions(expected, regions);
}

#[test]
fn event_key_i64_nanosecond_range_boundaries() {
    for nanos in [i64::MIN, i64::MAX] {
        let time = DateTime::from_timestamp_nanos(nanos);
        let expected = nanos.to_be_bytes();
        let regions = put_and_read_timestamp_regions(time);
        assert_timestamp_regions(expected, regions);
    }
}

#[test]
fn chrono_timestamp_nanos_opt_out_of_range_dates() {
    // Practical chrono range for i64 epoch nanoseconds: roughly
    // 1677-09-21 through 2262-04-11. Outside that range,
    // `timestamp_nanos_opt()` returns `None` and no in-range `DateTime`
    // can be constructed for direct key assertions.
    let far_past = DateTime::parse_from_rfc3339("1000-01-01T00:00:00Z")
        .expect("valid RFC3339")
        .with_timezone(&Utc);
    let far_future = DateTime::parse_from_rfc3339("3000-01-01T00:00:00Z")
        .expect("valid RFC3339")
        .with_timezone(&Utc);

    assert!(
        far_past.timestamp_nanos_opt().is_none(),
        "before ~1677-09-21 overflows i64 nanoseconds"
    );
    assert!(
        far_future.timestamp_nanos_opt().is_none(),
        "after ~2262-04-11 overflows i64 nanoseconds"
    );
}

#[test]
fn event_key_put_maps_out_of_range_time_to_i64_max() {
    // Current `EventDb::put` uses `timestamp_nanos_opt().unwrap_or(i64::MAX)`.
    // Both underflow and overflow therefore encode `i64::MAX` in key[0..8].
    let far_future = DateTime::parse_from_rfc3339("3000-01-01T00:00:00Z")
        .expect("valid RFC3339")
        .with_timezone(&Utc);
    assert!(far_future.timestamp_nanos_opt().is_none());

    let expected = i64::MAX.to_be_bytes();
    let regions = put_and_read_timestamp_regions(far_future);
    assert_timestamp_regions(expected, regions);

    let far_past = DateTime::parse_from_rfc3339("1000-01-01T00:00:00Z")
        .expect("valid RFC3339")
        .with_timezone(&Utc);
    assert!(far_past.timestamp_nanos_opt().is_none());

    let regions = put_and_read_timestamp_regions(far_past);
    assert_timestamp_regions(expected, regions);
}

#[test]
fn event_key_timestamp_is_big_endian_not_little_endian() {
    let time = Utc.with_ymd_and_hms(1985, 3, 4, 5, 6, 7).unwrap();
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
    let time = Utc.with_ymd_and_hms(2020, 6, 15, 12, 0, 0).unwrap();
    let millis = time.timestamp_millis();

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
