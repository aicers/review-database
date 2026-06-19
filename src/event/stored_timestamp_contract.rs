//! Baseline contract tests for event stored-field timestamps.
//!
//! Event `*FieldsStored` structs persist [`jiff::Timestamp`] values with the
//! [`timestamp::ts_nanoseconds`](super::timestamp::ts_nanoseconds) adapter.
//! That serde adapter writes a signed 64-bit Unix-epoch nanosecond count.
//! Production event storage serializes those structs with `bincode::serialize`
//! (fixint encoding), so each timestamp field occupies exactly eight
//! little-endian bytes on disk.
//!
//! # Test approach
//!
//! Core `i64` nanosecond contract checks use minimal test-only structs
//! (`TsNanosecondsField` and `DualTsNanosecondsFields`) so serde behavior
//! is pinned without coupling to unrelated stored-schema field ordering.
//! Production-path smoke tests exercise `convert_for_storage` for
//! representative event kinds and decode a checked-in raw binary fixture.
//!
//! | Coverage | Mechanism | Representative stored struct |
//! | --- | --- | --- |
//! | Single `ts_nanoseconds` field | `TsNanosecondsField` round-trip and size checks | [`HttpThreatFieldsStored`](super::HttpThreatFieldsStored) (`time`) |
//! | Multiple `ts_nanoseconds` fields | `DualTsNanosecondsFields` adjacent eight-byte values | [`NetworkThreatFieldsStored`](super::network::NetworkThreatFieldsStored) (`time`, `start_time`) |
//! | Full stored-event bytes | Checked-in fixture + `convert_for_storage` | [`ExtraThreatFieldsStored`](super::log::ExtraThreatFieldsStored) (`time`) |
//! | Production conversion | `convert_for_storage` byte prefix check | [`HttpThreatFieldsStored`](super::HttpThreatFieldsStored) (`time`) |
//!
//! A switch to Jiff default serde or an `i128` nanosecond representation at
//! this boundary would change serialized sizes or byte patterns and cause
//! these tests to fail.

use chrono::{DateTime, NaiveDate, Utc};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use super::{
    EventKind, ExtraThreatFields, ExtraThreatFieldsStored, HttpThreatFields,
    HttpThreatFieldsStored, convert_for_storage, timestamp,
};

/// Mirrors a single stored `ts_nanoseconds` field for isolated size checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TsNanosecondsField {
    #[serde(with = "timestamp::ts_nanoseconds")]
    time: Timestamp,
}

/// Mirrors multiple stored `ts_nanoseconds` fields without pinning unrelated schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DualTsNanosecondsFields {
    #[serde(with = "timestamp::ts_nanoseconds")]
    time: Timestamp,
    #[serde(with = "timestamp::ts_nanoseconds")]
    start_time: Timestamp,
}

/// Returns `1969-12-31T23:59:59.123456789Z`.
fn pre_1970_timestamp() -> Timestamp {
    "1969-12-31T23:59:59.123456789Z"
        .parse()
        .expect("valid timestamp")
}

/// Returns `2024-06-15T12:30:45.987654321Z`.
fn modern_timestamp() -> Timestamp {
    "2024-06-15T12:30:45.987654321Z"
        .parse()
        .expect("valid timestamp")
}

fn chrono_pre_1970_timestamp() -> DateTime<Utc> {
    let naive = NaiveDate::from_ymd_opt(1969, 12, 31)
        .expect("valid date")
        .and_hms_nano_opt(23, 59, 59, 123_456_789)
        .expect("valid time");
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

fn chrono_modern_timestamp() -> DateTime<Utc> {
    let naive = NaiveDate::from_ymd_opt(2024, 6, 15)
        .expect("valid date")
        .and_hms_nano_opt(12, 30, 45, 987_654_321)
        .expect("valid time");
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

fn subsec_nanos_from_i64_contract(time: Timestamp) -> i64 {
    timestamp::to_i64_nanos(time)
        .expect("in range")
        .rem_euclid(1_000_000_000)
}

fn serialize_ts_field(time: Timestamp) -> Vec<u8> {
    bincode::serialize(&TsNanosecondsField { time }).expect("serializable timestamp field")
}

fn assert_eight_byte_i64_contract(bytes: &[u8], expected_nanos: i64) {
    assert_eq!(
        bytes.len(),
        8,
        "ts_nanoseconds must serialize to eight fixint bytes, not {bytes:?}"
    );
    let decoded_nanos: i64 = bincode::deserialize(bytes).expect("i64 nanoseconds");
    assert_eq!(decoded_nanos, expected_nanos);
}

fn extra_threat_fields(time: DateTime<Utc>) -> ExtraThreatFields {
    ExtraThreatFields {
        time,
        sensor: "sensor".to_string(),
        service: "service".to_string(),
        content: "content".to_string(),
        db_name: "db".to_string(),
        rule_id: 1,
        matched_to: "rule".to_string(),
        cluster_id: None,
        attack_kind: "kind".to_string(),
        confidence: 1.0,
        category: None,
        triage_scores: None,
    }
}

fn http_threat_fields(time: DateTime<Utc>) -> HttpThreatFields {
    HttpThreatFields {
        time,
        sensor: String::new(),
        orig_addr: "127.0.0.1".parse().expect("valid ip"),
        orig_port: 0,
        resp_addr: "127.0.0.2".parse().expect("valid ip"),
        resp_port: 0,
        proto: 6,
        start_time: 0,
        duration: 0,
        orig_pkts: 0,
        resp_pkts: 0,
        orig_l2_bytes: 0,
        resp_l2_bytes: 0,
        method: String::new(),
        host: String::new(),
        uri: String::new(),
        referer: String::new(),
        version: String::new(),
        user_agent: String::new(),
        request_len: 0,
        response_len: 0,
        status_code: 0,
        status_msg: String::new(),
        username: String::new(),
        password: String::new(),
        cookie: String::new(),
        content_encoding: String::new(),
        content_type: String::new(),
        cache_control: String::new(),
        filenames: Vec::new(),
        mime_types: Vec::new(),
        body: Vec::new(),
        state: String::new(),
        db_name: String::new(),
        rule_id: 0,
        matched_to: String::new(),
        cluster_id: None,
        attack_kind: String::new(),
        confidence: 0.0,
        category: None,
    }
}

#[test]
fn ts_nanoseconds_field_uses_eight_byte_i64_bincode() {
    let time = modern_timestamp();
    let bytes = serialize_ts_field(time);
    assert_eight_byte_i64_contract(&bytes, timestamp::to_i64_nanos(time).expect("in range"));
}

#[test]
fn ts_nanoseconds_field_rejects_i128_sized_encoding() {
    let nanos = timestamp::to_i64_nanos(pre_1970_timestamp()).expect("in range");
    let i64_bytes = bincode::serialize(&nanos).expect("i64 serializable");
    let i128_bytes = bincode::serialize(&(i128::from(nanos))).expect("i128 serializable");

    assert_eq!(i64_bytes.len(), 8);
    assert_eq!(i128_bytes.len(), 16);
    assert_ne!(i64_bytes, i128_bytes);
}

#[test]
fn pre_1970_timestamp_round_trips_with_nanosecond_precision() {
    let time = pre_1970_timestamp();
    let bytes = serialize_ts_field(time);
    let decoded: TsNanosecondsField = bincode::deserialize(&bytes).expect("decodable");
    assert_eq!(decoded.time, time);
    assert_eq!(subsec_nanos_from_i64_contract(decoded.time), 123_456_789);
}

#[test]
fn modern_timestamp_round_trips_with_nanosecond_precision() {
    let time = modern_timestamp();
    let bytes = serialize_ts_field(time);
    let decoded: TsNanosecondsField = bincode::deserialize(&bytes).expect("decodable");
    assert_eq!(decoded.time, time);
    assert_eq!(decoded.time.subsec_nanosecond(), 987_654_321);
}

#[test]
fn i64_nanosecond_boundaries_round_trip_and_out_of_range_is_rejected() {
    for nanos in [i64::MIN, i64::MAX] {
        let time = timestamp::from_i64_nanos(nanos).expect("valid nanoseconds");
        let bytes = serialize_ts_field(time);
        assert_eight_byte_i64_contract(&bytes, nanos);
        let decoded: TsNanosecondsField = bincode::deserialize(&bytes).expect("decodable");
        assert_eq!(decoded.time, time);
    }

    let out_of_range =
        Timestamp::from_nanosecond(i128::from(i64::MAX) + 1).expect("valid jiff timestamp");
    assert!(bincode::serialize(&TsNanosecondsField { time: out_of_range }).is_err());
}

#[test]
fn full_stored_event_fixture_decodes_to_current_jiff_type() {
    const FIXTURE: &[u8] =
        include_bytes!("../../tests/fixtures/event_extra_threat_pre_1970_stored.bin");
    let expected = pre_1970_timestamp();
    let expected_nanos = timestamp::to_i64_nanos(expected).expect("in range");

    assert_eq!(FIXTURE.len(), 97);
    assert_eight_byte_i64_contract(&FIXTURE[..8], expected_nanos);

    let decoded: ExtraThreatFieldsStored =
        bincode::deserialize(FIXTURE).expect("fixture matches stored event contract");
    assert_eq!(decoded.time, expected);
}

#[test]
fn convert_for_storage_preserves_http_threat_i64_timestamp_bytes() {
    let time = chrono_modern_timestamp();
    let producer_bytes =
        bincode::serialize(&http_threat_fields(time)).expect("serializable producer fields");
    let bytes = convert_for_storage(EventKind::HttpThreat, &producer_bytes, None)
        .expect("convertible to stored fields");
    let expected = timestamp::from_chrono(time).expect("in range");
    let nanos = timestamp::to_i64_nanos(expected).expect("in range");
    assert_eight_byte_i64_contract(bytes.get(..8).expect("timestamp prefix"), nanos);

    let decoded: HttpThreatFieldsStored =
        bincode::deserialize(&bytes).expect("round-trippable stored fields");
    assert_eq!(decoded.time, expected);
}

#[test]
fn dual_ts_nanoseconds_fields_use_eight_byte_i64_bincode() {
    let time = pre_1970_timestamp();
    let start_time = modern_timestamp();
    let bytes = bincode::serialize(&DualTsNanosecondsFields { time, start_time })
        .expect("serializable dual timestamp fields");

    assert_eq!(
        bytes.len(),
        16,
        "two ts_nanoseconds fields must occupy sixteen bytes"
    );

    let decoded: DualTsNanosecondsFields =
        bincode::deserialize(&bytes).expect("round-trippable dual timestamp fields");
    assert_eq!(decoded.time, time);
    assert_eq!(decoded.start_time, start_time);
    assert_eq!(subsec_nanos_from_i64_contract(decoded.time), 123_456_789);
    assert_eq!(
        subsec_nanos_from_i64_contract(decoded.start_time),
        987_654_321
    );

    assert_eight_byte_i64_contract(
        bytes.get(..8).expect("leading timestamp"),
        timestamp::to_i64_nanos(time).expect("in range"),
    );
    assert_eight_byte_i64_contract(
        bytes.get(8..16).expect("second timestamp"),
        timestamp::to_i64_nanos(start_time).expect("in range"),
    );
}

#[test]
fn extra_threat_production_bytes_match_full_stored_event_fixture() {
    const FIXTURE: &[u8] =
        include_bytes!("../../tests/fixtures/event_extra_threat_pre_1970_stored.bin");
    let time = chrono_pre_1970_timestamp();
    let producer_bytes =
        bincode::serialize(&extra_threat_fields(time)).expect("serializable producer fields");
    let bytes = convert_for_storage(EventKind::ExtraThreat, &producer_bytes, None)
        .expect("convertible to stored fields");
    assert_eq!(bytes, FIXTURE);
    assert_eight_byte_i64_contract(
        bytes.get(..8).expect("timestamp prefix"),
        timestamp::to_i64_nanos(pre_1970_timestamp()).expect("in range"),
    );

    let decoded: ExtraThreatFieldsStored =
        bincode::deserialize(&bytes).expect("round-trippable stored fields");
    assert_eq!(decoded.time, pre_1970_timestamp());
}

#[test]
#[ignore = "rewrites the checked-in binary fixture; run only when intentionally replacing this baseline fixture"]
fn regenerate_extra_threat_pre_1970_stored_fixture() {
    let time = chrono_pre_1970_timestamp();
    let producer_bytes =
        bincode::serialize(&extra_threat_fields(time)).expect("serializable producer fields");
    let bytes = convert_for_storage(EventKind::ExtraThreat, &producer_bytes, None)
        .expect("convertible to stored fields");
    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/event_extra_threat_pre_1970_stored.bin");

    std::fs::write(fixture_path, bytes).expect("write raw binary fixture");
}
