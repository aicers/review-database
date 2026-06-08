//! Baseline contract tests for event stored-field timestamps.
//!
//! Event `*FieldsStored` structs persist `DateTime<Utc>` values with
//! `#[serde(with = "chrono::serde::ts_nanoseconds")]`. That serde adapter
//! writes a signed 64-bit Unix-epoch nanosecond count. Production event
//! storage serializes those structs with `bincode::serialize` (fixint
//! encoding), so each timestamp field occupies exactly eight little-endian
//! bytes on disk.
//!
//! # Covered stored fields
//!
//! | Struct | Timestamp field(s) | Why representative |
//! | --- | --- | --- |
//! | [`HttpThreatFieldsStored`](super::HttpThreatFieldsStored) | `time` | HTTP threat events; exercised by `convert_for_storage` and migration tests |
//! | [`NetworkThreatFieldsStored`](super::network::NetworkThreatFieldsStored) | `time`, `start_time` | Multiple `ts_nanoseconds` fields in one stored struct |
//! | [`ExtraThreatFieldsStored`](super::log::ExtraThreatFieldsStored) | `time` | Log/extra-threat family with a compact stored layout |
//!
//! These structs share the same serde attribute and bincode path as every
//! other event stored field that uses `ts_nanoseconds`. Pinning the contract
//! on this set guards the storage boundary before a Jiff migration.
//!
//! A switch to Jiff default serde or an `i128` nanosecond representation at
//! this boundary would change serialized sizes or byte patterns and cause
//! these tests to fail.

use chrono::{DateTime, NaiveDate, Utc, serde::ts_nanoseconds};
use serde::{Deserialize, Serialize};

use super::{ExtraThreatFieldsStored, HttpThreatFieldsStored, network::NetworkThreatFieldsStored};

/// Mirrors a single stored `ts_nanoseconds` field for isolated size checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TsNanosecondsField {
    #[serde(with = "ts_nanoseconds")]
    time: DateTime<Utc>,
}

/// Returns `1969-12-31T23:59:59.123456789Z`.
fn pre_1970_timestamp() -> DateTime<Utc> {
    let naive = NaiveDate::from_ymd_opt(1969, 12, 31)
        .expect("valid date")
        .and_hms_nano_opt(23, 59, 59, 123_456_789)
        .expect("valid time");
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

/// Returns `2024-06-15T12:30:45.987654321Z`.
fn modern_timestamp() -> DateTime<Utc> {
    let naive = NaiveDate::from_ymd_opt(2024, 6, 15)
        .expect("valid date")
        .and_hms_nano_opt(12, 30, 45, 987_654_321)
        .expect("valid time");
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

fn serialize_ts_field(time: DateTime<Utc>) -> Vec<u8> {
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

#[test]
fn ts_nanoseconds_field_uses_eight_byte_i64_bincode() {
    let time = modern_timestamp();
    let bytes = serialize_ts_field(time);
    assert_eight_byte_i64_contract(&bytes, time.timestamp_nanos_opt().expect("in range"));
}

#[test]
fn ts_nanoseconds_field_rejects_i128_sized_encoding() {
    let nanos = pre_1970_timestamp()
        .timestamp_nanos_opt()
        .expect("in range");
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
    assert_eq!(decoded.time.timestamp_subsec_nanos(), 123_456_789);
}

#[test]
fn modern_timestamp_round_trips_with_nanosecond_precision() {
    let time = modern_timestamp();
    let bytes = serialize_ts_field(time);
    let decoded: TsNanosecondsField = bincode::deserialize(&bytes).expect("decodable");
    assert_eq!(decoded.time, time);
    assert_eq!(decoded.time.timestamp_subsec_nanos(), 987_654_321);
}

#[test]
fn pre_1970_fixture_bytes_decode_to_chrono_timestamp() {
    const FIXTURE: &[u8] =
        include_bytes!("../../tests/fixtures/event_ts_nanoseconds_pre_1970_i64.bin");
    let expected = pre_1970_timestamp();
    let expected_nanos = expected.timestamp_nanos_opt().expect("in range");

    assert_eight_byte_i64_contract(FIXTURE, expected_nanos);

    let decoded: TsNanosecondsField =
        bincode::deserialize(FIXTURE).expect("fixture matches stored contract");
    assert_eq!(decoded.time, expected);
}

#[test]
fn http_threat_stored_time_leads_serialized_struct() {
    let time = modern_timestamp();
    let stored = HttpThreatFieldsStored {
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
    };

    let bytes = bincode::serialize(&stored).expect("serializable stored fields");
    let nanos = time.timestamp_nanos_opt().expect("in range");
    assert_eight_byte_i64_contract(bytes.get(..8).expect("timestamp prefix"), nanos);

    let decoded: HttpThreatFieldsStored =
        bincode::deserialize(&bytes).expect("round-trippable stored fields");
    assert_eq!(decoded.time, time);
}

#[test]
fn network_threat_stored_timestamps_round_trip() {
    let time = pre_1970_timestamp();
    let start_time = modern_timestamp();
    let stored = NetworkThreatFieldsStored {
        time,
        sensor: "sensor".to_string(),
        orig_addr: "10.0.0.1".parse().expect("valid ip"),
        orig_port: 1234,
        resp_addr: "10.0.0.2".parse().expect("valid ip"),
        resp_port: 443,
        proto: 6,
        service: "tls".to_string(),
        start_time,
        duration: 1,
        orig_pkts: 2,
        resp_pkts: 3,
        orig_l2_bytes: 4,
        resp_l2_bytes: 5,
        content: "payload".to_string(),
        db_name: "db".to_string(),
        rule_id: 9,
        matched_to: "rule".to_string(),
        cluster_id: Some(7),
        attack_kind: "scan".to_string(),
        confidence: 0.75,
        category: None,
        triage_scores: None,
    };

    let bytes = bincode::serialize(&stored).expect("serializable stored fields");
    let decoded: NetworkThreatFieldsStored =
        bincode::deserialize(&bytes).expect("round-trippable stored fields");
    assert_eq!(decoded.time, time);
    assert_eq!(decoded.start_time, start_time);
    assert_eq!(decoded.time.timestamp_subsec_nanos(), 123_456_789);
    assert_eq!(decoded.start_time.timestamp_subsec_nanos(), 987_654_321);

    let time_prefix = bytes.get(..8).expect("leading timestamp");
    assert_eight_byte_i64_contract(time_prefix, time.timestamp_nanos_opt().expect("in range"));
}

#[test]
fn extra_threat_stored_timestamp_round_trips_through_bincode() {
    let time = pre_1970_timestamp();
    let stored = ExtraThreatFieldsStored {
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
    };

    let bytes = bincode::serialize(&stored).expect("serializable stored fields");
    let decoded: ExtraThreatFieldsStored =
        bincode::deserialize(&bytes).expect("round-trippable stored fields");
    assert_eq!(decoded.time, time);
}
