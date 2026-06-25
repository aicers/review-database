//! Jiff timestamp helpers for the event i64 epoch-nanosecond storage contract.
//!
//! Event keys and stored event fields persist timestamps as signed 64-bit
//! Unix-epoch nanosecond counts. In-memory values use [`jiff::Timestamp`];
//! the [`ts_nanoseconds`] serde adapter maps to and from those eight-byte
//! values without introducing Jiff's default `i128` nanosecond encoding.

use chrono::{DateTime, Utc};
use jiff::Timestamp;
use thiserror::Error;

/// Invariant message for `expect` when converting stored `i64` nanoseconds to Jiff.
pub const I64_NANOS_JIFF_INVARIANT: &str = "every i64 epoch-nanosecond value fits in Jiff's timestamp range; pinned by stored timestamp contract tests";

/// Errors converting between Jiff timestamps and the i64 nanosecond contract.
#[derive(Debug, Error)]
pub enum TimestampError {
    /// Nanoseconds cannot be represented as a signed 64-bit integer.
    #[error("timestamp nanoseconds {0} exceed i64 range")]
    OutOfI64Range(i128),
    /// Jiff rejected the nanosecond value.
    #[error("invalid timestamp: {0}")]
    Invalid(jiff::Error),
}

/// Serde adapter that reads and writes primitive `i64` Unix-epoch nanoseconds.
pub mod ts_nanoseconds {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::{Timestamp, from_i64_nanos, to_i64_nanos};

    /// Serializes a timestamp as signed 64-bit epoch nanoseconds.
    ///
    /// # Errors
    ///
    /// Returns an error when the timestamp cannot be represented as `i64`
    /// nanoseconds.
    pub fn serialize<S: Serializer>(time: &Timestamp, serializer: S) -> Result<S::Ok, S::Error> {
        let nanos = to_i64_nanos(*time).map_err(serde::ser::Error::custom)?;
        nanos.serialize(serializer)
    }

    /// Deserializes signed 64-bit epoch nanoseconds into a timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error when the stored nanoseconds are invalid for Jiff.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Timestamp, D::Error> {
        let nanos = i64::deserialize(deserializer)?;
        from_i64_nanos(nanos).map_err(serde::de::Error::custom)
    }
}

/// Converts a timestamp to signed 64-bit epoch nanoseconds.
///
/// # Errors
///
/// Returns [`TimestampError::OutOfI64Range`] when the value does not fit in
/// `i64`.
pub fn to_i64_nanos(time: Timestamp) -> Result<i64, TimestampError> {
    i64::try_from(time.as_nanosecond())
        .map_err(|_| TimestampError::OutOfI64Range(time.as_nanosecond()))
}

/// Converts signed 64-bit epoch nanoseconds to a timestamp.
///
/// # Errors
///
/// Returns [`TimestampError::Invalid`] when Jiff rejects the value.
pub fn from_i64_nanos(nanos: i64) -> Result<Timestamp, TimestampError> {
    Timestamp::from_nanosecond(i128::from(nanos)).map_err(TimestampError::Invalid)
}

/// Converts a timestamp to the nanoseconds encoded in event database keys.
///
/// Values outside the `i64` nanosecond range map to [`i64::MAX`], matching
/// the prior chrono `timestamp_nanos_opt().unwrap_or(i64::MAX)` contract.
#[must_use]
pub fn event_key_nanos(time: Timestamp) -> i64 {
    to_i64_nanos(time).unwrap_or(i64::MAX)
}

/// Converts a chrono UTC datetime to a timestamp when it fits the i64 contract.
///
/// # Errors
///
/// Returns [`TimestampError::OutOfI64Range`] when chrono cannot represent
/// the value as `i64` nanoseconds.
pub fn from_chrono(time: DateTime<Utc>) -> Result<Timestamp, TimestampError> {
    let nanos = time
        .timestamp_nanos_opt()
        .ok_or(TimestampError::OutOfI64Range(0))?;
    from_i64_nanos(nanos)
}

/// Converts a timestamp to a chrono UTC datetime when it fits the i64 contract.
///
/// # Errors
///
/// Returns an error when the timestamp is outside the `i64` nanosecond range
/// or chrono cannot represent the value.
pub fn to_chrono(time: Timestamp) -> Result<DateTime<Utc>, TimestampError> {
    Ok(DateTime::from_timestamp_nanos(to_i64_nanos(time)?))
}

/// Formats a timestamp as an RFC 3339 string in UTC.
///
/// # Errors
///
/// Returns an error when the timestamp is outside the `i64` nanosecond range.
pub fn format_rfc3339(time: Timestamp) -> Result<String, TimestampError> {
    Ok(to_chrono(time)?.to_rfc3339())
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, NaiveDate, TimeZone, Utc};
    use jiff::Timestamp;

    use super::{
        TimestampError, event_key_nanos, format_rfc3339, from_chrono, from_i64_nanos, to_i64_nanos,
        ts_nanoseconds,
    };

    fn modern_timestamp() -> Timestamp {
        "2024-06-15T12:30:45.987654321Z"
            .parse()
            .expect("valid timestamp")
    }

    fn pre_1970_timestamp() -> Timestamp {
        "1969-12-31T23:59:59.123456789Z"
            .parse()
            .expect("valid timestamp")
    }

    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug)]
    struct TsField {
        #[serde(with = "ts_nanoseconds")]
        time: Timestamp,
    }

    #[test]
    fn i64_nanos_round_trip() {
        for nanos in [0, 1, -1, i64::MIN, i64::MAX] {
            let time = from_i64_nanos(nanos).expect("valid nanoseconds");
            assert_eq!(to_i64_nanos(time).expect("in range"), nanos);
        }
    }

    #[test]
    fn serde_adapter_uses_eight_byte_i64_bincode() {
        let time = modern_timestamp();
        let bytes = bincode::serialize(&TsField { time }).expect("serializable");
        assert_eq!(bytes.len(), 8);
        let decoded: TsField = bincode::deserialize(&bytes).expect("decodable");
        assert_eq!(decoded.time, time);
    }

    #[test]
    fn serde_adapter_reads_legacy_i64_bytes() {
        let nanos: i64 = pre_1970_timestamp()
            .as_nanosecond()
            .try_into()
            .expect("in range");
        let legacy_bytes = bincode::serialize(&nanos).expect("i64 serializable");
        let decoded: TsField = bincode::deserialize(&legacy_bytes).expect("legacy bytes");
        assert_eq!(decoded.time, pre_1970_timestamp());
    }

    #[test]
    fn serde_adapter_rejects_i128_sized_encoding() {
        let nanos = pre_1970_timestamp().as_nanosecond();
        let i64_bytes =
            bincode::serialize(&i64::try_from(nanos).expect("in range")).expect("i64 serializable");
        let i128_bytes = bincode::serialize(&nanos).expect("i128 serializable");
        assert_eq!(i64_bytes.len(), 8);
        assert_eq!(i128_bytes.len(), 16);
        assert_ne!(i64_bytes, i128_bytes);
    }

    #[test]
    fn serialize_rejects_out_of_i64_range() {
        let out_of_range =
            Timestamp::from_nanosecond(i128::from(i64::MAX) + 1).expect("valid jiff timestamp");
        let err = bincode::serialize(&TsField { time: out_of_range }).expect_err("must fail");
        assert!(err.to_string().contains("exceed i64 range"));
    }

    #[test]
    fn event_key_nanos_matches_chrono_contract() {
        let cases = [
            ("2020-06-15T12:30:45Z", 1_592_224_245_000_000_000),
            ("1965-10-15T12:34:56.123456789Z", -132_924_303_876_543_211),
            ("1985-03-04T05:06:07Z", 478_760_767_000_000_000),
        ];
        for (input, expected_nanos) in cases {
            let time: Timestamp = input.parse().expect("valid timestamp");
            let chrono_nanos = expected_nanos;
            assert_eq!(chrono_nanos, expected_nanos);
            assert_eq!(event_key_nanos(time), expected_nanos);
            assert_eq!(
                event_key_nanos(time).to_be_bytes(),
                chrono_nanos.to_be_bytes()
            );
        }
    }

    #[test]
    fn event_key_nanos_maps_out_of_i64_range_to_max() {
        let far_future = Timestamp::from_nanosecond(i128::from(i64::MAX) + 1).expect("valid jiff");
        let far_past = Timestamp::from_nanosecond(i128::from(i64::MIN) - 1).expect("valid jiff");
        assert_eq!(event_key_nanos(far_future), i64::MAX);
        assert_eq!(event_key_nanos(far_past), i64::MAX);
    }

    #[test]
    fn chrono_conversion_round_trips_representative_values() {
        let chrono_time = Utc.with_ymd_and_hms(2020, 6, 15, 12, 30, 45).unwrap();
        let time = from_chrono(chrono_time).expect("in range");
        assert_eq!(
            format_rfc3339(time).expect("format"),
            chrono_time.to_rfc3339()
        );
    }

    #[test]
    fn from_chrono_rejects_out_of_i64_range() {
        let out_of_range = NaiveDate::from_ymd_opt(2263, 1, 1)
            .expect("valid date")
            .and_hms_opt(0, 0, 0)
            .expect("valid time");
        let out_of_range = DateTime::from_naive_utc_and_offset(out_of_range, Utc);
        assert!(matches!(
            from_chrono(out_of_range),
            Err(TimestampError::OutOfI64Range(_))
        ));
    }
}
