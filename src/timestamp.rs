//! Conversions between [`jiff::Timestamp`] and the stored timestamp forms.
//!
//! Binary forms — database keys and table values —
//! persist a point in time as a signed 64-bit count of Unix-epoch
//! nanoseconds. In-memory values use [`jiff::Timestamp`]. The functions here
//! map between the two without Jiff's default `i128` nanosecond encoding.
//!
//! The `i64` nanosecond range spans `1677-09-21T00:12:43.145224192Z` to
//! `2262-04-11T23:47:16.854775807Z`. An event key maps a value outside it to
//! `i64::MAX`; table values store it saturated to the nearer end.

use jiff::Timestamp;
use thiserror::Error;

/// Invariant message for `expect` when converting stored `i64` nanoseconds to Jiff.
pub const I64_NANOS_JIFF_INVARIANT: &str =
    "every i64 epoch-nanosecond value fits in Jiff's timestamp range";

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

/// Serde adapter that writes [`saturating_i64_nanos`] and reads `i64`
/// Unix-epoch nanoseconds.
///
/// Table values use it, so that a timestamp outside the `i64` nanosecond
/// range is stored at the nearer end of the range instead of failing.
pub(crate) mod ts_nanoseconds_saturating {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::{Timestamp, from_i64_nanos, saturating_i64_nanos};

    /// Serializes a timestamp as signed 64-bit epoch nanoseconds, saturated
    /// to the `i64` range.
    ///
    /// # Errors
    ///
    /// Returns an error only when the serializer fails.
    pub(crate) fn serialize<S: Serializer>(
        time: &Timestamp,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        saturating_i64_nanos(*time).serialize(serializer)
    }

    /// Deserializes signed 64-bit epoch nanoseconds into a timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error when the stored value is not an `i64`.
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Timestamp, D::Error> {
        let nanos = i64::deserialize(deserializer)?;
        from_i64_nanos(nanos).map_err(serde::de::Error::custom)
    }
}

/// The optional form of [`ts_nanoseconds_saturating`].
pub(crate) mod ts_nanoseconds_saturating_option {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::{Timestamp, from_i64_nanos, saturating_i64_nanos};

    /// Serializes an optional timestamp as optional signed 64-bit epoch
    /// nanoseconds, saturated to the `i64` range.
    ///
    /// # Errors
    ///
    /// Returns an error only when the serializer fails.
    #[allow(clippy::ref_option)] // `serde(with)` passes the field by reference.
    pub(crate) fn serialize<S: Serializer>(
        time: &Option<Timestamp>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        time.map(saturating_i64_nanos).serialize(serializer)
    }

    /// Deserializes optional signed 64-bit epoch nanoseconds into an
    /// optional timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error when the stored value is not an optional `i64`.
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Timestamp>, D::Error> {
        Option::<i64>::deserialize(deserializer)?
            .map(from_i64_nanos)
            .transpose()
            .map_err(serde::de::Error::custom)
    }
}

/// Serde adapter that reads and writes `i64` Unix-epoch seconds, flooring a
/// subsecond timestamp toward negative infinity on write.
///
/// `1969-12-31T23:59:59.5Z` is written as `-1`, not `0`.
pub(crate) mod ts_seconds_floor {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::{NANOS_PER_SECOND, Timestamp};

    /// Serializes a timestamp as its floored signed 64-bit epoch seconds.
    ///
    /// # Errors
    ///
    /// Returns an error only when the serializer fails.
    pub(crate) fn serialize<S: Serializer>(
        time: &Timestamp,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let seconds = i64::try_from(time.as_nanosecond().div_euclid(NANOS_PER_SECOND))
            .expect("every Jiff timestamp's whole seconds fit in i64");
        seconds.serialize(serializer)
    }

    /// Deserializes signed 64-bit epoch seconds into a timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error when the seconds fall outside Jiff's timestamp range.
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Timestamp, D::Error> {
        let seconds = i64::deserialize(deserializer)?;
        Timestamp::from_second(seconds).map_err(serde::de::Error::custom)
    }
}

/// The number of nanoseconds in a second.
const NANOS_PER_SECOND: i128 = 1_000_000_000;

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

/// Converts a timestamp to signed 64-bit epoch nanoseconds, saturating a
/// value outside the `i64` range to [`i64::MIN`] or [`i64::MAX`], whichever
/// end is nearer.
#[must_use]
pub(crate) fn saturating_i64_nanos(time: Timestamp) -> i64 {
    let nanos = time.as_nanosecond();
    i64::try_from(nanos).unwrap_or(if nanos < 0 { i64::MIN } else { i64::MAX })
}

/// Converts a timestamp to the nanoseconds encoded in event database keys.
///
/// Values outside the `i64` nanosecond range map to [`i64::MAX`], the value
/// event keys have always used for them.
#[must_use]
pub(crate) fn event_key_nanos(time: Timestamp) -> i64 {
    to_i64_nanos(time).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use bincode::Options;
    use jiff::Timestamp;

    use super::{
        event_key_nanos, from_i64_nanos, saturating_i64_nanos, to_i64_nanos,
        ts_nanoseconds_saturating, ts_nanoseconds_saturating_option, ts_seconds_floor,
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
    struct SaturatingField {
        #[serde(with = "ts_nanoseconds_saturating")]
        time: Timestamp,
    }

    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug)]
    struct SaturatingOptionField {
        #[serde(with = "ts_nanoseconds_saturating_option")]
        time: Option<Timestamp>,
    }

    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug)]
    struct SecondsField {
        #[serde(with = "ts_seconds_floor")]
        time: Timestamp,
    }

    fn varint<T: serde::Serialize>(value: &T) -> Vec<u8> {
        bincode::DefaultOptions::new()
            .serialize(value)
            .expect("serializable")
    }

    #[test]
    fn i64_nanos_round_trip() {
        for nanos in [0, 1, -1, i64::MIN, i64::MAX] {
            let time = from_i64_nanos(nanos).expect("valid nanoseconds");
            assert_eq!(to_i64_nanos(time).expect("in range"), nanos);
        }
    }

    #[test]
    fn event_key_nanos_keeps_the_key_contract() {
        let cases = [
            ("2020-06-15T12:30:45Z", 1_592_224_245_000_000_000_i64),
            ("1965-10-15T12:34:56.123456789Z", -132_924_303_876_543_211),
            ("1985-03-04T05:06:07Z", 478_760_767_000_000_000),
        ];
        for (input, expected_nanos) in cases {
            let time: Timestamp = input.parse().expect("valid timestamp");
            assert_eq!(event_key_nanos(time), expected_nanos);
            assert_eq!(
                event_key_nanos(time).to_be_bytes(),
                expected_nanos.to_be_bytes()
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
    fn saturating_i64_nanos_saturates_to_the_nearer_end() {
        assert_eq!(saturating_i64_nanos(Timestamp::MAX), i64::MAX);
        assert_eq!(saturating_i64_nanos(Timestamp::MIN), i64::MIN);
        let just_above =
            Timestamp::from_nanosecond(i128::from(i64::MAX) + 1).expect("valid jiff timestamp");
        let just_below =
            Timestamp::from_nanosecond(i128::from(i64::MIN) - 1).expect("valid jiff timestamp");
        assert_eq!(saturating_i64_nanos(just_above), i64::MAX);
        assert_eq!(saturating_i64_nanos(just_below), i64::MIN);
        let far_future: Timestamp = "2300-01-01T00:00:00Z".parse().expect("valid timestamp");
        let far_past: Timestamp = "1600-01-01T00:00:00Z".parse().expect("valid timestamp");
        assert_eq!(saturating_i64_nanos(far_future), i64::MAX);
        assert_eq!(saturating_i64_nanos(far_past), i64::MIN);
    }

    #[test]
    fn saturating_i64_nanos_keeps_in_range_values() {
        for nanos in [i64::MIN, i64::MIN + 1, -1, 0, 1, i64::MAX - 1, i64::MAX] {
            let time = from_i64_nanos(nanos).expect("valid nanoseconds");
            assert_eq!(saturating_i64_nanos(time), nanos);
        }
        assert_eq!(
            saturating_i64_nanos(modern_timestamp()),
            1_718_454_645_987_654_321
        );
        assert_eq!(saturating_i64_nanos(pre_1970_timestamp()), -876_543_211);
    }

    #[test]
    fn saturating_adapter_round_trips_and_saturates() {
        for time in [
            modern_timestamp(),
            pre_1970_timestamp(),
            Timestamp::UNIX_EPOCH,
        ] {
            let bytes = varint(&SaturatingField { time });
            assert_eq!(
                bytes,
                varint(&i64::try_from(time.as_nanosecond()).expect("in range"))
            );
            let decoded: SaturatingField = bincode::DefaultOptions::new()
                .deserialize(&bytes)
                .expect("decodable");
            assert_eq!(decoded.time, time);
        }

        let bytes = varint(&SaturatingField {
            time: Timestamp::MAX,
        });
        assert_eq!(bytes, varint(&i64::MAX));
        let decoded: SaturatingField = bincode::DefaultOptions::new()
            .deserialize(&bytes)
            .expect("decodable");
        assert_eq!(decoded.time, from_i64_nanos(i64::MAX).expect("valid"));

        let bytes = varint(&SaturatingField {
            time: Timestamp::MIN,
        });
        assert_eq!(bytes, varint(&i64::MIN));
    }

    #[test]
    fn saturating_option_adapter_round_trips_and_saturates() {
        for time in [None, Some(modern_timestamp()), Some(pre_1970_timestamp())] {
            let bytes = varint(&SaturatingOptionField { time });
            assert_eq!(
                bytes,
                varint(&time.map(|t| i64::try_from(t.as_nanosecond()).expect("in range")))
            );
            let decoded: SaturatingOptionField = bincode::DefaultOptions::new()
                .deserialize(&bytes)
                .expect("decodable");
            assert_eq!(decoded.time, time);
        }

        let bytes = varint(&SaturatingOptionField {
            time: Some(Timestamp::MAX),
        });
        assert_eq!(bytes, varint(&Some(i64::MAX)));
        let bytes = varint(&SaturatingOptionField {
            time: Some(Timestamp::MIN),
        });
        assert_eq!(bytes, varint(&Some(i64::MIN)));
        let decoded: SaturatingOptionField = bincode::DefaultOptions::new()
            .deserialize(&bytes)
            .expect("decodable");
        assert_eq!(decoded.time, Some(from_i64_nanos(i64::MIN).expect("valid")));
    }

    /// Pins `ts_seconds_floor` to the values chrono's `ts_seconds` wrote:
    /// `DateTime::timestamp()`, which floors toward negative infinity.
    #[test]
    fn ts_seconds_floor_matches_chrono_ts_seconds_bytes() {
        let cases: [(&str, i64); 5] = [
            ("2024-06-15T12:30:45Z", 1_718_454_645),
            ("2024-06-15T12:30:45.987654321Z", 1_718_454_645),
            ("1969-12-31T23:59:59Z", -1),
            ("1969-01-01T00:00:00Z", -31_536_000),
            ("1969-12-31T23:59:59.5Z", -1),
        ];
        for (input, seconds) in cases {
            let time: Timestamp = input.parse().expect("valid timestamp");
            assert_eq!(varint(&SecondsField { time }), varint(&seconds), "{input}");
        }
        let half: Timestamp = "1969-12-31T23:59:59.5Z".parse().expect("valid timestamp");
        assert_eq!(varint(&SecondsField { time: half }), [1]);
    }

    #[test]
    fn ts_seconds_floor_reads_whole_seconds() {
        let decoded: SecondsField = bincode::DefaultOptions::new()
            .deserialize(&varint(&-1_i64))
            .expect("decodable");
        assert_eq!(
            decoded.time,
            "1969-12-31T23:59:59Z"
                .parse::<Timestamp>()
                .expect("valid timestamp")
        );
        let out_of_range = varint(&(Timestamp::MAX.as_second() + 1));
        assert!(
            bincode::DefaultOptions::new()
                .deserialize::<SecondsField>(&out_of_range)
                .is_err()
        );
    }
}
