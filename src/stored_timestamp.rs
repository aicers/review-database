//! Serde adapters that preserve the existing `chrono::DateTime<Utc>` bincode
//! contract for table timestamp fields while exposing `jiff::Timestamp` in the
//! public API.
//!
//! On-disk and serde payloads continue to use chrono's string encoding through
//! these adapters. New writes serialize through chrono so existing stored bytes
//! remain readable without an in-place migration.

/// Serde adapter for required `creation_time`-style fields.
pub mod required {
    use chrono::{DateTime, Utc};
    use jiff::Timestamp;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serializes a `Timestamp` using the historical chrono string contract.
    ///
    /// # Panics
    ///
    /// Panics if the timestamp is outside chrono's supported range.
    pub fn serialize<S>(value: &Timestamp, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let datetime = DateTime::<Utc>::from_timestamp(
            value.as_second(),
            value.subsec_nanosecond().cast_unsigned(),
        )
        .expect("Jiff timestamps are within chrono's supported range");
        datetime.serialize(serializer)
    }

    /// Deserializes a `Timestamp` from the historical chrono string contract.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Timestamp, D::Error>
    where
        D: Deserializer<'de>,
    {
        let datetime = DateTime::<Utc>::deserialize(deserializer)?;
        Timestamp::new(
            datetime.timestamp(),
            datetime.timestamp_subsec_nanos().cast_signed(),
        )
        .map_err(serde::de::Error::custom)
    }
}
