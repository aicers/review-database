//! POC (not for merge): evidence for migrating `Network`/`Node` `creation_time`
//! to a primitive `i64` epoch-nanoseconds contract.
//!
//! `Network`/`Node` store `creation_time` via chrono's default serde (an
//! RFC 3339 string), and `review_database` encodes table values with
//! `bincode::DefaultOptions` (the private `serialize` helper in `src/tables.rs`).
//! Reproducing that encoder shows that `chrono::DateTime<Utc>` and
//! `jiff::Timestamp` do not serialize to identical bytes: chrono pads the
//! fractional part to 0/3/6/9 digits (`SecondsFormat::AutoSi`, keeping trailing
//! zeros) while jiff trims them. Old chrono bytes stay readable by jiff, but a
//! jiff-native rewrite is not byte-identical, so keeping the chrono string
//! contract without a migration is not free.
//!
//! Run: `cargo test --test poc_timestamp_bytes --all-features`

use bincode::Options;
use chrono::{DateTime, Utc};
use jiff::Timestamp;

/// Mirrors `review_database`'s private table-value encoder in `src/tables.rs`:
/// `bincode::DefaultOptions::new().serialize(input)`.
fn table_value_bytes<T: serde::Serialize>(value: &T) -> Vec<u8> {
    bincode::DefaultOptions::new()
        .serialize(value)
        .expect("timestamp serializes")
}

fn chrono_utc(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .expect("valid RFC 3339")
        .with_timezone(&Utc)
}

fn jiff_ts(s: &str) -> Timestamp {
    s.parse().expect("valid RFC 3339")
}

/// The same instant serializes to different table-value bytes depending on the
/// timestamp library, so swapping the stored type is not byte-preserving.
#[test]
fn chrono_and_jiff_table_value_bytes_are_not_interchangeable() {
    // Fractional part has trailing zeros at the 3/6/9 boundary: chrono pads,
    // jiff trims -> different bytes.
    for s in [
        "2024-01-15T10:30:00.120Z",
        "2024-01-15T10:30:00.100Z",
        "2024-01-15T10:30:00.500Z",
        "1969-12-31T23:59:59.500Z",
    ] {
        assert_ne!(
            table_value_bytes(&chrono_utc(s)),
            table_value_bytes(&jiff_ts(s)),
            "expected differing table-value bytes for {s}",
        );
    }

    // No trailing zeros at the boundary: bytes happen to coincide. This is why
    // a check against only full-precision fixtures wrongly looks byte-stable.
    for s in [
        "2024-01-15T10:30:00Z",
        "2024-01-15T10:30:00.123456Z",
        "2000-02-29T12:34:56.123456789Z",
        "2024-01-15T10:30:00.000000001Z",
    ] {
        assert_eq!(
            table_value_bytes(&chrono_utc(s)),
            table_value_bytes(&jiff_ts(s)),
            "expected identical table-value bytes for {s}",
        );
    }
}

/// Old chrono bytes remain readable by jiff, but a jiff-native rewrite does not
/// reproduce them, so the swap silently changes what is stored on disk.
#[test]
fn old_chrono_bytes_are_readable_by_jiff_but_rewrite_is_not_byte_stable() {
    let s = "2024-01-15T10:30:00.120Z";
    let old_chrono_bytes = table_value_bytes(&chrono_utc(s));

    // New jiff-native code can decode the old chrono-written bytes.
    let decoded: Timestamp = bincode::DefaultOptions::new()
        .deserialize(&old_chrono_bytes)
        .expect("jiff decodes chrono bytes");
    assert_eq!(decoded, jiff_ts(s));

    // But re-serializing with jiff yields different bytes than were stored.
    let rewritten = table_value_bytes(&decoded);
    assert_ne!(old_chrono_bytes, rewritten);

    // Mutual readability: chrono can also decode jiff-written bytes.
    let back: DateTime<Utc> = bincode::DefaultOptions::new()
        .deserialize(&rewritten)
        .expect("chrono decodes jiff bytes");
    assert_eq!(back, chrono_utc(s));
}
