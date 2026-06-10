//! Literal-byte contract test for `Account` table values (issue #762, part of #746).
//!
//! `tests/fixtures/account_bytes.bin` was produced once by calling
//! `bytes_fixture_account()` and serializing with `Account::value()`, which uses
//! `bincode::DefaultOptions` directly in `src/account.rs`. Expected bytes are
//! checked in from the fixture rather than generated in this test.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use review_database::{
    Role, Value, bytes_fixture_account,
    types::{Account, FromKeyValue},
};

const ACCOUNT_BYTES_FIXTURE: &[u8] = include_bytes!("fixtures/account_bytes.bin");
const FIXTURE_TIMESTAMP: &str = "2000-02-29T12:34:56.123456789Z";

#[test]
fn account_table_value_bytes_match_fixture() {
    let fixed_time: DateTime<Utc> = FIXTURE_TIMESTAMP.parse().expect("valid timestamp");

    let decoded = Account::from_key_value(b"fixture-user", ACCOUNT_BYTES_FIXTURE)
        .expect("fixture bytes must deserialize via FromKeyValue");

    assert_eq!(decoded.username, "fixture-user");
    assert_eq!(decoded.role, Role::SecurityMonitor);
    assert_eq!(decoded.name, "Fixture Name");
    assert_eq!(decoded.department, "Fixture Department");
    assert_eq!(decoded.language.as_deref(), Some("en"));
    assert_eq!(decoded.theme.as_deref(), Some("dark"));
    assert_eq!(decoded.creation_time(), fixed_time);
    assert_eq!(decoded.last_signin_time(), Some(fixed_time));
    assert_eq!(
        decoded.allow_access_from,
        Some(vec![
            "192.0.2.1".parse::<IpAddr>().expect("valid IPv4"),
            "2001:db8::1".parse::<IpAddr>().expect("valid IPv6"),
        ])
    );
    assert_eq!(decoded.max_parallel_sessions, Some(3));
    assert_eq!(decoded.password_last_modified_at(), fixed_time);
    assert_eq!(decoded.customer_ids, Some(vec![1, 2, 42]));
    assert_eq!(decoded.failed_login_attempts, 2);
    assert_eq!(decoded.locked_out_until, Some(fixed_time));
    assert!(decoded.is_suspended);

    let expected = bytes_fixture_account();
    assert_eq!(decoded, expected);

    let encoded = expected.value();
    assert_eq!(encoded.as_slice(), ACCOUNT_BYTES_FIXTURE);
}
