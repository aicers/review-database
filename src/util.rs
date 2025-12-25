//! Utility functions for the review database.

use std::net::IpAddr;

/// The unknown country code, used when lookup fails or returns an invalid code.
pub const UNKNOWN_COUNTRY_CODE: &str = "XX";

/// Looks up the country code for the given IP address.
///
/// # Arguments
///
/// * `locator` - The `IP2Location` database to use for the lookup
/// * `addr` - The IP address to look up
///
/// # Returns
///
/// Returns the two-letter country code for the IP address, or "XX" if the lookup fails
/// or the returned code is not a valid two-letter alphabetic code.
#[must_use]
pub fn find_ip_country(locator: &ip2location::DB, addr: IpAddr) -> String {
    locator
        .ip_lookup(addr)
        .map(|r| get_record_country_short_name(&r))
        .ok()
        .flatten()
        .filter(|code| is_valid_country_code(code))
        .unwrap_or_else(|| UNKNOWN_COUNTRY_CODE.to_string())
}

/// Validates that the given country code is a valid two-letter alphabetic code.
fn is_valid_country_code(code: &str) -> bool {
    let bytes = code.as_bytes();
    bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1].is_ascii_alphabetic()
}

/// Converts a country code string to a 2-byte array.
/// Returns `[b'X', b'X']` if the code is invalid.
#[must_use]
pub fn country_code_to_bytes(code: &str) -> [u8; 2] {
    let bytes = code.as_bytes();
    if bytes.len() == 2 {
        [bytes[0], bytes[1]]
    } else {
        *b"XX"
    }
}

fn get_record_country_short_name(record: &ip2location::Record) -> Option<String> {
    use ip2location::Record;
    match record {
        Record::ProxyDb(r) => r
            .country
            .as_ref()
            .map(|c| c.short_name.clone().into_owned()),
        Record::LocationDb(r) => r
            .country
            .as_ref()
            .map(|c| c.short_name.clone().into_owned()),
    }
}
