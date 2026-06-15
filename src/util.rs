//! Utility functions for the review database.

use std::net::IpAddr;

/// Country code used before an endpoint lookup or migration has resolved it.
pub(crate) const COUNTRY_CODE_PENDING: [u8; 2] = *b"ZZ";

/// Country code used when a lookup does not produce a valid result.
pub(crate) const COUNTRY_CODE_INVALID: [u8; 2] = *b"XX";

/// Formats a two-letter country code for display output.
#[must_use]
pub(crate) fn country_code_as_str(code: &[u8; 2]) -> &str {
    std::str::from_utf8(code).unwrap_or("XX")
}

/// Formats a list of two-letter country codes as a comma-separated string.
#[must_use]
pub(crate) fn country_codes_to_string(codes: &[[u8; 2]]) -> String {
    if codes.is_empty() {
        String::new()
    } else {
        codes
            .iter()
            .map(country_code_as_str)
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Looks up the country code for the given IP address.
///
/// # Arguments
///
/// * `locator` - The `IP2Location` database to use for the lookup
/// * `addr` - The IP address to look up
///
/// # Returns
///
/// Returns the two-letter country code for the IP address, or "XX" if the lookup fails.
#[must_use]
pub fn find_ip_country(locator: &ip2location::DB, addr: IpAddr) -> String {
    country_code_as_str(&lookup_country_code(locator, addr)).to_owned()
}

/// Looks up and validates a stored two-letter country code.
#[must_use]
pub(crate) fn lookup_country_code(locator: &ip2location::DB, addr: IpAddr) -> [u8; 2] {
    locator
        .ip_lookup(addr)
        .ok()
        .and_then(|record| record_country_code(&record))
        .unwrap_or(COUNTRY_CODE_INVALID)
}

pub(crate) fn record_country_code(record: &ip2location::Record<'_>) -> Option<[u8; 2]> {
    get_record_country_short_name(record).and_then(parse_country_code)
}

fn parse_country_code(code: &str) -> Option<[u8; 2]> {
    let bytes = code.as_bytes();
    if bytes.len() == 2 && bytes.iter().all(u8::is_ascii_alphabetic) {
        Some([bytes[0], bytes[1]])
    } else {
        None
    }
}

fn get_record_country_short_name<'a>(record: &'a ip2location::Record<'_>) -> Option<&'a str> {
    use ip2location::Record;
    match record {
        Record::ProxyDb(r) => r.country.as_ref().map(|c| c.short_name.as_ref()),
        Record::LocationDb(r) => r.country.as_ref().map(|c| c.short_name.as_ref()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        COUNTRY_CODE_PENDING, country_code_as_str, country_codes_to_string, parse_country_code,
    };

    #[test]
    fn country_code_as_str_formats_pending_code() {
        assert_eq!(country_code_as_str(&COUNTRY_CODE_PENDING), "ZZ");
    }

    #[test]
    fn country_code_as_str_returns_invalid_fallback_for_non_utf8() {
        assert_eq!(country_code_as_str(&[0xFF, 0xFE]), "XX");
    }

    #[test]
    fn parse_country_code_rejects_invalid_values() {
        assert_eq!(parse_country_code("US"), Some(*b"US"));
        assert_eq!(parse_country_code("USA"), None);
        assert_eq!(parse_country_code("1A"), None);
    }

    #[test]
    fn country_codes_to_string_formats_multiple_codes() {
        assert_eq!(
            country_codes_to_string(&[COUNTRY_CODE_PENDING, [b'U', b'S']]),
            "ZZ,US"
        );
    }
}
