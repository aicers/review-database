//! Utility functions for the review database.

use std::net::IpAddr;

/// Country code used before an endpoint lookup or migration has resolved it.
pub(crate) const COUNTRY_CODE_PENDING: [u8; 2] = [b'Z', b'Z'];

/// Country code used when a lookup does not produce a valid result.
pub(crate) const COUNTRY_CODE_INVALID: [u8; 2] = [b'X', b'X'];
const COUNTRY_CODE_INVALID_DISPLAY: &str = "XX";

/// Formats a two-letter country code for display output.
#[must_use]
pub(crate) fn country_code_to_string(code: &[u8; 2]) -> &str {
    std::str::from_utf8(code).unwrap_or(COUNTRY_CODE_INVALID_DISPLAY)
}

/// Formats a list of two-letter country codes as a comma-separated string.
#[must_use]
pub(crate) fn country_codes_to_string(codes: &[[u8; 2]]) -> String {
    if codes.is_empty() {
        String::new()
    } else {
        codes
            .iter()
            .map(country_code_to_string)
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
    locator
        .ip_lookup(addr)
        .map(|r| get_record_country_short_name(&r))
        .ok()
        .flatten()
        .unwrap_or_else(|| country_code_to_string(&COUNTRY_CODE_INVALID).to_string())
}

/// Looks up and validates a stored two-letter country code.
#[must_use]
pub(crate) fn lookup_country_code(locator: Option<&ip2location::DB>, addr: IpAddr) -> [u8; 2] {
    let Some(locator) = locator else {
        return COUNTRY_CODE_PENDING;
    };
    let code = find_ip_country(locator, addr).to_ascii_uppercase();
    let bytes = code.as_bytes();
    if bytes.len() == 2 && bytes.iter().all(u8::is_ascii_alphabetic) {
        [bytes[0], bytes[1]]
    } else {
        COUNTRY_CODE_INVALID
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

#[cfg(test)]
mod tests {
    use super::{
        COUNTRY_CODE_INVALID, COUNTRY_CODE_PENDING, country_code_to_string,
        country_codes_to_string, lookup_country_code,
    };

    #[test]
    fn country_code_to_string_formats_pending_code() {
        assert_eq!(country_code_to_string(&COUNTRY_CODE_PENDING), "ZZ");
    }

    #[test]
    fn country_code_to_string_returns_invalid_fallback_for_non_utf8() {
        assert_eq!(country_code_to_string(&[0xFF, 0xFE]), "XX");
    }

    #[test]
    fn lookup_without_locator_preserves_pending_code() {
        assert_eq!(
            lookup_country_code(None, "192.0.2.1".parse().unwrap()),
            COUNTRY_CODE_PENDING
        );
        assert_eq!(country_code_to_string(&COUNTRY_CODE_INVALID), "XX");
    }

    #[test]
    fn country_codes_to_string_formats_multiple_codes() {
        assert_eq!(
            country_codes_to_string(&[COUNTRY_CODE_PENDING, [b'U', b'S']]),
            "ZZ,US"
        );
    }
}
