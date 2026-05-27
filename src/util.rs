//! Utility functions for the review database.

use std::net::IpAddr;

/// Country code used before an endpoint lookup or migration has resolved it.
pub(crate) const COUNTRY_CODE_PENDING: [u8; 2] = [b'Z', b'Z'];

/// Formats a two-letter country code for display output.
#[must_use]
pub(crate) fn country_code_to_string(code: [u8; 2]) -> String {
    String::from_utf8_lossy(&code).into_owned()
}

/// Formats a list of two-letter country codes as a comma-separated string.
#[must_use]
pub(crate) fn country_codes_to_string(codes: &[[u8; 2]]) -> String {
    if codes.is_empty() {
        String::new()
    } else {
        codes
            .iter()
            .map(|code| country_code_to_string(*code))
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
        .unwrap_or_else(|| "XX".to_string())
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
    use super::{COUNTRY_CODE_PENDING, country_code_to_string, country_codes_to_string};

    #[test]
    fn country_code_to_string_formats_pending_code() {
        assert_eq!(country_code_to_string(COUNTRY_CODE_PENDING), "ZZ");
    }

    #[test]
    fn country_codes_to_string_formats_multiple_codes() {
        assert_eq!(
            country_codes_to_string(&[COUNTRY_CODE_PENDING, [b'U', b'S']]),
            "ZZ,US"
        );
    }
}
