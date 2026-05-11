use std::{fmt, net::IpAddr};

use attrievent::attribute::{RawEventAttrKind, TlsAttr};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, ThreatLevel, TriageScore, common::Match};
use crate::TriageExclusion;
use crate::event::common::{AttrValue, triage_scores_to_string, vector_to_string};

macro_rules! find_tls_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {{
        if let RawEventAttrKind::Tls(attr) = $raw_event_attr {
            let target_value = match attr {
                TlsAttr::SrcAddr => AttrValue::Addr($event.orig_addr),
                TlsAttr::SrcPort => AttrValue::UInt($event.orig_port.into()),
                TlsAttr::DstAddr => AttrValue::Addr($event.resp_addr),
                TlsAttr::DstPort => AttrValue::UInt($event.resp_port.into()),
                TlsAttr::Proto => AttrValue::UInt($event.proto.into()),
                TlsAttr::Duration => AttrValue::SInt($event.duration),
                TlsAttr::OrigPkts => AttrValue::UInt($event.orig_pkts),
                TlsAttr::RespPkts => AttrValue::UInt($event.resp_pkts),
                TlsAttr::OrigL2Bytes => AttrValue::UInt($event.orig_l2_bytes),
                TlsAttr::RespL2Bytes => AttrValue::UInt($event.resp_l2_bytes),
                TlsAttr::ServerName => AttrValue::String(&$event.server_name),
                TlsAttr::AlpnProtocol => AttrValue::String(&$event.server_name),
                TlsAttr::Ja3 => AttrValue::String(&$event.ja3),
                TlsAttr::Version => AttrValue::String(&$event.version),
                TlsAttr::ClientCipherSuites => AttrValue::VecUInt(std::borrow::Cow::Owned(
                    $event
                        .client_cipher_suites
                        .iter()
                        .map(|val| u64::from(*val))
                        .collect(),
                )),
                TlsAttr::ClientExtensions => AttrValue::VecUInt(std::borrow::Cow::Owned(
                    $event
                        .client_extensions
                        .iter()
                        .map(|val| u64::from(*val))
                        .collect(),
                )),
                TlsAttr::Cipher => AttrValue::UInt($event.cipher.into()),
                TlsAttr::Extensions => AttrValue::VecUInt(std::borrow::Cow::Owned(
                    $event
                        .extensions
                        .iter()
                        .map(|val| u64::from(*val))
                        .collect(),
                )),
                TlsAttr::Ja3s => AttrValue::String(&$event.ja3s),
                TlsAttr::Serial => AttrValue::String(&$event.serial),
                TlsAttr::SubjectCountry => AttrValue::String(&$event.subject_country),
                TlsAttr::SubjectOrgName => AttrValue::String(&$event.subject_org_name),
                TlsAttr::SubjectCommonName => AttrValue::String(&$event.subject_common_name),
                TlsAttr::ValidityNotBefore => AttrValue::SInt($event.validity_not_before.into()),
                TlsAttr::ValidityNotAfter => AttrValue::SInt($event.validity_not_after.into()),
                TlsAttr::SubjectAltName => AttrValue::String(&$event.subject_alt_name),
                TlsAttr::IssuerCountry => AttrValue::String(&$event.issuer_country),
                TlsAttr::IssuerOrgName => AttrValue::String(&$event.issuer_org_name),
                TlsAttr::IssuerOrgUnitName => AttrValue::String(&$event.issuer_org_unit_name),
                TlsAttr::IssuerCommonName => AttrValue::String(&$event.issuer_common_name),
                TlsAttr::LastAlert => AttrValue::UInt($event.last_alert.into()),
            };
            Some(target_value)
        } else {
            None
        }
    }};
}

pub type BlocklistTlsFields = BlocklistTlsFieldsV0_42;

#[derive(Serialize, Deserialize)]
pub struct BlocklistTlsFieldsV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub server_name: String,
    pub alpn_protocol: String,
    pub ja3: String,
    pub version: String,
    pub client_cipher_suites: Vec<u16>,
    pub client_extensions: Vec<u16>,
    pub cipher: u16,
    pub extensions: Vec<u16>,
    pub ja3s: String,
    pub serial: String,
    pub subject_country: String,
    pub subject_org_name: String,
    pub subject_common_name: String,
    pub validity_not_before: i64,
    pub validity_not_after: i64,
    pub subject_alt_name: String,
    pub issuer_country: String,
    pub issuer_org_name: String,
    pub issuer_org_unit_name: String,
    pub issuer_common_name: String,
    pub last_alert: u8,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl BlocklistTlsFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);
        format!(
            "category={:?} sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} server_name={:?} alpn_protocol={:?} ja3={:?} version={:?} client_cipher_suites={:?} client_extensions={:?} cipher={:?} extensions={:?} ja3s={:?} serial={:?} subject_country={:?} subject_org_name={:?} subject_common_name={:?} validity_not_before={:?} validity_not_after={:?} subject_alt_name={:?} issuer_country={:?} issuer_org_name={:?} issuer_org_unit_name={:?} issuer_common_name={:?} last_alert={:?} confidence={:?}",
            self.category.as_ref().map_or_else(
                || "Unspecified".to_string(),
                std::string::ToString::to_string
            ),
            self.sensor,
            self.orig_addr.to_string(),
            self.orig_port.to_string(),
            self.resp_addr.to_string(),
            self.resp_port.to_string(),
            self.proto.to_string(),
            start_time_dt.to_rfc3339(),
            self.duration.to_string(),
            self.orig_pkts.to_string(),
            self.resp_pkts.to_string(),
            self.orig_l2_bytes.to_string(),
            self.resp_l2_bytes.to_string(),
            self.server_name,
            self.alpn_protocol,
            self.ja3,
            self.version,
            vector_to_string(&self.client_cipher_suites),
            vector_to_string(&self.client_extensions),
            self.cipher.to_string(),
            vector_to_string(&self.extensions),
            self.ja3s,
            self.serial,
            self.subject_country,
            self.subject_org_name,
            self.subject_common_name,
            self.validity_not_before.to_string(),
            self.validity_not_after.to_string(),
            self.subject_alt_name,
            self.issuer_country,
            self.issuer_org_name,
            self.issuer_org_unit_name,
            self.issuer_common_name,
            self.last_alert.to_string(),
            self.confidence.to_string(),
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct BlocklistTls {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub server_name: String,
    pub alpn_protocol: String,
    pub ja3: String,
    pub version: String,
    pub client_cipher_suites: Vec<u16>,
    pub client_extensions: Vec<u16>,
    pub cipher: u16,
    pub extensions: Vec<u16>,
    pub ja3s: String,
    pub serial: String,
    pub subject_country: String,
    pub subject_org_name: String,
    pub subject_common_name: String,
    pub validity_not_before: i64,
    pub validity_not_after: i64,
    pub subject_alt_name: String,
    pub issuer_country: String,
    pub issuer_org_name: String,
    pub issuer_org_unit_name: String,
    pub issuer_common_name: String,
    pub last_alert: u8,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlocklistTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} server_name={:?} alpn_protocol={:?} ja3={:?} version={:?} client_cipher_suites={:?} client_extensions={:?} cipher={:?} extensions={:?} ja3s={:?} serial={:?} subject_country={:?} subject_org_name={:?} subject_common_name={:?} validity_not_before={:?} validity_not_after={:?} subject_alt_name={:?} issuer_country={:?} issuer_org_name={:?} issuer_org_unit_name={:?} issuer_common_name={:?} last_alert={:?} confidence={:?} triage_scores={:?}",
            self.sensor,
            self.orig_addr.to_string(),
            self.orig_port.to_string(),
            self.resp_addr.to_string(),
            self.resp_port.to_string(),
            self.proto.to_string(),
            self.start_time.to_rfc3339(),
            self.duration.to_string(),
            self.orig_pkts.to_string(),
            self.resp_pkts.to_string(),
            self.orig_l2_bytes.to_string(),
            self.resp_l2_bytes.to_string(),
            self.server_name,
            self.alpn_protocol,
            self.ja3,
            self.version,
            vector_to_string(&self.client_cipher_suites),
            vector_to_string(&self.client_extensions),
            self.cipher.to_string(),
            vector_to_string(&self.extensions),
            self.ja3s,
            self.serial,
            self.subject_country,
            self.subject_org_name,
            self.subject_common_name,
            self.validity_not_before.to_string(),
            self.validity_not_after.to_string(),
            self.subject_alt_name,
            self.issuer_country,
            self.issuer_org_name,
            self.issuer_org_unit_name,
            self.issuer_common_name,
            self.last_alert.to_string(),
            self.confidence.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl BlocklistTls {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistTlsFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            orig_addr: fields.orig_addr,
            orig_port: fields.orig_port,
            resp_addr: fields.resp_addr,
            resp_port: fields.resp_port,
            proto: fields.proto,
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            duration: fields.duration,
            orig_pkts: fields.orig_pkts,
            resp_pkts: fields.resp_pkts,
            orig_l2_bytes: fields.orig_l2_bytes,
            resp_l2_bytes: fields.resp_l2_bytes,
            server_name: fields.server_name,
            alpn_protocol: fields.alpn_protocol,
            ja3: fields.ja3,
            version: fields.version,
            client_cipher_suites: fields.client_cipher_suites,
            client_extensions: fields.client_extensions,
            cipher: fields.cipher,
            extensions: fields.extensions,
            ja3s: fields.ja3s,
            serial: fields.serial,
            subject_country: fields.subject_country,
            subject_org_name: fields.subject_org_name,
            subject_common_name: fields.subject_common_name,
            validity_not_before: fields.validity_not_before,
            validity_not_after: fields.validity_not_after,
            subject_alt_name: fields.subject_alt_name,
            issuer_country: fields.issuer_country,
            issuer_org_name: fields.issuer_org_name,
            issuer_org_unit_name: fields.issuer_org_unit_name,
            issuer_common_name: fields.issuer_common_name,
            last_alert: fields.last_alert,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl BlocklistTls {
    #[must_use]
    pub fn threat_level() -> ThreatLevel {
        ThreatLevel::Medium
    }
}

impl Match for BlocklistTls {
    fn src_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.orig_addr)
    }

    fn src_port(&self) -> u16 {
        self.orig_port
    }

    fn dst_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.resp_addr)
    }

    fn dst_port(&self) -> u16 {
        self.resp_port
    }

    fn proto(&self) -> u8 {
        self.proto
    }

    fn category(&self) -> Option<EventCategory> {
        self.category
    }

    fn level(&self) -> ThreatLevel {
        Self::threat_level()
    }

    fn kind(&self) -> &'static str {
        "blocklist tls"
    }

    fn sensor(&self) -> &str {
        self.sensor.as_str()
    }

    fn confidence(&self) -> Option<f32> {
        Some(self.confidence)
    }

    fn learning_method(&self) -> LearningMethod {
        LearningMethod::SemiSupervised
    }

    fn find_attr_by_kind(&self, raw_event_attr: RawEventAttrKind) -> Option<AttrValue<'_>> {
        find_tls_attr_by_kind!(self, raw_event_attr)
    }

    fn score_by_triage_exclusion(&self, triage_exclusion: &[TriageExclusion]) -> f64 {
        let matched = triage_exclusion.iter().any(|ti| match ti {
            TriageExclusion::IpAddress(filter) => self
                .src_addrs()
                .iter()
                .chain(self.dst_addrs().iter())
                .any(|&ip| filter.contains(ip)),
            TriageExclusion::Domain(regex_set) => regex_set.is_match(&self.server_name),
            TriageExclusion::Hostname(hostnames) => hostnames.contains(&self.server_name),
            TriageExclusion::Uri(_) => false, // TLS records don't carry URIs
        });
        if matched { f64::MIN } else { 0.0 }
    }
}

pub struct SuspiciousTlsTraffic {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub server_name: String,
    pub alpn_protocol: String,
    pub ja3: String,
    pub version: String,
    pub client_cipher_suites: Vec<u16>,
    pub client_extensions: Vec<u16>,
    pub cipher: u16,
    pub extensions: Vec<u16>,
    pub ja3s: String,
    pub serial: String,
    pub subject_country: String,
    pub subject_org_name: String,
    pub subject_common_name: String,
    pub validity_not_before: i64,
    pub validity_not_after: i64,
    pub subject_alt_name: String,
    pub issuer_country: String,
    pub issuer_org_name: String,
    pub issuer_org_unit_name: String,
    pub issuer_common_name: String,
    pub last_alert: u8,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for SuspiciousTlsTraffic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} server_name={:?} alpn_protocol={:?} ja3={:?} version={:?} client_cipher_suites={:?} client_extensions={:?} cipher={:?} extensions={:?} ja3s={:?} serial={:?} subject_country={:?} subject_org_name={:?} subject_common_name={:?} validity_not_before={:?} validity_not_after={:?} subject_alt_name={:?} issuer_country={:?} issuer_org_name={:?} issuer_org_unit_name={:?} issuer_common_name={:?} last_alert={:?} confidence={:?} triage_scores={:?}",
            self.sensor,
            self.orig_addr.to_string(),
            self.orig_port.to_string(),
            self.resp_addr.to_string(),
            self.resp_port.to_string(),
            self.proto.to_string(),
            self.start_time.to_rfc3339(),
            self.duration.to_string(),
            self.orig_pkts.to_string(),
            self.resp_pkts.to_string(),
            self.orig_l2_bytes.to_string(),
            self.resp_l2_bytes.to_string(),
            self.server_name,
            self.alpn_protocol,
            self.ja3,
            self.version,
            vector_to_string(&self.client_cipher_suites),
            vector_to_string(&self.client_extensions),
            self.cipher.to_string(),
            vector_to_string(&self.extensions),
            self.ja3s,
            self.serial,
            self.subject_country,
            self.subject_org_name,
            self.subject_common_name,
            self.validity_not_before.to_string(),
            self.validity_not_after.to_string(),
            self.subject_alt_name,
            self.issuer_country,
            self.issuer_org_name,
            self.issuer_org_unit_name,
            self.issuer_common_name,
            self.last_alert.to_string(),
            self.confidence.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl SuspiciousTlsTraffic {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistTlsFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            orig_addr: fields.orig_addr,
            orig_port: fields.orig_port,
            resp_addr: fields.resp_addr,
            resp_port: fields.resp_port,
            proto: fields.proto,
            duration: fields.duration,
            orig_pkts: fields.orig_pkts,
            resp_pkts: fields.resp_pkts,
            orig_l2_bytes: fields.orig_l2_bytes,
            resp_l2_bytes: fields.resp_l2_bytes,
            server_name: fields.server_name,
            alpn_protocol: fields.alpn_protocol,
            ja3: fields.ja3,
            version: fields.version,
            client_cipher_suites: fields.client_cipher_suites,
            client_extensions: fields.client_extensions,
            cipher: fields.cipher,
            extensions: fields.extensions,
            ja3s: fields.ja3s,
            serial: fields.serial,
            subject_country: fields.subject_country,
            subject_org_name: fields.subject_org_name,
            subject_common_name: fields.subject_common_name,
            validity_not_before: fields.validity_not_before,
            validity_not_after: fields.validity_not_after,
            subject_alt_name: fields.subject_alt_name,
            issuer_country: fields.issuer_country,
            issuer_org_name: fields.issuer_org_name,
            issuer_org_unit_name: fields.issuer_org_unit_name,
            issuer_common_name: fields.issuer_common_name,
            last_alert: fields.last_alert,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl SuspiciousTlsTraffic {
    #[must_use]
    pub fn threat_level() -> ThreatLevel {
        ThreatLevel::Medium
    }
}

impl Match for SuspiciousTlsTraffic {
    fn src_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.orig_addr)
    }

    fn src_port(&self) -> u16 {
        self.orig_port
    }

    fn dst_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.resp_addr)
    }

    fn dst_port(&self) -> u16 {
        self.resp_port
    }

    fn proto(&self) -> u8 {
        self.proto
    }

    fn category(&self) -> Option<EventCategory> {
        self.category
    }

    fn level(&self) -> ThreatLevel {
        Self::threat_level()
    }

    fn kind(&self) -> &'static str {
        "suspicious tls traffic"
    }

    fn sensor(&self) -> &str {
        self.sensor.as_str()
    }

    fn confidence(&self) -> Option<f32> {
        Some(self.confidence)
    }

    fn learning_method(&self) -> LearningMethod {
        LearningMethod::SemiSupervised
    }

    fn find_attr_by_kind(&self, raw_event_attr: RawEventAttrKind) -> Option<AttrValue<'_>> {
        find_tls_attr_by_kind!(self, raw_event_attr)
    }

    fn score_by_triage_exclusion(&self, triage_exclusion: &[TriageExclusion]) -> f64 {
        let matched = triage_exclusion.iter().any(|ti| match ti {
            TriageExclusion::IpAddress(filter) => self
                .src_addrs()
                .iter()
                .chain(self.dst_addrs().iter())
                .any(|&ip| filter.contains(ip)),
            TriageExclusion::Domain(regex_set) => regex_set.is_match(&self.server_name),
            TriageExclusion::Hostname(hostnames) => hostnames.contains(&self.server_name),
            TriageExclusion::Uri(_) => false, // TLS records don't carry URIs
        });
        if matched { f64::MIN } else { 0.0 }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::{TimeZone, Utc};

    use super::{BlocklistTls, BlocklistTlsFields, Match, SuspiciousTlsTraffic};
    use crate::event::EventCategory;
    use crate::tables::{ExclusionReason, TriageExclusion};
    use crate::types::HostNetworkGroup;

    fn tls_fields(server_name: &str) -> BlocklistTlsFields {
        BlocklistTlsFields {
            sensor: "sensor".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            orig_port: 12345,
            resp_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            resp_port: 443,
            proto: 6,
            start_time: Utc
                .with_ymd_and_hms(2023, 1, 1, 12, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 1_000_000_000,
            orig_pkts: 10,
            resp_pkts: 15,
            orig_l2_bytes: 1100,
            resp_l2_bytes: 2200,
            server_name: server_name.to_string(),
            alpn_protocol: "h2".to_string(),
            ja3: "ja3".to_string(),
            version: "TLSv1.3".to_string(),
            client_cipher_suites: vec![],
            client_extensions: vec![],
            cipher: 0,
            extensions: vec![],
            ja3s: "ja3s".to_string(),
            serial: "serial".to_string(),
            subject_country: "US".to_string(),
            subject_org_name: "org".to_string(),
            subject_common_name: "common".to_string(),
            validity_not_before: 0,
            validity_not_after: 0,
            subject_alt_name: "alt".to_string(),
            issuer_country: "US".to_string(),
            issuer_org_name: "org".to_string(),
            issuer_org_unit_name: "unit".to_string(),
            issuer_common_name: "common".to_string(),
            last_alert: 0,
            confidence: 0.9,
            category: Some(EventCategory::InitialAccess),
        }
    }

    fn ip_exclusion(addr: &str) -> TriageExclusion {
        TriageExclusion::from(ExclusionReason::IpAddress(HostNetworkGroup::new(
            vec![addr.parse().unwrap()],
            vec![],
            vec![],
        )))
    }

    fn domain_exclusion(domain: &str) -> TriageExclusion {
        TriageExclusion::from(ExclusionReason::Domain(vec![domain.to_string()]))
    }

    fn hostname_exclusion(hostname: &str) -> TriageExclusion {
        TriageExclusion::from(ExclusionReason::Hostname(vec![hostname.to_string()]))
    }

    fn uri_exclusion(uri: &str) -> TriageExclusion {
        TriageExclusion::from(ExclusionReason::Uri(vec![uri.to_string()]))
    }

    #[test]
    fn blocklist_tls_exclusion_matches_ip_address() {
        let time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        let event = BlocklistTls::new(time, tls_fields("internal-cert.example.com"));

        assert!(event.matched_any_exclusion(&[ip_exclusion("192.168.1.100")]));
        assert!(event.matched_any_exclusion(&[ip_exclusion("198.51.100.1")]));
        assert!(!event.matched_any_exclusion(&[ip_exclusion("10.0.0.1")]));
    }

    #[test]
    fn blocklist_tls_exclusion_matches_domain_via_server_name() {
        let time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        let event = BlocklistTls::new(time, tls_fields("internal-cert.example.com"));

        // Subdomain match: "example.com" matches "internal-cert.example.com".
        assert!(event.matched_any_exclusion(&[domain_exclusion("example.com")]));
        // Exact match.
        assert!(event.matched_any_exclusion(&[domain_exclusion("internal-cert.example.com")]));
        // Non-match.
        assert!(!event.matched_any_exclusion(&[domain_exclusion("other.com")]));
    }

    #[test]
    fn blocklist_tls_exclusion_matches_hostname_exact() {
        let time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        let event = BlocklistTls::new(time, tls_fields("internal-cert.example.com"));

        assert!(event.matched_any_exclusion(&[hostname_exclusion("internal-cert.example.com")]));
        // Hostname matching is exact equality, not substring.
        assert!(!event.matched_any_exclusion(&[hostname_exclusion("example.com")]));
        assert!(!event.matched_any_exclusion(&[hostname_exclusion("other")]));
    }

    #[test]
    fn blocklist_tls_exclusion_does_not_match_uri() {
        let time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        let event = BlocklistTls::new(time, tls_fields("internal-cert.example.com"));

        assert!(!event.matched_any_exclusion(&[uri_exclusion("/anything")]));
        assert!(!event.matched_any_exclusion(&[uri_exclusion("internal-cert.example.com")]));
    }

    #[test]
    fn suspicious_tls_traffic_exclusion_matches_all_kinds() {
        let time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        let event = SuspiciousTlsTraffic::new(time, tls_fields("internal-cert.example.com"));

        assert!(event.matched_any_exclusion(&[ip_exclusion("192.168.1.100")]));
        assert!(event.matched_any_exclusion(&[domain_exclusion("example.com")]));
        assert!(event.matched_any_exclusion(&[hostname_exclusion("internal-cert.example.com")]));
        assert!(!event.matched_any_exclusion(&[uri_exclusion("/anything")]));
        assert!(!event.matched_any_exclusion(&[]));
    }
}
