#![allow(clippy::module_name_repetitions)]

use std::{fmt, net::IpAddr};

use attrievent::attribute::{RawEventAttrKind, RdpAttr};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use super::timestamp::{self, ts_nanoseconds as jiff_ts_nanoseconds};
use super::{
    EventCategory, LearningMethod, ThreatLevel, TriageScore,
    common::{Match, vector_to_string},
};
use crate::event::common::{AttrValue, triage_scores_to_string};

macro_rules! find_rdp_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {{
        if let RawEventAttrKind::Rdp(attr) = $raw_event_attr {
            let target_value = match attr {
                RdpAttr::SrcAddr => AttrValue::Addr($event.orig_addr),
                RdpAttr::SrcPort => AttrValue::UInt($event.orig_port.into()),
                RdpAttr::DstAddr => AttrValue::Addr($event.resp_addr),
                RdpAttr::DstPort => AttrValue::UInt($event.resp_port.into()),
                RdpAttr::Proto => AttrValue::UInt($event.proto.into()),
                RdpAttr::Duration => AttrValue::SInt($event.duration),
                RdpAttr::OrigPkts => AttrValue::UInt($event.orig_pkts),
                RdpAttr::RespPkts => AttrValue::UInt($event.resp_pkts),
                RdpAttr::OrigL2Bytes => AttrValue::UInt($event.orig_l2_bytes),
                RdpAttr::RespL2Bytes => AttrValue::UInt($event.resp_l2_bytes),
                RdpAttr::Cookie => AttrValue::String(&$event.cookie),
            };
            Some(target_value)
        } else {
            None
        }
    }};
}

#[derive(Serialize, Deserialize)]
pub struct RdpBruteForceFields {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub resp_addrs: Vec<IpAddr>,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub first_event_start_time: i64,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub last_event_start_time: i64,
    pub proto: u8,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

pub(crate) type RdpBruteForceFieldsStored = RdpBruteForceFieldsStoredV0_46;

#[derive(Deserialize, Serialize)]
pub(crate) struct RdpBruteForceFieldsStoredV0_46 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_country_code: [u8; 2],
    pub resp_addrs: Vec<IpAddr>,
    pub resp_country_codes: Vec<[u8; 2]>,
    pub first_event_start_time: i64,
    pub last_event_start_time: i64,
    pub proto: u8,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl From<RdpBruteForceFields> for RdpBruteForceFieldsStored {
    fn from(value: RdpBruteForceFields) -> Self {
        let resp_addr_count = value.resp_addrs.len();
        Self {
            sensor: value.sensor,
            orig_addr: value.orig_addr,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addrs: value.resp_addrs,
            resp_country_codes: vec![crate::util::COUNTRY_CODE_PENDING; resp_addr_count],
            first_event_start_time: value.first_event_start_time,
            last_event_start_time: value.last_event_start_time,
            proto: value.proto,
            confidence: value.confidence,
            category: value.category,
        }
    }
}

impl RdpBruteForceFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let first_event_start_time =
            timestamp::format_i64_nanos_rfc3339(self.first_event_start_time).unwrap_or_default();
        let last_event_start_time =
            timestamp::format_i64_nanos_rfc3339(self.last_event_start_time).unwrap_or_default();
        format!(
            "category={:?} sensor={:?} orig_addr={:?} resp_addrs={:?} first_event_start_time={:?} last_event_start_time={:?} proto={:?} confidence={:?}",
            self.category.as_ref().map_or_else(
                || "Unspecified".to_string(),
                std::string::ToString::to_string
            ),
            self.sensor,
            self.orig_addr.to_string(),
            vector_to_string(&self.resp_addrs),
            first_event_start_time,
            last_event_start_time,
            self.proto.to_string(),
            self.confidence.to_string()
        )
    }
}

#[derive(Serialize, Deserialize)]
pub struct RdpBruteForce {
    pub sensor: String,
    #[serde(with = "jiff_ts_nanoseconds")]
    pub time: Timestamp,
    pub orig_addr: IpAddr,
    pub orig_country_code: [u8; 2],
    pub resp_addrs: Vec<IpAddr>,
    pub resp_country_codes: Vec<[u8; 2]>,
    #[serde(with = "jiff_ts_nanoseconds")]
    pub first_event_start_time: Timestamp,
    #[serde(with = "jiff_ts_nanoseconds")]
    pub last_event_start_time: Timestamp,
    pub proto: u8,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for RdpBruteForce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "orig_addr={:?} orig_country_code={:?} resp_addrs={:?} resp_country_codes={:?} first_event_start_time={:?} last_event_start_time={:?} proto={:?} triage_scores={:?}",
            self.orig_addr.to_string(),
            crate::util::country_code_as_str(&self.orig_country_code),
            vector_to_string(&self.resp_addrs),
            crate::util::country_codes_to_string(&self.resp_country_codes),
            timestamp::format_rfc3339(self.first_event_start_time).unwrap_or_default(),
            timestamp::format_rfc3339(self.last_event_start_time).unwrap_or_default(),
            self.proto.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl RdpBruteForce {
    pub(super) fn new(time: Timestamp, fields: &RdpBruteForceFieldsStored) -> Self {
        RdpBruteForce {
            sensor: fields.sensor.clone(),
            time,
            orig_addr: fields.orig_addr,
            orig_country_code: fields.orig_country_code,
            resp_addrs: fields.resp_addrs.clone(),
            resp_country_codes: fields.resp_country_codes.clone(),
            first_event_start_time: timestamp::from_i64_nanos(fields.first_event_start_time)
                .expect(timestamp::I64_NANOS_JIFF_INVARIANT),
            last_event_start_time: timestamp::from_i64_nanos(fields.last_event_start_time)
                .expect(timestamp::I64_NANOS_JIFF_INVARIANT),
            proto: fields.proto,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl RdpBruteForce {
    #[must_use]
    pub fn threat_level() -> ThreatLevel {
        ThreatLevel::Medium
    }
}

impl Match for RdpBruteForce {
    fn orig_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.orig_addr)
    }

    fn orig_port(&self) -> u16 {
        0
    }

    fn orig_country_codes(&self) -> &[[u8; 2]] {
        std::slice::from_ref(&self.orig_country_code)
    }

    fn resp_addrs(&self) -> &[IpAddr] {
        &self.resp_addrs
    }

    fn resp_port(&self) -> u16 {
        0
    }

    fn resp_country_codes(&self) -> &[[u8; 2]] {
        &self.resp_country_codes
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
        "rdp brute force"
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
        if let RawEventAttrKind::Rdp(attr) = raw_event_attr {
            match attr {
                RdpAttr::SrcAddr => Some(AttrValue::Addr(self.orig_addr)),
                RdpAttr::DstAddr => Some(AttrValue::VecAddr(std::borrow::Cow::Borrowed(
                    &self.resp_addrs,
                ))),
                RdpAttr::Proto => Some(AttrValue::UInt(self.proto.into())),
                _ => None,
            }
        } else {
            None
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct BlocklistRdpFields {
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
    pub cookie: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

pub(crate) type BlocklistRdpFieldsStored = BlocklistRdpFieldsStoredV0_46;

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistRdpFieldsStoredV0_46 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub orig_country_code: [u8; 2],
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub resp_country_code: [u8; 2],
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub cookie: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl From<BlocklistRdpFields> for BlocklistRdpFieldsStored {
    fn from(value: BlocklistRdpFields) -> Self {
        Self {
            sensor: value.sensor,
            orig_addr: value.orig_addr,
            orig_port: value.orig_port,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: value.resp_addr,
            resp_port: value.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: value.proto,
            start_time: value.start_time,
            duration: value.duration,
            orig_pkts: value.orig_pkts,
            resp_pkts: value.resp_pkts,
            orig_l2_bytes: value.orig_l2_bytes,
            resp_l2_bytes: value.resp_l2_bytes,
            cookie: value.cookie,
            confidence: value.confidence,
            category: value.category,
        }
    }
}

impl BlocklistRdpFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time = timestamp::format_i64_nanos_rfc3339(self.start_time).unwrap_or_default();
        format!(
            "category={:?} sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} cookie={:?} confidence={:?}",
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
            start_time,
            self.duration.to_string(),
            self.orig_pkts.to_string(),
            self.resp_pkts.to_string(),
            self.orig_l2_bytes.to_string(),
            self.resp_l2_bytes.to_string(),
            self.cookie,
            self.confidence.to_string()
        )
    }
}

pub struct BlocklistRdp {
    pub time: Timestamp,
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub orig_country_code: [u8; 2],
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub resp_country_code: [u8; 2],
    pub proto: u8,
    pub start_time: Timestamp,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub cookie: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}
impl fmt::Display for BlocklistRdp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} orig_country_code={:?} resp_addr={:?} resp_port={:?} resp_country_code={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} cookie={:?} triage_scores={:?}",
            self.sensor,
            self.orig_addr.to_string(),
            self.orig_port.to_string(),
            crate::util::country_code_as_str(&self.orig_country_code),
            self.resp_addr.to_string(),
            self.resp_port.to_string(),
            crate::util::country_code_as_str(&self.resp_country_code),
            self.proto.to_string(),
            timestamp::format_rfc3339(self.start_time).unwrap_or_default(),
            self.duration.to_string(),
            self.orig_pkts.to_string(),
            self.resp_pkts.to_string(),
            self.orig_l2_bytes.to_string(),
            self.resp_l2_bytes.to_string(),
            self.cookie,
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl BlocklistRdp {
    pub(super) fn new(time: Timestamp, fields: BlocklistRdpFieldsStored) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            orig_addr: fields.orig_addr,
            orig_port: fields.orig_port,
            orig_country_code: fields.orig_country_code,
            resp_addr: fields.resp_addr,
            resp_port: fields.resp_port,
            resp_country_code: fields.resp_country_code,
            proto: fields.proto,
            start_time: timestamp::from_i64_nanos(fields.start_time)
                .expect(timestamp::I64_NANOS_JIFF_INVARIANT),
            duration: fields.duration,
            orig_pkts: fields.orig_pkts,
            resp_pkts: fields.resp_pkts,
            orig_l2_bytes: fields.orig_l2_bytes,
            resp_l2_bytes: fields.resp_l2_bytes,
            cookie: fields.cookie,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl BlocklistRdp {
    #[must_use]
    pub fn threat_level() -> ThreatLevel {
        ThreatLevel::Medium
    }
}

impl Match for BlocklistRdp {
    fn orig_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.orig_addr)
    }

    fn orig_port(&self) -> u16 {
        self.orig_port
    }

    fn orig_country_codes(&self) -> &[[u8; 2]] {
        std::slice::from_ref(&self.orig_country_code)
    }

    fn resp_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.resp_addr)
    }

    fn resp_port(&self) -> u16 {
        self.resp_port
    }

    fn resp_country_codes(&self) -> &[[u8; 2]] {
        std::slice::from_ref(&self.resp_country_code)
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
        "blocklist rdp"
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
        find_rdp_attr_by_kind!(self, raw_event_attr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct RdpBruteForceFieldsLegacy {
        sensor: String,
        orig_addr: IpAddr,
        resp_addrs: Vec<IpAddr>,
        start_time: i64,
        end_time: i64,
        proto: u8,
        confidence: f32,
        category: Option<EventCategory>,
    }

    #[test]
    fn rdp_bruteforce_bincode_compatibility() {
        let old = RdpBruteForceFieldsLegacy {
            sensor: "sensor".to_string(),
            orig_addr: IpAddr::from([127, 0, 0, 1]),
            resp_addrs: vec![IpAddr::from([127, 0, 0, 2])],
            start_time: 123,
            end_time: 456,
            proto: 6,
            confidence: 0.3,
            category: Some(EventCategory::Discovery),
        };
        let bytes = bincode::serialize(&old).expect("legacy fields should serialize");
        let parsed: RdpBruteForceFields =
            bincode::deserialize(&bytes).expect("new fields should deserialize");
        assert_eq!(parsed.first_event_start_time, 123);
        assert_eq!(parsed.last_event_start_time, 456);
    }
}
