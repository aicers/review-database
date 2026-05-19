#![allow(clippy::module_name_repetitions)]

use std::{fmt, net::IpAddr};

use attrievent::attribute::{RawEventAttrKind, RdpAttr};
use chrono::{DateTime, Utc};
use itertools::Itertools;
use serde::{Deserialize, Serialize};

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
    pub start_time: i64,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub end_time: i64,
    pub proto: u8,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

pub(crate) type RdpBruteForceFieldsStored = RdpBruteForceFieldsStoredV0_46;

#[derive(Deserialize, Serialize)]
pub(crate) struct RdpBruteForceFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub resp_addrs: Vec<IpAddr>,
    pub start_time: i64,
    pub end_time: i64,
    pub proto: u8,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct RdpBruteForceFieldsStoredV0_46 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_country_code: [u8; 2],
    pub resp_addrs: Vec<IpAddr>,
    pub resp_country_codes: Vec<[u8; 2]>,
    pub start_time: i64,
    pub end_time: i64,
    pub proto: u8,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl From<RdpBruteForceFieldsStoredV0_42> for RdpBruteForceFieldsStored {
    fn from(old: RdpBruteForceFieldsStoredV0_42) -> Self {
        let resp_country_codes = vec![crate::util::UNRESOLVED_COUNTRY_CODE; old.resp_addrs.len()];
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_country_code: crate::util::UNRESOLVED_COUNTRY_CODE,
            resp_addrs: old.resp_addrs,
            start_time: old.start_time,
            end_time: old.end_time,
            proto: old.proto,
            resp_country_codes,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<RdpBruteForceFields> for RdpBruteForceFieldsStored {
    fn from(value: RdpBruteForceFields) -> Self {
        let resp_country_codes = vec![crate::util::UNRESOLVED_COUNTRY_CODE; value.resp_addrs.len()];
        Self {
            sensor: value.sensor,
            orig_addr: value.orig_addr,
            orig_country_code: crate::util::UNRESOLVED_COUNTRY_CODE,
            resp_addrs: value.resp_addrs,
            start_time: value.start_time,
            end_time: value.end_time,
            proto: value.proto,
            resp_country_codes,
            confidence: value.confidence,
            category: value.category,
        }
    }
}

impl RdpBruteForceFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);
        let end_time_dt = DateTime::from_timestamp_nanos(self.end_time);
        format!(
            "category={:?} sensor={:?} orig_addr={:?} resp_addrs={:?} start_time={:?} end_time={:?} proto={:?} confidence={:?}",
            self.category.as_ref().map_or_else(
                || "Unspecified".to_string(),
                std::string::ToString::to_string
            ),
            self.sensor,
            self.orig_addr.to_string(),
            vector_to_string(&self.resp_addrs),
            start_time_dt.to_rfc3339(),
            end_time_dt.to_rfc3339(),
            self.proto.to_string(),
            self.confidence.to_string()
        )
    }
}

#[derive(Serialize, Deserialize)]
pub struct RdpBruteForce {
    pub sensor: String,
    pub time: DateTime<Utc>,
    pub orig_addr: IpAddr,
    pub orig_country_code: [u8; 2],
    pub resp_addrs: Vec<IpAddr>,
    pub resp_country_codes: Vec<[u8; 2]>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub proto: u8,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for RdpBruteForce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "orig_addr={:?} orig_country_code={:?} resp_addrs={:?} resp_country_codes={:?} start_time={:?} end_time={:?} proto={:?} triage_scores={:?}",
            self.orig_addr.to_string(),
            std::str::from_utf8(&self.orig_country_code).unwrap_or("XX"),
            vector_to_string(&self.resp_addrs),
            self.resp_country_codes
                .iter()
                .map(|code| std::str::from_utf8(code).unwrap_or("XX"))
                .join(","),
            self.start_time.to_rfc3339(),
            self.end_time.to_rfc3339(),
            self.proto.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl RdpBruteForce {
    pub(super) fn new(time: DateTime<Utc>, fields: &RdpBruteForceFieldsStored) -> Self {
        RdpBruteForce {
            sensor: fields.sensor.clone(),
            time,
            orig_addr: fields.orig_addr,
            orig_country_code: fields.orig_country_code,
            resp_addrs: fields.resp_addrs.clone(),
            resp_country_codes: fields.resp_country_codes.clone(),
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            end_time: DateTime::from_timestamp_nanos(fields.end_time),
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
    fn src_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.orig_addr)
    }

    fn src_port(&self) -> u16 {
        0
    }

    fn dst_addrs(&self) -> &[IpAddr] {
        &self.resp_addrs
    }

    fn dst_port(&self) -> u16 {
        0
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
pub(crate) struct BlocklistRdpFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
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

impl From<BlocklistRdpFieldsStoredV0_42> for BlocklistRdpFieldsStored {
    fn from(old: BlocklistRdpFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            cookie: old.cookie,
            confidence: old.confidence,
            category: old.category,
            orig_country_code: crate::util::UNRESOLVED_COUNTRY_CODE,
            resp_country_code: crate::util::UNRESOLVED_COUNTRY_CODE,
        }
    }
}

impl From<BlocklistRdpFields> for BlocklistRdpFieldsStored {
    fn from(value: BlocklistRdpFields) -> Self {
        Self {
            sensor: value.sensor,
            orig_addr: value.orig_addr,
            orig_port: value.orig_port,
            resp_addr: value.resp_addr,
            resp_port: value.resp_port,
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
            orig_country_code: crate::util::UNRESOLVED_COUNTRY_CODE,
            resp_country_code: crate::util::UNRESOLVED_COUNTRY_CODE,
        }
    }
}

impl BlocklistRdpFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);
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
            start_time_dt.to_rfc3339(),
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
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub orig_country_code: [u8; 2],
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub resp_country_code: [u8; 2],
    pub proto: u8,
    pub start_time: DateTime<Utc>,
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
            std::str::from_utf8(&self.orig_country_code).unwrap_or("XX"),
            self.resp_addr.to_string(),
            self.resp_port.to_string(),
            std::str::from_utf8(&self.resp_country_code).unwrap_or("XX"),
            self.proto.to_string(),
            self.start_time.to_rfc3339(),
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
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistRdpFieldsStored) -> Self {
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
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
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
