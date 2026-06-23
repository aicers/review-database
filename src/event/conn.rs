use std::{fmt, net::IpAddr};

use attrievent::attribute::{ConnAttr, RawEventAttrKind};
use chrono::DateTime;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use super::timestamp::{self, ts_nanoseconds as jiff_ts_nanoseconds};
use super::{EventCategory, LearningMethod, ThreatLevel, TriageScore, common::Match};
use crate::event::common::{AttrValue, triage_scores_to_string, vector_to_string};

#[macro_export]
macro_rules! find_conn_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {{
        if let RawEventAttrKind::Conn(attr) = $raw_event_attr {
            let target_value = match attr {
                ConnAttr::SrcAddr => AttrValue::Addr($event.orig_addr),
                ConnAttr::SrcPort => AttrValue::UInt($event.orig_port.into()),
                ConnAttr::DstAddr => AttrValue::Addr($event.resp_addr),
                ConnAttr::DstPort => AttrValue::UInt($event.resp_port.into()),
                ConnAttr::Proto => AttrValue::UInt($event.proto.into()),
                ConnAttr::ConnState => AttrValue::String(&$event.conn_state),
                ConnAttr::Duration => AttrValue::SInt($event.duration),
                ConnAttr::Service => AttrValue::String(&$event.service),
                ConnAttr::OrigBytes => AttrValue::UInt($event.orig_bytes),
                ConnAttr::RespBytes => AttrValue::UInt($event.resp_bytes),
                ConnAttr::OrigPkts => AttrValue::UInt($event.orig_pkts),
                ConnAttr::RespPkts => AttrValue::UInt($event.resp_pkts),
                ConnAttr::OrigL2Bytes => AttrValue::UInt($event.orig_l2_bytes),
                ConnAttr::RespL2Bytes => AttrValue::UInt($event.resp_l2_bytes),
            };
            Some(target_value)
        } else {
            None
        }
    }};
}
pub(crate) use find_conn_attr_by_kind;

#[derive(Serialize, Deserialize)]
pub struct PortScanFields {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub resp_ports: Vec<u16>,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub first_event_start_time: i64,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub last_event_start_time: i64,
    pub proto: u8,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

pub(crate) type PortScanFieldsStored = PortScanFieldsStoredV0_46;

#[derive(Deserialize, Serialize)]
pub(crate) struct PortScanFieldsStoredV0_46 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_country_code: [u8; 2],
    pub resp_addr: IpAddr,
    pub resp_ports: Vec<u16>,
    pub resp_country_code: [u8; 2],
    pub first_event_start_time: i64,
    pub last_event_start_time: i64,
    pub proto: u8,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl From<PortScanFields> for PortScanFieldsStored {
    fn from(value: PortScanFields) -> Self {
        Self {
            sensor: value.sensor,
            orig_addr: value.orig_addr,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: value.resp_addr,
            resp_ports: value.resp_ports,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            first_event_start_time: value.first_event_start_time,
            last_event_start_time: value.last_event_start_time,
            proto: value.proto,
            confidence: value.confidence,
            category: value.category,
        }
    }
}

impl PortScanFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let first_event_start_time_dt = DateTime::from_timestamp_nanos(self.first_event_start_time);
        let last_event_start_time_dt = DateTime::from_timestamp_nanos(self.last_event_start_time);
        format!(
            "category={:?} sensor={:?} orig_addr={:?} resp_addr={:?} resp_ports={:?} first_event_start_time={:?} last_event_start_time={:?} proto={:?} confidence={:?}",
            self.category.as_ref().map_or_else(
                || "Unspecified".to_string(),
                std::string::ToString::to_string
            ),
            self.sensor,
            self.orig_addr.to_string(),
            self.resp_addr.to_string(),
            vector_to_string(&self.resp_ports),
            first_event_start_time_dt.to_rfc3339(),
            last_event_start_time_dt.to_rfc3339(),
            self.proto.to_string(),
            self.confidence.to_string()
        )
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Serialize, Deserialize)]
pub struct PortScan {
    pub sensor: String,
    #[serde(with = "jiff_ts_nanoseconds")]
    pub time: Timestamp,
    pub orig_addr: IpAddr,
    pub orig_country_code: [u8; 2],
    pub resp_addr: IpAddr,
    pub resp_ports: Vec<u16>,
    pub resp_country_code: [u8; 2],
    #[serde(with = "jiff_ts_nanoseconds")]
    pub first_event_start_time: Timestamp,
    #[serde(with = "jiff_ts_nanoseconds")]
    pub last_event_start_time: Timestamp,
    pub proto: u8,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for PortScan {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "orig_addr={:?} orig_country_code={:?} resp_addr={:?} resp_country_code={:?} resp_ports={:?} first_event_start_time={:?} last_event_start_time={:?} proto={:?} triage_scores={:?}",
            self.orig_addr.to_string(),
            crate::util::country_code_as_str(&self.orig_country_code),
            self.resp_addr.to_string(),
            crate::util::country_code_as_str(&self.resp_country_code),
            vector_to_string(&self.resp_ports),
            timestamp::format_rfc3339(self.first_event_start_time).unwrap_or_default(),
            timestamp::format_rfc3339(self.last_event_start_time).unwrap_or_default(),
            self.proto.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl PortScan {
    pub(super) fn new(time: Timestamp, fields: &PortScanFieldsStored) -> Self {
        PortScan {
            sensor: fields.sensor.clone(),
            time,
            orig_addr: fields.orig_addr,
            orig_country_code: fields.orig_country_code,
            resp_addr: fields.resp_addr,
            resp_ports: fields.resp_ports.clone(),
            resp_country_code: fields.resp_country_code,
            proto: fields.proto,
            first_event_start_time: timestamp::from_i64_nanos(fields.first_event_start_time)
                .expect(timestamp::I64_NANOS_JIFF_INVARIANT),
            last_event_start_time: timestamp::from_i64_nanos(fields.last_event_start_time)
                .expect(timestamp::I64_NANOS_JIFF_INVARIANT),
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl PortScan {
    #[must_use]
    pub fn threat_level() -> ThreatLevel {
        ThreatLevel::Medium
    }
}

impl Match for PortScan {
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
        std::slice::from_ref(&self.resp_addr)
    }

    fn resp_port(&self) -> u16 {
        0
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
        "port scan"
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
        if let RawEventAttrKind::Conn(attr) = raw_event_attr {
            match attr {
                ConnAttr::SrcAddr => Some(AttrValue::Addr(self.orig_addr)),
                ConnAttr::DstAddr => Some(AttrValue::Addr(self.resp_addr)),
                ConnAttr::DstPort => Some(AttrValue::VecUInt(std::borrow::Cow::Owned(
                    self.resp_ports.iter().map(|val| u64::from(*val)).collect(),
                ))),
                ConnAttr::Proto => Some(AttrValue::UInt(self.proto.into())),
                _ => None,
            }
        } else {
            None
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct MultiHostPortScanFields {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub resp_port: u16,
    pub resp_addrs: Vec<IpAddr>,
    pub proto: u8,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub first_event_start_time: i64,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub last_event_start_time: i64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

pub(crate) type MultiHostPortScanFieldsStored = MultiHostPortScanFieldsStoredV0_46;

#[derive(Deserialize, Serialize)]
pub(crate) struct MultiHostPortScanFieldsStoredV0_46 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_country_code: [u8; 2],
    pub resp_addrs: Vec<IpAddr>,
    pub resp_port: u16,
    pub resp_country_codes: Vec<[u8; 2]>,
    pub proto: u8,
    pub first_event_start_time: i64,
    pub last_event_start_time: i64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl From<MultiHostPortScanFields> for MultiHostPortScanFieldsStored {
    fn from(value: MultiHostPortScanFields) -> Self {
        let resp_addr_count = value.resp_addrs.len();
        Self {
            sensor: value.sensor,
            orig_addr: value.orig_addr,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addrs: value.resp_addrs,
            resp_port: value.resp_port,
            resp_country_codes: vec![crate::util::COUNTRY_CODE_PENDING; resp_addr_count],
            proto: value.proto,
            first_event_start_time: value.first_event_start_time,
            last_event_start_time: value.last_event_start_time,
            confidence: value.confidence,
            category: value.category,
        }
    }
}

impl MultiHostPortScanFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let first_event_start_time_dt = DateTime::from_timestamp_nanos(self.first_event_start_time);
        let last_event_start_time_dt = DateTime::from_timestamp_nanos(self.last_event_start_time);
        format!(
            "category={:?} sensor={:?} orig_addr={:?} resp_addrs={:?} resp_port={:?} proto={:?} first_event_start_time={:?} last_event_start_time={:?} confidence={:?}",
            self.category.as_ref().map_or_else(
                || "Unspecified".to_string(),
                std::string::ToString::to_string
            ),
            self.sensor,
            self.orig_addr.to_string(),
            vector_to_string(&self.resp_addrs),
            self.resp_port.to_string(),
            self.proto.to_string(),
            first_event_start_time_dt.to_rfc3339(),
            last_event_start_time_dt.to_rfc3339(),
            self.confidence.to_string()
        )
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Serialize, Deserialize)]
pub struct MultiHostPortScan {
    pub sensor: String,
    #[serde(with = "jiff_ts_nanoseconds")]
    pub time: Timestamp,
    pub orig_addr: IpAddr,
    pub orig_country_code: [u8; 2],
    pub resp_addrs: Vec<IpAddr>,
    pub resp_port: u16,
    pub resp_country_codes: Vec<[u8; 2]>,
    pub proto: u8,
    #[serde(with = "jiff_ts_nanoseconds")]
    pub first_event_start_time: Timestamp,
    #[serde(with = "jiff_ts_nanoseconds")]
    pub last_event_start_time: Timestamp,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for MultiHostPortScan {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "orig_addr={:?} orig_country_code={:?} resp_addrs={:?} resp_port={:?} resp_country_codes={:?} proto={:?} first_event_start_time={:?} last_event_start_time={:?} triage_scores={:?}",
            self.orig_addr.to_string(),
            crate::util::country_code_as_str(&self.orig_country_code),
            vector_to_string(&self.resp_addrs),
            self.resp_port.to_string(),
            crate::util::country_codes_to_string(&self.resp_country_codes),
            self.proto.to_string(),
            timestamp::format_rfc3339(self.first_event_start_time).unwrap_or_default(),
            timestamp::format_rfc3339(self.last_event_start_time).unwrap_or_default(),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl MultiHostPortScan {
    pub(super) fn new(time: Timestamp, fields: &MultiHostPortScanFieldsStored) -> Self {
        MultiHostPortScan {
            sensor: fields.sensor.clone(),
            time,
            orig_addr: fields.orig_addr,
            orig_country_code: fields.orig_country_code,
            resp_addrs: fields.resp_addrs.clone(),
            resp_port: fields.resp_port,
            resp_country_codes: fields.resp_country_codes.clone(),
            proto: fields.proto,
            first_event_start_time: timestamp::from_i64_nanos(fields.first_event_start_time)
                .expect(timestamp::I64_NANOS_JIFF_INVARIANT),
            last_event_start_time: timestamp::from_i64_nanos(fields.last_event_start_time)
                .expect(timestamp::I64_NANOS_JIFF_INVARIANT),
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl MultiHostPortScan {
    #[must_use]
    pub fn threat_level() -> ThreatLevel {
        ThreatLevel::Medium
    }
}

impl Match for MultiHostPortScan {
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
        self.resp_port
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
        "multi host port scan"
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
        if let RawEventAttrKind::Conn(attr) = raw_event_attr {
            match attr {
                ConnAttr::SrcAddr => Some(AttrValue::Addr(self.orig_addr)),
                ConnAttr::DstPort => Some(AttrValue::UInt(self.resp_port.into())),
                ConnAttr::DstAddr => Some(AttrValue::VecAddr(std::borrow::Cow::Borrowed(
                    &self.resp_addrs,
                ))),
                ConnAttr::Proto => Some(AttrValue::UInt(self.proto.into())),
                _ => None,
            }
        } else {
            None
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ExternalDdosFields {
    pub sensor: String,
    pub orig_addrs: Vec<IpAddr>,
    pub resp_addr: IpAddr,
    pub proto: u8,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub first_event_start_time: i64,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub last_event_start_time: i64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

pub(crate) type ExternalDdosFieldsStored = ExternalDdosFieldsStoredV0_46;

#[derive(Deserialize, Serialize)]
pub(crate) struct ExternalDdosFieldsStoredV0_46 {
    pub sensor: String,
    pub orig_addrs: Vec<IpAddr>,
    pub orig_country_codes: Vec<[u8; 2]>,
    pub resp_addr: IpAddr,
    pub resp_country_code: [u8; 2],
    pub proto: u8,
    pub first_event_start_time: i64,
    pub last_event_start_time: i64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl From<ExternalDdosFields> for ExternalDdosFieldsStored {
    fn from(value: ExternalDdosFields) -> Self {
        let orig_addr_count = value.orig_addrs.len();
        Self {
            sensor: value.sensor,
            orig_addrs: value.orig_addrs,
            orig_country_codes: vec![crate::util::COUNTRY_CODE_PENDING; orig_addr_count],
            resp_addr: value.resp_addr,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: value.proto,
            first_event_start_time: value.first_event_start_time,
            last_event_start_time: value.last_event_start_time,
            confidence: value.confidence,
            category: value.category,
        }
    }
}

impl ExternalDdosFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let first_event_start_time_dt = DateTime::from_timestamp_nanos(self.first_event_start_time);
        let last_event_start_time_dt = DateTime::from_timestamp_nanos(self.last_event_start_time);
        format!(
            "category={:?} sensor={:?} orig_addrs={:?} resp_addr={:?} proto={:?} first_event_start_time={:?} last_event_start_time={:?} confidence={:?}",
            self.category.as_ref().map_or_else(
                || "Unspecified".to_string(),
                std::string::ToString::to_string
            ),
            self.sensor,
            vector_to_string(&self.orig_addrs),
            self.resp_addr.to_string(),
            self.proto.to_string(),
            first_event_start_time_dt.to_rfc3339(),
            last_event_start_time_dt.to_rfc3339(),
            self.confidence.to_string()
        )
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Serialize, Deserialize)]
pub struct ExternalDdos {
    pub sensor: String,
    #[serde(with = "jiff_ts_nanoseconds")]
    pub time: Timestamp,
    pub orig_addrs: Vec<IpAddr>,
    pub orig_country_codes: Vec<[u8; 2]>,
    pub resp_addr: IpAddr,
    pub resp_country_code: [u8; 2],
    pub proto: u8,
    #[serde(with = "jiff_ts_nanoseconds")]
    pub first_event_start_time: Timestamp,
    #[serde(with = "jiff_ts_nanoseconds")]
    pub last_event_start_time: Timestamp,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for ExternalDdos {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "orig_addrs={:?} orig_country_codes={:?} resp_addr={:?} resp_country_code={:?} proto={:?} first_event_start_time={:?} last_event_start_time={:?} triage_scores={:?}",
            vector_to_string(&self.orig_addrs),
            crate::util::country_codes_to_string(&self.orig_country_codes),
            self.resp_addr.to_string(),
            crate::util::country_code_as_str(&self.resp_country_code),
            self.proto.to_string(),
            timestamp::format_rfc3339(self.first_event_start_time).unwrap_or_default(),
            timestamp::format_rfc3339(self.last_event_start_time).unwrap_or_default(),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl ExternalDdos {
    pub(super) fn new(time: Timestamp, fields: &ExternalDdosFieldsStored) -> Self {
        ExternalDdos {
            sensor: fields.sensor.clone(),
            time,
            orig_addrs: fields.orig_addrs.clone(),
            orig_country_codes: fields.orig_country_codes.clone(),
            resp_addr: fields.resp_addr,
            resp_country_code: fields.resp_country_code,
            proto: fields.proto,
            first_event_start_time: timestamp::from_i64_nanos(fields.first_event_start_time)
                .expect(timestamp::I64_NANOS_JIFF_INVARIANT),
            last_event_start_time: timestamp::from_i64_nanos(fields.last_event_start_time)
                .expect(timestamp::I64_NANOS_JIFF_INVARIANT),
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl ExternalDdos {
    #[must_use]
    pub fn threat_level() -> ThreatLevel {
        ThreatLevel::Medium
    }
}

impl Match for ExternalDdos {
    fn orig_addrs(&self) -> &[IpAddr] {
        &self.orig_addrs
    }

    fn orig_port(&self) -> u16 {
        0
    }

    fn orig_country_codes(&self) -> &[[u8; 2]] {
        &self.orig_country_codes
    }

    fn resp_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.resp_addr)
    }

    fn resp_port(&self) -> u16 {
        0
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
        "external ddos"
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
        if let RawEventAttrKind::Conn(attr) = raw_event_attr {
            match attr {
                ConnAttr::SrcAddr => Some(AttrValue::VecAddr(std::borrow::Cow::Borrowed(
                    &self.orig_addrs,
                ))),
                ConnAttr::DstAddr => Some(AttrValue::Addr(self.resp_addr)),
                ConnAttr::Proto => Some(AttrValue::UInt(self.proto.into())),
                _ => None,
            }
        } else {
            None
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct BlocklistConnFields {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub conn_state: String,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub start_time: i64,
    pub duration: i64,
    pub service: String,
    pub orig_bytes: u64,
    pub resp_bytes: u64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

pub(crate) type BlocklistConnFieldsStored = BlocklistConnFieldsStoredV0_46;

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistConnFieldsStoredV0_46 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub orig_country_code: [u8; 2],
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub resp_country_code: [u8; 2],
    pub proto: u8,
    pub conn_state: String,
    pub start_time: i64,
    pub duration: i64,
    pub service: String,
    pub orig_bytes: u64,
    pub resp_bytes: u64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl From<BlocklistConnFields> for BlocklistConnFieldsStored {
    fn from(value: BlocklistConnFields) -> Self {
        Self {
            sensor: value.sensor,
            orig_addr: value.orig_addr,
            orig_port: value.orig_port,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: value.resp_addr,
            resp_port: value.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: value.proto,
            conn_state: value.conn_state,
            start_time: value.start_time,
            duration: value.duration,
            service: value.service,
            orig_bytes: value.orig_bytes,
            resp_bytes: value.resp_bytes,
            orig_pkts: value.orig_pkts,
            resp_pkts: value.resp_pkts,
            orig_l2_bytes: value.orig_l2_bytes,
            resp_l2_bytes: value.resp_l2_bytes,
            confidence: value.confidence,
            category: value.category,
        }
    }
}

impl BlocklistConnFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);

        format!(
            "category={:?} sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} conn_state={:?} start_time={:?} duration={:?} service={:?} orig_bytes={:?} resp_bytes={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} confidence={:?}",
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
            self.conn_state,
            start_time_dt.to_rfc3339(),
            self.duration.to_string(),
            self.service,
            self.orig_bytes.to_string(),
            self.resp_bytes.to_string(),
            self.orig_pkts.to_string(),
            self.resp_pkts.to_string(),
            self.orig_l2_bytes.to_string(),
            self.resp_l2_bytes.to_string(),
            self.confidence.to_string(),
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct BlocklistConn {
    pub sensor: String,
    pub time: Timestamp,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub orig_country_code: [u8; 2],
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub resp_country_code: [u8; 2],
    pub proto: u8,
    pub conn_state: String,
    pub start_time: Timestamp,
    pub duration: i64,
    pub service: String,
    pub orig_bytes: u64,
    pub resp_bytes: u64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlocklistConn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} orig_country_code={:?} resp_addr={:?} resp_port={:?} resp_country_code={:?} proto={:?} conn_state={:?} start_time={:?} duration={:?} service={:?} orig_bytes={:?} resp_bytes={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} triage_scores={:?}",
            self.sensor,
            self.orig_addr.to_string(),
            self.orig_port.to_string(),
            crate::util::country_code_as_str(&self.orig_country_code),
            self.resp_addr.to_string(),
            self.resp_port.to_string(),
            crate::util::country_code_as_str(&self.resp_country_code),
            self.proto.to_string(),
            self.conn_state,
            timestamp::format_rfc3339(self.start_time).unwrap_or_default(),
            self.duration.to_string(),
            self.service,
            self.orig_bytes.to_string(),
            self.resp_bytes.to_string(),
            self.orig_pkts.to_string(),
            self.resp_pkts.to_string(),
            self.orig_l2_bytes.to_string(),
            self.resp_l2_bytes.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl BlocklistConn {
    pub(super) fn new(time: Timestamp, fields: BlocklistConnFieldsStored) -> Self {
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
            conn_state: fields.conn_state,
            start_time: timestamp::from_i64_nanos(fields.start_time)
                .expect(timestamp::I64_NANOS_JIFF_INVARIANT),
            duration: fields.duration,
            service: fields.service,
            orig_bytes: fields.orig_bytes,
            resp_bytes: fields.resp_bytes,
            orig_pkts: fields.orig_pkts,
            resp_pkts: fields.resp_pkts,
            orig_l2_bytes: fields.orig_l2_bytes,
            resp_l2_bytes: fields.resp_l2_bytes,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl BlocklistConn {
    #[must_use]
    pub fn threat_level() -> ThreatLevel {
        ThreatLevel::Medium
    }
}

impl Match for BlocklistConn {
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
        "blocklist conn"
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
        find_conn_attr_by_kind!(self, raw_event_attr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct PortScanFieldsLegacy {
        sensor: String,
        orig_addr: IpAddr,
        resp_addr: IpAddr,
        resp_ports: Vec<u16>,
        start_time: i64,
        end_time: i64,
        proto: u8,
        confidence: f32,
        category: Option<EventCategory>,
    }

    #[derive(Serialize)]
    struct MultiHostPortScanFieldsLegacy {
        sensor: String,
        orig_addr: IpAddr,
        resp_port: u16,
        resp_addrs: Vec<IpAddr>,
        proto: u8,
        start_time: i64,
        end_time: i64,
        confidence: f32,
        category: Option<EventCategory>,
    }

    #[derive(Serialize)]
    struct ExternalDdosFieldsLegacy {
        sensor: String,
        orig_addrs: Vec<IpAddr>,
        resp_addr: IpAddr,
        proto: u8,
        start_time: i64,
        end_time: i64,
        confidence: f32,
        category: Option<EventCategory>,
    }

    #[test]
    fn port_scan_bincode_compatibility() {
        let old = PortScanFieldsLegacy {
            sensor: "sensor".to_string(),
            orig_addr: IpAddr::from([127, 0, 0, 1]),
            resp_addr: IpAddr::from([127, 0, 0, 2]),
            resp_ports: vec![80, 443],
            start_time: 11,
            end_time: 22,
            proto: 6,
            confidence: 0.3,
            category: Some(EventCategory::Reconnaissance),
        };
        let bytes = bincode::serialize(&old).expect("legacy fields should serialize");
        let parsed: PortScanFields =
            bincode::deserialize(&bytes).expect("new fields should deserialize");
        assert_eq!(parsed.first_event_start_time, 11);
        assert_eq!(parsed.last_event_start_time, 22);
    }

    #[test]
    fn multi_host_port_scan_bincode_compatibility() {
        let old = MultiHostPortScanFieldsLegacy {
            sensor: "sensor".to_string(),
            orig_addr: IpAddr::from([127, 0, 0, 1]),
            resp_port: 80,
            resp_addrs: vec![IpAddr::from([127, 0, 0, 2])],
            proto: 6,
            start_time: 33,
            end_time: 44,
            confidence: 0.3,
            category: Some(EventCategory::Reconnaissance),
        };
        let bytes = bincode::serialize(&old).expect("legacy fields should serialize");
        let parsed: MultiHostPortScanFields =
            bincode::deserialize(&bytes).expect("new fields should deserialize");
        assert_eq!(parsed.first_event_start_time, 33);
        assert_eq!(parsed.last_event_start_time, 44);
    }

    #[test]
    fn external_ddos_bincode_compatibility() {
        let old = ExternalDdosFieldsLegacy {
            sensor: "sensor".to_string(),
            orig_addrs: vec![IpAddr::from([127, 0, 0, 2])],
            resp_addr: IpAddr::from([127, 0, 0, 1]),
            proto: 6,
            start_time: 55,
            end_time: 66,
            confidence: 0.3,
            category: Some(EventCategory::Impact),
        };
        let bytes = bincode::serialize(&old).expect("legacy fields should serialize");
        let parsed: ExternalDdosFields =
            bincode::deserialize(&bytes).expect("new fields should deserialize");
        assert_eq!(parsed.first_event_start_time, 55);
        assert_eq!(parsed.last_event_start_time, 66);
    }
}
