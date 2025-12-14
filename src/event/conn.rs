use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{ConnAttr, RawEventAttrKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
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

pub type PortScanFields = PortScanFieldsV0_43;

#[derive(Serialize, Deserialize)]
pub struct PortScanFieldsV0_43 {
    pub sensor: String,
    pub src_country_code: Option<[u8; 2]>,
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub dst_country_code: Option<[u8; 2]>,
    pub resp_ports: Vec<u16>,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub start_time: i64,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub end_time: i64,
    pub proto: u8,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl PortScanFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);
        let end_time_dt = DateTime::from_timestamp_nanos(self.end_time);
        format!(
            "category={:?} sensor={:?} orig_addr={:?} resp_addr={:?} resp_ports={:?} start_time={:?} end_time={:?} proto={:?} confidence={:?}",
            self.category.as_ref().map_or_else(
                || "Unspecified".to_string(),
                std::string::ToString::to_string
            ),
            self.sensor,
            self.orig_addr.to_string(),
            self.resp_addr.to_string(),
            vector_to_string(&self.resp_ports),
            start_time_dt.to_rfc3339(),
            end_time_dt.to_rfc3339(),
            self.proto.to_string(),
            self.confidence.to_string()
        )
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Serialize, Deserialize)]
pub struct PortScan {
    pub sensor: String,
    pub time: DateTime<Utc>,
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub resp_ports: Vec<u16>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub proto: u8,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for PortScan {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "orig_addr={:?} resp_addr={:?} resp_ports={:?} start_time={:?} end_time={:?} proto={:?} triage_scores={:?}",
            self.orig_addr.to_string(),
            self.resp_addr.to_string(),
            vector_to_string(&self.resp_ports),
            self.start_time.to_rfc3339(),
            self.end_time.to_rfc3339(),
            self.proto.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl PortScan {
    pub(super) fn new(time: DateTime<Utc>, fields: &PortScanFields) -> Self {
        PortScan {
            sensor: fields.sensor.clone(),
            time,
            orig_addr: fields.orig_addr,
            resp_addr: fields.resp_addr,
            resp_ports: fields.resp_ports.clone(),
            proto: fields.proto,
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            end_time: DateTime::from_timestamp_nanos(fields.end_time),
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for PortScan {
    fn src_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.orig_addr)
    }

    fn src_port(&self) -> u16 {
        0
    }

    fn dst_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.resp_addr)
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

    fn level(&self) -> NonZeroU8 {
        MEDIUM
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

pub type MultiHostPortScanFields = MultiHostPortScanFieldsV0_43;

#[derive(Serialize, Deserialize)]
pub struct MultiHostPortScanFieldsV0_43 {
    pub sensor: String,
    pub src_country_code: Option<[u8; 2]>,
    pub orig_addr: IpAddr,
    pub resp_port: u16,
    pub resp_addrs: Vec<IpAddr>,
    pub dst_country_codes: Vec<Option<[u8; 2]>>,
    pub proto: u8,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub start_time: i64,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub end_time: i64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl MultiHostPortScanFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);
        let end_time_dt = DateTime::from_timestamp_nanos(self.end_time);
        format!(
            "category={:?} sensor={:?} orig_addr={:?} resp_addrs={:?} resp_port={:?} proto={:?} start_time={:?} end_time={:?} confidence={:?}",
            self.category.as_ref().map_or_else(
                || "Unspecified".to_string(),
                std::string::ToString::to_string
            ),
            self.sensor,
            self.orig_addr.to_string(),
            vector_to_string(&self.resp_addrs),
            self.resp_port.to_string(),
            self.proto.to_string(),
            start_time_dt.to_rfc3339(),
            end_time_dt.to_rfc3339(),
            self.confidence.to_string()
        )
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Serialize, Deserialize)]
pub struct MultiHostPortScan {
    pub sensor: String,
    pub time: DateTime<Utc>,
    pub orig_addr: IpAddr,
    pub resp_port: u16,
    pub resp_addrs: Vec<IpAddr>,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for MultiHostPortScan {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "orig_addr={:?} resp_addrs={:?} resp_port={:?} proto={:?} start_time={:?} end_time={:?} triage_scores={:?}",
            self.orig_addr.to_string(),
            vector_to_string(&self.resp_addrs),
            self.resp_port.to_string(),
            self.proto.to_string(),
            self.start_time.to_rfc3339(),
            self.end_time.to_rfc3339(),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl MultiHostPortScan {
    pub(super) fn new(time: DateTime<Utc>, fields: &MultiHostPortScanFields) -> Self {
        MultiHostPortScan {
            sensor: fields.sensor.clone(),
            time,
            orig_addr: fields.orig_addr,
            resp_port: fields.resp_port,
            resp_addrs: fields.resp_addrs.clone(),
            proto: fields.proto,
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            end_time: DateTime::from_timestamp_nanos(fields.end_time),
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for MultiHostPortScan {
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
        self.resp_port
    }

    fn proto(&self) -> u8 {
        self.proto
    }

    fn category(&self) -> Option<EventCategory> {
        self.category
    }

    fn level(&self) -> NonZeroU8 {
        MEDIUM
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

pub type ExternalDdosFields = ExternalDdosFieldsV0_43;

#[derive(Serialize, Deserialize)]
pub struct ExternalDdosFieldsV0_43 {
    pub sensor: String,
    pub orig_addrs: Vec<IpAddr>,
    pub src_country_codes: Vec<Option<[u8; 2]>>,
    pub resp_addr: IpAddr,
    pub dst_country_code: Option<[u8; 2]>,
    pub proto: u8,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub start_time: i64,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub end_time: i64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl ExternalDdosFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);
        let end_time_dt = DateTime::from_timestamp_nanos(self.end_time);
        format!(
            "category={:?} sensor={:?} orig_addrs={:?} resp_addr={:?} proto={:?} start_time={:?} end_time={:?} confidence={:?}",
            self.category.as_ref().map_or_else(
                || "Unspecified".to_string(),
                std::string::ToString::to_string
            ),
            self.sensor,
            vector_to_string(&self.orig_addrs),
            self.resp_addr.to_string(),
            self.proto.to_string(),
            start_time_dt.to_rfc3339(),
            end_time_dt.to_rfc3339(),
            self.confidence.to_string()
        )
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Serialize, Deserialize)]
pub struct ExternalDdos {
    pub sensor: String,
    pub time: DateTime<Utc>,
    pub orig_addrs: Vec<IpAddr>,
    pub resp_addr: IpAddr,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for ExternalDdos {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "orig_addrs={:?} resp_addr={:?} proto={:?} start_time={:?} end_time={:?} triage_scores={:?}",
            vector_to_string(&self.orig_addrs),
            self.resp_addr.to_string(),
            self.proto.to_string(),
            self.start_time.to_rfc3339(),
            self.end_time.to_rfc3339(),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl ExternalDdos {
    pub(super) fn new(time: DateTime<Utc>, fields: &ExternalDdosFields) -> Self {
        ExternalDdos {
            sensor: fields.sensor.clone(),
            time,
            orig_addrs: fields.orig_addrs.clone(),
            resp_addr: fields.resp_addr,
            proto: fields.proto,
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            end_time: DateTime::from_timestamp_nanos(fields.end_time),
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for ExternalDdos {
    fn src_addrs(&self) -> &[IpAddr] {
        &self.orig_addrs
    }

    fn src_port(&self) -> u16 {
        0
    }

    fn dst_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.resp_addr)
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

    fn level(&self) -> NonZeroU8 {
        MEDIUM
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

pub type BlocklistConnFields = BlocklistConnFieldsV0_43;

#[derive(Deserialize, Serialize)]
pub struct BlocklistConnFieldsV0_43 {
    pub sensor: String,
    pub src_country_code: Option<[u8; 2]>,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub dst_country_code: Option<[u8; 2]>,
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
    pub time: DateTime<Utc>,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub conn_state: String,
    pub start_time: DateTime<Utc>,
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
            "sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} conn_state={:?} start_time={:?} duration={:?} service={:?} orig_bytes={:?} resp_bytes={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} triage_scores={:?}",
            self.sensor,
            self.orig_addr.to_string(),
            self.orig_port.to_string(),
            self.resp_addr.to_string(),
            self.resp_port.to_string(),
            self.proto.to_string(),
            self.conn_state,
            self.start_time.to_rfc3339(),
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
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistConnFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            orig_addr: fields.orig_addr,
            orig_port: fields.orig_port,
            resp_addr: fields.resp_addr,
            resp_port: fields.resp_port,
            proto: fields.proto,
            conn_state: fields.conn_state,
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
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

impl Match for BlocklistConn {
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

    fn level(&self) -> NonZeroU8 {
        MEDIUM
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
