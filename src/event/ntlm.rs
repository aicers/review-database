use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{NtlmAttr, RawEventAttrKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::event::common::{AttrValue, triage_scores_to_string};

macro_rules! find_ntlm_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {{
        if let RawEventAttrKind::Ntlm(attr) = $raw_event_attr {
            let target_value = match attr {
                NtlmAttr::SrcAddr => AttrValue::Addr($event.orig_addr),
                NtlmAttr::SrcPort => AttrValue::UInt($event.orig_port.into()),
                NtlmAttr::DstAddr => AttrValue::Addr($event.resp_addr),
                NtlmAttr::DstPort => AttrValue::UInt($event.resp_port.into()),
                NtlmAttr::Proto => AttrValue::UInt($event.proto.into()),
                NtlmAttr::Duration => AttrValue::SInt($event.duration),
                NtlmAttr::OrigPkts => AttrValue::UInt($event.orig_pkts),
                NtlmAttr::RespPkts => AttrValue::UInt($event.resp_pkts),
                NtlmAttr::OrigL2Bytes => AttrValue::UInt($event.orig_l2_bytes),
                NtlmAttr::RespL2Bytes => AttrValue::UInt($event.resp_l2_bytes),
                NtlmAttr::Protocol => AttrValue::String(&$event.protocol),
                NtlmAttr::Username => AttrValue::String(&$event.username),
                NtlmAttr::Hostname => AttrValue::String(&$event.hostname),
                NtlmAttr::Domainname => AttrValue::String(&$event.domainname),
                NtlmAttr::Success => AttrValue::String(&$event.success),
            };
            Some(target_value)
        } else {
            None
        }
    }};
}

pub type BlocklistNtlmFields = BlocklistNtlmFieldsV0_42;

#[derive(Serialize, Deserialize)]
pub struct BlocklistNtlmFieldsV0_42 {
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
    pub protocol: String,
    pub username: String,
    pub hostname: String,
    pub domainname: String,
    pub success: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl BlocklistNtlmFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);
        format!(
            "category={:?} sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} protocol={:?} username={:?} hostname={:?} domainname={:?} success={:?} confidence={:?}",
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
            self.protocol,
            self.username,
            self.hostname,
            self.domainname,
            self.success,
            self.confidence.to_string(),
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct BlocklistNtlm {
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
    pub protocol: String,
    pub username: String,
    pub hostname: String,
    pub domainname: String,
    pub success: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}
impl fmt::Display for BlocklistNtlm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} protocol={:?} username={:?} hostname={:?} domainname={:?} success={:?} triage_scores={:?}",
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
            self.protocol,
            self.username,
            self.hostname,
            self.domainname,
            self.success,
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}
impl BlocklistNtlm {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistNtlmFields) -> Self {
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
            protocol: fields.protocol,
            username: fields.username,
            hostname: fields.hostname,
            domainname: fields.domainname,
            success: fields.success,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistNtlm {
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
        "blocklist ntlm"
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
        find_ntlm_attr_by_kind!(self, raw_event_attr)
    }
}
