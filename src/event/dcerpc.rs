use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::RawEventAttrKind;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::event::common::{AttrValue, triage_scores_to_string};

pub type BlocklistDceRpcFields = BlocklistDceRpcFieldsV0_44;

#[derive(Serialize, Deserialize)]
pub struct BlocklistDceRpcFieldsV0_44 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub orig_country_code: [u8; 2],
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub resp_country_code: [u8; 2],
    pub proto: u8,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub rtt: i64,
    pub named_pipe: String,
    pub endpoint: String,
    pub operation: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl BlocklistDceRpcFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);
        format!(
            "category={:?} sensor={:?} orig_addr={:?} orig_port={:?} orig_country_code={:?} resp_addr={:?} resp_port={:?} resp_country_code={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} rtt={:?} named_pipe={:?} endpoint={:?} operation={:?} confidence={:?}",
            self.category.as_ref().map_or_else(
                || "Unspecified".to_string(),
                std::string::ToString::to_string
            ),
            self.sensor,
            self.orig_addr.to_string(),
            self.orig_port.to_string(),
            std::str::from_utf8(&self.orig_country_code).unwrap_or("XX"),
            self.resp_addr.to_string(),
            self.resp_port.to_string(),
            std::str::from_utf8(&self.resp_country_code).unwrap_or("XX"),
            self.proto.to_string(),
            start_time_dt.to_rfc3339(),
            self.duration.to_string(),
            self.orig_pkts.to_string(),
            self.resp_pkts.to_string(),
            self.orig_l2_bytes.to_string(),
            self.resp_l2_bytes.to_string(),
            self.rtt.to_string(),
            self.named_pipe,
            self.endpoint,
            self.operation,
            self.confidence.to_string()
        )
    }
}

pub struct BlocklistDceRpc {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub orig_country_code: [u8; 2],
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_country_code: [u8; 2],
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub rtt: i64,
    pub named_pipe: String,
    pub endpoint: String,
    pub operation: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlocklistDceRpc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} orig_country_code={:?} resp_addr={:?} resp_port={:?} resp_country_code={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} rtt={:?} named_pipe={:?} endpoint={:?} operation={:?} triage_scores={:?}",
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
            self.rtt.to_string(),
            self.named_pipe,
            self.endpoint,
            self.operation,
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl BlocklistDceRpc {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistDceRpcFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            orig_country_code: fields.orig_country_code,
            orig_addr: fields.orig_addr,
            orig_port: fields.orig_port,
            resp_addr: fields.resp_addr,
            resp_country_code: fields.resp_country_code,
            resp_port: fields.resp_port,
            proto: fields.proto,
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            duration: fields.duration,
            orig_pkts: fields.orig_pkts,
            resp_pkts: fields.resp_pkts,
            orig_l2_bytes: fields.orig_l2_bytes,
            resp_l2_bytes: fields.resp_l2_bytes,
            rtt: fields.rtt,
            named_pipe: fields.named_pipe,
            endpoint: fields.endpoint,
            operation: fields.operation,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistDceRpc {
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
        "blocklist dcerpc"
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

    // Since `dcerpc` is not currently an event type collected by Feature Sensor, and as a result,
    // the notation for each attribute of `dcerpc` has not been finalized. Therefore, we will
    // proceed with this part after the collection and notation of dcerpc events is finalized.
    fn find_attr_by_kind(&self, _raw_event_attr: RawEventAttrKind) -> Option<AttrValue<'_>> {
        None
    }
}
