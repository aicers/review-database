use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{NfsAttr, RawEventAttrKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::event::common::{AttrValue, triage_scores_to_string};

macro_rules! find_nfs_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {{
        if let RawEventAttrKind::Nfs(attr) = $raw_event_attr {
            let target_value = match attr {
                NfsAttr::SrcAddr => AttrValue::Addr($event.orig_addr),
                NfsAttr::SrcPort => AttrValue::UInt($event.orig_port.into()),
                NfsAttr::DstAddr => AttrValue::Addr($event.resp_addr),
                NfsAttr::DstPort => AttrValue::UInt($event.resp_port.into()),
                NfsAttr::Proto => AttrValue::UInt($event.proto.into()),
                NfsAttr::Duration => AttrValue::SInt($event.duration),
                NfsAttr::OrigPkts => AttrValue::UInt($event.orig_pkts),
                NfsAttr::RespPkts => AttrValue::UInt($event.resp_pkts),
                NfsAttr::OrigL2Bytes => AttrValue::UInt($event.orig_l2_bytes),
                NfsAttr::RespL2Bytes => AttrValue::UInt($event.resp_l2_bytes),
                NfsAttr::ReadFiles => {
                    AttrValue::VecString(std::borrow::Cow::Borrowed(&$event.read_files))
                }
                NfsAttr::WriteFiles => {
                    AttrValue::VecString(std::borrow::Cow::Borrowed(&$event.write_files))
                }
            };
            Some(target_value)
        } else {
            None
        }
    }};
}

pub type BlocklistNfsFields = BlocklistNfsFieldsV0_42;

#[derive(Serialize, Deserialize)]
pub struct BlocklistNfsFieldsV0_42 {
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
    pub read_files: Vec<String>,
    pub write_files: Vec<String>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl BlocklistNfsFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);
        format!(
            "category={:?} sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} read_files={:?} write_files={:?} confidence={:?}",
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
            self.read_files.join(","),
            self.write_files.join(","),
            self.confidence.to_string()
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct BlocklistNfs {
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
    pub read_files: Vec<String>,
    pub write_files: Vec<String>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}
impl fmt::Display for BlocklistNfs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} read_files={:?} write_files={:?} triage_scores={:?}",
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
            self.read_files.join(","),
            self.write_files.join(","),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl BlocklistNfs {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistNfsFields) -> Self {
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
            read_files: fields.read_files,
            write_files: fields.write_files,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistNfs {
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
        "blocklist nfs"
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
        find_nfs_attr_by_kind!(self, raw_event_attr)
    }
}
