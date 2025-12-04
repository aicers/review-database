use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{RawEventAttrKind, SmtpAttr};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::event::common::{AttrValue, triage_scores_to_string};

macro_rules! find_smtp_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {{
        if let RawEventAttrKind::Smtp(attr) = $raw_event_attr {
            let target_value = match attr {
                SmtpAttr::SrcAddr => AttrValue::Addr($event.orig_addr),
                SmtpAttr::SrcPort => AttrValue::UInt($event.orig_port.into()),
                SmtpAttr::DstAddr => AttrValue::Addr($event.resp_addr),
                SmtpAttr::DstPort => AttrValue::UInt($event.resp_port.into()),
                SmtpAttr::Proto => AttrValue::UInt($event.proto.into()),
                SmtpAttr::Duration => AttrValue::SInt($event.duration),
                SmtpAttr::OrigPkts => AttrValue::UInt($event.orig_pkts),
                SmtpAttr::RespPkts => AttrValue::UInt($event.resp_pkts),
                SmtpAttr::OrigL2Bytes => AttrValue::UInt($event.orig_l2_bytes),
                SmtpAttr::RespL2Bytes => AttrValue::UInt($event.resp_l2_bytes),
                SmtpAttr::MailFrom => AttrValue::String(&$event.mailfrom),
                SmtpAttr::Date => AttrValue::String(&$event.date),
                SmtpAttr::From => AttrValue::String(&$event.from),
                SmtpAttr::To => AttrValue::String(&$event.to),
                SmtpAttr::Subject => AttrValue::String(&$event.subject),
                SmtpAttr::Agent => AttrValue::String(&$event.agent),
                SmtpAttr::State => AttrValue::String(&$event.state),
            };
            Some(target_value)
        } else {
            None
        }
    }};
}

pub type BlocklistSmtpFields = BlocklistSmtpFieldsV0_42;

#[derive(Serialize, Deserialize)]
pub struct BlocklistSmtpFieldsV0_42 {
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
    pub mailfrom: String,
    pub date: String,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub agent: String,
    pub state: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl BlocklistSmtpFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);
        format!(
            "category={:?} sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} mailfrom={:?} date={:?} from={:?} to={:?} subject={:?} agent={:?} state={:?} confidence={:?}",
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
            self.mailfrom,
            self.date,
            self.from,
            self.to,
            self.subject,
            self.agent,
            self.state,
            self.confidence.to_string()
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct BlocklistSmtp {
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
    pub mailfrom: String,
    pub date: String,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub agent: String,
    pub state: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}
impl fmt::Display for BlocklistSmtp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} mailfrom={:?} date={:?} from={:?} to={:?} subject={:?} agent={:?} state={:?} triage_scores={:?}",
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
            self.mailfrom,
            self.date,
            self.from,
            self.to,
            self.subject,
            self.agent,
            self.state,
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl BlocklistSmtp {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistSmtpFields) -> Self {
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
            mailfrom: fields.mailfrom,
            date: fields.date,
            from: fields.from,
            to: fields.to,
            subject: fields.subject,
            agent: fields.agent,
            state: fields.state,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistSmtp {
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
        "blocklist smtp"
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
        find_smtp_attr_by_kind!(self, raw_event_attr)
    }
}
