use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{DnsAttr, RawEventAttrKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::event::common::{AttrValue, triage_scores_to_string};

macro_rules! find_malformed_dns_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {{
        if let RawEventAttrKind::Dns(attr) = $raw_event_attr {
            let target_value = match attr {
                DnsAttr::SrcAddr => AttrValue::Addr($event.orig_addr),
                DnsAttr::SrcPort => AttrValue::UInt($event.orig_port.into()),
                DnsAttr::DstAddr => AttrValue::Addr($event.resp_addr),
                DnsAttr::DstPort => AttrValue::UInt($event.resp_port.into()),
                DnsAttr::Proto => AttrValue::UInt($event.proto.into()),
                DnsAttr::Duration => AttrValue::SInt($event.duration),
                DnsAttr::OrigPkts => AttrValue::UInt($event.orig_pkts),
                DnsAttr::RespPkts => AttrValue::UInt($event.resp_pkts),
                DnsAttr::OrigL2Bytes => AttrValue::UInt($event.orig_l2_bytes),
                DnsAttr::RespL2Bytes => AttrValue::UInt($event.resp_l2_bytes),
                DnsAttr::TransId => AttrValue::UInt($event.trans_id.into()),
                _ => return None,
            };
            Some(target_value)
        } else {
            None
        }
    }};
}

#[derive(Serialize, Deserialize)]
pub struct BlocklistMalformedDnsFields {
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
    pub trans_id: u16,
    pub flags: u16,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
    pub query_count: u32,
    pub resp_count: u32,
    pub query_bytes: u64,
    pub resp_bytes: u64,
    pub query_body: Vec<Vec<u8>>,
    pub resp_body: Vec<Vec<u8>>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    #[serde(default)]
    pub src_country_code: Option<[u8; 2]>,
    #[serde(default)]
    pub dst_country_code: Option<[u8; 2]>,
}

impl BlocklistMalformedDnsFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);
        format!(
            "category={:?} sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} trans_id={:?} flags={:?} question_count={:?} answer_count={:?} authority_count={:?} additional_count={:?} query_count={:?} resp_count={:?} query_bytes={:?} resp_bytes={:?} query_body={:?} resp_body={:?} confidence={:?}",
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
            self.trans_id.to_string(),
            self.flags.to_string(),
            self.question_count.to_string(),
            self.answer_count.to_string(),
            self.authority_count.to_string(),
            self.additional_count.to_string(),
            self.query_count.to_string(),
            self.resp_count.to_string(),
            self.query_bytes.to_string(),
            self.resp_bytes.to_string(),
            format_vec_vec_u8(&self.query_body),
            format_vec_vec_u8(&self.resp_body),
            self.confidence.to_string(),
        )
    }
}

/// Formats a Vec<Vec<u8>> as a comma-separated list of UTF-8 strings
fn format_vec_vec_u8(data: &[Vec<u8>]) -> String {
    data.iter()
        .map(|v| String::from_utf8_lossy(v).to_string())
        .collect::<Vec<_>>()
        .join(",")
}

pub struct BlocklistMalformedDns {
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
    pub trans_id: u16,
    pub flags: u16,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
    pub query_count: u32,
    pub resp_count: u32,
    pub query_bytes: u64,
    pub resp_bytes: u64,
    pub query_body: Vec<Vec<u8>>,
    pub resp_body: Vec<Vec<u8>>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlocklistMalformedDns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let start_time_str = self.start_time.to_rfc3339();

        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} trans_id={:?} flags={:?} question_count={:?} answer_count={:?} authority_count={:?} additional_count={:?} query_count={:?} resp_count={:?} query_bytes={:?} resp_bytes={:?} query_body={:?} resp_body={:?} triage_scores={:?}",
            self.sensor,
            self.orig_addr.to_string(),
            self.orig_port.to_string(),
            self.resp_addr.to_string(),
            self.resp_port.to_string(),
            self.proto.to_string(),
            start_time_str,
            self.duration.to_string(),
            self.orig_pkts.to_string(),
            self.resp_pkts.to_string(),
            self.orig_l2_bytes.to_string(),
            self.resp_l2_bytes.to_string(),
            self.trans_id.to_string(),
            self.flags.to_string(),
            self.question_count.to_string(),
            self.answer_count.to_string(),
            self.authority_count.to_string(),
            self.additional_count.to_string(),
            self.query_count.to_string(),
            self.resp_count.to_string(),
            self.query_bytes.to_string(),
            self.resp_bytes.to_string(),
            format_vec_vec_u8(&self.query_body),
            format_vec_vec_u8(&self.resp_body),
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl BlocklistMalformedDns {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistMalformedDnsFields) -> Self {
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
            trans_id: fields.trans_id,
            flags: fields.flags,
            question_count: fields.question_count,
            answer_count: fields.answer_count,
            authority_count: fields.authority_count,
            additional_count: fields.additional_count,
            query_count: fields.query_count,
            resp_count: fields.resp_count,
            query_bytes: fields.query_bytes,
            resp_bytes: fields.resp_bytes,
            query_body: fields.query_body,
            resp_body: fields.resp_body,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistMalformedDns {
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
        "blocklist malformed dns"
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

    fn find_attr_by_kind(
        &self,
        raw_event_attr: attrievent::attribute::RawEventAttrKind,
    ) -> Option<AttrValue<'_>> {
        find_malformed_dns_attr_by_kind!(self, raw_event_attr)
    }
}
