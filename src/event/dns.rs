#![allow(clippy::module_name_repetitions, clippy::struct_excessive_bools)]
use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{DnsAttr, RawEventAttrKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, HIGH, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::{
    TriageExclusion,
    event::common::{AttrValue, triage_scores_to_string, vector_to_string},
};

macro_rules! find_dns_attr_by_kind {
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
                DnsAttr::Query => AttrValue::String(&$event.query),
                DnsAttr::Answer => AttrValue::VecString(std::borrow::Cow::Borrowed(&$event.answer)),
                DnsAttr::TransId => AttrValue::UInt($event.trans_id.into()),
                DnsAttr::Rtt => AttrValue::SInt($event.rtt),
                DnsAttr::QClass => AttrValue::UInt($event.qclass.into()),
                DnsAttr::QType => AttrValue::UInt($event.qtype.into()),
                DnsAttr::RCode => AttrValue::UInt($event.rcode.into()),
                DnsAttr::AA => AttrValue::Bool($event.aa_flag),
                DnsAttr::TC => AttrValue::Bool($event.tc_flag),
                DnsAttr::RD => AttrValue::Bool($event.rd_flag),
                DnsAttr::RA => AttrValue::Bool($event.ra_flag),
                DnsAttr::Ttl => AttrValue::VecSInt(std::borrow::Cow::Owned(
                    $event.ttl.iter().map(|val| i64::from(*val)).collect(),
                )),
            };
            Some(target_value)
        } else {
            None
        }
    }};
}

pub type DnsEventFields = DnsEventFieldsV0_44;

#[derive(Deserialize, Serialize)]
pub struct DnsEventFieldsV0_44 {
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
    pub query: String,
    pub answer: Vec<String>,
    pub trans_id: u16,
    pub rtt: i64,
    pub qclass: u16,
    pub qtype: u16,
    pub rcode: u16,
    pub aa_flag: bool,
    pub tc_flag: bool,
    pub rd_flag: bool,
    pub ra_flag: bool,
    pub ttl: Vec<i32>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl DnsEventFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);
        format!(
            "category={:?} sensor={:?} orig_addr={:?} orig_port={:?} orig_country_code={:?} resp_addr={:?} resp_port={:?} resp_country_code={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} query={:?} answer={:?} trans_id={:?} rtt={:?} qclass={:?} qtype={:?} rcode={:?} aa_flag={:?} tc_flag={:?} rd_flag={:?} ra_flag={:?} ttl={:?} confidence={:?}",
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
            self.query,
            self.answer.join(","),
            self.trans_id.to_string(),
            self.rtt.to_string(),
            self.qclass.to_string(),
            self.qtype.to_string(),
            self.rcode.to_string(),
            self.aa_flag.to_string(),
            self.tc_flag.to_string(),
            self.rd_flag.to_string(),
            self.ra_flag.to_string(),
            vector_to_string(&self.ttl),
            self.confidence.to_string(),
        )
    }
}

#[derive(Deserialize, Serialize)]
pub struct DnsCovertChannel {
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
    pub query: String,
    pub answer: Vec<String>,
    pub trans_id: u16,
    pub rtt: i64,
    pub qclass: u16,
    pub qtype: u16,
    pub rcode: u16,
    pub aa_flag: bool,
    pub tc_flag: bool,
    pub rd_flag: bool,
    pub ra_flag: bool,
    pub ttl: Vec<i32>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for DnsCovertChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} orig_country_code={:?} resp_addr={:?} resp_port={:?} resp_country_code={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} query={:?} answer={:?} trans_id={:?} rtt={:?} qclass={:?} qtype={:?} rcode={:?} aa_flag={:?} tc_flag={:?} rd_flag={:?} ra_flag={:?} ttl={:?} confidence={:?} triage_scores={:?}",
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
            self.query,
            self.answer.join(","),
            self.trans_id.to_string(),
            self.rtt.to_string(),
            self.qclass.to_string(),
            self.qtype.to_string(),
            self.rcode.to_string(),
            self.aa_flag.to_string(),
            self.tc_flag.to_string(),
            self.rd_flag.to_string(),
            self.ra_flag.to_string(),
            vector_to_string(&self.ttl),
            self.confidence.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl DnsCovertChannel {
    pub(super) fn new(time: DateTime<Utc>, fields: DnsEventFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            orig_country_code: fields.orig_country_code,
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            duration: fields.duration,
            orig_pkts: fields.orig_pkts,
            resp_pkts: fields.resp_pkts,
            orig_l2_bytes: fields.orig_l2_bytes,
            resp_l2_bytes: fields.resp_l2_bytes,
            orig_addr: fields.orig_addr,
            orig_port: fields.orig_port,
            resp_addr: fields.resp_addr,
            resp_country_code: fields.resp_country_code,
            resp_port: fields.resp_port,
            proto: fields.proto,
            query: fields.query,
            answer: fields.answer,
            trans_id: fields.trans_id,
            rtt: fields.rtt,
            qclass: fields.qclass,
            qtype: fields.qtype,
            rcode: fields.rcode,
            aa_flag: fields.aa_flag,
            tc_flag: fields.tc_flag,
            rd_flag: fields.rd_flag,
            ra_flag: fields.ra_flag,
            ttl: fields.ttl,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for DnsCovertChannel {
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
        "dns covert channel"
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
        find_dns_attr_by_kind!(self, raw_event_attr)
    }

    fn score_by_triage_exclusion(&self, triage_exclusion: &[TriageExclusion]) -> f64 {
        let matched = triage_exclusion.iter().any(|ti| match ti {
            TriageExclusion::IpAddress(filter) => self
                .src_addrs()
                .iter()
                .chain(self.dst_addrs().iter())
                .any(|&ip| filter.contains(ip)),
            TriageExclusion::Domain(regex_set) => regex_set.is_match(&self.query),
            TriageExclusion::Hostname(hostnames) => {
                let hostname = self
                    .query
                    .split_once('.')
                    .map_or(self.query.clone(), |(label, _)| label.to_string());
                hostnames.contains(&hostname)
            }
            TriageExclusion::Uri(_) => false, // DNS queries don't match URIs
        });
        if matched { f64::MIN } else { 0.0 }
    }
}

// TODO: Locky ransomware event uses same sruct with DnsCovertChannel. It can be merged.
pub struct LockyRansomware {
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
    pub query: String,
    pub answer: Vec<String>,
    pub trans_id: u16,
    pub rtt: i64,
    pub qclass: u16,
    pub qtype: u16,
    pub rcode: u16,
    pub aa_flag: bool,
    pub tc_flag: bool,
    pub rd_flag: bool,
    pub ra_flag: bool,
    pub ttl: Vec<i32>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for LockyRansomware {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} orig_country_code={:?} resp_addr={:?} resp_port={:?} resp_country_code={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} query={:?} answer={:?} trans_id={:?} rtt={:?} qclass={:?} qtype={:?} rcode={:?} aa_flag={:?} tc_flag={:?} rd_flag={:?} ra_flag={:?} ttl={:?} confidence={:?} triage_scores={:?}",
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
            self.query,
            self.answer.join(","),
            self.trans_id.to_string(),
            self.rtt.to_string(),
            self.qclass.to_string(),
            self.qtype.to_string(),
            self.rcode.to_string(),
            self.aa_flag.to_string(),
            self.tc_flag.to_string(),
            self.rd_flag.to_string(),
            self.ra_flag.to_string(),
            vector_to_string(&self.ttl),
            self.confidence.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl LockyRansomware {
    pub(super) fn new(time: DateTime<Utc>, fields: DnsEventFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            orig_country_code: fields.orig_country_code,
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            duration: fields.duration,
            orig_pkts: fields.orig_pkts,
            resp_pkts: fields.resp_pkts,
            orig_l2_bytes: fields.orig_l2_bytes,
            resp_l2_bytes: fields.resp_l2_bytes,
            orig_addr: fields.orig_addr,
            orig_port: fields.orig_port,
            resp_addr: fields.resp_addr,
            resp_country_code: fields.resp_country_code,
            resp_port: fields.resp_port,
            proto: fields.proto,
            query: fields.query,
            answer: fields.answer,
            trans_id: fields.trans_id,
            rtt: fields.rtt,
            qclass: fields.qclass,
            qtype: fields.qtype,
            rcode: fields.rcode,
            aa_flag: fields.aa_flag,
            tc_flag: fields.tc_flag,
            rd_flag: fields.rd_flag,
            ra_flag: fields.ra_flag,
            ttl: fields.ttl,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for LockyRansomware {
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
        HIGH
    }

    fn kind(&self) -> &'static str {
        "locky ransomware"
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
        find_dns_attr_by_kind!(self, raw_event_attr)
    }

    fn score_by_triage_exclusion(&self, triage_exclusion: &[TriageExclusion]) -> f64 {
        let matched = triage_exclusion.iter().any(|ti| match ti {
            TriageExclusion::IpAddress(filter) => self
                .src_addrs()
                .iter()
                .chain(self.dst_addrs().iter())
                .any(|&ip| filter.contains(ip)),
            TriageExclusion::Domain(regex_set) => regex_set.is_match(&self.query),
            TriageExclusion::Hostname(hostnames) => {
                let hostname = self
                    .query
                    .split_once('.')
                    .map_or(self.query.clone(), |(label, _)| label.to_string());
                hostnames.contains(&hostname)
            }
            TriageExclusion::Uri(_) => false, // DNS queries don't match URIs
        });
        if matched { f64::MIN } else { 0.0 }
    }
}

pub type CryptocurrencyMiningPoolFields = CryptocurrencyMiningPoolFieldsV0_44;

#[derive(Deserialize, Serialize)]
pub struct CryptocurrencyMiningPoolFieldsV0_44 {
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
    pub query: String,
    pub answer: Vec<String>,
    pub trans_id: u16,
    pub rtt: i64,
    pub qclass: u16,
    pub qtype: u16,
    pub rcode: u16,
    pub aa_flag: bool,
    pub tc_flag: bool,
    pub rd_flag: bool,
    pub ra_flag: bool,
    pub ttl: Vec<i32>,
    pub coins: Vec<String>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl CryptocurrencyMiningPoolFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);
        format!(
            "category={:?} sensor={:?} orig_addr={:?} orig_port={:?} orig_country_code={:?} resp_addr={:?} resp_port={:?} resp_country_code={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} query={:?} answer={:?} trans_id={:?} rtt={:?} qclass={:?} qtype={:?} rcode={:?} aa_flag={:?} tc_flag={:?} rd_flag={:?} ra_flag={:?} ttl={:?} coins={:?} confidence={:?}",
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
            self.query,
            self.answer.join(","),
            self.trans_id.to_string(),
            self.rtt.to_string(),
            self.qclass.to_string(),
            self.qtype.to_string(),
            self.rcode.to_string(),
            self.aa_flag.to_string(),
            self.tc_flag.to_string(),
            self.rd_flag.to_string(),
            self.ra_flag.to_string(),
            vector_to_string(&self.ttl),
            self.coins.join(","),
            self.confidence.to_string()
        )
    }
}

#[derive(Serialize, Deserialize)]
pub struct CryptocurrencyMiningPool {
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
    pub query: String,
    pub answer: Vec<String>,
    pub trans_id: u16,
    pub rtt: i64,
    pub qclass: u16,
    pub qtype: u16,
    pub rcode: u16,
    pub aa_flag: bool,
    pub tc_flag: bool,
    pub rd_flag: bool,
    pub ra_flag: bool,
    pub ttl: Vec<i32>,
    pub coins: Vec<String>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for CryptocurrencyMiningPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} orig_country_code={:?} resp_addr={:?} resp_port={:?} resp_country_code={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} query={:?} answer={:?} trans_id={:?} rtt={:?} qclass={:?} qtype={:?} rcode={:?} aa_flag={:?} tc_flag={:?} rd_flag={:?} ra_flag={:?} ttl={:?} coins={:?} triage_scores={:?}",
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
            self.query,
            self.answer.join(","),
            self.trans_id.to_string(),
            self.rtt.to_string(),
            self.qclass.to_string(),
            self.qtype.to_string(),
            self.rcode.to_string(),
            self.aa_flag.to_string(),
            self.tc_flag.to_string(),
            self.rd_flag.to_string(),
            self.ra_flag.to_string(),
            vector_to_string(&self.ttl),
            self.coins.join(","),
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl CryptocurrencyMiningPool {
    pub(super) fn new(time: DateTime<Utc>, fields: CryptocurrencyMiningPoolFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            orig_country_code: fields.orig_country_code,
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            duration: fields.duration,
            orig_pkts: fields.orig_pkts,
            resp_pkts: fields.resp_pkts,
            orig_l2_bytes: fields.orig_l2_bytes,
            resp_l2_bytes: fields.resp_l2_bytes,
            orig_addr: fields.orig_addr,
            orig_port: fields.orig_port,
            resp_addr: fields.resp_addr,
            resp_country_code: fields.resp_country_code,
            resp_port: fields.resp_port,
            proto: fields.proto,
            query: fields.query,
            answer: fields.answer,
            trans_id: fields.trans_id,
            rtt: fields.rtt,
            qclass: fields.qclass,
            qtype: fields.qtype,
            rcode: fields.rcode,
            aa_flag: fields.aa_flag,
            tc_flag: fields.tc_flag,
            rd_flag: fields.rd_flag,
            ra_flag: fields.ra_flag,
            ttl: fields.ttl,
            coins: fields.coins,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for CryptocurrencyMiningPool {
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
        "cryptocurrency mining pool"
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
        find_dns_attr_by_kind!(self, raw_event_attr)
    }

    fn score_by_triage_exclusion(&self, triage_exclusion: &[TriageExclusion]) -> f64 {
        let matched = triage_exclusion.iter().any(|ti| match ti {
            TriageExclusion::IpAddress(filter) => self
                .src_addrs()
                .iter()
                .chain(self.dst_addrs().iter())
                .any(|&ip| filter.contains(ip)),
            TriageExclusion::Domain(regex_set) => regex_set.is_match(&self.query),
            TriageExclusion::Hostname(hostnames) => {
                let hostname = self
                    .query
                    .split_once('.')
                    .map_or(self.query.clone(), |(label, _)| label.to_string());
                hostnames.contains(&hostname)
            }
            TriageExclusion::Uri(_) => false, // DNS queries don't match URIs
        });
        if matched { f64::MIN } else { 0.0 }
    }
}

pub type BlocklistDnsFields = BlocklistDnsFieldsV0_44;

#[derive(Deserialize, Serialize)]
pub struct BlocklistDnsFieldsV0_44 {
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
    pub query: String,
    pub answer: Vec<String>,
    pub trans_id: u16,
    pub rtt: i64,
    pub qclass: u16,
    pub qtype: u16,
    pub rcode: u16,
    pub aa_flag: bool,
    pub tc_flag: bool,
    pub rd_flag: bool,
    pub ra_flag: bool,
    pub ttl: Vec<i32>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl BlocklistDnsFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);
        format!(
            "category={:?} sensor={:?} orig_addr={:?} orig_port={:?} orig_country_code={:?} resp_addr={:?} resp_port={:?} resp_country_code={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} query={:?} answer={:?} trans_id={:?} rtt={:?} qclass={:?} qtype={:?} rcode={:?} aa_flag={:?} tc_flag={:?} rd_flag={:?} ra_flag={:?} ttl={:?} confidence={:?}",
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
            self.query,
            self.answer.join(","),
            self.trans_id.to_string(),
            self.rtt.to_string(),
            self.qclass.to_string(),
            self.qtype.to_string(),
            self.rcode.to_string(),
            self.aa_flag.to_string(),
            self.tc_flag.to_string(),
            self.rd_flag.to_string(),
            self.ra_flag.to_string(),
            vector_to_string(&self.ttl),
            self.confidence.to_string(),
        )
    }
}

#[derive(Serialize, Deserialize)]
pub struct BlocklistDns {
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
    pub query: String,
    pub answer: Vec<String>,
    pub trans_id: u16,
    pub rtt: i64,
    pub qclass: u16,
    pub qtype: u16,
    pub rcode: u16,
    pub aa_flag: bool,
    pub tc_flag: bool,
    pub rd_flag: bool,
    pub ra_flag: bool,
    pub ttl: Vec<i32>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlocklistDns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} orig_country_code={:?} resp_addr={:?} resp_port={:?} resp_country_code={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} query={:?} answer={:?} trans_id={:?} rtt={:?} qclass={:?} qtype={:?} rcode={:?} aa_flag={:?} tc_flag={:?} rd_flag={:?} ra_flag={:?} ttl={:?} triage_scores={:?}",
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
            self.query,
            self.answer.join(","),
            self.trans_id.to_string(),
            self.rtt.to_string(),
            self.qclass.to_string(),
            self.qtype.to_string(),
            self.rcode.to_string(),
            self.aa_flag.to_string(),
            self.tc_flag.to_string(),
            self.rd_flag.to_string(),
            self.ra_flag.to_string(),
            vector_to_string(&self.ttl),
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl BlocklistDns {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistDnsFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            orig_country_code: fields.orig_country_code,
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            orig_addr: fields.orig_addr,
            orig_port: fields.orig_port,
            resp_addr: fields.resp_addr,
            resp_country_code: fields.resp_country_code,
            resp_port: fields.resp_port,
            proto: fields.proto,
            duration: fields.duration,
            orig_pkts: fields.orig_pkts,
            resp_pkts: fields.resp_pkts,
            orig_l2_bytes: fields.orig_l2_bytes,
            resp_l2_bytes: fields.resp_l2_bytes,
            query: fields.query,
            answer: fields.answer,
            trans_id: fields.trans_id,
            rtt: fields.rtt,
            qclass: fields.qclass,
            qtype: fields.qtype,
            rcode: fields.rcode,
            aa_flag: fields.aa_flag,
            tc_flag: fields.tc_flag,
            rd_flag: fields.rd_flag,
            ra_flag: fields.ra_flag,
            ttl: fields.ttl,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistDns {
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
        "blocklist dns"
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
        find_dns_attr_by_kind!(self, raw_event_attr)
    }

    fn score_by_triage_exclusion(&self, triage_exclusion: &[TriageExclusion]) -> f64 {
        let matched = triage_exclusion.iter().any(|ti| match ti {
            TriageExclusion::IpAddress(filter) => self
                .src_addrs()
                .iter()
                .chain(self.dst_addrs().iter())
                .any(|&ip| filter.contains(ip)),
            TriageExclusion::Domain(regex_set) => regex_set.is_match(&self.query),
            TriageExclusion::Hostname(hostnames) => {
                let hostname = self
                    .query
                    .split_once('.')
                    .map_or(self.query.clone(), |(label, _)| label.to_string());
                hostnames.contains(&hostname)
            }
            TriageExclusion::Uri(_) => false, // DNS queries don't match URIs
        });
        if matched { f64::MIN } else { 0.0 }
    }
}
