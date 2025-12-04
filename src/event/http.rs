use std::{fmt, net::IpAddr, num::NonZeroU8};

use aho_corasick::AhoCorasickBuilder;
use attrievent::attribute::{HttpAttr, RawEventAttrKind};
use chrono::{DateTime, Utc, serde::ts_nanoseconds};
use serde::{Deserialize, Serialize};

use super::{EventCategory, EventFilter, LOW, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::{
    TriageExclusion,
    event::common::{AttrValue, triage_scores_to_string},
};

macro_rules! find_http_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {
        if let RawEventAttrKind::Http(attr) = $raw_event_attr {
            match attr {
                HttpAttr::SrcAddr => Some(AttrValue::Addr($event.orig_addr)),
                HttpAttr::SrcPort => Some(AttrValue::UInt($event.orig_port.into())),
                HttpAttr::DstAddr => Some(AttrValue::Addr($event.resp_addr)),
                HttpAttr::DstPort => Some(AttrValue::UInt($event.resp_port.into())),
                HttpAttr::Proto => Some(AttrValue::UInt($event.proto.into())),
                HttpAttr::Duration => Some(AttrValue::SInt($event.duration)),
                HttpAttr::OrigPkts => Some(AttrValue::UInt($event.orig_pkts)),
                HttpAttr::RespPkts => Some(AttrValue::UInt($event.resp_pkts)),
                HttpAttr::OrigL2Bytes => Some(AttrValue::UInt($event.orig_l2_bytes)),
                HttpAttr::RespL2Bytes => Some(AttrValue::UInt($event.resp_l2_bytes)),
                HttpAttr::Method => Some(AttrValue::String(&$event.method)),
                HttpAttr::Host => Some(AttrValue::String(&$event.host)),
                HttpAttr::Uri => Some(AttrValue::String(&$event.uri)),
                HttpAttr::Referer => Some(AttrValue::String(&$event.referer)),
                HttpAttr::Version => Some(AttrValue::String(&$event.version)),
                HttpAttr::UserAgent => Some(AttrValue::String(&$event.user_agent)),
                HttpAttr::RequestLen => u64::try_from($event.request_len).ok().map(AttrValue::UInt),
                HttpAttr::ResponseLen => {
                    u64::try_from($event.response_len).ok().map(AttrValue::UInt)
                }
                HttpAttr::StatusCode => Some(AttrValue::UInt($event.status_code.into())),
                HttpAttr::StatusMsg => Some(AttrValue::String(&$event.status_msg)),
                HttpAttr::Username => Some(AttrValue::String(&$event.username)),
                HttpAttr::Password => Some(AttrValue::String(&$event.password)),
                HttpAttr::Cookie => Some(AttrValue::String(&$event.cookie)),
                HttpAttr::ContentEncoding => Some(AttrValue::String(&$event.content_encoding)),
                HttpAttr::ContentType => Some(AttrValue::String(&$event.content_type)),
                HttpAttr::CacheControl => Some(AttrValue::String(&$event.cache_control)),
                HttpAttr::Filenames => Some(AttrValue::VecString(std::borrow::Cow::Borrowed(
                    &$event.filenames,
                ))),
                HttpAttr::MimeTypes => Some(AttrValue::VecString(std::borrow::Cow::Borrowed(
                    &$event.mime_types,
                ))),
                HttpAttr::Body => Some(AttrValue::VecRaw(&$event.body)),
                HttpAttr::State => Some(AttrValue::String(&$event.state)),
            }
        } else {
            None
        }
    };
}
pub(super) use find_http_attr_by_kind;

pub type HttpEventFields = HttpEventFieldsV0_42;

#[derive(Deserialize, Serialize)]
pub struct HttpEventFieldsV0_42 {
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
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referer: String,
    pub version: String,
    pub user_agent: String,
    pub request_len: usize,
    pub response_len: usize,
    pub status_code: u16,
    pub status_msg: String,
    pub username: String,
    pub password: String,
    pub cookie: String,
    pub content_encoding: String,
    pub content_type: String,
    pub cache_control: String,
    pub filenames: Vec<String>,
    pub mime_types: Vec<String>,
    pub body: Vec<u8>,
    pub state: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl HttpEventFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);
        format!(
            "category={:?} sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} method={:?} host={:?} uri={:?} referer={:?} version={:?} user_agent={:?} request_len={:?} response_len={:?} status_code={:?} status_msg={:?} username={:?} password={:?} cookie={:?} content_encoding={:?} content_type={:?} cache_control={:?} filenames={:?} mime_types={:?} body={:?} state={:?} confidence={:?}",
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
            self.method,
            self.host,
            self.uri,
            self.referer,
            self.version,
            self.user_agent,
            self.request_len.to_string(),
            self.response_len.to_string(),
            self.status_code.to_string(),
            self.status_msg,
            self.username,
            self.password,
            self.cookie,
            self.content_encoding,
            self.content_type,
            self.cache_control,
            self.filenames.join(","),
            self.mime_types.join(","),
            get_post_body(&self.body),
            self.state,
            self.confidence.to_string()
        )
    }
}

pub type RepeatedHttpSessionsFields = RepeatedHttpSessionsFieldsV0_42;

#[derive(Serialize, Deserialize)]
pub struct RepeatedHttpSessionsFieldsV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub start_time: i64,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub end_time: i64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl RepeatedHttpSessionsFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);
        let end_time_dt = DateTime::from_timestamp_nanos(self.end_time);
        format!(
            "category={:?} sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} end_time={:?} confidence={:?}",
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
            end_time_dt.to_rfc3339(),
            self.confidence.to_string()
        )
    }
}

#[derive(Serialize, Deserialize)]
pub struct RepeatedHttpSessions {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for RepeatedHttpSessions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} end_time={:?} triage_scores={:?}",
            self.sensor,
            self.orig_addr.to_string(),
            self.orig_port.to_string(),
            self.resp_addr.to_string(),
            self.resp_port.to_string(),
            self.proto.to_string(),
            self.start_time.to_rfc3339(),
            self.end_time.to_rfc3339(),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl RepeatedHttpSessions {
    pub(super) fn new(time: DateTime<Utc>, fields: &RepeatedHttpSessionsFields) -> Self {
        RepeatedHttpSessions {
            time,
            sensor: fields.sensor.clone(),
            orig_addr: fields.orig_addr,
            orig_port: fields.orig_port,
            resp_addr: fields.resp_addr,
            resp_port: fields.resp_port,
            proto: fields.proto,
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            end_time: DateTime::from_timestamp_nanos(fields.end_time),
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for RepeatedHttpSessions {
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

    fn level(&self) -> std::num::NonZeroU8 {
        MEDIUM
    }

    fn kind(&self) -> &'static str {
        "repeated http sessions"
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
        if let RawEventAttrKind::Http(attr) = raw_event_attr {
            match attr {
                HttpAttr::SrcAddr => Some(AttrValue::Addr(self.orig_addr)),
                HttpAttr::SrcPort => Some(AttrValue::UInt(self.orig_port.into())),
                HttpAttr::DstAddr => Some(AttrValue::Addr(self.resp_addr)),
                HttpAttr::DstPort => Some(AttrValue::UInt(self.resp_port.into())),
                HttpAttr::Proto => Some(AttrValue::UInt(self.proto.into())),
                _ => None,
            }
        } else {
            None
        }
    }
}

pub type HttpThreatFields = HttpThreatFieldsV0_42;

#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct HttpThreatFieldsV0_42 {
    #[serde(with = "ts_nanoseconds")]
    pub time: DateTime<Utc>,
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
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referer: String,
    pub version: String,
    pub user_agent: String,
    pub request_len: usize,
    pub response_len: usize,
    pub status_code: u16,
    pub status_msg: String,
    pub username: String,
    pub password: String,
    pub cookie: String,
    pub content_encoding: String,
    pub content_type: String,
    pub cache_control: String,
    pub filenames: Vec<String>,
    pub mime_types: Vec<String>,
    pub body: Vec<u8>,
    pub state: String,
    pub db_name: String,
    pub rule_id: u32,
    pub matched_to: String,
    pub cluster_id: Option<usize>,
    pub attack_kind: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl HttpThreatFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);
        format!(
            "category={:?} sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} method={:?} host={:?} uri={:?} referer={:?} version={:?} user_agent={:?} request_len={:?} response_len={:?} status_code={:?} status_msg={:?} username={:?} password={:?} cookie={:?} content_encoding={:?} content_type={:?} cache_control={:?} filenames={:?} mime_types={:?} body={:?} state={:?} db_name={:?} rule_id={:?} matched_to={:?} cluster_id={:?} attack_kind={:?} confidence={:?}",
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
            self.method,
            self.host,
            self.uri,
            self.referer,
            self.version,
            self.user_agent,
            self.request_len.to_string(),
            self.response_len.to_string(),
            self.status_code.to_string(),
            self.status_msg,
            self.username,
            self.password,
            self.cookie,
            self.content_encoding,
            self.content_type,
            self.cache_control,
            self.filenames.join(","),
            self.mime_types.join(","),
            get_post_body(&self.body),
            self.state,
            self.db_name,
            self.rule_id.to_string(),
            self.matched_to,
            self.cluster_id.map_or("-".to_string(), |s| s.to_string()),
            self.attack_kind,
            self.confidence.to_string(),
        )
    }
}

// HTTP Request body has Vec<u8> type, and it's too large to print.
const MAX_POST_BODY_LEN: usize = 10;
pub(super) fn get_post_body(post_body: &[u8]) -> String {
    let post_body = String::from_utf8_lossy(post_body);
    if post_body.len() > MAX_POST_BODY_LEN {
        let mut trimmed = post_body
            .get(..MAX_POST_BODY_LEN)
            .map_or(String::new(), ToString::to_string);
        trimmed.push_str("...");
        trimmed
    } else {
        post_body.to_string()
    }
}

#[derive(Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct HttpThreat {
    #[serde(with = "ts_nanoseconds")]
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
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referer: String,
    pub version: String,
    pub user_agent: String,
    pub request_len: usize,
    pub response_len: usize,
    pub status_code: u16,
    pub status_msg: String,
    pub username: String,
    pub password: String,
    pub cookie: String,
    pub content_encoding: String,
    pub content_type: String,
    pub cache_control: String,
    pub filenames: Vec<String>,
    pub mime_types: Vec<String>,
    pub body: Vec<u8>,
    pub state: String,
    pub db_name: String,
    pub rule_id: u32,
    pub matched_to: String,
    pub cluster_id: Option<usize>,
    pub attack_kind: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for HttpThreat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} method={:?} host={:?} uri={:?} referer={:?} version={:?} user_agent={:?} request_len={:?} response_len={:?} status_code={:?} status_msg={:?} username={:?} password={:?} cookie={:?} content_encoding={:?} content_type={:?} cache_control={:?} filenames={:?} mime_types={:?} body={:?} state={:?} db_name={:?} rule_id={:?} matched_to={:?} cluster_id={:?} attack_kind={:?} confidence={:?} triage_scores={:?}",
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
            self.method,
            self.host,
            self.uri,
            self.referer,
            self.version,
            self.user_agent,
            self.request_len.to_string(),
            self.response_len.to_string(),
            self.status_code.to_string(),
            self.status_msg,
            self.username,
            self.password,
            self.cookie,
            self.content_encoding,
            self.content_type,
            self.cache_control,
            self.filenames.join(","),
            self.mime_types.join(","),
            get_post_body(&self.body),
            self.state,
            self.db_name,
            self.rule_id.to_string(),
            self.matched_to,
            self.cluster_id.map_or("-".to_string(), |s| s.to_string()),
            self.attack_kind,
            self.confidence.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl HttpThreat {
    pub(super) fn new(time: DateTime<Utc>, fields: HttpThreatFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            orig_addr: fields.orig_addr,
            orig_port: fields.orig_port,
            resp_addr: fields.resp_addr,
            resp_port: fields.resp_port,
            proto: fields.proto,
            duration: fields.duration,
            orig_pkts: fields.orig_pkts,
            resp_pkts: fields.resp_pkts,
            orig_l2_bytes: fields.orig_l2_bytes,
            resp_l2_bytes: fields.resp_l2_bytes,
            method: fields.method,
            host: fields.host,
            uri: fields.uri,
            referer: fields.referer,
            version: fields.version,
            user_agent: fields.user_agent,
            request_len: fields.request_len,
            response_len: fields.response_len,
            status_code: fields.status_code,
            status_msg: fields.status_msg,
            username: fields.username,
            password: fields.password,
            cookie: fields.cookie,
            content_encoding: fields.content_encoding,
            content_type: fields.content_type,
            cache_control: fields.cache_control,
            filenames: fields.filenames,
            mime_types: fields.mime_types,
            body: fields.body,
            state: fields.state,
            db_name: fields.db_name,
            rule_id: fields.rule_id,
            matched_to: fields.matched_to,
            cluster_id: fields.cluster_id,
            attack_kind: fields.attack_kind,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for HttpThreat {
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
        LOW
    }

    fn kind(&self) -> &'static str {
        "http threat"
    }

    fn sensor(&self) -> &str {
        self.sensor.as_str()
    }

    fn confidence(&self) -> Option<f32> {
        Some(self.confidence)
    }

    fn learning_method(&self) -> LearningMethod {
        LearningMethod::Unsupervised
    }

    fn find_attr_by_kind(&self, raw_event_attr: RawEventAttrKind) -> Option<AttrValue<'_>> {
        find_http_attr_by_kind!(self, raw_event_attr)
    }

    fn kind_matches(&self, filter: &EventFilter) -> bool {
        if let Some(kinds) = &filter.kinds {
            let patterns = self
                .attack_kind
                .split_whitespace()
                .filter(|s| s.chars().any(char::is_alphanumeric))
                .map(ToString::to_string)
                .collect::<Vec<String>>();
            let ac = AhoCorasickBuilder::new()
                .ascii_case_insensitive(true)
                .build(patterns)
                .expect("automatic build should not fail");
            if kinds.iter().all(|kind| {
                let words = kind
                    .split_whitespace()
                    .filter(|s| s.chars().any(char::is_alphanumeric))
                    .map(ToString::to_string)
                    .collect::<Vec<String>>();
                !words.iter().all(|w| ac.is_match(w))
            }) {
                return false;
            }
        }
        true
    }

    fn score_by_triage_exclusion(&self, triage_exclusion: &[TriageExclusion]) -> f64 {
        let matched = triage_exclusion.iter().any(|ti| match ti {
            TriageExclusion::IpAddress(filter) => self
                .src_addrs()
                .iter()
                .chain(self.dst_addrs().iter())
                .any(|&ip| filter.contains(ip)),
            TriageExclusion::Domain(regex_set) => regex_set.is_match(&self.host),
            TriageExclusion::Hostname(hostnames) => hostnames.contains(&self.host),
            TriageExclusion::Uri(uris) => uris.contains(&self.uri),
        });
        if matched { f64::MIN } else { 0.0 }
    }
}

pub type DgaFields = DgaFieldsV0_42;

#[derive(Debug, Deserialize, Serialize)]
pub struct DgaFieldsV0_42 {
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
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referer: String,
    pub version: String,
    pub user_agent: String,
    pub request_len: usize,
    pub response_len: usize,
    pub status_code: u16,
    pub status_msg: String,
    pub username: String,
    pub password: String,
    pub cookie: String,
    pub content_encoding: String,
    pub content_type: String,
    pub cache_control: String,
    pub filenames: Vec<String>,
    pub mime_types: Vec<String>,
    pub body: Vec<u8>,
    pub state: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl DgaFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);
        format!(
            "category={:?} sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} method={:?} host={:?} uri={:?} referer={:?} version={:?} user_agent={:?} request_len={:?} response_len={:?} status_code={:?} status_msg={:?} username={:?} password={:?} cookie={:?} content_encoding={:?} content_type={:?} cache_control={:?} filenames={:?} mime_types={:?} body={:?} state={:?} confidence={:?}",
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
            self.method,
            self.host,
            self.uri,
            self.referer,
            self.version,
            self.user_agent,
            self.request_len.to_string(),
            self.response_len.to_string(),
            self.status_code.to_string(),
            self.status_msg,
            self.username,
            self.password,
            self.cookie,
            self.content_encoding,
            self.content_type,
            self.cache_control,
            self.filenames.join(","),
            self.mime_types.join(","),
            get_post_body(&self.body),
            self.state,
            self.confidence.to_string()
        )
    }
}

#[derive(Deserialize, Serialize)]
pub struct DomainGenerationAlgorithm {
    #[serde(with = "ts_nanoseconds")]
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
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referer: String,
    pub version: String,
    pub user_agent: String,
    pub request_len: usize,
    pub response_len: usize,
    pub status_code: u16,
    pub status_msg: String,
    pub username: String,
    pub password: String,
    pub cookie: String,
    pub content_encoding: String,
    pub content_type: String,
    pub cache_control: String,
    pub filenames: Vec<String>,
    pub mime_types: Vec<String>,
    pub body: Vec<u8>,
    pub state: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for DomainGenerationAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} method={:?} host={:?} uri={:?} referer={:?} version={:?} user_agent={:?} request_len={:?} response_len={:?} status_code={:?} status_msg={:?} username={:?} password={:?} cookie={:?} content_encoding={:?} content_type={:?} cache_control={:?} filenames={:?} mime_types={:?} body={:?} state={:?} confidence={:?} triage_scores={:?}",
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
            self.method,
            self.host,
            self.uri,
            self.referer,
            self.version,
            self.user_agent,
            self.request_len.to_string(),
            self.response_len.to_string(),
            self.status_code.to_string(),
            self.status_msg,
            self.username,
            self.password,
            self.cookie,
            self.content_encoding,
            self.content_type,
            self.cache_control,
            self.filenames.join(","),
            self.mime_types.join(","),
            get_post_body(&self.body),
            self.state,
            self.confidence.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl DomainGenerationAlgorithm {
    pub(super) fn new(time: DateTime<Utc>, fields: DgaFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            orig_addr: fields.orig_addr,
            orig_port: fields.orig_port,
            resp_addr: fields.resp_addr,
            resp_port: fields.resp_port,
            proto: fields.proto,
            duration: fields.duration,
            orig_pkts: fields.orig_pkts,
            resp_pkts: fields.resp_pkts,
            orig_l2_bytes: fields.orig_l2_bytes,
            resp_l2_bytes: fields.resp_l2_bytes,
            host: fields.host,
            method: fields.method,
            uri: fields.uri,
            referer: fields.referer,
            version: fields.version,
            user_agent: fields.user_agent,
            request_len: fields.request_len,
            response_len: fields.response_len,
            status_code: fields.status_code,
            status_msg: fields.status_msg,
            username: fields.username,
            password: fields.password,
            cookie: fields.cookie,
            content_encoding: fields.content_encoding,
            content_type: fields.content_type,
            cache_control: fields.cache_control,
            filenames: fields.filenames,
            mime_types: fields.mime_types,
            body: fields.body,
            state: fields.state,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for DomainGenerationAlgorithm {
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
        LOW
    }

    fn kind(&self) -> &'static str {
        "dga"
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
        find_http_attr_by_kind!(self, raw_event_attr)
    }

    fn score_by_triage_exclusion(&self, triage_exclusion: &[TriageExclusion]) -> f64 {
        let matched = triage_exclusion.iter().any(|ti| match ti {
            TriageExclusion::IpAddress(filter) => self
                .src_addrs()
                .iter()
                .chain(self.dst_addrs().iter())
                .any(|&ip| filter.contains(ip)),
            TriageExclusion::Domain(regex_set) => regex_set.is_match(&self.host),
            TriageExclusion::Hostname(hostnames) => hostnames.contains(&self.host),
            TriageExclusion::Uri(uris) => uris.contains(&self.uri),
        });
        if matched { f64::MIN } else { 0.0 }
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Serialize, Deserialize)]
pub struct NonBrowser {
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
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referer: String,
    pub version: String,
    pub user_agent: String,
    pub request_len: usize,
    pub response_len: usize,
    pub status_code: u16,
    pub status_msg: String,
    pub username: String,
    pub password: String,
    pub cookie: String,
    pub content_encoding: String,
    pub content_type: String,
    pub cache_control: String,
    pub filenames: Vec<String>,
    pub mime_types: Vec<String>,
    pub body: Vec<u8>,
    pub state: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for NonBrowser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} method={:?} host={:?} uri={:?} referer={:?} version={:?} user_agent={:?} request_len={:?} response_len={:?} status_code={:?} status_msg={:?} username={:?} password={:?} cookie={:?} content_encoding={:?} content_type={:?} cache_control={:?} filenames={:?} mime_types={:?} body={:?} state={:?} triage_scores={:?}",
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
            self.method,
            self.host,
            self.uri,
            self.referer,
            self.version,
            self.user_agent,
            self.request_len.to_string(),
            self.response_len.to_string(),
            self.status_code.to_string(),
            self.status_msg,
            self.username,
            self.password,
            self.cookie,
            self.content_encoding,
            self.content_type,
            self.cache_control,
            self.filenames.join(","),
            self.mime_types.join(","),
            get_post_body(&self.body),
            self.state,
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl NonBrowser {
    pub(super) fn new(time: DateTime<Utc>, fields: &HttpEventFields) -> Self {
        NonBrowser {
            time,
            sensor: fields.sensor.clone(),
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            duration: fields.duration,
            orig_pkts: fields.orig_pkts,
            resp_pkts: fields.resp_pkts,
            orig_l2_bytes: fields.orig_l2_bytes,
            resp_l2_bytes: fields.resp_l2_bytes,
            orig_addr: fields.orig_addr,
            orig_port: fields.orig_port,
            resp_addr: fields.resp_addr,
            resp_port: fields.resp_port,
            proto: fields.proto,
            method: fields.method.clone(),
            host: fields.host.clone(),
            uri: fields.uri.clone(),
            referer: fields.referer.clone(),
            version: fields.version.clone(),
            user_agent: fields.user_agent.clone(),
            request_len: fields.request_len,
            response_len: fields.response_len,
            status_code: fields.status_code,
            status_msg: fields.status_msg.clone(),
            username: fields.username.clone(),
            password: fields.password.clone(),
            cookie: fields.cookie.clone(),
            content_encoding: fields.content_encoding.clone(),
            content_type: fields.content_type.clone(),
            cache_control: fields.cache_control.clone(),
            filenames: fields.filenames.clone(),
            mime_types: fields.mime_types.clone(),
            body: fields.body.clone(),
            state: fields.state.clone(),
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for NonBrowser {
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
        "non browser"
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
        find_http_attr_by_kind!(self, raw_event_attr)
    }

    fn score_by_triage_exclusion(&self, triage_exclusion: &[TriageExclusion]) -> f64 {
        let matched = triage_exclusion.iter().any(|ti| match ti {
            TriageExclusion::IpAddress(filter) => self
                .src_addrs()
                .iter()
                .chain(self.dst_addrs().iter())
                .any(|&ip| filter.contains(ip)),
            TriageExclusion::Domain(regex_set) => regex_set.is_match(&self.host),
            TriageExclusion::Hostname(hostnames) => hostnames.contains(&self.host),
            TriageExclusion::Uri(uris) => uris.contains(&self.uri),
        });
        if matched { f64::MIN } else { 0.0 }
    }
}

// Note: BlocklistHttpFields has been merged with DgaFields as they have identical structure.
// Use DgaFields for both BlocklistHttp and DomainGenerationAlgorithm events.
pub type BlocklistHttpFields = DgaFields;

#[allow(clippy::module_name_repetitions)]
#[derive(Deserialize, Serialize)]
pub struct BlocklistHttp {
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
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referer: String,
    pub version: String,
    pub user_agent: String,
    pub request_len: usize,
    pub response_len: usize,
    pub status_code: u16,
    pub status_msg: String,
    pub username: String,
    pub password: String,
    pub cookie: String,
    pub content_encoding: String,
    pub content_type: String,
    pub cache_control: String,
    pub filenames: Vec<String>,
    pub mime_types: Vec<String>,
    pub body: Vec<u8>,
    pub state: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlocklistHttp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} method={:?} host={:?} uri={:?} referer={:?} version={:?} user_agent={:?} request_len={:?} response_len={:?} status_code={:?} status_msg={:?} username={:?} password={:?} cookie={:?} content_encoding={:?} content_type={:?} cache_control={:?} filenames={:?} mime_types={:?} body={:?} state={:?} triage_scores={:?}",
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
            self.method,
            self.host,
            self.uri,
            self.referer,
            self.version,
            self.user_agent,
            self.request_len.to_string(),
            self.response_len.to_string(),
            self.status_code.to_string(),
            self.status_msg,
            self.username,
            self.password,
            self.cookie,
            self.content_encoding,
            self.content_type,
            self.cache_control,
            self.filenames.join(","),
            self.mime_types.join(","),
            get_post_body(&self.body),
            self.state,
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl BlocklistHttp {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistHttpFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            orig_addr: fields.orig_addr,
            orig_port: fields.orig_port,
            resp_addr: fields.resp_addr,
            resp_port: fields.resp_port,
            proto: fields.proto,
            duration: fields.duration,
            orig_pkts: fields.orig_pkts,
            resp_pkts: fields.resp_pkts,
            orig_l2_bytes: fields.orig_l2_bytes,
            resp_l2_bytes: fields.resp_l2_bytes,
            method: fields.method.clone(),
            host: fields.host.clone(),
            uri: fields.uri.clone(),
            referer: fields.referer.clone(),
            version: fields.version.clone(),
            user_agent: fields.user_agent.clone(),
            request_len: fields.request_len,
            response_len: fields.response_len,
            status_code: fields.status_code,
            status_msg: fields.status_msg.clone(),
            username: fields.username.clone(),
            password: fields.password.clone(),
            cookie: fields.cookie.clone(),
            content_encoding: fields.content_encoding.clone(),
            content_type: fields.content_type.clone(),
            cache_control: fields.cache_control.clone(),
            filenames: fields.filenames.clone(),
            mime_types: fields.mime_types.clone(),
            body: fields.body.clone(),
            state: fields.state.clone(),
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistHttp {
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
        "blocklist http"
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
        find_http_attr_by_kind!(self, raw_event_attr)
    }

    fn score_by_triage_exclusion(&self, triage_exclusion: &[TriageExclusion]) -> f64 {
        let matched = triage_exclusion.iter().any(|ti| match ti {
            TriageExclusion::IpAddress(filter) => self
                .src_addrs()
                .iter()
                .chain(self.dst_addrs().iter())
                .any(|&ip| filter.contains(ip)),
            TriageExclusion::Domain(regex_set) => regex_set.is_match(&self.host),
            TriageExclusion::Hostname(hostnames) => hostnames.contains(&self.host),
            TriageExclusion::Uri(uris) => uris.contains(&self.uri),
        });
        if matched { f64::MIN } else { 0.0 }
    }
}
