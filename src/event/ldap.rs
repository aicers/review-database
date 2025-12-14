#![allow(clippy::module_name_repetitions)]
use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{LdapAttr, RawEventAttrKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::event::common::{AttrValue, triage_scores_to_string};

macro_rules! find_ldap_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {{
        if let RawEventAttrKind::Ldap(attr) = $raw_event_attr {
            let target_value = match attr {
                LdapAttr::SrcAddr => AttrValue::Addr($event.orig_addr),
                LdapAttr::SrcPort => AttrValue::UInt($event.orig_port.into()),
                LdapAttr::DstAddr => AttrValue::Addr($event.resp_addr),
                LdapAttr::DstPort => AttrValue::UInt($event.resp_port.into()),
                LdapAttr::Proto => AttrValue::UInt($event.proto.into()),
                LdapAttr::Duration => AttrValue::SInt($event.duration),
                LdapAttr::OrigPkts => AttrValue::UInt($event.orig_pkts),
                LdapAttr::RespPkts => AttrValue::UInt($event.resp_pkts),
                LdapAttr::OrigL2Bytes => AttrValue::UInt($event.orig_l2_bytes),
                LdapAttr::RespL2Bytes => AttrValue::UInt($event.resp_l2_bytes),
                LdapAttr::MessageId => AttrValue::UInt($event.message_id.into()),
                LdapAttr::Version => AttrValue::UInt($event.version.into()),
                LdapAttr::Opcode => {
                    AttrValue::VecString(std::borrow::Cow::Borrowed(&$event.opcode))
                }
                LdapAttr::Result => {
                    AttrValue::VecString(std::borrow::Cow::Borrowed(&$event.result))
                }
                LdapAttr::DiagnosticMessage => {
                    AttrValue::VecString(std::borrow::Cow::Borrowed(&$event.diagnostic_message))
                }
                LdapAttr::Object => {
                    AttrValue::VecString(std::borrow::Cow::Borrowed(&$event.object))
                }
                LdapAttr::Argument => {
                    AttrValue::VecString(std::borrow::Cow::Borrowed(&$event.argument))
                }
            };
            Some(target_value)
        } else {
            None
        }
    }};
}

pub type LdapBruteForceFields = LdapBruteForceFieldsV0_43;

#[derive(Serialize, Deserialize)]
pub struct LdapBruteForceFieldsV0_43 {
    pub sensor: String,
    pub src_country_code: Option<[u8; 2]>,
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub dst_country_code: Option<[u8; 2]>,
    pub resp_port: u16,
    pub proto: u8,
    pub user_pw_list: Vec<(String, String)>,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub start_time: i64,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub end_time: i64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl LdapBruteForceFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);
        let end_time_dt = DateTime::from_timestamp_nanos(self.end_time);
        format!(
            "category={:?} sensor={:?} orig_addr={:?} resp_addr={:?} resp_port={:?} proto={:?} user_pw_list={:?} start_time={:?} end_time={:?} confidence={:?}",
            self.category.as_ref().map_or_else(
                || "Unspecified".to_string(),
                std::string::ToString::to_string
            ),
            self.sensor,
            self.orig_addr.to_string(),
            self.resp_addr.to_string(),
            self.resp_port.to_string(),
            self.proto.to_string(),
            get_user_pw_list(&self.user_pw_list),
            start_time_dt.to_rfc3339(),
            end_time_dt.to_rfc3339(),
            self.confidence.to_string()
        )
    }
}

fn get_user_pw_list(user_pw_list: &[(String, String)]) -> String {
    if user_pw_list.is_empty() {
        String::new()
    } else {
        user_pw_list
            .iter()
            .map(|(user, pw)| format!("{user}:{pw}"))
            .collect::<Vec<String>>()
            .join(",")
    }
}

#[derive(Serialize, Deserialize)]
pub struct LdapBruteForce {
    pub sensor: String,
    pub time: DateTime<Utc>,
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub user_pw_list: Vec<(String, String)>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for LdapBruteForce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "orig_addr={:?} resp_addr={:?} resp_port={:?} proto={:?} user_pw_list={:?} start_time={:?} end_time={:?} triage_scores={:?}",
            self.orig_addr.to_string(),
            self.resp_addr.to_string(),
            self.resp_port.to_string(),
            self.proto.to_string(),
            get_user_pw_list(&self.user_pw_list),
            self.start_time.to_rfc3339(),
            self.end_time.to_rfc3339(),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl LdapBruteForce {
    pub(super) fn new(time: DateTime<Utc>, fields: &LdapBruteForceFields) -> Self {
        LdapBruteForce {
            sensor: fields.sensor.clone(),
            time,
            orig_addr: fields.orig_addr,
            resp_addr: fields.resp_addr,
            resp_port: fields.resp_port,
            proto: fields.proto,
            user_pw_list: fields.user_pw_list.clone(),
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            end_time: DateTime::from_timestamp_nanos(fields.end_time),
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for LdapBruteForce {
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
        "ldap brute force"
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
        if let RawEventAttrKind::Ldap(attr) = raw_event_attr {
            match attr {
                LdapAttr::SrcAddr => Some(AttrValue::Addr(self.orig_addr)),
                LdapAttr::DstAddr => Some(AttrValue::Addr(self.resp_addr)),
                LdapAttr::DstPort => Some(AttrValue::UInt(self.resp_port.into())),
                LdapAttr::Proto => Some(AttrValue::UInt(self.proto.into())),
                _ => None,
            }
        } else {
            None
        }
    }
}

pub type LdapEventFields = LdapEventFieldsV0_43;

#[derive(Serialize, Deserialize)]
pub struct LdapEventFieldsV0_43 {
    pub sensor: String,
    pub src_country_code: Option<[u8; 2]>,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub dst_country_code: Option<[u8; 2]>,
    pub resp_port: u16,
    pub proto: u8,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub message_id: u32,
    pub version: u8,
    pub opcode: Vec<String>,
    pub result: Vec<String>,
    pub diagnostic_message: Vec<String>,
    pub object: Vec<String>,
    pub argument: Vec<String>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl LdapEventFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);
        format!(
            "category={:?} sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} message_id={:?} version={:?} opcode={:?} result={:?} diagnostic_message={:?} object={:?} argument={:?} confidence={:?}",
            self.category.as_ref().map_or_else(
                || "Unspecified".to_string(),
                std::string::ToString::to_string
            ),
            self.sensor.clone(),
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
            self.message_id.to_string(),
            self.version.to_string(),
            self.opcode.join(","),
            self.result.join(","),
            self.diagnostic_message.join(","),
            self.object.join(","),
            self.argument.join(","),
            self.confidence.to_string()
        )
    }
}

#[derive(Deserialize, Serialize)]
pub struct LdapPlainText {
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
    pub message_id: u32,
    pub version: u8,
    pub opcode: Vec<String>,
    pub result: Vec<String>,
    pub diagnostic_message: Vec<String>,
    pub object: Vec<String>,
    pub argument: Vec<String>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for LdapPlainText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} message_id={:?} version={:?} opcode={:?} result={:?} diagnostic_message={:?} object={:?} argument={:?} triage_scores={:?}",
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
            self.message_id.to_string(),
            self.version.to_string(),
            self.opcode.join(","),
            self.result.join(","),
            self.diagnostic_message.join(","),
            self.object.join(","),
            self.argument.join(","),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl LdapPlainText {
    pub(super) fn new(time: DateTime<Utc>, fields: LdapEventFields) -> Self {
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
            message_id: fields.message_id,
            version: fields.version,
            opcode: fields.opcode,
            result: fields.result,
            diagnostic_message: fields.diagnostic_message,
            object: fields.object,
            argument: fields.argument,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for LdapPlainText {
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
        "ldap plain text"
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
        find_ldap_attr_by_kind!(self, raw_event_attr)
    }
}

#[derive(Deserialize, Serialize)]
pub struct BlocklistLdap {
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
    pub message_id: u32,
    pub version: u8,
    pub opcode: Vec<String>,
    pub result: Vec<String>,
    pub diagnostic_message: Vec<String>,
    pub object: Vec<String>,
    pub argument: Vec<String>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlocklistLdap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} message_id={:?} version={:?} opcode={:?} result={:?} diagnostic_message={:?} object={:?} argument={:?} triage_scores={:?}",
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
            self.message_id.to_string(),
            self.version.to_string(),
            self.opcode.join(","),
            self.result.join(","),
            self.diagnostic_message.join(","),
            self.object.join(","),
            self.argument.join(","),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl BlocklistLdap {
    pub(super) fn new(time: DateTime<Utc>, fields: LdapEventFields) -> Self {
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
            message_id: fields.message_id,
            version: fields.version,
            opcode: fields.opcode,
            result: fields.result,
            diagnostic_message: fields.diagnostic_message,
            object: fields.object,
            argument: fields.argument,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistLdap {
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
        "blocklist ldap"
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
        find_ldap_attr_by_kind!(self, raw_event_attr)
    }
}
