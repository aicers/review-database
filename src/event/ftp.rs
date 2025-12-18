#![allow(clippy::module_name_repetitions)]
use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{FtpAttr, RawEventAttrKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::{
    event::common::{AttrValue, triage_scores_to_string},
    types::EventCategoryV0_41,
};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FtpCommand {
    pub command: String,
    pub reply_code: String,
    pub reply_msg: String,
    pub data_passive: bool,
    pub data_orig_addr: IpAddr,
    pub data_resp_addr: IpAddr,
    pub data_resp_port: u16,
    pub file: String,
    pub file_size: u64,
    pub file_id: String,
}

macro_rules! find_ftp_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {{
        if let RawEventAttrKind::Ftp(attr) = $raw_event_attr {
            let target_value = match attr {
                FtpAttr::SrcAddr => AttrValue::Addr($event.orig_addr),
                FtpAttr::SrcPort => AttrValue::UInt($event.orig_port.into()),
                FtpAttr::DstAddr => AttrValue::Addr($event.resp_addr),
                FtpAttr::DstPort => AttrValue::UInt($event.resp_port.into()),
                FtpAttr::Proto => AttrValue::UInt($event.proto.into()),
                FtpAttr::Duration => AttrValue::SInt($event.duration),
                FtpAttr::OrigPkts => AttrValue::UInt($event.orig_pkts),
                FtpAttr::RespPkts => AttrValue::UInt($event.resp_pkts),
                FtpAttr::OrigL2Bytes => AttrValue::UInt($event.orig_l2_bytes),
                FtpAttr::RespL2Bytes => AttrValue::UInt($event.resp_l2_bytes),
                FtpAttr::User => AttrValue::String(&$event.user),
                FtpAttr::Password => AttrValue::String(&$event.password),
                FtpAttr::Command => {
                    let values = $event
                        .commands
                        .iter()
                        .map(|c| c.command.clone())
                        .collect::<Vec<_>>();
                    if values.is_empty() {
                        return None;
                    }
                    AttrValue::VecString(std::borrow::Cow::Owned(values))
                }
                FtpAttr::ReplyCode => {
                    let values = $event
                        .commands
                        .iter()
                        .map(|c| c.reply_code.clone())
                        .collect::<Vec<_>>();
                    if values.is_empty() {
                        return None;
                    }
                    AttrValue::VecString(std::borrow::Cow::Owned(values))
                }
                FtpAttr::ReplyMsg => {
                    let values = $event
                        .commands
                        .iter()
                        .map(|c| c.reply_msg.clone())
                        .collect::<Vec<_>>();
                    if values.is_empty() {
                        return None;
                    }
                    AttrValue::VecString(std::borrow::Cow::Owned(values))
                }
                FtpAttr::DataPassive => {
                    let values = $event
                        .commands
                        .iter()
                        .map(|c| c.data_passive)
                        .collect::<Vec<_>>();
                    if values.is_empty() {
                        return None;
                    }
                    AttrValue::VecBool(std::borrow::Cow::Owned(values))
                }
                FtpAttr::DataOrigAddr => {
                    let values = $event
                        .commands
                        .iter()
                        .map(|c| c.data_orig_addr)
                        .collect::<Vec<_>>();
                    if values.is_empty() {
                        return None;
                    }
                    AttrValue::VecAddr(std::borrow::Cow::Owned(values))
                }
                FtpAttr::DataRespAddr => {
                    let values = $event
                        .commands
                        .iter()
                        .map(|c| c.data_resp_addr)
                        .collect::<Vec<_>>();
                    if values.is_empty() {
                        return None;
                    }
                    AttrValue::VecAddr(std::borrow::Cow::Owned(values))
                }
                FtpAttr::DataRespPort => {
                    let values = $event
                        .commands
                        .iter()
                        .map(|c| u64::from(c.data_resp_port))
                        .collect::<Vec<_>>();
                    if values.is_empty() {
                        return None;
                    }
                    AttrValue::VecUInt(std::borrow::Cow::Owned(values))
                }
                FtpAttr::File => {
                    let values = $event
                        .commands
                        .iter()
                        .map(|c| c.file.clone())
                        .collect::<Vec<_>>();
                    if values.is_empty() {
                        return None;
                    }
                    AttrValue::VecString(std::borrow::Cow::Owned(values))
                }
                FtpAttr::FileSize => {
                    let values = $event
                        .commands
                        .iter()
                        .map(|c| c.file_size)
                        .collect::<Vec<_>>();
                    if values.is_empty() {
                        return None;
                    }
                    AttrValue::VecUInt(std::borrow::Cow::Owned(values))
                }
                FtpAttr::FileId => {
                    let values = $event
                        .commands
                        .iter()
                        .map(|c| c.file_id.clone())
                        .collect::<Vec<_>>();
                    if values.is_empty() {
                        return None;
                    }
                    AttrValue::VecString(std::borrow::Cow::Owned(values))
                }
            };
            Some(target_value)
        } else {
            None
        }
    }};
}

pub type FtpBruteForceFields = FtpBruteForceFieldsV0_43;

impl FtpBruteForceFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);
        let end_time_dt = DateTime::from_timestamp_nanos(self.end_time);
        format!(
            "category={:?} sensor={:?} orig_addr={:?} resp_addr={:?} resp_port={:?} proto={:?} user_list={:?} start_time={:?} end_time={:?} is_internal={:?} confidence={:?}",
            self.category.as_ref().map_or_else(
                || "Unspecified".to_string(),
                std::string::ToString::to_string
            ),
            self.sensor,
            self.orig_addr.to_string(),
            self.resp_addr.to_string(),
            self.resp_port.to_string(),
            self.proto.to_string(),
            self.user_list.join(","),
            start_time_dt.to_rfc3339(),
            end_time_dt.to_rfc3339(),
            self.is_internal.to_string(),
            self.confidence.to_string()
        )
    }
}

#[derive(Serialize, Deserialize)]
pub struct FtpBruteForceFieldsV0_43 {
    pub sensor: String,
    pub src_country_code: Option<[u8; 2]>,
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub dst_country_code: Option<[u8; 2]>,
    pub resp_port: u16,
    pub proto: u8,
    pub user_list: Vec<String>,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub start_time: i64,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub end_time: i64,
    pub is_internal: bool,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl From<FtpBruteForceFieldsV0_41> for FtpBruteForceFieldsV0_43 {
    fn from(value: FtpBruteForceFieldsV0_41) -> Self {
        Self {
            sensor: String::new(),
            src_country_code: None,
            orig_addr: value.src_addr,
            resp_addr: value.dst_addr,
            dst_country_code: None,
            resp_port: value.dst_port,
            proto: value.proto,
            user_list: value.user_list,
            start_time: value.start_time.timestamp_nanos_opt().unwrap_or_default(),
            end_time: value.end_time.timestamp_nanos_opt().unwrap_or_default(),
            is_internal: value.is_internal,
            confidence: value.confidence,
            category: value.category.into(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct FtpBruteForceFieldsV0_41 {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub user_list: Vec<String>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub is_internal: bool,
    pub confidence: f32,
    pub category: EventCategoryV0_41,
}
#[derive(Serialize, Deserialize)]
pub struct FtpBruteForce {
    pub sensor: String,
    pub src_country_code: Option<[u8; 2]>,
    pub time: DateTime<Utc>,
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub dst_country_code: Option<[u8; 2]>,
    pub resp_port: u16,
    pub proto: u8,
    pub user_list: Vec<String>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub is_internal: bool,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for FtpBruteForce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "orig_addr={:?} resp_addr={:?} resp_port={:?} proto={:?} user_list={:?} start_time={:?} end_time={:?} is_internal={:?} triage_scores={:?}",
            self.orig_addr.to_string(),
            self.resp_addr.to_string(),
            self.resp_port.to_string(),
            self.proto.to_string(),
            self.user_list.join(","),
            self.start_time.to_rfc3339(),
            self.end_time.to_rfc3339(),
            self.is_internal.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl FtpBruteForce {
    pub(super) fn new(time: DateTime<Utc>, fields: &FtpBruteForceFields) -> Self {
        FtpBruteForce {
            sensor: fields.sensor.clone(),
            src_country_code: fields.src_country_code,
            time,
            orig_addr: fields.orig_addr,
            resp_addr: fields.resp_addr,
            dst_country_code: fields.dst_country_code,
            resp_port: fields.resp_port,
            proto: fields.proto,
            user_list: fields.user_list.clone(),
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            end_time: DateTime::from_timestamp_nanos(fields.end_time),
            is_internal: fields.is_internal,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for FtpBruteForce {
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
        "ftp brute force"
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
        if let RawEventAttrKind::Ftp(attr) = raw_event_attr {
            match attr {
                FtpAttr::SrcAddr => Some(AttrValue::Addr(self.orig_addr)),
                FtpAttr::DstAddr => Some(AttrValue::Addr(self.resp_addr)),
                FtpAttr::DstPort => Some(AttrValue::UInt(self.resp_port.into())),
                FtpAttr::Proto => Some(AttrValue::UInt(self.proto.into())),
                FtpAttr::User => Some(AttrValue::VecString(std::borrow::Cow::Borrowed(
                    &self.user_list,
                ))),
                _ => None,
            }
        } else {
            None
        }
    }
}

pub type FtpEventFields = FtpEventFieldsV0_43;

impl FtpEventFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);
        let commands_str = self
            .commands
            .iter()
            .map(|cmd| format!("{}:{}:{}", cmd.command, cmd.reply_code, cmd.reply_msg))
            .collect::<Vec<_>>()
            .join(";");

        format!(
            "category={:?} sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} user={:?} password={:?} commands={:?} confidence={:?}",
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
            self.user,
            self.password,
            commands_str,
            self.confidence.to_string()
        )
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FtpEventFieldsV0_43 {
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
    pub user: String,
    pub password: String,
    pub commands: Vec<FtpCommand>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub struct FtpPlainText {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub src_country_code: Option<[u8; 2]>,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub dst_country_code: Option<[u8; 2]>,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub user: String,
    pub password: String,
    pub commands: Vec<FtpCommand>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for FtpPlainText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let commands_str = self
            .commands
            .iter()
            .map(|cmd| format!("{}:{}:{}", cmd.command, cmd.reply_code, cmd.reply_msg))
            .collect::<Vec<_>>()
            .join(";");

        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} user={:?} password={:?} commands={:?} triage_scores={:?}",
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
            self.user,
            self.password,
            commands_str,
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl FtpPlainText {
    pub(super) fn new(time: DateTime<Utc>, fields: FtpEventFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            src_country_code: fields.src_country_code,
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            orig_addr: fields.orig_addr,
            orig_port: fields.orig_port,
            resp_addr: fields.resp_addr,
            dst_country_code: fields.dst_country_code,
            resp_port: fields.resp_port,
            proto: fields.proto,
            duration: fields.duration,
            orig_pkts: fields.orig_pkts,
            resp_pkts: fields.resp_pkts,
            orig_l2_bytes: fields.orig_l2_bytes,
            resp_l2_bytes: fields.resp_l2_bytes,
            user: fields.user,
            password: fields.password,
            commands: fields.commands,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for FtpPlainText {
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
        "ftp plain text"
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
        find_ftp_attr_by_kind!(self, raw_event_attr)
    }
}

#[derive(Deserialize, Serialize)]
pub struct BlocklistFtp {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub src_country_code: Option<[u8; 2]>,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub dst_country_code: Option<[u8; 2]>,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub user: String,
    pub password: String,
    pub commands: Vec<FtpCommand>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlocklistFtp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let commands_str = self
            .commands
            .iter()
            .map(|cmd| format!("{}:{}:{}", cmd.command, cmd.reply_code, cmd.reply_msg))
            .collect::<Vec<_>>()
            .join(";");

        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} user={:?} password={:?} commands={:?} triage_scores={:?}",
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
            self.user,
            self.password,
            commands_str,
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl BlocklistFtp {
    pub(super) fn new(time: DateTime<Utc>, fields: FtpEventFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            src_country_code: fields.src_country_code,
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            orig_addr: fields.orig_addr,
            orig_port: fields.orig_port,
            resp_addr: fields.resp_addr,
            dst_country_code: fields.dst_country_code,
            resp_port: fields.resp_port,
            proto: fields.proto,
            duration: fields.duration,
            orig_pkts: fields.orig_pkts,
            resp_pkts: fields.resp_pkts,
            orig_l2_bytes: fields.orig_l2_bytes,
            resp_l2_bytes: fields.resp_l2_bytes,
            user: fields.user,
            password: fields.password,
            commands: fields.commands,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistFtp {
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
        "blocklist ftp"
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
        find_ftp_attr_by_kind!(self, raw_event_attr)
    }
}
