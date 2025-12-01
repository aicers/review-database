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
                FtpAttr::SrcAddr => AttrValue::Addr($event.src_addr),
                FtpAttr::SrcPort => AttrValue::UInt($event.src_port.into()),
                FtpAttr::DstAddr => AttrValue::Addr($event.dst_addr),
                FtpAttr::DstPort => AttrValue::UInt($event.dst_port.into()),
                FtpAttr::Proto => AttrValue::UInt($event.proto.into()),
                FtpAttr::User => AttrValue::String(&$event.user),
                FtpAttr::Password => AttrValue::String(&$event.password),
                FtpAttr::Command => {
                    if let Some(first_cmd) = $event.commands.first() {
                        AttrValue::String(&first_cmd.command)
                    } else {
                        return None;
                    }
                }
                FtpAttr::ReplyCode => {
                    if let Some(first_cmd) = $event.commands.first() {
                        AttrValue::String(&first_cmd.reply_code)
                    } else {
                        return None;
                    }
                }
                FtpAttr::ReplyMsg => {
                    if let Some(first_cmd) = $event.commands.first() {
                        AttrValue::String(&first_cmd.reply_msg)
                    } else {
                        return None;
                    }
                }
                FtpAttr::DataPassive => {
                    if let Some(first_cmd) = $event.commands.first() {
                        AttrValue::Bool(first_cmd.data_passive)
                    } else {
                        return None;
                    }
                }
                FtpAttr::DataOrigAddr => {
                    if let Some(first_cmd) = $event.commands.first() {
                        AttrValue::Addr(first_cmd.data_orig_addr)
                    } else {
                        return None;
                    }
                }
                FtpAttr::DataRespAddr => {
                    if let Some(first_cmd) = $event.commands.first() {
                        AttrValue::Addr(first_cmd.data_resp_addr)
                    } else {
                        return None;
                    }
                }
                FtpAttr::DataRespPort => {
                    if let Some(first_cmd) = $event.commands.first() {
                        AttrValue::UInt(first_cmd.data_resp_port.into())
                    } else {
                        return None;
                    }
                }
                FtpAttr::File => {
                    if let Some(first_cmd) = $event.commands.first() {
                        AttrValue::String(&first_cmd.file)
                    } else {
                        return None;
                    }
                }
                FtpAttr::FileSize => {
                    if let Some(first_cmd) = $event.commands.first() {
                        AttrValue::UInt(first_cmd.file_size)
                    } else {
                        return None;
                    }
                }
                FtpAttr::FileId => {
                    if let Some(first_cmd) = $event.commands.first() {
                        AttrValue::String(&first_cmd.file_id)
                    } else {
                        return None;
                    }
                }
            };
            Some(target_value)
        } else {
            None
        }
    }};
}

pub type FtpBruteForceFields = FtpBruteForceFieldsV0_42;

impl FtpBruteForceFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);
        let end_time_dt = DateTime::from_timestamp_nanos(self.end_time);
        format!(
            "category={:?} sensor={:?} src_addr={:?} dst_addr={:?} dst_port={:?} proto={:?} user_list={:?} start_time={:?} end_time={:?} is_internal={:?} confidence={:?} threat_level={:?}",
            self.category.as_ref().map_or_else(
                || "Unspecified".to_string(),
                std::string::ToString::to_string
            ),
            self.sensor,
            self.src_addr.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.user_list.join(","),
            start_time_dt.to_rfc3339(),
            end_time_dt.to_rfc3339(),
            self.is_internal.to_string(),
            self.confidence.to_string(),
            self.threat_level.to_string()
        )
    }
}

#[derive(Serialize, Deserialize)]
pub struct FtpBruteForceFieldsV0_42 {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub user_list: Vec<String>,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub start_time: i64,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub end_time: i64,
    pub is_internal: bool,
    pub confidence: f32,
    pub threat_level: u8,
    pub category: Option<EventCategory>,
}

impl From<FtpBruteForceFieldsV0_41> for FtpBruteForceFieldsV0_42 {
    fn from(value: FtpBruteForceFieldsV0_41) -> Self {
        Self {
            sensor: String::new(),
            src_addr: value.src_addr,
            dst_addr: value.dst_addr,
            dst_port: value.dst_port,
            proto: value.proto,
            user_list: value.user_list,
            start_time: value.start_time.timestamp_nanos_opt().unwrap_or_default(),
            end_time: value.end_time.timestamp_nanos_opt().unwrap_or_default(),
            is_internal: value.is_internal,
            confidence: value.confidence,
            threat_level: 0,
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
    pub time: DateTime<Utc>,
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub user_list: Vec<String>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub is_internal: bool,
    pub confidence: f32,
    pub threat_level: u8,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for FtpBruteForce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "src_addr={:?} dst_addr={:?} dst_port={:?} proto={:?} user_list={:?} start_time={:?} end_time={:?} is_internal={:?} threat_level={:?} triage_scores={:?}",
            self.src_addr.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
            self.proto.to_string(),
            self.user_list.join(","),
            self.start_time.to_rfc3339(),
            self.end_time.to_rfc3339(),
            self.is_internal.to_string(),
            self.threat_level.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl FtpBruteForce {
    pub(super) fn new(time: DateTime<Utc>, fields: &FtpBruteForceFields) -> Self {
        FtpBruteForce {
            sensor: fields.sensor.clone(),
            time,
            src_addr: fields.src_addr,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            user_list: fields.user_list.clone(),
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            end_time: DateTime::from_timestamp_nanos(fields.end_time),
            is_internal: fields.is_internal,
            confidence: fields.confidence,
            threat_level: fields.threat_level,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for FtpBruteForce {
    fn src_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.src_addr)
    }

    fn src_port(&self) -> u16 {
        0
    }

    fn dst_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.dst_addr)
    }

    fn dst_port(&self) -> u16 {
        self.dst_port
    }

    fn proto(&self) -> u8 {
        self.proto
    }

    fn category(&self) -> Option<EventCategory> {
        self.category
    }

    fn level(&self) -> NonZeroU8 {
        NonZeroU8::new(self.threat_level).unwrap_or(MEDIUM)
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
                FtpAttr::SrcAddr => Some(AttrValue::Addr(self.src_addr)),
                FtpAttr::DstAddr => Some(AttrValue::Addr(self.dst_addr)),
                FtpAttr::DstPort => Some(AttrValue::UInt(self.dst_port.into())),
                FtpAttr::Proto => Some(AttrValue::UInt(self.proto.into())),
                FtpAttr::User => Some(AttrValue::VecString(&self.user_list)),
                _ => None,
            }
        } else {
            None
        }
    }
}

pub type FtpEventFields = FtpEventFieldsV0_42;

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
            "category={:?} sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} user={:?} password={:?} commands={:?} confidence={:?} threat_level={:?}",
            self.category.as_ref().map_or_else(
                || "Unspecified".to_string(),
                std::string::ToString::to_string
            ),
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
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
            self.confidence.to_string(),
            self.threat_level.to_string()
        )
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FtpEventFieldsV0_42 {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
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
    pub threat_level: u8,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub struct FtpPlainText {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
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
    pub threat_level: u8,
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
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} user={:?} password={:?} commands={:?} threat_level={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
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
            self.threat_level.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl FtpPlainText {
    pub(super) fn new(time: DateTime<Utc>, fields: FtpEventFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
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
            threat_level: fields.threat_level,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for FtpPlainText {
    fn src_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.src_addr)
    }

    fn src_port(&self) -> u16 {
        self.src_port
    }

    fn dst_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.dst_addr)
    }

    fn dst_port(&self) -> u16 {
        self.dst_port
    }

    fn proto(&self) -> u8 {
        self.proto
    }

    fn category(&self) -> Option<EventCategory> {
        self.category
    }

    fn level(&self) -> NonZeroU8 {
        NonZeroU8::new(self.threat_level).unwrap_or(MEDIUM)
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
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
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
    pub threat_level: u8,
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
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} user={:?} password={:?} commands={:?} threat_level={:?} triage_scores={:?}",
            self.sensor,
            self.src_addr.to_string(),
            self.src_port.to_string(),
            self.dst_addr.to_string(),
            self.dst_port.to_string(),
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
            self.threat_level.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl BlocklistFtp {
    pub(super) fn new(time: DateTime<Utc>, fields: FtpEventFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
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
            threat_level: fields.threat_level,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistFtp {
    fn src_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.src_addr)
    }

    fn src_port(&self) -> u16 {
        self.src_port
    }

    fn dst_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.dst_addr)
    }

    fn dst_port(&self) -> u16 {
        self.dst_port
    }

    fn proto(&self) -> u8 {
        self.proto
    }

    fn category(&self) -> Option<EventCategory> {
        self.category
    }

    fn level(&self) -> NonZeroU8 {
        NonZeroU8::new(self.threat_level).unwrap_or(MEDIUM)
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
