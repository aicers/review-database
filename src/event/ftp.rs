#![allow(clippy::module_name_repetitions)]
use std::{fmt, net::IpAddr};

use attrievent::attribute::{FtpAttr, RawEventAttrKind};
use chrono::DateTime;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use super::timestamp::{self, ts_nanoseconds as jiff_ts_nanoseconds};
use super::{EventCategory, LearningMethod, ThreatLevel, TriageScore, common::Match};
use crate::event::common::{AttrValue, triage_scores_to_string};

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

impl FtpBruteForceFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let first_event_start_time_dt = DateTime::from_timestamp_nanos(self.first_event_start_time);
        let last_event_start_time_dt = DateTime::from_timestamp_nanos(self.last_event_start_time);
        format!(
            "category={:?} sensor={:?} orig_addr={:?} resp_addr={:?} resp_port={:?} proto={:?} user_list={:?} first_event_start_time={:?} last_event_start_time={:?} is_internal={:?} confidence={:?}",
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
            first_event_start_time_dt.to_rfc3339(),
            last_event_start_time_dt.to_rfc3339(),
            self.is_internal.to_string(),
            self.confidence.to_string()
        )
    }
}

#[derive(Serialize, Deserialize)]
pub struct FtpBruteForceFields {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub user_list: Vec<String>,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub first_event_start_time: i64,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub last_event_start_time: i64,
    pub is_internal: bool,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

pub(crate) type FtpBruteForceFieldsStored = FtpBruteForceFieldsStoredV0_46;

#[derive(Deserialize, Serialize)]
pub(crate) struct FtpBruteForceFieldsStoredV0_46 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_country_code: [u8; 2],
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub resp_country_code: [u8; 2],
    pub proto: u8,
    pub user_list: Vec<String>,
    pub first_event_start_time: i64,
    pub last_event_start_time: i64,
    pub is_internal: bool,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl From<FtpBruteForceFields> for FtpBruteForceFieldsStored {
    fn from(value: FtpBruteForceFields) -> Self {
        Self {
            sensor: value.sensor,
            orig_addr: value.orig_addr,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: value.resp_addr,
            resp_port: value.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: value.proto,
            user_list: value.user_list,
            first_event_start_time: value.first_event_start_time,
            last_event_start_time: value.last_event_start_time,
            is_internal: value.is_internal,
            confidence: value.confidence,
            category: value.category,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct FtpBruteForce {
    pub sensor: String,
    #[serde(with = "jiff_ts_nanoseconds")]
    pub time: Timestamp,
    pub orig_addr: IpAddr,
    pub orig_country_code: [u8; 2],
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub resp_country_code: [u8; 2],
    pub proto: u8,
    pub user_list: Vec<String>,
    #[serde(with = "jiff_ts_nanoseconds")]
    pub first_event_start_time: Timestamp,
    #[serde(with = "jiff_ts_nanoseconds")]
    pub last_event_start_time: Timestamp,
    pub is_internal: bool,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for FtpBruteForce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "orig_addr={:?} orig_country_code={:?} resp_addr={:?} resp_port={:?} resp_country_code={:?} proto={:?} user_list={:?} first_event_start_time={:?} last_event_start_time={:?} is_internal={:?} triage_scores={:?}",
            self.orig_addr.to_string(),
            crate::util::country_code_as_str(&self.orig_country_code),
            self.resp_addr.to_string(),
            self.resp_port.to_string(),
            crate::util::country_code_as_str(&self.resp_country_code),
            self.proto.to_string(),
            self.user_list.join(","),
            timestamp::format_rfc3339(self.first_event_start_time).unwrap_or_default(),
            timestamp::format_rfc3339(self.last_event_start_time).unwrap_or_default(),
            self.is_internal.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl FtpBruteForce {
    pub(super) fn new(time: Timestamp, fields: &FtpBruteForceFieldsStored) -> Self {
        FtpBruteForce {
            sensor: fields.sensor.clone(),
            time,
            orig_addr: fields.orig_addr,
            orig_country_code: fields.orig_country_code,
            resp_addr: fields.resp_addr,
            resp_port: fields.resp_port,
            resp_country_code: fields.resp_country_code,
            proto: fields.proto,
            user_list: fields.user_list.clone(),
            first_event_start_time: timestamp::from_i64_nanos(fields.first_event_start_time)
                .expect(timestamp::I64_NANOS_JIFF_INVARIANT),
            last_event_start_time: timestamp::from_i64_nanos(fields.last_event_start_time)
                .expect(timestamp::I64_NANOS_JIFF_INVARIANT),
            is_internal: fields.is_internal,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl FtpBruteForce {
    #[must_use]
    pub fn threat_level() -> ThreatLevel {
        ThreatLevel::Medium
    }
}

impl Match for FtpBruteForce {
    fn orig_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.orig_addr)
    }

    fn orig_port(&self) -> u16 {
        0
    }

    fn orig_country_codes(&self) -> &[[u8; 2]] {
        std::slice::from_ref(&self.orig_country_code)
    }

    fn resp_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.resp_addr)
    }

    fn resp_port(&self) -> u16 {
        self.resp_port
    }

    fn resp_country_codes(&self) -> &[[u8; 2]] {
        std::slice::from_ref(&self.resp_country_code)
    }

    fn proto(&self) -> u8 {
        self.proto
    }

    fn category(&self) -> Option<EventCategory> {
        self.category
    }

    fn level(&self) -> ThreatLevel {
        Self::threat_level()
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
pub struct FtpEventFields {
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
    pub user: String,
    pub password: String,
    pub commands: Vec<FtpCommand>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

pub(crate) type FtpEventFieldsStored = FtpEventFieldsStoredV0_46;

#[derive(Deserialize, Serialize)]
pub(crate) struct FtpEventFieldsStoredV0_46 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub orig_country_code: [u8; 2],
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub resp_country_code: [u8; 2],
    pub proto: u8,
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

impl From<FtpEventFields> for FtpEventFieldsStored {
    fn from(value: FtpEventFields) -> Self {
        Self {
            sensor: value.sensor,
            orig_addr: value.orig_addr,
            orig_port: value.orig_port,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: value.resp_addr,
            resp_port: value.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: value.proto,
            start_time: value.start_time,
            duration: value.duration,
            orig_pkts: value.orig_pkts,
            resp_pkts: value.resp_pkts,
            orig_l2_bytes: value.orig_l2_bytes,
            resp_l2_bytes: value.resp_l2_bytes,
            user: value.user,
            password: value.password,
            commands: value.commands,
            confidence: value.confidence,
            category: value.category,
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct FtpPlainText {
    #[serde(with = "jiff_ts_nanoseconds")]
    pub time: Timestamp,
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub orig_country_code: [u8; 2],
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub resp_country_code: [u8; 2],
    pub proto: u8,
    #[serde(with = "jiff_ts_nanoseconds")]
    pub start_time: Timestamp,
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
            "sensor={:?} orig_addr={:?} orig_port={:?} orig_country_code={:?} resp_addr={:?} resp_port={:?} resp_country_code={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} user={:?} password={:?} commands={:?} triage_scores={:?}",
            self.sensor,
            self.orig_addr.to_string(),
            self.orig_port.to_string(),
            crate::util::country_code_as_str(&self.orig_country_code),
            self.resp_addr.to_string(),
            self.resp_port.to_string(),
            crate::util::country_code_as_str(&self.resp_country_code),
            self.proto.to_string(),
            timestamp::format_rfc3339(self.start_time).unwrap_or_default(),
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
    pub(super) fn new(time: Timestamp, fields: FtpEventFieldsStored) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            start_time: timestamp::from_i64_nanos(fields.start_time)
                .expect(timestamp::I64_NANOS_JIFF_INVARIANT),
            orig_addr: fields.orig_addr,
            orig_port: fields.orig_port,
            orig_country_code: fields.orig_country_code,
            resp_addr: fields.resp_addr,
            resp_port: fields.resp_port,
            resp_country_code: fields.resp_country_code,
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

impl FtpPlainText {
    #[must_use]
    pub fn threat_level() -> ThreatLevel {
        ThreatLevel::Medium
    }
}

impl Match for FtpPlainText {
    fn orig_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.orig_addr)
    }

    fn orig_port(&self) -> u16 {
        self.orig_port
    }

    fn orig_country_codes(&self) -> &[[u8; 2]] {
        std::slice::from_ref(&self.orig_country_code)
    }

    fn resp_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.resp_addr)
    }

    fn resp_port(&self) -> u16 {
        self.resp_port
    }

    fn resp_country_codes(&self) -> &[[u8; 2]] {
        std::slice::from_ref(&self.resp_country_code)
    }

    fn proto(&self) -> u8 {
        self.proto
    }

    fn category(&self) -> Option<EventCategory> {
        self.category
    }

    fn level(&self) -> ThreatLevel {
        Self::threat_level()
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
    #[serde(with = "jiff_ts_nanoseconds")]
    pub time: Timestamp,
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub orig_country_code: [u8; 2],
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub resp_country_code: [u8; 2],
    pub proto: u8,
    #[serde(with = "jiff_ts_nanoseconds")]
    pub start_time: Timestamp,
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
            "sensor={:?} orig_addr={:?} orig_port={:?} orig_country_code={:?} resp_addr={:?} resp_port={:?} resp_country_code={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} user={:?} password={:?} commands={:?} triage_scores={:?}",
            self.sensor,
            self.orig_addr.to_string(),
            self.orig_port.to_string(),
            crate::util::country_code_as_str(&self.orig_country_code),
            self.resp_addr.to_string(),
            self.resp_port.to_string(),
            crate::util::country_code_as_str(&self.resp_country_code),
            self.proto.to_string(),
            timestamp::format_rfc3339(self.start_time).unwrap_or_default(),
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
    pub(super) fn new(time: Timestamp, fields: FtpEventFieldsStored) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            start_time: timestamp::from_i64_nanos(fields.start_time)
                .expect(timestamp::I64_NANOS_JIFF_INVARIANT),
            orig_addr: fields.orig_addr,
            orig_port: fields.orig_port,
            orig_country_code: fields.orig_country_code,
            resp_addr: fields.resp_addr,
            resp_port: fields.resp_port,
            resp_country_code: fields.resp_country_code,
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

impl BlocklistFtp {
    #[must_use]
    pub fn threat_level() -> ThreatLevel {
        ThreatLevel::Medium
    }
}

impl Match for BlocklistFtp {
    fn orig_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.orig_addr)
    }

    fn orig_port(&self) -> u16 {
        self.orig_port
    }

    fn orig_country_codes(&self) -> &[[u8; 2]] {
        std::slice::from_ref(&self.orig_country_code)
    }

    fn resp_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.resp_addr)
    }

    fn resp_port(&self) -> u16 {
        self.resp_port
    }

    fn resp_country_codes(&self) -> &[[u8; 2]] {
        std::slice::from_ref(&self.resp_country_code)
    }

    fn proto(&self) -> u8 {
        self.proto
    }

    fn category(&self) -> Option<EventCategory> {
        self.category
    }

    fn level(&self) -> ThreatLevel {
        Self::threat_level()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct FtpBruteForceFieldsLegacy {
        sensor: String,
        orig_addr: IpAddr,
        resp_addr: IpAddr,
        resp_port: u16,
        proto: u8,
        user_list: Vec<String>,
        start_time: i64,
        end_time: i64,
        is_internal: bool,
        confidence: f32,
        category: Option<EventCategory>,
    }

    #[test]
    fn ftp_bruteforce_bincode_compatibility() {
        let old = FtpBruteForceFieldsLegacy {
            sensor: "sensor".to_string(),
            orig_addr: IpAddr::from([127, 0, 0, 1]),
            resp_addr: IpAddr::from([127, 0, 0, 2]),
            resp_port: 21,
            proto: 6,
            user_list: vec!["user".to_string()],
            start_time: 77,
            end_time: 88,
            is_internal: true,
            confidence: 0.3,
            category: Some(EventCategory::CredentialAccess),
        };
        let bytes = bincode::serialize(&old).expect("legacy fields should serialize");
        let parsed: FtpBruteForceFields =
            bincode::deserialize(&bytes).expect("new fields should deserialize");
        assert_eq!(parsed.first_event_start_time, 77);
        assert_eq!(parsed.last_event_start_time, 88);
    }
}
