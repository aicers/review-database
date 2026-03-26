use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{ConnAttr, RawEventAttrKind};
use chrono::{DateTime, Utc};
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::event::common::{AttrValue, triage_scores_to_string};

pub type UnusualDestinationPatternFields = UnusualDestinationPatternFieldsV0_44;

#[derive(Serialize, Deserialize)]
pub struct UnusualDestinationPatternFieldsV0_44 {
    pub sensor: String,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub start_time: i64,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub end_time: i64,
    pub destination_ips: Vec<IpAddr>,
    pub resp_country_codes: Vec<[u8; 2]>,
    pub count: usize,
    pub expected_mean: f64,
    pub std_deviation: f64,
    pub z_score: f64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl UnusualDestinationPatternFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);
        let end_time_dt = DateTime::from_timestamp_nanos(self.end_time);
        format!(
            "category={:?} sensor={:?} start_time={:?} end_time={:?} destination_ips={:?} resp_country_codes={:?} count={:?} expected_mean={:?} std_deviation={:?} z_score={:?} confidence={:?}",
            self.category.as_ref().map_or_else(
                || "Unspecified".to_string(),
                std::string::ToString::to_string
            ),
            self.sensor,
            start_time_dt.to_rfc3339(),
            end_time_dt.to_rfc3339(),
            format_ip_vec(&self.destination_ips),
            self.resp_country_codes
                .iter()
                .map(|code| std::str::from_utf8(code).unwrap_or("XX"))
                .join(","),
            self.count.to_string(),
            self.expected_mean.to_string(),
            self.std_deviation.to_string(),
            self.z_score.to_string(),
            self.confidence.to_string(),
        )
    }
}

/// Formats a Vec<IpAddr> as a comma-separated list of IP addresses
fn format_ip_vec(ips: &[IpAddr]) -> String {
    ips.iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

pub struct UnusualDestinationPattern {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub destination_ips: Vec<IpAddr>,
    pub resp_country_codes: Vec<[u8; 2]>,
    pub count: usize,
    pub expected_mean: f64,
    pub std_deviation: f64,
    pub z_score: f64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for UnusualDestinationPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} start_time={:?} end_time={:?} destination_ips={:?} resp_country_codes={:?} count={:?} expected_mean={:?} std_deviation={:?} z_score={:?} triage_scores={:?}",
            self.sensor,
            self.start_time.to_rfc3339(),
            self.end_time.to_rfc3339(),
            format_ip_vec(&self.destination_ips),
            self.resp_country_codes
                .iter()
                .map(|code| std::str::from_utf8(code).unwrap_or("XX"))
                .join(","),
            self.count.to_string(),
            self.expected_mean.to_string(),
            self.std_deviation.to_string(),
            self.z_score.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl UnusualDestinationPattern {
    pub(super) fn new(time: DateTime<Utc>, fields: UnusualDestinationPatternFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            end_time: DateTime::from_timestamp_nanos(fields.end_time),
            destination_ips: fields.destination_ips,
            resp_country_codes: fields.resp_country_codes,
            count: fields.count,
            expected_mean: fields.expected_mean,
            std_deviation: fields.std_deviation,
            z_score: fields.z_score,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for UnusualDestinationPattern {
    fn src_addrs(&self) -> &[IpAddr] {
        &[]
    }

    fn src_port(&self) -> u16 {
        0
    }

    fn dst_addrs(&self) -> &[IpAddr] {
        &self.destination_ips
    }

    fn dst_port(&self) -> u16 {
        0
    }

    fn proto(&self) -> u8 {
        0
    }

    fn category(&self) -> Option<EventCategory> {
        self.category
    }

    fn level(&self) -> NonZeroU8 {
        MEDIUM
    }

    fn kind(&self) -> &'static str {
        "unusual destination pattern"
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
        if let RawEventAttrKind::Conn(attr) = raw_event_attr
            && attr == ConnAttr::DstAddr
        {
            Some(AttrValue::VecAddr(std::borrow::Cow::Borrowed(
                &self.destination_ips,
            )))
        } else {
            None
        }
    }
}
