use std::{fmt, net::IpAddr};

use attrievent::attribute::{ConnAttr, RawEventAttrKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, ThreatLevel, TriageScore, common::Match};
use crate::event::common::{AttrValue, triage_scores_to_string};

#[derive(Serialize, Deserialize)]
pub struct UnusualDestinationPatternFields {
    pub sensor: String,
    pub sampling_window_start_time: i64,
    pub sampling_window_end_time: i64,
    pub destination_ips: Vec<IpAddr>,
    pub count: usize,
    pub expected_mean: f64,
    pub std_deviation: f64,
    pub z_score: f64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

pub(crate) type UnusualDestinationPatternFieldsStored = UnusualDestinationPatternFieldsStoredV0_46;

#[derive(Deserialize, Serialize)]
pub(crate) struct UnusualDestinationPatternFieldsStoredV0_46 {
    pub sensor: String,
    pub sampling_window_start_time: i64,
    pub sampling_window_end_time: i64,
    pub destination_ips: Vec<IpAddr>,
    pub resp_country_codes: Vec<[u8; 2]>,
    pub count: usize,
    pub expected_mean: f64,
    pub std_deviation: f64,
    pub z_score: f64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl From<UnusualDestinationPatternFields> for UnusualDestinationPatternFieldsStored {
    fn from(value: UnusualDestinationPatternFields) -> Self {
        let destination_ip_count = value.destination_ips.len();
        Self {
            sensor: value.sensor,
            sampling_window_start_time: value.sampling_window_start_time,
            sampling_window_end_time: value.sampling_window_end_time,
            destination_ips: value.destination_ips,
            resp_country_codes: vec![crate::util::COUNTRY_CODE_PENDING; destination_ip_count],
            count: value.count,
            expected_mean: value.expected_mean,
            std_deviation: value.std_deviation,
            z_score: value.z_score,
            confidence: value.confidence,
            category: value.category,
        }
    }
}

impl UnusualDestinationPatternFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let sampling_window_start_time_dt =
            DateTime::from_timestamp_nanos(self.sampling_window_start_time);
        let sampling_window_end_time_dt =
            DateTime::from_timestamp_nanos(self.sampling_window_end_time);
        format!(
            "category={:?} sensor={:?} sampling_window_start_time={:?} sampling_window_end_time={:?} destination_ips={:?} count={:?} expected_mean={:?} std_deviation={:?} z_score={:?} confidence={:?}",
            self.category.as_ref().map_or_else(
                || "Unspecified".to_string(),
                std::string::ToString::to_string
            ),
            self.sensor,
            sampling_window_start_time_dt.to_rfc3339(),
            sampling_window_end_time_dt.to_rfc3339(),
            format_ip_vec(&self.destination_ips),
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
    pub sampling_window_start_time: DateTime<Utc>,
    pub sampling_window_end_time: DateTime<Utc>,
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
            "sensor={:?} sampling_window_start_time={:?} sampling_window_end_time={:?} destination_ips={:?} resp_country_codes={:?} count={:?} expected_mean={:?} std_deviation={:?} z_score={:?} triage_scores={:?}",
            self.sensor,
            self.sampling_window_start_time.to_rfc3339(),
            self.sampling_window_end_time.to_rfc3339(),
            format_ip_vec(&self.destination_ips),
            crate::util::country_codes_to_string(&self.resp_country_codes),
            self.count.to_string(),
            self.expected_mean.to_string(),
            self.std_deviation.to_string(),
            self.z_score.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl UnusualDestinationPattern {
    pub(super) fn new(time: DateTime<Utc>, fields: UnusualDestinationPatternFieldsStored) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            sampling_window_start_time: DateTime::from_timestamp_nanos(
                fields.sampling_window_start_time,
            ),
            sampling_window_end_time: DateTime::from_timestamp_nanos(
                fields.sampling_window_end_time,
            ),
            destination_ips: fields.destination_ips,
            resp_country_codes: fields.resp_country_codes.clone(),
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

impl UnusualDestinationPattern {
    #[must_use]
    pub fn threat_level() -> ThreatLevel {
        ThreatLevel::Medium
    }
}

impl Match for UnusualDestinationPattern {
    fn src_addrs(&self) -> &[IpAddr] {
        &[]
    }

    fn src_port(&self) -> u16 {
        0
    }

    fn orig_country_codes(&self) -> &[[u8; 2]] {
        &[]
    }

    fn dst_addrs(&self) -> &[IpAddr] {
        &self.destination_ips
    }

    fn dst_port(&self) -> u16 {
        0
    }

    fn resp_country_codes(&self) -> &[[u8; 2]] {
        &self.resp_country_codes
    }

    fn proto(&self) -> u8 {
        0
    }

    fn category(&self) -> Option<EventCategory> {
        self.category
    }

    fn level(&self) -> ThreatLevel {
        Self::threat_level()
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use chrono::TimeZone;

    use super::*;

    fn sample_fields(category: Option<EventCategory>) -> UnusualDestinationPatternFields {
        UnusualDestinationPatternFields {
            sensor: "sensor".to_string(),
            sampling_window_start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 1)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            sampling_window_end_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 2)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            destination_ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            count: 1,
            expected_mean: 1.0,
            std_deviation: 0.1,
            z_score: 2.0,
            confidence: 0.3,
            category,
        }
    }

    #[test]
    fn unusual_destination_pattern_fields_syslog_rfc5424() {
        let fields = sample_fields(Some(EventCategory::Reconnaissance));
        let syslog = fields.syslog_rfc5424();
        assert!(syslog.contains("sampling_window_start_time=\"1970-01-01T00:01:01+00:00\""));
        assert!(syslog.contains("sampling_window_end_time=\"1970-01-01T00:01:02+00:00\""));
        assert!(syslog.contains("category=\"Reconnaissance\""));
        assert!(syslog.contains("destination_ips=\"127.0.0.1\""));
    }

    #[test]
    fn unusual_destination_pattern_fields_syslog_rfc5424_unspecified_category() {
        let fields = sample_fields(None);
        let syslog = fields.syslog_rfc5424();
        assert!(syslog.contains("category=\"Unspecified\""));
    }

    #[test]
    fn unusual_destination_pattern_fields_stored_from() {
        let fields = sample_fields(Some(EventCategory::Reconnaissance));
        let start = fields.sampling_window_start_time;
        let end = fields.sampling_window_end_time;
        let stored: UnusualDestinationPatternFieldsStored = fields.into();
        assert_eq!(stored.sampling_window_start_time, start);
        assert_eq!(stored.sampling_window_end_time, end);
        assert_eq!(
            stored.resp_country_codes.len(),
            stored.destination_ips.len()
        );
    }

    #[derive(Serialize)]
    struct UnusualDestinationPatternFieldsLegacy {
        sensor: String,
        start_time: i64,
        end_time: i64,
        destination_ips: Vec<IpAddr>,
        count: usize,
        expected_mean: f64,
        std_deviation: f64,
        z_score: f64,
        confidence: f32,
        category: Option<EventCategory>,
    }

    #[test]
    fn unusual_destination_pattern_bincode_compatibility() {
        let old = UnusualDestinationPatternFieldsLegacy {
            sensor: "sensor".to_string(),
            start_time: 777,
            end_time: 888,
            destination_ips: vec![IpAddr::from([127, 0, 0, 1])],
            count: 1,
            expected_mean: 1.0,
            std_deviation: 0.1,
            z_score: 2.0,
            confidence: 0.3,
            category: Some(EventCategory::Reconnaissance),
        };
        let bytes = bincode::serialize(&old).expect("legacy fields should serialize");
        let parsed: UnusualDestinationPatternFields =
            bincode::deserialize(&bytes).expect("new fields should deserialize");
        assert_eq!(parsed.sampling_window_start_time, 777);
        assert_eq!(parsed.sampling_window_end_time, 888);
    }
}
