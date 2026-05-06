#![allow(clippy::module_name_repetitions)]
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr},
};

use attrievent::attribute::{RawEventAttrKind, WindowAttr};
use chrono::{DateTime, Utc, serde::ts_nanoseconds};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, ThreatLevel, TriageScore, common::Match};
use crate::event::common::{AttrValue, triage_scores_to_string};

// TODO: We plan to implement the triage feature only after we have cleaned up the range of
// values for the properties for each sysmon service.
macro_rules! find_window_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {
        if let RawEventAttrKind::Window(attr) = $raw_event_attr {
            let target_value = match attr {
                WindowAttr::Service => AttrValue::String(&$event.service),
                WindowAttr::AgentName => AttrValue::String(&$event.agent_name),
                WindowAttr::AgentId => AttrValue::String(&$event.agent_id),
                WindowAttr::ProcessGuid => AttrValue::String(&$event.process_guid),
                WindowAttr::ProcessId => AttrValue::UInt($event.process_id.into()),
                WindowAttr::Image => AttrValue::String(&$event.image),
                WindowAttr::User => AttrValue::String(&$event.user),
                WindowAttr::Content => AttrValue::String(&$event.content),
            };
            Some(target_value)
        } else {
            None
        }
    };
}

#[derive(Serialize, Deserialize)]
pub struct WindowsThreatFields {
    #[serde(with = "ts_nanoseconds")]
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub service: String,
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub user: String,
    pub content: String,
    pub db_name: String,
    pub rule_id: u32,
    pub matched_to: String,
    pub cluster_id: Option<u32>,
    pub attack_kind: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

#[derive(Deserialize, Serialize)]
pub struct WindowsThreatFieldsStored {
    #[serde(with = "ts_nanoseconds")]
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub service: String,
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub user: String,
    pub content: String,
    pub db_name: String,
    pub rule_id: u32,
    pub matched_to: String,
    pub cluster_id: Option<u32>,
    pub attack_kind: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl From<WindowsThreatFields> for WindowsThreatFieldsStored {
    fn from(value: WindowsThreatFields) -> Self {
        Self {
            time: value.time,
            sensor: value.sensor,
            service: value.service,
            agent_name: value.agent_name,
            agent_id: value.agent_id,
            process_guid: value.process_guid,
            process_id: value.process_id,
            image: value.image,
            user: value.user,
            content: value.content,
            db_name: value.db_name,
            rule_id: value.rule_id,
            matched_to: value.matched_to,
            cluster_id: value.cluster_id,
            attack_kind: value.attack_kind,
            confidence: value.confidence,
            category: value.category,
            triage_scores: value.triage_scores,
        }
    }
}

// image, user, content field enclosed with double quotes(\") instead of "{:?}"
impl WindowsThreatFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} sensor={:?} service={:?} agent_name={:?} agent_id={:?} process_guid={:?} process_id={:?} image=\"{}\" user=\"{}\" content=\"{}\" db_name={:?} rule_id={:?} matched_to={:?} cluster_id={:?} attack_kind={:?} confidence={:?}",
            self.category.as_ref().map_or_else(
                || "Unspecified".to_string(),
                std::string::ToString::to_string
            ),
            self.sensor,
            self.service,
            self.agent_name,
            self.agent_id,
            self.process_guid,
            self.process_id.to_string(),
            self.image,
            self.user,
            self.content,
            self.db_name,
            self.rule_id.to_string(),
            self.matched_to,
            self.cluster_id.map_or("-".to_string(), |s| s.to_string()),
            self.attack_kind,
            self.confidence.to_string()
        )
    }
}

pub struct WindowsThreat {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub service: String,
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub user: String,
    pub content: String,
    pub db_name: String,
    pub rule_id: u32,
    pub matched_to: String,
    pub cluster_id: Option<u32>,
    pub attack_kind: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl WindowsThreat {
    pub(super) fn new(time: DateTime<Utc>, fields: WindowsThreatFieldsStored) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            service: fields.service,
            agent_name: fields.agent_name,
            agent_id: fields.agent_id,
            process_guid: fields.process_guid,
            process_id: fields.process_id,
            image: fields.image,
            user: fields.user,
            content: fields.content,
            db_name: fields.db_name,
            rule_id: fields.rule_id,
            matched_to: fields.matched_to,
            cluster_id: fields.cluster_id,
            attack_kind: fields.attack_kind,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: fields.triage_scores,
        }
    }

    #[must_use]
    pub fn threat_level() -> ThreatLevel {
        ThreatLevel::Medium
    }
}

impl fmt::Display for WindowsThreat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} service={:?} agent_name={:?} agent_id={:?} process_guid={:?} process_id={:?} image=\"{}\" user=\"{}\" content=\"{}\" db_name={:?} rule_id={:?} matched_to={:?} cluster_id={:?} attack_kind={:?} confidence={:?} triage_scores={:?}",
            self.sensor,
            self.service,
            self.agent_name,
            self.agent_id,
            self.process_guid,
            self.process_id.to_string(),
            self.image,
            self.user,
            self.content,
            self.db_name,
            self.rule_id.to_string(),
            self.matched_to,
            self.cluster_id.map_or("-".to_string(), |s| s.to_string()),
            self.attack_kind,
            self.confidence.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

// TODO: Make new Match trait for Windows threat events
impl Match for WindowsThreat {
    fn sensor(&self) -> &str {
        &self.sensor
    }

    fn src_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    }

    fn src_port(&self) -> u16 {
        0
    }

    fn dst_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&IpAddr::V4(Ipv4Addr::UNSPECIFIED))
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

    fn level(&self) -> ThreatLevel {
        Self::threat_level()
    }

    fn kind(&self) -> &'static str {
        "windows threat"
    }

    fn confidence(&self) -> Option<f32> {
        Some(self.confidence)
    }

    fn learning_method(&self) -> LearningMethod {
        LearningMethod::Unsupervised
    }

    fn find_attr_by_kind(&self, raw_event_attr: RawEventAttrKind) -> Option<AttrValue<'_>> {
        find_window_attr_by_kind!(self, raw_event_attr)
    }
}
