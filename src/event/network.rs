#![allow(clippy::module_name_repetitions)]
use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{NetworkAttr, RawEventAttrKind};
use chrono::{DateTime, Utc, serde::ts_nanoseconds};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::event::common::{AttrValue, triage_scores_to_string};

// TODO: We plan to implement the triage feature after detection events from other network
// protocols are consolidated into `NetworkThreat` events.
macro_rules! find_network_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {
        if let RawEventAttrKind::Network(attr) = $raw_event_attr {
            let target_value = match attr {
                NetworkAttr::SrcAddr => AttrValue::Addr($event.orig_addr),
                NetworkAttr::SrcPort => AttrValue::UInt($event.orig_port.into()),
                NetworkAttr::DstAddr => AttrValue::Addr($event.resp_addr),
                NetworkAttr::DstPort => AttrValue::UInt($event.resp_port.into()),
                NetworkAttr::Proto => AttrValue::UInt($event.proto.into()),
                NetworkAttr::Duration => AttrValue::SInt($event.duration),
                NetworkAttr::OrigPkts => AttrValue::UInt($event.orig_pkts),
                NetworkAttr::RespPkts => AttrValue::UInt($event.resp_pkts),
                NetworkAttr::OrigL2Bytes => AttrValue::UInt($event.orig_l2_bytes),
                NetworkAttr::RespL2Bytes => AttrValue::UInt($event.resp_l2_bytes),
                NetworkAttr::Content => AttrValue::String(&$event.content),
            };
            Some(target_value)
        } else {
            None
        }
    };
}

#[derive(Serialize, Deserialize)]
pub struct NetworkThreat {
    #[serde(with = "ts_nanoseconds")]
    pub time: DateTime<Utc>,
    pub sensor: String,
    #[serde(default)]
    pub src_country_code: [u8; 2],
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    #[serde(default)]
    pub dst_country_code: [u8; 2],
    pub resp_port: u16,
    pub proto: u8,
    pub service: String,
    #[serde(with = "ts_nanoseconds")]
    pub start_time: DateTime<Utc>,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub content: String,
    pub db_name: String,
    pub rule_id: u32,
    pub matched_to: String,
    pub cluster_id: Option<usize>,
    pub attack_kind: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl NetworkThreat {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        format!(
            "category={:?} sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} service={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} content={:?} db_name={:?} rule_id={:?} matched_to={:?} cluster_id={:?} attack_kind={:?} confidence={:?}",
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
            self.service,
            self.start_time.to_rfc3339(),
            self.duration.to_string(),
            self.orig_pkts.to_string(),
            self.resp_pkts.to_string(),
            self.orig_l2_bytes.to_string(),
            self.resp_l2_bytes.to_string(),
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

impl fmt::Display for NetworkThreat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} service={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} content={:?} db_name={:?} rule_id={:?} matched_to={:?} cluster_id={:?} attack_kind={:?} confidence={:?} triage_scores={:?}",
            self.sensor,
            self.orig_addr.to_string(),
            self.orig_port.to_string(),
            self.resp_addr.to_string(),
            self.resp_port.to_string(),
            self.proto.to_string(),
            self.service,
            self.start_time.to_rfc3339(),
            self.duration.to_string(),
            self.orig_pkts.to_string(),
            self.resp_pkts.to_string(),
            self.orig_l2_bytes.to_string(),
            self.resp_l2_bytes.to_string(),
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

impl Match for NetworkThreat {
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
        "network threat"
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
        find_network_attr_by_kind!(self, raw_event_attr)
    }
}
