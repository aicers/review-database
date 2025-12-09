use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{MqttAttr, RawEventAttrKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::event::common::{AttrValue, triage_scores_to_string};

macro_rules! find_mqtt_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {{
        if let RawEventAttrKind::Mqtt(attr) = $raw_event_attr {
            let target_value = match attr {
                MqttAttr::SrcAddr => AttrValue::Addr($event.src_addr),
                MqttAttr::SrcPort => AttrValue::UInt($event.src_port.into()),
                MqttAttr::DstAddr => AttrValue::Addr($event.dst_addr),
                MqttAttr::DstPort => AttrValue::UInt($event.dst_port.into()),
                MqttAttr::Proto => AttrValue::UInt($event.proto.into()),
                MqttAttr::Duration => AttrValue::SInt($event.duration),
                MqttAttr::OrigPkts => AttrValue::UInt($event.orig_pkts),
                MqttAttr::RespPkts => AttrValue::UInt($event.resp_pkts),
                MqttAttr::OrigL2Bytes => AttrValue::UInt($event.orig_l2_bytes),
                MqttAttr::RespL2Bytes => AttrValue::UInt($event.resp_l2_bytes),
                MqttAttr::Protocol => AttrValue::String(&$event.protocol),
                MqttAttr::Version => AttrValue::UInt($event.version.into()),
                MqttAttr::ClientId => AttrValue::String(&$event.client_id),
                MqttAttr::ConnackReason => AttrValue::UInt($event.connack_reason.into()),
                MqttAttr::Subscribe => {
                    AttrValue::VecString(std::borrow::Cow::Borrowed(&$event.subscribe))
                }
                MqttAttr::SubackReason => AttrValue::VecUInt(std::borrow::Cow::Owned(
                    $event
                        .suback_reason
                        .iter()
                        .map(|val| u64::from(*val))
                        .collect(),
                )),
            };
            Some(target_value)
        } else {
            None
        }
    }};
}

pub type BlocklistMqttFields = BlocklistMqttFieldsV0_42;

#[derive(Serialize, Deserialize)]
pub struct BlocklistMqttFieldsV0_42 {
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
    pub protocol: String,
    pub version: u8,
    pub client_id: String,
    pub connack_reason: u8,
    pub subscribe: Vec<String>,
    pub suback_reason: Vec<u8>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl BlocklistMqttFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);

        format!(
            "category={:?} sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} protocol={:?} version={:?} client_id={:?} connack_reason={:?} subscribe={:?} suback_reason={:?} confidence={:?}",
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
            self.protocol,
            self.version.to_string(),
            self.client_id,
            self.connack_reason.to_string(),
            self.subscribe.join(","),
            String::from_utf8_lossy(&self.suback_reason),
            self.confidence.to_string(),
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct BlocklistMqtt {
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
    pub protocol: String,
    pub version: u8,
    pub client_id: String,
    pub connack_reason: u8,
    pub subscribe: Vec<String>,
    pub suback_reason: Vec<u8>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlocklistMqtt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} src_addr={:?} src_port={:?} dst_addr={:?} dst_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} protocol={:?} version={:?} client_id={:?} connack_reason={:?} subscribe={:?} suback_reason={:?} triage_scores={:?}",
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
            self.protocol,
            self.version.to_string(),
            self.client_id,
            self.connack_reason.to_string(),
            self.subscribe.join(","),
            String::from_utf8_lossy(&self.suback_reason),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl BlocklistMqtt {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistMqttFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            src_addr: fields.src_addr,
            src_port: fields.src_port,
            dst_addr: fields.dst_addr,
            dst_port: fields.dst_port,
            proto: fields.proto,
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            duration: fields.duration,
            orig_pkts: fields.orig_pkts,
            resp_pkts: fields.resp_pkts,
            orig_l2_bytes: fields.orig_l2_bytes,
            resp_l2_bytes: fields.resp_l2_bytes,
            protocol: fields.protocol,
            version: fields.version,
            client_id: fields.client_id,
            connack_reason: fields.connack_reason,
            subscribe: fields.subscribe,
            suback_reason: fields.suback_reason,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistMqtt {
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
        MEDIUM
    }

    fn kind(&self) -> &'static str {
        "blocklist mqtt"
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
        find_mqtt_attr_by_kind!(self, raw_event_attr)
    }
}
