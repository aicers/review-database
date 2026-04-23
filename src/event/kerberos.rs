use std::{fmt, net::IpAddr};

use attrievent::attribute::{KerberosAttr, RawEventAttrKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, ThreatLevel, TriageScore, common::Match};
use crate::event::common::{AttrValue, triage_scores_to_string};

macro_rules! find_kerberos_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {{
        if let RawEventAttrKind::Kerberos(attr) = $raw_event_attr {
            let target_value = match attr {
                KerberosAttr::SrcAddr => AttrValue::Addr($event.orig_addr),
                KerberosAttr::SrcPort => AttrValue::UInt($event.orig_port.into()),
                KerberosAttr::DstAddr => AttrValue::Addr($event.resp_addr),
                KerberosAttr::DstPort => AttrValue::UInt($event.resp_port.into()),
                KerberosAttr::Proto => AttrValue::UInt($event.proto.into()),
                KerberosAttr::Duration => AttrValue::SInt($event.duration),
                KerberosAttr::OrigPkts => AttrValue::UInt($event.orig_pkts),
                KerberosAttr::RespPkts => AttrValue::UInt($event.resp_pkts),
                KerberosAttr::OrigL2Bytes => AttrValue::UInt($event.orig_l2_bytes),
                KerberosAttr::RespL2Bytes => AttrValue::UInt($event.resp_l2_bytes),
                KerberosAttr::ClientTime => AttrValue::SInt($event.client_time),
                KerberosAttr::ServerTime => AttrValue::SInt($event.server_time),
                KerberosAttr::ErrorCode => AttrValue::UInt($event.error_code.into()),
                KerberosAttr::ClientRealm => AttrValue::String(&$event.client_realm),
                KerberosAttr::CnameType => AttrValue::UInt($event.cname_type.into()),
                KerberosAttr::ClientName => {
                    AttrValue::VecString(std::borrow::Cow::Borrowed(&$event.client_name))
                }
                KerberosAttr::Realm => AttrValue::String(&$event.realm),
                KerberosAttr::SnameType => AttrValue::UInt($event.sname_type.into()),
                KerberosAttr::ServiceName => {
                    AttrValue::VecString(std::borrow::Cow::Borrowed(&$event.service_name))
                }
            };
            Some(target_value)
        } else {
            None
        }
    }};
}

#[derive(Serialize, Deserialize)]
pub struct BlocklistKerberosFields {
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
    pub client_time: i64,
    pub server_time: i64,
    pub error_code: u32,
    pub client_realm: String,
    pub cname_type: u8,
    pub client_name: Vec<String>,
    pub realm: String,
    pub sname_type: u8,
    pub service_name: Vec<String>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

pub(crate) type BlocklistKerberosFieldsStored = BlocklistKerberosFieldsStoredV0_42;

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistKerberosFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub client_time: i64,
    pub server_time: i64,
    pub error_code: u32,
    pub client_realm: String,
    pub cname_type: u8,
    pub client_name: Vec<String>,
    pub realm: String,
    pub sname_type: u8,
    pub service_name: Vec<String>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl From<BlocklistKerberosFields> for BlocklistKerberosFieldsStored {
    fn from(value: BlocklistKerberosFields) -> Self {
        Self {
            sensor: value.sensor,
            orig_addr: value.orig_addr,
            orig_port: value.orig_port,
            resp_addr: value.resp_addr,
            resp_port: value.resp_port,
            proto: value.proto,
            start_time: value.start_time,
            duration: value.duration,
            orig_pkts: value.orig_pkts,
            resp_pkts: value.resp_pkts,
            orig_l2_bytes: value.orig_l2_bytes,
            resp_l2_bytes: value.resp_l2_bytes,
            client_time: value.client_time,
            server_time: value.server_time,
            error_code: value.error_code,
            client_realm: value.client_realm,
            cname_type: value.cname_type,
            client_name: value.client_name,
            realm: value.realm,
            sname_type: value.sname_type,
            service_name: value.service_name,
            confidence: value.confidence,
            category: value.category,
        }
    }
}

impl BlocklistKerberosFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);
        format!(
            "category={:?} sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} client_time={:?} server_time={:?} error_code={:?} client_realm={:?} cname_type={:?} client_name={:?} realm={:?} sname_type={:?} service_name={:?} confidence={:?}",
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
            self.client_time.to_string(),
            self.server_time.to_string(),
            self.error_code.to_string(),
            self.client_realm,
            self.cname_type.to_string(),
            self.client_name.join(","),
            self.realm,
            self.sname_type.to_string(),
            self.service_name.join(","),
            self.confidence.to_string()
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct BlocklistKerberos {
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
    pub client_time: i64,
    pub server_time: i64,
    pub error_code: u32,
    pub client_realm: String,
    pub cname_type: u8,
    pub client_name: Vec<String>,
    pub realm: String,
    pub sname_type: u8,
    pub service_name: Vec<String>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlocklistKerberos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} client_time={:?} server_time={:?} error_code={:?} client_realm={:?} cname_type={:?} client_name={:?} realm={:?} sname_type={:?} service_name={:?} triage_scores={:?}",
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
            self.client_time.to_string(),
            self.server_time.to_string(),
            self.error_code.to_string(),
            self.client_realm,
            self.cname_type.to_string(),
            self.client_name.join(","),
            self.realm,
            self.sname_type.to_string(),
            self.service_name.join(","),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl BlocklistKerberos {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistKerberosFieldsStored) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            orig_addr: fields.orig_addr,
            orig_port: fields.orig_port,
            resp_addr: fields.resp_addr,
            resp_port: fields.resp_port,
            proto: fields.proto,
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            duration: fields.duration,
            orig_pkts: fields.orig_pkts,
            resp_pkts: fields.resp_pkts,
            orig_l2_bytes: fields.orig_l2_bytes,
            resp_l2_bytes: fields.resp_l2_bytes,
            client_time: fields.client_time,
            server_time: fields.server_time,
            error_code: fields.error_code,
            client_realm: fields.client_realm,
            cname_type: fields.cname_type,
            client_name: fields.client_name,
            realm: fields.realm,
            sname_type: fields.sname_type,
            service_name: fields.service_name,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl BlocklistKerberos {
    #[must_use]
    pub fn threat_level() -> ThreatLevel {
        ThreatLevel::Medium
    }
}

impl Match for BlocklistKerberos {
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

    fn level(&self) -> ThreatLevel {
        Self::threat_level()
    }

    fn kind(&self) -> &'static str {
        "blocklist kerberos"
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
        find_kerberos_attr_by_kind!(self, raw_event_attr)
    }
}
