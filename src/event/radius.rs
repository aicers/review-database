use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{RadiusAttr, RawEventAttrKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::event::common::{AttrValue, triage_scores_to_string};

macro_rules! find_radius_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {{
        if let RawEventAttrKind::Radius(attr) = $raw_event_attr {
            let target_value = match attr {
                RadiusAttr::SrcAddr => AttrValue::Addr($event.orig_addr),
                RadiusAttr::SrcPort => AttrValue::UInt($event.orig_port.into()),
                RadiusAttr::DstAddr => AttrValue::Addr($event.resp_addr),
                RadiusAttr::DstPort => AttrValue::UInt($event.resp_port.into()),
                RadiusAttr::Proto => AttrValue::UInt($event.proto.into()),
                RadiusAttr::Duration => AttrValue::SInt($event.duration),
                RadiusAttr::OrigPkts => AttrValue::UInt($event.orig_pkts),
                RadiusAttr::RespPkts => AttrValue::UInt($event.resp_pkts),
                RadiusAttr::OrigL2Bytes => AttrValue::UInt($event.orig_l2_bytes),
                RadiusAttr::RespL2Bytes => AttrValue::UInt($event.resp_l2_bytes),
                RadiusAttr::Id => AttrValue::UInt($event.id.into()),
                RadiusAttr::Code => AttrValue::UInt($event.code.into()),
                RadiusAttr::RespCode => AttrValue::UInt($event.resp_code.into()),
                RadiusAttr::Auth => AttrValue::String(&$event.auth),
                RadiusAttr::RespAuth => AttrValue::String(&$event.resp_auth),
                RadiusAttr::UserName => AttrValue::VecRaw(&$event.user_name),
                RadiusAttr::UserPasswd => AttrValue::VecRaw(&$event.user_passwd),
                RadiusAttr::ChapPasswd => AttrValue::VecRaw(&$event.chap_passwd),
                RadiusAttr::NasIp => AttrValue::Addr($event.nas_ip),
                RadiusAttr::NasPort => AttrValue::UInt($event.nas_port.into()),
                RadiusAttr::State => AttrValue::VecRaw(&$event.state),
                RadiusAttr::NasId => AttrValue::VecRaw(&$event.nas_id),
                RadiusAttr::NasPortType => AttrValue::UInt($event.nas_port_type.into()),
                RadiusAttr::Message => AttrValue::String(&$event.message),
            };
            Some(target_value)
        } else {
            None
        }
    }};
}

pub type BlocklistRadiusFields = BlocklistRadiusFieldsV0_44;

#[derive(Serialize, Deserialize)]
pub struct BlocklistRadiusFieldsV0_44 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub orig_country_code: [u8; 2],
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub resp_country_code: [u8; 2],
    pub proto: u8,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub id: u8,
    pub code: u8,
    pub resp_code: u8,
    pub auth: String,
    pub resp_auth: String,
    pub user_name: Vec<u8>,
    pub user_passwd: Vec<u8>,
    pub chap_passwd: Vec<u8>,
    pub nas_ip: IpAddr,
    pub nas_port: u32,
    pub state: Vec<u8>,
    pub nas_id: Vec<u8>,
    pub nas_port_type: u32,
    pub message: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl BlocklistRadiusFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);
        format!(
            "category={:?} sensor={:?} orig_addr={:?} orig_port={:?} orig_country_code={:?} resp_addr={:?} resp_port={:?} resp_country_code={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} id={:?} code={:?} resp_code={:?} auth={:?} resp_auth={:?} user_name={:?} user_passwd={:?} chap_passwd={:?} nas_ip={:?} nas_port={:?} state={:?} nas_id={:?} nas_port_type={:?} message={:?} confidence={:?}",
            self.category.as_ref().map_or_else(
                || "Unspecified".to_string(),
                std::string::ToString::to_string
            ),
            self.sensor,
            self.orig_addr.to_string(),
            self.orig_port.to_string(),
            std::str::from_utf8(&self.orig_country_code).unwrap_or("XX"),
            self.resp_addr.to_string(),
            self.resp_port.to_string(),
            std::str::from_utf8(&self.resp_country_code).unwrap_or("XX"),
            self.proto.to_string(),
            start_time_dt.to_rfc3339(),
            self.duration.to_string(),
            self.orig_pkts.to_string(),
            self.resp_pkts.to_string(),
            self.orig_l2_bytes.to_string(),
            self.resp_l2_bytes.to_string(),
            self.id.to_string(),
            self.code.to_string(),
            self.resp_code.to_string(),
            self.auth,
            self.resp_auth,
            String::from_utf8_lossy(&self.user_name),
            String::from_utf8_lossy(&self.user_passwd),
            String::from_utf8_lossy(&self.chap_passwd),
            self.nas_ip.to_string(),
            self.nas_port.to_string(),
            String::from_utf8_lossy(&self.state),
            String::from_utf8_lossy(&self.nas_id),
            self.nas_port_type.to_string(),
            self.message,
            self.confidence.to_string(),
        )
    }
}

pub struct BlocklistRadius {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub orig_country_code: [u8; 2],
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_country_code: [u8; 2],
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub id: u8,
    pub code: u8,
    pub resp_code: u8,
    pub auth: String,
    pub resp_auth: String,
    pub user_name: Vec<u8>,
    pub user_passwd: Vec<u8>,
    pub chap_passwd: Vec<u8>,
    pub nas_ip: IpAddr,
    pub nas_port: u32,
    pub state: Vec<u8>,
    pub nas_id: Vec<u8>,
    pub nas_port_type: u32,
    pub message: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlocklistRadius {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let start_time_str = self.start_time.to_rfc3339();

        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} orig_country_code={:?} resp_addr={:?} resp_port={:?} resp_country_code={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} id={:?} code={:?} resp_code={:?} auth={:?} resp_auth={:?} user_name={:?} user_passwd={:?} chap_passwd={:?} nas_ip={:?} nas_port={:?} state={:?} nas_id={:?} nas_port_type={:?} message={:?} triage_scores={:?}",
            self.sensor,
            self.orig_addr.to_string(),
            self.orig_port.to_string(),
            std::str::from_utf8(&self.orig_country_code).unwrap_or("XX"),
            self.resp_addr.to_string(),
            self.resp_port.to_string(),
            std::str::from_utf8(&self.resp_country_code).unwrap_or("XX"),
            self.proto.to_string(),
            start_time_str,
            self.duration.to_string(),
            self.orig_pkts.to_string(),
            self.resp_pkts.to_string(),
            self.orig_l2_bytes.to_string(),
            self.resp_l2_bytes.to_string(),
            self.id.to_string(),
            self.code.to_string(),
            self.resp_code.to_string(),
            self.auth,
            self.resp_auth,
            String::from_utf8_lossy(&self.user_name),
            String::from_utf8_lossy(&self.user_passwd),
            String::from_utf8_lossy(&self.chap_passwd),
            self.nas_ip.to_string(),
            self.nas_port.to_string(),
            String::from_utf8_lossy(&self.state),
            String::from_utf8_lossy(&self.nas_id),
            self.nas_port_type.to_string(),
            self.message,
            triage_scores_to_string(self.triage_scores.as_ref()),
        )
    }
}

impl BlocklistRadius {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistRadiusFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            orig_country_code: fields.orig_country_code,
            orig_addr: fields.orig_addr,
            orig_port: fields.orig_port,
            resp_addr: fields.resp_addr,
            resp_country_code: fields.resp_country_code,
            resp_port: fields.resp_port,
            proto: fields.proto,
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            duration: fields.duration,
            orig_pkts: fields.orig_pkts,
            resp_pkts: fields.resp_pkts,
            orig_l2_bytes: fields.orig_l2_bytes,
            resp_l2_bytes: fields.resp_l2_bytes,
            id: fields.id,
            code: fields.code,
            resp_code: fields.resp_code,
            auth: fields.auth,
            resp_auth: fields.resp_auth,
            user_name: fields.user_name,
            user_passwd: fields.user_passwd,
            chap_passwd: fields.chap_passwd,
            nas_ip: fields.nas_ip,
            nas_port: fields.nas_port,
            state: fields.state,
            nas_id: fields.nas_id,
            nas_port_type: fields.nas_port_type,
            message: fields.message,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistRadius {
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
        "blocklist radius"
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

    fn find_attr_by_kind(
        &self,
        raw_event_attr: attrievent::attribute::RawEventAttrKind,
    ) -> Option<AttrValue<'_>> {
        find_radius_attr_by_kind!(self, raw_event_attr)
    }
}
