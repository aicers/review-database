use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{DhcpAttr, RawEventAttrKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{
    EventCategory, LearningMethod, MEDIUM, TriageScore,
    common::{AttrValue, Match},
};
use crate::event::common::{to_hardware_address, triage_scores_to_string, vector_to_string};

macro_rules! find_dhcp_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {{
        if let RawEventAttrKind::Dhcp(attr) = $raw_event_attr {
            let target_value = match attr {
                DhcpAttr::SrcAddr => AttrValue::Addr($event.orig_addr),
                DhcpAttr::SrcPort => AttrValue::UInt($event.orig_port.into()),
                DhcpAttr::DstAddr => AttrValue::Addr($event.resp_addr),
                DhcpAttr::DstPort => AttrValue::UInt($event.resp_port.into()),
                DhcpAttr::Proto => AttrValue::UInt($event.proto.into()),
                DhcpAttr::Duration => AttrValue::SInt($event.duration),
                DhcpAttr::OrigPkts => AttrValue::UInt($event.orig_pkts),
                DhcpAttr::RespPkts => AttrValue::UInt($event.resp_pkts),
                DhcpAttr::OrigL2Bytes => AttrValue::UInt($event.orig_l2_bytes),
                DhcpAttr::RespL2Bytes => AttrValue::UInt($event.resp_l2_bytes),
                DhcpAttr::MsgType => AttrValue::UInt($event.msg_type.into()),
                DhcpAttr::CiAddr => AttrValue::Addr($event.ciaddr),
                DhcpAttr::YiAddr => AttrValue::Addr($event.yiaddr),
                DhcpAttr::SiAddr => AttrValue::Addr($event.siaddr),
                DhcpAttr::GiAddr => AttrValue::Addr($event.giaddr),
                DhcpAttr::SubNetMask => AttrValue::Addr($event.subnet_mask),
                DhcpAttr::Router => AttrValue::VecAddr(std::borrow::Cow::Borrowed(&$event.router)),
                DhcpAttr::DomainNameServer => {
                    AttrValue::VecAddr(std::borrow::Cow::Borrowed(&$event.domain_name_server))
                }
                DhcpAttr::ReqIpAddr => AttrValue::Addr($event.req_ip_addr),
                DhcpAttr::LeaseTime => AttrValue::UInt($event.lease_time.into()),
                DhcpAttr::ServerId => AttrValue::Addr($event.server_id),
                DhcpAttr::ParamReqList => AttrValue::VecUInt(std::borrow::Cow::Owned(
                    $event
                        .param_req_list
                        .iter()
                        .map(|val| u64::from(*val))
                        .collect(),
                )),
                DhcpAttr::Message => AttrValue::String(&$event.message),
                DhcpAttr::RenewalTime => AttrValue::UInt($event.renewal_time.into()),
                DhcpAttr::RebindingTime => AttrValue::UInt($event.rebinding_time.into()),
                DhcpAttr::ClassId => AttrValue::VecRaw(&$event.class_id),
                DhcpAttr::ClientIdType => AttrValue::UInt($event.client_id_type.into()),
                DhcpAttr::ClientId => AttrValue::VecRaw(&$event.client_id),
            };
            Some(target_value)
        } else {
            None
        }
    }};
}

pub type BlocklistDhcpFields = BlocklistDhcpFieldsV0_43;

#[derive(Serialize, Deserialize)]
pub struct BlocklistDhcpFieldsV0_43 {
    pub sensor: String,
    pub src_country_code: [u8; 2],
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub dst_country_code: [u8; 2],
    pub resp_port: u16,
    pub proto: u8,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub msg_type: u8,
    pub ciaddr: IpAddr,
    pub yiaddr: IpAddr,
    pub siaddr: IpAddr,
    pub giaddr: IpAddr,
    pub subnet_mask: IpAddr,
    pub router: Vec<IpAddr>,
    pub domain_name_server: Vec<IpAddr>,
    pub req_ip_addr: IpAddr,
    pub lease_time: u32,
    pub server_id: IpAddr,
    pub param_req_list: Vec<u8>,
    pub message: String,
    pub renewal_time: u32,
    pub rebinding_time: u32,
    pub class_id: Vec<u8>,
    pub client_id_type: u8,
    pub client_id: Vec<u8>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

// TODO: DHCP client identifier type.
//  - 00: Ascii string (need to support)
//  - 01: MAC address
//  - XX: Hexdecimal number

impl BlocklistDhcpFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);
        format!(
            "category={:?} sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} msg_type={:?} ciaddr={:?} yiaddr={:?} siaddr={:?} giaddr={:?} subnet_mask={:?} router={:?} domain_name_server={:?} req_ip_addr={:?} lease_time={:?} server_id={:?} param_req_list={:?} message={:?} renewal_time={:?} rebinding_time={:?} class_id={:?} client_id_type={:?} client_id={:?} confidence={:?}",
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
            self.msg_type.to_string(),
            self.ciaddr.to_string(),
            self.yiaddr.to_string(),
            self.siaddr.to_string(),
            self.giaddr.to_string(),
            self.subnet_mask.to_string(),
            vector_to_string(&self.router),
            vector_to_string(&self.domain_name_server),
            self.req_ip_addr.to_string(),
            self.lease_time.to_string(),
            self.server_id.to_string(),
            vector_to_string(&self.param_req_list),
            self.message,
            self.renewal_time.to_string(),
            self.rebinding_time.to_string(),
            std::str::from_utf8(&self.class_id)
                .unwrap_or_default()
                .to_string(),
            self.client_id_type.to_string(),
            to_hardware_address(&self.client_id),
            self.confidence.to_string(),
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct BlocklistDhcp {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub src_country_code: [u8; 2],
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub dst_country_code: [u8; 2],
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub msg_type: u8,
    pub ciaddr: IpAddr,
    pub yiaddr: IpAddr,
    pub siaddr: IpAddr,
    pub giaddr: IpAddr,
    pub subnet_mask: IpAddr,
    pub router: Vec<IpAddr>,
    pub domain_name_server: Vec<IpAddr>,
    pub req_ip_addr: IpAddr,
    pub lease_time: u32,
    pub server_id: IpAddr,
    pub param_req_list: Vec<u8>,
    pub message: String,
    pub renewal_time: u32,
    pub rebinding_time: u32,
    pub class_id: Vec<u8>,
    pub client_id_type: u8,
    pub client_id: Vec<u8>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}
impl fmt::Display for BlocklistDhcp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} msg_type={:?} ciaddr={:?} yiaddr={:?} siaddr={:?} giaddr={:?} subnet_mask={:?} router={:?} domain_name_server={:?} req_ip_addr={:?} lease_time={:?} server_id={:?} param_req_list={:?} message={:?} renewal_time={:?} rebinding_time={:?} class_id={:?} client_id_type={:?} client_id={:?} triage_scores={:?}",
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
            self.msg_type.to_string(),
            self.ciaddr.to_string(),
            self.yiaddr.to_string(),
            self.siaddr.to_string(),
            self.giaddr.to_string(),
            self.subnet_mask.to_string(),
            vector_to_string(&self.router),
            vector_to_string(&self.domain_name_server),
            self.req_ip_addr.to_string(),
            self.lease_time.to_string(),
            self.server_id.to_string(),
            vector_to_string(&self.param_req_list),
            self.message.clone(),
            self.renewal_time.to_string(),
            self.rebinding_time.to_string(),
            std::str::from_utf8(&self.class_id)
                .unwrap_or_default()
                .to_string(),
            self.client_id_type.to_string(),
            to_hardware_address(&self.client_id),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl BlocklistDhcp {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistDhcpFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            src_country_code: fields.src_country_code,
            orig_addr: fields.orig_addr,
            orig_port: fields.orig_port,
            resp_addr: fields.resp_addr,
            dst_country_code: fields.dst_country_code,
            resp_port: fields.resp_port,
            proto: fields.proto,
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            duration: fields.duration,
            orig_pkts: fields.orig_pkts,
            resp_pkts: fields.resp_pkts,
            orig_l2_bytes: fields.orig_l2_bytes,
            resp_l2_bytes: fields.resp_l2_bytes,
            msg_type: fields.msg_type,
            ciaddr: fields.ciaddr,
            yiaddr: fields.yiaddr,
            siaddr: fields.siaddr,
            giaddr: fields.giaddr,
            subnet_mask: fields.subnet_mask,
            router: fields.router,
            domain_name_server: fields.domain_name_server,
            req_ip_addr: fields.req_ip_addr,
            lease_time: fields.lease_time,
            server_id: fields.server_id,
            param_req_list: fields.param_req_list,
            message: fields.message,
            renewal_time: fields.renewal_time,
            rebinding_time: fields.rebinding_time,
            class_id: fields.class_id,
            client_id_type: fields.client_id_type,
            client_id: fields.client_id,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistDhcp {
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
        "blocklist dhcp"
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
        find_dhcp_attr_by_kind!(self, raw_event_attr)
    }
}
