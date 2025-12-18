use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{BootpAttr, RawEventAttrKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::event::common::{AttrValue, to_hardware_address, triage_scores_to_string};

macro_rules! find_bootp_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {{
        if let RawEventAttrKind::Bootp(attr) = $raw_event_attr {
            let target_value = match attr {
                BootpAttr::SrcAddr => AttrValue::Addr($event.orig_addr),
                BootpAttr::SrcPort => AttrValue::UInt($event.orig_port.into()),
                BootpAttr::DstAddr => AttrValue::Addr($event.resp_addr),
                BootpAttr::DstPort => AttrValue::UInt($event.resp_port.into()),
                BootpAttr::Proto => AttrValue::UInt($event.proto.into()),
                BootpAttr::Duration => AttrValue::SInt($event.duration),
                BootpAttr::OrigPkts => AttrValue::UInt($event.orig_pkts),
                BootpAttr::RespPkts => AttrValue::UInt($event.resp_pkts),
                BootpAttr::OrigL2Bytes => AttrValue::UInt($event.orig_l2_bytes),
                BootpAttr::RespL2Bytes => AttrValue::UInt($event.resp_l2_bytes),
                BootpAttr::Op => AttrValue::UInt($event.op.into()),
                BootpAttr::Htype => AttrValue::UInt($event.htype.into()),
                BootpAttr::Hops => AttrValue::UInt($event.hops.into()),
                BootpAttr::Xid => AttrValue::UInt($event.xid.into()),
                BootpAttr::CiAddr => AttrValue::Addr($event.ciaddr),
                BootpAttr::YiAddr => AttrValue::Addr($event.yiaddr),
                BootpAttr::SiAddr => AttrValue::Addr($event.siaddr),
                BootpAttr::GiAddr => AttrValue::Addr($event.giaddr),
                BootpAttr::ChAddr => AttrValue::VecRaw(&$event.chaddr),
                BootpAttr::SName => AttrValue::String(&$event.sname),
                BootpAttr::File => AttrValue::String(&$event.file),
            };
            Some(target_value)
        } else {
            None
        }
    }};
}

pub type BlocklistBootpFields = BlocklistBootpFieldsV0_43;

impl BlocklistBootpFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);
        format!(
            "category={:?} sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} op={:?} htype={:?} hops={:?} xid={:?} ciaddr={:?} yiaddr={:?} siaddr={:?} giaddr={:?} chaddr={:?} sname={:?} file={:?} confidence={:?}",
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
            self.op.to_string(),
            self.htype.to_string(),
            self.hops.to_string(),
            self.xid.to_string(),
            self.ciaddr.to_string(),
            self.yiaddr.to_string(),
            self.siaddr.to_string(),
            self.giaddr.to_string(),
            to_hardware_address(&self.chaddr),
            self.sname.clone(),
            self.file.clone(),
            self.confidence.to_string(),
        )
    }
}

#[derive(Serialize, Deserialize)]
pub struct BlocklistBootpFieldsV0_43 {
    pub sensor: String,
    pub src_country_code: Option<[u8; 2]>,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub dst_country_code: Option<[u8; 2]>,
    pub resp_port: u16,
    pub proto: u8,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub op: u8,
    pub htype: u8,
    pub hops: u8,
    pub xid: u32,
    pub ciaddr: IpAddr,
    pub yiaddr: IpAddr,
    pub siaddr: IpAddr,
    pub giaddr: IpAddr,
    pub chaddr: Vec<u8>,
    pub sname: String,
    pub file: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[allow(clippy::module_name_repetitions)]
pub struct BlocklistBootp {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub src_country_code: Option<[u8; 2]>,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub dst_country_code: Option<[u8; 2]>,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub op: u8,
    pub htype: u8,
    pub hops: u8,
    pub xid: u32,
    pub ciaddr: IpAddr,
    pub yiaddr: IpAddr,
    pub siaddr: IpAddr,
    pub giaddr: IpAddr,
    pub chaddr: Vec<u8>,
    pub sname: String,
    pub file: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}
impl fmt::Display for BlocklistBootp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} op={:?} htype={:?} hops={:?} xid={:?} ciaddr={:?} yiaddr={:?} siaddr={:?} giaddr={:?} chaddr={:?} sname={:?} file={:?} triage_scores={:?}",
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
            self.op.to_string(),
            self.htype.to_string(),
            self.hops.to_string(),
            self.xid.to_string(),
            self.ciaddr.to_string(),
            self.yiaddr.to_string(),
            self.siaddr.to_string(),
            self.giaddr.to_string(),
            to_hardware_address(&self.chaddr),
            self.sname.clone(),
            self.file.clone(),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl BlocklistBootp {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistBootpFields) -> Self {
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
            op: fields.op,
            htype: fields.htype,
            hops: fields.hops,
            xid: fields.xid,
            ciaddr: fields.ciaddr,
            yiaddr: fields.yiaddr,
            siaddr: fields.siaddr,
            giaddr: fields.giaddr,
            chaddr: fields.chaddr,
            sname: fields.sname,
            file: fields.file,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistBootp {
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
        "blocklist bootp"
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
        find_bootp_attr_by_kind!(self, raw_event_attr)
    }
}
