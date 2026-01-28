use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{RawEventAttrKind, SshAttr};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::event::common::{AttrValue, triage_scores_to_string};

macro_rules! find_ssh_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {{
        if let RawEventAttrKind::Ssh(attr) = $raw_event_attr {
            let target_value = match attr {
                SshAttr::SrcAddr => AttrValue::Addr($event.orig_addr),
                SshAttr::SrcPort => AttrValue::UInt($event.orig_port.into()),
                SshAttr::DstAddr => AttrValue::Addr($event.resp_addr),
                SshAttr::DstPort => AttrValue::UInt($event.resp_port.into()),
                SshAttr::Proto => AttrValue::UInt($event.proto.into()),
                SshAttr::Duration => AttrValue::SInt($event.duration),
                SshAttr::OrigPkts => AttrValue::UInt($event.orig_pkts),
                SshAttr::RespPkts => AttrValue::UInt($event.resp_pkts),
                SshAttr::OrigL2Bytes => AttrValue::UInt($event.orig_l2_bytes),
                SshAttr::RespL2Bytes => AttrValue::UInt($event.resp_l2_bytes),
                SshAttr::Client => AttrValue::String(&$event.client),
                SshAttr::Server => AttrValue::String(&$event.server),
                SshAttr::CipherAlg => AttrValue::String(&$event.cipher_alg),
                SshAttr::MacAlg => AttrValue::String(&$event.mac_alg),
                SshAttr::CompressionAlg => AttrValue::String(&$event.compression_alg),
                SshAttr::KexAlg => AttrValue::String(&$event.kex_alg),
                SshAttr::HostKeyAlg => AttrValue::String(&$event.host_key_alg),
                SshAttr::HasshAlgorithms => AttrValue::String(&$event.hassh_algorithms),
                SshAttr::Hassh => AttrValue::String(&$event.hassh),
                SshAttr::HasshServerAlgorithms => {
                    AttrValue::String(&$event.hassh_server_algorithms)
                }
                SshAttr::HasshServer => AttrValue::String(&$event.hassh_server),
                SshAttr::ClientShka => AttrValue::String(&$event.client_shka),
                SshAttr::ServerShka => AttrValue::String(&$event.server_shka),
            };
            Some(target_value)
        } else {
            None
        }
    }};
}

pub type BlocklistSshFields = BlocklistSshFieldsV0_44;

#[derive(Serialize, Deserialize)]
pub struct BlocklistSshFieldsV0_44 {
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
    pub client: String,
    pub server: String,
    pub cipher_alg: String,
    pub mac_alg: String,
    pub compression_alg: String,
    pub kex_alg: String,
    pub host_key_alg: String,
    pub hassh_algorithms: String,
    pub hassh: String,
    pub hassh_server_algorithms: String,
    pub hassh_server: String,
    pub client_shka: String,
    pub server_shka: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl BlocklistSshFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);
        format!(
            "category={:?} sensor={:?} orig_addr={:?} orig_port={:?} orig_country_code={:?} resp_addr={:?} resp_port={:?} resp_country_code={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} client={:?} server={:?} cipher_alg={:?} mac_alg={:?} compression_alg={:?} kex_alg={:?} host_key_alg={:?} hassh_algorithms={:?} hassh={:?} hassh_server_algorithms={:?} hassh_server={:?} client_shka={:?} server_shka={:?} confidence={:?}",
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
            self.client,
            self.server,
            self.cipher_alg,
            self.mac_alg,
            self.compression_alg,
            self.kex_alg,
            self.host_key_alg,
            self.hassh_algorithms,
            self.hassh,
            self.hassh_server_algorithms,
            self.hassh_server,
            self.client_shka,
            self.server_shka,
            self.confidence.to_string()
        )
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct BlocklistSsh {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub orig_country_code: [u8; 2],
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub resp_country_code: [u8; 2],
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub client: String,
    pub server: String,
    pub cipher_alg: String,
    pub mac_alg: String,
    pub compression_alg: String,
    pub kex_alg: String,
    pub host_key_alg: String,
    pub hassh_algorithms: String,
    pub hassh: String,
    pub hassh_server_algorithms: String,
    pub hassh_server: String,
    pub client_shka: String,
    pub server_shka: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}
impl fmt::Display for BlocklistSsh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} orig_country_code={:?} resp_addr={:?} resp_port={:?} resp_country_code={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} client={:?} server={:?} cipher_alg={:?} mac_alg={:?} compression_alg={:?} kex_alg={:?} host_key_alg={:?} hassh_algorithms={:?} hassh={:?} hassh_server_algorithms={:?} hassh_server={:?} client_shka={:?} server_shka={:?} triage_scores={:?}",
            self.sensor,
            self.orig_addr.to_string(),
            self.orig_port.to_string(),
            std::str::from_utf8(&self.orig_country_code).unwrap_or("XX"),
            self.resp_addr.to_string(),
            self.resp_port.to_string(),
            std::str::from_utf8(&self.resp_country_code).unwrap_or("XX"),
            self.proto.to_string(),
            self.start_time.to_rfc3339(),
            self.duration.to_string(),
            self.orig_pkts.to_string(),
            self.resp_pkts.to_string(),
            self.orig_l2_bytes.to_string(),
            self.resp_l2_bytes.to_string(),
            self.client,
            self.server,
            self.cipher_alg,
            self.mac_alg,
            self.compression_alg,
            self.kex_alg,
            self.host_key_alg,
            self.hassh_algorithms,
            self.hassh,
            self.hassh_server_algorithms,
            self.hassh_server,
            self.client_shka,
            self.server_shka,
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl BlocklistSsh {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistSshFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            orig_addr: fields.orig_addr,
            orig_port: fields.orig_port,
            orig_country_code: fields.orig_country_code,
            resp_addr: fields.resp_addr,
            resp_port: fields.resp_port,
            resp_country_code: fields.resp_country_code,
            proto: fields.proto,
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            duration: fields.duration,
            orig_pkts: fields.orig_pkts,
            resp_pkts: fields.resp_pkts,
            orig_l2_bytes: fields.orig_l2_bytes,
            resp_l2_bytes: fields.resp_l2_bytes,
            client: fields.client,
            server: fields.server,
            cipher_alg: fields.cipher_alg,
            mac_alg: fields.mac_alg,
            compression_alg: fields.compression_alg,
            kex_alg: fields.kex_alg,
            host_key_alg: fields.host_key_alg,
            hassh_algorithms: fields.hassh_algorithms,
            hassh: fields.hassh,
            hassh_server_algorithms: fields.hassh_server_algorithms,
            hassh_server: fields.hassh_server,
            client_shka: fields.client_shka,
            server_shka: fields.server_shka,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for BlocklistSsh {
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
        "blocklist ssh"
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
        find_ssh_attr_by_kind!(self, raw_event_attr)
    }
}
