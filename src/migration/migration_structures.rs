//! Old data structures for migration purposes.
//!
//! These structures represent the schemas from previous releases
//! and must not be modified. They are used to migrate data from
//! old formats to new formats.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    event::{DceRpcContext, EventKind, FtpCommand, TriageScore},
    types::HostNetworkGroup,
};

/// `AllowNetwork` structure from version 0.42.x (before `customer_id` was added)
///
/// In version 0.42.x, `AllowNetwork` used only name as the key.
/// From 0.43.x, `customer_id` was added and the key became `customer_id` + name.
#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct AllowNetworkV0_42 {
    pub(crate) id: u32,
    pub(crate) name: String,
    pub(crate) networks: HostNetworkGroup,
    pub(crate) description: String,
}

/// `BlockNetwork` structure from version 0.42.x (before `customer_id` was added)
///
/// In version 0.42.x, `BlockNetwork` used only name as the key.
/// From 0.43.x, `customer_id` was added and the key became `customer_id` + name.
#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct BlockNetworkV0_42 {
    pub(crate) id: u32,
    pub(crate) name: String,
    pub(crate) networks: HostNetworkGroup,
    pub(crate) description: String,
}

/// Network value structure from version 0.43.x
///
/// This structure represents the old serialized value format where:
/// - The key was `name + id.to_be_bytes()` (name followed by 4-byte big-endian id)
/// - The value contained `customer_ids` field (now removed)
/// - The value did NOT contain `id` field (id was in the key)
#[derive(Serialize, Deserialize)]
pub(crate) struct NetworkValueV0_43 {
    pub(crate) description: String,
    pub(crate) networks: HostNetworkGroup,
    pub(crate) customer_ids: Vec<u32>,
    pub(crate) tag_ids: Vec<u32>,
    pub(crate) creation_time: DateTime<Utc>,
}

// ============================================================================
// Old triage policy structures for migration
// (Confidence.threat_category: EventCategory -> Option<EventCategory>)
// ============================================================================

use crate::{PacketAttr, Response};

/// `Confidence` structure from version 0.44.0 (before `threat_category`
/// became optional). In this version, `threat_category` was `EventCategory`.
/// From 0.45.0-alpha.1, it changed to `Option<EventCategory>`.
#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct ConfidenceV0_44 {
    pub(crate) threat_category: EventCategory,
    pub(crate) threat_kind: String,
    pub(crate) confidence: f64,
    pub(crate) weight: Option<f64>,
}

/// `TriagePolicy` structure from version 0.44.0, containing
/// `ConfidenceV0_44` with non-optional `threat_category`.
#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct TriagePolicyV0_44 {
    pub(crate) id: u32,
    pub(crate) name: String,
    pub(crate) triage_exclusion_id: Vec<u32>,
    pub(crate) packet_attr: Vec<PacketAttr>,
    pub(crate) confidence: Vec<ConfidenceV0_44>,
    pub(crate) response: Vec<Response>,
    pub(crate) creation_time: DateTime<Utc>,
    pub(crate) customer_id: Option<u32>,
}

impl From<TriagePolicyV0_44> for crate::TriagePolicy {
    fn from(old: TriagePolicyV0_44) -> Self {
        Self {
            id: old.id,
            name: old.name,
            triage_exclusion_id: old.triage_exclusion_id,
            packet_attr: old.packet_attr,
            confidence: old
                .confidence
                .into_iter()
                .map(|c| crate::Confidence {
                    threat_category: Some(c.threat_category),
                    threat_kind: c.threat_kind,
                    confidence: c.confidence,
                    weight: c.weight,
                })
                .collect(),
            response: old.response,
            creation_time: old.creation_time,
            customer_id: old.customer_id,
        }
    }
}

// ============================================================================
// Historical persisted event schemas
// ============================================================================

use std::net::IpAddr;

use chrono::serde::ts_nanoseconds;

use crate::EventCategory;

#[derive(Serialize, Deserialize)]
pub(crate) struct BlocklistDceRpcFieldsStoredV0_42 {
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
    pub rtt: i64,
    pub named_pipe: String,
    pub endpoint: String,
    pub operation: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct BlocklistDhcpFieldsStoredV0_42 {
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

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct HttpThreatFieldsStoredV0_43 {
    #[serde(with = "ts_nanoseconds")]
    pub time: DateTime<Utc>,
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
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referer: String,
    pub version: String,
    pub user_agent: String,
    pub request_len: usize,
    pub response_len: usize,
    pub status_code: u16,
    pub status_msg: String,
    pub username: String,
    pub password: String,
    pub cookie: String,
    pub content_encoding: String,
    pub content_type: String,
    pub cache_control: String,
    pub filenames: Vec<String>,
    pub mime_types: Vec<String>,
    pub body: Vec<u8>,
    pub state: String,
    pub db_name: String,
    pub rule_id: u32,
    pub matched_to: String,
    pub cluster_id: Option<usize>,
    pub attack_kind: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistBootpFieldsStoredV0_42 {
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

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistMqttFieldsStoredV0_42 {
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
    pub protocol: String,
    pub version: u8,
    pub client_id: String,
    pub connack_reason: u8,
    pub subscribe: Vec<String>,
    pub suback_reason: Vec<u8>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistSmbFieldsStoredV0_42 {
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
    pub command: u8,
    pub path: String,
    pub service: String,
    pub file_name: String,
    pub file_size: u64,
    pub resource_type: u16,
    pub fid: u16,
    pub create_time: i64,
    pub access_time: i64,
    pub write_time: i64,
    pub change_time: i64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistNtlmFieldsStoredV0_42 {
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
    pub protocol: String,
    pub username: String,
    pub hostname: String,
    pub domainname: String,
    pub success: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct UnusualDestinationPatternFieldsStoredV0_45 {
    pub sensor: String,
    pub start_time: i64,
    pub end_time: i64,
    pub destination_ips: Vec<IpAddr>,
    pub count: usize,
    pub expected_mean: f64,
    pub std_deviation: f64,
    pub z_score: f64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct LdapBruteForceFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub user_pw_list: Vec<(String, String)>,
    pub start_time: i64,
    pub end_time: i64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct LdapEventFieldsStoredV0_42 {
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
    pub message_id: u32,
    pub version: u8,
    pub opcode: Vec<String>,
    pub result: Vec<String>,
    pub diagnostic_message: Vec<String>,
    pub object: Vec<String>,
    pub argument: Vec<String>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistMalformedDnsFieldsStoredV0_45 {
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
    pub trans_id: u16,
    pub flags: u16,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
    pub query_count: u32,
    pub resp_count: u32,
    pub query_bytes: u64,
    pub resp_bytes: u64,
    pub query_body: Vec<Vec<u8>>,
    pub resp_body: Vec<Vec<u8>>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Deserialize, Serialize)]
pub(crate) struct DnsEventFieldsStoredV0_42 {
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
    pub query: String,
    pub answer: Vec<String>,
    pub trans_id: u16,
    pub rtt: i64,
    pub qclass: u16,
    pub qtype: u16,
    pub rcode: u16,
    pub aa_flag: bool,
    pub tc_flag: bool,
    pub rd_flag: bool,
    pub ra_flag: bool,
    pub ttl: Vec<i32>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Deserialize, Serialize)]
pub(crate) struct CryptocurrencyMiningPoolFieldsStoredV0_42 {
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
    pub query: String,
    pub answer: Vec<String>,
    pub trans_id: u16,
    pub rtt: i64,
    pub qclass: u16,
    pub qtype: u16,
    pub rcode: u16,
    pub aa_flag: bool,
    pub tc_flag: bool,
    pub rd_flag: bool,
    pub ra_flag: bool,
    pub ttl: Vec<i32>,
    pub coins: Vec<String>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistDnsFieldsStoredV0_42 {
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
    pub query: String,
    pub answer: Vec<String>,
    pub trans_id: u16,
    pub rtt: i64,
    pub qclass: u16,
    pub qtype: u16,
    pub rcode: u16,
    pub aa_flag: bool,
    pub tc_flag: bool,
    pub rd_flag: bool,
    pub ra_flag: bool,
    pub ttl: Vec<i32>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistDhcpFieldsStoredV0_44 {
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
    pub options: Vec<(u8, Vec<u8>)>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct FtpBruteForceFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub user_list: Vec<String>,
    pub start_time: i64,
    pub end_time: i64,
    pub is_internal: bool,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct FtpEventFieldsStoredV0_42 {
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
    pub user: String,
    pub password: String,
    pub commands: Vec<FtpCommand>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct RdpBruteForceFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub resp_addrs: Vec<IpAddr>,
    pub start_time: i64,
    pub end_time: i64,
    pub proto: u8,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistRdpFieldsStoredV0_42 {
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
    pub cookie: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistDceRpcFieldsStoredV0_44 {
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
    pub context: Vec<DceRpcContext>,
    pub request: Vec<String>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistSshFieldsStoredV0_42 {
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

#[derive(Deserialize, Serialize)]
pub(crate) struct PortScanFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub resp_ports: Vec<u16>,
    pub start_time: i64,
    pub end_time: i64,
    pub proto: u8,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct MultiHostPortScanFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub resp_port: u16,
    pub resp_addrs: Vec<IpAddr>,
    pub proto: u8,
    pub start_time: i64,
    pub end_time: i64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct ExternalDdosFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addrs: Vec<IpAddr>,
    pub resp_addr: IpAddr,
    pub proto: u8,
    pub start_time: i64,
    pub end_time: i64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistConnFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub conn_state: String,
    pub start_time: i64,
    pub duration: i64,
    pub service: String,
    pub orig_bytes: u64,
    pub resp_bytes: u64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct HttpEventFieldsStoredV0_42 {
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
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referer: String,
    pub version: String,
    pub user_agent: String,
    pub request_len: usize,
    pub response_len: usize,
    pub status_code: u16,
    pub status_msg: String,
    pub username: String,
    pub password: String,
    pub cookie: String,
    pub content_encoding: String,
    pub content_type: String,
    pub cache_control: String,
    pub filenames: Vec<String>,
    pub mime_types: Vec<String>,
    pub body: Vec<u8>,
    pub state: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct RepeatedHttpSessionsFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub end_time: i64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct HttpThreatFieldsStoredV0_44 {
    #[serde(with = "ts_nanoseconds")]
    pub time: DateTime<Utc>,
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
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referer: String,
    pub version: String,
    pub user_agent: String,
    pub request_len: usize,
    pub response_len: usize,
    pub status_code: u16,
    pub status_msg: String,
    pub username: String,
    pub password: String,
    pub cookie: String,
    pub content_encoding: String,
    pub content_type: String,
    pub cache_control: String,
    pub filenames: Vec<String>,
    pub mime_types: Vec<String>,
    pub body: Vec<u8>,
    pub state: String,
    pub db_name: String,
    pub rule_id: u32,
    pub matched_to: String,
    pub cluster_id: Option<u32>,
    pub attack_kind: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct DgaFieldsStoredV0_42 {
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
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referer: String,
    pub version: String,
    pub user_agent: String,
    pub request_len: usize,
    pub response_len: usize,
    pub status_code: u16,
    pub status_msg: String,
    pub username: String,
    pub password: String,
    pub cookie: String,
    pub content_encoding: String,
    pub content_type: String,
    pub cache_control: String,
    pub filenames: Vec<String>,
    pub mime_types: Vec<String>,
    pub body: Vec<u8>,
    pub state: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistNfsFieldsStoredV0_42 {
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
    pub read_files: Vec<String>,
    pub write_files: Vec<String>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistRadiusFieldsStoredV0_45 {
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

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistSmtpFieldsStoredV0_42 {
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
    pub mailfrom: String,
    pub date: String,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub agent: String,
    pub state: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

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
    pub cname: Vec<String>,
    pub realm: String,
    pub sname_type: u8,
    pub sname: Vec<String>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct NetworkThreatFieldsStoredV0_45 {
    #[serde(with = "ts_nanoseconds")]
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
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
    pub cluster_id: Option<u32>,
    pub attack_kind: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistTlsFieldsStoredV0_42 {
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
    pub server_name: String,
    pub alpn_protocol: String,
    pub ja3: String,
    pub version: String,
    pub client_cipher_suites: Vec<u16>,
    pub client_extensions: Vec<u16>,
    pub cipher: u16,
    pub extensions: Vec<u16>,
    pub ja3s: String,
    pub serial: String,
    pub subject_country: String,
    pub subject_org_name: String,
    pub subject_common_name: String,
    pub validity_not_before: i64,
    pub validity_not_after: i64,
    pub subject_alt_name: String,
    pub issuer_country: String,
    pub issuer_org_name: String,
    pub issuer_org_unit_name: String,
    pub issuer_common_name: String,
    pub last_alert: u8,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl From<BlocklistBootpFieldsStoredV0_42> for crate::event::BlocklistBootpFieldsStoredV0_46 {
    fn from(old: BlocklistBootpFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            op: old.op,
            htype: old.htype,
            hops: old.hops,
            xid: old.xid,
            ciaddr: old.ciaddr,
            yiaddr: old.yiaddr,
            siaddr: old.siaddr,
            giaddr: old.giaddr,
            chaddr: old.chaddr,
            sname: old.sname,
            file: old.file,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistConnFieldsStoredV0_42> for crate::event::BlocklistConnFieldsStoredV0_46 {
    fn from(old: BlocklistConnFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: old.proto,
            conn_state: old.conn_state,
            start_time: old.start_time,
            duration: old.duration,
            service: old.service,
            orig_bytes: old.orig_bytes,
            resp_bytes: old.resp_bytes,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistDceRpcFieldsStoredV0_44> for crate::event::BlocklistDceRpcFieldsStoredV0_46 {
    fn from(old: BlocklistDceRpcFieldsStoredV0_44) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            context: old.context,
            request: old.request,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistDhcpFieldsStoredV0_44> for crate::event::BlocklistDhcpFieldsStoredV0_46 {
    fn from(old: BlocklistDhcpFieldsStoredV0_44) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            msg_type: old.msg_type,
            ciaddr: old.ciaddr,
            yiaddr: old.yiaddr,
            siaddr: old.siaddr,
            giaddr: old.giaddr,
            subnet_mask: old.subnet_mask,
            router: old.router,
            domain_name_server: old.domain_name_server,
            req_ip_addr: old.req_ip_addr,
            lease_time: old.lease_time,
            server_id: old.server_id,
            param_req_list: old.param_req_list,
            message: old.message,
            renewal_time: old.renewal_time,
            rebinding_time: old.rebinding_time,
            class_id: old.class_id,
            client_id_type: old.client_id_type,
            client_id: old.client_id,
            options: old.options,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistDnsFieldsStoredV0_42> for crate::event::BlocklistDnsFieldsStoredV0_46 {
    fn from(old: BlocklistDnsFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            query: old.query,
            answer: old.answer,
            trans_id: old.trans_id,
            rtt: old.rtt,
            qclass: old.qclass,
            qtype: old.qtype,
            rcode: old.rcode,
            aa_flag: old.aa_flag,
            tc_flag: old.tc_flag,
            rd_flag: old.rd_flag,
            ra_flag: old.ra_flag,
            ttl: old.ttl,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<FtpEventFieldsStoredV0_42> for crate::event::FtpEventFieldsStoredV0_46 {
    fn from(old: FtpEventFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            user: old.user,
            password: old.password,
            commands: old.commands,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<DgaFieldsStoredV0_42> for crate::event::DgaFieldsStoredV0_46 {
    fn from(old: DgaFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            method: old.method,
            host: old.host,
            uri: old.uri,
            referer: old.referer,
            version: old.version,
            user_agent: old.user_agent,
            request_len: old.request_len,
            response_len: old.response_len,
            status_code: old.status_code,
            status_msg: old.status_msg,
            username: old.username,
            password: old.password,
            cookie: old.cookie,
            content_encoding: old.content_encoding,
            content_type: old.content_type,
            cache_control: old.cache_control,
            filenames: old.filenames,
            mime_types: old.mime_types,
            body: old.body,
            state: old.state,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistKerberosFieldsStoredV0_42> for crate::event::BlocklistKerberosFieldsStoredV0_46 {
    fn from(old: BlocklistKerberosFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            client_time: old.client_time,
            server_time: old.server_time,
            error_code: old.error_code,
            client_realm: old.client_realm,
            cname_type: old.cname_type,
            cname: old.cname,
            realm: old.realm,
            sname_type: old.sname_type,
            sname: old.sname,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<LdapEventFieldsStoredV0_42> for crate::event::LdapEventFieldsStoredV0_46 {
    fn from(old: LdapEventFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            message_id: old.message_id,
            version: old.version,
            opcode: old.opcode,
            result: old.result,
            diagnostic_message: old.diagnostic_message,
            object: old.object,
            argument: old.argument,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistMalformedDnsFieldsStoredV0_45>
    for crate::event::BlocklistMalformedDnsFieldsStoredV0_46
{
    fn from(old: BlocklistMalformedDnsFieldsStoredV0_45) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            trans_id: old.trans_id,
            flags: old.flags,
            question_count: old.question_count,
            answer_count: old.answer_count,
            authority_count: old.authority_count,
            additional_count: old.additional_count,
            query_count: old.query_count,
            resp_count: old.resp_count,
            query_bytes: old.query_bytes,
            resp_bytes: old.resp_bytes,
            query_body: old.query_body,
            resp_body: old.resp_body,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistMqttFieldsStoredV0_42> for crate::event::BlocklistMqttFieldsStoredV0_46 {
    fn from(old: BlocklistMqttFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            protocol: old.protocol,
            version: old.version,
            client_id: old.client_id,
            connack_reason: old.connack_reason,
            subscribe: old.subscribe,
            suback_reason: old.suback_reason,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistNfsFieldsStoredV0_42> for crate::event::BlocklistNfsFieldsStoredV0_46 {
    fn from(old: BlocklistNfsFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            read_files: old.read_files,
            write_files: old.write_files,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistNtlmFieldsStoredV0_42> for crate::event::BlocklistNtlmFieldsStoredV0_46 {
    fn from(old: BlocklistNtlmFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            protocol: old.protocol,
            username: old.username,
            hostname: old.hostname,
            domainname: old.domainname,
            success: old.success,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistRadiusFieldsStoredV0_45> for crate::event::BlocklistRadiusFieldsStoredV0_46 {
    fn from(old: BlocklistRadiusFieldsStoredV0_45) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            id: old.id,
            code: old.code,
            resp_code: old.resp_code,
            auth: old.auth,
            resp_auth: old.resp_auth,
            user_name: old.user_name,
            user_passwd: old.user_passwd,
            chap_passwd: old.chap_passwd,
            nas_ip: old.nas_ip,
            nas_port: old.nas_port,
            state: old.state,
            nas_id: old.nas_id,
            nas_port_type: old.nas_port_type,
            message: old.message,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistRdpFieldsStoredV0_42> for crate::event::BlocklistRdpFieldsStoredV0_46 {
    fn from(old: BlocklistRdpFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            cookie: old.cookie,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistSmbFieldsStoredV0_42> for crate::event::BlocklistSmbFieldsStoredV0_46 {
    fn from(old: BlocklistSmbFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            command: old.command,
            path: old.path,
            service: old.service,
            file_name: old.file_name,
            file_size: old.file_size,
            resource_type: old.resource_type,
            fid: old.fid,
            create_time: old.create_time,
            access_time: old.access_time,
            write_time: old.write_time,
            change_time: old.change_time,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistSmtpFieldsStoredV0_42> for crate::event::BlocklistSmtpFieldsStoredV0_46 {
    fn from(old: BlocklistSmtpFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            mailfrom: old.mailfrom,
            date: old.date,
            from: old.from,
            to: old.to,
            subject: old.subject,
            agent: old.agent,
            state: old.state,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistSshFieldsStoredV0_42> for crate::event::BlocklistSshFieldsStoredV0_46 {
    fn from(old: BlocklistSshFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            client: old.client,
            server: old.server,
            cipher_alg: old.cipher_alg,
            mac_alg: old.mac_alg,
            compression_alg: old.compression_alg,
            kex_alg: old.kex_alg,
            host_key_alg: old.host_key_alg,
            hassh_algorithms: old.hassh_algorithms,
            hassh: old.hassh,
            hassh_server_algorithms: old.hassh_server_algorithms,
            hassh_server: old.hassh_server,
            client_shka: old.client_shka,
            server_shka: old.server_shka,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistTlsFieldsStoredV0_42> for crate::event::BlocklistTlsFieldsStoredV0_46 {
    fn from(old: BlocklistTlsFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            server_name: old.server_name,
            alpn_protocol: old.alpn_protocol,
            ja3: old.ja3,
            version: old.version,
            client_cipher_suites: old.client_cipher_suites,
            client_extensions: old.client_extensions,
            cipher: old.cipher,
            extensions: old.extensions,
            ja3s: old.ja3s,
            serial: old.serial,
            subject_country: old.subject_country,
            subject_org_name: old.subject_org_name,
            subject_common_name: old.subject_common_name,
            validity_not_before: old.validity_not_before,
            validity_not_after: old.validity_not_after,
            subject_alt_name: old.subject_alt_name,
            issuer_country: old.issuer_country,
            issuer_org_name: old.issuer_org_name,
            issuer_org_unit_name: old.issuer_org_unit_name,
            issuer_common_name: old.issuer_common_name,
            last_alert: old.last_alert,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<CryptocurrencyMiningPoolFieldsStoredV0_42>
    for crate::event::CryptocurrencyMiningPoolFieldsStoredV0_46
{
    fn from(old: CryptocurrencyMiningPoolFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            query: old.query,
            answer: old.answer,
            trans_id: old.trans_id,
            rtt: old.rtt,
            qclass: old.qclass,
            qtype: old.qtype,
            rcode: old.rcode,
            aa_flag: old.aa_flag,
            tc_flag: old.tc_flag,
            rd_flag: old.rd_flag,
            ra_flag: old.ra_flag,
            ttl: old.ttl,
            coins: old.coins,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<DnsEventFieldsStoredV0_42> for crate::event::DnsEventFieldsStoredV0_46 {
    fn from(old: DnsEventFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            query: old.query,
            answer: old.answer,
            trans_id: old.trans_id,
            rtt: old.rtt,
            qclass: old.qclass,
            qtype: old.qtype,
            rcode: old.rcode,
            aa_flag: old.aa_flag,
            tc_flag: old.tc_flag,
            rd_flag: old.rd_flag,
            ra_flag: old.ra_flag,
            ttl: old.ttl,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<ExternalDdosFieldsStoredV0_42> for crate::event::ExternalDdosFieldsStoredV0_46 {
    fn from(old: ExternalDdosFieldsStoredV0_42) -> Self {
        let orig_addr_count = old.orig_addrs.len();
        Self {
            sensor: old.sensor,
            orig_addrs: old.orig_addrs,
            orig_country_codes: vec![crate::util::COUNTRY_CODE_PENDING; orig_addr_count],
            resp_addr: old.resp_addr,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: old.proto,
            first_event_start_time: old.start_time,
            last_event_start_time: old.end_time,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<FtpBruteForceFieldsStoredV0_42> for crate::event::FtpBruteForceFieldsStoredV0_46 {
    fn from(old: FtpBruteForceFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: old.proto,
            user_list: old.user_list,
            first_event_start_time: old.start_time,
            last_event_start_time: old.end_time,
            is_internal: old.is_internal,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<HttpThreatFieldsStoredV0_44> for crate::event::HttpThreatFieldsStoredV0_46 {
    fn from(old: HttpThreatFieldsStoredV0_44) -> Self {
        Self {
            time: old.time,
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            method: old.method,
            host: old.host,
            uri: old.uri,
            referer: old.referer,
            version: old.version,
            user_agent: old.user_agent,
            request_len: old.request_len,
            response_len: old.response_len,
            status_code: old.status_code,
            status_msg: old.status_msg,
            username: old.username,
            password: old.password,
            cookie: old.cookie,
            content_encoding: old.content_encoding,
            content_type: old.content_type,
            cache_control: old.cache_control,
            filenames: old.filenames,
            mime_types: old.mime_types,
            body: old.body,
            state: old.state,
            db_name: old.db_name,
            rule_id: old.rule_id,
            matched_to: old.matched_to,
            cluster_id: old.cluster_id,
            attack_kind: old.attack_kind,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<LdapBruteForceFieldsStoredV0_42> for crate::event::LdapBruteForceFieldsStoredV0_46 {
    fn from(old: LdapBruteForceFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: old.proto,
            user_pw_list: old.user_pw_list,
            first_event_start_time: old.start_time,
            last_event_start_time: old.end_time,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<MultiHostPortScanFieldsStoredV0_42> for crate::event::MultiHostPortScanFieldsStoredV0_46 {
    fn from(old: MultiHostPortScanFieldsStoredV0_42) -> Self {
        let resp_addr_count = old.resp_addrs.len();
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addrs: old.resp_addrs,
            resp_port: old.resp_port,
            resp_country_codes: vec![crate::util::COUNTRY_CODE_PENDING; resp_addr_count],
            proto: old.proto,
            first_event_start_time: old.start_time,
            last_event_start_time: old.end_time,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<NetworkThreatFieldsStoredV0_45> for crate::event::NetworkThreatFieldsStoredV0_46 {
    fn from(old: NetworkThreatFieldsStoredV0_45) -> Self {
        Self {
            time: old.time,
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: old.proto,
            service: old.service,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            content: old.content,
            db_name: old.db_name,
            rule_id: old.rule_id,
            matched_to: old.matched_to,
            cluster_id: old.cluster_id,
            attack_kind: old.attack_kind,
            confidence: old.confidence,
            category: old.category,
            triage_scores: old.triage_scores,
        }
    }
}

impl From<HttpEventFieldsStoredV0_42> for crate::event::HttpEventFieldsStoredV0_46 {
    fn from(old: HttpEventFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            method: old.method,
            host: old.host,
            uri: old.uri,
            referer: old.referer,
            version: old.version,
            user_agent: old.user_agent,
            request_len: old.request_len,
            response_len: old.response_len,
            status_code: old.status_code,
            status_msg: old.status_msg,
            username: old.username,
            password: old.password,
            cookie: old.cookie,
            content_encoding: old.content_encoding,
            content_type: old.content_type,
            cache_control: old.cache_control,
            filenames: old.filenames,
            mime_types: old.mime_types,
            body: old.body,
            state: old.state,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<PortScanFieldsStoredV0_42> for crate::event::PortScanFieldsStoredV0_46 {
    fn from(old: PortScanFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: old.resp_addr,
            resp_ports: old.resp_ports,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            first_event_start_time: old.start_time,
            last_event_start_time: old.end_time,
            proto: old.proto,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<RdpBruteForceFieldsStoredV0_42> for crate::event::RdpBruteForceFieldsStoredV0_46 {
    fn from(old: RdpBruteForceFieldsStoredV0_42) -> Self {
        let resp_addr_count = old.resp_addrs.len();
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addrs: old.resp_addrs,
            resp_country_codes: vec![crate::util::COUNTRY_CODE_PENDING; resp_addr_count],
            first_event_start_time: old.start_time,
            last_event_start_time: old.end_time,
            proto: old.proto,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<RepeatedHttpSessionsFieldsStoredV0_42>
    for crate::event::RepeatedHttpSessionsFieldsStoredV0_46
{
    fn from(old: RepeatedHttpSessionsFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: old.proto,
            first_event_start_time: old.start_time,
            last_event_start_time: old.end_time,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<UnusualDestinationPatternFieldsStoredV0_45>
    for crate::event::UnusualDestinationPatternFieldsStoredV0_46
{
    fn from(old: UnusualDestinationPatternFieldsStoredV0_45) -> Self {
        let destination_ip_count = old.destination_ips.len();
        Self {
            sensor: old.sensor,
            sampling_window_start_time: old.start_time,
            sampling_window_end_time: old.end_time,
            destination_ips: old.destination_ips,
            resp_country_codes: vec![crate::util::COUNTRY_CODE_PENDING; destination_ip_count],
            count: old.count,
            expected_mean: old.expected_mean,
            std_deviation: old.std_deviation,
            z_score: old.z_score,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

fn convert_stored<Source, Target>(bytes: &[u8]) -> Result<Vec<u8>>
where
    Source: for<'de> Deserialize<'de>,
    Target: From<Source> + Serialize,
{
    let source: Source = bincode::deserialize(bytes)
        .context("failed to deserialize event fields as the previous stored schema")?;
    let target = Target::from(source);
    bincode::serialize(&target).context("failed to serialize target stored schema")
}

pub(crate) fn migrate_event_stored_schema_to_v0_46(
    kind: EventKind,
    bytes: &[u8],
) -> Result<Vec<u8>> {
    match kind {
        EventKind::BlocklistBootp => convert_stored::<
            BlocklistBootpFieldsStoredV0_42,
            crate::event::BlocklistBootpFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistConn | EventKind::TorConnectionConn => convert_stored::<
            BlocklistConnFieldsStoredV0_42,
            crate::event::BlocklistConnFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistDceRpc => convert_stored::<
            BlocklistDceRpcFieldsStoredV0_44,
            crate::event::BlocklistDceRpcFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistDhcp => convert_stored::<
            BlocklistDhcpFieldsStoredV0_44,
            crate::event::BlocklistDhcpFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistDns => convert_stored::<
            BlocklistDnsFieldsStoredV0_42,
            crate::event::BlocklistDnsFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistFtp | EventKind::FtpPlainText => convert_stored::<
            FtpEventFieldsStoredV0_42,
            crate::event::FtpEventFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistHttp | EventKind::DomainGenerationAlgorithm => {
            convert_stored::<DgaFieldsStoredV0_42, crate::event::DgaFieldsStoredV0_46>(bytes)
        }
        EventKind::BlocklistKerberos => convert_stored::<
            BlocklistKerberosFieldsStoredV0_42,
            crate::event::BlocklistKerberosFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistLdap | EventKind::LdapPlainText => convert_stored::<
            LdapEventFieldsStoredV0_42,
            crate::event::LdapEventFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistMalformedDns => convert_stored::<
            BlocklistMalformedDnsFieldsStoredV0_45,
            crate::event::BlocklistMalformedDnsFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistMqtt => convert_stored::<
            BlocklistMqttFieldsStoredV0_42,
            crate::event::BlocklistMqttFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistNfs => convert_stored::<
            BlocklistNfsFieldsStoredV0_42,
            crate::event::BlocklistNfsFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistNtlm => convert_stored::<
            BlocklistNtlmFieldsStoredV0_42,
            crate::event::BlocklistNtlmFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistRadius => convert_stored::<
            BlocklistRadiusFieldsStoredV0_45,
            crate::event::BlocklistRadiusFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistRdp => convert_stored::<
            BlocklistRdpFieldsStoredV0_42,
            crate::event::BlocklistRdpFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistSmb => convert_stored::<
            BlocklistSmbFieldsStoredV0_42,
            crate::event::BlocklistSmbFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistSmtp => convert_stored::<
            BlocklistSmtpFieldsStoredV0_42,
            crate::event::BlocklistSmtpFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistSsh => convert_stored::<
            BlocklistSshFieldsStoredV0_42,
            crate::event::BlocklistSshFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistTls | EventKind::SuspiciousTlsTraffic => convert_stored::<
            BlocklistTlsFieldsStoredV0_42,
            crate::event::BlocklistTlsFieldsStoredV0_46,
        >(bytes),
        EventKind::CryptocurrencyMiningPool => convert_stored::<
            CryptocurrencyMiningPoolFieldsStoredV0_42,
            crate::event::CryptocurrencyMiningPoolFieldsStoredV0_46,
        >(bytes),
        EventKind::DnsCovertChannel | EventKind::LockyRansomware => convert_stored::<
            DnsEventFieldsStoredV0_42,
            crate::event::DnsEventFieldsStoredV0_46,
        >(bytes),
        EventKind::ExternalDdos => convert_stored::<
            ExternalDdosFieldsStoredV0_42,
            crate::event::ExternalDdosFieldsStoredV0_46,
        >(bytes),
        EventKind::FtpBruteForce => convert_stored::<
            FtpBruteForceFieldsStoredV0_42,
            crate::event::FtpBruteForceFieldsStoredV0_46,
        >(bytes),
        EventKind::HttpThreat => convert_stored::<
            HttpThreatFieldsStoredV0_44,
            crate::event::HttpThreatFieldsStoredV0_46,
        >(bytes),
        EventKind::LdapBruteForce => convert_stored::<
            LdapBruteForceFieldsStoredV0_42,
            crate::event::LdapBruteForceFieldsStoredV0_46,
        >(bytes),
        EventKind::MultiHostPortScan => convert_stored::<
            MultiHostPortScanFieldsStoredV0_42,
            crate::event::MultiHostPortScanFieldsStoredV0_46,
        >(bytes),
        EventKind::NetworkThreat => convert_stored::<
            NetworkThreatFieldsStoredV0_45,
            crate::event::NetworkThreatFieldsStoredV0_46,
        >(bytes),
        EventKind::NonBrowser | EventKind::TorConnection => convert_stored::<
            HttpEventFieldsStoredV0_42,
            crate::event::HttpEventFieldsStoredV0_46,
        >(bytes),
        EventKind::PortScan => convert_stored::<
            PortScanFieldsStoredV0_42,
            crate::event::PortScanFieldsStoredV0_46,
        >(bytes),
        EventKind::RdpBruteForce => convert_stored::<
            RdpBruteForceFieldsStoredV0_42,
            crate::event::RdpBruteForceFieldsStoredV0_46,
        >(bytes),
        EventKind::RepeatedHttpSessions => convert_stored::<
            RepeatedHttpSessionsFieldsStoredV0_42,
            crate::event::RepeatedHttpSessionsFieldsStoredV0_46,
        >(bytes),
        EventKind::UnusualDestinationPattern => convert_stored::<
            UnusualDestinationPatternFieldsStoredV0_45,
            crate::event::UnusualDestinationPatternFieldsStoredV0_46,
        >(bytes),
        EventKind::ExtraThreat | EventKind::WindowsThreat => Ok(bytes.to_vec()),
    }
}

/// Validates that bytes use the output schema of the 0.46 event migration.
pub(super) fn validate_event_stored_schema_v0_46(kind: EventKind, bytes: &[u8]) -> Result<()> {
    fn validate<T>(bytes: &[u8]) -> Result<()>
    where
        T: for<'de> Deserialize<'de>,
    {
        bincode::deserialize::<T>(bytes)
            .map(|_| ())
            .context("failed to deserialize event fields as the 0.46 stored schema")
    }

    match kind {
        EventKind::BlocklistBootp => {
            validate::<crate::event::BlocklistBootpFieldsStoredV0_46>(bytes)
        }
        EventKind::BlocklistConn | EventKind::TorConnectionConn => {
            validate::<crate::event::BlocklistConnFieldsStoredV0_46>(bytes)
        }
        EventKind::BlocklistDceRpc => {
            validate::<crate::event::BlocklistDceRpcFieldsStoredV0_46>(bytes)
        }
        EventKind::BlocklistDhcp => validate::<crate::event::BlocklistDhcpFieldsStoredV0_46>(bytes),
        EventKind::BlocklistDns => validate::<crate::event::BlocklistDnsFieldsStoredV0_46>(bytes),
        EventKind::BlocklistFtp | EventKind::FtpPlainText => {
            validate::<crate::event::FtpEventFieldsStoredV0_46>(bytes)
        }
        EventKind::BlocklistHttp | EventKind::DomainGenerationAlgorithm => {
            validate::<crate::event::DgaFieldsStoredV0_46>(bytes)
        }
        EventKind::BlocklistKerberos => {
            validate::<crate::event::BlocklistKerberosFieldsStoredV0_46>(bytes)
        }
        EventKind::BlocklistLdap | EventKind::LdapPlainText => {
            validate::<crate::event::LdapEventFieldsStoredV0_46>(bytes)
        }
        EventKind::BlocklistMalformedDns => {
            validate::<crate::event::BlocklistMalformedDnsFieldsStoredV0_46>(bytes)
        }
        EventKind::BlocklistMqtt => validate::<crate::event::BlocklistMqttFieldsStoredV0_46>(bytes),
        EventKind::BlocklistNfs => validate::<crate::event::BlocklistNfsFieldsStoredV0_46>(bytes),
        EventKind::BlocklistNtlm => validate::<crate::event::BlocklistNtlmFieldsStoredV0_46>(bytes),
        EventKind::BlocklistRadius => {
            validate::<crate::event::BlocklistRadiusFieldsStoredV0_46>(bytes)
        }
        EventKind::BlocklistRdp => validate::<crate::event::BlocklistRdpFieldsStoredV0_46>(bytes),
        EventKind::BlocklistSmb => validate::<crate::event::BlocklistSmbFieldsStoredV0_46>(bytes),
        EventKind::BlocklistSmtp => validate::<crate::event::BlocklistSmtpFieldsStoredV0_46>(bytes),
        EventKind::BlocklistSsh => validate::<crate::event::BlocklistSshFieldsStoredV0_46>(bytes),
        EventKind::BlocklistTls | EventKind::SuspiciousTlsTraffic => {
            validate::<crate::event::BlocklistTlsFieldsStoredV0_46>(bytes)
        }
        EventKind::CryptocurrencyMiningPool => {
            validate::<crate::event::CryptocurrencyMiningPoolFieldsStoredV0_46>(bytes)
        }
        EventKind::DnsCovertChannel | EventKind::LockyRansomware => {
            validate::<crate::event::DnsEventFieldsStoredV0_46>(bytes)
        }
        EventKind::ExternalDdos => validate::<crate::event::ExternalDdosFieldsStoredV0_46>(bytes),
        EventKind::ExtraThreat | EventKind::WindowsThreat => Ok(()),
        EventKind::FtpBruteForce => validate::<crate::event::FtpBruteForceFieldsStoredV0_46>(bytes),
        EventKind::HttpThreat => validate::<crate::event::HttpThreatFieldsStoredV0_46>(bytes),
        EventKind::LdapBruteForce => {
            validate::<crate::event::LdapBruteForceFieldsStoredV0_46>(bytes)
        }
        EventKind::MultiHostPortScan => {
            validate::<crate::event::MultiHostPortScanFieldsStoredV0_46>(bytes)
        }
        EventKind::NetworkThreat => validate::<crate::event::NetworkThreatFieldsStoredV0_46>(bytes),
        EventKind::NonBrowser | EventKind::TorConnection => {
            validate::<crate::event::HttpEventFieldsStoredV0_46>(bytes)
        }
        EventKind::PortScan => validate::<crate::event::PortScanFieldsStoredV0_46>(bytes),
        EventKind::RdpBruteForce => validate::<crate::event::RdpBruteForceFieldsStoredV0_46>(bytes),
        EventKind::RepeatedHttpSessions => {
            validate::<crate::event::RepeatedHttpSessionsFieldsStoredV0_46>(bytes)
        }
        EventKind::UnusualDestinationPattern => {
            validate::<crate::event::UnusualDestinationPatternFieldsStoredV0_46>(bytes)
        }
    }
}
