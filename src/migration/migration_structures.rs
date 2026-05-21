//! Old data structures for migration purposes.
#![allow(dead_code)] // Legacy migration schema types; not every release path deserializes each layout.
//!
//! These structures represent the schemas from previous releases
//! and must not be modified. They are used to migrate data from
//! old formats to new formats.

use std::net::IpAddr;

use chrono::{DateTime, Utc, serde::ts_nanoseconds};
use serde::{Deserialize, Serialize};

use crate::types::{EventCategory, HostNetworkGroup};

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

// =============================================================================
// Event Fields structures before orig_country_code/resp_country_code
// These structs represent old event field schemas without
// country code fields. From 0.46.x, country code fields are stored internally.
// Also handles cluster_id type change from Option<usize> to Option<u32>.
// =============================================================================

/// FTP Command structure for `V0_43` migration
#[derive(Clone, Deserialize, Serialize)]
pub struct FtpCommandV0_43 {
    pub command: String,
    pub reply_code: String,
    pub reply_msg: String,
}

/// Port scan fields from version 0.43.x.
#[derive(Serialize, Deserialize)]
pub struct PortScanFieldsV0_43 {
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

/// Multi-host port scan fields from version 0.43.x
#[derive(Serialize, Deserialize)]
pub struct MultiHostPortScanFieldsV0_43 {
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

/// `BlocklistDceRpcFieldsStored` structure from version 0.42.x.
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

/// `BlocklistDhcpFieldsStored` structure from version 0.42.x
/// (before `options` field was added)
///
/// In 0.42.x, `BlocklistDhcpFieldsStored` did not have an `options` field.
/// From 0.44.x, `options: Vec<(u8, Vec<u8>)>` was added to the stored schema.
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

/// External `DDoS` fields from version 0.43.x
#[derive(Serialize, Deserialize)]
pub struct ExternalDdosFieldsV0_43 {
    pub sensor: String,
    pub orig_addrs: Vec<IpAddr>,
    pub resp_addr: IpAddr,
    pub proto: u8,
    pub start_time: i64,
    pub end_time: i64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

/// Blocklist connection fields from version 0.43.x
#[derive(Deserialize, Serialize)]
pub struct BlocklistConnFieldsV0_43 {
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

/// DNS event fields from version 0.43.x
#[allow(clippy::struct_excessive_bools)]
#[derive(Deserialize, Serialize)]
pub struct DnsEventFieldsV0_43 {
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

/// Cryptocurrency mining pool fields from version 0.43.x
#[allow(clippy::struct_excessive_bools)]
#[derive(Deserialize, Serialize)]
pub struct CryptocurrencyMiningPoolFieldsV0_43 {
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

/// Blocklist DNS fields from version 0.43.x
#[allow(clippy::struct_excessive_bools)]
#[derive(Deserialize, Serialize)]
pub struct BlocklistDnsFieldsV0_43 {
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

/// HTTP event fields from version 0.43.x
#[derive(Deserialize, Serialize)]
pub struct HttpEventFieldsV0_43 {
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

/// Repeated HTTP sessions fields from version 0.43.x
#[derive(Serialize, Deserialize)]
pub struct RepeatedHttpSessionsFieldsV0_43 {
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

/// `HttpThreatFieldsStored` structure from version 0.43.x (before the
/// `cluster_id` type change).
/// In 0.43.x, `cluster_id` was `Option<usize>`. From 0.44.x, it changed to
/// `Option<u32>` in the stored schema.
///
/// Note: Other event types (`NetworkThreat`, `WindowsThreat`, `ExtraThreat`) are not generated
/// on production servers, so their migration structures are not needed.
#[derive(Debug, Deserialize, Serialize)]
pub struct HttpThreatFieldsV0_43 {
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
    pub cluster_id: Option<usize>, // OLD TYPE
    pub attack_kind: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

/// DGA fields from version 0.43.x
#[derive(Deserialize, Serialize)]
pub struct DgaFieldsV0_43 {
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

/// RDP brute force fields from version 0.43.x
#[derive(Serialize, Deserialize)]
pub struct RdpBruteForceFieldsV0_43 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub resp_addrs: Vec<IpAddr>,
    pub start_time: i64,
    pub end_time: i64,
    pub proto: u8,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

/// Blocklist RDP fields from version 0.43.x
#[derive(Serialize, Deserialize)]
pub struct BlocklistRdpFieldsV0_43 {
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

/// FTP brute force fields from version 0.43.x
#[derive(Serialize, Deserialize)]
pub struct FtpBruteForceFieldsV0_43 {
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

/// FTP event fields from version 0.43.x
#[derive(Deserialize, Serialize)]
pub struct FtpEventFieldsV0_43 {
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
    pub commands: Vec<FtpCommandV0_43>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

/// LDAP brute force fields from version 0.43.x
#[derive(Serialize, Deserialize)]
pub struct LdapBruteForceFieldsV0_43 {
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

/// LDAP event fields from version 0.43.x
#[derive(Serialize, Deserialize)]
pub struct LdapEventFieldsV0_43 {
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

/// Blocklist SSH fields from version 0.43.x
#[derive(Serialize, Deserialize)]
pub struct BlocklistSshFieldsV0_43 {
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

/// Blocklist TLS fields from version 0.43.x
#[derive(Serialize, Deserialize)]
pub struct BlocklistTlsFieldsV0_43 {
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

/// Blocklist Kerberos fields from version 0.43.x
#[derive(Serialize, Deserialize)]
pub struct BlocklistKerberosFieldsV0_43 {
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

/// Blocklist SMTP fields from version 0.43.x
#[derive(Serialize, Deserialize)]
pub struct BlocklistSmtpFieldsV0_43 {
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

/// Blocklist NFS fields from version 0.43.x
#[derive(Serialize, Deserialize)]
pub struct BlocklistNfsFieldsV0_43 {
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

/// Blocklist DHCP fields from version 0.43.x
#[derive(Serialize, Deserialize)]
pub struct BlocklistDhcpFieldsV0_43 {
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

/// Blocklist DCE-RPC fields from version 0.43.x
#[derive(Serialize, Deserialize)]
pub struct BlocklistDceRpcFieldsV0_43 {
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

/// Blocklist NTLM fields from version 0.43.x
#[derive(Serialize, Deserialize)]
pub struct BlocklistNtlmFieldsV0_43 {
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

/// Blocklist SMB fields from version 0.43.x
#[derive(Serialize, Deserialize)]
pub struct BlocklistSmbFieldsV0_43 {
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

/// Blocklist MQTT fields from version 0.43.x
#[derive(Serialize, Deserialize)]
pub struct BlocklistMqttFieldsV0_43 {
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

/// Blocklist BOOTP fields from version 0.43.x
#[derive(Serialize, Deserialize)]
pub struct BlocklistBootpFieldsV0_43 {
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

/// Blocklist Radius fields from version 0.43.x
#[derive(Serialize, Deserialize)]
pub struct BlocklistRadiusFieldsV0_43 {
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

/// Blocklist malformed DNS fields from version 0.43.x
#[derive(Serialize, Deserialize)]
pub struct BlocklistMalformedDnsFieldsV0_43 {
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

/// Unusual destination pattern fields from version 0.43.x
#[derive(Serialize, Deserialize)]
pub struct UnusualDestinationPatternFieldsV0_43 {
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
