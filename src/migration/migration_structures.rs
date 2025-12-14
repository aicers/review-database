//! Old data structures for migration purposes.
//!
//! These structures represent the schemas from previous releases
//! and must not be modified. They are used to migrate data from
//! old formats to new formats.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::PeriodForSearch;
use crate::event::{FilterEndpoint, FlowKind, LearningMethod};
use crate::types::{EventCategory, HostNetworkGroup};

/// Filter value structure from version 0.41.x
///
/// This structure represents the persisted filter schema with a single
/// `confidence` field (minimum threshold semantics) before the change
/// to range-based filtering with `confidence_min` and `confidence_max`.
#[derive(Serialize, Deserialize)]
pub(crate) struct FilterValueV0_41 {
    pub(crate) directions: Option<Vec<FlowKind>>,
    pub(crate) keywords: Option<Vec<String>>,
    pub(crate) network_tags: Option<Vec<String>>,
    pub(crate) customers: Option<Vec<String>>,
    pub(crate) endpoints: Option<Vec<FilterEndpoint>>,
    pub(crate) sensors: Option<Vec<String>>,
    pub(crate) os: Option<Vec<String>>,
    pub(crate) devices: Option<Vec<String>>,
    pub(crate) hostnames: Option<Vec<String>>,
    pub(crate) user_ids: Option<Vec<String>>,
    pub(crate) user_names: Option<Vec<String>>,
    pub(crate) user_departments: Option<Vec<String>>,
    pub(crate) countries: Option<Vec<String>>,
    pub(crate) categories: Option<Vec<u8>>,
    pub(crate) levels: Option<Vec<u8>>,
    pub(crate) kinds: Option<Vec<String>>,
    pub(crate) learning_methods: Option<Vec<LearningMethod>>,
    pub(crate) confidence: Option<f32>,
    pub(crate) period: PeriodForSearch,
}

impl From<FilterValueV0_41> for crate::FilterValue {
    fn from(old: FilterValueV0_41) -> Self {
        Self {
            directions: old.directions,
            keywords: old.keywords,
            network_tags: old.network_tags,
            customers: old.customers,
            endpoints: old.endpoints,
            sensors: old.sensors,
            os: old.os,
            devices: old.devices,
            hostnames: old.hostnames,
            user_ids: old.user_ids,
            user_names: old.user_names,
            user_departments: old.user_departments,
            countries: old.countries,
            categories: old.categories,
            levels: old.levels,
            kinds: old.kinds,
            learning_methods: old.learning_methods,
            confidence_min: old.confidence,
            confidence_max: None,
            period: old.period,
        }
    }
}

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

// =============================================================================
// Event Fields V0_42 structures (before src_country_code/dst_country_code)
// These structs represent event field schemas from version 0.42.x without
// country code fields. From 0.43.x, country code fields were added.
// =============================================================================

/// FTP Command structure for `V0_42` migration
#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct FtpCommandV0_42 {
    pub command: String,
    pub reply_code: String,
    pub reply_msg: String,
}

/// Port scan fields from version 0.42.x (before country codes were added)
#[derive(Serialize, Deserialize)]
pub(crate) struct PortScanFieldsV0_42 {
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

/// Multi-host port scan fields from version 0.42.x
#[derive(Serialize, Deserialize)]
pub(crate) struct MultiHostPortScanFieldsV0_42 {
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

/// External `DDoS` fields from version 0.42.x
#[derive(Serialize, Deserialize)]
pub(crate) struct ExternalDdosFieldsV0_42 {
    pub sensor: String,
    pub orig_addrs: Vec<IpAddr>,
    pub resp_addr: IpAddr,
    pub proto: u8,
    pub start_time: i64,
    pub end_time: i64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

/// Blocklist connection fields from version 0.42.x
#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistConnFieldsV0_42 {
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

/// DNS event fields from version 0.42.x
#[allow(clippy::struct_excessive_bools)]
#[derive(Deserialize, Serialize)]
pub(crate) struct DnsEventFieldsV0_42 {
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

/// Cryptocurrency mining pool fields from version 0.42.x
#[allow(clippy::struct_excessive_bools)]
#[derive(Deserialize, Serialize)]
pub(crate) struct CryptocurrencyMiningPoolFieldsV0_42 {
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

/// Blocklist DNS fields from version 0.42.x
#[allow(clippy::struct_excessive_bools)]
#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistDnsFieldsV0_42 {
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

/// HTTP event fields from version 0.42.x
#[derive(Deserialize, Serialize)]
pub(crate) struct HttpEventFieldsV0_42 {
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

/// Repeated HTTP sessions fields from version 0.42.x
#[derive(Serialize, Deserialize)]
pub(crate) struct RepeatedHttpSessionsFieldsV0_42 {
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

/// HTTP threat fields from version 0.42.x
#[derive(Deserialize, Serialize)]
pub(crate) struct HttpThreatFieldsV0_42 {
    #[serde(with = "chrono::serde::ts_nanoseconds")]
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

/// DGA fields from version 0.42.x
#[derive(Deserialize, Serialize)]
pub(crate) struct DgaFieldsV0_42 {
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

/// RDP brute force fields from version 0.42.x
#[derive(Serialize, Deserialize)]
pub(crate) struct RdpBruteForceFieldsV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub resp_addrs: Vec<IpAddr>,
    pub start_time: i64,
    pub end_time: i64,
    pub proto: u8,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

/// Blocklist RDP fields from version 0.42.x
#[derive(Serialize, Deserialize)]
pub(crate) struct BlocklistRdpFieldsV0_42 {
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

/// FTP brute force fields from version 0.42.x
#[derive(Serialize, Deserialize)]
pub(crate) struct FtpBruteForceFieldsV0_42 {
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

/// FTP event fields from version 0.42.x
#[derive(Deserialize, Serialize)]
pub(crate) struct FtpEventFieldsV0_42 {
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
    pub commands: Vec<FtpCommandV0_42>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

/// LDAP brute force fields from version 0.42.x
#[derive(Serialize, Deserialize)]
pub(crate) struct LdapBruteForceFieldsV0_42 {
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

/// LDAP event fields from version 0.42.x
#[derive(Serialize, Deserialize)]
pub(crate) struct LdapEventFieldsV0_42 {
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

/// Blocklist SSH fields from version 0.42.x
#[derive(Serialize, Deserialize)]
pub(crate) struct BlocklistSshFieldsV0_42 {
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

/// Blocklist TLS fields from version 0.42.x
#[derive(Serialize, Deserialize)]
pub(crate) struct BlocklistTlsFieldsV0_42 {
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

/// Blocklist Kerberos fields from version 0.42.x
#[derive(Serialize, Deserialize)]
pub(crate) struct BlocklistKerberosFieldsV0_42 {
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

/// Blocklist SMTP fields from version 0.42.x
#[derive(Serialize, Deserialize)]
pub(crate) struct BlocklistSmtpFieldsV0_42 {
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

/// Blocklist NFS fields from version 0.42.x
#[derive(Serialize, Deserialize)]
pub(crate) struct BlocklistNfsFieldsV0_42 {
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

/// Blocklist DHCP fields from version 0.42.x
#[derive(Serialize, Deserialize)]
pub(crate) struct BlocklistDhcpFieldsV0_42 {
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

/// Blocklist DCE-RPC fields from version 0.42.x
#[derive(Serialize, Deserialize)]
pub(crate) struct BlocklistDceRpcFieldsV0_42 {
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

/// Blocklist NTLM fields from version 0.42.x
#[derive(Serialize, Deserialize)]
pub(crate) struct BlocklistNtlmFieldsV0_42 {
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

/// Blocklist SMB fields from version 0.42.x
#[derive(Serialize, Deserialize)]
pub(crate) struct BlocklistSmbFieldsV0_42 {
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

/// Blocklist MQTT fields from version 0.42.x
#[derive(Serialize, Deserialize)]
pub(crate) struct BlocklistMqttFieldsV0_42 {
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

/// Blocklist BOOTP fields from version 0.42.x
#[derive(Serialize, Deserialize)]
pub(crate) struct BlocklistBootpFieldsV0_42 {
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

/// Blocklist Radius fields from version 0.42.x
#[derive(Serialize, Deserialize)]
pub(crate) struct BlocklistRadiusFieldsV0_42 {
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

/// Blocklist malformed DNS fields from version 0.42.x
#[derive(Serialize, Deserialize)]
pub(crate) struct BlocklistMalformedDnsFieldsV0_42 {
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

/// Unusual destination pattern fields from version 0.42.x
#[derive(Serialize, Deserialize)]
pub(crate) struct UnusualDestinationPatternFieldsV0_42 {
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

// =============================================================================
// From trait implementations for V0_42 -> V0_43 conversions
// These enable migrating old event fields to new format with country codes
// =============================================================================

use crate::event::ExternalDdosFields;
use crate::event::{
    BlocklistBootpFields, BlocklistConnFields, BlocklistDceRpcFields, BlocklistDhcpFields,
    BlocklistDnsFields, BlocklistKerberosFields, BlocklistMalformedDnsFields, BlocklistMqttFields,
    BlocklistNfsFields, BlocklistNtlmFields, BlocklistRadiusFields, BlocklistRdpFields,
    BlocklistSmbFields, BlocklistSmtpFields, BlocklistSshFields, BlocklistTlsFields,
    CryptocurrencyMiningPoolFields, DgaFields, DnsEventFields, FtpBruteForceFields, FtpCommand,
    FtpEventFields, HttpEventFields, HttpThreatFields, LdapBruteForceFields, LdapEventFields,
    MultiHostPortScanFields, PortScanFields, RdpBruteForceFields, RepeatedHttpSessionsFields,
    UnusualDestinationPatternFields,
};

impl From<PortScanFieldsV0_42> for PortScanFields {
    fn from(old: PortScanFieldsV0_42) -> Self {
        Self {
            sensor: old.sensor,
            src_country_code: None,
            orig_addr: old.orig_addr,
            resp_addr: old.resp_addr,
            dst_country_code: None,
            resp_ports: old.resp_ports,
            start_time: old.start_time,
            end_time: old.end_time,
            proto: old.proto,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<MultiHostPortScanFieldsV0_42> for MultiHostPortScanFields {
    fn from(old: MultiHostPortScanFieldsV0_42) -> Self {
        let dst_country_codes = vec![None; old.resp_addrs.len()];
        Self {
            sensor: old.sensor,
            src_country_code: None,
            orig_addr: old.orig_addr,
            resp_port: old.resp_port,
            resp_addrs: old.resp_addrs,
            dst_country_codes,
            proto: old.proto,
            start_time: old.start_time,
            end_time: old.end_time,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<ExternalDdosFieldsV0_42> for ExternalDdosFields {
    fn from(old: ExternalDdosFieldsV0_42) -> Self {
        let src_country_codes = vec![None; old.orig_addrs.len()];
        Self {
            sensor: old.sensor,
            orig_addrs: old.orig_addrs,
            src_country_codes,
            resp_addr: old.resp_addr,
            dst_country_code: None,
            proto: old.proto,
            start_time: old.start_time,
            end_time: old.end_time,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistConnFieldsV0_42> for BlocklistConnFields {
    fn from(old: BlocklistConnFieldsV0_42) -> Self {
        Self {
            sensor: old.sensor,
            src_country_code: None,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            resp_addr: old.resp_addr,
            dst_country_code: None,
            resp_port: old.resp_port,
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

impl From<DnsEventFieldsV0_42> for DnsEventFields {
    fn from(old: DnsEventFieldsV0_42) -> Self {
        Self {
            sensor: old.sensor,
            src_country_code: None,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            resp_addr: old.resp_addr,
            dst_country_code: None,
            resp_port: old.resp_port,
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

impl From<CryptocurrencyMiningPoolFieldsV0_42> for CryptocurrencyMiningPoolFields {
    fn from(old: CryptocurrencyMiningPoolFieldsV0_42) -> Self {
        Self {
            sensor: old.sensor,
            src_country_code: None,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            resp_addr: old.resp_addr,
            dst_country_code: None,
            resp_port: old.resp_port,
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

impl From<BlocklistDnsFieldsV0_42> for BlocklistDnsFields {
    fn from(old: BlocklistDnsFieldsV0_42) -> Self {
        Self {
            sensor: old.sensor,
            src_country_code: None,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            resp_addr: old.resp_addr,
            dst_country_code: None,
            resp_port: old.resp_port,
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

impl From<HttpEventFieldsV0_42> for HttpEventFields {
    fn from(old: HttpEventFieldsV0_42) -> Self {
        Self {
            sensor: old.sensor,
            src_country_code: None,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            resp_addr: old.resp_addr,
            dst_country_code: None,
            resp_port: old.resp_port,
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

impl From<RepeatedHttpSessionsFieldsV0_42> for RepeatedHttpSessionsFields {
    fn from(old: RepeatedHttpSessionsFieldsV0_42) -> Self {
        Self {
            sensor: old.sensor,
            src_country_code: None,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            resp_addr: old.resp_addr,
            dst_country_code: None,
            resp_port: old.resp_port,
            proto: old.proto,
            start_time: old.start_time,
            end_time: old.end_time,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<HttpThreatFieldsV0_42> for HttpThreatFields {
    fn from(old: HttpThreatFieldsV0_42) -> Self {
        Self {
            time: old.time,
            sensor: old.sensor,
            src_country_code: None,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            resp_addr: old.resp_addr,
            dst_country_code: None,
            resp_port: old.resp_port,
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

impl From<DgaFieldsV0_42> for DgaFields {
    fn from(old: DgaFieldsV0_42) -> Self {
        Self {
            sensor: old.sensor,
            src_country_code: None,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            resp_addr: old.resp_addr,
            dst_country_code: None,
            resp_port: old.resp_port,
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

impl From<RdpBruteForceFieldsV0_42> for RdpBruteForceFields {
    fn from(old: RdpBruteForceFieldsV0_42) -> Self {
        let dst_country_codes = vec![None; old.resp_addrs.len()];
        Self {
            sensor: old.sensor,
            src_country_code: None,
            orig_addr: old.orig_addr,
            resp_addrs: old.resp_addrs,
            dst_country_codes,
            start_time: old.start_time,
            end_time: old.end_time,
            proto: old.proto,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistRdpFieldsV0_42> for BlocklistRdpFields {
    fn from(old: BlocklistRdpFieldsV0_42) -> Self {
        Self {
            sensor: old.sensor,
            src_country_code: None,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            resp_addr: old.resp_addr,
            dst_country_code: None,
            resp_port: old.resp_port,
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

impl From<FtpBruteForceFieldsV0_42> for FtpBruteForceFields {
    fn from(old: FtpBruteForceFieldsV0_42) -> Self {
        Self {
            sensor: old.sensor,
            src_country_code: None,
            orig_addr: old.orig_addr,
            resp_addr: old.resp_addr,
            dst_country_code: None,
            resp_port: old.resp_port,
            proto: old.proto,
            user_list: old.user_list,
            start_time: old.start_time,
            end_time: old.end_time,
            is_internal: old.is_internal,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<FtpCommandV0_42> for FtpCommand {
    fn from(old: FtpCommandV0_42) -> Self {
        use std::net::{IpAddr, Ipv4Addr};
        Self {
            command: old.command,
            reply_code: old.reply_code,
            reply_msg: old.reply_msg,
            // New fields added after V0_42 - use sensible defaults
            data_passive: false,
            data_orig_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            data_resp_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            data_resp_port: 0,
            file: String::new(),
            file_size: 0,
            file_id: String::new(),
        }
    }
}

impl From<FtpEventFieldsV0_42> for FtpEventFields {
    fn from(old: FtpEventFieldsV0_42) -> Self {
        Self {
            sensor: old.sensor,
            src_country_code: None,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            resp_addr: old.resp_addr,
            dst_country_code: None,
            resp_port: old.resp_port,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            user: old.user,
            password: old.password,
            commands: old.commands.into_iter().map(Into::into).collect(),
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<LdapBruteForceFieldsV0_42> for LdapBruteForceFields {
    fn from(old: LdapBruteForceFieldsV0_42) -> Self {
        Self {
            sensor: old.sensor,
            src_country_code: None,
            orig_addr: old.orig_addr,
            resp_addr: old.resp_addr,
            dst_country_code: None,
            resp_port: old.resp_port,
            proto: old.proto,
            user_pw_list: old.user_pw_list,
            start_time: old.start_time,
            end_time: old.end_time,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<LdapEventFieldsV0_42> for LdapEventFields {
    fn from(old: LdapEventFieldsV0_42) -> Self {
        Self {
            sensor: old.sensor,
            src_country_code: None,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            resp_addr: old.resp_addr,
            dst_country_code: None,
            resp_port: old.resp_port,
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

impl From<BlocklistSshFieldsV0_42> for BlocklistSshFields {
    fn from(old: BlocklistSshFieldsV0_42) -> Self {
        Self {
            sensor: old.sensor,
            src_country_code: None,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            resp_addr: old.resp_addr,
            dst_country_code: None,
            resp_port: old.resp_port,
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

impl From<BlocklistTlsFieldsV0_42> for BlocklistTlsFields {
    fn from(old: BlocklistTlsFieldsV0_42) -> Self {
        Self {
            sensor: old.sensor,
            src_country_code: None,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            resp_addr: old.resp_addr,
            dst_country_code: None,
            resp_port: old.resp_port,
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

impl From<BlocklistKerberosFieldsV0_42> for BlocklistKerberosFields {
    fn from(old: BlocklistKerberosFieldsV0_42) -> Self {
        Self {
            sensor: old.sensor,
            src_country_code: None,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            resp_addr: old.resp_addr,
            dst_country_code: None,
            resp_port: old.resp_port,
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
            client_name: old.client_name,
            realm: old.realm,
            sname_type: old.sname_type,
            service_name: old.service_name,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistSmtpFieldsV0_42> for BlocklistSmtpFields {
    fn from(old: BlocklistSmtpFieldsV0_42) -> Self {
        Self {
            sensor: old.sensor,
            src_country_code: None,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            resp_addr: old.resp_addr,
            dst_country_code: None,
            resp_port: old.resp_port,
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

impl From<BlocklistNfsFieldsV0_42> for BlocklistNfsFields {
    fn from(old: BlocklistNfsFieldsV0_42) -> Self {
        Self {
            sensor: old.sensor,
            src_country_code: None,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            resp_addr: old.resp_addr,
            dst_country_code: None,
            resp_port: old.resp_port,
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

impl From<BlocklistDhcpFieldsV0_42> for BlocklistDhcpFields {
    fn from(old: BlocklistDhcpFieldsV0_42) -> Self {
        Self {
            sensor: old.sensor,
            src_country_code: None,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            resp_addr: old.resp_addr,
            dst_country_code: None,
            resp_port: old.resp_port,
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
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistDceRpcFieldsV0_42> for BlocklistDceRpcFields {
    fn from(old: BlocklistDceRpcFieldsV0_42) -> Self {
        Self {
            sensor: old.sensor,
            src_country_code: None,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            resp_addr: old.resp_addr,
            dst_country_code: None,
            resp_port: old.resp_port,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            rtt: old.rtt,
            named_pipe: old.named_pipe,
            endpoint: old.endpoint,
            operation: old.operation,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistNtlmFieldsV0_42> for BlocklistNtlmFields {
    fn from(old: BlocklistNtlmFieldsV0_42) -> Self {
        Self {
            sensor: old.sensor,
            src_country_code: None,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            resp_addr: old.resp_addr,
            dst_country_code: None,
            resp_port: old.resp_port,
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

impl From<BlocklistSmbFieldsV0_42> for BlocklistSmbFields {
    fn from(old: BlocklistSmbFieldsV0_42) -> Self {
        Self {
            sensor: old.sensor,
            src_country_code: None,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            resp_addr: old.resp_addr,
            dst_country_code: None,
            resp_port: old.resp_port,
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

impl From<BlocklistMqttFieldsV0_42> for BlocklistMqttFields {
    fn from(old: BlocklistMqttFieldsV0_42) -> Self {
        Self {
            sensor: old.sensor,
            src_country_code: None,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            resp_addr: old.resp_addr,
            dst_country_code: None,
            resp_port: old.resp_port,
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

impl From<BlocklistBootpFieldsV0_42> for BlocklistBootpFields {
    fn from(old: BlocklistBootpFieldsV0_42) -> Self {
        Self {
            sensor: old.sensor,
            src_country_code: None,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            resp_addr: old.resp_addr,
            dst_country_code: None,
            resp_port: old.resp_port,
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

impl From<BlocklistRadiusFieldsV0_42> for BlocklistRadiusFields {
    fn from(old: BlocklistRadiusFieldsV0_42) -> Self {
        Self {
            sensor: old.sensor,
            src_country_code: None,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            resp_addr: old.resp_addr,
            dst_country_code: None,
            resp_port: old.resp_port,
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

impl From<BlocklistMalformedDnsFieldsV0_42> for BlocklistMalformedDnsFields {
    fn from(old: BlocklistMalformedDnsFieldsV0_42) -> Self {
        Self {
            sensor: old.sensor,
            src_country_code: None,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            resp_addr: old.resp_addr,
            dst_country_code: None,
            resp_port: old.resp_port,
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

impl From<UnusualDestinationPatternFieldsV0_42> for UnusualDestinationPatternFields {
    fn from(old: UnusualDestinationPatternFieldsV0_42) -> Self {
        let dst_country_codes = vec![None; old.destination_ips.len()];
        Self {
            sensor: old.sensor,
            start_time: old.start_time,
            end_time: old.end_time,
            destination_ips: old.destination_ips,
            dst_country_codes,
            count: old.count,
            expected_mean: old.expected_mean,
            std_deviation: old.std_deviation,
            z_score: old.z_score,
            confidence: old.confidence,
            category: old.category,
        }
    }
}
