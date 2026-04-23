//! Old data structures for migration purposes.
//!
//! These structures represent the schemas from previous releases
//! and must not be modified. They are used to migrate data from
//! old formats to new formats.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::HostNetworkGroup;

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
// Old event structures for migration
// ============================================================================

use std::net::IpAddr;

use chrono::serde::ts_nanoseconds;

use crate::EventCategory;

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

/// `HttpThreatFieldsStored` structure from version 0.43.x
/// (before `cluster_id` type change).
/// In 0.43.x, `cluster_id` was `Option<usize>`. From 0.44.x, it changed to
/// `Option<u32>` in the stored schema.
///
/// Note: Other event types (`NetworkThreat`, `WindowsThreat`, `ExtraThreat`) are not generated
/// on production servers, so their migration structures are not needed.
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
