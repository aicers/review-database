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
// Old event structures for migration (cluster_id: Option<usize> -> Option<u32>)
// ============================================================================

use std::net::IpAddr;

use chrono::serde::ts_nanoseconds;

use crate::EventCategory;

/// `BlocklistDceRpcFields` structure from version 0.42.x (before context/request changes)
///
/// In 0.42.x, DCE/RPC events used single-value fields (`rtt`, `named_pipe`,
/// `endpoint`, `operation`). From 0.44.x, these were replaced with
/// `context: Vec<DceRpcContext>` and `request: Vec<String>`.
#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistDceRpcFieldsV0_42 {
    pub(crate) sensor: String,
    pub(crate) orig_addr: IpAddr,
    pub(crate) orig_port: u16,
    pub(crate) resp_addr: IpAddr,
    pub(crate) resp_port: u16,
    pub(crate) proto: u8,
    pub(crate) start_time: i64,
    pub(crate) duration: i64,
    pub(crate) orig_pkts: u64,
    pub(crate) resp_pkts: u64,
    pub(crate) orig_l2_bytes: u64,
    pub(crate) resp_l2_bytes: u64,
    pub(crate) rtt: i64,
    pub(crate) named_pipe: String,
    pub(crate) endpoint: String,
    pub(crate) operation: String,
    pub(crate) confidence: f32,
    pub(crate) category: Option<EventCategory>,
}

/// `HttpThreatFields` structure from version 0.43.x (before `cluster_id` type change)
/// In 0.43.x, `cluster_id` was `Option<usize>`. From 0.44.x, it changed to `Option<u32>`.
///
/// Note: Other event types (`NetworkThreat`, `WindowsThreat`, `ExtraThreat`) are not generated
/// on production servers, so their migration structures are not needed.
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct HttpThreatFieldsV0_43 {
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
