//! Old data structures for migration purposes.
//!
//! These structures represent the schemas from previous releases
//! and must not be modified. They are used to migrate data from
//! old formats to new formats.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::PeriodForSearch;
use crate::event::{FilterEndpoint, FlowKind, LearningMethod};
use crate::types::HostNetworkGroup;

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

// ============================================================================
// Migration structures for cluster_id/model_id type unification (0.43 -> 0.44)
// ============================================================================

/// Key structure for `Cluster` table from version 0.43.x
/// In 0.43.x, `cluster_id` was `i32`. From 0.44.x, it changed to `u32`.
pub(crate) struct ClusterKeyV0_43 {
    pub(crate) model_id: u32,
    pub(crate) cluster_id: i32,
}

impl ClusterKeyV0_43 {
    pub(crate) fn from_be_bytes(buf: &[u8]) -> Self {
        let (val, rest) = buf.split_at(std::mem::size_of::<u32>());
        let mut arr = [0; std::mem::size_of::<u32>()];
        arr.copy_from_slice(val);
        let model_id = u32::from_be_bytes(arr);

        let mut arr = [0; std::mem::size_of::<i32>()];
        arr.copy_from_slice(rest);
        let cluster_id = i32::from_be_bytes(arr);

        Self {
            model_id,
            cluster_id,
        }
    }
}

/// Key structure for `TimeSeries` table from version 0.43.x
/// In 0.43.x, `cluster_id` was `i32`. From 0.44.x, it changed to `u32`.
pub(crate) struct TimeSeriesKeyV0_43 {
    pub(crate) model_id: u32,
    pub(crate) cluster_id: i32,
    pub(crate) time: i64,
    pub(crate) value: i64,
    pub(crate) count_index: Option<i32>,
}

impl TimeSeriesKeyV0_43 {
    pub(crate) fn from_bytes(buf: &[u8]) -> Self {
        let (val, rest) = buf.split_at(std::mem::size_of::<u32>());
        let mut arr = [0; std::mem::size_of::<u32>()];
        arr.copy_from_slice(val);
        let model_id = u32::from_be_bytes(arr);

        let (val, rest) = rest.split_at(std::mem::size_of::<i32>());
        let mut arr = [0; std::mem::size_of::<i32>()];
        arr.copy_from_slice(val);
        let cluster_id = i32::from_be_bytes(arr);

        let (val, rest) = rest.split_at(std::mem::size_of::<i64>());
        let mut arr = [0; std::mem::size_of::<i64>()];
        arr.copy_from_slice(val);
        let time = i64::from_be_bytes(arr);

        let (val, rest) = rest.split_at(std::mem::size_of::<i64>());
        arr.copy_from_slice(val);
        let value = i64::from_be_bytes(arr);

        let count_index = if rest.is_empty() {
            None
        } else {
            let mut arr = [0; std::mem::size_of::<i32>()];
            arr.copy_from_slice(rest);
            Some(i32::from_be_bytes(arr))
        };

        Self {
            model_id,
            cluster_id,
            time,
            value,
            count_index,
        }
    }

    pub(crate) fn to_new_key_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.model_id.to_be_bytes());
        // Convert i32 cluster_id to u32
        #[allow(clippy::cast_sign_loss)]
        let cluster_id_u32 = self.cluster_id as u32;
        buf.extend(cluster_id_u32.to_be_bytes());
        buf.extend(self.time.to_be_bytes());
        buf.extend(self.value.to_be_bytes());
        if let Some(count_index) = self.count_index {
            buf.extend(count_index.to_be_bytes());
        }
        buf
    }
}

// ============================================================================
// Old event structures for migration (cluster_id: Option<usize> -> Option<u32>)
// ============================================================================

use std::net::IpAddr;

use chrono::serde::ts_nanoseconds;

use crate::EventCategory;
use crate::event::TriageScore;

/// `HttpThreatFields` structure from version 0.43.x (before `cluster_id` type change)
/// In 0.43.x, `cluster_id` was `Option<usize>`. From 0.44.x, it changed to `Option<u32>`.
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

/// `NetworkThreat` structure from version 0.43.x (before `cluster_id` type change)
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct NetworkThreatV0_43 {
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
    pub cluster_id: Option<usize>, // OLD TYPE
    pub attack_kind: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

/// `WindowsThreat` structure from version 0.43.x (before `cluster_id` type change)
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct WindowsThreatV0_43 {
    #[serde(with = "ts_nanoseconds")]
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub service: String,
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub user: String,
    pub content: String,
    pub db_name: String,
    pub rule_id: u32,
    pub matched_to: String,
    pub cluster_id: Option<usize>, // OLD TYPE
    pub attack_kind: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

/// `ExtraThreat` structure from version 0.43.x (before `cluster_id` type change)
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct ExtraThreatV0_43 {
    #[serde(with = "ts_nanoseconds")]
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub service: String,
    pub content: String,
    pub db_name: String,
    pub rule_id: u32,
    pub matched_to: String,
    pub cluster_id: Option<usize>, // OLD TYPE
    pub attack_kind: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}
