//! Old data structures for migration purposes.
//!
//! These structures represent the schemas from previous releases
//! and must not be modified. They are used to migrate data from
//! old formats to new formats.

use serde::{Deserialize, Serialize};

use crate::HostNetworkGroup;
use crate::PeriodForSearch;
use crate::event::{FilterEndpoint, FlowKind, LearningMethod};

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
