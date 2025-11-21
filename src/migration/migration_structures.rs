//! Old data structures for migration purposes.
//!
//! These structures represent the schemas from previous releases
//! and must not be modified. They are used to migrate data from
//! old formats to new formats.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::event::{FilterEndpoint, FlowKind, LearningMethod};
use crate::{
    Confidence, EventCategory, PacketAttr, PeriodForSearch, Response, TidbKind, TidbRule,
    TriageExclusionReason,
};

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

/// `TriagePolicy` structure from version 0.42.x
///
/// This structure represents the triage policy schema before the addition
/// of the `customer_ids` field.
#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct TriagePolicyV0_42 {
    pub(crate) id: u32,
    pub(crate) name: String,
    pub(crate) ti_db: Vec<TriageExclusionReason>,
    pub(crate) packet_attr: Vec<PacketAttr>,
    pub(crate) confidence: Vec<Confidence>,
    pub(crate) response: Vec<Response>,
    pub(crate) creation_time: DateTime<Utc>,
}

impl From<TriagePolicyV0_42> for crate::TriagePolicy {
    fn from(old: TriagePolicyV0_42) -> Self {
        Self {
            id: old.id,
            name: old.name,
            ti_db: old.ti_db,
            packet_attr: old.packet_attr,
            confidence: old.confidence,
            response: old.response,
            creation_time: old.creation_time,
            customer_ids: None,
        }
    }
}

/// `Tidb` structure from version 0.42.x
///
/// This structure represents the TI database schema before the addition
/// of the `customer_ids` field.
#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct TidbV0_42 {
    pub(crate) id: u32,
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) kind: TidbKind,
    pub(crate) category: EventCategory,
    pub(crate) version: String,
    pub(crate) patterns: Vec<TidbRule>,
}

impl From<TidbV0_42> for crate::Tidb {
    fn from(old: TidbV0_42) -> Self {
        Self {
            id: old.id,
            name: old.name,
            description: old.description,
            kind: old.kind,
            category: old.category,
            version: old.version,
            patterns: old.patterns,
            customer_ids: None,
        }
    }
}
