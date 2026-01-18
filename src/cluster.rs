#![allow(deprecated)]
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

use crate::types::Cluster;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpdateClusterRequest {
    pub cluster_id: u32,
    pub detector_id: i32,
    pub signature: String,
    pub score: Option<f64>,
    pub size: i64,
    pub event_ids: Vec<crate::types::Id>,
    pub status_id: i32,
    pub labels: Option<Vec<String>>,
}

struct ClusterDbSchema {
    id: i32,
    cluster_id: u32,
    category_id: i32,
    detector_id: i32,
    event_ids: Vec<Option<i64>>,
    sensors: Vec<Option<String>>,
    labels: Option<Vec<Option<String>>>,
    qualifier_id: i32,
    status_id: i32,
    signature: String,
    size: i64,
    score: Option<f64>,
    last_modification_time: Option<NaiveDateTime>,
    model_id: u32,
}

impl From<ClusterDbSchema> for Cluster {
    fn from(c: ClusterDbSchema) -> Self {
        let event_ids: Vec<i64> = c.event_ids.into_iter().flatten().collect();
        let sensors: Vec<String> = c.sensors.into_iter().flatten().collect();
        let labels: Option<Vec<String>> = c
            .labels
            .map(|labels| labels.into_iter().flatten().collect());
        Cluster {
            id: c.id,
            cluster_id: c.cluster_id,
            category_id: c.category_id,
            detector_id: c.detector_id,
            event_ids,
            sensors,
            labels,
            qualifier_id: c.qualifier_id,
            status_id: c.status_id,
            signature: c.signature,
            size: c.size,
            score: c.score,
            last_modification_time: c.last_modification_time,
            model_id: c.model_id,
        }
    }
}
