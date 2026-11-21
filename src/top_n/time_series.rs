#![allow(deprecated)] // TODO: Remove this when LineSegment and Regression structs are deleted

use jiff::Timestamp;
use serde::Deserialize;

#[deprecated(
    since = "0.41.0",
    note = "This structure is no longer used and will be removed in a future version"
)]
// Frontend uses count of usize
#[derive(Clone, Debug, Deserialize)]
pub struct TimeCount {
    pub time: Timestamp,
    pub count: usize,
}

#[deprecated(
    since = "0.41.0",
    note = "This structure is no longer used and will be removed in a future version"
)]
#[derive(Deserialize)]
pub struct TopTrendsByColumn {
    pub count_index: usize, // 100_000 means counting events themselves.
    pub trends: Vec<ClusterTrend>,
}

#[deprecated(
    since = "0.41.0",
    note = "This structure is no longer used and will be removed in a future version"
)]
#[derive(Clone, Deserialize)]
pub struct ClusterTrend {
    pub cluster_id: String,
    pub series: Vec<TimeCount>,
}

#[deprecated(
    since = "0.41.0",
    note = "This structure is no longer used and will be removed in a future version"
)]
#[derive(Clone, Deserialize)]
pub struct LineSegment {
    pub first_index: usize,
    pub last_index: usize,
    pub reg_original: Regression,
    pub reg_trend: Regression,
}

#[deprecated(
    since = "0.41.0",
    note = "This structure is no longer used and will be removed in a future version"
)]
#[derive(Clone, Deserialize)]
pub struct Regression {
    pub slope: f64,
    pub intercept: f64,
    pub r_square: f64,
}
