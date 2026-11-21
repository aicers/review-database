use jiff::Timestamp;
use serde::Serialize;
use structured::ColumnStatistics;

#[derive(Serialize)]
pub struct Statistics {
    pub(crate) batch_ts: Timestamp,
    pub(crate) column_index: i32,
    pub(crate) column_stats: ColumnStatistics,
}
