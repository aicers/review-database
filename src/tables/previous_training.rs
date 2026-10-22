//! The read view of the previous training results.

use rocksdb::OptimisticTransactionDB;

use super::Cluster;
use super::{ColumnStats, CsvColumnExtra, IndexedTable, OutlierInfo, Table, TimeSeries};
use crate::{BatchInfo, IndexedMap, Map, Scores};

/// A read view of every model's previous training result: the per-model rows
/// a replace moved out of the current tables, in mirror column families with
/// the same row layout.
///
/// Each method returns the same table type as the [`Store`](crate::Store)
/// method of the same name, opened on the mirror. The view is read-only by
/// contract: nothing in this crate writes the mirrors except
/// [`Store::replace_model`](crate::Store::replace_model), which overwrites a
/// model's previous result with its current one, and
/// [`Store::delete_model`](crate::Store::delete_model). The writers the
/// returned tables expose must not be called through it, and the previous
/// result has no restore.
///
/// A model whose record has no
/// [`previous`](crate::ModelDigest::previous) summary has no rows here.
pub struct PreviousTrainingResults<'d> {
    batch_info: Map<'d>,
    scores: Map<'d>,
    cluster: Map<'d>,
    column_stats: Map<'d>,
    csv_column_extras: IndexedMap<'d>,
    time_series: Map<'d>,
    outliers: Map<'d>,
}

impl<'d> PreviousTrainingResults<'d> {
    /// Opens the view, or returns `None` if a mirror column family is
    /// missing.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Some(Self {
            batch_info: Map::open(db, super::PREVIOUS_BATCH_INFO)?,
            scores: Map::open(db, super::PREVIOUS_SCORES)?,
            cluster: Map::open(db, super::PREVIOUS_CLUSTER)?,
            column_stats: Map::open(db, super::PREVIOUS_COLUMN_STATS)?,
            csv_column_extras: IndexedMap::new(db, super::PREVIOUS_CSV_COLUMN_EXTRAS).ok()?,
            time_series: Map::open(db, super::PREVIOUS_TIME_SERIES)?,
            outliers: Map::open(db, super::PREVIOUS_OUTLIERS)?,
        })
    }

    /// Returns the previous batch information of every model.
    #[must_use]
    pub fn batch_info_map(&self) -> Table<'d, BatchInfo> {
        Table::new(self.batch_info.clone())
    }

    /// Returns the previous scores of every model.
    #[must_use]
    pub fn scores_map(&self) -> Table<'d, Scores> {
        Table::new(self.scores.clone())
    }

    /// Returns the previous clusters of every model.
    #[must_use]
    pub fn cluster_map(&self) -> Table<'d, Cluster> {
        Table::new(self.cluster.clone())
    }

    /// Returns the previous column statistics of every model.
    #[must_use]
    pub fn column_stats_map(&self) -> Table<'d, ColumnStats> {
        Table::new(self.column_stats.clone())
    }

    /// Returns the previous CSV column extras of every model.
    ///
    /// A moved row keeps its model id but carries an id in this mirror's own
    /// index, not the one it had in the current table.
    #[must_use]
    pub fn csv_column_extra_map(&self) -> IndexedTable<'d, CsvColumnExtra> {
        IndexedTable::new(self.csv_column_extras.clone())
    }

    /// Returns the previous time series of every model.
    #[must_use]
    pub fn time_series_map(&self) -> Table<'d, TimeSeries> {
        Table::new(self.time_series.clone())
    }

    /// Returns the previous outliers of every model.
    #[must_use]
    pub fn outlier_map(&self) -> Table<'d, OutlierInfo> {
        Table::new(self.outliers.clone())
    }
}
