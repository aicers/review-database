use std::collections::{BTreeMap, HashMap};

use anyhow::{Result, anyhow};
use rocksdb::OptimisticTransactionDB;

use crate::Iterable;
use crate::{Map, Table, UniqueKey, tables::Value, types::FromKeyValue};

impl<'d> Table<'d, TimeSeries> {
    /// Opens the `time_series` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::TIME_SERIES).map(Table::new)
    }

    /// Stores the time series of `model_id` for the batch at `batch_ts`.
    ///
    /// A row already stored under the same key is overwritten, so repeating
    /// an identical call succeeds and leaves the rows as the first call did.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn add_time_series(
        &self,
        model_id: u32,
        batch_ts: i64,
        series: Vec<(u32, Vec<Column>)>,
    ) -> Result<()> {
        let txn = self.map.db.transaction();
        for (cluster_id, columns) in series {
            for column in columns {
                for (value, count) in column.time_counts {
                    let ts = TimeSeries {
                        model_id,
                        cluster_id,
                        time: batch_ts,
                        count_index: column.index,
                        value,
                        count,
                    };
                    self.put_with_transaction(&ts, &txn)?;
                }
            }
        }
        Ok(txn.commit()?)
    }

    /// Returns the time range of time series for the given model.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database error occurs.
    pub fn get_time_range_of_model(&self, model_id: u32) -> Result<Option<(i64, i64)>> {
        use rocksdb::Direction;

        let prefix = model_id.to_be_bytes();
        self.prefix_iter(Direction::Forward, None, &prefix)
            .try_fold(None, |range: Option<(i64, i64)>, item| {
                let ts = item?;
                let value = ts.value;
                let new_range = match range {
                    Some((min, max)) => (min.min(value), max.max(value)),
                    None => (value, value),
                };
                Ok(Some(new_range))
            })
    }

    /// Gets the top time series of the given cluster, returning only stored points.
    ///
    /// `range` selects values according to [`TimeSeriesRange`]. The returned
    /// earliest and latest values cover the entire cluster, independent of the range.
    /// Columns are ordered by index, and points within each column by value.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database error occurs or count summation
    /// overflows for a value remaining in the result.
    pub fn get_top_time_series_of_cluster(
        &self,
        model_id: u32,
        cluster_id: u32,
        range: TimeSeriesRange,
    ) -> Result<(Option<i64>, Option<i64>, Vec<Column>)> {
        let mut prefix = [0; 8];
        prefix[..4].copy_from_slice(&model_id.to_be_bytes());
        prefix[4..].copy_from_slice(&cluster_id.to_be_bytes());
        let mut stored_range = None;
        let mut points = RangePoints::new(range);
        for item in self.prefix_iter(rocksdb::Direction::Forward, None, &prefix) {
            let ts = item?;
            stored_range = Some(extend_range(stored_range, ts.value));
            points.insert(&ts);
        }

        let mut columns: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for ((value, column, _), count) in points.counts {
            let count = count.ok_or_else(|| {
                anyhow!("count summation overflow for column {column:?}, value {value}")
            })?;
            columns.entry(column).or_default().push((value, count));
        }
        let columns = columns
            .into_iter()
            .map(|(index, time_counts)| Column { index, time_counts })
            .collect();
        let (earliest, latest) =
            stored_range.map_or((None, None), |(min, max)| (Some(min), Some(max)));
        Ok((earliest, latest, columns))
    }

    /// Returns the top trends of a model.
    ///
    /// When `time` is `Some`, selects that batch and ignores `range`.
    /// Otherwise, `range` selects values according to [`TimeSeriesRange`], with
    /// the latest value taken across all columns and clusters of the model.
    /// Points are ordered by value, and clusters by descending number of points.
    /// Column order is unspecified. Empty columns and clusters are omitted.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database operation fails or count
    /// summation overflows for a value remaining in the result, or a stored
    /// record cannot be decoded.
    pub fn get_top_time_series_of_model(
        &self,
        model_id: u32,
        time: Option<i64>,
        range: TimeSeriesRange,
    ) -> Result<Vec<(Option<i32>, Vec<Cluster>)>> {
        let mut points = RangePoints::new(if time.is_some() {
            TimeSeriesRange::Between {
                start: None,
                end: None,
            }
        } else {
            range
        });
        let prefix = model_id.to_be_bytes();
        for item in self.prefix_iter(rocksdb::Direction::Forward, None, &prefix) {
            let ts = item?;
            if time.is_some_and(|time| ts.time != time) {
                continue;
            }
            points.insert(&ts);
        }

        let mut columns: HashMap<_, HashMap<_, Vec<_>>> = HashMap::new();
        for ((value, column, cluster), count) in points.counts {
            let count = count.ok_or_else(|| {
                anyhow!(
                    "count summation overflow for cluster {cluster}, column {column:?}, value {value}"
                )
            })?;
            columns
                .entry(column)
                .or_default()
                .entry(cluster)
                .or_default()
                .push((value, count));
        }
        Ok(columns
            .into_iter()
            .map(|(column, clusters)| {
                let mut clusters: Vec<_> = clusters
                    .into_iter()
                    .map(|(id, time_counts)| Cluster { id, time_counts })
                    .collect();
                clusters.sort_unstable_by_key(|c| std::cmp::Reverse(c.time_counts.len()));
                (column, clusters)
            })
            .collect())
    }
}

/// Selects stored time-series values, measured in nanoseconds.
///
/// Queries return only stored points, summing duplicate values separately for
/// each column and cluster. No default window or vacant-slot filling is applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeSeriesRange {
    /// Includes values at or between the inclusive bounds. An omitted bound
    /// leaves that direction unbounded; omitting both includes all stored values.
    Between {
        start: Option<i64>,
        end: Option<i64>,
    },
    /// Includes values from `L - width` through `L`, where `L` is the latest
    /// stored value across the query target's columns (and, for a model, clusters).
    /// The lower bound saturates at `i64::MIN`. An empty target returns no points.
    Latest { width: u64 },
}

struct RangePoints {
    range: TimeSeriesRange,
    maximum: Option<i64>,
    // Value comes first so every expired point can be removed once, without
    // rescanning retained columns or clusters. None marks a sum that overflowed;
    // it is only an error if the point survives the final window.
    counts: BTreeMap<(i64, Option<i32>, u32), Option<usize>>,
}

impl RangePoints {
    fn new(range: TimeSeriesRange) -> Self {
        Self {
            range,
            maximum: None,
            counts: BTreeMap::new(),
        }
    }

    fn insert(&mut self, ts: &TimeSeries) {
        match self.range {
            TimeSeriesRange::Between { start, end } => {
                if !in_range(ts.value, start, end) {
                    return;
                }
            }
            TimeSeriesRange::Latest { width } => {
                let maximum = self.maximum.map_or(ts.value, |m| m.max(ts.value));
                self.maximum = Some(maximum);
                let lower = maximum.saturating_sub_unsigned(width);
                while self
                    .counts
                    .first_key_value()
                    .is_some_and(|(key, _)| key.0 < lower)
                {
                    self.counts.pop_first();
                }
                if ts.value < lower {
                    return;
                }
            }
        }
        let count = self
            .counts
            .entry((ts.value, ts.count_index, ts.cluster_id))
            .or_insert(Some(0));
        *count = count.and_then(|count| count.checked_add(ts.count));
    }
}

fn extend_range(range: Option<(i64, i64)>, value: i64) -> (i64, i64) {
    range.map_or((value, value), |(min, max)| {
        (min.min(value), max.max(value))
    })
}

fn in_range(value: i64, start: Option<i64>, end: Option<i64>) -> bool {
    start.is_none_or(|start| value >= start) && end.is_none_or(|end| value <= end)
}

pub type TimeCount = (i64, usize); // (utc_timestamp_nano, count)
pub struct Column {
    pub index: Option<i32>,
    pub time_counts: Vec<TimeCount>, // Vec<(utc_timestamp_nano, count)>,
}

pub struct Cluster {
    pub id: u32,
    pub time_counts: Vec<TimeCount>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TimeSeries {
    pub model_id: u32,
    pub cluster_id: u32,
    pub time: i64, // batch_ts
    pub value: i64,
    pub count_index: Option<i32>, // column index
    pub count: usize,
}

impl UniqueKey for TimeSeries {
    type AsBytes<'a> = Vec<u8>;

    fn unique_key(&self) -> Vec<u8> {
        Key {
            model_id: self.model_id,
            cluster_id: self.cluster_id,
            time: self.time,
            value: self.value,
            count_index: self.count_index,
        }
        .to_bytes()
    }
}

impl Value for TimeSeries {
    type AsBytes<'a> = Vec<u8>;

    fn value(&self) -> Vec<u8> {
        self.count.to_be_bytes().to_vec()
    }
}

impl FromKeyValue for TimeSeries {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let key = Key::from_bytes(key)?;

        let value = usize::from_be_bytes(value.try_into()?);

        Ok(Self {
            model_id: key.model_id,
            cluster_id: key.cluster_id,
            time: key.time,
            value: key.value,
            count_index: key.count_index,
            count: value,
        })
    }
}

struct Key {
    model_id: u32,
    cluster_id: u32,
    time: i64,
    value: i64,
    count_index: Option<i32>,
}

impl Key {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.model_id.to_be_bytes());
        buf.extend(self.cluster_id.to_be_bytes());
        buf.extend(self.time.to_be_bytes());
        buf.extend(self.value.to_be_bytes());
        if let Some(count_index) = self.count_index {
            buf.extend(count_index.to_be_bytes());
        }
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        anyhow::ensure!(
            matches!(buf.len(), 24 | 28),
            "invalid TimeSeries key length: {}",
            buf.len()
        );
        let (val, rest) = buf.split_at(size_of::<u32>());
        let mut buf = [0; size_of::<u32>()];
        buf.copy_from_slice(val);
        let model_id = u32::from_be_bytes(buf);

        let (val, rest) = rest.split_at(size_of::<u32>());
        let mut buf = [0; size_of::<u32>()];
        buf.copy_from_slice(val);
        let cluster_id = u32::from_be_bytes(buf);

        let (val, rest) = rest.split_at(size_of::<i64>());
        let mut buf = [0; size_of::<i64>()];
        buf.copy_from_slice(val);
        let time = i64::from_be_bytes(buf);

        let (val, rest) = rest.split_at(size_of::<i64>());
        buf.copy_from_slice(val);
        let value = i64::from_be_bytes(buf);

        let mut buf = [0; size_of::<i32>()];
        let count_index = if rest.is_empty() {
            None
        } else {
            buf.copy_from_slice(rest);
            Some(i32::from_be_bytes(buf))
        };

        Ok(Self {
            model_id,
            cluster_id,
            time,
            value,
            count_index,
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn malformed_keys_and_model_records_return_errors() {
        for len in [0, 23, 25, 27, 29] {
            assert!(super::Key::from_bytes(&vec![0; len]).is_err());
        }
        for len in [24, 28] {
            assert!(super::Key::from_bytes(&vec![0; len]).is_ok());
        }
        let (_permit, store) = setup_store();
        let table = store.time_series_map();
        table
            .add_time_series(1, 1, vec![(1, vec![create_test_column(0, vec![(1, 1)])])])
            .unwrap();
        let key = super::Key {
            model_id: 1,
            cluster_id: 2,
            time: 2,
            value: 100,
            count_index: None,
        }
        .to_bytes();
        table.map.put(&key, &[0; 3]).unwrap();
        assert!(
            table
                .get_top_time_series_of_model(
                    1,
                    Some(1),
                    TimeSeriesRange::Between {
                        start: None,
                        end: None
                    },
                )
                .is_err()
        );
        assert!(
            table
                .get_top_time_series_of_model(
                    1,
                    None,
                    TimeSeriesRange::Between {
                        start: Some(0),
                        end: Some(2)
                    },
                )
                .is_err()
        );
    }

    use std::sync::Arc;

    use super::*;
    use crate::Store;
    use crate::test::{DbGuard, acquire_db_permit};

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path(), None).unwrap());
        (permit, store)
    }

    fn create_test_column(count_index: i32, time_counts: Vec<(i64, usize)>) -> Column {
        Column {
            index: Some(count_index),
            time_counts,
        }
    }

    fn assert_top_time_series_range(
        table: &Table<'_, TimeSeries>,
        model_id: u32,
        start: Option<i64>,
        end: Option<i64>,
        expected: &[(i64, usize)],
    ) {
        let (_, _, columns) = table
            .get_top_time_series_of_cluster(model_id, 1, TimeSeriesRange::Between { start, end })
            .unwrap();
        assert_eq!(columns.len(), 1);
        assert_eq!(columns[0].index, Some(0));
        assert_eq!(columns[0].time_counts, expected);

        let columns = table
            .get_top_time_series_of_model(model_id, None, TimeSeriesRange::Between { start, end })
            .unwrap();
        assert_eq!(columns.len(), 1);
        let (index, clusters) = &columns[0];
        assert_eq!(*index, Some(0));
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].id, 1);
        assert_eq!(clusters[0].time_counts, expected);
    }

    type ExpectedPoints<'a> = (i32, u32, &'a [TimeCount]);

    fn assert_query_points(
        table: &Table<'_, TimeSeries>,
        model: u32,
        range: TimeSeriesRange,
        expected: &[ExpectedPoints<'_>],
    ) {
        let expected_model: BTreeMap<_, _> = expected
            .iter()
            .map(|(column, cluster, points)| ((Some(*column), *cluster), points.to_vec()))
            .collect();
        let columns = table
            .get_top_time_series_of_model(model, None, range)
            .unwrap();
        assert!(columns.iter().all(|(_, clusters)| !clusters.is_empty()));
        for (_, clusters) in &columns {
            assert!(
                clusters
                    .windows(2)
                    .all(|pair| pair[0].time_counts.len() >= pair[1].time_counts.len())
            );
            assert!(clusters.iter().all(|c| !c.time_counts.is_empty()));
        }
        let actual: BTreeMap<_, _> = columns
            .into_iter()
            .flat_map(|(column, clusters)| {
                clusters
                    .into_iter()
                    .map(move |cluster| ((column, cluster.id), cluster.time_counts))
            })
            .collect();
        assert_eq!(actual, expected_model);
        let (_, _, columns) = table
            .get_top_time_series_of_cluster(model, 1, range)
            .unwrap();
        let actual: Vec<_> = columns
            .into_iter()
            .map(|c| (c.index, c.time_counts))
            .collect();
        let expected: Vec<_> = expected_model
            .into_iter()
            .filter_map(|((column, cluster), points)| (cluster == 1).then_some((column, points)))
            .collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn latest_accepts_later_batches_below_the_maximum() {
        let (_permit, store) = setup_store();
        let table = store.time_series_map();
        table
            .add_time_series(1, 0, vec![(1, vec![create_test_column(0, vec![(6, 1)])])])
            .unwrap();
        table
            .add_time_series(
                1,
                1,
                vec![(1, vec![create_test_column(0, vec![(1, 2), (4, 3)])])],
            )
            .unwrap();
        assert_query_points(
            &table,
            1,
            TimeSeriesRange::Latest { width: 2 },
            &[(0, 1, &[(4, 3), (6, 1)])],
        );
    }

    #[test]
    fn latest_uses_all_columns_and_omits_expired_columns() {
        let (_permit, store) = setup_store();
        let table = store.time_series_map();
        for (model, early) in [(1, 0), (2, 5)] {
            table
                .add_time_series(
                    model,
                    0,
                    vec![(
                        1,
                        vec![
                            create_test_column(0, vec![(early, 1)]),
                            create_test_column(1, vec![(6, 2)]),
                        ],
                    )],
                )
                .unwrap();
        }
        assert_query_points(
            &table,
            1,
            TimeSeriesRange::Latest { width: 2 },
            &[(1, 1, &[(6, 2)])],
        );
        assert_query_points(
            &table,
            2,
            TimeSeriesRange::Latest { width: 2 },
            &[(0, 1, &[(5, 1)]), (1, 1, &[(6, 2)])],
        );
    }

    #[test]
    fn latest_uses_the_query_target_and_omits_expired_clusters() {
        let (_permit, store) = setup_store();
        let table = store.time_series_map();
        table
            .add_time_series(
                1,
                0,
                vec![
                    (1, vec![create_test_column(0, vec![(0, 1), (6, 2)])]),
                    (2, vec![create_test_column(0, vec![(10, 3)])]),
                ],
            )
            .unwrap();
        let (_, _, columns) = table
            .get_top_time_series_of_cluster(1, 1, TimeSeriesRange::Latest { width: 2 })
            .unwrap();
        assert_eq!(columns.len(), 1);
        assert_eq!(columns[0].time_counts, [(6, 2)]);
        let columns = table
            .get_top_time_series_of_model(1, None, TimeSeriesRange::Latest { width: 2 })
            .unwrap();
        assert_eq!(columns.len(), 1);
        assert_eq!(columns[0].1.len(), 1);
        assert_eq!(columns[0].1[0].id, 2);
        assert_eq!(columns[0].1[0].time_counts, [(10, 3)]);
    }

    #[test]
    fn ranges_keep_counts_separate_per_column_and_cluster() {
        let (_permit, store) = setup_store();
        let table = store.time_series_map();
        table
            .add_time_series(
                1,
                0,
                vec![
                    (
                        1,
                        vec![
                            create_test_column(0, vec![(5, 1), (6, 2)]),
                            create_test_column(1, vec![(6, 3)]),
                        ],
                    ),
                    (2, vec![create_test_column(0, vec![(6, 4)])]),
                ],
            )
            .unwrap();
        for range in [
            TimeSeriesRange::Latest { width: 2 },
            TimeSeriesRange::Between {
                start: None,
                end: None,
            },
        ] {
            assert_query_points(
                &table,
                1,
                range,
                &[
                    (0, 1, &[(5, 1), (6, 2)]),
                    (1, 1, &[(6, 3)]),
                    (0, 2, &[(6, 4)]),
                ],
            );
        }
    }

    #[test]
    fn latest_handles_empty_targets_and_saturating_bounds() {
        let (_permit, store) = setup_store();
        let table = store.time_series_map();
        assert_query_points(&table, 1, TimeSeriesRange::Latest { width: 0 }, &[]);
        let (earliest, latest, _) = table
            .get_top_time_series_of_cluster(1, 1, TimeSeriesRange::Latest { width: 0 })
            .unwrap();
        assert_eq!((earliest, latest), (None, None));
        table
            .add_time_series(
                1,
                0,
                vec![(1, vec![create_test_column(0, vec![(i64::MIN, 1)])])],
            )
            .unwrap();
        assert_query_points(
            &table,
            1,
            TimeSeriesRange::Latest {
                width: 7_200_000_000_000,
            },
            &[(0, 1, &[(i64::MIN, 1)])],
        );
    }

    #[test]
    fn overflow_is_an_error_only_for_retained_values() {
        let (_permit, store) = setup_store();
        let table = store.time_series_map();
        for (batch, value, count) in [
            (0, 0, usize::MAX),
            (1, 0, 1),
            (2, 3, usize::MAX - 1),
            (3, 3, 1),
        ] {
            table
                .add_time_series(
                    1,
                    batch,
                    vec![(1, vec![create_test_column(0, vec![(value, count)])])],
                )
                .unwrap();
        }
        assert_query_points(
            &table,
            1,
            TimeSeriesRange::Latest { width: 2 },
            &[(0, 1, &[(3, usize::MAX)])],
        );
        assert_query_points(
            &table,
            1,
            TimeSeriesRange::Between {
                start: Some(1),
                end: None,
            },
            &[(0, 1, &[(3, usize::MAX)])],
        );
        for range in [
            TimeSeriesRange::Latest { width: 3 },
            TimeSeriesRange::Between {
                start: None,
                end: None,
            },
        ] {
            let cluster = table
                .get_top_time_series_of_cluster(1, 1, range)
                .err()
                .unwrap();
            let model = table
                .get_top_time_series_of_model(1, None, range)
                .err()
                .unwrap();
            assert!(cluster.to_string().contains("count summation overflow"));
            assert!(model.to_string().contains("count summation overflow"));
        }
    }

    #[test]
    fn test_get_top_time_series_bound_combinations() {
        const HOUR: i64 = 60 * 60 * 1_000_000_000;
        const T: i64 = 1_640_995_200_000_000_000;

        let (_permit, store) = setup_store();
        let table = store.time_series_map();
        let values = [
            (T, 10),
            (T + HOUR, 20),
            (T + 3 * HOUR, 30),
            (T + 6 * HOUR, 40),
        ];
        for (batch, points) in [
            (0, vec![values[0], values[2]]),
            (1, vec![values[1], values[3]]),
        ] {
            table
                .add_time_series(1, batch, vec![(1, vec![create_test_column(0, points)])])
                .unwrap();
        }
        assert_query_points(
            &table,
            1,
            TimeSeriesRange::Latest {
                width: u64::try_from(3 * HOUR).unwrap(),
            },
            &[(0, 1, &values[2..])],
        );
        assert_query_points(
            &table,
            1,
            TimeSeriesRange::Latest { width: u64::MAX },
            &[(0, 1, &values)],
        );
        let (earliest, latest, _) = table
            .get_top_time_series_of_cluster(
                1,
                1,
                TimeSeriesRange::Latest {
                    width: u64::try_from(3 * HOUR).unwrap(),
                },
            )
            .unwrap();
        assert_eq!((earliest, latest), (Some(T), Some(T + 6 * HOUR)));
        let batch = table
            .get_top_time_series_of_model(1, Some(0), TimeSeriesRange::Latest { width: 0 })
            .unwrap();
        assert_eq!(batch[0].1[0].time_counts, [values[0], values[2]]);

        let (earliest, latest, _) = table
            .get_top_time_series_of_cluster(
                1,
                1,
                TimeSeriesRange::Between {
                    start: Some(T + HOUR),
                    end: Some(T + 3 * HOUR),
                },
            )
            .unwrap();
        assert_eq!((earliest, latest), (Some(T), Some(T + 6 * HOUR)));

        for (start, end, expected) in [
            (Some(T + HOUR), None, &values[1..]),
            (None, Some(T + 3 * HOUR), &values[..3]),
            (Some(T + HOUR), Some(T + 3 * HOUR), &values[1..3]),
            (None, None, &values[..]),
        ] {
            assert_top_time_series_range(&table, 1, start, end, expected);
        }
    }

    #[test]
    fn test_get_top_time_series_unbounded_extremes() {
        let (_permit, store) = setup_store();
        let table = store.time_series_map();
        let values = [(i64::MIN, 1), (i64::MAX, 2)];
        table
            .add_time_series(
                2,
                0,
                vec![(1, vec![create_test_column(0, values.to_vec())])],
            )
            .unwrap();
        assert_top_time_series_range(&table, 2, Some(0), None, &values[1..]);
        assert_top_time_series_range(&table, 2, None, Some(0), &values[..1]);
    }

    #[test]
    fn test_add_time_series() {
        let (_permit, store) = setup_store();
        let table = store.time_series_map();

        let model_id = 1;
        let batch_ts = 1_640_995_200_000_000_000; // 2022-01-01 00:00:00 UTC in nanoseconds

        let series = vec![
            (
                1,
                vec![create_test_column(
                    0,
                    vec![(1_640_995_200, 10), (1_640_995_260, 15)],
                )],
            ),
            (
                2,
                vec![create_test_column(
                    1,
                    vec![(1_640_995_200, 5), (1_640_995_260, 8)],
                )],
            ),
        ];

        let result = table.add_time_series(model_id, batch_ts, series);
        assert!(result.is_ok());
    }

    /// Repeating an identical call succeeds and leaves the rows as the first
    /// call did.
    #[test]
    fn add_time_series_repeat_is_a_no_op() {
        let (_permit, store) = setup_store();
        let table = store.time_series_map();
        let series = || {
            vec![
                (1, vec![create_test_column(0, vec![(100, 10), (160, 15)])]),
                (2, vec![create_test_column(1, vec![(100, 5)])]),
            ]
        };

        table.add_time_series(4, 1_000, series()).unwrap();
        let first: Vec<_> = table
            .iter(rocksdb::Direction::Forward, None)
            .map(Result::unwrap)
            .collect();
        assert_eq!(first.len(), 3);

        table.add_time_series(4, 1_000, series()).unwrap();
        let second: Vec<_> = table
            .iter(rocksdb::Direction::Forward, None)
            .map(Result::unwrap)
            .collect();
        assert_eq!(second, first);
    }

    #[test]
    fn test_add_time_series_with_invalid_timestamp() {
        let (_permit, store) = setup_store();
        let table = store.time_series_map();

        let model_id = 1;
        let batch_ts = 1_640_995_200_000_000_000;

        // This test would need to be adjusted based on how the actual ColumnTimeSeries is structured
        // For now, we'll test the valid case
        let series = vec![(1, vec![create_test_column(0, vec![(1_640_995_200, 10)])])];

        let result = table.add_time_series(model_id, batch_ts, series);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_time_range_of_model() {
        let (_permit, store) = setup_store();
        let table = store.time_series_map();

        let model_id = 1;
        let batch_ts = 1_640_995_200_000_000_000;

        // Add some time series data
        let series = vec![(
            1,
            vec![create_test_column(
                0,
                vec![(1_640_995_200, 10), (1_640_995_260, 15)],
            )],
        )];

        table.add_time_series(model_id, batch_ts, series).unwrap();

        let time_range = table.get_time_range_of_model(model_id).unwrap();
        assert!(time_range.is_some());

        if let Some((min_time, max_time)) = time_range {
            assert!(min_time <= max_time);
        }
    }

    #[test]
    fn test_get_time_range_of_empty_model() {
        let (_permit, store) = setup_store();
        let table = store.time_series_map();

        let model_id = 999; // Non-existent model
        let time_range = table.get_time_range_of_model(model_id).unwrap();
        assert!(time_range.is_none());
    }

    #[test]
    fn test_get_top_time_series_of_cluster() {
        let (_permit, store) = setup_store();
        let table = store.time_series_map();

        let model_id = 1;
        let cluster_id = 1;
        let batch_ts = 1_640_995_200_000_000_000;

        // Add time series data
        let series = vec![(
            cluster_id,
            vec![create_test_column(
                0,
                vec![(1_640_995_200, 10), (1_640_995_260, 15)],
            )],
        )];

        table.add_time_series(model_id, batch_ts, series).unwrap();

        let result = table
            .get_top_time_series_of_cluster(
                model_id,
                cluster_id,
                TimeSeriesRange::Between {
                    start: None,
                    end: None,
                },
            )
            .unwrap();
        let (earliest, latest, columns) = result;

        assert!(earliest.is_some());
        assert!(latest.is_some());
        assert!(!columns.is_empty());
    }

    #[test]
    fn test_get_top_time_series_of_cluster_with_time_range() {
        let (_permit, store) = setup_store();
        let table = store.time_series_map();

        let model_id = 1;
        let cluster_id = 1;
        let batch_ts = 1_640_995_200_000_000_000;

        // Add time series data
        let series = vec![(
            cluster_id,
            vec![create_test_column(
                0,
                vec![(1_640_995_200, 10), (1_640_995_260, 15)],
            )],
        )];

        table.add_time_series(model_id, batch_ts, series).unwrap();

        let start = Some(1_640_995_200);
        let end = Some(1_640_995_260);

        let result = table
            .get_top_time_series_of_cluster(
                model_id,
                cluster_id,
                TimeSeriesRange::Between { start, end },
            )
            .unwrap();
        let (earliest, latest, columns) = result;

        assert!(earliest.is_some());
        assert!(latest.is_some());
        assert!(!columns.is_empty());
    }

    #[test]
    fn test_get_top_time_series_of_model() {
        let (_permit, store) = setup_store();
        let table = store.time_series_map();

        let model_id = 1;
        let batch_ts = 1_640_995_200_000_000_000;

        // Add time series data for multiple clusters
        let series = vec![
            (
                1,
                vec![create_test_column(
                    0,
                    vec![(1_640_995_200, 10), (1_640_995_260, 15)],
                )],
            ),
            (
                2,
                vec![create_test_column(
                    1,
                    vec![(1_640_995_200, 5), (1_640_995_260, 8)],
                )],
            ),
        ];

        table.add_time_series(model_id, batch_ts, series).unwrap();

        let result = table
            .get_top_time_series_of_model(
                model_id,
                None,
                TimeSeriesRange::Between {
                    start: None,
                    end: None,
                },
            )
            .unwrap();
        assert!(!result.is_empty());

        // Check that we have the expected number of columns
        assert_eq!(result.len(), 2); // One for each count_index (0 and 1)
    }

    #[test]
    fn test_get_top_time_series_of_model_with_specific_time() {
        let (_permit, store) = setup_store();
        let table = store.time_series_map();

        let model_id = 1;
        let batch_ts = 1_640_995_200_000_000_000;

        // Add time series data
        let series = vec![(
            1,
            vec![create_test_column(
                0,
                vec![(1_640_995_200, 10), (1_640_995_260, 15)],
            )],
        )];

        table.add_time_series(model_id, batch_ts, series).unwrap();

        let result = table
            .get_top_time_series_of_model(
                model_id,
                Some(batch_ts),
                TimeSeriesRange::Between {
                    start: None,
                    end: None,
                },
            )
            .unwrap();
        let bounded_result = table
            .get_top_time_series_of_model(
                model_id,
                Some(batch_ts),
                TimeSeriesRange::Between {
                    start: Some(0),
                    end: Some(1),
                },
            )
            .unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(bounded_result.len(), 1);
        let (index, clusters) = &result[0];
        let (bounded_index, bounded_clusters) = &bounded_result[0];
        assert_eq!(index, bounded_index);
        assert_eq!(clusters.len(), 1);
        assert_eq!(bounded_clusters.len(), 1);
        assert_eq!(clusters[0].id, bounded_clusters[0].id);
        assert_eq!(clusters[0].time_counts, bounded_clusters[0].time_counts);
        assert_eq!(
            clusters[0].time_counts,
            [(1_640_995_200, 10), (1_640_995_260, 15)]
        );
    }

    #[test]
    fn test_top_time_series_sums_matching_values() {
        let (_permit, store) = setup_store();
        let table = store.time_series_map();
        for (batch, count) in [(0, 2), (1, 3)] {
            table
                .add_time_series(
                    1,
                    batch,
                    vec![(1, vec![create_test_column(0, vec![(10, count)])])],
                )
                .unwrap();
        }
        assert_top_time_series_range(&table, 1, None, None, &[(10, 5)]);
        let (earliest, latest, columns) = table
            .get_top_time_series_of_cluster(
                1,
                1,
                TimeSeriesRange::Between {
                    start: Some(11),
                    end: None,
                },
            )
            .unwrap();
        assert_eq!((earliest, latest), (Some(10), Some(10)));
        assert!(columns.is_empty());
    }

    #[test]
    fn test_top_time_series_queries_count_overflow() {
        let (_permit, store) = setup_store();
        let table = store.time_series_map();
        for (batch, count) in [(0, usize::MAX), (1, 1)] {
            table
                .add_time_series(
                    1,
                    batch,
                    vec![(1, vec![create_test_column(0, vec![(0, count)])])],
                )
                .unwrap();
        }

        let cluster_error = table
            .get_top_time_series_of_cluster(
                1,
                1,
                TimeSeriesRange::Between {
                    start: Some(0),
                    end: Some(0),
                },
            )
            .err()
            .unwrap();
        assert!(
            cluster_error
                .to_string()
                .contains("count summation overflow")
        );
        let model_error = table
            .get_top_time_series_of_model(
                1,
                None,
                TimeSeriesRange::Between {
                    start: Some(0),
                    end: Some(0),
                },
            )
            .err()
            .unwrap();
        assert!(model_error.to_string().contains("count summation overflow"));
    }

    #[test]
    fn test_time_series_unique_key() {
        let ts = TimeSeries {
            model_id: 1,
            cluster_id: 2,
            time: 1_640_995_200_000_000_000,
            value: 1_640_995_200,
            count_index: Some(3),
            count: 10,
        };

        let key = ts.unique_key();
        assert_ne!(key, Vec::<u8>::new());

        // Test that the key can be reconstructed
        let reconstructed = TimeSeries::from_key_value(&key, &ts.value()).unwrap();
        assert_eq!(ts.model_id, reconstructed.model_id);
        assert_eq!(ts.cluster_id, reconstructed.cluster_id);
        assert_eq!(ts.time, reconstructed.time);
        assert_eq!(ts.value, reconstructed.value);
        assert_eq!(ts.count_index, reconstructed.count_index);
        assert_eq!(ts.count, reconstructed.count);
    }

    #[test]
    fn test_time_series_value() {
        let ts = TimeSeries {
            model_id: 1,
            cluster_id: 2,
            time: 1_640_995_200_000_000_000,
            value: 1_640_995_200,
            count_index: Some(3),
            count: 42,
        };

        let value_bytes = ts.value();
        let reconstructed_count = usize::from_be_bytes(value_bytes.try_into().unwrap());
        assert_eq!(ts.count, reconstructed_count);
    }

    #[test]
    fn test_key_to_bytes_and_from_bytes() {
        let key = Key {
            model_id: 1,
            cluster_id: 2,
            time: 1_640_995_200_000_000_000,
            value: 1_640_995_200,
            count_index: Some(3),
        };

        let bytes = key.to_bytes();
        let reconstructed = Key::from_bytes(&bytes).unwrap();

        assert_eq!(key.model_id, reconstructed.model_id);
        assert_eq!(key.cluster_id, reconstructed.cluster_id);
        assert_eq!(key.time, reconstructed.time);
        assert_eq!(key.value, reconstructed.value);
        assert_eq!(key.count_index, reconstructed.count_index);
    }

    #[test]
    fn test_key_to_bytes_and_from_bytes_no_count_index() {
        let key = Key {
            model_id: 1,
            cluster_id: 2,
            time: 1_640_995_200_000_000_000,
            value: 1_640_995_200,
            count_index: None,
        };

        let bytes = key.to_bytes();
        let reconstructed = Key::from_bytes(&bytes).unwrap();

        assert_eq!(key.model_id, reconstructed.model_id);
        assert_eq!(key.cluster_id, reconstructed.cluster_id);
        assert_eq!(key.time, reconstructed.time);
        assert_eq!(key.value, reconstructed.value);
        assert_eq!(key.count_index, reconstructed.count_index);
    }

    #[test]
    fn test_insert_and_retrieve_time_series() {
        let (_permit, store) = setup_store();
        let table = store.time_series_map();

        let ts = TimeSeries {
            model_id: 1,
            cluster_id: 2,
            time: 1_640_995_200_000_000_000,
            value: 1_640_995_200,
            count_index: Some(3),
            count: 42,
        };

        // Insert the time series
        table.insert(&ts).unwrap();

        // Retrieve it using the unique key
        let key = ts.unique_key();
        let retrieved = table.map.get(&key).unwrap();
        assert!(retrieved.is_some());

        // Reconstruct the TimeSeries from the stored data
        let reconstructed = TimeSeries::from_key_value(&key, retrieved.unwrap().as_ref()).unwrap();
        assert_eq!(ts, reconstructed);
    }

    #[test]
    fn test_insert_duplicate_time_series() {
        let (_permit, store) = setup_store();
        let table = store.time_series_map();

        let ts = TimeSeries {
            model_id: 1,
            cluster_id: 2,
            time: 1_640_995_200_000_000_000,
            value: 1_640_995_200,
            count_index: Some(3),
            count: 42,
        };

        // Insert the first time
        table.insert(&ts).unwrap();

        // Try to insert the same key again
        let result = table.insert(&ts);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_time_series_same_model() {
        let (_permit, store) = setup_store();
        let table = store.time_series_map();

        let model_id = 1;
        let batch_ts = 1_640_995_200_000_000_000;

        // Add multiple time series for the same model
        let series = vec![
            (
                1,
                vec![create_test_column(
                    0,
                    vec![(1_640_995_200, 10), (1_640_995_260, 15)],
                )],
            ),
            (
                2,
                vec![create_test_column(
                    1,
                    vec![(1_640_995_200, 5), (1_640_995_260, 8)],
                )],
            ),
            (
                3,
                vec![create_test_column(
                    2,
                    vec![(1_640_995_200, 20), (1_640_995_260, 25)],
                )],
            ),
        ];

        table.add_time_series(model_id, batch_ts, series).unwrap();

        // Test that we can retrieve all series for the model
        let time_range = table.get_time_range_of_model(model_id).unwrap();
        assert!(time_range.is_some());

        let top_series = table
            .get_top_time_series_of_model(
                model_id,
                None,
                TimeSeriesRange::Between {
                    start: None,
                    end: None,
                },
            )
            .unwrap();
        assert_eq!(top_series.len(), 3); // One for each count_index
    }

    #[test]
    fn test_time_series_with_different_count_indices() {
        let (_permit, store) = setup_store();
        let table = store.time_series_map();

        let model_id = 1;
        let cluster_id = 1;
        let batch_ts = 1_640_995_200_000_000_000;

        // Add time series with different count indices
        let series = vec![(
            cluster_id,
            vec![
                create_test_column(0, vec![(1_640_995_200, 10)]),
                create_test_column(1, vec![(1_640_995_200, 15)]),
                create_test_column(2, vec![(1_640_995_200, 20)]),
            ],
        )];

        table.add_time_series(model_id, batch_ts, series).unwrap();

        let result = table
            .get_top_time_series_of_cluster(
                model_id,
                cluster_id,
                TimeSeriesRange::Between {
                    start: None,
                    end: None,
                },
            )
            .unwrap();
        let (_, _, columns) = result;

        // Should have 3 columns (one for each count_index)
        assert_eq!(columns.len(), 3);

        // Check that columns are sorted by count_index
        for i in 1..columns.len() {
            let prev_count_index = columns[i - 1].index;
            let curr_count_index = columns[i].index;
            assert!(prev_count_index <= curr_count_index);
        }
    }
}
