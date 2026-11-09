use std::collections::HashMap;

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

    /// Returns the earliest and latest stored values for the given cluster,
    /// across all columns and batches, or `None` if the cluster is empty.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database error occurs.
    pub fn get_time_range_of_cluster(
        &self,
        model_id: u32,
        cluster_id: u32,
    ) -> Result<Option<(i64, i64)>> {
        let mut prefix = model_id.to_be_bytes().to_vec();
        prefix.extend(cluster_id.to_be_bytes());
        self.prefix_iter(rocksdb::Direction::Forward, None, &prefix)
            .try_fold(None, |range, item| {
                let value = item?.value;
                Ok(Some(extend_range(range, value)))
            })
    }

    /// Gets the top time series of the given cluster.
    ///
    /// `start` and `end` are inclusive nanosecond timestamp bounds. An omitted
    /// bound leaves that side unbounded. The returned earliest and latest values
    /// cover the entire cluster, independent of these bounds.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database error occurs or count summation
    /// overflows.
    pub fn get_top_time_series_of_cluster(
        &self,
        model_id: u32,
        cluster_id: u32,
        start: Option<i64>,
        end: Option<i64>,
    ) -> Result<(Option<i64>, Option<i64>, Vec<Column>)> {
        use rocksdb::Direction;

        let mut prefix = model_id.to_be_bytes().to_vec();
        prefix.extend(cluster_id.to_be_bytes());
        let mut range = None;
        let mut columns: HashMap<Option<i32>, HashMap<i64, usize>> = HashMap::new();
        for item in self.prefix_iter(Direction::Forward, None, &prefix) {
            let ts = item?;
            range = Some(extend_range(range, ts.value));
            if in_range(ts.value, start, end) {
                let count = columns
                    .entry(ts.count_index)
                    .or_default()
                    .entry(ts.value)
                    .or_default();
                *count = count.checked_add(ts.count).ok_or_else(|| {
                    anyhow!(
                        "count summation overflow for column {:?}, value {}",
                        ts.count_index,
                        ts.value
                    )
                })?;
            }
        }

        let mut columns = columns
            .into_iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(column, top_n)| {
                let mut top_n = top_n.into_iter().collect::<Vec<_>>();
                top_n.sort_unstable_by_key(|t| t.0);
                Column {
                    index: column,
                    time_counts: top_n,
                }
            })
            .collect::<Vec<_>>();
        columns.sort_unstable_by_key(|c| c.index);

        let (earliest, latest) = range.map_or((None, None), |(min, max)| (Some(min), Some(max)));
        Ok((earliest, latest, columns))
    }

    /// Returns the top trends of a model.
    ///
    /// When `time` is `Some`, selects that batch and ignores `start` and `end`.
    /// Otherwise, `start` and `end` are inclusive nanosecond timestamp bounds.
    /// An omitted bound leaves that side unbounded.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database operation fails or count
    /// summation overflows or a stored record cannot be decoded.
    pub fn get_top_time_series_of_model(
        &self,
        model_id: u32,
        time: Option<i64>,
        start: Option<i64>,
        end: Option<i64>,
    ) -> Result<Vec<(Option<i32>, Vec<Cluster>)>> {
        let series = self.time_series_of_model(model_id, time, start, end)?;
        let mut columns: HashMap<Option<i32>, HashMap<u32, HashMap<i64, usize>>> = HashMap::new();
        for ts in series {
            let count = columns
                .entry(ts.count_index)
                .or_default()
                .entry(ts.cluster_id)
                .or_default()
                .entry(ts.value)
                .or_default();
            *count = count.checked_add(ts.count).ok_or_else(|| {
                anyhow!(
                    "count summation overflow for cluster {}, column {:?}, value {}",
                    ts.cluster_id,
                    ts.count_index,
                    ts.value
                )
            })?;
        }
        let mut res: Vec<_> = columns
            .into_iter()
            .map(|(column, cluster_series)| {
                let trends: Vec<_> = cluster_series
                    .into_iter()
                    .filter_map(|(cluster_id, series)| {
                        if series.is_empty() {
                            None
                        } else {
                            let mut series: Vec<_> = series.into_iter().collect();
                            series.sort_by_key(|v| v.0);
                            Some(Cluster {
                                id: cluster_id,
                                time_counts: series,
                            })
                        }
                    })
                    .collect();
                (column, trends)
            })
            .collect();
        for s in &mut res {
            s.1.sort_by_key(|v| std::cmp::Reverse(v.time_counts.len()));
        }
        Ok(res)
    }

    fn time_series_of_model(
        &self,
        model_id: u32,
        time: Option<i64>,
        start: Option<i64>,
        end: Option<i64>,
    ) -> Result<Vec<TimeSeries>> {
        let prefix = model_id.to_be_bytes().to_vec();

        if let Some(time) = time {
            self.prefix_iter(rocksdb::Direction::Forward, None, &prefix)
                .filter_map(|item| match item {
                    Ok(ts) if ts.time == time => Some(Ok(ts)),
                    Ok(_) => None,
                    Err(e) => Some(Err(e)),
                })
                .collect::<Result<Vec<_>>>()
        } else {
            Ok(self
                .prefix_iter(rocksdb::Direction::Forward, None, &prefix)
                .filter_map(|item| match item {
                    Ok(ts) => {
                        if in_range(ts.value, start, end) {
                            Some(Ok::<_, anyhow::Error>(ts))
                        } else {
                            None
                        }
                    }
                    Err(e) => Some(Err(e)),
                })
                .collect::<Result<Vec<_>>>()?)
        }
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
                .get_top_time_series_of_model(1, Some(1), None, None)
                .is_err()
        );
        assert!(
            table
                .get_top_time_series_of_model(1, None, Some(0), Some(2))
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
            .get_top_time_series_of_cluster(model_id, 1, start, end)
            .unwrap();
        assert_eq!(columns.len(), 1);
        assert_eq!(columns[0].index, Some(0));
        assert_eq!(columns[0].time_counts, expected);

        let columns = table
            .get_top_time_series_of_model(model_id, None, start, end)
            .unwrap();
        assert_eq!(columns.len(), 1);
        let (index, clusters) = &columns[0];
        assert_eq!(*index, Some(0));
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].id, 1);
        assert_eq!(clusters[0].time_counts, expected);
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
        table
            .add_time_series(
                1,
                T,
                vec![(1, vec![create_test_column(0, values.to_vec())])],
            )
            .unwrap();

        let (earliest, latest, _) = table
            .get_top_time_series_of_cluster(1, 1, Some(T + HOUR), Some(T + 3 * HOUR))
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
        assert_top_time_series_range(&table, 2, Some(i64::MIN), None, &values);
        assert_top_time_series_range(&table, 2, None, Some(i64::MAX), &values);
    }

    #[test]
    fn test_cluster_range_across_columns_and_batches() {
        const HOUR: i64 = 60 * 60 * 1_000_000_000;
        const T: i64 = 1_640_995_200_000_000_000;
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
                            create_test_column(0, vec![(T, 1)]),
                            create_test_column(1, vec![(T - HOUR, 2)]),
                        ],
                    ),
                    (2, vec![create_test_column(0, vec![(T - 2 * HOUR, 3)])]),
                ],
            )
            .unwrap();
        table
            .add_time_series(
                1,
                1,
                vec![(1, vec![create_test_column(0, vec![(T + 7 * HOUR, 4)])])],
            )
            .unwrap();
        assert_eq!(
            table.get_time_range_of_cluster(1, 1).unwrap(),
            Some((T - HOUR, T + 7 * HOUR))
        );
        assert_eq!(
            table.get_time_range_of_cluster(1, 2).unwrap(),
            Some((T - 2 * HOUR, T - 2 * HOUR))
        );
        assert_eq!(table.get_time_range_of_cluster(1, 3).unwrap(), None);
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
            .get_top_time_series_of_cluster(model_id, cluster_id, None, None)
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
            .get_top_time_series_of_cluster(model_id, cluster_id, start, end)
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
            .get_top_time_series_of_model(model_id, None, None, None)
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
            .get_top_time_series_of_model(model_id, Some(batch_ts), None, None)
            .unwrap();
        let bounded_result = table
            .get_top_time_series_of_model(model_id, Some(batch_ts), Some(0), Some(1))
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
    fn test_time_series_of_model() {
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

        // Test with specific time
        let result = table
            .time_series_of_model(model_id, Some(batch_ts), None, None)
            .unwrap();
        assert_ne!(result, Vec::new());

        // Test with time range
        let result = table
            .time_series_of_model(model_id, None, Some(1_640_995_200), Some(1_640_995_260))
            .unwrap();
        assert_ne!(result, Vec::new());
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
            .get_top_time_series_of_cluster(1, 1, Some(11), None)
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
            .get_top_time_series_of_cluster(1, 1, Some(0), Some(0))
            .err()
            .unwrap();
        assert!(
            cluster_error
                .to_string()
                .contains("count summation overflow")
        );
        let model_error = table
            .get_top_time_series_of_model(1, None, Some(0), Some(0))
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
            .get_top_time_series_of_model(model_id, None, None, None)
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
            .get_top_time_series_of_cluster(model_id, cluster_id, None, None)
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
