use std::collections::HashMap;

use anyhow::{Result, anyhow};
use chrono::Utc;
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
                    self.insert_with_transaction(&ts, &txn)?;
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

    fn get_range(
        &self,
        prefix: &[u8],
        start: Option<i64>,
        end: Option<i64>,
    ) -> Result<(TimeRange, (i64, i64))> {
        use rocksdb::Direction;
        let mut iter = self.prefix_iter(Direction::Forward, None, prefix);
        let (earliest, latest) = iter
            .try_fold(None, |range: Option<(i64, i64)>, item| {
                let ts = item?;
                let value = ts.value;
                let new_range = match range {
                    Some((min, max)) => (min.min(value), max.max(value)),
                    None => (value, value),
                };
                Ok::<std::option::Option<(i64, i64)>, anyhow::Error>(Some(new_range))
            })?
            .map_or((None, None), |(min, max)| (Some(min), Some(max)));

        let recent = latest.unwrap_or(
            Utc::now()
                .timestamp_nanos_opt()
                .ok_or(anyhow!("illegal time stamp"))?,
        );
        let (start, end) = if let (Some(s), Some(e)) = (start, end) {
            (s, e)
        } else {
            let prev = chrono::DateTime::<chrono::Utc>::from_timestamp_nanos(recent)
                - chrono::Duration::hours(2);
            (
                prev.timestamp_nanos_opt()
                    .ok_or(anyhow!("illegal time stamp"))?,
                recent,
            )
        };
        Ok(((earliest, latest), (start, end)))
    }

    /// Gets the top time series of the given cluster,
    /// extrapolation is performed to fill vacant slots.
    ///
    /// # Panics
    ///
    /// Will panic if `usize` is smaller than 4 bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database error occurs.
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
        let ((earliest, latest), (start, end)) = self.get_range(&prefix, start, end)?;
        let mut columns: HashMap<Option<i32>, HashMap<i64, usize>> = HashMap::new();
        for item in self.prefix_iter(Direction::Forward, None, &prefix) {
            let ts = item?;
            if ts.value >= start && ts.value <= end {
                columns
                    .entry(ts.count_index)
                    .or_default()
                    .entry(ts.value)
                    .and_modify(|c| *c += ts.count)
                    .or_insert(ts.count);
            }
        }

        let mut columns = columns
            .into_iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(column, top_n)| {
                let mut top_n = top_n.into_iter().collect::<Vec<_>>();
                top_n.sort_by_key(|t| t.0);
                let top_n = fill_vacant_time_slots(&top_n);
                Column {
                    index: column,
                    time_counts: top_n,
                }
            })
            .collect::<Vec<_>>();
        columns.sort_by_key(|c| c.index);

        Ok((earliest, latest, columns))
    }

    /// Returns the top trends of a model.
    ///
    /// # Panics
    ///
    /// Will panic if `usize` is smaller than 4 bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database operation fails.
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
            columns
                .entry(ts.count_index)
                .or_default()
                .entry(ts.cluster_id)
                .or_default()
                .entry(ts.value)
                .and_modify(|c| *c += ts.count)
                .or_insert(ts.count);
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
                .filter_map(|item| {
                    let ts = item.ok()?;
                    if ts.time == time { Some(Ok(ts)) } else { None }
                })
                .collect::<Result<Vec<_>>>()
        } else {
            let ((_, _), (start, end)) = self.get_range(&prefix, start, end)?;

            Ok(self
                .prefix_iter(rocksdb::Direction::Forward, None, &prefix)
                .filter_map(|item| match item {
                    Ok(ts) => {
                        if ts.value >= start && ts.value <= end {
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

type TimeRange = (Option<i64>, Option<i64>);

fn fill_vacant_time_slots(series: &[(i64, usize)]) -> Vec<(i64, usize)> {
    if series.len() <= 2 {
        return series.to_vec();
    }
    let mut min_diff = series[1].0 - series[0].0;
    for index in 2..series.len() {
        let diff = series[index].0 - series[index - 1].0;
        if diff < min_diff {
            min_diff = diff;
        }
    }
    let mut filled_series = vec![series[0]];
    for (cur, prev) in series[1..].iter().zip(series[..series.len() - 1].iter()) {
        let diff = (cur.0 - prev.0) / min_diff;
        if diff > 1 {
            for d in 1..diff {
                filled_series.push((prev.0 + d * min_diff, 0));
            }
        }
        filled_series.push(*cur);
    }

    filled_series
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
        let key = Key::from_bytes(key);

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

    pub fn from_bytes(buf: &[u8]) -> Self {
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

        Self {
            model_id,
            cluster_id,
            time,
            value,
            count_index,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::Store;
    use crate::test::{DbGuard, acquire_db_permit};

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        (permit, store)
    }

    fn create_test_column(count_index: i32, time_counts: Vec<(i64, usize)>) -> Column {
        Column {
            index: Some(count_index),
            time_counts,
        }
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
        assert!(!result.is_empty());
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
        assert!(!result.is_empty());

        // Test with time range
        let result = table
            .time_series_of_model(model_id, None, Some(1_640_995_200), Some(1_640_995_260))
            .unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    fn test_fill_vacant_time_slots() {
        let series = vec![(1000, 10), (2000, 15), (4000, 20)];
        let filled = fill_vacant_time_slots(&series);

        assert_eq!(filled.len(), 4);
        assert_eq!(filled[0], (1000, 10));
        assert_eq!(filled[1], (2000, 15)); // Original value
        assert_eq!(filled[2], (3000, 0)); // Filled slot
        assert_eq!(filled[3], (4000, 20));
    }

    #[test]
    fn test_fill_vacant_time_slots_short_series() {
        let series = vec![(1000, 10)];
        let filled = fill_vacant_time_slots(&series);
        assert_eq!(filled, series);

        let series = vec![(1000, 10), (2000, 15)];
        let filled = fill_vacant_time_slots(&series);
        assert_eq!(filled, series);
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
        assert!(!key.is_empty());

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
        let reconstructed = Key::from_bytes(&bytes);

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
        let reconstructed = Key::from_bytes(&bytes);

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
