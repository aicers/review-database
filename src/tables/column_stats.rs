use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use chrono::NaiveDateTime;
use num_traits::{FromPrimitive, ToPrimitive};
use rocksdb::{Direction, OptimisticTransactionDB};
use serde::{Deserialize, Serialize};
use structured::{Description, Element, NLargestCount};

use crate::tables::TableIter;
use crate::types::FromKeyValue;
use crate::{ElementCount, Map, Statistics, Table, TopElementCountsByColumn};
use crate::{Iterable, UniqueKey, tables::Value as ValueTrait};

const DEFAULT_NUMBER_OF_COLUMN: u32 = 30;
const DEFAULT_PORTION_OF_TOP_N: f64 = 1.0;

#[derive(Deserialize)]
pub struct TopColumnsOfCluster {
    pub cluster_id: i32,
    pub columns: Vec<TopElementCountsByColumn>,
}

#[derive(Deserialize)]
pub struct TopMultimaps {
    pub n_index: usize,
    pub selected: Vec<TopColumnsOfCluster>,
}

/// Result of a column statistics retention operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionResult {
    /// Number of entries deleted.
    pub deleted: u64,
    /// Number of batches processed.
    pub batches: u64,
}

impl<'d> Table<'d, ColumnStats> {
    /// Opens the `column_stats` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::COLUMN_STATS).map(Table::new)
    }

    /// Retrieves a `TableIter` for the `ColumnStats` entries matching the given parameters.
    #[must_use]
    pub fn get(&self, batch_ts: i64, model_id: u32, cluster_id: u32) -> TableIter<'_, ColumnStats> {
        let key = Key {
            model_id,
            cluster_id,
            batch_ts,
            column_index: 0,
        };
        let prefix = key.to_bytes();
        self.prefix_iter(
            Direction::Forward,
            None,
            &prefix[..prefix.len() - size_of::<u32>()],
        )
    }

    /// # Errors
    ///
    /// Returns an error if the `entry` key is invalid or the database operation fails.
    pub fn remove(&self, entry: &ColumnStats) -> Result<()> {
        self.map.delete(&entry.unique_key())
    }

    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn remove_by_model(&self, model_id: u32) -> Result<()> {
        let iter = self.prefix_iter(Direction::Forward, None, &model_id.to_be_bytes());
        let to_deletes: Vec<_> = iter
            .filter_map(|result| {
                let stats = result.ok()?;
                Some(stats.unique_key())
            })
            .collect();
        for to_delete in to_deletes {
            self.map.delete(&to_delete)?;
        }

        Ok(())
    }

    /// Deletes column statistics entries older than the specified cutoff timestamp.
    ///
    /// This method performs batched deletes to avoid holding large transactions
    /// and reduce database pressure. It iterates through all entries and removes
    /// those with `batch_ts` older than the cutoff.
    ///
    /// # Arguments
    ///
    /// * `cutoff_ts` - Entries with `batch_ts` before this timestamp will be deleted.
    ///   The timestamp is in nanoseconds since Unix epoch.
    /// * `batch_size` - Maximum number of entries to delete in a single transaction.
    ///   Recommended values are between 1,000 and 50,000.
    ///
    /// # Returns
    ///
    /// Returns a `RetentionResult` containing the number of entries deleted and
    /// the number of batches processed.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn retain(&self, cutoff_ts: i64, batch_size: usize) -> Result<RetentionResult> {
        let mut total_deleted = 0u64;
        let mut batches_processed = 0u64;

        loop {
            let mut to_delete: Vec<Vec<u8>> = Vec::with_capacity(batch_size);

            // Collect keys to delete in this batch
            for result in self.iter(Direction::Forward, None) {
                let stats = result.context("failed to read column stats entry")?;
                if stats.batch_ts < cutoff_ts {
                    to_delete.push(stats.unique_key());
                    if to_delete.len() >= batch_size {
                        break;
                    }
                }
            }

            if to_delete.is_empty() {
                break;
            }

            // Delete the batch within a transaction
            let txn = self.map.db.transaction();
            for key in &to_delete {
                txn.delete_cf(self.map.cf, key)
                    .context("failed to delete column stats entry")?;
            }
            txn.commit().context("failed to commit retention batch")?;

            total_deleted += to_delete.len() as u64;
            batches_processed += 1;
        }

        Ok(RetentionResult {
            deleted: total_deleted,
            batches: batches_processed,
        })
    }

    /// Counts the number of entries that would be deleted by a retention operation.
    ///
    /// This is a dry-run mode that reports how many entries would be deleted
    /// without performing any actual deletions.
    ///
    /// # Arguments
    ///
    /// * `cutoff_ts` - Entries with `batch_ts` before this timestamp would be deleted.
    ///   The timestamp is in nanoseconds since Unix epoch.
    ///
    /// # Returns
    ///
    /// Returns the number of entries that would be deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn count_expired(&self, cutoff_ts: i64) -> Result<u64> {
        let mut count = 0u64;

        for result in self.iter(Direction::Forward, None) {
            let stats = result.context("failed to read column stats entry")?;
            if stats.batch_ts < cutoff_ts {
                count += 1;
            }
        }

        Ok(count)
    }

    /// Returns the column statistics for the given cluster and time.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn get_column_statistics(
        &self,
        model: u32,
        cluster: u32,
        time: Vec<NaiveDateTime>,
    ) -> Result<Vec<Statistics>> {
        if time.is_empty() {
            let mut prefix = model.to_be_bytes().to_vec();
            prefix.extend(cluster.to_be_bytes());

            return self
                .prefix_iter(Direction::Forward, None, &prefix)
                .map(|result| {
                    let column_stats = result?;
                    Ok(Statistics {
                        batch_ts: from_timestamp(column_stats.batch_ts)?,
                        column_index: i32::try_from(column_stats.column_index)?,
                        column_stats: structured::ColumnStatistics {
                            description: column_stats.description,
                            n_largest_count: column_stats.n_largest_count,
                        },
                    })
                })
                .collect();
        }
        time.into_iter()
            .map(from_naive_utc)
            .flat_map(|t| self.get(t, model, cluster))
            .map(|result: std::result::Result<ColumnStats, anyhow::Error>| {
                let column_stats = result?;
                Ok(Statistics {
                    batch_ts: from_timestamp(column_stats.batch_ts)?,
                    column_index: i32::try_from(column_stats.column_index)?,
                    column_stats: structured::ColumnStatistics {
                        description: column_stats.description,
                        n_largest_count: column_stats.n_largest_count,
                    },
                })
            })
            .collect()
    }

    /// Inserts column statistics into the database.
    ///
    /// # Differences from Postgres version
    /// This function expects `cluster_id` as a `u32`, not a `String`.
    /// Conversion must be handled before calling.
    ///
    /// # Errors
    /// Returns an error if the database operation fails.
    pub fn insert_column_statistics(
        &self,
        stats: Vec<(u32, Vec<structured::ColumnStatistics>)>,
        model_id: u32,
        batch_ts: NaiveDateTime,
    ) -> Result<()> {
        let batch_ts = from_naive_utc(batch_ts);
        for (cluster_id, columns) in stats {
            let mut key = Key {
                cluster_id,
                batch_ts,
                column_index: 0,
                model_id,
            };
            for (column_index, col) in columns.into_iter().enumerate() {
                key.column_index = u32::try_from(column_index)?;

                let value = Value {
                    description: col.description,
                    n_largest_count: col.n_largest_count,
                };
                // Insert the serialized value into the map.
                self.map
                    .insert(&key.to_bytes(), &super::serialize(&value)?)?;
            }
        }

        Ok(())
    }

    /// Gets the top N multimaps of a model.
    /// `cluster_ids`: retrieved by `load_cluster_ids(model_id)`
    ///     limited by `get_limited_cluster_ids(..portion_of_clusters..)`
    /// `column_1`: the `CsvColumnExtra::column_1` value of the model,
    ///     default to `vec![]`.
    /// `column_n`: the `CsvColumnExtra::column_n` value of the model,
    ///     default to `vec![]`.
    ///
    /// # Panics
    ///
    /// Will panic if `column_1` or `column_n` is not a valid slice of booleans,
    /// or if `number_of_top_n` is larger than `usize::MAX`.
    /// Will panic if `cluster_ids` contains invalid `i32` values.
    /// Will panic if `column_1` or `column_n` contains indices that are out of bounds for `u32`.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn get_top_multimaps_of_model(
        &self,
        model_id: u32,
        cluster_ids: Vec<u32>,
        (column_1, column_n): (&[bool], &[bool]),
        number_of_top_n: usize,
        min_top_n_of_1_to_n: usize,
        time: Option<NaiveDateTime>,
    ) -> Result<Vec<TopMultimaps>> {
        let time = time.map(from_naive_utc);
        let column_1: HashSet<_> = get_selected_column_index(column_1).into_iter().collect();
        let column_n: HashSet<_> = get_selected_column_index(column_n).into_iter().collect();
        let prefix_size = if time.is_some() {
            size_of::<i32>() + size_of::<u32>() + size_of::<i64>()
        } else {
            size_of::<i32>() + size_of::<u32>()
        };
        let mut prefix = Vec::with_capacity(prefix_size);
        prefix.extend(model_id.to_be_bytes());
        prefix.extend(u32::to_be_bytes(0)); // placeholder for cluster_id
        if let Some(ts) = time {
            prefix.extend(ts.to_be_bytes());
        }
        let mut top_n_stats = vec![];
        for cluster_id in cluster_ids {
            prefix[size_of::<i32>()..size_of::<i32>() + size_of::<u32>()]
                .copy_from_slice(&cluster_id.to_be_bytes());

            let iter = self.prefix_iter(Direction::Forward, None, &prefix);
            for result in iter {
                let column_stats = result?;
                if column_stats.model_id != model_id {
                    continue;
                }
                if column_n.contains(&column_stats.column_index)
                    || column_1.contains(&column_stats.column_index)
                {
                    top_n_stats.push(column_stats);
                }
            }
        }

        let mut result = Vec::new();
        for col_n in column_n {
            let candidates: Vec<_> = top_n_stats
                .iter()
                .filter(|s| {
                    s.column_index == col_n && s.n_largest_count.top_n().len() > min_top_n_of_1_to_n
                })
                .map(|s| (s.cluster_id, s.batch_ts, s.n_largest_count.top_n().len()))
                .collect();

            let mut clusters = candidates.into_iter().fold(
                HashMap::new(),
                |mut acc: HashMap<_, Vec<_>>, (cluster_id, batch_ts, count)| {
                    let e = acc.entry(cluster_id).or_default();
                    e.push((batch_ts, count));
                    acc
                },
            );

            for counts in clusters.values_mut() {
                counts.sort_unstable_by(|a, b| b.0.cmp(&a.0));
                counts.sort_unstable_by(|a, b| b.1.cmp(&a.1));
            }

            let mut clusters: Vec<_> = clusters.into_iter().map(|(k, val)| (k, val[0])).collect();
            clusters.sort_unstable_by_key(|(cluster_id, _)| *cluster_id);
            clusters.sort_unstable_by_key(|(_, (batch_ts, _))| *batch_ts);
            clusters.truncate(number_of_top_n);

            let selected: HashSet<_> = clusters.iter().map(|(c, _)| *c).collect();
            let batches: HashSet<_> = clusters
                .into_iter()
                .map(|(_, (batch_ts, _))| batch_ts)
                .collect();
            let selected = top_n_stats
                .iter()
                .filter(|s| selected.contains(&s.cluster_id) && batches.contains(&s.batch_ts))
                .fold(
                    HashMap::new(),
                    |mut acc: HashMap<_, HashMap<_, Vec<&[_]>>>, s| {
                        let entry = acc.entry(s.cluster_id).or_default();
                        let e = entry.entry(s.column_index).or_default();
                        e.push(s.n_largest_count.top_n());
                        acc
                    },
                );

            result.push(to_multi_maps(col_n, selected));
        }

        Ok(result)
    }

    /// Gets the top N columns of a model.
    /// `cluster_ids`: retrieved by `load_cluster_ids(model_id)` and
    ///     limited by `get_limited_cluster_ids(..portion_of_clusters..)`
    /// `top_n`: the `CsvColumnExtra::column_top_n` value of the model.
    ///
    /// # Panics
    ///
    /// Will panic if `top_n` is not a valid slice of booleans or if `number_of_top_n` is larger than `usize::MAX`.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database error occurs.
    pub fn get_top_columns_of_model(
        &self,
        model_id: u32,
        cluster_ids: Vec<u32>,
        top_n: &[bool],
        number_of_top_n: usize,
        time: Option<NaiveDateTime>,
        portion_of_top_n: Option<f64>,
    ) -> Result<Vec<TopElementCountsByColumn>> {
        let columns = get_columns_for_top_n(top_n);
        let time = time.map(from_naive_utc);
        let prefix_size = if time.is_some() {
            size_of::<i32>() + size_of::<u32>() + size_of::<i64>()
        } else {
            size_of::<i32>() + size_of::<u32>()
        };
        let mut prefix = Vec::with_capacity(prefix_size);
        prefix.extend(model_id.to_be_bytes());
        prefix.extend(u32::to_be_bytes(0)); // placeholder for cluster_id
        if let Some(ts) = time {
            prefix.extend(ts.to_be_bytes());
        }

        let mut total_of_top_n: HashMap<_, HashMap<_, HashMap<String, i64>>> = HashMap::new();
        for cluster_id in cluster_ids {
            prefix[size_of::<i32>()..size_of::<i32>() + size_of::<u32>()]
                .copy_from_slice(&cluster_id.to_be_bytes());

            let iter = self.prefix_iter(Direction::Forward, None, &prefix);
            for result in iter {
                let column_stats = result?;

                if !columns.contains(&i32::try_from(column_stats.column_index)?) {
                    continue;
                }
                let entry = total_of_top_n
                    .entry(cluster_id)
                    .or_default()
                    .entry(column_stats.column_index)
                    .or_default();
                for (value, count) in column_stats.n_largest_count.top_n().iter().map(|ec| {
                    (
                        ec.value.to_string(),
                        ec.count.to_i64().expect("Count is not a valid i64"),
                    )
                }) {
                    *entry.entry(value).or_insert(0) += count;
                }
            }
        }
        let limited_top_n = limited_top_n_of_clusters(
            total_of_top_n,
            portion_of_top_n.unwrap_or(DEFAULT_PORTION_OF_TOP_N),
        );

        Ok(to_element_counts(limited_top_n, number_of_top_n))
    }

    /// Gets top N IP addresses of a cluster.
    /// `cluster_ids`: retrieved by `load_cluster_ids(model_id)` and
    ///     limited by `cluster_id: &str`.
    ///
    /// # Panics
    ///
    /// Will panic if `usize` is smaller than 4 bytes or if `cluster_ids` is empty.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database operation fails.
    pub fn get_top_ip_addresses_of_cluster(
        &self,
        model_id: u32,
        cluster_ids: &[i32],
        size: usize,
    ) -> Result<Vec<TopElementCountsByColumn>> {
        use std::cmp::Reverse;

        if cluster_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut prefix = Vec::with_capacity(size_of::<i32>() + size_of::<u32>());
        prefix.extend(model_id.to_be_bytes());
        prefix.extend(u32::to_be_bytes(0)); // placeholder for cluster_id

        let mut top_n: HashMap<u32, HashMap<String, i64>> = HashMap::new();
        for cluster_id in cluster_ids {
            prefix[size_of::<i32>()..].copy_from_slice(&cluster_id.to_be_bytes());
            let iter = self.prefix_iter(Direction::Forward, None, &prefix);
            for result in iter {
                let column_stats = result?;
                if column_stats.model_id != model_id {
                    continue;
                }
                match column_stats.n_largest_count.mode().as_ref() {
                    Some(Element::IpAddr(_)) => {}
                    // Only process IP addresses.
                    _ => continue,
                }
                let entry: &mut _ = top_n.entry(column_stats.column_index).or_default();
                for ec in column_stats.n_largest_count.top_n() {
                    *entry.entry(ec.value.to_string()).or_insert(0) +=
                        ec.count.to_i64().expect("Count is not a valid i64");
                }
            }
        }

        let mut top_n: Vec<TopElementCountsByColumn> = top_n
            .into_iter()
            .map(|t| {
                let mut top_n: Vec<ElementCount> =
                    t.1.into_iter()
                        .map(|t| ElementCount {
                            value: t.0,
                            count: t.1,
                        })
                        .collect();
                top_n.sort_by_key(|v| Reverse(v.count));
                top_n.truncate(size);
                TopElementCountsByColumn {
                    column_index: t.0.to_usize().expect("column index < usize::max"),
                    counts: top_n,
                }
            })
            .collect();
        top_n.sort_by_key(|v| v.column_index);
        Ok(top_n)
    }

    /// Gets top N IP addresses of a model.
    /// `cluster_ids`: retrieved by `load_cluster_ids_with_size_limit(model_id, portion_of_cluster)`.
    ///
    /// # Panics
    ///
    /// Will panic if `portion_of_top_n` is not between 0.0 and 1.0.
    /// Will panic if a `column_index` from the database cannot be represented as a `usize`.
    ///
    /// # Errors
    ///
    /// Returns an error if an underlying database operation fails.
    pub fn get_top_ip_addresses_of_model(
        &self,
        model_id: u32,
        cluster_ids: &[u32],
        size: usize, // number of top N IP addresses to return
        time: Option<NaiveDateTime>,
        portion_of_top_n: Option<f64>,
    ) -> Result<Vec<TopElementCountsByColumn>> {
        let time = time.map(from_naive_utc).map(i64::to_be_bytes);
        let mut total_of_top_n: HashMap<_, HashMap<_, HashMap<String, i64>>> = HashMap::new();
        let prefix_size = if time.is_some() {
            size_of::<i32>() + size_of::<u32>() + size_of::<i64>()
        } else {
            size_of::<i32>() + size_of::<u32>()
        };
        let mut prefix = Vec::with_capacity(prefix_size);
        prefix.extend(model_id.to_be_bytes());
        prefix.extend(u32::to_be_bytes(0)); // placeholder for cluster_id
        if let Some(ts) = time {
            prefix.extend(ts);
        }

        for &cluster_id in cluster_ids {
            prefix[size_of::<i32>()..size_of::<i32>() + size_of::<u32>()]
                .copy_from_slice(&cluster_id.to_be_bytes());

            let iter = self.prefix_iter(Direction::Forward, None, &prefix);
            for result in iter {
                let column_stats = result?;
                if column_stats.model_id != model_id {
                    continue;
                }
                if !matches!(
                    column_stats.n_largest_count.mode().as_ref(),
                    Some(Element::IpAddr(_))
                ) {
                    continue;
                }
                let entry = total_of_top_n
                    .entry(cluster_id)
                    .or_default()
                    .entry(column_stats.column_index)
                    .or_default();
                for result in column_stats.n_largest_count.top_n().iter().map(|ec| {
                    ec.count
                        .to_i64()
                        .map(|c| (ec.value.to_string(), c))
                        .ok_or_else(|| {
                            anyhow::anyhow!("Count {} is too large to fit in i64", ec.count)
                        })
                }) {
                    let (value, count) = result?;
                    *entry.entry(value).or_insert(0) += count;
                }
            }
        }
        let limited_top_n = limited_top_n_of_clusters(
            total_of_top_n,
            portion_of_top_n.unwrap_or(DEFAULT_PORTION_OF_TOP_N),
        );
        Ok(to_element_counts(limited_top_n, size))
    }

    /// Returns the number of rounds in the given cluster.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn count_rounds_by_cluster(&self, model_id: i32, cluster_id: u32) -> Result<i64> {
        let mut prefix = model_id.to_be_bytes().to_vec();
        prefix.extend(cluster_id.to_be_bytes());
        let iter = self.prefix_iter(Direction::Forward, None, &prefix);
        i64::try_from(
            iter.filter_map(|result| {
                let column_stats = result.ok()?;
                Some(column_stats.batch_ts)
            })
            .collect::<HashSet<_>>()
            .len(),
        )
        .map_err(|_| anyhow::anyhow!("Failed to convert count to i64"))
    }

    /// Returns the rounds in the given cluster.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn load_rounds_by_cluster(
        &self,
        model_id: u32,
        cluster_id: u32,
        after: &Option<NaiveDateTime>,
        before: &Option<NaiveDateTime>,
        is_first: bool,
        limit: usize,
    ) -> Result<(i32, Vec<NaiveDateTime>)> {
        let mut prefix = model_id.to_be_bytes().to_vec();
        prefix.extend(cluster_id.to_be_bytes());
        let mut buf = Vec::with_capacity(size_of::<u32>() + size_of::<i64>());
        buf.extend(cluster_id.to_be_bytes());
        let (direction, from) = if is_first {
            if let Some(after) = after {
                let after_ts = from_naive_utc(*after);
                buf.extend(after_ts.to_be_bytes());
                (Direction::Forward, Some(buf.as_slice()))
            } else {
                (Direction::Forward, None)
            }
        } else if let Some(before) = before {
            let before_ts = from_naive_utc(*before);
            buf.extend(before_ts.to_be_bytes());
            (Direction::Reverse, Some(buf.as_slice()))
        } else {
            (Direction::Reverse, None)
        };
        let iter = self.prefix_iter(direction, from, &prefix);
        let mut model_id = Option::None;
        let mut rounds = HashSet::new();
        for (m_id, round) in iter.filter_map(|result| {
            let column_stats = result.ok()?;
            Some((
                column_stats.model_id,
                from_timestamp(column_stats.batch_ts).ok()?,
            ))
        }) {
            if model_id.is_none() {
                model_id = Some(m_id);
            } else if model_id != Some(m_id) {
                return Err(anyhow::anyhow!("Model ID mismatch"));
            }
            rounds.insert(round);
            if rounds.len() >= limit {
                break;
            }
        }
        let model_id = model_id.ok_or_else(|| anyhow::anyhow!("No model ID found"))?;
        Ok((i32::try_from(model_id)?, rounds.into_iter().collect()))
    }

    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn get_column_types_of_model(
        &self,
        model_id: u32,
    ) -> Result<Vec<crate::StructuredColumnType>> {
        let prefix = model_id.to_be_bytes();

        if let Some(first) = self.prefix_iter(Direction::Forward, None, &prefix).next() {
            let column_stats = first?;
            let key = column_stats.unique_key();
            let iter = self.prefix_iter(
                Direction::Forward,
                None,
                &key[..key.len() - size_of::<u32>()],
            );
            let mut column_types = Vec::new();
            for result in iter {
                let column_stats = result?;
                if column_stats.model_id == model_id {
                    column_types.push(crate::StructuredColumnType::from((
                        i32::try_from(column_stats.column_index)?,
                        get_column_type(&column_stats)
                            .ok_or(anyhow::anyhow!("Unsupported column type"))?,
                    )));
                }
            }
            return Ok(column_types);
        }

        Ok(Vec::new())
    }
}

/// #Panics
///
/// Panics if the indices of selected columns are not valid `u32` values.
fn get_selected_column_index(columns: &[bool]) -> Vec<u32> {
    // Collect the indices of columns that are marked as selected.
    columns
        .iter()
        .enumerate()
        .filter_map(|(index, &is_selected)| {
            if is_selected {
                Some(index.to_u32().expect("column index < u32::max"))
            } else {
                None
            }
        })
        .collect()
}

fn get_column_type(column_stats: &ColumnStats) -> Option<i32> {
    // Determine the column type based on the mode of n_largest_count.
    // This is a simplified mapping; adjust as necessary for your application.
    match &column_stats.n_largest_count.mode() {
        Some(Element::Int(_)) => Some(1),
        Some(Element::Enum(_)) => Some(2),
        Some(Element::FloatRange(_)) => Some(3),
        Some(Element::Text(_)) => Some(4),
        Some(Element::IpAddr(_)) => Some(5),
        Some(Element::DateTime(_)) => Some(6),
        Some(Element::Binary(_)) => Some(7),
        _ => None,
    }
}

fn get_columns_for_top_n(top_n: &[bool]) -> HashSet<i32> {
    // Collect the indices of columns that are marked for top N.
    top_n
        .iter()
        .enumerate()
        .filter_map(|(index, &is_top_n)| {
            if is_top_n {
                Some(index.to_i32().expect("column index < i32::max"))
            } else {
                None
            }
        })
        .collect()
}

fn limited_top_n_of_clusters(
    top_n_of_clusters: HashMap<u32, HashMap<u32, HashMap<String, i64>>>,
    limit_rate: f64,
) -> HashMap<u32, HashMap<String, i64>> {
    use std::cmp::Reverse;

    let mut top_n_total: HashMap<u32, HashMap<String, i64>> = HashMap::new(); // (usize, (String, BigDecimal)) = (column_index, (Ip Address, size))
    for (_, top_n) in top_n_of_clusters {
        for (column_index, t) in top_n {
            let total_sizes: i64 = t.iter().map(|v| v.1).sum();
            let mut top_n: Vec<(String, i64)> = t.into_iter().collect();
            top_n.sort_by_key(|v| Reverse(v.1));

            let size_including_ips =
                i64::from_f64((total_sizes.to_f64().unwrap_or(0.0) * limit_rate).trunc())
                    .unwrap_or_else(|| i64::from_u32(DEFAULT_NUMBER_OF_COLUMN).unwrap_or(i64::MAX));

            let mut sum_sizes = 0;
            for (ip, size) in top_n {
                sum_sizes += size;
                *top_n_total
                    .entry(column_index)
                    .or_default()
                    .entry(ip)
                    .or_insert(0) += size;
                if sum_sizes > size_including_ips {
                    break;
                }
            }
        }
    }

    top_n_total
}

fn to_element_counts(
    top_n_total: HashMap<u32, HashMap<String, i64>>,
    number_of_top_n: usize,
) -> Vec<TopElementCountsByColumn> {
    let mut top_n: Vec<TopElementCountsByColumn> = top_n_total
        .into_iter()
        .map(|(column_index, map)| {
            let mut top_n: Vec<ElementCount> = map
                .into_iter()
                .map(|(dsc, size)| ElementCount {
                    value: dsc,
                    count: size,
                })
                .collect();
            top_n
                .sort_unstable_by(|a, b| b.count.cmp(&a.count).then_with(|| a.value.cmp(&b.value)));
            top_n.truncate(number_of_top_n);
            TopElementCountsByColumn {
                column_index: usize::try_from(column_index).expect("column index < usize::max"),
                counts: top_n,
            }
        })
        .collect();
    top_n.sort_by_key(|v| v.column_index);

    top_n
}

fn from_timestamp(timestamp: i64) -> Result<NaiveDateTime> {
    // Convert the timestamp to a NaiveDateTime.
    const A_BILLION: i64 = 1_000_000_000;
    let s = timestamp.div_euclid(A_BILLION);
    let nanos = u32::try_from(timestamp.rem_euclid(A_BILLION))?;
    chrono::DateTime::from_timestamp(s, nanos)
        .map(|t| t.naive_utc())
        .ok_or(anyhow::anyhow!("Invalid timestamp: {timestamp}"))
}

fn from_naive_utc(date: NaiveDateTime) -> i64 {
    // Convert a NaiveDateTime to a timestamp in nanoseconds.
    const A_BILLION: i64 = 1_000_000_000;

    let seconds = date.and_utc().timestamp();
    let nanos = i64::from(date.and_utc().timestamp_subsec_nanos());
    seconds * A_BILLION + nanos
}

fn to_multi_maps(
    column: u32,
    selected: HashMap<u32, HashMap<u32, Vec<&[structured::ElementCount]>>>,
) -> TopMultimaps {
    TopMultimaps {
        n_index: column.to_usize().expect("column index < usize::max"),
        selected: selected
            .into_iter()
            .map(|(cluster_id, v)| {
                let cluster_id = cluster_id.to_i32().expect("cluster_id is a valid i32");
                TopColumnsOfCluster {
                    cluster_id,
                    columns: v
                        .into_iter()
                        .map(|(col, top_n)| TopElementCountsByColumn {
                            column_index: col.to_usize().expect("column index < usize::max"),
                            counts: top_n
                                .into_iter()
                                .flat_map(|ecs| {
                                    ecs.iter().map(|ec| ElementCount {
                                        value: ec.value.to_string(),
                                        count: ec.count.to_i64().expect("Count is not a valid i64"),
                                    })
                                })
                                .collect(),
                        })
                        .collect(),
                }
            })
            .collect(),
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct ColumnStats {
    pub model_id: u32,
    pub cluster_id: u32,
    pub batch_ts: i64,
    pub column_index: u32,
    pub description: Description,
    pub n_largest_count: NLargestCount,
}

impl FromKeyValue for ColumnStats {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let key = Key::from_be_bytes(key);

        let value: Value = super::deserialize(value)?;

        Ok(Self {
            model_id: key.model_id,
            cluster_id: key.cluster_id,
            batch_ts: key.batch_ts,
            column_index: key.column_index,
            description: value.description,
            n_largest_count: value.n_largest_count,
        })
    }
}

impl UniqueKey for ColumnStats {
    type AsBytes<'a> = Vec<u8>;

    fn unique_key(&self) -> Vec<u8> {
        Key {
            cluster_id: self.cluster_id,
            batch_ts: self.batch_ts,
            column_index: self.column_index,
            model_id: self.model_id,
        }
        .to_bytes()
    }
}

impl ValueTrait for ColumnStats {
    type AsBytes<'a> = Vec<u8>;

    fn value(&self) -> Vec<u8> {
        super::serialize(&Value {
            description: self.description.clone(),
            n_largest_count: self.n_largest_count.clone(),
        })
        .expect("serializable")
    }
}

struct Key {
    pub model_id: u32,
    pub cluster_id: u32,
    pub batch_ts: i64,
    pub column_index: u32,
}
impl Key {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let capacity = size_of::<i32>() + size_of::<i64>() + size_of::<u32>() * 2;

        let mut buf = Vec::with_capacity(capacity);
        buf.extend(self.model_id.to_be_bytes());
        buf.extend(self.cluster_id.to_be_bytes());
        buf.extend(self.batch_ts.to_be_bytes());
        buf.extend(self.column_index.to_be_bytes());

        buf
    }

    pub fn from_be_bytes(buf: &[u8]) -> Self {
        let (val, rest) = buf.split_at(size_of::<i32>());

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
        let batch_ts = i64::from_be_bytes(buf);

        let mut buf = [0; size_of::<u32>()];
        buf.copy_from_slice(rest);
        let column_index = u32::from_be_bytes(buf);

        Self {
            model_id,
            cluster_id,
            batch_ts,
            column_index,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Value {
    pub description: Description,
    pub n_largest_count: NLargestCount,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use chrono::NaiveDate;
    use structured::{Description, Element, NLargestCount};
    use structured::{ElementCount, FloatRange};

    use super::*;
    use crate::Store;
    use crate::test::{DbGuard, acquire_db_permit};

    #[test]
    fn test_column_stats() {
        use structured::{Description, NLargestCount};
        let (_permit, store) = setup_store();
        let table = store.column_stats_map();

        let stats = super::ColumnStats {
            cluster_id: 42,
            batch_ts: 1_622_547_800,
            column_index: 0,
            model_id: 1,
            description: Description::default(),
            n_largest_count: NLargestCount::default(),
        };
        table.insert(&stats).unwrap();
        let retrieved = table.get(1_622_547_800, 1, 42).next().unwrap().unwrap();
        assert_eq!(retrieved, stats);
    }

    #[test]
    fn test_insert_and_get_column_statistics() {
        use chrono::NaiveDate;
        use structured::{ColumnStatistics, Description, Element, NLargestCount};

        let (_permit, store) = setup_store();
        let table = store.column_stats_map();

        let cluster_id = 1;
        let model_id = 99;
        let batch_ts = NaiveDate::from_ymd_opt(2023, 6, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();

        let statistics = vec![(
            cluster_id,
            vec![ColumnStatistics {
                description: Description::default(),
                n_largest_count: NLargestCount::new(
                    2,
                    vec![
                        ElementCount {
                            value: Element::Int(1),
                            count: 10,
                        },
                        ElementCount {
                            value: Element::Int(2),
                            count: 5,
                        },
                    ],
                    Some(Element::Int(1)),
                ),
            }],
        )];

        table
            .insert_column_statistics(statistics, model_id, batch_ts)
            .unwrap();

        let stats = table
            .get_column_statistics(model_id, cluster_id, vec![batch_ts])
            .unwrap();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].column_index, 0);
        assert_eq!(
            stats[0].column_stats.n_largest_count.number_of_elements(),
            2
        );
    }

    #[test]
    fn test_count_rounds_by_cluster() {
        use chrono::NaiveDate;
        use structured::{ColumnStatistics, Description, Element, NLargestCount};

        let (_permit, store) = setup_store();
        let table = store.column_stats_map();

        let cluster_id = 11;
        let model_id = 2;

        let batch1 = NaiveDate::from_ymd_opt(2023, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();
        let batch2 = NaiveDate::from_ymd_opt(2023, 2, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();

        let stats1 = ColumnStatistics {
            description: Description::default(),
            n_largest_count: NLargestCount::new(
                1,
                vec![ElementCount {
                    value: Element::Int(42),
                    count: 7,
                }],
                Some(Element::Int(42)),
            ),
        };

        let stats2 = ColumnStatistics {
            description: Description::default(),
            n_largest_count: NLargestCount::new(
                1,
                vec![ElementCount {
                    value: Element::Int(83),
                    count: 3,
                }],
                Some(Element::Int(83)),
            ),
        };

        table
            .insert_column_statistics(vec![(cluster_id, vec![stats1])], model_id, batch1)
            .unwrap();

        table
            .insert_column_statistics(vec![(cluster_id, vec![stats2])], model_id, batch2)
            .unwrap();

        let count = table.count_rounds_by_cluster(2, cluster_id).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_load_rounds_by_cluster() {
        use chrono::NaiveDate;
        use structured::{ColumnStatistics, Description, Element, NLargestCount};

        let (_permit, store) = setup_store();
        let table = store.column_stats_map();

        let cluster_id = 123;
        let model_id = 42_u32;

        let batch1 = NaiveDate::from_ymd_opt(2024, 1, 10)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();
        let batch2 = NaiveDate::from_ymd_opt(2024, 2, 10)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();

        let stats = ColumnStatistics {
            description: Description::default(),
            n_largest_count: NLargestCount::new(
                1,
                vec![ElementCount {
                    value: Element::Int(5),
                    count: 1,
                }],
                Some(Element::Int(5)),
            ),
        };

        for batch in &[batch1, batch2] {
            table
                .insert_column_statistics(vec![(cluster_id, vec![stats.clone()])], model_id, *batch)
                .unwrap();
        }

        let (retrieved_model_id, rounds) = table
            .load_rounds_by_cluster(model_id, cluster_id, &None, &None, true, 10)
            .unwrap();

        assert_eq!(u32::try_from(retrieved_model_id).unwrap(), model_id);
        assert_eq!(rounds.len(), 2);
        assert!(rounds.contains(&batch1));
        assert!(rounds.contains(&batch2));
    }

    #[test]
    fn test_get_column_types_of_model() {
        use chrono::NaiveDate;
        use structured::{ColumnStatistics, Description, Element, NLargestCount};

        let (_permit, store) = setup_store();
        let table = store.column_stats_map();

        let model_id = 101;
        let cluster_id = 7;
        let batch_ts = NaiveDate::from_ymd_opt(2023, 3, 15)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();

        let stats = ColumnStatistics {
            description: Description::default(),
            n_largest_count: NLargestCount::new(
                1,
                vec![ElementCount {
                    value: Element::IpAddr("127.0.0.1".parse().unwrap()),
                    count: 1,
                }],
                Some(Element::IpAddr("127.0.0.1".parse().unwrap())),
            ),
        };

        table
            .insert_column_statistics(vec![(cluster_id, vec![stats])], model_id, batch_ts)
            .unwrap();

        let column_types = table.get_column_types_of_model(model_id).unwrap();
        assert_eq!(column_types.len(), 1);
        assert_eq!(column_types[0].column_index, 0);
    }
    #[test]
    fn test_get_selected_column_index() {
        let columns = vec![false, true, false, true];
        let indices = get_selected_column_index(&columns);
        assert_eq!(indices, vec![1, 3]);
    }

    #[test]
    fn test_get_columns_for_top_n() {
        let top_n = vec![true, false, true];
        let indices = get_columns_for_top_n(&top_n);
        assert!(indices.contains(&0));
        assert!(indices.contains(&2));
        assert!(!indices.contains(&1));
    }

    #[test]
    fn test_get_column_type_variants() {
        let mut column_stats = ColumnStats {
            cluster_id: 0,
            batch_ts: 0,
            column_index: 0,
            model_id: 0,
            description: Description::default(),
            n_largest_count: NLargestCount::default(),
        };

        let variants = vec![
            (Element::Int(1), 1),
            (Element::Enum("abc".into()), 2),
            (
                Element::FloatRange(FloatRange {
                    smallest: 1.0,
                    largest: 2.0,
                }),
                3,
            ),
            (Element::Text("text".into()), 4),
            (Element::IpAddr("127.0.0.1".parse().unwrap()), 5),
            (
                Element::DateTime(jiff::civil::DateTime::new(2024, 1, 1, 0, 0, 0, 0).unwrap()),
                6,
            ),
            (Element::Binary(vec![1, 2, 3]), 7),
        ];

        for (element, expected_type) in variants {
            column_stats.n_largest_count = NLargestCount::new(1, vec![], Some(element));
            assert_eq!(get_column_type(&column_stats), Some(expected_type));
        }
    }

    #[test]
    fn test_from_and_to_timestamp() {
        let now = NaiveDate::from_ymd_opt(2024, 1, 1)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap();
        let ts = from_naive_utc(now);
        let restored = from_timestamp(ts).unwrap();
        assert_eq!(restored, now);
    }

    #[test]
    fn test_key_to_and_from_bytes() {
        let original = Key {
            cluster_id: 42,
            batch_ts: 123_456_789,
            column_index: 7,
            model_id: 99,
        };
        let bytes = original.to_bytes();
        let parsed = Key::from_be_bytes(&bytes);
        assert_eq!(parsed.cluster_id, original.cluster_id);
        assert_eq!(parsed.batch_ts, original.batch_ts);
        assert_eq!(parsed.column_index, original.column_index);
        assert_eq!(parsed.model_id, original.model_id);
    }

    #[test]
    fn test_limited_top_n_of_clusters() {
        let mut input: HashMap<u32, HashMap<u32, HashMap<String, i64>>> = HashMap::new();
        input.insert(
            1,
            vec![
                (0, vec![("a".to_string(), 10), ("b".to_string(), 5)]),
                (1, vec![("c".to_string(), 20), ("d".to_string(), 10)]),
            ]
            .into_iter()
            .map(|(col, data)| (col, data.into_iter().collect()))
            .collect(),
        );

        let limited = limited_top_n_of_clusters(input, 0.5);
        assert!(limited.contains_key(&0));
        assert!(limited.contains_key(&1));
    }

    #[test]
    fn test_to_element_counts() {
        let mut map = HashMap::new();
        map.insert(
            0,
            vec![("x".to_string(), 100), ("y".to_string(), 50)]
                .into_iter()
                .collect(),
        );
        let result = to_element_counts(map, 1);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].counts.len(), 1);
        assert_eq!(result[0].counts[0].value, "x");
    }

    #[test]
    fn test_to_multi_maps_basic() {
        let mut selected: HashMap<u32, HashMap<u32, Vec<&[ElementCount]>>> = HashMap::new();
        let cluster_id = 1u32;
        let column_index = 0u32;
        let data = vec![ElementCount {
            value: Element::Int(1),
            count: 42,
        }];

        selected
            .entry(cluster_id)
            .or_default()
            .insert(column_index, vec![&data]);

        let result = to_multi_maps(0, selected);
        assert_eq!(result.n_index, 0);
        assert_eq!(result.selected.len(), 1);
        assert_eq!(result.selected[0].cluster_id, 1);
        assert_eq!(result.selected[0].columns[0].counts[0].count, 42);
    }
    #[test]
    fn test_get_top_ip_addresses_of_model() {
        use chrono::NaiveDate;
        use structured::{ColumnStatistics, Description, Element, ElementCount, NLargestCount};

        let (_permit, store) = setup_store();
        let table = store.column_stats_map();

        let model_id = 10;
        let cluster_id = 55;
        let column_index = 0;
        let batch_ts = NaiveDate::from_ymd_opt(2025, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();

        let ip_counts = NLargestCount::new(
            3,
            vec![
                ElementCount {
                    value: Element::IpAddr("192.168.0.1".parse().unwrap()),
                    count: 30,
                },
                ElementCount {
                    value: Element::IpAddr("10.0.0.1".parse().unwrap()),
                    count: 20,
                },
                ElementCount {
                    value: Element::IpAddr("8.8.8.8".parse().unwrap()),
                    count: 10,
                },
            ],
            Some(Element::IpAddr("192.168.0.1".parse().unwrap())),
        );

        let stats = ColumnStatistics {
            description: Description::default(),
            n_largest_count: ip_counts.clone(),
        };

        table
            .insert_column_statistics(vec![(cluster_id, vec![stats])], model_id, batch_ts)
            .unwrap();

        let result = table
            .get_top_ip_addresses_of_model(model_id, &[cluster_id], 2, Some(batch_ts), Some(1.0))
            .unwrap();

        // One cluster, one column, only top 2 returned
        assert_eq!(result.len(), 1); // one column
        let column_result = &result[0];
        assert_eq!(column_result.column_index, column_index);

        let values: Vec<_> = column_result
            .counts
            .iter()
            .map(|e| e.value.clone())
            .collect();

        assert_eq!(values.len(), 2);
        assert_eq!(values[0], "192.168.0.1");
        assert_eq!(values[1], "10.0.0.1");

        let counts: Vec<_> = column_result.counts.iter().map(|e| e.count).collect();
        assert_eq!(counts, vec![30, 20]);
    }

    #[test]
    fn test_retain_deletes_old_entries() {
        use structured::{ColumnStatistics, Description, Element, NLargestCount};

        let (_permit, store) = setup_store();
        let table = store.column_stats_map();

        let model_id = 100;
        let cluster_id = 1;

        // Create entries with different timestamps
        // Old entry (2020-01-01)
        let old_batch = NaiveDate::from_ymd_opt(2020, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();

        // Recent entry (2025-01-01)
        let recent_batch = NaiveDate::from_ymd_opt(2025, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();

        let stats = ColumnStatistics {
            description: Description::default(),
            n_largest_count: NLargestCount::new(
                1,
                vec![ElementCount {
                    value: Element::Int(1),
                    count: 10,
                }],
                Some(Element::Int(1)),
            ),
        };

        // Insert old and recent entries
        table
            .insert_column_statistics(vec![(cluster_id, vec![stats.clone()])], model_id, old_batch)
            .unwrap();
        table
            .insert_column_statistics(
                vec![(cluster_id, vec![stats.clone()])],
                model_id + 1,
                recent_batch,
            )
            .unwrap();

        // Cutoff at 2024-01-01 (should delete the 2020 entry but keep the 2025 entry)
        let cutoff = NaiveDate::from_ymd_opt(2024, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();
        let cutoff_ts = from_naive_utc(cutoff);

        let result = table.retain(cutoff_ts, 100).unwrap();
        assert_eq!(result.deleted, 1);
        assert_eq!(result.batches, 1);

        // Verify old entry was deleted
        let old_ts = from_naive_utc(old_batch);
        assert!(table.get(old_ts, model_id, cluster_id).next().is_none());

        // Verify recent entry still exists
        let recent_ts = from_naive_utc(recent_batch);
        assert!(
            table
                .get(recent_ts, model_id + 1, cluster_id)
                .next()
                .is_some()
        );
    }

    #[test]
    fn test_retain_batching() {
        use structured::{ColumnStatistics, Description, Element, NLargestCount};

        let (_permit, store) = setup_store();
        let table = store.column_stats_map();

        let cluster_id = 1;

        // Create 10 old entries
        let old_batch = NaiveDate::from_ymd_opt(2020, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();

        let stats = ColumnStatistics {
            description: Description::default(),
            n_largest_count: NLargestCount::new(
                1,
                vec![ElementCount {
                    value: Element::Int(1),
                    count: 10,
                }],
                Some(Element::Int(1)),
            ),
        };

        for model_id in 0..10u32 {
            table
                .insert_column_statistics(
                    vec![(cluster_id, vec![stats.clone()])],
                    model_id,
                    old_batch,
                )
                .unwrap();
        }

        // Delete with batch size of 3 (should result in 4 batches: 3+3+3+1)
        let cutoff = NaiveDate::from_ymd_opt(2024, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();
        let cutoff_ts = from_naive_utc(cutoff);

        let result = table.retain(cutoff_ts, 3).unwrap();
        assert_eq!(result.deleted, 10);
        assert_eq!(result.batches, 4);
    }

    #[test]
    fn test_retain_no_entries_to_delete() {
        use structured::{ColumnStatistics, Description, Element, NLargestCount};

        let (_permit, store) = setup_store();
        let table = store.column_stats_map();

        let model_id = 100;
        let cluster_id = 1;

        // Create only recent entries
        let recent_batch = NaiveDate::from_ymd_opt(2025, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();

        let stats = ColumnStatistics {
            description: Description::default(),
            n_largest_count: NLargestCount::new(
                1,
                vec![ElementCount {
                    value: Element::Int(1),
                    count: 10,
                }],
                Some(Element::Int(1)),
            ),
        };

        table
            .insert_column_statistics(vec![(cluster_id, vec![stats])], model_id, recent_batch)
            .unwrap();

        // Cutoff at 2024-01-01 (no entries should be deleted)
        let cutoff = NaiveDate::from_ymd_opt(2024, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();
        let cutoff_ts = from_naive_utc(cutoff);

        let result = table.retain(cutoff_ts, 100).unwrap();
        assert_eq!(result.deleted, 0);
        assert_eq!(result.batches, 0);
    }

    #[test]
    fn test_count_expired() {
        use structured::{ColumnStatistics, Description, Element, NLargestCount};

        let (_permit, store) = setup_store();
        let table = store.column_stats_map();

        let cluster_id = 1;

        // Create entries with different timestamps
        let old_batch = NaiveDate::from_ymd_opt(2020, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();
        let recent_batch = NaiveDate::from_ymd_opt(2025, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();

        let stats = ColumnStatistics {
            description: Description::default(),
            n_largest_count: NLargestCount::new(
                1,
                vec![ElementCount {
                    value: Element::Int(1),
                    count: 10,
                }],
                Some(Element::Int(1)),
            ),
        };

        // Insert 3 old and 2 recent entries
        for model_id in 0..3u32 {
            table
                .insert_column_statistics(
                    vec![(cluster_id, vec![stats.clone()])],
                    model_id,
                    old_batch,
                )
                .unwrap();
        }
        for model_id in 100..102u32 {
            table
                .insert_column_statistics(
                    vec![(cluster_id, vec![stats.clone()])],
                    model_id,
                    recent_batch,
                )
                .unwrap();
        }

        let cutoff = NaiveDate::from_ymd_opt(2024, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();
        let cutoff_ts = from_naive_utc(cutoff);

        // Should count only the 3 old entries
        let count = table.count_expired(cutoff_ts).unwrap();
        assert_eq!(count, 3);
    }

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        (permit, store)
    }
}
