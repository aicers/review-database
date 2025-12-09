use std::{cmp::Reverse, mem::size_of};

use anyhow::{Result, anyhow, bail};
use chrono::NaiveDateTime;
use rocksdb::{Direction, OptimisticTransactionDB};
use serde::{Deserialize, Serialize};

use crate::{
    Iterable, Map, Table, UniqueKey,
    tables::{TableIter, Value as ValueTrait},
    types::FromKeyValue,
};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Cluster {
    pub model_id: u32,
    pub id: i32,
    pub category_id: i32,
    pub detector_id: i32,
    pub event_ids: Vec<i64>,
    pub sensors: Vec<String>,
    pub labels: Option<Vec<String>>,
    pub qualifier_id: i32,
    pub status_id: i32,
    pub signature: String,
    pub size: i64,
    pub score: Option<f64>,
    pub last_modification_time: Option<NaiveDateTime>,
}

impl<'d> Table<'d, Cluster> {
    /// Opens the `cluster` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::CLUSTER).map(Table::new)
    }

    /// Counts the number of clusters matching the given conditions.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    pub fn count_clusters(
        &self,
        model: u32,
        categories: Option<&[i32]>,
        detectors: Option<&[i32]>,
        qualifiers: Option<&[i32]>,
        statuses: Option<&[i32]>,
    ) -> Result<usize> {
        let prefix = model.to_be_bytes();
        let iter = self.prefix_iter(Direction::Forward, None, &prefix);

        Ok(filter_cluster(iter, categories, detectors, qualifiers, statuses).count())
    }

    /// Updates the cluster with the given ID.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    pub fn update_cluster(
        &self,
        model_id: u32,
        id: i32,
        category: Option<i32>,
        qualifier: Option<i32>,
        status: Option<i32>,
    ) -> Result<()> {
        if category.is_none() && qualifier.is_none() && status.is_none() {
            return Err(anyhow!("no update fields provided"));
        }

        let key = Key {
            model_id,
            cluster_id: id,
        }
        .to_bytes();
        let Some(value) = self.map.get(&key)? else {
            bail!("cluster with model_id {model_id} and id {id} not found")
        };
        let mut entry: Cluster = FromKeyValue::from_key_value(&key, value.as_ref())?;
        if let Some(category) = category {
            entry.category_id = category;
        }
        if let Some(qualifier) = qualifier {
            entry.qualifier_id = qualifier;
        }
        if let Some(status) = status {
            entry.status_id = status;
        }

        entry.last_modification_time = Some(chrono::Utc::now().naive_utc());
        self.put(&entry)
    }

    /// Updates the clusters with the given cluster IDs. Retain only the top `max_event_id_num` event IDs per cluster.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    pub fn update_clusters(
        &self,
        updates: Vec<crate::UpdateClusterRequest>,
        model_id: u32,
        max_event_id_num: usize,
    ) -> Result<()> {
        let txn = self.map.db.transaction();
        let now = chrono::Utc::now().naive_utc();
        for mut update in updates {
            let key = Key {
                model_id,
                cluster_id: update.cluster_id,
            }
            .to_bytes();

            update
                .event_ids
                .sort_unstable_by_key(|(id, _)| Reverse(*id));

            let Some(value) = self.map.get(&key)? else {
                let (event_ids, sensors) =
                    update.event_ids.into_iter().take(max_event_id_num).unzip();

                let entry = Cluster {
                    model_id,
                    id: update.cluster_id,
                    category_id: 1, // default to "Uncategorized"
                    detector_id: update.detector_id,
                    event_ids,
                    sensors,
                    labels: update.labels,
                    qualifier_id: 1, // default to "Unqualified"
                    status_id: update.status_id,
                    signature: update.signature,
                    size: update.size,
                    score: update.score,
                    last_modification_time: Some(now),
                };
                self.insert_with_transaction(&entry, &txn)?;
                continue;
            };
            let mut entry: Cluster = FromKeyValue::from_key_value(&key, value.as_ref())?;

            let mut event_ids: Vec<_> = entry
                .event_ids
                .iter()
                .zip(entry.sensors.iter())
                .chain(update.event_ids.iter().map(|item| (&item.0, &item.1)))
                .collect();
            event_ids.sort_unstable_by_key(|(id, _)| Reverse(**id));
            let (event_ids, sensors): (Vec<_>, Vec<_>) = event_ids
                .into_iter()
                .take(max_event_id_num)
                .map(|item| (*item.0, item.1.clone()))
                .unzip();

            entry.event_ids = event_ids;
            entry.sensors = sensors;

            entry.status_id = update.status_id;

            if let Some(labels) = update.labels {
                entry.labels = Some(labels);
            }

            entry.signature = update.signature;

            entry.size += update.size;

            if let Some(score) = update.score {
                entry.score = Some(score);
            }
            entry.last_modification_time = Some(now);
            self.put_with_transaction(&entry, &txn)?;
        }
        Ok(txn.commit()?)
    }

    /// Returns the clusters that satisfy the given conditions.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    #[allow(clippy::too_many_arguments)]
    pub fn load_clusters(
        &self,
        model: u32,
        categories: Option<&[i32]>,
        detectors: Option<&[i32]>,
        qualifiers: Option<&[i32]>,
        statuses: Option<&[i32]>,
        after: &Option<(i32, i64)>,
        before: &Option<(i32, i64)>,
        is_first: bool,
        limit: usize,
    ) -> Result<Vec<Cluster>> {
        let prefix = model.to_be_bytes();
        let direction = Direction::Forward;
        let iter = self.prefix_iter(direction, None, &prefix);
        let mut clusters = filter_cluster(iter, categories, detectors, qualifiers, statuses)
            .filter(|c| {
                if let Some((id, size)) = after
                    && is_first
                {
                    return c.size < *size || (c.id < *id && c.size == *size);
                }
                if let Some((id, size)) = before
                    && !is_first
                {
                    return c.size > *size || (c.id > *id && c.size == *size);
                }
                true
            })
            .take(limit)
            .collect::<Vec<_>>();
        if is_first {
            clusters.sort_unstable_by_key(|c| (std::cmp::Reverse(c.size), std::cmp::Reverse(c.id)));
        } else {
            clusters.sort_unstable_by_key(|c| (c.size, c.id));
        }
        Ok(clusters)
    }
}

fn filter_cluster(
    iter: TableIter<'_, Cluster>,
    categories: Option<&[i32]>,
    detectors: Option<&[i32]>,
    qualifiers: Option<&[i32]>,
    statuses: Option<&[i32]>,
) -> impl Iterator<Item = Cluster> {
    iter.filter_map(move |res| {
        let cluster = res.ok()?;
        if let Some(categories) = categories
            && !categories.contains(&cluster.category_id)
        {
            return None;
        }
        if let Some(detectors) = detectors
            && !detectors.contains(&cluster.detector_id)
        {
            return None;
        }
        if let Some(qualifiers) = qualifiers
            && !qualifiers.contains(&cluster.qualifier_id)
        {
            return None;
        }
        if let Some(statuses) = statuses
            && !statuses.contains(&cluster.status_id)
        {
            return None;
        }
        Some(cluster)
    })
}

#[derive(Deserialize, Serialize)]
struct Value {
    category_id: i32,
    detector_id: i32,
    event_ids: Vec<i64>,
    sensors: Vec<String>,
    labels: Option<Vec<String>>,
    qualifier_id: i32,
    status_id: i32,
    signature: String,
    size: i64,
    score: Option<f64>,
    last_modification_time: Option<NaiveDateTime>,
}

impl ValueTrait for Cluster {
    type AsBytes<'a> = Vec<u8>;

    fn value(&self) -> Vec<u8> {
        super::serialize(&Value {
            category_id: self.category_id,
            detector_id: self.detector_id,
            event_ids: self.event_ids.clone(),
            sensors: self.sensors.clone(),
            labels: self.labels.clone(),
            qualifier_id: self.qualifier_id,
            status_id: self.status_id,
            signature: self.signature.clone(),
            size: self.size,
            score: self.score,
            last_modification_time: self.last_modification_time,
        })
        .expect("serializable")
    }
}
struct Key {
    model_id: u32,
    cluster_id: i32,
}

impl FromKeyValue for Cluster {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let key = Key::from_be_bytes(key);

        let value: Value = super::deserialize(value)?;

        Ok(Self {
            model_id: key.model_id,
            id: key.cluster_id,
            category_id: value.category_id,
            detector_id: value.detector_id,
            event_ids: value.event_ids,
            sensors: value.sensors,
            labels: value.labels,
            qualifier_id: value.qualifier_id,
            status_id: value.status_id,
            signature: value.signature,
            size: value.size,
            score: value.score,
            last_modification_time: value.last_modification_time,
        })
    }
}

impl UniqueKey for Cluster {
    type AsBytes<'a> = Vec<u8>;

    fn unique_key(&self) -> Vec<u8> {
        Key {
            model_id: self.model_id,
            cluster_id: self.id,
        }
        .to_bytes()
    }
}

impl Key {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let capacity = size_of::<u32>() + size_of::<i32>();

        let mut buf = Vec::with_capacity(capacity);
        buf.extend(self.model_id.to_be_bytes());
        buf.extend(self.cluster_id.to_be_bytes());

        buf
    }

    pub fn from_be_bytes(buf: &[u8]) -> Self {
        let (val, rest) = buf.split_at(size_of::<u32>());
        let mut buf = [0; size_of::<u32>()];
        buf.copy_from_slice(val);
        let model_id = u32::from_be_bytes(buf);

        let mut buf = [0; size_of::<i32>()];
        buf.copy_from_slice(rest);
        let cluster_id = i32::from_be_bytes(buf);

        Self {
            model_id,
            cluster_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::Store;
    use crate::test::{DbGuard, acquire_db_permit};

    #[test]
    fn test_key_bytes_roundtrip() {
        let key = Key {
            model_id: 123,
            cluster_id: 456,
        };
        let bytes = key.to_bytes();
        let decoded = Key::from_be_bytes(&bytes);

        assert_eq!(decoded.model_id, 123);
        assert_eq!(decoded.cluster_id, 456);
    }

    #[test]
    fn test_unique_key_matches_key_bytes() {
        let cluster = Cluster {
            model_id: 7,
            id: 99,
            category_id: 2,
            detector_id: 3,
            event_ids: vec![1, 2, 3],
            sensors: vec!["s1".to_string(), "s2".to_string()],
            labels: Some(vec!["a".to_string(), "b".to_string()]),
            qualifier_id: 5,
            status_id: 6,
            signature: "sig".to_string(),
            size: 42,
            score: Some(0.75),
            last_modification_time: None,
        };

        let unique = cluster.unique_key();
        let expected = Key {
            model_id: cluster.model_id,
            cluster_id: cluster.id,
        }
        .to_bytes();

        assert_eq!(unique, expected);
    }

    #[test]
    fn test_value_and_from_key_value_roundtrip() -> anyhow::Result<()> {
        // Create a cluster with None last_modification_time to make equality simple.
        let original = Cluster {
            model_id: 1,
            id: 2,
            category_id: 10,
            detector_id: 20,
            event_ids: vec![1001, 1002],
            sensors: vec!["src1".into(), "src2".into()],
            labels: None,
            qualifier_id: 3,
            status_id: 4,
            signature: "abcdef".into(),
            size: 1234,
            score: Some(9.87),
            last_modification_time: None,
        };

        // Serialize key + value (value uses Cluster::value via ValueTrait impl).
        let key_bytes = Key {
            model_id: original.model_id,
            cluster_id: original.id,
        }
        .to_bytes();

        let value_bytes = original.value();

        // Now deserialize using FromKeyValue::from_key_value
        let decoded = Cluster::from_key_value(&key_bytes, &value_bytes)?;

        // They should be equal
        assert_eq!(decoded.model_id, original.model_id);
        assert_eq!(decoded.id, original.id);
        assert_eq!(decoded.category_id, original.category_id);
        assert_eq!(decoded.detector_id, original.detector_id);
        assert_eq!(decoded.event_ids, original.event_ids);
        assert_eq!(decoded.sensors, original.sensors);
        assert_eq!(decoded.labels, original.labels);
        assert_eq!(decoded.qualifier_id, original.qualifier_id);
        assert_eq!(decoded.status_id, original.status_id);
        assert_eq!(decoded.signature, original.signature);
        assert_eq!(decoded.size, original.size);
        assert_eq!(decoded.score, original.score);
        assert_eq!(
            decoded.last_modification_time,
            original.last_modification_time
        );

        Ok(())
    }

    #[test]
    fn test_value_with_last_modification_time_roundtrip() -> anyhow::Result<()> {
        // Verify last_modification_time serializes & deserializes correctly too.
        let ts = chrono::DateTime::from_timestamp(1_600_000_000, 0).map(|dt| dt.naive_utc());
        let original = Cluster {
            model_id: 11,
            id: 22,
            category_id: 33,
            detector_id: 44,
            event_ids: vec![9],
            sensors: vec!["x".into()],
            labels: Some(vec!["lbl".into()]),
            qualifier_id: 55,
            status_id: 66,
            signature: "sig2".into(),
            size: 777,
            score: None,
            last_modification_time: ts,
        };

        let key_bytes = Key {
            model_id: original.model_id,
            cluster_id: original.id,
        }
        .to_bytes();
        let value_bytes = original.value();
        let decoded = Cluster::from_key_value(&key_bytes, &value_bytes)?;

        assert_eq!(decoded.last_modification_time, ts);
        assert_eq!(decoded, original);
        Ok(())
    }

    #[test]
    fn test_insert_and_count_clusters() {
        let (_permit, store) = setup_store();
        let table = store.cluster_map();

        // Insert 3 clusters
        let c1 = make_cluster(1, 1);
        let c2 = make_cluster(1, 2);
        let c3 = make_cluster(1, 3);
        table.insert(&c1).unwrap();
        table.insert(&c2).unwrap();
        table.insert(&c3).unwrap();

        // Count all clusters for model 1
        let count = table.count_clusters(1, None, None, None, None).unwrap();
        assert_eq!(count, 3);

        // Count with a filter that excludes everything
        let count = table
            .count_clusters(1, Some(&[99]), None, None, None)
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_update_cluster_fields() {
        let (_permit, store) = setup_store();
        let table = store.cluster_map();

        let mut c1 = make_cluster(1, 42);
        c1.category_id = 10;
        table.insert(&c1).unwrap();

        // Update cluster’s category, qualifier, and status
        table
            .update_cluster(1, 42, Some(20), Some(30), Some(40))
            .unwrap();

        let loaded = table
            .load_clusters(1, None, None, None, None, &None, &None, true, 10)
            .unwrap();
        assert_eq!(loaded.len(), 1);
        let updated = &loaded[0];
        assert_eq!(updated.category_id, 20);
        assert_eq!(updated.qualifier_id, 30);
        assert_eq!(updated.status_id, 40);
        assert!(updated.last_modification_time.is_some());
    }

    #[test]
    fn test_update_clusters_insert_and_merge() {
        let (_permit, store) = setup_store();
        let table = store.cluster_map();

        // Case 1: cluster doesn’t exist → should insert
        let req = crate::UpdateClusterRequest {
            cluster_id: 7,
            detector_id: 77,
            event_ids: vec![(123, "sX".into()), (456, "sY".into())],
            labels: Some(vec!["lbl".into()]),
            status_id: 5,
            signature: "new-sig".into(),
            size: 10,
            score: Some(0.5),
        };
        table.update_clusters(vec![req], 1, 2).unwrap();

        let inserted = table
            .load_clusters(1, None, None, None, None, &None, &None, true, 10)
            .unwrap();
        assert_eq!(inserted.len(), 1);
        assert_eq!(inserted[0].id, 7);
        assert_eq!(inserted[0].detector_id, 77);
        assert_eq!(inserted[0].event_ids.len(), 2);

        // Case 2: updating same cluster → should merge event_ids/sensors
        let req2 = crate::UpdateClusterRequest {
            cluster_id: 7,
            detector_id: 77,
            event_ids: vec![(123, "sX".into()), (999, "sZ".into())], // 123 is dup
            labels: None,
            status_id: 9,
            signature: "merged-sig".into(),
            size: 5,
            score: None,
        };
        table.update_clusters(vec![req2], 1, 1).unwrap();

        let merged = table
            .load_clusters(1, None, None, None, None, &None, &None, true, 10)
            .unwrap();
        assert_eq!(merged.len(), 1);
        let c = &merged[0];
        assert_eq!(c.status_id, 9);
        assert_eq!(c.event_ids, vec![999]);
        assert!(c.sensors.contains(&"sZ".to_string()));
        assert_eq!(c.size, 15); // 10 + 5
        assert_eq!(c.signature, "merged-sig");
    }

    #[test]
    fn test_load_clusters_pagination() {
        let (_permit, store) = setup_store();
        let table = store.cluster_map();

        for i in 0..5 {
            let mut c = make_cluster(1, i);
            c.size = i64::from(i * 10);
            table.insert(&c).unwrap();
        }

        // Load with limit
        let loaded = table
            .load_clusters(1, None, None, None, None, &None, &None, true, 3)
            .unwrap();
        assert_eq!(loaded.len(), 3);

        // Pagination using `after` (simulate cursor)
        let after = Some((2, 20)); // after cluster id=2 size=20
        let next = table
            .load_clusters(1, None, None, None, None, &after, &None, true, 10)
            .unwrap();
        for c in next {
            assert!(c.size < 20 || (c.id < 2 && c.size == 20));
        }
    }

    fn make_cluster(model_id: u32, cluster_id: i32) -> Cluster {
        Cluster {
            model_id,
            id: cluster_id,
            category_id: 1,
            detector_id: 1,
            event_ids: vec![10, 20],
            sensors: vec!["s1".into()],
            labels: Some(vec!["l1".into()]),
            qualifier_id: 1,
            status_id: 1,
            signature: format!("sig-{cluster_id}"),
            size: 100,
            score: Some(1.0),
            last_modification_time: None,
        }
    }

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        (permit, store)
    }
}
