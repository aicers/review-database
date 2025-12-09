#![allow(deprecated)]
use chrono::NaiveDateTime;
use diesel::{BoolExpressionMethods, ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;
use serde::{Deserialize, Serialize};

use crate::{Database, Error, schema::cluster::dsl, types::Cluster};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpdateClusterRequest {
    pub cluster_id: i32,
    pub detector_id: i32,
    pub signature: String,
    pub score: Option<f64>,
    pub size: i64,
    pub event_ids: Vec<crate::types::Id>,
    pub status_id: i32,
    pub labels: Option<Vec<String>>,
}

#[derive(Queryable)]
struct ClusterDbSchema {
    id: i32,
    cluster_id: i32,
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
    model_id: i32,
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
            cluster_id: c.cluster_id.try_into().unwrap_or(0),
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
            model_id: c.model_id.try_into().unwrap_or(0),
        }
    }
}

impl Database {
    /// Counts the number of clusters matching the given conditions.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    #[deprecated(
        since = "0.41.0",
        note = "This function is no longer used and will be removed in a future version"
    )]
    pub async fn count_clusters(
        &self,
        model: i32,
        categories: Option<&[i32]>,
        detectors: Option<&[i32]>,
        qualifiers: Option<&[i32]>,
        statuses: Option<&[i32]>,
    ) -> Result<i64, Error> {
        let mut query = dsl::cluster.filter(dsl::model_id.eq(&model)).into_boxed();
        if let Some(categories) = categories {
            query = query.filter(dsl::category_id.eq_any(categories));
        }
        if let Some(detectors) = detectors {
            query = query.filter(dsl::detector_id.eq_any(detectors));
        }
        if let Some(qualifiers) = qualifiers {
            query = query.filter(dsl::qualifier_id.eq_any(qualifiers));
        }
        if let Some(statuses) = statuses {
            query = query.filter(dsl::status_id.eq_any(statuses));
        }

        let mut conn = self.pool.get().await?;
        Ok(query.count().get_result(&mut conn).await?)
    }

    /// Returns the clusters that satisfy the given conditions.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    #[allow(clippy::too_many_arguments)]
    #[deprecated(
        since = "0.41.0",
        note = "This function is no longer used and will be removed in a future version"
    )]
    pub async fn load_clusters(
        &self,
        model: i32,
        categories: Option<&[i32]>,
        detectors: Option<&[i32]>,
        qualifiers: Option<&[i32]>,
        statuses: Option<&[i32]>,
        after: &Option<(i32, i64)>,
        before: &Option<(i32, i64)>,
        is_first: bool,
        limit: i64,
    ) -> Result<Vec<Cluster>, Error> {
        let mut query = dsl::cluster
            .select((
                dsl::id,
                dsl::cluster_id,
                dsl::category_id,
                dsl::detector_id,
                dsl::event_ids,
                dsl::sensors,
                dsl::labels,
                dsl::qualifier_id,
                dsl::status_id,
                dsl::signature,
                dsl::size,
                dsl::score,
                dsl::last_modification_time,
                dsl::model_id,
            ))
            .filter(dsl::model_id.eq(&model))
            .limit(limit)
            .into_boxed();

        if let Some(categories) = categories {
            query = query.filter(dsl::category_id.eq_any(categories));
        }
        if let Some(detectors) = detectors {
            query = query.filter(dsl::detector_id.eq_any(detectors));
        }
        if let Some(qualifiers) = qualifiers {
            query = query.filter(dsl::qualifier_id.eq_any(qualifiers));
        }
        if let Some(statuses) = statuses {
            query = query.filter(dsl::status_id.eq_any(statuses));
        }
        if let Some(after) = after {
            query = query.filter(
                dsl::size
                    .eq(after.1)
                    .and(dsl::id.lt(after.0))
                    .or(dsl::size.lt(after.1)),
            );
        }
        if let Some(before) = before {
            query = query.filter(
                dsl::size
                    .eq(before.1)
                    .and(dsl::id.gt(before.0))
                    .or(dsl::size.gt(before.1)),
            );
        }
        if is_first {
            query = query
                .order_by(dsl::size.desc())
                .then_order_by(dsl::id.desc());
        } else {
            query = query.order_by(dsl::size.asc()).then_order_by(dsl::id.asc());
        }

        let mut conn = self.pool.get().await?;
        let rows = query.get_results::<ClusterDbSchema>(&mut conn).await?;
        if is_first {
            Ok(rows.into_iter().map(Into::into).collect())
        } else {
            Ok(rows.into_iter().rev().map(Into::into).collect())
        }
    }

    /// Find the numerical ids according to string ids of clusters for a model
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    #[deprecated(
        since = "0.41.0",
        note = "This function is no longer used and will be removed in a future version"
    )]
    pub async fn cluster_name_to_ids(
        &self,
        model_id: u32,
        names: &[i32],
    ) -> Result<Vec<(i32, i32)>, Error> {
        let model_id_i32 = i32::try_from(model_id)?;
        let query = dsl::cluster
            .select((dsl::id, dsl::cluster_id))
            .filter(dsl::model_id.eq(&model_id_i32))
            .filter(dsl::cluster_id.eq_any(names));
        let mut conn = self.pool.get().await?;
        Ok(query.get_results(&mut conn).await?)
    }
}
