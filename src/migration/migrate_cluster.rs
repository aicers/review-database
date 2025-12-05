use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::Result;
use chrono::{Datelike, Timelike};
use serde::Deserialize;

use crate::Database;
use crate::tables::Cluster;

pub(crate) async fn run(database: &Database, store: &crate::Store) -> Result<()> {
    let models = super::migrate_time_series::retrieve_model_to_migrate(database).await?;
    update_cluster_id_in_column_stats(database, store).await?;
    for &model in &models {
        migrate_clusters_for_model(database, store, model).await?;
        remove_clusters(database, model).await?;
    }
    Ok(())
}

async fn remove_clusters(database: &Database, model: u32) -> Result<()> {
    use diesel::ExpressionMethods;
    use diesel_async::RunQueryDsl;

    use crate::diesel::QueryDsl;
    use crate::schema::cluster::dsl;
    let mut conn = database.pool.get().await?;
    let model_i32 = i32::try_from(model)?;
    diesel::delete(dsl::cluster.filter(dsl::model_id.eq(model_i32)))
        .execute(&mut conn)
        .await?;
    Ok(())
}

#[derive(Deserialize)]
enum ElementV41 {
    Int(i64),
    UInt(u64),
    Enum(String),
    Float(f64),
    FloatRange(structured::FloatRange),
    Text(String),
    Binary(Vec<u8>),
    IpAddr(IpAddr),
    DateTime(chrono::NaiveDateTime),
}

#[derive(Deserialize)]
struct ElementCountV41 {
    value: ElementV41,
    count: usize,
}

#[derive(Deserialize)]
struct DescriptonV41 {
    count: usize,
    mean: Option<f64>,
    s_deviation: Option<f64>,
    min: Option<ElementV41>,
    max: Option<ElementV41>,
}

impl TryFrom<ElementV41> for structured::Element {
    type Error = anyhow::Error;

    fn try_from(value: ElementV41) -> Result<Self, Self::Error> {
        use jiff::civil::{DateTime, date, time};
        match value {
            ElementV41::Int(e) => Ok(structured::Element::Int(e)),
            ElementV41::UInt(e) => Ok(structured::Element::UInt(e)),
            ElementV41::Enum(e) => Ok(structured::Element::Enum(e)),
            ElementV41::Float(e) => Ok(structured::Element::Float(e)),
            ElementV41::FloatRange(e) => Ok(structured::Element::FloatRange(e)),
            ElementV41::Text(e) => Ok(structured::Element::Text(e)),
            ElementV41::Binary(e) => Ok(structured::Element::Binary(e)),
            ElementV41::IpAddr(e) => Ok(structured::Element::IpAddr(e)),
            ElementV41::DateTime(dt) => {
                let date = date(
                    i16::try_from(dt.year())?,
                    i8::try_from(dt.month())?,
                    i8::try_from(dt.day())?,
                );
                let time = time(
                    i8::try_from(dt.hour())?,
                    i8::try_from(dt.minute())?,
                    i8::try_from(dt.second())?,
                    i32::try_from(dt.nanosecond())?,
                );

                let e = DateTime::from_parts(date, time);

                Ok(structured::Element::DateTime(e))
            }
        }
    }
}

impl TryFrom<DescriptonV41> for structured::Description {
    type Error = anyhow::Error;
    fn try_from(value: DescriptonV41) -> Result<Self, Self::Error> {
        Ok(structured::Description::new(
            value.count,
            value.mean,
            value.s_deviation,
            value.min.map(TryInto::try_into).transpose()?,
            value.max.map(TryInto::try_into).transpose()?,
        ))
    }
}

#[derive(Deserialize)]
struct NLargestCountV41 {
    number_of_elements: usize,
    top_n: Vec<ElementCountV41>,
    mode: Option<ElementV41>,
}

impl TryFrom<NLargestCountV41> for structured::NLargestCount {
    type Error = anyhow::Error;
    fn try_from(value: NLargestCountV41) -> Result<Self, Self::Error> {
        let top_n: Vec<_> = value
            .top_n
            .into_iter()
            .map(|ec| {
                Ok::<_, anyhow::Error>(structured::ElementCount {
                    value: ec.value.try_into()?,
                    count: ec.count,
                })
            })
            .collect::<Result<_, anyhow::Error>>()?;
        Ok(structured::NLargestCount::new(
            value.number_of_elements,
            top_n,
            value.mode.map(TryInto::try_into).transpose()?,
        ))
    }
}

#[derive(Deserialize)]
struct ColumnStatsKeyV41 {
    pub cluster_id: u32,
    pub batch_ts: i64,
    pub column_index: u32,
    pub model_id: i32,
}

#[derive(Deserialize)]
struct ColumnStatsValueV41 {
    description: DescriptonV41,
    n_largest_count: NLargestCountV41,
}

impl TryFrom<(ColumnStatsKeyV41, ColumnStatsValueV41)> for crate::ColumnStats {
    type Error = anyhow::Error;
    fn try_from(
        (key, value): (ColumnStatsKeyV41, ColumnStatsValueV41),
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            model_id: u32::try_from(key.model_id)?,
            cluster_id: key.cluster_id,
            batch_ts: key.batch_ts,
            column_index: key.column_index,
            description: value.description.try_into()?,
            n_largest_count: value.n_largest_count.try_into()?,
        })
    }
}

async fn update_cluster_id_in_column_stats(
    database: &Database,
    store: &crate::Store,
) -> Result<()> {
    use diesel_async::RunQueryDsl;

    use crate::diesel::QueryDsl;
    use crate::schema::cluster::dsl as c_d;

    let mut conn = database.pool.get().await?;

    let cluster_ids: HashMap<u32, u32> = c_d::cluster
        .select((c_d::id, c_d::cluster_id))
        .load::<(i32, i32)>(&mut conn)
        .await?
        .into_iter()
        .map(|(id, cid)| Ok((u32::try_from(id)?, u32::try_from(cid)?)))
        .collect::<Result<_, anyhow::Error>>()?;
    let map = store.column_stats_map();
    let raw = map.raw();
    let mut updated = vec![];
    let iter = raw.db.iterator_cf(raw.cf, rocksdb::IteratorMode::Start);
    let txn = raw.db.transaction();
    for item in iter {
        let (old_key, old_value) = item?;
        let mut old_k: ColumnStatsKeyV41 = bincode::deserialize(&old_key)?;
        old_k.cluster_id = cluster_ids
            .get(&old_k.cluster_id)
            .copied()
            .ok_or(anyhow::anyhow!("Unable to find Cluster id"))?;
        let old_v: ColumnStatsValueV41 = bincode::deserialize(&old_value)?;
        let new: crate::ColumnStats = (old_k, old_v).try_into()?;
        updated.push(new);
        raw.delete_with_transaction(&old_key, &txn)?;
    }
    txn.commit()?;

    let txn = map.transaction();
    for c in updated {
        map.put_with_transaction(&c, &txn)?;
    }
    txn.commit()?;

    Ok(())
}

async fn migrate_clusters_for_model(
    database: &Database,
    store: &crate::Store,
    model: u32,
) -> Result<()> {
    let clusters = retrieve_cluster_to_migrate(database, model).await?;
    let map = store.cluster_map();
    let txn = map.transaction();
    for c in clusters {
        map.put_with_transaction(&c, &txn)?;
    }
    txn.commit()?;
    Ok(())
}

#[allow(deprecated)]
async fn retrieve_cluster_to_migrate(
    database: &Database,
    model: u32,
) -> Result<Vec<crate::Cluster>> {
    let model_i32 = i32::try_from(model)?;
    Ok(database
        .load_clusters(
            model_i32,
            None,
            None,
            None,
            None,
            &None,
            &None,
            false,
            usize::MAX,
        )
        .await?
        .into_iter()
        .map(|c| Cluster {
            model_id: model,
            id: c.id,
            category_id: c.category_id,
            detector_id: c.detector_id,
            event_ids: c.event_ids,
            labels: c.labels,
            last_modification_time: c.last_modification_time,
            qualifier_id: c.qualifier_id,
            score: c.score,
            signature: c.signature,
            size: c.size,
            status_id: c.status_id,
            sensors: c.sensors,
        })
        .collect())
}
