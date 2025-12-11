use std::collections::{HashMap, HashSet};

use anyhow::Result;

use crate::Database;
use crate::tables::Model;

pub(crate) async fn run(database: &Database, store: &crate::Store) -> Result<()> {
    let models = retrieve_models(database).await?;
    if models.is_empty() {
        return Ok(());
    }
    insert_models(store, models)?;
    remove_all_models(database).await?;
    Ok(())
}

async fn remove_all_models(database: &Database) -> Result<()> {
    use diesel_async::RunQueryDsl;

    use crate::schema::model::dsl;
    let mut conn = database.pool.get().await?;
    diesel::delete(dsl::model).execute(&mut conn).await?;
    Ok(())
}

async fn retrieve_models(database: &Database) -> Result<Vec<Model>> {
    use diesel_async::RunQueryDsl;

    use crate::diesel::QueryDsl;
    use crate::schema::model::dsl;
    let mut conn = database.pool.get().await?;
    let query = dsl::model
        .select((
            dsl::id,
            dsl::name,
            dsl::version,
            dsl::kind,
            dsl::max_event_id_num,
            dsl::data_source_id,
            dsl::classification_id,
        ))
        .order_by(dsl::id);
    Ok(query
        .load(&mut conn)
        .await?
        .into_iter()
        .map(
            |(id, name, version, kind, max_event_id_num, data_source_id, classification_id): (
                i32,
                String,
                i32,
                String,
                i32,
                i32,
                Option<i64>,
            )| {
                Model {
                    id: u32::try_from(id).expect("Model id should be non-negative"),
                    name,
                    version,
                    kind,
                    max_event_id_num,
                    data_source_id,
                    classification_id,
                }
            },
        )
        .collect())
}

fn insert_models(store: &crate::Store, models: Vec<Model>) -> Result<()> {
    let mut map = store.model_map();
    if map.count()? > 0 {
        return Err(anyhow::anyhow!(
            "Model map is not empty. Aborting migration."
        ));
    }

    let models = models
        .into_iter()
        .map(|m| (m.id, m))
        .collect::<HashMap<_, _>>();
    let max_id = *models.keys().max().unwrap_or(&0);

    let dummy = Model {
        id: 0,
        name: String::new(),
        version: 0,
        kind: String::new(),
        max_event_id_num: 0,
        data_source_id: 0,
        classification_id: None,
    };

    let mut inserted = HashSet::new();
    for id in 0..=max_id {
        let mut ith = dummy.clone();
        ith.name = id.to_string();
        let ith = map.put(ith)?;
        inserted.insert(ith);
        if ith != id {
            for id in inserted {
                map.remove(id)?;
            }
            return Err(anyhow::anyhow!(
                "Model IDs are not continuous. Aborting migration."
            ));
        }
    }

    for (id, model) in models {
        map.update_model(&model)?;
        inserted.remove(&id);
    }
    for id in inserted {
        map.remove(id)?;
    }
    Ok(())
}
