use std::borrow::Cow;

use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use super::UniqueKey;
#[cfg(test)]
use crate::IndexedMapUpdate;
use crate::{
    EXCLUSIVE, Indexable, IndexedMap, IndexedTable, Iterable, collections::Indexed,
    types::FromKeyValue,
};

/// The record of a model: what the model is, who owns it, and which training
/// produced its current and previous classifiers.
///
/// A record is created, given a new classifier and removed only through
/// [`Store::complete_run`](crate::Store::complete_run),
/// [`Store::replace_model`](crate::Store::replace_model),
/// [`Store::update_model`](crate::Store::update_model) and
/// [`Store::delete_model`](crate::Store::delete_model), which keep it, the
/// model's per-model records and its classifier files consistent.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Model {
    pub id: u32,
    pub name: String,
    pub version: i32,
    /// The clustering method.
    pub kind: String,
    pub max_event_id_num: i32,
    pub classification_id: Option<i64>,
    /// The Giganto event kind the model was trained on, such as `http`, a
    /// Sysmon kind or a log kind.
    pub event_kind: String,
    /// The customer the model belongs to.
    pub customer_id: u32,
    /// The engine instance the model belongs to; `None` is the model's "no
    /// instance" state, `Some` its ready state.
    pub instance: Option<ModelInstance>,
    /// When the run that produced the current classifier succeeded.
    pub trained_at: DateTime<Utc>,
    /// The generation of the current classifier file.
    pub classifier_generation: u64,
    /// The id of the run that produced the current classifier.
    pub trained_run_id: u32,
    /// The exact training definition text of the run that produced the
    /// current classifier. It is a snapshot that changes only on replace,
    /// and nothing in this crate parses it.
    pub trained_definition: String,
    /// The summary of the previous training result, `None` until the first
    /// replace. It is also the previous result's existence marker: a model
    /// whose `previous` is `None` has no rows in
    /// [`Store::previous_training_results`](crate::Store::previous_training_results).
    pub previous: Option<PreviousTraining>,
    /// The `classification_id` whose cluster updates were last applied by
    /// [`Store::update_clusters`](crate::Store::update_clusters).
    pub clusters_applied: Option<i64>,
    /// The `sources` of the training definition of the run that produced
    /// the current classifier, a snapshot taken with `trained_definition`.
    /// A timeseries model's sources are sampling-policy IDs, and naming one
    /// here keeps that policy in use.
    pub trained_sources: Vec<String>,
}

/// The engine instance a model belongs to, named as the agents table keys an
/// `Agent`: its node id, then its key.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ModelInstance {
    pub node_id: u32,
    pub agent_key: String,
}

/// The owner a model is created for, and which a replace of it must match.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelOwner {
    pub customer_id: u32,
    pub instance: ModelInstance,
}

/// The run that produced a classifier, and that run's exact training
/// definition text and sources.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrainedWith {
    pub run_id: u32,
    pub definition: String,
    /// The `sources` of the run's training definition.
    pub sources: Vec<String>,
}

/// The outcome of [`Store::replace_model`](crate::Store::replace_model).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplacedModel {
    /// The id of the model inserted or replaced.
    pub id: u32,
    /// `true` if no model of that name existed and one was inserted.
    pub inserted: bool,
}

/// The summary of a model's previous training result, with the snapshot of
/// the definition that trained it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreviousTraining {
    pub trained_at: DateTime<Utc>,
    pub version: i32,
    pub classifier_generation: u64,
    pub trained_run_id: u32,
    pub trained_definition: String,
}

/// Functions for the `model` indexed map.
impl<'d> IndexedTable<'d, Model> {
    /// Opens the `model` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        IndexedMap::new(db, super::MODELS)
            .map(IndexedTable::new)
            .ok()
    }

    /// Updates the `Model` from `old` to `new`, given `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `id` is invalid or the database operation fails.
    #[cfg(test)]
    pub(crate) fn update(&mut self, id: u32, old: &Update, new: &Update) -> Result<()> {
        self.indexed_map.update(id, old, new)
    }

    /// Adds a new model to the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the model already exists or if a database operation fails.
    #[cfg(test)]
    pub(crate) fn add_model(&self, model: Model) -> Result<u32> {
        self.indexed_map.insert(model)
    }

    /// Adds a new model within a transaction and returns its id.
    ///
    /// # Errors
    ///
    /// Returns an error if the model already exists or if a database operation fails.
    pub(crate) fn add_model_with_transaction(
        &self,
        model: Model,
        txn: &rocksdb::Transaction<OptimisticTransactionDB>,
    ) -> Result<u32> {
        self.indexed_map.insert_with_transaction(model, txn)
    }

    /// Deletes the model with the given name.
    ///
    /// # Errors
    ///
    /// Returns an error if the model does not exist or if a database operation fails.
    #[cfg(test)]
    pub(crate) fn delete_model(&self, name: &str) -> Result<u32> {
        let model: Model = self.load_model_by_name(name)?;
        self.indexed_map.remove::<Model>(model.id)?;
        Ok(model.id)
    }

    /// Removes the model with the given id within a transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the model does not exist or if a database operation fails.
    pub(crate) fn remove_model_with_transaction(
        &self,
        id: u32,
        txn: &rocksdb::Transaction<OptimisticTransactionDB>,
    ) -> Result<()> {
        self.indexed_map
            .remove_with_transaction::<Model>(id, txn)
            .map(|_| ())
    }

    /// Returns the number of models.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    pub fn count_models(&self) -> Result<usize> {
        self.count()
    }

    /// Returns the model with the given ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the model does not exist or if a database operation fails.
    pub fn load_model(&self, id: u32) -> Result<Model> {
        self.get_by_id(id)?.ok_or(anyhow!("model not found"))
    }

    /// Returns the model with the given name.
    ///
    /// # Errors
    ///
    /// Returns an error if the model does not exist or if a database operation fails.
    pub fn load_model_by_name(&self, name: &str) -> Result<Model> {
        self.indexed_map
            .get_by_key(name.as_bytes())?
            .map(|r| super::deserialize(r.as_ref()))
            .transpose()?
            .ok_or(anyhow!("model not found"))
    }

    /// Returns the model with the given name, read within a transaction that
    /// the read then conflicts with.
    ///
    /// # Errors
    ///
    /// Returns an error if the name is empty or if a database operation fails.
    pub(crate) fn load_model_by_name_in_transaction(
        &self,
        name: &str,
        txn: &rocksdb::Transaction<OptimisticTransactionDB>,
    ) -> Result<Option<Model>> {
        if name.is_empty() {
            return Ok(None);
        }
        txn.get_for_update_cf(self.indexed_map.cf(), name.as_bytes(), EXCLUSIVE)?
            .map(|value| super::deserialize(&value))
            .transpose()
    }

    /// Returns every model record as `txn` sees it, ordered by name, skipping
    /// the index entry at the empty key.
    ///
    /// The scan is not tracked by `txn`: a record written after it does not
    /// conflict with the transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails or a record cannot be
    /// deserialized.
    pub(crate) fn scan(
        &self,
        txn: &rocksdb::Transaction<OptimisticTransactionDB>,
    ) -> Result<Vec<Model>> {
        txn.iterator_cf(self.indexed_map.cf(), rocksdb::IteratorMode::Start)
            .filter_map(|entry| match entry {
                Ok((key, _)) if key.is_empty() => None,
                Ok((_, value)) => Some(super::deserialize(&value)),
                Err(e) => Some(Err(anyhow!("cannot read models: {e}"))),
            })
            .collect()
    }

    /// Returns the model with the given name as `snapshot` holds it.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    pub(crate) fn load_model_by_name_in_snapshot(
        &self,
        name: &str,
        snapshot: &rocksdb::SnapshotWithThreadMode<'_, OptimisticTransactionDB>,
    ) -> Result<Option<Model>> {
        if name.is_empty() {
            return Ok(None);
        }
        snapshot
            .get_cf(self.indexed_map.cf(), name.as_bytes())?
            .map(|value| super::deserialize(&value))
            .transpose()
    }

    /// Returns the models between `after` and `before`.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    pub fn load_models(
        &self,
        after: &Option<(u32, String)>,
        before: &Option<(u32, String)>,
        is_first: bool,
        limit: usize,
    ) -> Result<Vec<Model>> {
        let (direction, from) = if is_first {
            (
                rocksdb::Direction::Forward,
                after.as_ref().map(|(_id, name)| name.as_bytes()),
            )
        } else {
            (
                rocksdb::Direction::Reverse,
                before.as_ref().map(|(_id, name)| name.as_bytes()),
            )
        };
        let iter = self.iter(direction, from);
        iter.filter_map(|res| {
            res.map(|model| {
                if let Some((id, name)) = after
                    && model.id <= *id
                    && model.name.as_bytes() <= name.as_bytes()
                {
                    return None;
                }
                if let Some((id, name)) = before
                    && model.id >= *id
                    && model.name.as_bytes() >= name.as_bytes()
                {
                    return None;
                }
                Some(model)
            })
            .transpose()
        })
        .take(limit)
        .collect()
    }

    /// Replaces the model with the given id, as stored, by `model`.
    ///
    /// # Errors
    ///
    /// Returns an error if the model does not exist or if a database operation fails.
    #[cfg(test)]
    pub(crate) fn update_model(&mut self, model: &Model) -> Result<u32> {
        let old = self.load_model(model.id)?;
        self.update(model.id, &Update::from(&old), &Update::from(model))?;
        Ok(model.id)
    }

    /// Replaces the stored record `old` by `new` within a transaction.
    ///
    /// `old` must be the record as `txn` read it for update with
    /// [`load_model_by_name_in_transaction`](Self::load_model_by_name_in_transaction).
    /// The record is not read again: a change committed since that read
    /// makes `txn` conflict at its commit, so the caller's retry loop starts
    /// over, rather than failing here with an error no loop retries. The id
    /// and name do not change, so neither do the record's key and the index.
    ///
    /// # Errors
    ///
    /// Returns an error if `new` has another id or name, or if a database
    /// operation fails.
    pub(crate) fn update_model_with_transaction(
        &self,
        old: &Model,
        new: &Model,
        txn: &rocksdb::Transaction<OptimisticTransactionDB>,
    ) -> Result<()> {
        if old.id != new.id || old.name != new.name {
            return Err(anyhow!("a model's id and name do not change"));
        }
        txn.put_cf(self.indexed_map.cf(), new.name.as_bytes(), new.value())
            .map_err(Into::into)
    }
}

impl FromKeyValue for Model {
    fn from_key_value(_key: &[u8], value: &[u8]) -> Result<Self> {
        super::deserialize(value)
    }
}

impl UniqueKey for Model {
    type AsBytes<'a> = &'a [u8];

    fn unique_key(&self) -> &[u8] {
        self.name.as_bytes()
    }
}

impl Indexable for Model {
    fn key(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.name.as_bytes())
    }
    fn index(&self) -> u32 {
        self.id
    }
    fn make_indexed_key(key: Cow<[u8]>, _index: u32) -> Cow<[u8]> {
        key
    }
    fn value(&self) -> Vec<u8> {
        super::serialize(self).expect("serializable")
    }

    fn set_index(&mut self, index: u32) {
        self.id = index;
    }
}

/// A whole-record update of a model, for the tests' `update_model`: as
/// `old`, it matches only the record it was taken from; as `new`, it
/// replaces every field but the id.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct Update(Model);

#[cfg(test)]
impl From<&Model> for Update {
    fn from(model: &Model) -> Self {
        Self(model.clone())
    }
}

#[cfg(test)]
impl IndexedMapUpdate for Update {
    type Entry = Model;

    fn key(&self) -> Option<Cow<'_, [u8]>> {
        Some(Cow::Borrowed(self.0.name.as_bytes()))
    }

    fn apply(&self, value: Self::Entry) -> Result<Self::Entry, anyhow::Error> {
        Ok(Model {
            id: value.id,
            ..self.0.clone()
        })
    }

    fn verify(&self, value: &Self::Entry) -> bool {
        self.0 == *value
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
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path(), None).unwrap());
        (permit, store)
    }

    fn make_model(name: &str, version: i32) -> Model {
        Model {
            id: 0, // will be set by insert
            name: name.to_string(),
            version,
            kind: "test-kind".to_string(),
            max_event_id_num: 100,
            classification_id: None,
            event_kind: "http".to_string(),
            customer_id: 7,
            instance: Some(ModelInstance {
                node_id: 1,
                agent_key: "unsupervised@host".to_string(),
            }),
            trained_at: chrono::DateTime::from_timestamp(1_700_000_000, 123).unwrap(),
            classifier_generation: 1,
            trained_run_id: 9,
            trained_definition: "eps = 5.0".to_string(),
            previous: None,
            clusters_applied: None,
            trained_sources: vec!["3".to_string()],
        }
    }

    #[test]
    fn test_add_and_load_model() {
        let (_permit, store) = setup_store();
        let table = store.model_map();
        let model = make_model("alpha", 1);

        let id = table.add_model(model.clone()).unwrap();
        assert_eq!(id, 0);

        let loaded = table.load_model(id).unwrap();
        assert_eq!(loaded.name, "alpha");
        assert_eq!(loaded.version, 1);

        let loaded_by_name = table.load_model_by_name("alpha").unwrap();
        assert_eq!(loaded_by_name.id, id);

        // Every field of the record round-trips.
        assert_eq!(loaded_by_name, Model { id, ..model });
    }

    #[test]
    fn test_count_models() {
        let (_permit, store) = setup_store();
        let table = store.model_map();
        let m1 = make_model("m1", 1);
        let m2 = make_model("m2", 2);

        table.add_model(m1).unwrap();
        table.add_model(m2).unwrap();

        let count = table.count_models().unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_delete_model() {
        let (_permit, store) = setup_store();
        let table = store.model_map();
        let m = make_model("to-delete", 1);
        let id = table.add_model(m).unwrap();

        let deleted_id = table.delete_model("to-delete").unwrap();
        assert_eq!(deleted_id, id);

        let result = table.load_model(id);
        assert!(result.is_err(), "model should be deleted");
    }

    #[test]
    fn test_update_model() {
        let (_permit, store) = setup_store();
        let mut table = store.model_map();
        let mut m = make_model("beta", 1);
        let id = table.add_model(m.clone()).unwrap();

        // modify model
        m.id = id;
        m.version = 2;
        m.kind = "updated-kind".into();

        let updated_id = table.update_model(&m).unwrap();
        assert_eq!(updated_id, id);

        let loaded = table.load_model(id).unwrap();
        assert_eq!(loaded.version, 2);
        assert_eq!(loaded.kind, "updated-kind");
    }

    #[test]
    fn test_load_models_with_pagination() {
        let (_permit, store) = setup_store();
        let table = store.model_map();

        let m1 = make_model("a", 1);
        let m2 = make_model("b", 1);
        let m3 = make_model("c", 1);

        let id1 = table.add_model(m1).unwrap();
        let id2 = table.add_model(m2).unwrap();
        let id3 = table.add_model(m3).unwrap();

        assert!(id1 < id2 && id2 < id3);

        // Forward pagination
        let after = Some((id1, "a".to_string()));
        let results = table.load_models(&after, &None, true, 10).unwrap();
        assert!(results.iter().all(|m| m.name != "a"));
        assert!(results.iter().any(|m| m.name == "b"));

        // Reverse pagination
        let before = Some((id3, "c".to_string()));
        let results = table.load_models(&None, &before, false, 10).unwrap();
        assert!(results.iter().all(|m| m.name != "c"));
        assert!(results.iter().any(|m| m.name == "b"));

        // Limit
        let results = table.load_models(&None, &None, true, 2).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_update_apply_and_verify() {
        let mut m = make_model("verify", 1);
        m.id = 123;

        let mut changed = m.clone();
        changed.id = 0;
        changed.version = 2;
        changed.max_event_id_num = 200;
        changed.classification_id = Some(5);
        let update = Update::from(&changed);

        let applied = update.apply(m.clone()).unwrap();
        assert_eq!(applied.id, 123, "the id is kept");
        assert_eq!(applied.version, 2);
        assert_eq!(applied.max_event_id_num, 200);
        assert_eq!(applied.classification_id, Some(5));

        assert!(Update::from(&m).verify(&m));
        assert!(!Update::from(&m).verify(&applied)); // a changed record doesn't match
    }

    #[test]
    fn a_record_changed_after_the_read_makes_the_update_conflict_at_commit() {
        let (_permit, store) = setup_store();
        let table = store.model_map();
        table.add_model(make_model("gamma", 1)).unwrap();

        let txn = store.states.db().transaction();
        let read = table
            .load_model_by_name_in_transaction("gamma", &txn)
            .unwrap()
            .unwrap();

        // A run completing between the read and the write.
        let completing = store.states.db().transaction();
        let stored = table
            .load_model_by_name_in_transaction("gamma", &completing)
            .unwrap()
            .unwrap();
        let completed = Model {
            classifier_generation: 2,
            trained_run_id: 10,
            ..stored.clone()
        };
        table
            .update_model_with_transaction(&stored, &completed, &completing)
            .unwrap();
        completing.commit().unwrap();

        let detached = Model {
            instance: None,
            ..read.clone()
        };
        table
            .update_model_with_transaction(&read, &detached, &txn)
            .unwrap();
        let error = txn.commit().unwrap_err();
        assert!(
            error.as_ref().starts_with("Resource busy:"),
            "a retryable conflict, not {error}"
        );
        assert_eq!(table.load_model_by_name("gamma").unwrap(), completed);
    }

    #[test]
    fn an_update_keeps_the_index() {
        let (_permit, store) = setup_store();
        let table = store.model_map();
        let id = table.add_model(make_model("gamma", 1)).unwrap();
        let old = table.load_model(id).unwrap();
        let new = Model {
            version: 2,
            ..old.clone()
        };

        let txn = store.states.db().transaction();
        table
            .update_model_with_transaction(&old, &new, &txn)
            .unwrap();
        txn.commit().unwrap();

        assert_eq!(table.load_model(id).unwrap(), new);
        assert_eq!(table.load_model_by_name("gamma").unwrap(), new);
        assert_eq!(table.add_model(make_model("delta", 1)).unwrap(), id + 1);
    }

    #[test]
    fn test_update_with_transaction_refuses_renaming() {
        let (_permit, store) = setup_store();
        let table = store.model_map();
        let id = table.add_model(make_model("gamma", 1)).unwrap();
        let old = table.load_model(id).unwrap();
        let mut renamed = old.clone();
        renamed.name = "delta".to_string();

        let txn = store.states.db().transaction();
        assert!(
            table
                .update_model_with_transaction(&old, &renamed, &txn)
                .is_err()
        );
    }
}
