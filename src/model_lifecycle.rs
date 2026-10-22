//! Models stored together with their per-model records and classifier files.
//!
//! A model is its record in the "models" column family, the rows keyed by its
//! id in the per-model column families and their previous-result mirrors, and
//! its classifier files under `classifiers/model_<id>/`, one per generation.
//! The record names the current generation and, in its `previous` summary,
//! the previous one. Everything here keeps the three consistent.
//!
//! # The model-files lock
//!
//! [`Store`] owns one mutex, the model-files lock. Every operation that reads
//! a model record and then writes or removes classifier files, or reads the
//! classifier file a record names, holds it from its first read of the record
//! through the file write, the transaction commit and the post-commit file
//! or directory removal. Callers' own locks are not relied on: review-web,
//! for one, holds only read guards on its shared `Store`. Without this lock,
//! two writers of one generation could leave a committed record pointing at
//! the losing writer's file, and, since ids are reused, a delete's directory
//! removal could remove the classifier of a model inserted under the id it
//! freed. A poisoned lock is taken as is: every guarded operation leaves the
//! store as a crash at the same point would, which the next operation already
//! handles.
//!
//! # Crash consistency
//!
//! A classifier is always written to a new file, of the generation after the
//! current one, before the transaction that makes the record name that
//! generation commits; the current file is never overwritten, and no file is
//! removed before the commit that stops referring to it. So:
//!
//! - A crash after the file write and before the commit (of a replace, or of
//!   an analysis round's `update_model`) leaves an unreferenced file of the
//!   next generation, which the retry overwrites; the record still names the
//!   earlier, intact file.
//! - A crash after the commit and before the post-commit removal leaves the
//!   earlier previous file (replace) or the earlier current file
//!   (`update_model`) behind, unreferenced.
//! - A crash after a delete's commit and before its directory removal leaves
//!   `classifiers/model_<id>/` with no record. The next model inserted under
//!   that id writes each generation's file, renaming over any leftover,
//!   before its record names it, so a leftover file is never read, and the
//!   directory goes with that model's delete.
//!
//! Leftovers of the first two kinds are likewise removed with the model's
//! directory on delete. A failure of a post-commit removal does not fail the
//! operation, whose commit has already taken effect: it is logged and leaves
//! the same leftovers a crash would.
//!
//! "Before the commit" and "after the commit" hold across a power loss only
//! because every transaction that is followed by a file removal is a
//! [`ModelTransaction`], whose commit returns once its write-ahead log entry
//! is on disk. With RocksDB's default unsynced writes, a power loss could
//! keep the removal and lose the commit, restoring a record whose classifier
//! file is gone.

use std::{
    ops::Deref,
    sync::{MutexGuard, PoisonError},
};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use rocksdb::{
    ColumnFamily, IteratorMode, OptimisticTransactionDB, OptimisticTransactionOptions, Transaction,
    WriteOptions,
};
use tracing::warn;

use crate::{
    BatchInfo, CsvColumnExtraConfig as CsvColumnExtra, EXCLUSIVE, IndexedMap, ModelIndicator,
    ModelOwner, PreviousTraining, PreviousTrainingResults, ReplacedModel, Scores, Store,
    TrainedWith, UniqueKey, UpdateClusterRequest, classifier_fs, collections::Indexed,
    model::ClusteringMethod, tables, types::FromKeyValue,
};

type Txn<'a> = Transaction<'a, OptimisticTransactionDB>;

/// The generation of a new model's first classifier.
const FIRST_GENERATION: u64 = 1;

/// The per-model column families whose keys start with the model id in
/// big-endian, each with the mirror holding the previous training result.
const ID_PREFIXED_FAMILIES: [(&str, &str); 5] = [
    (tables::BATCH_INFO, tables::PREVIOUS_BATCH_INFO),
    (tables::CLUSTER, tables::PREVIOUS_CLUSTER),
    (tables::COLUMN_STATS, tables::PREVIOUS_COLUMN_STATS),
    (tables::TIME_SERIES, tables::PREVIOUS_TIME_SERIES),
    (tables::OUTLIERS, tables::PREVIOUS_OUTLIERS),
];

/// Proof that the caller holds the model-files lock of `store`.
pub(crate) struct ModelFilesGuard<'a> {
    store: &'a Store,
    _guard: MutexGuard<'a, ()>,
}

impl ModelFilesGuard<'_> {
    /// Fails unless this guard holds the lock of `store`.
    fn check(&self, store: &Store) -> Result<()> {
        if std::ptr::eq(self.store, store) {
            Ok(())
        } else {
            Err(anyhow!("the model-files lock held is not this store's"))
        }
    }
}

/// A transaction whose commit is on disk when it returns.
///
/// Every transaction after whose commit a classifier file or directory is
/// removed is one of these, the one a caller of
/// [`Store::replace_model_with_transaction`] commits included: the removal
/// must never reach disk without the commit that stopped referring to the
/// file. It can be created only by [`Store::model_transaction`].
pub(crate) struct ModelTransaction<'a>(Txn<'a>);

impl ModelTransaction<'_> {
    /// Commits the transaction, returning `Ok(false)` if it conflicted with a
    /// concurrent write and has to be retried.
    pub(crate) fn commit_or_retry(self) -> Result<bool> {
        commit_or_retry(self.0)
    }
}

impl<'a> Deref for ModelTransaction<'a> {
    type Target = Txn<'a>;

    fn deref(&self) -> &Txn<'a> {
        &self.0
    }
}

/// The work left after the transaction of a replace commits.
pub(crate) struct PendingReplace {
    replaced: ReplacedModel,
    /// The generation of the classifier file the overwritten previous result
    /// named, which nothing refers to once the transaction commits.
    unreferenced_generation: Option<u64>,
}

impl Store {
    /// Takes the model-files lock.
    pub(crate) fn lock_model_files(&self) -> ModelFilesGuard<'_> {
        #[cfg(test)]
        self.run_model_files_hook(ModelFilesPoint::Locking)
            .expect("the lock points only observe");
        let guard = self
            .model_files
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        #[cfg(test)]
        self.run_model_files_hook(ModelFilesPoint::Locked)
            .expect("the lock points only observe");
        ModelFilesGuard {
            store: self,
            _guard: guard,
        }
    }

    /// Begins a transaction whose commit syncs the write-ahead log, so that it
    /// is on disk when the commit returns.
    pub(crate) fn model_transaction(&self) -> ModelTransaction<'_> {
        let mut writeopts = WriteOptions::default();
        writeopts.set_sync(true);
        ModelTransaction(
            self.states
                .db()
                .transaction_opt(&writeopts, &OptimisticTransactionOptions::default()),
        )
    }

    /// Inserts a model trained by a run, or gives the model of the same name
    /// a new classifier, keeping its current training result as the previous
    /// one.
    ///
    /// The Central Manager creates and replaces models only through
    /// [`Store::complete_run`], which calls the same replace in the
    /// transaction that ends the model's run as succeeded: only a model's
    /// own run can create or replace it (RFC 0006 §7 of Clumit Security
    /// Web), which aicers/review enforces by refusing engines'
    /// `insert_model`. This method stays public for tests and tools; it
    /// writes no training definition and no run. The model is looked up by
    /// `model.name`; `model.id` is ignored.
    ///
    /// - If no model has that name, a record is inserted for `owner` with
    ///   the body's method and event kind, `trained_at`, `trained`'s run id
    ///   and definition text, its first classifier generation and no previous
    ///   result, and the body's classifier, batch information and scores are
    ///   stored.
    /// - If one does, it keeps its id. Its current batch information,
    ///   scores, clusters, column statistics, CSV column extras, time series
    ///   and outliers become its previous training result, read through
    ///   [`Store::previous_training_results`], overwriting the earlier one;
    ///   the body's batch information and scores become current; and the
    ///   record's `previous` summarises the training replaced. Its indicators
    ///   stay with it. The new classifier is written to a new file and the
    ///   record switches to it in the same transaction that moves the rows;
    ///   the earlier previous classifier file is removed after that commits.
    ///
    /// # Errors
    ///
    /// Returns an error, and changes nothing, if the body's method is
    /// `Distribution` (runs train only the multidimension, prefix and
    /// timeseries methods) or is not a known method; if a new model's name
    /// is not a valid model name; if the existing model belongs to another
    /// customer or instance, or has another method or event kind; or if
    /// writing the classifier file or a database operation fails.
    // The upload is handed over by value, as its decoded body is; the retry
    // after a commit conflict reads it again, so the body works on references.
    #[allow(clippy::needless_pass_by_value)]
    pub fn replace_model(
        &self,
        model: crate::model::Model,
        owner: ModelOwner,
        trained_at: DateTime<Utc>,
        trained: TrainedWith,
    ) -> Result<ReplacedModel> {
        let files = self.lock_model_files();
        loop {
            let txn = self.model_transaction();
            let pending = self.replace_model_with_transaction(
                &files, &txn, &model, &owner, trained_at, &trained,
            )?;
            #[cfg(test)]
            self.run_model_files_hook(ModelFilesPoint::BeforeCommit)?;
            if txn.commit_or_retry()? {
                #[cfg(test)]
                self.run_model_files_hook(ModelFilesPoint::AfterCommit)?;
                return Ok(self.finish_model_replace(&files, &pending));
            }
        }
    }

    /// Inserts or replaces a model, as [`Store::replace_model`] describes,
    /// within `txn`, which the caller commits.
    ///
    /// The classifier file is written here, before the caller commits. A
    /// caller that holds `files` from before this call until after
    /// [`Store::finish_model_replace`] can commit its own writes atomically
    /// with the replace. `txn` is a [`ModelTransaction`] because
    /// [`Store::finish_model_replace`] removes a classifier file the commit
    /// stops referring to.
    pub(crate) fn replace_model_with_transaction(
        &self,
        files: &ModelFilesGuard<'_>,
        txn: &ModelTransaction<'_>,
        model: &crate::model::Model,
        owner: &ModelOwner,
        trained_at: DateTime<Utc>,
        trained: &TrainedWith,
    ) -> Result<PendingReplace> {
        files.check(self)?;
        let method = model.method()?;
        if method == ClusteringMethod::Distribution {
            bail!(
                "model {:?} uses the Distribution method; models are trained only with the \
                 Multifield, Prefix and Timeseries methods",
                model.name
            );
        }
        let models = self.model_map();
        let Some(record) = models.load_model_by_name_in_transaction(&model.name, txn)? else {
            classifier_fs::validate_name(&model.name)
                .with_context(|| format!("invalid model name {:?}", model.name))?;
            let record = tables::Model {
                id: 0,
                name: model.name.clone(),
                version: model.version,
                kind: method.to_string(),
                max_event_id_num: model.max_event_id_num,
                classification_id: Some(model.classification_id),
                event_kind: model.event_kind.clone(),
                customer_id: owner.customer_id,
                instance: Some(owner.instance.clone()),
                trained_at,
                classifier_generation: FIRST_GENERATION,
                trained_run_id: trained.run_id,
                trained_definition: trained.definition.clone(),
                previous: None,
                clusters_applied: None,
            };
            let id = models.add_model_with_transaction(record, txn)?;
            self.classifier_fm.store_classifier(
                id,
                FIRST_GENERATION,
                &model.serialized_classifier,
            )?;
            self.put_round_rows(txn, id, model)?;
            return Ok(PendingReplace {
                replaced: ReplacedModel { id, inserted: true },
                unreferenced_generation: None,
            });
        };

        if record.customer_id != owner.customer_id
            || record.instance.as_ref() != Some(&owner.instance)
        {
            bail!("model {:?} belongs to another owner", model.name);
        }
        if record.kind != method.to_string() {
            bail!(
                "model {:?} uses the {} method, not {method}",
                model.name,
                record.kind
            );
        }
        if record.event_kind != model.event_kind {
            bail!(
                "model {:?} reads {:?} events, not {:?}",
                model.name,
                record.event_kind,
                model.event_kind
            );
        }

        let generation = next_generation(&record)?;
        self.classifier_fm
            .store_classifier(record.id, generation, &model.serialized_classifier)?;
        let db = self.states.db();
        delete_previous_rows(db, txn, record.id)?;
        move_current_rows_to_previous(db, txn, record.id)?;
        self.put_round_rows(txn, record.id, model)?;
        let replaced = tables::Model {
            version: model.version,
            max_event_id_num: model.max_event_id_num,
            classification_id: Some(model.classification_id),
            trained_at,
            classifier_generation: generation,
            trained_run_id: trained.run_id,
            trained_definition: trained.definition.clone(),
            previous: Some(PreviousTraining {
                trained_at: record.trained_at,
                version: record.version,
                classifier_generation: record.classifier_generation,
                trained_run_id: record.trained_run_id,
                trained_definition: record.trained_definition.clone(),
            }),
            clusters_applied: None,
            ..record.clone()
        };
        models.update_model_with_transaction(&record, &replaced, txn)?;
        Ok(PendingReplace {
            replaced: ReplacedModel {
                id: record.id,
                inserted: false,
            },
            unreferenced_generation: record
                .previous
                .as_ref()
                .map(|previous| previous.classifier_generation),
        })
    }

    /// Removes the classifier file a committed replace stopped referring to,
    /// and returns the replace's outcome.
    ///
    /// A failure to remove the file is logged, not returned: the commit has
    /// already taken effect.
    pub(crate) fn finish_model_replace(
        &self,
        _files: &ModelFilesGuard<'_>,
        pending: &PendingReplace,
    ) -> ReplacedModel {
        if let Some(generation) = pending.unreferenced_generation {
            self.remove_unreferenced_classifier(pending.replaced.id, generation);
        }
        pending.replaced
    }

    /// Stores an analysis round's model: its classifier, batch information
    /// and scores, and its version, maximum number of event ids and
    /// classification id.
    ///
    /// The model is looked up by `model.name`. Its owner, event kind,
    /// training time, trained run and definition, previous result and the
    /// classification id its clusters were last updated for stay as they
    /// are. The classifier is written to a new file and the record switches
    /// to it in the same transaction that stores the batch information and
    /// scores, so a classification id read back always comes with that
    /// upload's classifier, batch information and scores; the earlier
    /// current classifier file is removed after that commits.
    ///
    /// # Errors
    ///
    /// Returns an error, and changes nothing, if no model has the name, if
    /// `model.id` is not that model's id, if the method or the event kind
    /// differs from the model's, or if writing the classifier file or a
    /// database operation fails.
    // The upload is handed over by value, as its decoded body is; the retry
    // after a commit conflict reads it again, so the body works on references.
    #[allow(clippy::needless_pass_by_value)]
    pub fn update_model(&self, model: crate::model::Model) -> Result<i32> {
        let files = self.lock_model_files();
        let models = self.model_map();
        loop {
            let txn = self.model_transaction();
            let Some(record) = models.load_model_by_name_in_transaction(&model.name, &txn)? else {
                bail!("model {:?} not found", model.name);
            };
            if u32::try_from(model.id).ok() != Some(record.id) {
                bail!(
                    "model {:?} has id {}, not {}",
                    model.name,
                    record.id,
                    model.id
                );
            }
            let method = model.method()?;
            if record.kind != method.to_string() {
                bail!(
                    "model {:?} uses the {} method, not {method}",
                    model.name,
                    record.kind
                );
            }
            if record.event_kind != model.event_kind {
                bail!(
                    "model {:?} reads {:?} events, not {:?}",
                    model.name,
                    record.event_kind,
                    model.event_kind
                );
            }

            let generation = next_generation(&record)?;
            self.classifier_fm.store_classifier(
                record.id,
                generation,
                &model.serialized_classifier,
            )?;
            self.put_round_rows(&txn, record.id, &model)?;
            let updated = tables::Model {
                version: model.version,
                max_event_id_num: model.max_event_id_num,
                classification_id: Some(model.classification_id),
                classifier_generation: generation,
                ..record.clone()
            };
            models.update_model_with_transaction(&record, &updated, &txn)?;
            #[cfg(test)]
            self.run_model_files_hook(ModelFilesPoint::BeforeCommit)?;
            if txn.commit_or_retry()? {
                #[cfg(test)]
                self.run_model_files_hook(ModelFilesPoint::AfterCommit)?;
                self.remove_unreferenced_classifier(record.id, record.classifier_generation);
                drop(files);
                return Ok(i32::try_from(record.id)?);
            }
        }
    }

    /// Deletes the model with the given name, with everything stored for it.
    ///
    /// The record (with the current and the previous definition snapshots),
    /// the model's rows in every per-model column family and in every
    /// previous-result column family, and its indicators are removed in one
    /// transaction; after that commits, the model's classifier directory is
    /// removed with every classifier file in it. Detection events stay.
    ///
    /// # Errors
    ///
    /// Returns an error, and changes nothing, if no model has the name or a
    /// database operation fails. A failure to remove the classifier
    /// directory is logged, not returned: the commit has already taken
    /// effect.
    pub fn delete_model(&self, name: &str) -> Result<()> {
        let files = self.lock_model_files();
        let models = self.model_map();
        let db = self.states.db();
        loop {
            let txn = self.model_transaction();
            let Some(record) = models.load_model_by_name_in_transaction(name, &txn)? else {
                bail!("model {name:?} not found");
            };
            models.remove_model_with_transaction(record.id, &txn)?;
            delete_model_rows(db, &txn, record.id)?;
            #[cfg(test)]
            self.run_model_files_hook(ModelFilesPoint::BeforeCommit)?;
            if txn.commit_or_retry()? {
                #[cfg(test)]
                self.run_model_files_hook(ModelFilesPoint::AfterCommit)?;
                if let Err(e) = self.classifier_fm.delete_model_dir(record.id) {
                    warn!("model {name:?} is deleted, but its classifier files remain: {e}");
                }
                drop(files);
                return Ok(());
            }
        }
    }

    /// Applies an analysis round's cluster updates to the model with the
    /// given id, once per classification.
    ///
    /// If the updates of the model's current classification id were already
    /// applied, nothing changes and `Ok(false)` is returned. Otherwise the
    /// updates are applied, keeping at most the model's maximum number of
    /// event ids per cluster, and recorded as applied for that
    /// classification id in the same transaction, and `Ok(true)` is
    /// returned.
    ///
    /// # Errors
    ///
    /// Returns an error, and changes nothing, if no model has the id, if its
    /// maximum number of event ids is negative, if accumulating a cluster's
    /// size overflows `i64`, or if a database operation fails.
    pub fn update_clusters(&self, model_id: u32, updates: &[UpdateClusterRequest]) -> Result<bool> {
        let files = self.lock_model_files();
        let models = self.model_map();
        let clusters = self.cluster_map();
        loop {
            let txn = self.states.db().transaction();
            let Some(record) = models.get_by_id_in_transaction(model_id, &txn)? else {
                bail!("model {model_id} not found");
            };
            if record.clusters_applied == record.classification_id {
                return Ok(false);
            }
            let max_event_id_num = usize::try_from(record.max_event_id_num).with_context(|| {
                format!(
                    "model {model_id} has a negative maximum number of event ids: {}",
                    record.max_event_id_num
                )
            })?;
            clusters.update_clusters_with_transaction(updates, model_id, max_event_id_num, &txn)?;
            let applied = tables::Model {
                clusters_applied: record.classification_id,
                ..record.clone()
            };
            models.update_model_with_transaction(&record, &applied, &txn)?;
            if commit_or_retry(txn)? {
                drop(files);
                return Ok(true);
            }
        }
    }

    /// Returns the model with the given name, with its current classifier
    /// and scores.
    ///
    /// Model names are unique in the database. `event_kind` comes from the
    /// model's record and `scores` are the ones last stored for it (empty
    /// when it has none), read under the model-files lock together with the
    /// record and the classifier. `batch_info` is empty.
    ///
    /// # Errors
    ///
    /// Returns an error if the model does not exist, if its classifier file
    /// is missing, or if a database or file operation fails.
    pub fn load_model_by_name(&self, name: &str) -> Result<crate::model::Model> {
        let files = self.lock_model_files();
        let record = self.model_map().load_model_by_name(name)?;
        if !self
            .classifier_fm
            .classifier_exists(record.id, record.classifier_generation)
        {
            bail!("Classifier file not found for model {}", record.name);
        }
        let classifier = self
            .classifier_fm
            .load_classifier(record.id, record.classifier_generation)?;
        let scores = self
            .scores_map()
            .get(record.id)?
            .map(Scores::into_inner)
            .unwrap_or_default();
        drop(files);

        Ok(crate::model::Model {
            id: i32::try_from(record.id)?,
            name: record.name,
            version: record.version,
            kind: record.kind,
            serialized_classifier: classifier,
            max_event_id_num: record.max_event_id_num,
            event_kind: record.event_kind,
            classification_id: record.classification_id.unwrap_or_default(),
            batch_info: Vec::new(),
            scores,
        })
    }

    /// Returns the read view of every model's previous training result.
    ///
    /// The view is read-only by contract; see [`PreviousTrainingResults`].
    #[must_use]
    pub fn previous_training_results(&self) -> PreviousTrainingResults<'_> {
        self.states.previous_training_results()
    }

    /// Writes the body's batch information and scores as the current rows of
    /// model `id`.
    fn put_round_rows(&self, txn: &Txn<'_>, id: u32, model: &crate::model::Model) -> Result<()> {
        let batch_info = self.batch_info_map();
        for batch in &model.batch_info {
            batch_info.put_with_transaction(&BatchInfo::new(id, batch.clone()), txn)?;
        }
        self.scores_map()
            .put_with_transaction(&Scores::new(id, model.scores.clone()), txn)
    }

    /// Removes the classifier file of model `id` in `generation`, which no
    /// committed record refers to any longer, logging a failure.
    fn remove_unreferenced_classifier(&self, id: u32, generation: u64) {
        if let Err(e) = self.classifier_fm.delete_classifier(id, generation) {
            warn!("unreferenced classifier file of model {id} remains: {e}");
        }
    }
}

/// Returns the generation after the current one of `record`.
fn next_generation(record: &tables::Model) -> Result<u64> {
    record
        .classifier_generation
        .checked_add(1)
        .ok_or_else(|| anyhow!("model {:?} has no classifier generation left", record.name))
}

/// Commits `txn`, returning `Ok(false)` if it conflicted with a concurrent
/// write and has to be retried.
fn commit_or_retry(txn: Txn<'_>) -> Result<bool> {
    match txn.commit() {
        Ok(()) => Ok(true),
        Err(e) if e.as_ref().starts_with("Resource busy:") => Ok(false),
        Err(e) => Err(e).context("failed to commit model changes"),
    }
}

pub(crate) fn column_family<'d>(
    db: &'d OptimisticTransactionDB,
    name: &str,
) -> Result<&'d ColumnFamily> {
    db.cf_handle(name)
        .ok_or_else(|| anyhow!("database error: cannot find column family \"{name}\""))
}

/// Returns the keys in `cf` that start with `prefix`, as `txn` sees them.
fn keys_with_prefix(txn: &Txn<'_>, cf: &ColumnFamily, prefix: &[u8]) -> Result<Vec<Box<[u8]>>> {
    let mut readopts = rocksdb::ReadOptions::default();
    readopts.set_iterate_range(rocksdb::PrefixRange(prefix));
    txn.iterator_cf_opt(cf, readopts, IteratorMode::Start)
        .map(|entry| {
            entry
                .map(|(key, _)| key)
                .context("cannot read per-model rows")
        })
        .collect()
}

/// Deletes the rows of `cf` whose keys start with `prefix`.
fn delete_prefix(txn: &Txn<'_>, cf: &ColumnFamily, prefix: &[u8]) -> Result<()> {
    for key in keys_with_prefix(txn, cf, prefix)? {
        // Read for update so that a concurrent write of the row makes the
        // transaction retry rather than be lost.
        txn.get_for_update_cf(cf, &key, EXCLUSIVE)?;
        txn.delete_cf(cf, &key)?;
    }
    Ok(())
}

/// Moves the row at `key` from `from` to `to`, keeping its key and value.
fn move_row(txn: &Txn<'_>, from: &ColumnFamily, to: &ColumnFamily, key: &[u8]) -> Result<()> {
    if let Some(value) = txn.get_for_update_cf(from, key, EXCLUSIVE)? {
        txn.put_cf(to, key, &value)?;
        txn.delete_cf(from, key)?;
    }
    Ok(())
}

/// Returns the key of the scores row of model `id`, which is not a
/// big-endian prefix but the bincode encoding of the id.
fn scores_key(id: u32) -> Vec<u8> {
    Scores::new(id, crate::types::ModelScores::default()).unique_key()
}

/// Removes the CSV column extra of model `id` from the indexed map `map`,
/// returning it.
fn take_csv_column_extra(
    map: &IndexedMap<'_>,
    txn: &Txn<'_>,
    id: u32,
) -> Result<Option<CsvColumnExtra>> {
    let key = id.to_be_bytes();
    let Some(value) = txn.get_for_update_cf(map.cf(), key, EXCLUSIVE)? else {
        return Ok(None);
    };
    let extra = CsvColumnExtra::from_key_value(&key, &value)?;
    map.remove_with_transaction::<CsvColumnExtra>(extra.id, txn)?;
    Ok(Some(extra))
}

/// Deletes every row of model `id` in the previous-result column families.
fn delete_previous_rows(db: &OptimisticTransactionDB, txn: &Txn<'_>, id: u32) -> Result<()> {
    for (_, previous) in ID_PREFIXED_FAMILIES {
        delete_prefix(txn, column_family(db, previous)?, &id.to_be_bytes())?;
    }
    let previous_scores = column_family(db, tables::PREVIOUS_SCORES)?;
    txn.get_for_update_cf(previous_scores, scores_key(id), EXCLUSIVE)?;
    txn.delete_cf(previous_scores, scores_key(id))?;
    take_csv_column_extra(
        &IndexedMap::new(db, tables::PREVIOUS_CSV_COLUMN_EXTRAS)?,
        txn,
        id,
    )?;
    Ok(())
}

/// Moves every row of model `id` in the per-model column families into the
/// matching previous-result column family. A row keeps its key and value,
/// except a CSV column extra, which takes an id in the mirror's own index.
fn move_current_rows_to_previous(
    db: &OptimisticTransactionDB,
    txn: &Txn<'_>,
    id: u32,
) -> Result<()> {
    for (current, previous) in ID_PREFIXED_FAMILIES {
        let current = column_family(db, current)?;
        let previous = column_family(db, previous)?;
        for key in keys_with_prefix(txn, current, &id.to_be_bytes())? {
            move_row(txn, current, previous, &key)?;
        }
    }
    move_row(
        txn,
        column_family(db, tables::SCORES)?,
        column_family(db, tables::PREVIOUS_SCORES)?,
        &scores_key(id),
    )?;
    if let Some(extra) =
        take_csv_column_extra(&IndexedMap::new(db, tables::CSV_COLUMN_EXTRAS)?, txn, id)?
    {
        IndexedMap::new(db, tables::PREVIOUS_CSV_COLUMN_EXTRAS)?
            .insert_with_transaction(extra, txn)?;
    }
    Ok(())
}

/// Deletes every row of model `id`, current and previous, and its
/// indicators; the record itself is left to the caller.
fn delete_model_rows(db: &OptimisticTransactionDB, txn: &Txn<'_>, id: u32) -> Result<()> {
    for (current, _) in ID_PREFIXED_FAMILIES {
        delete_prefix(txn, column_family(db, current)?, &id.to_be_bytes())?;
    }
    let scores = column_family(db, tables::SCORES)?;
    txn.get_for_update_cf(scores, scores_key(id), EXCLUSIVE)?;
    txn.delete_cf(scores, scores_key(id))?;
    take_csv_column_extra(&IndexedMap::new(db, tables::CSV_COLUMN_EXTRAS)?, txn, id)?;
    delete_previous_rows(db, txn, id)?;

    let indicators = column_family(db, tables::MODEL_INDICATORS)?;
    let mut owned = Vec::new();
    for entry in txn.iterator_cf(indicators, IteratorMode::Start) {
        let (key, value) = entry.context("cannot read model indicators")?;
        if ModelIndicator::from_key_value(&key, &value)?.model_id == id {
            owned.push(key);
        }
    }
    for key in owned {
        txn.get_for_update_cf(indicators, &key, EXCLUSIVE)?;
        txn.delete_cf(indicators, &key)?;
    }
    Ok(())
}

/// A point at which the model-files test hook runs.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ModelFilesPoint {
    /// Before taking the model-files lock.
    Locking,
    /// Right after taking the model-files lock.
    Locked,
    /// After the classifier file write, before the commit.
    BeforeCommit,
    /// After the commit, before the post-commit file or directory removal.
    AfterCommit,
}

/// A hook the tests run at each [`ModelFilesPoint`]; an error it returns at
/// `BeforeCommit` or `AfterCommit` ends the operation with that error.
#[cfg(test)]
pub(crate) type ModelFilesHook =
    std::sync::Arc<dyn Fn(ModelFilesPoint) -> Result<()> + Send + Sync>;

#[cfg(test)]
impl Store {
    pub(crate) fn set_model_files_hook(&self, hook: Option<ModelFilesHook>) {
        *self
            .model_files_hook
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = hook;
    }

    pub(crate) fn run_model_files_hook(&self, point: ModelFilesPoint) -> Result<()> {
        let hook = self
            .model_files_hook
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        hook.map_or(Ok(()), |hook| hook(point))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        path::{Path, PathBuf},
        sync::{Arc, Mutex, TryLockError, mpsc},
        thread,
    };

    use chrono::{DateTime, NaiveDate, Utc};
    use structured::{ColumnStatistics, Description, NLargestCount};

    use super::*;
    use crate::{
        ColumnTimeSeries, ModelInstance, OutlierInfo,
        test::{DbGuard, acquire_db_permit},
        types::{ModelBatchInfo, ModelScores},
    };

    /// Every family a model's rows live in, current and previous, with the
    /// model records and indicators.
    const MODEL_FAMILIES: [&str; 16] = [
        tables::MODELS,
        tables::MODEL_INDICATORS,
        tables::BATCH_INFO,
        tables::SCORES,
        tables::CLUSTER,
        tables::COLUMN_STATS,
        tables::CSV_COLUMN_EXTRAS,
        tables::TIME_SERIES,
        tables::OUTLIERS,
        tables::PREVIOUS_BATCH_INFO,
        tables::PREVIOUS_SCORES,
        tables::PREVIOUS_CLUSTER,
        tables::PREVIOUS_COLUMN_STATS,
        tables::PREVIOUS_CSV_COLUMN_EXTRAS,
        tables::PREVIOUS_TIME_SERIES,
        tables::PREVIOUS_OUTLIERS,
    ];

    type Entries = Vec<(Vec<u8>, Vec<u8>)>;

    struct TestStore {
        _permit: DbGuard<'static>,
        store: Store,
        _db_dir: tempfile::TempDir,
        _backup_dir: tempfile::TempDir,
    }

    fn setup_store() -> TestStore {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Store::new(db_dir.path(), backup_dir.path(), None).unwrap();
        TestStore {
            _permit: permit,
            store,
            _db_dir: db_dir,
            _backup_dir: backup_dir,
        }
    }

    fn owner() -> ModelOwner {
        ModelOwner {
            customer_id: 1,
            instance: ModelInstance {
                node_id: 2,
                agent_key: "unsupervised@host-a".to_string(),
            },
        }
    }

    fn trained(run_id: u32, definition: &str) -> TrainedWith {
        TrainedWith {
            run_id,
            definition: definition.to_string(),
        }
    }

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    fn batch(id: i64) -> ModelBatchInfo {
        ModelBatchInfo {
            id,
            earliest: id,
            latest: id + 1,
            size: 3,
            sensors: vec!["sensor-a".to_string()],
        }
    }

    fn scores(score: f64) -> ModelScores {
        [(1, score)].into_iter().collect()
    }

    /// A multidimension body of `http` events named `name`.
    fn body(name: &str, classifier: &[u8], classification_id: i64) -> crate::model::Model {
        crate::model::Model {
            id: 0,
            name: name.to_string(),
            version: 1,
            kind: "Multifield".to_string(),
            serialized_classifier: classifier.to_vec(),
            max_event_id_num: 10,
            event_kind: "http".to_string(),
            classification_id,
            batch_info: vec![batch(classification_id)],
            scores: scores(0.5),
        }
    }

    fn insert(store: &Store, name: &str, classifier: &[u8]) -> u32 {
        let replaced = store
            .replace_model(
                body(name, classifier, 1),
                owner(),
                at(100),
                trained(1, "eps = 5.0"),
            )
            .unwrap();
        assert!(replaced.inserted);
        replaced.id
    }

    fn replace(store: &Store, name: &str, classifier: &[u8], run_id: u32) -> Result<ReplacedModel> {
        store.replace_model(
            body(name, classifier, i64::from(run_id)),
            owner(),
            at(i64::from(run_id) * 100),
            trained(run_id, &format!("run = {run_id}")),
        )
    }

    fn record(store: &Store, name: &str) -> tables::Model {
        store.model_map().load_model_by_name(name).unwrap()
    }

    fn update_request(cluster_id: u32, event: i64, size: i64) -> UpdateClusterRequest {
        UpdateClusterRequest {
            cluster_id,
            detector_id: 1,
            signature: "signature".to_string(),
            score: Some(0.25),
            size,
            event_ids: vec![(event, "sensor-a".to_string())],
            status_id: 2,
            labels: None,
        }
    }

    /// Writes a row of `id`, tagged `tag`, in each per-model family an
    /// analysis round fills besides batch information and scores, and sets
    /// the cluster's category, qualifier and status.
    fn add_round_rows(store: &Store, id: u32, tag: i64) {
        store
            .cluster_map()
            .update_clusters(&[update_request(1, tag, 4)], id, 10)
            .unwrap();
        store
            .cluster_map()
            .update_cluster(id, 1, Some(5), Some(6), Some(7))
            .unwrap();
        store
            .outlier_map()
            .insert(&OutlierInfo {
                model_id: id,
                timestamp: tag,
                rank: 1,
                id: 9,
                sensor: "sensor-a".to_string(),
                distance: 0.5,
                is_saved: false,
            })
            .unwrap();
        let batch_ts = NaiveDate::from_ymd_opt(2026, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            + chrono::Duration::seconds(tag);
        store
            .column_stats_map()
            .insert_column_statistics(
                vec![(
                    1,
                    vec![ColumnStatistics {
                        description: Description::default(),
                        n_largest_count: NLargestCount::default(),
                    }],
                )],
                id,
                batch_ts,
            )
            .unwrap();
        let alias = [format!("alias-{tag}")];
        let extras = store.csv_column_extra_map();
        if let Some(extra) = extras.get_by_model(id).unwrap() {
            extras
                .update(extra.id, Some(&alias), None, None, None, None)
                .unwrap();
        } else {
            extras
                .insert(id, Some(&alias), None, None, None, None)
                .unwrap();
        }
        store
            .time_series_map()
            .add_time_series(
                id,
                tag,
                vec![(
                    1,
                    vec![ColumnTimeSeries {
                        index: Some(0),
                        time_counts: vec![(tag, 2)],
                    }],
                )],
            )
            .unwrap();
    }

    /// Every entry of `family`.
    fn entries(store: &Store, family: &str) -> Entries {
        let db = store.states.db();
        let cf = db.cf_handle(family).unwrap();
        db.iterator_cf(cf, IteratorMode::Start)
            .map(|entry| {
                let (key, value) = entry.unwrap();
                (key.to_vec(), value.to_vec())
            })
            .collect()
    }

    /// The rows of model `id` in `family`, keyed by its id first (or, in a
    /// scores family, by the encoding of its id).
    fn rows_of(store: &Store, family: &str, id: u32) -> Entries {
        let prefix = if family == tables::SCORES || family == tables::PREVIOUS_SCORES {
            scores_key(id)
        } else {
            id.to_be_bytes().to_vec()
        };
        entries(store, family)
            .into_iter()
            .filter(|(key, _)| {
                if family == tables::SCORES || family == tables::PREVIOUS_SCORES {
                    *key == prefix
                } else {
                    key.starts_with(&prefix)
                }
            })
            .collect()
    }

    /// Every entry of every model family.
    fn model_families(store: &Store) -> Vec<(&'static str, Entries)> {
        MODEL_FAMILIES
            .into_iter()
            .map(|family| (family, entries(store, family)))
            .collect()
    }

    /// Every file under the `classifiers` directory, with its contents.
    fn classifier_files(store: &Store) -> Vec<(PathBuf, Vec<u8>)> {
        fn collect(dir: &Path, files: &mut Vec<(PathBuf, Vec<u8>)>) {
            let Ok(read) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in read {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    collect(&path, files);
                } else {
                    files.push((path.clone(), std::fs::read(&path).unwrap()));
                }
            }
        }
        let mut files = Vec::new();
        collect(
            &store.classifier_fm.model_dir(0).with_file_name(""),
            &mut files,
        );
        files.sort_unstable();
        files
    }

    fn classifier(store: &Store, id: u32, generation: u64) -> Option<Vec<u8>> {
        store.classifier_fm.load_classifier(id, generation).ok()
    }

    fn model_dir(store: &Store, id: u32) -> PathBuf {
        store.classifier_fm.model_dir(id)
    }

    /// The generations of the classifier files in the directory of `id`.
    fn generations(store: &Store, id: u32) -> HashSet<u64> {
        let Ok(read) = std::fs::read_dir(model_dir(store, id)) else {
            return HashSet::new();
        };
        read.map(|entry| {
            let name = entry.unwrap().file_name().into_string().unwrap();
            name.strip_prefix("classifier_")
                .and_then(|name| name.strip_suffix(".bin"))
                .unwrap()
                .parse()
                .unwrap()
        })
        .collect()
    }

    fn fail_before_commit(store: &Store) {
        store.set_model_files_hook(Some(Arc::new(|point| {
            if point == ModelFilesPoint::BeforeCommit {
                bail!("injected failure before commit");
            }
            Ok(())
        })));
    }

    #[test]
    fn replace_inserts_a_new_model() {
        let ts = setup_store();
        let store = &ts.store;

        let replaced = store
            .replace_model(
                body("alpha", b"classifier", 3),
                owner(),
                at(1_000),
                trained(11, "[model]\neps = 5.0\n"),
            )
            .unwrap();
        assert_eq!(
            replaced,
            ReplacedModel {
                id: 0,
                inserted: true
            }
        );

        assert_eq!(
            record(store, "alpha"),
            tables::Model {
                id: 0,
                name: "alpha".to_string(),
                version: 1,
                kind: "Multifield".to_string(),
                max_event_id_num: 10,
                classification_id: Some(3),
                event_kind: "http".to_string(),
                customer_id: 1,
                instance: Some(owner().instance),
                trained_at: at(1_000),
                classifier_generation: 1,
                trained_run_id: 11,
                trained_definition: "[model]\neps = 5.0\n".to_string(),
                previous: None,
                clusters_applied: None,
            }
        );
        assert_eq!(
            store.batch_info_map().get_all_for(0).unwrap(),
            vec![BatchInfo::new(0, batch(3))]
        );

        let loaded = store.load_model_by_name("alpha").unwrap();
        assert_eq!(loaded.id, 0);
        assert_eq!(loaded.event_kind, "http");
        assert_eq!(loaded.kind, "Multifield");
        assert_eq!(loaded.classification_id, 3);
        assert_eq!(loaded.serialized_classifier, b"classifier");
        assert_eq!(loaded.scores, scores(0.5));
        assert_eq!(loaded.batch_info, Vec::new());
        assert_eq!(generations(store, 0), HashSet::from([1]));
    }

    #[test]
    fn replace_looks_a_model_up_by_name_not_by_the_body_id() {
        let ts = setup_store();
        let store = &ts.store;
        let alpha = insert(store, "alpha", b"alpha");
        let beta = insert(store, "beta", b"beta");

        let replaced = store
            .replace_model(
                crate::model::Model {
                    id: i32::try_from(alpha).unwrap(),
                    ..body("beta", b"beta 2", 2)
                },
                owner(),
                at(200),
                trained(2, "run = 2"),
            )
            .unwrap();
        assert_eq!(
            replaced,
            ReplacedModel {
                id: beta,
                inserted: false
            }
        );
        assert_eq!(record(store, "alpha").classifier_generation, 1);
        assert_eq!(classifier(store, alpha, 1).unwrap(), b"alpha");

        let inserted = store
            .replace_model(
                crate::model::Model {
                    id: 42,
                    ..body("gamma", b"gamma", 1)
                },
                owner(),
                at(300),
                trained(3, "run = 3"),
            )
            .unwrap();
        assert_eq!(
            inserted,
            ReplacedModel {
                id: 2,
                inserted: true
            }
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn replace_moves_the_current_result_to_the_previous_one() {
        let ts = setup_store();
        let store = &ts.store;
        let id = insert(store, "alpha", b"first");
        add_round_rows(store, id, 10);
        let other = insert(store, "beta", b"other");
        add_round_rows(store, other, 20);
        store
            .model_indicator_map()
            .insert(ModelIndicator {
                name: "indicator".to_string(),
                description: "kept".to_string(),
                model_id: id,
                tokens: HashSet::new(),
                last_modification_time: at(5),
            })
            .unwrap();
        let first = record(store, "alpha");
        let current: Vec<_> = ID_PREFIXED_FAMILIES
            .into_iter()
            .map(|(current, _)| rows_of(store, current, id))
            .collect();
        let current_scores = rows_of(store, tables::SCORES, id);
        let clusters = store
            .cluster_map()
            .load_clusters(id, None, None, None, None, &None, &None, true, 10)
            .unwrap();
        assert_eq!(clusters.len(), 1);
        let indicators = entries(store, tables::MODEL_INDICATORS);
        let other_rows: Vec<_> = MODEL_FAMILIES
            .into_iter()
            .map(|family| rows_of(store, family, other))
            .collect();

        let replaced = store
            .replace_model(
                crate::model::Model {
                    version: 2,
                    max_event_id_num: 20,
                    batch_info: vec![batch(30)],
                    scores: scores(0.75),
                    ..body("alpha", b"second", 30)
                },
                owner(),
                at(2_000),
                trained(2, "eps = 2.0"),
            )
            .unwrap();
        assert_eq!(
            replaced,
            ReplacedModel {
                id,
                inserted: false
            }
        );

        // The previous rows are the earlier current ones, key and value.
        for ((_, previous), rows) in ID_PREFIXED_FAMILIES.into_iter().zip(&current) {
            assert!(!rows.is_empty(), "{previous} has rows to move");
            assert_eq!(&rows_of(store, previous, id), rows, "{previous}");
        }
        assert_eq!(rows_of(store, tables::PREVIOUS_SCORES, id), current_scores);
        let previous = store.previous_training_results();
        assert_eq!(
            previous
                .cluster_map()
                .load_clusters(id, None, None, None, None, &None, &None, true, 10)
                .unwrap(),
            clusters
        );
        let moved = previous
            .cluster_map()
            .load_clusters(id, None, None, None, None, &None, &None, true, 10)
            .unwrap();
        assert_eq!(
            (
                moved[0].category_id,
                moved[0].qualifier_id,
                moved[0].status_id
            ),
            (5, 6, 7)
        );
        assert_eq!(
            previous.batch_info_map().get_all_for(id).unwrap(),
            vec![BatchInfo::new(id, batch(1))]
        );
        assert_eq!(
            previous.scores_map().get(id).unwrap(),
            Some(Scores::new(id, scores(0.5)))
        );
        let extra = previous
            .csv_column_extra_map()
            .get_by_model(id)
            .unwrap()
            .unwrap();
        assert_eq!(extra.column_alias, Some(vec!["alias-10".to_string()]));
        assert!(
            store
                .csv_column_extra_map()
                .get_by_model(id)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            previous
                .time_series_map()
                .get_time_range_of_model(id)
                .unwrap(),
            Some((10, 10))
        );

        // The current tables hold only the new batch information and scores.
        for (family, _) in ID_PREFIXED_FAMILIES {
            if family == tables::BATCH_INFO {
                continue;
            }
            assert_eq!(rows_of(store, family, id), Entries::new(), "{family}");
        }
        assert_eq!(
            store.batch_info_map().get_all_for(id).unwrap(),
            vec![BatchInfo::new(id, batch(30))]
        );
        assert_eq!(
            store.scores_map().get(id).unwrap(),
            Some(Scores::new(id, scores(0.75)))
        );

        // The record summarises the replaced training.
        let second = record(store, "alpha");
        assert_eq!(
            second,
            tables::Model {
                version: 2,
                max_event_id_num: 20,
                classification_id: Some(30),
                trained_at: at(2_000),
                classifier_generation: 2,
                trained_run_id: 2,
                trained_definition: "eps = 2.0".to_string(),
                previous: Some(PreviousTraining {
                    trained_at: first.trained_at,
                    version: first.version,
                    classifier_generation: 1,
                    trained_run_id: 1,
                    trained_definition: "eps = 5.0".to_string(),
                }),
                clusters_applied: None,
                ..first.clone()
            }
        );
        assert_eq!(
            store
                .load_model_by_name("alpha")
                .unwrap()
                .serialized_classifier,
            b"second"
        );
        assert_eq!(classifier(store, id, 1).unwrap(), b"first");

        // The indicators, and another model's rows, are untouched.
        assert_eq!(entries(store, tables::MODEL_INDICATORS), indicators);
        let after: Vec<_> = MODEL_FAMILIES
            .into_iter()
            .map(|family| rows_of(store, family, other))
            .collect();
        assert_eq!(after, other_rows);
    }

    #[test]
    fn a_second_replace_overwrites_the_previous_result() {
        let ts = setup_store();
        let store = &ts.store;
        let id = insert(store, "alpha", b"first");
        add_round_rows(store, id, 10);
        replace(store, "alpha", b"second", 2).unwrap();
        add_round_rows(store, id, 20);
        let second: Vec<_> = ID_PREFIXED_FAMILIES
            .into_iter()
            .map(|(current, _)| rows_of(store, current, id))
            .collect();
        let second_scores = rows_of(store, tables::SCORES, id);

        replace(store, "alpha", b"third", 3).unwrap();

        for ((_, previous), rows) in ID_PREFIXED_FAMILIES.into_iter().zip(&second) {
            assert_eq!(&rows_of(store, previous, id), rows, "{previous}");
        }
        assert_eq!(rows_of(store, tables::PREVIOUS_SCORES, id), second_scores);
        let extra = store
            .previous_training_results()
            .csv_column_extra_map()
            .get_by_model(id)
            .unwrap()
            .unwrap();
        assert_eq!(extra.column_alias, Some(vec!["alias-20".to_string()]));
        assert_eq!(
            store
                .previous_training_results()
                .csv_column_extra_map()
                .count()
                .unwrap(),
            1
        );

        let third = record(store, "alpha");
        assert_eq!(third.classifier_generation, 3);
        let previous = third.previous.unwrap();
        assert_eq!(previous.classifier_generation, 2);
        assert_eq!(previous.trained_run_id, 2);
        assert_eq!(generations(store, id), HashSet::from([2, 3]));
        assert_eq!(classifier(store, id, 2).unwrap(), b"second");
        assert_eq!(classifier(store, id, 3).unwrap(), b"third");
    }

    #[test]
    fn definition_snapshots_follow_the_classifier() {
        let ts = setup_store();
        let store = &ts.store;
        store
            .replace_model(
                body("alpha", b"first", 1),
                owner(),
                at(100),
                trained(1, "[dbscan]\neps = 5.0\n"),
            )
            .unwrap();
        let inserted = record(store, "alpha");
        assert_eq!(inserted.trained_run_id, 1);
        assert_eq!(inserted.trained_definition, "[dbscan]\neps = 5.0\n");

        store
            .update_model(crate::model::Model {
                id: 0,
                ..body("alpha", b"round", 2)
            })
            .unwrap();
        let updated = record(store, "alpha");
        assert_eq!(updated.trained_run_id, 1);
        assert_eq!(updated.trained_definition, "[dbscan]\neps = 5.0\n");

        store
            .replace_model(
                body("alpha", b"second", 3),
                owner(),
                at(200),
                trained(2, "[dbscan]\neps = 2.0\n"),
            )
            .unwrap();
        let replaced = record(store, "alpha");
        assert_eq!(replaced.trained_run_id, 2);
        assert_eq!(replaced.trained_definition, "[dbscan]\neps = 2.0\n");
        let previous = replaced.previous.unwrap();
        assert_eq!(previous.trained_run_id, 1);
        assert_eq!(previous.trained_definition, "[dbscan]\neps = 5.0\n");

        store.delete_model("alpha").unwrap();
        assert!(store.model_map().load_model_by_name("alpha").is_err());
        let left: Vec<_> = entries(store, tables::MODELS)
            .into_iter()
            .filter(|(key, _)| !key.is_empty())
            .collect();
        assert_eq!(left, Entries::new());
    }

    #[test]
    fn refused_replaces_change_nothing() {
        let ts = setup_store();
        let store = &ts.store;
        let id = insert(store, "alpha", b"first");
        add_round_rows(store, id, 10);
        replace(store, "alpha", b"second", 2).unwrap();
        let rows = model_families(store);
        let files = classifier_files(store);

        let other_customer = ModelOwner {
            customer_id: 9,
            ..owner()
        };
        let other_instance = ModelOwner {
            instance: ModelInstance {
                node_id: 3,
                agent_key: "unsupervised@host-b".to_string(),
            },
            ..owner()
        };
        let refusals = [
            (body("alpha", b"x", 4), other_customer, "another owner"),
            (body("alpha", b"x", 4), other_instance, "another owner"),
            (
                crate::model::Model {
                    kind: "Prefix".to_string(),
                    ..body("alpha", b"x", 4)
                },
                owner(),
                "method",
            ),
            (
                crate::model::Model {
                    event_kind: "dns".to_string(),
                    ..body("alpha", b"x", 4)
                },
                owner(),
                "events",
            ),
            (
                crate::model::Model {
                    kind: "Distribution".to_string(),
                    ..body("alpha", b"x", 4)
                },
                owner(),
                "Distribution",
            ),
            (
                crate::model::Model {
                    kind: "Distribution".to_string(),
                    ..body("gamma", b"x", 4)
                },
                owner(),
                "Distribution",
            ),
            (body("bad/name", b"x", 4), owner(), "invalid model name"),
            (
                body(&"n".repeat(256), b"x", 4),
                owner(),
                "invalid model name",
            ),
            // 86 characters, but 258 bytes: the limit is on bytes.
            (
                body(&"\u{d55c}".repeat(86), b"x", 4),
                owner(),
                "invalid model name",
            ),
            (body("", b"x", 4), owner(), "invalid model name"),
        ];
        for (model, owner, reason) in refusals {
            let name = model.name.clone();
            let error = store
                .replace_model(model, owner, at(9_000), trained(9, "refused"))
                .unwrap_err();
            assert!(
                format!("{error:#}").contains(reason),
                "{name:?}: unexpected error {error:#}"
            );
            assert_eq!(model_families(store), rows, "{name:?} changed rows");
            assert_eq!(classifier_files(store), files, "{name:?} changed files");
        }
    }

    #[test]
    fn a_name_of_255_bytes_is_stored_and_loaded() {
        let ts = setup_store();
        let store = &ts.store;
        let name = "n".repeat(255);

        let id = insert(store, &name, b"long");

        let loaded = store.load_model_by_name(&name).unwrap();
        assert_eq!(loaded.serialized_classifier, b"long");
        assert_eq!(
            store
                .classifier_fm
                .create_classifier_path(id, 1)
                .file_name(),
            Some(std::ffi::OsStr::new("classifier_1.bin"))
        );
        replace(store, &name, b"longer", 2).unwrap();
        assert_eq!(
            store
                .load_model_by_name(&name)
                .unwrap()
                .serialized_classifier,
            b"longer"
        );
    }

    #[test]
    fn a_replace_failing_before_its_commit_changes_nothing() {
        let ts = setup_store();
        let store = &ts.store;
        let id = insert(store, "alpha", b"first");
        add_round_rows(store, id, 10);
        replace(store, "alpha", b"second", 2).unwrap();
        add_round_rows(store, id, 20);
        let rows = model_families(store);

        fail_before_commit(store);
        assert!(replace(store, "alpha", b"third", 3).is_err());
        store.set_model_files_hook(None);

        assert_eq!(model_families(store), rows);
        let loaded = store.load_model_by_name("alpha").unwrap();
        assert_eq!(loaded.serialized_classifier, b"second");
        assert_eq!(record(store, "alpha").classifier_generation, 2);
        assert_eq!(classifier(store, id, 1).unwrap(), b"first");
        // The unreferenced file the failed replace wrote is overwritten by
        // the retry.
        assert_eq!(classifier(store, id, 3).unwrap(), b"third");
        replace(store, "alpha", b"retried", 3).unwrap();
        assert_eq!(
            store
                .load_model_by_name("alpha")
                .unwrap()
                .serialized_classifier,
            b"retried"
        );
        assert_eq!(generations(store, id), HashSet::from([2, 3]));
    }

    #[test]
    fn update_model_refuses_a_body_of_another_model() {
        let ts = setup_store();
        let store = &ts.store;
        let alpha = insert(store, "alpha", b"alpha");
        let beta = insert(store, "beta", b"beta");
        let rows = model_families(store);
        let files = classifier_files(store);

        let refusals = [
            (
                crate::model::Model {
                    id: i32::try_from(beta).unwrap(),
                    ..body("alpha", b"x", 7)
                },
                "has id",
            ),
            (
                crate::model::Model {
                    id: -1,
                    ..body("alpha", b"x", 7)
                },
                "has id",
            ),
            (
                crate::model::Model {
                    id: i32::try_from(alpha).unwrap(),
                    event_kind: "dns".to_string(),
                    ..body("alpha", b"x", 7)
                },
                "events",
            ),
            (
                crate::model::Model {
                    id: i32::try_from(alpha).unwrap(),
                    kind: "Prefix".to_string(),
                    ..body("alpha", b"x", 7)
                },
                "method",
            ),
            (body("gamma", b"x", 7), "not found"),
        ];
        for (model, reason) in refusals {
            let error = store.update_model(model).unwrap_err();
            assert!(
                error.to_string().contains(reason),
                "unexpected error {error}"
            );
            assert_eq!(model_families(store), rows);
            assert_eq!(classifier_files(store), files);
        }
    }

    #[test]
    fn update_model_stores_a_round_under_the_record() {
        let ts = setup_store();
        let store = &ts.store;
        let id = insert(store, "alpha", b"first");
        insert(store, "beta", b"beta");
        replace(store, "alpha", b"second", 2).unwrap();
        let before = record(store, "alpha");

        let updated = store
            .update_model(crate::model::Model {
                id: i32::try_from(id).unwrap(),
                version: 5,
                max_event_id_num: 40,
                batch_info: vec![batch(50)],
                scores: scores(0.9),
                ..body("alpha", b"round", 50)
            })
            .unwrap();
        assert_eq!(updated, i32::try_from(id).unwrap());

        assert_eq!(
            record(store, "alpha"),
            tables::Model {
                version: 5,
                max_event_id_num: 40,
                classification_id: Some(50),
                classifier_generation: 3,
                ..before
            }
        );
        let batches = store.batch_info_map().get_all_for(id).unwrap();
        assert!(batches.contains(&BatchInfo::new(id, batch(50))));
        assert_eq!(
            store.scores_map().get(id).unwrap(),
            Some(Scores::new(id, scores(0.9)))
        );
        let loaded = store.load_model_by_name("alpha").unwrap();
        assert_eq!(loaded.serialized_classifier, b"round");
        assert_eq!(loaded.classification_id, 50);
        assert_eq!(loaded.scores, scores(0.9));
        // The earlier current file is gone; the previous result's stays.
        assert_eq!(generations(store, id), HashSet::from([1, 3]));
        assert_eq!(classifier(store, id, 1).unwrap(), b"first");
    }

    #[test]
    fn update_model_failing_to_write_its_classifier_changes_nothing() {
        let ts = setup_store();
        let store = &ts.store;
        let id = insert(store, "alpha", b"first");
        let rows = model_families(store);
        // A directory where the next generation's file goes makes the
        // rename onto it fail.
        std::fs::create_dir(store.classifier_fm.create_classifier_path(id, 2)).unwrap();

        assert!(
            store
                .update_model(crate::model::Model {
                    id: i32::try_from(id).unwrap(),
                    ..body("alpha", b"round", 2)
                })
                .is_err()
        );

        assert_eq!(model_families(store), rows);
        assert_eq!(record(store, "alpha").classification_id, Some(1));
        assert_eq!(
            store
                .load_model_by_name("alpha")
                .unwrap()
                .serialized_classifier,
            b"first"
        );
    }

    #[test]
    fn update_model_failing_before_its_commit_changes_nothing() {
        let ts = setup_store();
        let store = &ts.store;
        let id = insert(store, "alpha", b"first");
        let rows = model_families(store);

        fail_before_commit(store);
        assert!(
            store
                .update_model(crate::model::Model {
                    id: i32::try_from(id).unwrap(),
                    ..body("alpha", b"round", 2)
                })
                .is_err()
        );
        store.set_model_files_hook(None);

        assert_eq!(model_families(store), rows);
        let loaded = store.load_model_by_name("alpha").unwrap();
        assert_eq!(loaded.classification_id, 1);
        assert_eq!(loaded.serialized_classifier, b"first");
        assert_eq!(record(store, "alpha").classifier_generation, 1);
    }

    #[test]
    fn delete_removes_the_model_with_everything_stored_for_it() {
        let ts = setup_store();
        let store = &ts.store;
        let id = insert(store, "alpha", b"first");
        add_round_rows(store, id, 10);
        replace(store, "alpha", b"second", 2).unwrap();
        add_round_rows(store, id, 20);
        store
            .model_indicator_map()
            .insert(ModelIndicator {
                name: "indicator".to_string(),
                model_id: id,
                ..ModelIndicator::default()
            })
            .unwrap();
        // An orphan generation left by an interrupted write.
        store
            .classifier_fm
            .store_classifier(id, 7, b"orphan")
            .unwrap();
        let other = insert(store, "beta", b"beta");
        add_round_rows(store, other, 30);
        store
            .model_indicator_map()
            .insert(ModelIndicator {
                name: "other indicator".to_string(),
                model_id: other,
                ..ModelIndicator::default()
            })
            .unwrap();
        let other_rows: Vec<_> = MODEL_FAMILIES
            .into_iter()
            .filter(|family| *family != tables::MODELS && *family != tables::MODEL_INDICATORS)
            .map(|family| rows_of(store, family, other))
            .collect();

        store.delete_model("alpha").unwrap();

        for family in MODEL_FAMILIES {
            if family == tables::MODELS || family == tables::MODEL_INDICATORS {
                continue;
            }
            assert_eq!(rows_of(store, family, id), Entries::new(), "{family}");
        }
        assert!(store.model_map().load_model_by_name("alpha").is_err());
        assert!(
            store
                .model_indicator_map()
                .get("indicator")
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .previous_training_results()
                .csv_column_extra_map()
                .get_by_model(id)
                .unwrap()
                .is_none()
        );
        assert!(!model_dir(store, id).exists());

        assert!(
            store
                .model_indicator_map()
                .get("other indicator")
                .unwrap()
                .is_some()
        );
        let after: Vec<_> = MODEL_FAMILIES
            .into_iter()
            .filter(|family| *family != tables::MODELS && *family != tables::MODEL_INDICATORS)
            .map(|family| rows_of(store, family, other))
            .collect();
        assert_eq!(after, other_rows);
        assert_eq!(
            store
                .load_model_by_name("beta")
                .unwrap()
                .serialized_classifier,
            b"beta"
        );
        assert!(store.delete_model("alpha").is_err());
    }

    /// A post-commit removal that fails leaves its target behind and does not
    /// fail the operation, whose commit has already taken effect.
    #[test]
    fn a_failed_post_commit_removal_does_not_fail_the_operation() {
        // A non-empty directory where a classifier file was cannot be removed
        // as a file.
        fn block_file_removal(path: &Path) {
            std::fs::remove_file(path).unwrap();
            std::fs::create_dir(path).unwrap();
            std::fs::write(path.join("blocker"), b"").unwrap();
        }

        let ts = setup_store();
        let store = &ts.store;
        let id = insert(store, "alpha", b"first");
        replace(store, "alpha", b"second", 2).unwrap();

        // A replace removes the earlier previous file, generation 1.
        let first = store.classifier_fm.create_classifier_path(id, 1);
        block_file_removal(&first);
        assert_eq!(
            replace(store, "alpha", b"third", 3).unwrap(),
            ReplacedModel {
                id,
                inserted: false
            }
        );
        let replaced = record(store, "alpha");
        assert_eq!(replaced.classifier_generation, 3);
        assert_eq!(replaced.previous.unwrap().classifier_generation, 2);
        assert!(first.is_dir());

        // An analysis round removes the earlier current file, generation 3.
        let third = store.classifier_fm.create_classifier_path(id, 3);
        block_file_removal(&third);
        store
            .update_model(crate::model::Model {
                id: i32::try_from(id).unwrap(),
                ..body("alpha", b"round", 4)
            })
            .unwrap();
        assert_eq!(record(store, "alpha").classifier_generation, 4);
        assert_eq!(
            store
                .load_model_by_name("alpha")
                .unwrap()
                .serialized_classifier,
            b"round"
        );
        assert!(third.is_dir());

        // A delete removes the model directory, which a file cannot be
        // removed as.
        let dir = model_dir(store, id);
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::write(&dir, b"blocker").unwrap();
        store.delete_model("alpha").unwrap();
        assert!(store.model_map().load_model_by_name("alpha").is_err());
        assert!(dir.is_file());
    }

    #[test]
    fn load_model_by_name_returns_the_stored_scores() {
        let ts = setup_store();
        let store = &ts.store;
        let id = insert(store, "alpha", b"first");
        assert_eq!(
            store.load_model_by_name("alpha").unwrap().scores,
            scores(0.5)
        );

        store
            .update_model(crate::model::Model {
                id: i32::try_from(id).unwrap(),
                scores: scores(0.25),
                ..body("alpha", b"round", 2)
            })
            .unwrap();
        assert_eq!(
            store.load_model_by_name("alpha").unwrap().scores,
            scores(0.25)
        );

        store
            .replace_model(
                crate::model::Model {
                    scores: scores(0.125),
                    ..body("alpha", b"second", 3)
                },
                owner(),
                at(300),
                trained(3, "run = 3"),
            )
            .unwrap();
        assert_eq!(
            store.load_model_by_name("alpha").unwrap().scores,
            scores(0.125)
        );

        store.scores_map().delete(id).unwrap();
        assert_eq!(
            store.load_model_by_name("alpha").unwrap().scores,
            ModelScores::default()
        );
    }

    #[test]
    fn update_clusters_applies_once_per_classification() {
        let ts = setup_store();
        let store = &ts.store;
        let id = insert(store, "alpha", b"first");
        let updates = [update_request(1, 100, 4), update_request(2, 200, 6)];
        let sizes = |store: &Store| {
            let mut clusters = store
                .cluster_map()
                .load_clusters(id, None, None, None, None, &None, &None, true, 10)
                .unwrap();
            clusters.sort_unstable_by_key(|cluster| cluster.id);
            clusters
                .into_iter()
                .map(|cluster| (cluster.size, cluster.event_ids))
                .collect::<Vec<_>>()
        };

        assert!(store.update_clusters(id, &updates).unwrap());
        assert!(!store.update_clusters(id, &updates).unwrap());
        assert_eq!(sizes(store), vec![(4, vec![100]), (6, vec![200])]);
        assert_eq!(record(store, "alpha").clusters_applied, Some(1));

        // A new classification applies the same updates again.
        store
            .update_model(crate::model::Model {
                id: i32::try_from(id).unwrap(),
                ..body("alpha", b"round", 2)
            })
            .unwrap();
        assert_eq!(record(store, "alpha").clusters_applied, Some(1));
        assert!(store.update_clusters(id, &updates).unwrap());
        assert!(!store.update_clusters(id, &updates).unwrap());
        // Merging keeps every event id, repeats included, as it always has.
        assert_eq!(
            sizes(store),
            vec![(8, vec![100, 100]), (12, vec![200, 200])]
        );

        // So does the first call after a replace, even for a classification
        // id applied before it.
        store
            .replace_model(
                body("alpha", b"second", 2),
                owner(),
                at(200),
                trained(2, "run = 2"),
            )
            .unwrap();
        assert_eq!(record(store, "alpha").clusters_applied, None);
        assert!(store.update_clusters(id, &updates).unwrap());
        assert!(!store.update_clusters(id, &updates).unwrap());
        assert_eq!(sizes(store), vec![(4, vec![100]), (6, vec![200])]);

        assert!(store.update_clusters(99, &updates).is_err());
    }

    const HELD: &str = "held";
    const WAITING: &str = "waiting";

    /// Runs `held` in a thread that stops at `point` until the test releases
    /// it, and `waiting` in another thread started while it is stopped, and
    /// returns both results.
    ///
    /// The held thread then fails at `point` if `fail` is set. Asserts that
    /// the model-files lock is held while it is stopped, and that the
    /// waiting thread takes the lock only after the release.
    fn run_while_held<A: Send, B: Send>(
        store: &Store,
        point: ModelFilesPoint,
        fail: bool,
        held: impl FnOnce() -> Result<A> + Send,
        waiting: impl FnOnce() -> Result<B> + Send,
    ) -> (Result<A>, Result<B>) {
        let (stopped_tx, stopped_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (locking_tx, locking_rx) = mpsc::channel();
        let release_rx = Mutex::new(release_rx);
        let log = Arc::new(Mutex::new(Vec::new()));
        let hook_log = Arc::clone(&log);
        store.set_model_files_hook(Some(Arc::new(move |at| {
            match (thread::current().name(), at) {
                (Some(HELD), at) if at == point => {
                    hook_log.lock().unwrap().push("held");
                    stopped_tx.send(()).unwrap();
                    release_rx.lock().unwrap().recv().unwrap();
                    if fail {
                        bail!("injected failure");
                    }
                }
                (Some(WAITING), ModelFilesPoint::Locking) => locking_tx.send(()).unwrap(),
                (Some(WAITING), ModelFilesPoint::Locked) => {
                    hook_log.lock().unwrap().push("waiting locked");
                }
                _ => {}
            }
            Ok(())
        })));

        let results = thread::scope(|s| {
            let held = thread::Builder::new()
                .name(HELD.to_string())
                .spawn_scoped(s, held)
                .unwrap();
            stopped_rx.recv().unwrap();
            assert!(matches!(
                store.model_files.try_lock(),
                Err(TryLockError::WouldBlock)
            ));
            let waiting = thread::Builder::new()
                .name(WAITING.to_string())
                .spawn_scoped(s, waiting)
                .unwrap();
            locking_rx.recv().unwrap();
            log.lock().unwrap().push("released");
            release_tx.send(()).unwrap();
            (held.join().unwrap(), waiting.join().unwrap())
        });
        store.set_model_files_hook(None);
        assert_eq!(
            *log.lock().unwrap(),
            vec!["held", "released", "waiting locked"]
        );
        results
    }

    #[test]
    fn a_replace_waits_for_a_replace_of_the_same_model() {
        let ts = setup_store();
        let store = &ts.store;
        let id = insert(store, "alpha", b"one");

        let (held, waiting) = run_while_held(
            store,
            ModelFilesPoint::BeforeCommit,
            false,
            || replace(store, "alpha", b"two", 2),
            || replace(store, "alpha", b"three", 3),
        );
        held.unwrap();
        waiting.unwrap();

        let record = record(store, "alpha");
        assert_eq!(record.classifier_generation, 3);
        assert_eq!(record.trained_run_id, 3);
        assert_eq!(record.previous.unwrap().classifier_generation, 2);
        assert_eq!(classifier(store, id, 3).unwrap(), b"three");
        assert_eq!(classifier(store, id, 2).unwrap(), b"two");
        assert_eq!(generations(store, id), HashSet::from([2, 3]));
    }

    #[test]
    fn a_replace_that_does_not_commit_leaves_the_files_of_the_one_that_does() {
        let ts = setup_store();
        let store = &ts.store;
        let id = insert(store, "alpha", b"one");

        let (held, waiting) = run_while_held(
            store,
            ModelFilesPoint::BeforeCommit,
            true,
            || replace(store, "alpha", b"two", 2),
            || replace(store, "alpha", b"three", 3),
        );
        assert!(held.is_err());
        waiting.unwrap();

        let record = record(store, "alpha");
        assert_eq!(record.classifier_generation, 2);
        assert_eq!(record.trained_run_id, 3);
        assert_eq!(record.previous.unwrap().classifier_generation, 1);
        assert_eq!(classifier(store, id, 2).unwrap(), b"three");
        assert_eq!(classifier(store, id, 1).unwrap(), b"one");
    }

    #[test]
    fn an_analysis_update_waits_for_a_replace() {
        let ts = setup_store();
        let store = &ts.store;
        let id = insert(store, "alpha", b"one");
        let round = crate::model::Model {
            id: i32::try_from(id).unwrap(),
            ..body("alpha", b"round", 9)
        };

        let (held, waiting) = run_while_held(
            store,
            ModelFilesPoint::BeforeCommit,
            false,
            || replace(store, "alpha", b"two", 2),
            || store.update_model(round),
        );
        held.unwrap();
        waiting.unwrap();

        let record = record(store, "alpha");
        assert_eq!(record.classifier_generation, 3);
        assert_eq!(record.classification_id, Some(9));
        assert_eq!(record.trained_run_id, 2);
        assert_eq!(record.previous.unwrap().classifier_generation, 1);
        assert_eq!(classifier(store, id, 3).unwrap(), b"round");
        assert_eq!(classifier(store, id, 1).unwrap(), b"one");
        assert_eq!(generations(store, id), HashSet::from([1, 3]));
    }

    #[test]
    fn an_analysis_update_that_does_not_commit_leaves_the_files_of_the_replace() {
        let ts = setup_store();
        let store = &ts.store;
        let id = insert(store, "alpha", b"one");
        let round = crate::model::Model {
            id: i32::try_from(id).unwrap(),
            ..body("alpha", b"round", 9)
        };

        let (held, waiting) = run_while_held(
            store,
            ModelFilesPoint::BeforeCommit,
            true,
            || store.update_model(round),
            || replace(store, "alpha", b"two", 2),
        );
        assert!(held.is_err());
        waiting.unwrap();

        let record = record(store, "alpha");
        assert_eq!(record.classifier_generation, 2);
        assert_eq!(record.classification_id, Some(2));
        assert_eq!(classifier(store, id, 2).unwrap(), b"two");
        assert_eq!(classifier(store, id, 1).unwrap(), b"one");
    }

    #[test]
    fn a_delete_waits_for_a_replace_of_another_model() {
        let ts = setup_store();
        let store = &ts.store;
        let alpha = insert(store, "alpha", b"one");
        let beta = insert(store, "beta", b"beta");

        let (held, waiting) = run_while_held(
            store,
            ModelFilesPoint::BeforeCommit,
            false,
            || replace(store, "alpha", b"two", 2),
            || store.delete_model("beta"),
        );
        held.unwrap();
        waiting.unwrap();

        assert_eq!(record(store, "alpha").classifier_generation, 2);
        assert_eq!(classifier(store, alpha, 2).unwrap(), b"two");
        assert!(store.model_map().load_model_by_name("beta").is_err());
        assert!(!model_dir(store, beta).exists());
    }

    #[test]
    fn a_model_inserted_under_a_freed_id_keeps_its_classifier() {
        let ts = setup_store();
        let store = &ts.store;
        let id = insert(store, "alpha", b"one");

        let (held, waiting) = run_while_held(
            store,
            ModelFilesPoint::AfterCommit,
            false,
            || store.delete_model("alpha"),
            || replace(store, "gamma", b"gamma", 1),
        );
        held.unwrap();
        let inserted = waiting.unwrap();

        assert_eq!(inserted, ReplacedModel { id, inserted: true });
        assert_eq!(
            store
                .load_model_by_name("gamma")
                .unwrap()
                .serialized_classifier,
            b"gamma"
        );
    }
}
