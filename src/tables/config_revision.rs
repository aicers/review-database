//! The configuration revisions of engine instances.
//!
//! An engine instance, an [`Agent`] of kind [`AgentKind::SemiSupervised`] or
//! [`AgentKind::Unsupervised`] named by its node id and agent key, has a
//! configuration revision: a number that rises each time the content of its
//! applied document, `Agent::config`, changes. Two column families keep it.
//!
//! - `config revisions` holds, under the agent's key, the highest number
//!   ever issued for the pair and the instance's current revision. The row
//!   outlives the agent, so a number is never issued twice for one pair.
//! - `config revision history` holds the completed document of every issued
//!   revision, with the time it was applied and the customer the node
//!   belonged to then. A row is removed only with the history of its
//!   customer.
//!
//! Every writer of an agent row computes what the write does to the revision
//! with [`ConfigRevisions::prepare`], before it stages anything, and records
//! it with [`ConfigRevisions::apply`] in the same transaction as the row.

use std::collections::HashMap;

use anyhow::{Context, Result};
use jiff::Timestamp;
use rocksdb::{OptimisticTransactionDB, Transaction};
use serde::{Deserialize, Serialize};

use super::{Agent, AgentConfig, AgentKind, InnerNode, Model, engine_instance};
use crate::{
    ClusteringModelTypeRef, CompletionMode, DetectionModelsSectionError, EXCLUSIVE, IndexedTable,
    Map, ModelInstance, collections::KeyIndex, complete_engine_document,
    detection_model::detector_models, timestamp::ts_nanoseconds_saturating,
};

/// The points in this module where a test can commit a concurrent write.
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum HookPoint {
    /// Between reading the node index and reading the node row it names.
    NodeLookup,
    /// After the history iterator of a customer history removal is created.
    HistoryScan,
    /// After the model records an Unsupervised Engine document names are
    /// read for its completion, before it is completed.
    ModelLookup,
}

/// A test hook, run once on the thread that set it.
#[cfg(test)]
type Hook = Box<dyn FnOnce(&OptimisticTransactionDB)>;

#[cfg(test)]
thread_local! {
    static HOOK: std::cell::RefCell<Option<(HookPoint, Hook)>> =
        const { std::cell::RefCell::new(None) };
    static FAIL_MODEL_READS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Sets whether, on this thread, every read of a model record for the
/// completion of an Unsupervised Engine document fails.
#[cfg(test)]
pub(crate) fn fail_model_reads(fail: bool) {
    FAIL_MODEL_READS.with(|slot| slot.set(fail));
}

/// Sets `hook` to run, on this thread, the next time a write reaches
/// `point`.
#[cfg(test)]
pub(crate) fn set_hook(point: HookPoint, hook: impl FnOnce(&OptimisticTransactionDB) + 'static) {
    HOOK.with(|slot| *slot.borrow_mut() = Some((point, Box::new(hook))));
}

#[cfg(test)]
fn run_hook(point: HookPoint, db: &OptimisticTransactionDB) {
    let hook = HOOK.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.as_ref().is_some_and(|(at, _)| *at == point) {
            slot.take().map(|(_, hook)| hook)
        } else {
            None
        }
    });
    if let Some(hook) = hook {
        hook(db);
    }
}

/// A configuration revision of an engine instance, as its history row
/// records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigRevisionRecord {
    /// The completed engine configuration document the revision stored.
    pub document: String,
    /// The time of the write that stored it.
    pub applied_at: Timestamp,
    /// The customer of the node's applied profile, else of its draft
    /// profile, as the write left the node; `None` if it had neither.
    pub customer_id: Option<u32>,
}

/// The persisted revision state of one `(node id, agent key)` pair.
#[derive(Clone, Copy, Default, Deserialize, Serialize)]
struct State {
    /// The highest revision number ever issued for the pair; 0 before the
    /// first.
    last_issued: u64,
    /// The number recorded by the write that stored the agent's current
    /// `config`, or `None` if there is none.
    current: Option<u64>,
}

/// The persisted form of a [`ConfigRevisionRecord`].
#[derive(Deserialize, Serialize)]
struct HistoryValue {
    document: String,
    #[serde(with = "ts_nanoseconds_saturating")]
    applied_at: Timestamp,
    customer_id: Option<u32>,
}

/// Where the customer id of a revision a write records comes from.
#[derive(Clone, Copy)]
pub(crate) enum CustomerOf {
    /// The writer knows the node's profiles as the write leaves them.
    Known(Option<u32>),
    /// The node row the agent belongs to is read within the transaction.
    Node,
}

impl CustomerOf {
    /// Returns the customer id the profiles `profile` and `profile_draft`
    /// give: the applied profile's, else the draft's.
    pub(crate) fn of_profiles(
        profile: Option<&super::NodeProfile>,
        profile_draft: Option<&super::NodeProfile>,
    ) -> Self {
        Self::Known(profile.or(profile_draft).map(|p| p.customer_id))
    }
}

/// An agent row a writer stored, and the revision number its write issued.
pub(crate) struct Written {
    /// The row as stored, its `config` completed where completion ran.
    pub(crate) row: Agent,
    /// The revision number the write issued, or `None` if it issued none.
    pub(crate) revision: Option<u64>,
}

/// What a write does to the revision of the instance at its key.
enum Change {
    /// The stored `config` and its current revision stay as they are.
    Keep,
    /// The key has no current revision afterwards.
    Clear,
    /// A new revision is recorded.
    Issue {
        number: u64,
        document: String,
        customer_id: Option<u32>,
    },
}

/// An agent write whose checks have passed and whose revision is decided,
/// ready to be staged by [`ConfigRevisions::apply`].
pub(crate) struct Prepared {
    row: Agent,
    change: Change,
}

impl Prepared {
    /// Returns the row the write stores.
    pub(crate) fn row(&self) -> &Agent {
        &self.row
    }
}

/// The two column families of the configuration revisions, the node table a
/// revision's customer is read from, and the model records the completion of
/// an Unsupervised Engine document reads.
pub(crate) struct ConfigRevisions<'d> {
    db: &'d OptimisticTransactionDB,
    states: Map<'d>,
    history: Map<'d>,
    nodes: Map<'d>,
    models: IndexedTable<'d, Model>,
}

impl<'d> ConfigRevisions<'d> {
    pub(crate) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Some(Self {
            db,
            states: Map::open(db, super::CONFIG_REVISIONS)?,
            history: Map::open(db, super::CONFIG_REVISION_HISTORY)?,
            nodes: Map::open(db, super::NODES)?,
            models: IndexedTable::<Model>::open(db)?,
        })
    }

    /// Completes `document`, the engine document of an agent of `kind`, in
    /// `mode` with [`complete_engine_document`], within `txn`.
    ///
    /// For an [`AgentKind::Unsupervised`] document, the record of every model
    /// its `[[detectors]]` name is read first within `txn`, which sees its own
    /// writes, and written back unchanged, so that a concurrent write of any
    /// of them conflicts with `txn` whichever commits first; completion is
    /// given the clustering model type of each record, and `None` for a name
    /// with no record.
    ///
    /// # Errors
    ///
    /// Returns an error if a model record cannot be read or written back. A
    /// completion failure is returned inside the `Ok`.
    pub(crate) fn complete_in_transaction(
        &self,
        txn: &Transaction<OptimisticTransactionDB>,
        kind: AgentKind,
        document: &str,
        mode: CompletionMode,
    ) -> Result<std::result::Result<String, DetectionModelsSectionError>> {
        if kind != AgentKind::Unsupervised {
            return Ok(complete_engine_document(kind, document, &|_| None, mode));
        }
        let mut types: HashMap<String, ClusteringModelTypeRef> = HashMap::new();
        for name in detector_models(document) {
            #[cfg(test)]
            if FAIL_MODEL_READS.with(std::cell::Cell::get) {
                anyhow::bail!("cannot read model {name:?}: injected failure");
            }
            let record = self
                .models
                .load_model_by_name_in_transaction(&name, txn)
                .with_context(|| format!("cannot read model {name:?}"))?;
            self.models
                .write_back_in_transaction(&name, record.as_ref(), txn)?;
            if let Some(record) = record {
                types.insert(name, record.clustering_model_type);
            }
        }
        #[cfg(test)]
        run_hook(HookPoint::ModelLookup, self.db);
        Ok(complete_engine_document(
            kind,
            document,
            &|name| types.get(name).cloned(),
            mode,
        ))
    }

    /// Returns the current revision of `instance`; `None` if the agent is
    /// absent, is not an engine kind, has no `config`, or has a `config`
    /// stored before revisions were recorded and never written since.
    ///
    /// The agent row and the revision state are read from one snapshot.
    pub(crate) fn current(
        &self,
        agents: &rocksdb::ColumnFamily,
        instance: &ModelInstance,
    ) -> Result<Option<u64>> {
        let key = engine_instance::key(instance.node_id, &instance.agent_key);
        let snapshot = self.db.snapshot();
        let Some(agent) = snapshot
            .get_cf(agents, &key)
            .context("cannot read agent")?
            .map(|value| <Agent as crate::types::FromKeyValue>::from_key_value(&key, &value))
            .transpose()?
        else {
            return Ok(None);
        };
        if !is_engine(agent.kind) || agent.config.is_none() {
            return Ok(None);
        }
        let state: State = snapshot
            .get_cf(self.states.cf, &key)
            .context("cannot read config revision state")?
            .map_or(Ok(State::default()), |value| super::deserialize(&value))?;
        Ok(state.current)
    }

    /// Returns the history row of revision `revision` of `instance`, or
    /// `None` if it was never issued or has been removed.
    pub(crate) fn record(
        &self,
        instance: &ModelInstance,
        revision: u64,
    ) -> Result<Option<ConfigRevisionRecord>> {
        let key = history_key(instance.node_id, &instance.agent_key, revision)?;
        let Some(value) = self.history.get(&key)? else {
            return Ok(None);
        };
        let value: HistoryValue = super::deserialize(value.as_ref())?;
        Ok(Some(ConfigRevisionRecord {
            document: value.document,
            applied_at: value.applied_at,
            customer_id: value.customer_id,
        }))
    }

    /// Decides, within `txn` and without staging anything, what storing
    /// `new` at its key does, given `prior`, the row stored at that key
    /// before the write (`None` if the key is empty or the write moves the
    /// row there from another key).
    ///
    /// When `new` gives an engine document, an engine kind with a `config`,
    /// the document is completed in [`CompletionMode::Apply`] by
    /// [`complete_in_transaction`](Self::complete_in_transaction), which
    /// reads the model records an Unsupervised Engine document names within
    /// `txn`, unless `prior` is of the same kind and carries the same
    /// `config` bytes; the completed document is what the write stores, and
    /// a new revision is issued unless `prior` is of the same kind and
    /// carries the completed bytes. Otherwise the key has no current revision
    /// afterwards.
    ///
    /// # Errors
    ///
    /// Returns an error that carries the [`DetectionModelsSectionError`]
    /// if completion fails, or an error if the database operation fails,
    /// including the read of a model record.
    pub(crate) fn prepare(
        &self,
        txn: &Transaction<OptimisticTransactionDB>,
        prior: Option<&Agent>,
        new: &Agent,
        customer: CustomerOf,
    ) -> Result<Prepared> {
        let mut row = new.clone();
        let Some(config) = new.config.as_ref().filter(|_| is_engine(new.kind)) else {
            return Ok(Prepared {
                row,
                change: Change::Clear,
            });
        };
        let prior_config = prior
            .filter(|prior| prior.kind == new.kind)
            .and_then(|prior| prior.config.as_ref());
        if prior_config.is_some_and(|prior| prior.as_ref() == config.as_ref()) {
            return Ok(Prepared {
                row,
                change: Change::Keep,
            });
        }
        let completed = self
            .complete_in_transaction(txn, new.kind, config.as_ref(), CompletionMode::Apply)?
            .with_context(|| {
                format!(
                    "cannot complete the engine document of agent {} on node {}",
                    new.key, new.node_id
                )
            })?;
        if let Some(prior_config) = prior_config.filter(|prior| prior.as_ref() == completed) {
            row.config = Some(prior_config.clone());
            return Ok(Prepared {
                row,
                change: Change::Keep,
            });
        }
        row.config = Some(
            AgentConfig::try_from(completed.clone())
                .context("the completed engine document is not valid TOML")?,
        );
        let state = self.state_for_update(txn, &row.unique_key_bytes())?;
        let number = state
            .last_issued
            .checked_add(1)
            .context("no configuration revision number is left to issue")?;
        let customer_id = match customer {
            CustomerOf::Known(customer_id) => customer_id,
            CustomerOf::Node => self.customer_of_node(txn, new.node_id)?,
        };
        Ok(Prepared {
            row,
            change: Change::Issue {
                number,
                document: completed,
                customer_id,
            },
        })
    }

    /// Stages, within `txn`, what `prepared` decided for the revision of the
    /// key its row is stored at; the caller stages the row itself.
    pub(crate) fn apply(
        &self,
        txn: &Transaction<OptimisticTransactionDB>,
        prepared: Prepared,
    ) -> Result<Written> {
        let Prepared { row, change } = prepared;
        let revision = match change {
            Change::Keep => None,
            Change::Clear => {
                self.clear_current(txn, row.node_id, &row.key)?;
                None
            }
            Change::Issue {
                number,
                document,
                customer_id,
            } => {
                let key = row.unique_key_bytes();
                let value = HistoryValue {
                    document,
                    applied_at: Timestamp::now(),
                    customer_id,
                };
                self.history.put_with_transaction(
                    &history_key(row.node_id, &row.key, number)?,
                    &super::serialize(&value)?,
                    txn,
                )?;
                let state = State {
                    last_issued: number,
                    current: Some(number),
                };
                self.states
                    .put_with_transaction(&key, &super::serialize(&state)?, txn)?;
                Some(number)
            }
        };
        Ok(Written { row, revision })
    }

    /// Stages, within `txn`, that the key of agent `agent_key` on node
    /// `node_id` has no current revision; the highest number issued for it
    /// and its history stay.
    pub(crate) fn clear_current(
        &self,
        txn: &Transaction<OptimisticTransactionDB>,
        node_id: u32,
        agent_key: &str,
    ) -> Result<()> {
        self.clear_current_at(txn, &engine_instance::key(node_id, agent_key))
    }

    /// Stages, within `txn`, that the agent row key `key` has no current
    /// revision, as [`clear_current`](Self::clear_current) does.
    pub(crate) fn clear_current_at(
        &self,
        txn: &Transaction<OptimisticTransactionDB>,
        key: &[u8],
    ) -> Result<()> {
        let state = self.state_for_update(txn, key)?;
        if state.current.is_none() {
            return Ok(());
        }
        let state = State {
            current: None,
            ..state
        };
        self.states
            .put_with_transaction(key, &super::serialize(&state)?, txn)
    }

    /// Removes, in one transaction, every history row whose customer id is
    /// `customer_id`, and returns how many it removed.
    ///
    /// The scan that finds the rows is not tracked for conflicts, so each one
    /// found is read again for update before it is removed and counted: a
    /// row a concurrent call removed first is then either gone, and skipped,
    /// or its removal conflicts with this transaction, which is retried.
    pub(crate) fn remove_customer_history(&self, customer_id: u32) -> Result<usize> {
        loop {
            let txn = self.db.transaction();
            let mut removed = 0;
            let iter = txn.iterator_cf(self.history.cf, rocksdb::IteratorMode::Start);
            #[cfg(test)]
            run_hook(HookPoint::HistoryScan, self.db);
            for item in iter {
                let (key, value) = item.context("cannot read config revision history")?;
                let value: HistoryValue = super::deserialize(&value)?;
                if value.customer_id != Some(customer_id) {
                    continue;
                }
                if txn
                    .get_for_update_cf(self.history.cf, &key, EXCLUSIVE)
                    .context("cannot read config revision history")?
                    .is_none()
                {
                    continue;
                }
                txn.delete_cf(self.history.cf, &key)
                    .context("cannot remove config revision history")?;
                removed += 1;
            }
            match txn.commit() {
                Ok(()) => return Ok(removed),
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to remove config revision history");
                    }
                }
            }
        }
    }

    /// Returns the revision state stored under `key`, read for update within
    /// `txn`.
    fn state_for_update(
        &self,
        txn: &Transaction<OptimisticTransactionDB>,
        key: &[u8],
    ) -> Result<State> {
        txn.get_for_update_cf(self.states.cf, key, EXCLUSIVE)
            .context("cannot read config revision state")?
            .map_or(Ok(State::default()), |value| super::deserialize(&value))
    }

    /// Returns the customer id of node `node_id` as `txn` sees it: that of
    /// its applied profile, else of its draft profile; `None` if it has
    /// neither or does not exist.
    ///
    /// The node row is read for update, so a concurrent change of it
    /// conflicts with `txn`. The index that finds it is read for update only
    /// when it names no node `node_id`, so that the write does not conflict
    /// with every node write; a row found through an index entry that a
    /// concurrent rename or removal has since made stale is either gone or
    /// another node's, and the lookup is then made again.
    fn customer_of_node(
        &self,
        txn: &Transaction<OptimisticTransactionDB>,
        node_id: u32,
    ) -> Result<Option<u32>> {
        loop {
            let Some(name) = node_name(
                txn.get_cf(self.nodes.cf, [])
                    .context("cannot read node index")?,
                node_id,
            )?
            else {
                let tracked = txn
                    .get_for_update_cf(self.nodes.cf, [], EXCLUSIVE)
                    .context("cannot read node index")?;
                if node_name(tracked, node_id)?.is_some() {
                    continue;
                }
                return Ok(None);
            };
            #[cfg(test)]
            run_hook(HookPoint::NodeLookup, self.db);
            let Some(value) = txn
                .get_for_update_cf(self.nodes.cf, &name, EXCLUSIVE)
                .context("cannot read node")?
            else {
                continue;
            };
            let node: InnerNode = super::deserialize(&value)?;
            if node.id != node_id {
                continue;
            }
            return Ok(node
                .profile
                .as_ref()
                .or(node.profile_draft.as_ref())
                .map(|profile| profile.customer_id));
        }
    }
}

/// Returns the name the node index `index` gives node `node_id`, or `None` if
/// there is no index or it names no such node.
fn node_name(index: Option<Vec<u8>>, node_id: u32) -> Result<Option<Vec<u8>>> {
    let Some(index) = index else {
        return Ok(None);
    };
    Ok(KeyIndex::from_bytes(index)?
        .get(node_id)?
        .map(<[u8]>::to_vec))
}

/// Returns whether agents of `kind` are engine instances, whose `config` is
/// an engine configuration document with revisions.
pub(crate) fn is_engine(kind: AgentKind) -> bool {
    match kind {
        AgentKind::SemiSupervised | AgentKind::Unsupervised => true,
        AgentKind::Sensor | AgentKind::TimeSeriesGenerator | AgentKind::LogCollector => false,
    }
}

/// Returns the key of the history row of revision `revision` of the agent
/// `agent_key` on node `node_id`: the node id, the length of the agent key
/// and the agent key, then the revision, all integers big-endian, so the
/// rows of one instance are contiguous and in revision order.
fn history_key(node_id: u32, agent_key: &str, revision: u64) -> Result<Vec<u8>> {
    let len = u32::try_from(agent_key.len()).context("agent key too long")?;
    let mut key = Vec::with_capacity(4 + 4 + agent_key.len() + 8);
    key.extend(node_id.to_be_bytes());
    key.extend(len.to_be_bytes());
    key.extend(agent_key.as_bytes());
    key.extend(revision.to_be_bytes());
    Ok(key)
}

impl Agent {
    /// Returns the key of this agent's row, as bytes.
    pub(crate) fn unique_key_bytes(&self) -> Vec<u8> {
        engine_instance::key(self.node_id, &self.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_keys_do_not_collide_across_agent_keys() {
        // "a" followed by a revision whose first byte is `b` must not equal
        // "ab" followed by another revision.
        let one = history_key(1, "a", u64::from(b'b') << 56).unwrap();
        let two = history_key(1, "ab", 0).unwrap();
        assert_ne!(one, two);
        assert!(history_key(1, "a", 1).unwrap() < history_key(1, "a", 2).unwrap());
    }

    #[test]
    fn engine_kinds() {
        assert!(is_engine(AgentKind::SemiSupervised));
        assert!(is_engine(AgentKind::Unsupervised));
        assert!(!is_engine(AgentKind::Sensor));
        assert!(!is_engine(AgentKind::TimeSeriesGenerator));
        assert!(!is_engine(AgentKind::LogCollector));
    }
}
