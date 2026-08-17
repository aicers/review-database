//! The agent table.

use std::mem::size_of;

use anyhow::Result;
use num_derive::{FromPrimitive, ToPrimitive};
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};
use strum_macros::EnumString;

use super::{AgentConfig, AgentStatus, Lifecycle};
use crate::{Map, Table, UniqueKey, tables::Value as ValueTrait, types::FromKeyValue};

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Copy,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    EnumString,
    FromPrimitive,
    ToPrimitive,
)]
#[repr(u32)]
#[strum(serialize_all = "snake_case")]
pub enum AgentKind {
    Unsupervised = 1,
    Sensor = 2,
    SemiSupervised = 3,
    TimeSeriesGenerator = 4,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Agent {
    pub node_id: u32,
    pub key: String,
    pub kind: AgentKind,
    pub status: AgentStatus,
    pub config: Option<AgentConfig>,
    pub draft: Option<AgentConfig>,
    /// The version of the build installed on the host, as the host reports it.
    ///
    /// An opaque display label, not required to be semver. Build identity is
    /// `(installed_version, installed_commit)`; the version alone does not
    /// identify a build.
    pub installed_version: Option<String>,
    /// The commit of the build installed on the host, as the host reports it.
    pub installed_commit: Option<String>,
    /// The install and run state of the build on the host.
    pub lifecycle: Lifecycle,
    /// The addresses this instance actually bound, as `(config key, host:port)`
    /// pairs reported by the host.
    ///
    /// Agents dial out on an ephemeral port and bind no service address, so this
    /// stays empty for them; it is `ExternalService` that carries entries. It is
    /// observed state and is never derived from `config` or `draft`.
    pub bound_addrs: Vec<(String, String)>,
}

impl Agent {
    /// Creates a newly registered agent, with no build installed yet.
    ///
    /// `installed_version`, `installed_commit`, `lifecycle` and `bound_addrs`
    /// describe what a host reports, and registration precedes any report, so
    /// they start empty and [`Lifecycle::NotInstalled`] respectively. Install
    /// state is written afterwards by assigning to the fields of a record read
    /// back from the database.
    ///
    /// # Errors
    ///
    /// Returns an error if `config` fails to be `validate`-ed.
    pub fn new(
        node_id: u32,
        key: String,
        kind: AgentKind,
        status: AgentStatus,
        config: Option<String>,
        draft: Option<String>,
    ) -> Result<Self> {
        let config = config.map(TryInto::try_into).transpose()?;
        let draft = draft.map(TryInto::try_into).transpose()?;
        Ok(Self {
            node_id,
            key,
            kind,
            status,
            config,
            draft,
            installed_version: None,
            installed_commit: None,
            lifecycle: Lifecycle::NotInstalled,
            bound_addrs: Vec::new(),
        })
    }
}

impl FromKeyValue for Agent {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let value: Value = super::deserialize(value)?;

        let (node_id, key) = key.split_at(size_of::<u32>());
        let mut buf = [0; size_of::<u32>()];
        buf.copy_from_slice(node_id);
        let node_id = u32::from_be_bytes(buf);
        let key = std::str::from_utf8(key)?.to_string();

        Ok(Self {
            node_id,
            key,
            kind: value.kind,
            status: value.status,
            config: value.config,
            draft: value.draft,
            installed_version: value.installed_version,
            installed_commit: value.installed_commit,
            lifecycle: Lifecycle::from_stored_index(value.lifecycle),
            bound_addrs: value.bound_addrs,
        })
    }
}

impl UniqueKey for Agent {
    type AsBytes<'a> = Vec<u8>;

    fn unique_key(&self) -> Vec<u8> {
        let mut buf = self.node_id.to_be_bytes().to_vec();
        buf.extend(self.key.as_bytes());
        buf
    }
}

impl ValueTrait for Agent {
    type AsBytes<'a> = Vec<u8>;

    fn value(&self) -> Vec<u8> {
        let value = Value {
            kind: self.kind,
            status: self.status,
            config: self.config.clone(),
            draft: self.draft.clone(),
            installed_version: self.installed_version.clone(),
            installed_commit: self.installed_commit.clone(),
            lifecycle: self.lifecycle.to_stored_index(),
            bound_addrs: self.bound_addrs.clone(),
        };
        super::serialize(&value).expect("serializable")
    }
}

/// The persisted form of an [`Agent`].
///
/// `lifecycle` is the [`Lifecycle`] variant index rather than the enum itself:
/// a derived enum field fails the whole row when it meets a variant index this
/// build does not know, whereas a `u8` reads back and resolves to
/// [`Lifecycle::Unknown`]. The bytes are the same either way.
#[derive(Serialize, Deserialize)]
struct Value {
    kind: AgentKind,
    status: AgentStatus,
    config: Option<AgentConfig>,
    draft: Option<AgentConfig>,
    installed_version: Option<String>,
    installed_commit: Option<String>,
    lifecycle: u8,
    bound_addrs: Vec<(String, String)>,
}

/// Functions for the agents table.
impl<'d> Table<'d, Agent> {
    /// Opens the agents table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::AGENTS).map(Table::new)
    }

    #[allow(unused)]
    pub(crate) fn raw(&self) -> &Map<'_> {
        &self.map
    }

    /// Returns an agent with the given `node_id` and `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the agent does not exist or the database operation fails.
    pub fn get(&self, node_id: u32, id: &str) -> Result<Option<Agent>> {
        let mut key = node_id.to_be_bytes().to_vec();
        key.extend(id.as_bytes());
        let Some(value) = self.map.get(&key)? else {
            return Ok(None);
        };
        Ok(Some(Agent::from_key_value(&key, value.as_ref())?))
    }

    /// Deletes the agent with given `node_id` and `id`.
    ///
    /// # Errors
    ///
    /// Returns `None` if the table does not exist.
    pub fn delete(&self, node_id: u32, id: &str) -> Result<()> {
        let mut key = node_id.to_be_bytes().to_vec();
        key.extend(id.as_bytes());
        self.map.delete(&key)
    }

    /// Updates the `Agent` in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the serialization fails or the database operation fails.
    pub fn update(&self, old: &Agent, new: &Agent) -> Result<()> {
        let (ok, ov) = (old.unique_key(), old.value());
        let (nk, nv) = (new.unique_key(), new.value());
        self.map.update((&ok, &ov), (&nk, &nv))
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use super::*;
    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{Iterable, Store};

    const VALID_TOML: &str = r#"test = "true""#;

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path(), None).unwrap());
        (permit, store)
    }

    fn create_agent(
        node_id: u32,
        key: &str,
        kind: AgentKind,
        config: Option<&str>,
        draft: Option<&str>,
    ) -> Agent {
        Agent::new(
            node_id,
            key.to_string(),
            kind,
            AgentStatus::Enabled,
            config.map(ToString::to_string),
            draft.map(ToString::to_string),
        )
        .unwrap()
    }

    #[test]
    fn agent_creation() {
        let agent = create_agent(
            1,
            "test_key",
            AgentKind::Unsupervised,
            Some(VALID_TOML),
            Some(VALID_TOML),
        );
        assert_eq!(agent.node_id, 1);
        assert_eq!(agent.key, "test_key");
        assert_eq!(agent.kind, AgentKind::Unsupervised);
        assert_eq!(agent.config.as_ref().unwrap().as_ref(), VALID_TOML);
        assert_eq!(agent.draft.as_ref().unwrap().as_ref(), VALID_TOML);

        let invalid = "invalid";
        assert!(
            Agent::new(
                1,
                "test_key".to_string(),
                AgentKind::Unsupervised,
                AgentStatus::Enabled,
                Some(invalid.to_string()),
                Some(invalid.to_string()),
            )
            .is_err()
        );
    }

    #[test]
    fn config_try_from() {
        let config = AgentConfig::try_from(VALID_TOML.to_string()).unwrap();
        assert_eq!(config.as_ref(), VALID_TOML);
    }

    #[test]
    fn serialization() {
        let agent = create_agent(
            1,
            "test_key",
            AgentKind::Unsupervised,
            Some(VALID_TOML),
            Some(VALID_TOML),
        );
        let serialized = agent.value();
        let deserialized = Agent::from_key_value(&agent.unique_key(), &serialized).unwrap();
        assert_eq!(agent, deserialized);
    }

    #[test]
    fn operations() {
        let (_permit, store) = setup_store();
        let table = store.agents_map();

        let agent = create_agent(
            1,
            "test_key",
            AgentKind::Unsupervised,
            Some(VALID_TOML),
            None,
        );

        // Insert and retrieve agent
        assert!(table.insert(&agent).is_ok());
        let retrieved_agent = table.get(1, "test_key").unwrap().unwrap();
        assert_eq!(agent, retrieved_agent);

        let new_toml = r#"another_test = "abc""#;
        // Update agent
        let updated_agent = create_agent(
            1,
            "test_key",
            AgentKind::Sensor,
            Some(new_toml),
            Some(new_toml),
        );
        table.update(&agent, &updated_agent).unwrap();
        let retrieved_updated_agent = table.get(1, "test_key").unwrap().unwrap();
        assert_eq!(updated_agent, retrieved_updated_agent);

        // Delete agent
        table.delete(1, "test_key").unwrap();
        let result = table.get(1, "test_key").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn new_agent_has_no_install_state() {
        let agent = create_agent(1, "test_key", AgentKind::Sensor, Some(VALID_TOML), None);
        assert_eq!(agent.installed_version, None);
        assert_eq!(agent.installed_commit, None);
        assert_eq!(agent.lifecycle, Lifecycle::NotInstalled);
        assert!(agent.bound_addrs.is_empty());
    }

    #[test]
    fn install_state_round_trips() {
        let empty = create_agent(1, "test_key", AgentKind::Sensor, Some(VALID_TOML), None);
        let restored = Agent::from_key_value(&empty.unique_key(), &empty.value()).unwrap();
        assert_eq!(empty, restored);

        let mut populated = empty;
        populated.installed_version = Some("1.2.3".to_string());
        populated.installed_commit = Some("0123456789abcdef".to_string());
        populated.lifecycle = Lifecycle::Stopped;
        populated.bound_addrs = vec![
            ("first_addr".to_string(), "127.0.0.1:1111".to_string()),
            ("second_addr".to_string(), "[::1]:2222".to_string()),
        ];
        let restored = Agent::from_key_value(&populated.unique_key(), &populated.value()).unwrap();
        assert_eq!(populated, restored);
        assert_eq!(restored.bound_addrs, populated.bound_addrs);
    }

    #[test]
    fn every_lifecycle_round_trips_on_a_record() {
        let agent = create_agent(1, "test_key", AgentKind::Sensor, Some(VALID_TOML), None);
        for lifecycle in [
            Lifecycle::NotInstalled,
            Lifecycle::Installing,
            Lifecycle::Running,
            Lifecycle::Stopped,
            Lifecycle::Failed,
            Lifecycle::Removing,
            Lifecycle::Unknown,
        ] {
            let mut agent = agent.clone();
            agent.lifecycle = lifecycle;
            let restored = Agent::from_key_value(&agent.unique_key(), &agent.value()).unwrap();
            assert_eq!(restored.lifecycle, lifecycle);
        }
    }

    /// `status` and `lifecycle` are orthogonal: a config reload may have failed
    /// on a package that is up, and every pair must be storable.
    #[test]
    fn status_and_lifecycle_are_independent() {
        let mut agent = create_agent(1, "test_key", AgentKind::Sensor, Some(VALID_TOML), None);
        agent.status = AgentStatus::ReloadFailed;
        agent.lifecycle = Lifecycle::Running;
        let restored = Agent::from_key_value(&agent.unique_key(), &agent.value()).unwrap();
        assert_eq!(restored.status, AgentStatus::ReloadFailed);
        assert_eq!(restored.lifecycle, Lifecycle::Running);

        for status in [
            AgentStatus::Disabled,
            AgentStatus::Enabled,
            AgentStatus::ReloadFailed,
            AgentStatus::Unknown,
        ] {
            for lifecycle in [
                Lifecycle::NotInstalled,
                Lifecycle::Installing,
                Lifecycle::Running,
                Lifecycle::Stopped,
                Lifecycle::Failed,
                Lifecycle::Removing,
                Lifecycle::Unknown,
            ] {
                let mut agent = agent.clone();
                agent.status = status;
                agent.lifecycle = lifecycle;
                let restored = Agent::from_key_value(&agent.unique_key(), &agent.value()).unwrap();
                assert_eq!(restored.status, status);
                assert_eq!(restored.lifecycle, lifecycle);
            }
        }
    }

    /// A row carrying a lifecycle number this build does not know stays
    /// readable: it reads back as `Unknown`, with every other field intact.
    ///
    /// This is what fails if the persisted field is ever changed back to the
    /// `Lifecycle` type — the row would then error with `invalid value: integer
    /// 9, expected variant index 0 <= i < 7`.
    #[test]
    fn forged_lifecycle_number_still_deserializes() {
        let forged = Value {
            kind: AgentKind::SemiSupervised,
            status: AgentStatus::ReloadFailed,
            config: Some(VALID_TOML.to_string().try_into().unwrap()),
            draft: Some(VALID_TOML.to_string().try_into().unwrap()),
            installed_version: Some("1.2.3".to_string()),
            installed_commit: Some("cafebabe".to_string()),
            lifecycle: 9,
            bound_addrs: vec![("addr".to_string(), "127.0.0.1:1111".to_string())],
        };
        let serialized = super::super::serialize(&forged).unwrap();

        let mut key = 1_u32.to_be_bytes().to_vec();
        key.extend(b"test_key");
        let agent = Agent::from_key_value(&key, &serialized).unwrap();

        assert_eq!(agent.lifecycle, Lifecycle::Unknown);
        assert_ne!(agent.lifecycle, Lifecycle::NotInstalled);
        assert_eq!(agent.kind, AgentKind::SemiSupervised);
        assert_eq!(agent.status, AgentStatus::ReloadFailed);
        assert_eq!(agent.config.as_ref().unwrap().as_ref(), VALID_TOML);
        assert_eq!(agent.draft.as_ref().unwrap().as_ref(), VALID_TOML);
        assert_eq!(agent.installed_version.as_deref(), Some("1.2.3"));
        assert_eq!(agent.installed_commit.as_deref(), Some("cafebabe"));
        assert_eq!(
            agent.bound_addrs,
            vec![("addr".to_string(), "127.0.0.1:1111".to_string())]
        );
    }

    /// Storing the variant index in a `u8` is a representation choice, not a
    /// format change: the bytes are what a derived enum field would write.
    #[test]
    fn raw_index_is_byte_identical_to_a_derived_enum_field() {
        #[derive(Serialize)]
        struct ValueWithEnum {
            kind: AgentKind,
            status: AgentStatus,
            config: Option<AgentConfig>,
            draft: Option<AgentConfig>,
            installed_version: Option<String>,
            installed_commit: Option<String>,
            lifecycle: Lifecycle,
            bound_addrs: Vec<(String, String)>,
        }

        for lifecycle in [
            Lifecycle::NotInstalled,
            Lifecycle::Installing,
            Lifecycle::Running,
            Lifecycle::Stopped,
            Lifecycle::Failed,
            Lifecycle::Removing,
            Lifecycle::Unknown,
        ] {
            let raw = Value {
                kind: AgentKind::Sensor,
                status: AgentStatus::Enabled,
                config: Some(VALID_TOML.to_string().try_into().unwrap()),
                draft: None,
                installed_version: Some("1.2.3".to_string()),
                installed_commit: None,
                lifecycle: lifecycle.to_stored_index(),
                bound_addrs: vec![("addr".to_string(), "127.0.0.1:1111".to_string())],
            };
            let with_enum = ValueWithEnum {
                kind: raw.kind,
                status: raw.status,
                config: raw.config.clone(),
                draft: raw.draft.clone(),
                installed_version: raw.installed_version.clone(),
                installed_commit: raw.installed_commit.clone(),
                lifecycle,
                bound_addrs: raw.bound_addrs.clone(),
            };
            assert_eq!(
                super::super::serialize(&raw).unwrap(),
                super::super::serialize(&with_enum).unwrap()
            );
        }
    }

    #[test]
    fn table_operations_preserve_install_state() {
        let (_permit, store) = setup_store();
        let table = store.agents_map();

        let mut agent = create_agent(
            1,
            "001.piglet",
            AgentKind::Sensor,
            Some(VALID_TOML),
            Some(VALID_TOML),
        );
        agent.installed_version = Some("1.2.3".to_string());
        agent.installed_commit = Some("deadbeef".to_string());
        agent.lifecycle = Lifecycle::Installing;
        table.insert(&agent).unwrap();
        assert_eq!(table.get(1, "001.piglet").unwrap().unwrap(), agent);

        // Update only `lifecycle`.
        let mut running = agent.clone();
        running.lifecycle = Lifecycle::Running;
        table.update(&agent, &running).unwrap();
        let stored = table.get(1, "001.piglet").unwrap().unwrap();
        assert_eq!(stored, running);
        assert_eq!(stored.lifecycle, Lifecycle::Running);
        assert_eq!(stored.installed_commit.as_deref(), Some("deadbeef"));

        // Update only `installed_commit`.
        let mut rebuilt = running.clone();
        rebuilt.installed_commit = Some("feedface".to_string());
        table.update(&running, &rebuilt).unwrap();
        let stored = table.get(1, "001.piglet").unwrap().unwrap();
        assert_eq!(stored, rebuilt);
        assert_eq!(stored.installed_commit.as_deref(), Some("feedface"));
        assert_eq!(stored.lifecycle, Lifecycle::Running);
        assert_eq!(stored.installed_version.as_deref(), Some("1.2.3"));

        table.delete(1, "001.piglet").unwrap();
        assert!(table.get(1, "001.piglet").unwrap().is_none());
    }

    /// Two instances of the same component on one node are independent rows.
    #[test]
    fn instances_of_one_kind_coexist_on_a_node() {
        let (_permit, store) = setup_store();
        let table = store.agents_map();

        let mut first = create_agent(
            1,
            "001.piglet",
            AgentKind::Sensor,
            Some(VALID_TOML),
            Some(VALID_TOML),
        );
        first.installed_version = Some("1.0.0".to_string());
        first.installed_commit = Some("1111111".to_string());
        first.lifecycle = Lifecycle::Running;

        let second_toml = r#"second = "instance""#;
        let mut second = create_agent(1, "002.piglet", AgentKind::Sensor, Some(second_toml), None);
        second.installed_version = Some("2.0.0".to_string());
        second.installed_commit = Some("2222222".to_string());
        second.lifecycle = Lifecycle::Failed;

        table.insert(&first).unwrap();
        table.insert(&second).unwrap();

        let stored_first = table.get(1, "001.piglet").unwrap().unwrap();
        let stored_second = table.get(1, "002.piglet").unwrap().unwrap();
        assert_eq!(stored_first, first);
        assert_eq!(stored_second, second);
        assert_eq!(
            table
                .iter(rocksdb::Direction::Forward, None)
                .filter_map(Result::ok)
                .count(),
            2
        );

        table.delete(1, "001.piglet").unwrap();
        assert!(table.get(1, "001.piglet").unwrap().is_none());
        assert_eq!(table.get(1, "002.piglet").unwrap().unwrap(), second);
    }
}
