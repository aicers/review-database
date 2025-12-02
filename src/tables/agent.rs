//! The agent table.

use std::mem::size_of;

use anyhow::Result;
use num_derive::{FromPrimitive, ToPrimitive};
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};
use strum_macros::EnumString;

use super::{AgentConfig, AgentStatus};
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
    pub node: u32,
    pub key: String,
    pub kind: AgentKind,
    pub status: AgentStatus,
    pub config: Option<AgentConfig>,
    pub draft: Option<AgentConfig>,
}

impl Agent {
    /// # Errors
    ///
    /// Returns an error if `config` fails to be `validate`-ed.
    pub fn new(
        node: u32,
        key: String,
        kind: AgentKind,
        status: AgentStatus,
        config: Option<String>,
        draft: Option<String>,
    ) -> Result<Self> {
        let config = config.map(TryInto::try_into).transpose()?;
        let draft = draft.map(TryInto::try_into).transpose()?;
        Ok(Self {
            node,
            key,
            kind,
            status,
            config,
            draft,
        })
    }
}

impl FromKeyValue for Agent {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let value: Value = super::deserialize(value)?;

        let (node, key) = key.split_at(size_of::<u32>());
        let mut buf = [0; size_of::<u32>()];
        buf.copy_from_slice(node);
        let node = u32::from_be_bytes(buf);
        let key = std::str::from_utf8(key)?.to_string();

        Ok(Self {
            node,
            key,
            kind: value.kind,
            status: value.status,
            config: value.config,
            draft: value.draft,
        })
    }
}

impl UniqueKey for Agent {
    type AsBytes<'a> = Vec<u8>;

    fn unique_key(&self) -> Vec<u8> {
        let mut buf = self.node.to_be_bytes().to_vec();
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
        };
        super::serialize(&value).expect("serializable")
    }
}

#[derive(Serialize, Deserialize)]
struct Value {
    kind: AgentKind,
    status: AgentStatus,
    config: Option<AgentConfig>,
    draft: Option<AgentConfig>,
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

    /// Returns an agent with the given `node` and `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the agent does not exist or the database operation fails.
    pub fn get(&self, node: u32, id: &str) -> Result<Option<Agent>> {
        let mut key = node.to_be_bytes().to_vec();
        key.extend(id.as_bytes());
        let Some(value) = self.map.get(&key)? else {
            return Ok(None);
        };
        Ok(Some(Agent::from_key_value(&key, value.as_ref())?))
    }

    /// Deletes the agent with given `node` and `id`.
    ///
    /// # Errors
    ///
    /// Returns `None` if the table does not exist.
    pub fn delete(&self, node: u32, id: &str) -> Result<()> {
        let mut key = node.to_be_bytes().to_vec();
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
    use crate::Store;
    use crate::test::{DbGuard, acquire_db_permit};

    const VALID_TOML: &str = r#"test = "true""#;

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        (permit, store)
    }

    fn create_agent(
        node: u32,
        key: &str,
        kind: AgentKind,
        config: Option<&str>,
        draft: Option<&str>,
    ) -> Agent {
        Agent::new(
            node,
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
        assert_eq!(agent.node, 1);
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
}
