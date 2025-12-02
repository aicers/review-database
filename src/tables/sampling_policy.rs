//! The `SamplingPolicy` table.

use std::{borrow::Cow, net::IpAddr};

use anyhow::Result;
use chrono::{DateTime, Utc};
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use super::UniqueKey;
use crate::{
    Indexable, IndexedMap, IndexedMapUpdate, IndexedTable, collections::Indexed,
    types::FromKeyValue,
};

#[derive(Clone, Deserialize, Serialize)]
pub struct SamplingPolicy {
    pub id: u32,
    pub name: String,
    pub kind: Kind,
    pub interval: Interval,
    pub period: Period,
    pub offset: i32,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub node: Option<String>,
    pub column: Option<u32>,
    pub immutable: bool,
    pub creation_time: DateTime<Utc>,
}

impl FromKeyValue for SamplingPolicy {
    fn from_key_value(_key: &[u8], value: &[u8]) -> anyhow::Result<Self> {
        super::deserialize(value)
    }
}

impl UniqueKey for SamplingPolicy {
    type AsBytes<'a> = &'a [u8];

    fn unique_key(&self) -> &[u8] {
        self.name.as_bytes()
    }
}

impl Indexable for SamplingPolicy {
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
        super::serialize(&self).expect("serializable")
    }

    fn set_index(&mut self, index: u32) {
        self.id = index;
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[repr(u32)]
pub enum Interval {
    FiveMinutes = 0,
    TenMinutes = 1,
    FifteenMinutes = 2,
    ThirtyMinutes = 3,
    OneHour = 4,
}

#[derive(Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[repr(u32)]
pub enum Period {
    SixHours = 0,
    TwelveHours = 1,
    OneDay = 2,
}

#[derive(Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[repr(u32)]
pub enum Kind {
    Conn = 0,
    Dns = 1,
    Http = 2,
    Rdp = 3,
}

/// Functions for the `sampling_policy` indexed map.
impl<'d> IndexedTable<'d, SamplingPolicy> {
    /// Opens the `sampling policy` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        IndexedMap::new(db, super::SAMPLING_POLICY)
            .map(IndexedTable::new)
            .ok()
    }

    /// Updates the `SamplingPolicy` from `old` to `new`, given `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `id` is invalid or the database operation fails.
    pub fn update(&mut self, id: u32, old: &Update, new: &Update) -> Result<()> {
        self.indexed_map.update(id, old, new)
    }
}

#[derive(Clone)]
pub struct Update {
    pub name: String,
    pub kind: Kind,
    pub interval: Interval,
    pub period: Period,
    pub offset: i32,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub node: Option<String>,
    pub column: Option<u32>,
    pub immutable: bool,
}

impl From<SamplingPolicy> for Update {
    fn from(input: SamplingPolicy) -> Self {
        Self {
            name: input.name,
            kind: input.kind,
            interval: input.interval,
            period: input.period,
            offset: input.offset,
            src_ip: input.src_ip,
            dst_ip: input.dst_ip,
            node: input.node,
            column: input.column,
            immutable: input.immutable,
        }
    }
}

impl IndexedMapUpdate for Update {
    type Entry = SamplingPolicy;

    fn key(&self) -> Option<Cow<'_, [u8]>> {
        Some(Cow::Borrowed(self.name.as_bytes()))
    }

    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry, anyhow::Error> {
        value.name.clear();
        value.name.push_str(&self.name);
        value.kind = self.kind;
        value.interval = self.interval;
        value.period = self.period;
        value.offset = self.offset;

        value.src_ip = self.src_ip;

        value.dst_ip = self.dst_ip;

        value.node.clone_from(&self.node);

        value.column = self.column;

        value.immutable = self.immutable;

        Ok(value)
    }

    fn verify(&self, value: &Self::Entry) -> bool {
        if self.name != value.name {
            return false;
        }
        if self.kind != value.kind {
            return false;
        }
        if self.interval != value.interval {
            return false;
        }
        if self.period != value.period {
            return false;
        }
        if self.offset != value.offset {
            return false;
        }

        if let (Some(ip_self), Some(ip_value)) = (self.src_ip, value.src_ip) {
            if ip_self != ip_value {
                return false;
            }
        } else if self.src_ip.is_some() || value.src_ip.is_some() {
            return false;
        }

        if let (Some(ip_self), Some(ip_value)) = (self.dst_ip, value.dst_ip) {
            if ip_self != ip_value {
                return false;
            }
        } else if self.dst_ip.is_some() || value.dst_ip.is_some() {
            return false;
        }

        if self.node != value.node {
            return false;
        }

        if self.column != value.column {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{
        SamplingInterval, SamplingKind, SamplingPeriod, SamplingPolicy, SamplingPolicyUpdate, Store,
    };

    #[test]
    fn update() {
        let (_permit, store) = setup_store();
        let mut table = store.sampling_policy_map();

        let sp = create_sampling_policy("a");
        let id = table.put(sp.clone()).unwrap();

        let old: SamplingPolicyUpdate = sp.into();
        let new = create_sampling_policy("b");
        let update: SamplingPolicyUpdate = new.clone().into();

        assert!(table.update(id, &old, &update).is_ok());
        assert_eq!(table.count().unwrap(), 1);
        let entry = table.get_by_id(id).unwrap();
        assert_eq!(entry.map(|e| e.name), Some("b".to_string()));
    }

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        (permit, store)
    }

    fn create_sampling_policy(name: &str) -> SamplingPolicy {
        SamplingPolicy {
            name: name.to_string(),
            kind: SamplingKind::Conn,
            interval: SamplingInterval::FifteenMinutes,
            period: SamplingPeriod::TwelveHours,
            id: 0,
            src_ip: None,
            dst_ip: None,
            offset: 0,
            node: None,
            column: None,
            immutable: false,
            creation_time: chrono::Utc::now(),
        }
    }
}
