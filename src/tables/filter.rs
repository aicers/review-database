//! The `filter` map.

use anyhow::Result;
use chrono::{DateTime, Utc};
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use crate::{
    Iterable, Map, Table,
    event::{FilterEndpoint, FlowKind, LearningMethod},
    types::FromKeyValue,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PeriodForSearch {
    Recent(String),
    Custom(DateTime<Utc>, DateTime<Utc>),
}

pub struct Filter {
    pub username: String,
    pub name: String,
    pub directions: Option<Vec<FlowKind>>,
    pub keywords: Option<Vec<String>>,
    pub network_tags: Option<Vec<String>>,
    pub customers: Option<Vec<String>>,
    pub endpoints: Option<Vec<FilterEndpoint>>,
    pub sensors: Option<Vec<String>>,
    pub os: Option<Vec<String>>,
    pub devices: Option<Vec<String>>,
    pub hostnames: Option<Vec<String>>,
    pub user_ids: Option<Vec<String>>,
    pub user_names: Option<Vec<String>>,
    pub user_departments: Option<Vec<String>>,
    pub countries: Option<Vec<String>>,
    pub categories: Option<Vec<u8>>,
    pub levels: Option<Vec<u8>>,
    pub kinds: Option<Vec<String>>,
    pub learning_methods: Option<Vec<LearningMethod>>,
    pub confidence_min: Option<f32>,
    pub confidence_max: Option<f32>,
    pub period: PeriodForSearch,
}

impl Default for Filter {
    fn default() -> Self {
        Self {
            username: String::new(),
            name: String::new(),
            directions: None,
            keywords: None,
            network_tags: None,
            customers: None,
            endpoints: None,
            sensors: None,
            os: None,
            devices: None,
            hostnames: None,
            user_ids: None,
            user_names: None,
            user_departments: None,
            countries: None,
            categories: None,
            levels: None,
            kinds: None,
            learning_methods: None,
            confidence_min: None,
            confidence_max: None,
            period: PeriodForSearch::Recent("1 hour".to_string()),
        }
    }
}

impl Filter {
    fn create_key(username: &str, name: &str) -> Vec<u8> {
        let mut key = username.as_bytes().to_owned();
        key.push(0);
        key.extend(name.as_bytes());
        key
    }

    pub(crate) fn into_key_value(self) -> Result<(Vec<u8>, Vec<u8>)> {
        let key = Filter::create_key(&self.username, &self.name);
        let value = Value {
            directions: self.directions,
            keywords: self.keywords,
            network_tags: self.network_tags,
            customers: self.customers,
            endpoints: self.endpoints,
            sensors: self.sensors,
            os: self.os,
            devices: self.devices,
            hostnames: self.hostnames,
            user_ids: self.user_ids,
            user_names: self.user_names,
            user_departments: self.user_departments,
            countries: self.countries,
            categories: self.categories,
            levels: self.levels,
            kinds: self.kinds,
            learning_methods: self.learning_methods,
            confidence_min: self.confidence_min,
            confidence_max: self.confidence_max,
            period: self.period,
        };
        let value = super::serialize(&value)?;
        Ok((key, value))
    }
}

#[derive(Serialize, Deserialize)]
pub struct Value {
    pub(crate) directions: Option<Vec<FlowKind>>,
    pub(crate) keywords: Option<Vec<String>>,
    pub(crate) network_tags: Option<Vec<String>>,
    pub(crate) customers: Option<Vec<String>>,
    pub(crate) endpoints: Option<Vec<FilterEndpoint>>,
    pub(crate) sensors: Option<Vec<String>>,
    pub(crate) os: Option<Vec<String>>,
    pub(crate) devices: Option<Vec<String>>,
    pub(crate) hostnames: Option<Vec<String>>,
    pub(crate) user_ids: Option<Vec<String>>,
    pub(crate) user_names: Option<Vec<String>>,
    pub(crate) user_departments: Option<Vec<String>>,
    pub(crate) countries: Option<Vec<String>>,
    pub(crate) categories: Option<Vec<u8>>,
    pub(crate) levels: Option<Vec<u8>>,
    pub(crate) kinds: Option<Vec<String>>,
    pub(crate) learning_methods: Option<Vec<LearningMethod>>,
    pub(crate) confidence_min: Option<f32>,
    pub(crate) confidence_max: Option<f32>,
    pub(crate) period: PeriodForSearch,
}

impl FromKeyValue for Filter {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        use anyhow::anyhow;

        let sep = key
            .iter()
            .position(|c| *c == 0)
            .ok_or(anyhow!("corruptted access token"))?;
        let username = std::str::from_utf8(&key[..sep])?.to_string();
        let name = std::str::from_utf8(&key[sep + 1..])?.to_string();
        let value: Value = super::deserialize(value)?;
        Ok(Self {
            username,
            name,
            directions: value.directions,
            keywords: value.keywords,
            network_tags: value.network_tags,
            customers: value.customers,
            endpoints: value.endpoints,
            sensors: value.sensors,
            os: value.os,
            devices: value.devices,
            hostnames: value.hostnames,
            user_ids: value.user_ids,
            user_names: value.user_names,
            user_departments: value.user_departments,
            countries: value.countries,
            categories: value.categories,
            levels: value.levels,
            kinds: value.kinds,
            learning_methods: value.learning_methods,
            confidence_min: value.confidence_min,
            confidence_max: value.confidence_max,
            period: value.period,
        })
    }
}

/// Functions for the `filter` map.
impl<'d> Table<'d, Filter> {
    /// Opens the  `filter` map in the database.
    ///
    /// Returns `None` if the map does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::FILTERS).map(Table::new)
    }

    /// Inserts `Filter` into map in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn insert(&self, filter: Filter) -> Result<()> {
        let (key, value) = filter.into_key_value()?;
        self.map.insert(&key, &value)
    }

    /// Removes `Filter` with given `username` and `name` from map in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the combo does not exist or the database operation fails.
    pub fn remove<'a>(&self, username: &str, filters: impl Iterator<Item = &'a str>) -> Result<()> {
        for filter in filters {
            let key = Filter::create_key(username, filter);
            self.map.delete(&key)?;
        }
        Ok(())
    }

    /// Finds `Filter` with given `username` `name` in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn get(&self, username: &str, name: &str) -> Result<Option<Filter>> {
        let key = Filter::create_key(username, name);

        self.map
            .get(&key)?
            .map(|v| Filter::from_key_value(&key, v.as_ref()))
            .transpose()
    }

    /// Lists `Filter`(s) with given `username` in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn list(&self, username: &str) -> Result<Vec<Filter>> {
        use rocksdb::Direction::Forward;
        let prefix = username.as_bytes();
        let iter = self.prefix_iter(Forward, Some(prefix), prefix);
        iter.filter_map(|filter| {
            filter
                .map(|f| {
                    if f.username == username {
                        Some(f)
                    } else {
                        None
                    }
                })
                .transpose()
        })
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::{DateTime, Utc};

    use crate::test::{DbGuard, acquire_db_permit};
    use crate::types::FromKeyValue;
    use crate::{Filter, PeriodForSearch, Store};

    const FIXTURE_PERIOD_START: &str = "2000-01-01T00:00:00Z";
    const FIXTURE_PERIOD_END: &str = "2000-01-31T23:59:59.999999999Z";
    const FIXTURE_USERNAME: &str = "fixture-user";
    const FIXTURE_FILTER_NAME: &str = "fixture-filter";

    /// Historical bincode bytes for public `PeriodForSearch::Custom` serde.
    ///
    /// Captured once from `review-database` v0.45.0 via `tables::serialize`
    /// (`bincode::DefaultOptions`) on `deterministic_period_for_search_custom()`.
    const PERIOD_FOR_SEARCH_CUSTOM_V0: &[u8] = &[
        0x01, 0x14, 0x32, 0x30, 0x30, 0x30, 0x2d, 0x30, 0x31, 0x2d, 0x30, 0x31, 0x54, 0x30, 0x30,
        0x3a, 0x30, 0x30, 0x3a, 0x30, 0x30, 0x5a, 0x1e, 0x32, 0x30, 0x30, 0x30, 0x2d, 0x30, 0x31,
        0x2d, 0x33, 0x31, 0x54, 0x32, 0x33, 0x3a, 0x35, 0x39, 0x3a, 0x35, 0x39, 0x2e, 0x39, 0x39,
        0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x5a,
    ];

    /// Builds a deterministic public `PeriodForSearch::Custom` for serde baselines.
    ///
    /// Fixed RFC3339 timestamps pin the chrono-bearing public `Serialize` /
    /// `Deserialize` surface for `PeriodForSearch`.
    fn deterministic_period_for_search_custom() -> PeriodForSearch {
        let period_start: DateTime<Utc> = FIXTURE_PERIOD_START
            .parse()
            .expect("valid RFC 3339 timestamp");
        let period_end: DateTime<Utc> = FIXTURE_PERIOD_END
            .parse()
            .expect("valid RFC 3339 timestamp");

        PeriodForSearch::Custom(period_start, period_end)
    }

    /// Builds a deterministic `Filter` for literal-byte compatibility tests.
    ///
    /// Fixed `PeriodForSearch::Custom` timestamps pin the bincode wire format
    /// exercised by `Filter::into_key_value` (private projected `Value`) and
    /// `FromKeyValue::from_key_value`.
    fn deterministic_fixture_filter() -> Filter {
        Filter {
            username: FIXTURE_USERNAME.to_string(),
            name: FIXTURE_FILTER_NAME.to_string(),
            directions: None,
            keywords: None,
            network_tags: None,
            customers: None,
            endpoints: None,
            sensors: None,
            os: None,
            devices: None,
            hostnames: None,
            user_ids: None,
            user_names: None,
            user_departments: None,
            countries: None,
            categories: None,
            levels: None,
            kinds: None,
            learning_methods: None,
            confidence_min: None,
            confidence_max: None,
            period: deterministic_period_for_search_custom(),
        }
    }

    fn assert_filter_eq(actual: &Filter, expected: &Filter) {
        assert_eq!(actual.username, expected.username);
        assert_eq!(actual.name, expected.name);
        assert_eq!(actual.directions, expected.directions);
        assert_eq!(actual.keywords, expected.keywords);
        assert_eq!(actual.network_tags, expected.network_tags);
        assert_eq!(actual.customers, expected.customers);
        assert_eq!(actual.endpoints, expected.endpoints);
        assert_eq!(actual.sensors, expected.sensors);
        assert_eq!(actual.os, expected.os);
        assert_eq!(actual.devices, expected.devices);
        assert_eq!(actual.hostnames, expected.hostnames);
        assert_eq!(actual.user_ids, expected.user_ids);
        assert_eq!(actual.user_names, expected.user_names);
        assert_eq!(actual.user_departments, expected.user_departments);
        assert_eq!(actual.countries, expected.countries);
        assert_eq!(actual.categories, expected.categories);
        assert_eq!(actual.levels, expected.levels);
        assert_eq!(actual.kinds, expected.kinds);
        assert_eq!(actual.learning_methods, expected.learning_methods);
        assert_eq!(actual.confidence_min, expected.confidence_min);
        assert_eq!(actual.confidence_max, expected.confidence_max);
        assert_eq!(actual.period, expected.period);
    }

    /// Verifies the public bincode serde surface for `PeriodForSearch::Custom`.
    ///
    /// `PERIOD_FOR_SEARCH_CUSTOM_V0` was produced once by calling
    /// `tables::serialize` on `deterministic_period_for_search_custom()`.
    /// The active test decodes those literal bytes and round-trips through the
    /// production `tables::deserialize` / `tables::serialize` helpers without
    /// deriving expected bytes from the serializer under assertion.
    #[test]
    fn period_for_search_custom_backward_compatibility() -> anyhow::Result<()> {
        let expected = deterministic_period_for_search_custom();

        let decoded: PeriodForSearch = crate::tables::deserialize(PERIOD_FOR_SEARCH_CUSTOM_V0)
            .expect("fixture bytes must deserialize");
        assert_eq!(decoded, expected);

        let produced = crate::tables::serialize(&expected)?;
        assert_eq!(produced.as_slice(), PERIOD_FOR_SEARCH_CUSTOM_V0);

        Ok(())
    }

    /// Verifies the private projected `Value` wire format for `Filter.period`.
    ///
    /// `tests/fixtures/filter_period_value_literal.bin` was produced once by
    /// calling `Filter::into_key_value` on `deterministic_fixture_filter()`,
    /// which serializes the private `Value` struct (username/name excluded;
    /// stored in the key) via `tables::serialize` (`bincode::DefaultOptions`).
    #[test]
    fn filter_period_projected_value_backward_compatibility() {
        const FIXTURE_BYTES: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/filter_period_value_literal.bin"
        ));

        let expected = deterministic_fixture_filter();
        let key = Filter::create_key(FIXTURE_USERNAME, FIXTURE_FILTER_NAME);

        let decoded = Filter::from_key_value(&key, FIXTURE_BYTES)
            .expect("fixture bytes must deserialize via FromKeyValue");
        assert_filter_eq(&decoded, &expected);

        let (_produced_key, produced_value) = deterministic_fixture_filter()
            .into_key_value()
            .expect("deterministic filter must serialize");
        assert_eq!(produced_value.as_slice(), FIXTURE_BYTES);
    }

    #[test]
    #[ignore = "one-shot helper to regenerate tests/fixtures/filter_period_value_literal.bin"]
    fn write_filter_period_value_literal_fixture() {
        let (_key, value) = deterministic_fixture_filter()
            .into_key_value()
            .expect("deterministic filter must serialize");
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/filter_period_value_literal.bin"
        );
        std::fs::write(path, &value).expect("write fixture");
    }

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path(), None).unwrap());
        (permit, store)
    }

    #[test]
    fn operations() {
        let (_permit, store) = setup_store();
        let table = store.filter_map();

        let tester = &[("bbb", "f2"), ("aaa", "f1"), ("bb", "f1"), ("aaaa", "f2")];
        for &(username, name) in tester {
            let filter = Filter {
                username: username.to_string(),
                name: name.to_string(),
                ..Default::default()
            };
            assert!(table.insert(filter).is_ok());
        }

        for &(username, name) in tester {
            let filter = Filter {
                username: username.to_string(),
                name: name.to_string(),
                ..Default::default()
            };
            assert!(table.insert(filter).is_err());
        }

        for (username, name) in tester {
            let res = table.list(username).unwrap();
            assert_eq!(res.len(), 1);
            assert_eq!(res[0].username, *username);
            assert_eq!(res[0].name, *name);

            let res = table.get(username, name).unwrap();
            assert!(res.is_some());
            let filter = res.unwrap();
            assert_eq!(filter.username, *username);
            assert_eq!(filter.name, *name);
        }

        for (username, name) in tester {
            assert!(table.remove(username, vec![*name].into_iter()).is_ok());
        }
    }
}
