//! The `label_db` table.

use std::io::{BufReader, Read};

use anyhow::{Context, Result, bail};
use data_encoding::BASE64;
use flate2::read::GzDecoder;
use rocksdb::{Direction, OptimisticTransactionDB};
use serde::{Deserialize, Serialize};

use crate::{EventCategory, Iterable, Map, Table, UniqueKey, types::FromKeyValue};

#[derive(Clone, Deserialize, Serialize)]
pub struct LabelDb {
    pub id: u32,
    pub name: String,
    pub description: Option<String>,
    pub kind: Kind,
    pub category: EventCategory,
    pub version: String,
    pub patterns: Vec<Rule>,
}

impl LabelDb {
    /// Parses and validates input label database
    ///
    /// # Errors
    ///
    /// * Returns an error if it fails to decode or uncompress input label database
    /// * Returns an error if the input label database is invalid
    pub fn new(data: &str) -> Result<Self> {
        let data = BASE64.decode(data.as_bytes())?;
        let decoder = GzDecoder::new(&data[..]);
        let mut buf = Vec::new();
        let mut reader = BufReader::new(decoder);
        reader.read_to_end(&mut buf)?;
        let label_db: LabelDb = super::deserialize(&buf).context("invalid value in database")?;
        label_db.validate()?;
        Ok(label_db)
    }

    pub(crate) fn into_key_value(self) -> Result<(Vec<u8>, Vec<u8>)> {
        let value = super::serialize(&self)?;
        let key = self.name.into_bytes();
        Ok((key, value))
    }

    fn validate(&self) -> Result<()> {
        if self.id == 0 {
            bail!("invalid db id");
        } else if self.name.trim().is_empty() {
            bail!("invalid db name");
        } else if self.version.trim().is_empty() {
            bail!("db version is required");
        }
        Ok(())
    }

    #[must_use]
    pub fn patterns(&self) -> String {
        format!("{} rules", self.patterns.len())
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Rule {
    pub rule_id: u32,
    pub category: EventCategory,
    pub name: String,
    pub kind: Option<RuleKind>,
    pub description: Option<String>,
    pub references: Option<Vec<String>>,
    pub samples: Option<Vec<String>>,
    pub signatures: Option<Vec<String>>,
    /// Confidence level of the rule, ranging from 0.0 to 1.0.
    pub confidence: Option<f32>,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Ip,
    Url,
    Token,
    Regex,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleKind {
    Os,
    AgentSoftware,
}

impl UniqueKey for LabelDb {
    type AsBytes<'a> = &'a [u8];

    fn unique_key(&self) -> &[u8] {
        self.name.as_bytes()
    }
}

impl FromKeyValue for LabelDb {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let name = std::str::from_utf8(key)?.to_string();
        let value: LabelDb = super::deserialize(value)?;
        if name != value.name {
            bail!("unmatched name");
        }
        Ok(value)
    }
}

/// Functions for the `label_db` map.
impl<'d> Table<'d, LabelDb> {
    /// Opens the  `label_db` map in the database.
    ///
    /// Returns `None` if the map does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::LABEL_DB).map(Table::new)
    }

    /// Returns the `LabelDb` with the given name.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub fn get(&self, name: &str) -> Result<Option<LabelDb>> {
        self.map
            .get(name.as_bytes())?
            .map(|v| LabelDb::from_key_value(name.as_bytes(), v.as_ref()))
            .transpose()
    }

    /// Inserts new label database
    ///
    /// # Errors
    ///
    /// * Returns an error if it fails to encode label database
    /// * Returns an error if it fails to save label database
    pub fn insert(&self, entry: LabelDb) -> Result<()> {
        let (key, value) = entry.into_key_value()?;

        self.map.put(&key, &value)?;
        Ok(())
    }

    /// Replaces label database with the new
    ///
    /// # Errors
    ///
    /// * Returns an error if the label database name does not match
    /// * Returns an error if it fails to encode label database
    /// * Returns an error if it fails to delete or save label database
    pub fn update(&self, name: &str, entry: LabelDb) -> Result<()> {
        if name != entry.name {
            bail!("LabelDb name does not matched");
        }
        let (key, value) = entry.into_key_value()?;
        self.map.delete(&key)?;
        self.map.put(name.as_bytes(), &value)
    }

    /// Returns the list of label databases
    ///
    /// # Errors
    ///
    /// * Returns an error if it fails to read database
    /// * Returns an error if it fails to decode label database
    /// * Returns an error if the rule does not exist
    pub fn get_list(&self) -> Result<Vec<LabelDb>> {
        self.iter(Direction::Forward, None).collect()
    }

    /// For a specified `(name, version)` in the provided vector,
    /// if matched `label_db` is found, returns `(name, None)`.
    /// Otherwise, returns `(name, Some(new_label_db))`.
    ///
    /// # Errors
    ///
    /// * Returns an error if it fails to decode label database
    pub fn get_patterns<'a>(
        &self,
        info: &[(&'a str, &str)],
    ) -> Result<Vec<(&'a str, Option<LabelDb>)>> {
        //TODO: This job is too heavy if label_db is nothing changed.
        //      LabelDb header and patterns should be stored separately.
        let mut ret = Vec::new();
        for &(db_name, db_version) in info {
            let Some(mut label_db) = self.get(db_name)? else {
                return Ok(Vec::new());
            };

            //TODO: These conf should be from the Model's Template
            if label_db.version == db_version {
                ret.push((db_name, None));
            } else {
                label_db.patterns = label_db
                    .patterns
                    .into_iter()
                    .filter_map(|mut rule| {
                        if rule.signatures.is_some() {
                            rule.description = None;
                            rule.references = None;
                            rule.samples = None;
                            Some(rule)
                        } else {
                            None
                        }
                    })
                    .collect();
                ret.push((db_name, Some(label_db)));
            }
        }
        Ok(ret)
    }

    /// Removes label database
    ///
    /// # Errors
    ///
    /// * Returns an error if it failes to remove value from database
    pub fn remove(&self, name: &str) -> Result<()> {
        self.map.delete(name.as_bytes())
    }

    #[allow(unused)]
    pub(crate) fn raw(&self) -> &Map<'_> {
        &self.map
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{LabelDb, Store};

    #[test]
    fn serde() {
        use std::io::{Cursor, Read};

        use data_encoding::BASE64;
        use flate2::{Compression, bufread::GzEncoder};

        let name = "label_db";
        let value = create_entry(name);
        let id = value.id;
        let serialized = crate::tables::serialize(&value).unwrap();
        let cursor = Cursor::new(serialized);

        let mut gz = GzEncoder::new(cursor, Compression::fast());
        let mut zipped = Vec::new();
        gz.read_to_end(&mut zipped).unwrap();
        let encoded = BASE64.encode(&zipped);
        let res = super::LabelDb::new(&encoded);

        assert!(res.is_ok());
        let label_db = res.unwrap();
        assert_eq!(label_db.name, name);
        assert_eq!(label_db.id, id);
    }

    #[test]
    fn operations() {
        use crate::Iterable;
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let table = store.label_db_map();

        let tester = &["1", "2", "3"];
        for name in tester {
            let entry = create_entry(name);

            assert!(table.insert(entry).is_ok());
        }

        for &name in tester {
            let res = table.get(name).unwrap().map(|entry: LabelDb| entry.name);
            assert_eq!(Some(name.to_string()), res);
        }

        let res: anyhow::Result<Vec<_>> = table
            .iter(rocksdb::Direction::Forward, None)
            .map(|r| r.map(|entry| entry.name))
            .collect();
        assert!(res.is_ok());
        let list = res.unwrap();
        assert_eq!(
            tester.to_vec(),
            list.iter().map(String::as_str).collect::<Vec<_>>()
        );

        for name in list {
            assert!(table.remove(&name).is_ok());
        }
    }

    fn create_entry(name: &str) -> LabelDb {
        LabelDb {
            id: 1,
            name: name.to_string(),
            description: None,
            kind: super::Kind::Regex,
            category: crate::EventCategory::Reconnaissance,
            version: "1".to_string(),
            patterns: vec![],
        }
    }
}
