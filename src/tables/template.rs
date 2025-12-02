//! The `template` table.

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use crate::{Map, Table, UniqueKey, types::FromKeyValue};

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub enum Template {
    Structured(Structured),
    Unstructured(Unstructured),
}

impl Template {
    fn into_key_value(self) -> Result<(Vec<u8>, Vec<u8>)> {
        let value = super::serialize(&self)?;
        let key = match self {
            Self::Structured(s) => s.name.into_bytes(),
            Self::Unstructured(u) => u.name.into_bytes(),
        };
        Ok((key, value))
    }

    fn name(&self) -> &str {
        match &self {
            Self::Structured(s) => s.name.as_str(),
            Self::Unstructured(u) => u.name.as_str(),
        }
    }
}

impl UniqueKey for Template {
    type AsBytes<'a> = &'a [u8];

    fn unique_key(&self) -> &[u8] {
        self.name().as_bytes()
    }
}

impl FromKeyValue for Template {
    fn from_key_value(_key: &[u8], value: &[u8]) -> Result<Self> {
        super::deserialize(value)
    }
}

#[derive(Debug, Copy, Clone, Deserialize, Eq, PartialEq, Serialize)]
pub enum StructuredClusteringAlgorithm {
    Dbscan,
    Optics,
}

#[derive(Debug, Copy, Clone, Deserialize, Eq, PartialEq, Serialize)]
pub enum UnstructuredClusteringAlgorithm {
    Prefix,
    Distribution,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct Structured {
    pub name: String,
    pub description: String,
    pub algorithm: Option<StructuredClusteringAlgorithm>,
    pub eps: Option<f32>,
    pub format: Option<String>,
    pub time_intervals: Option<Vec<i64>>,
    pub numbers_of_top_n: Option<Vec<i32>>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct Unstructured {
    pub name: String,
    pub description: String,
    pub algorithm: Option<UnstructuredClusteringAlgorithm>,
    pub min_token_length: Option<i32>,
}

/// Functions for the `template` map.
impl<'d> Table<'d, Template> {
    /// Opens the  `template` map in the database.
    ///
    /// Returns `None` if the map does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::TEMPLATES).map(Table::new)
    }

    /// Inserts the `Template` into the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the serialization fails or the database operation fails.
    pub fn insert(&self, template: Template) -> Result<()> {
        let (key, value) = template.into_key_value()?;
        self.map.put(&key, &value)
    }

    /// Removes the `Template` with the given name.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn remove(&self, name: &str) -> Result<()> {
        self.map.delete(name.as_bytes())
    }

    /// Updates the `Template` in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the serialization fails or the database operation fails.
    pub fn update(&self, old: Template, new: Template) -> Result<()> {
        let (ok, ov) = old.into_key_value()?;
        let (nk, nv) = new.into_key_value()?;
        self.map.update((&ok, &ov), (&nk, &nv))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{Store, Structured, Template, Unstructured};

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        (permit, store)
    }

    #[test]
    fn operations() {
        use crate::Iterable;
        let (_permit, store) = setup_store();
        let table = store.template_map();

        let structured = Structured {
            name: "structured".to_string(),
            description: String::new(),
            algorithm: None,
            eps: None,
            format: None,
            time_intervals: None,
            numbers_of_top_n: None,
        };

        let unstructured = Unstructured {
            name: "unstructured".to_string(),
            description: String::new(),
            algorithm: None,
            min_token_length: None,
        };

        assert!(
            table
                .insert(Template::Structured(structured.clone()))
                .is_ok()
        );
        assert!(
            table
                .insert(Template::Unstructured(unstructured.clone()))
                .is_ok()
        );

        let mut new_structured = structured.clone();
        new_structured.name = "new_structured".to_string();
        assert!(
            table
                .update(
                    Template::Structured(structured),
                    Template::Structured(new_structured.clone())
                )
                .is_ok()
        );

        assert!(table.remove("unstructured").is_ok());

        let res: anyhow::Result<Vec<_>> = table.iter(rocksdb::Direction::Forward, None).collect();
        assert!(res.is_ok());
        let templates = res.unwrap();
        assert_eq!(templates, vec![Template::Structured(new_structured)]);
    }
}
