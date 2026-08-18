//! The `csv column extras` table.
use std::borrow::Cow;

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use crate::{
    Indexable, IndexedMap, IndexedMapUpdate, IndexedTable, collections::Indexed,
    types::FromKeyValue,
};

#[derive(Deserialize, Serialize, Default)]
pub struct CsvColumnExtra {
    pub id: u32,
    pub model_id: u32,
    pub column_alias: Option<Vec<String>>,
    pub column_display: Option<Vec<bool>>,
    pub column_top_n: Option<Vec<bool>>,
    pub column_1: Option<Vec<bool>>,
    pub column_n: Option<Vec<bool>>,
}

impl FromKeyValue for CsvColumnExtra {
    fn from_key_value(_key: &[u8], value: &[u8]) -> Result<Self> {
        super::deserialize(value)
    }
}

impl Indexable for CsvColumnExtra {
    fn key(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.model_id.to_be_bytes().to_vec())
    }

    fn index(&self) -> u32 {
        self.id
    }

    fn make_indexed_key(key: Cow<[u8]>, _index: u32) -> Cow<[u8]> {
        key
    }

    fn value(&self) -> Vec<u8> {
        use bincode::Options;

        bincode::DefaultOptions::new()
            .serialize(self)
            .expect("serializable")
    }

    fn set_index(&mut self, index: u32) {
        self.id = index;
    }
}

impl IndexedMapUpdate for CsvColumnExtra {
    type Entry = CsvColumnExtra;

    fn key(&self) -> Option<Cow<'_, [u8]>> {
        Some(Cow::Owned(self.model_id.to_be_bytes().to_vec()))
    }

    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry, anyhow::Error> {
        if let Some(val) = &self.column_alias {
            value.column_alias = Some(val.to_owned());
        }
        if let Some(val) = &self.column_display {
            value.column_display = Some(val.to_owned());
        }
        if let Some(val) = &self.column_top_n {
            value.column_top_n = Some(val.to_owned());
        }
        if let Some(val) = &self.column_1 {
            value.column_1 = Some(val.to_owned());
        }
        if let Some(val) = &self.column_n {
            value.column_n = Some(val.to_owned());
        }

        Ok(value)
    }

    fn verify(&self, value: &Self::Entry) -> bool {
        self.model_id == value.model_id
    }
}

impl<'d> IndexedTable<'d, CsvColumnExtra> {
    /// Opens the csv column extras table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        IndexedMap::new(db, super::CSV_COLUMN_EXTRAS)
            .map(IndexedTable::new)
            .ok()
    }

    /// Inserts a csv column extra instance into the table and
    /// returns the ID of the newly added csv column extra instance.
    ///
    /// # Errors
    ///
    /// Returns an error if the table already has an entry with
    /// the same `model_id`.
    pub fn insert(
        &self,
        model_id: u32,
        column_alias: Option<&[String]>,
        column_display: Option<&[bool]>,
        column_top_n: Option<&[bool]>,
        column_1: Option<&[bool]>,
        column_n: Option<&[bool]>,
    ) -> Result<u32> {
        let entry = CsvColumnExtra {
            id: u32::MAX,
            model_id,
            column_alias: column_alias.map(ToOwned::to_owned),
            column_display: column_display.map(ToOwned::to_owned),
            column_top_n: column_top_n.map(ToOwned::to_owned),
            column_1: column_1.map(ToOwned::to_owned),
            column_n: column_n.map(ToOwned::to_owned),
        };
        self.indexed_map.insert(entry)
    }

    /// Loads extra information regarding the columns of a CSV model.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection to the database fails.
    pub fn get_by_model(&self, model_id: u32) -> Result<Option<CsvColumnExtra>> {
        let key = model_id.to_be_bytes();
        let res = self.indexed_map.get_by_key(&key)?;

        res.map(|r| super::deserialize(r.as_ref())).transpose()
    }

    /// Updates extra information regarding the columns of a CSV model.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection to the database fails.
    pub fn update(
        &self,
        id: u32,
        column_alias: Option<&[String]>,
        column_display: Option<&[bool]>,
        column_top_n: Option<&[bool]>,
        column_1: Option<&[bool]>,
        column_n: Option<&[bool]>,
    ) -> Result<()> {
        let old: CsvColumnExtra = self
            .indexed_map
            .get_by_id(id)
            .map(|r| r.ok_or(anyhow::anyhow!("csv column extra {id} unavailable")))??;
        let new = CsvColumnExtra {
            id,
            model_id: old.model_id,
            column_alias: column_alias.map(ToOwned::to_owned),
            column_display: column_display.map(ToOwned::to_owned),
            column_top_n: column_top_n.map(ToOwned::to_owned),
            column_1: column_1.map(ToOwned::to_owned),
            column_n: column_n.map(ToOwned::to_owned),
        };
        self.indexed_map.update(id, &old, &new)
    }
}
