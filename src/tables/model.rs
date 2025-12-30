use std::borrow::Cow;

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use super::UniqueKey;
use crate::{
    Indexable, IndexedMap, IndexedMapUpdate, IndexedTable, Iterable, collections::Indexed,
    types::FromKeyValue,
};

#[derive(Clone, Deserialize, Serialize)]
pub struct Model {
    pub id: u32,
    pub name: String,
    pub version: i32,
    pub kind: String,
    pub max_event_id_num: i32,
    pub data_source_id: i32,
    pub classification_id: Option<i64>,
    /// Description of the model, providing information about its purpose or usage.
    pub description: String,
    /// Path to the model file in the pretrained directory.
    pub file_path: Option<String>,
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
    pub fn update(&mut self, id: u32, old: &Update, new: &Update) -> Result<()> {
        self.indexed_map.update(id, old, new)
    }

    /// Adds a new model to the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the model already exists or if a database operation fails.
    pub fn add_model(&self, model: Model) -> Result<u32> {
        self.indexed_map.insert(model)
    }

    /// Deletes the model with the given name.
    ///
    /// # Errors
    ///
    /// Returns an error if the model does not exist or if a database operation fails.
    pub fn delete_model(&self, name: &str) -> Result<u32> {
        let model: Model = self.load_model_by_name(name)?;
        self.remove(model.id)?;
        Ok(model.id)
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
        self.get_by_id(id)?
            .ok_or(anyhow::anyhow!("model not found"))
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
            .ok_or(anyhow::anyhow!("model not found"))
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

    /// Updates the model with the given name.
    ///
    /// # Errors
    ///
    /// Returns an error if the model does not exist or if a database operation fails.
    pub fn update_model(&mut self, model: &Model) -> Result<u32> {
        let old = self.load_model(model.id)?;
        let old = old.into();
        let new = model.into();
        self.update(model.id, &old, &new)?;
        Ok(model.id)
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

#[derive(Clone, Deserialize, Serialize)]
pub struct Update {
    name: Option<String>,
    version: Option<i32>,
    kind: Option<String>,
    max_event_id_num: Option<i32>,
    data_source_id: Option<i32>,
    classification_id: Option<i64>,
    description: Option<String>,
    /// `None` means "don't update", `Some(None)` means "set to null",
    /// `Some(Some(path))` means "set to path".
    #[allow(clippy::option_option)]
    file_path: Option<Option<String>>,
}

impl From<Model> for Update {
    fn from(model: Model) -> Self {
        Self {
            name: Some(model.name),
            version: Some(model.version),
            kind: Some(model.kind),
            max_event_id_num: Some(model.max_event_id_num),
            data_source_id: Some(model.data_source_id),
            classification_id: model.classification_id,
            description: Some(model.description),
            file_path: Some(model.file_path),
        }
    }
}

impl From<&Model> for Update {
    fn from(model: &Model) -> Self {
        Self {
            name: Some(model.name.clone()),
            version: Some(model.version),
            kind: Some(model.kind.clone()),
            max_event_id_num: Some(model.max_event_id_num),
            data_source_id: Some(model.data_source_id),
            classification_id: model.classification_id,
            description: Some(model.description.clone()),
            file_path: Some(model.file_path.clone()),
        }
    }
}

impl IndexedMapUpdate for Update {
    type Entry = Model;

    fn key(&self) -> Option<Cow<'_, [u8]>> {
        self.name
            .as_ref()
            .map(|name| Cow::Borrowed(name.as_bytes()))
    }

    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry, anyhow::Error> {
        if let Some(name) = &self.name {
            value.name.clone_from(name);
        }
        if let Some(version) = self.version {
            value.version = version;
        }
        if let Some(kind) = &self.kind {
            value.kind.clone_from(kind);
        }
        if let Some(max_event_id_num) = self.max_event_id_num {
            value.max_event_id_num = max_event_id_num;
        }
        if let Some(data_source_id) = self.data_source_id {
            value.data_source_id = data_source_id;
        }
        if let Some(description) = &self.description {
            value.description.clone_from(description);
        }
        if let Some(file_path) = &self.file_path {
            value.file_path.clone_from(file_path);
        }
        Ok(value)
    }

    fn verify(&self, value: &Self::Entry) -> bool {
        if let Some(name) = &self.name
            && name != &value.name
        {
            return false;
        }
        if let Some(version) = self.version
            && version != value.version
        {
            return false;
        }
        if let Some(kind) = &self.kind
            && kind != &value.kind
        {
            return false;
        }
        if let Some(max_event_id_num) = self.max_event_id_num
            && max_event_id_num != value.max_event_id_num
        {
            return false;
        }
        if let Some(data_source_id) = self.data_source_id
            && data_source_id != value.data_source_id
        {
            return false;
        }
        if let Some(description) = &self.description
            && description != &value.description
        {
            return false;
        }
        if let Some(file_path) = &self.file_path
            && file_path != &value.file_path
        {
            return false;
        }
        true
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
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        (permit, store)
    }

    fn make_model(name: &str, version: i32) -> Model {
        Model {
            id: 0, // will be set by insert
            name: name.to_string(),
            version,
            kind: "test-kind".to_string(),
            max_event_id_num: 100,
            data_source_id: 42,
            classification_id: None,
            description: String::new(),
            file_path: None,
        }
    }

    #[test]
    fn test_add_and_load_model() {
        let (_permit, store) = setup_store();
        let table = store.model_map();
        let model = make_model("alpha", 1);

        let id = table.add_model(model.clone()).unwrap();
        assert!(id == 0);

        let loaded = table.load_model(id).unwrap();
        assert_eq!(loaded.name, "alpha");
        assert_eq!(loaded.version, 1);

        let loaded_by_name = table.load_model_by_name("alpha").unwrap();
        assert_eq!(loaded_by_name.id, id);
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

        let update = Update {
            name: Some("verify".into()),
            version: Some(2),
            kind: Some("changed".into()),
            max_event_id_num: Some(200),
            data_source_id: Some(77),
            classification_id: None,
            description: Some("test description".into()),
            file_path: Some(Some("test/path.bin".into())),
        };

        let applied = update.apply(m.clone()).unwrap();
        assert_eq!(applied.version, 2);
        assert_eq!(applied.kind, "changed");
        assert_eq!(applied.max_event_id_num, 200);
        assert_eq!(applied.data_source_id, 77);
        assert_eq!(applied.description, "test description");
        assert_eq!(applied.file_path, Some("test/path.bin".to_string()));

        assert!(update.verify(&applied));
        assert!(!update.verify(&m)); // old model doesn't match update
    }

    #[test]
    fn test_model_description_and_file_path() {
        let (_permit, store) = setup_store();
        let mut table = store.model_map();

        let mut m = make_model("model-with-desc", 1);
        m.description = "A test model for classification".to_string();
        m.file_path = Some("pretrained/test/model.bin".to_string());

        let id = table.add_model(m).unwrap();

        let loaded = table.load_model(id).unwrap();
        assert_eq!(loaded.description, "A test model for classification");
        assert_eq!(
            loaded.file_path,
            Some("pretrained/test/model.bin".to_string())
        );

        // Test updating description and file_path
        let mut updated = loaded.clone();
        updated.description = "Updated description".to_string();
        updated.file_path = Some("pretrained/new/path.bin".to_string());

        table.update_model(&updated).unwrap();

        let reloaded = table.load_model(id).unwrap();
        assert_eq!(reloaded.description, "Updated description");
        assert_eq!(
            reloaded.file_path,
            Some("pretrained/new/path.bin".to_string())
        );
    }
}
