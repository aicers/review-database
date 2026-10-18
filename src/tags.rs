use crate::{IndexedTable, TriageResponse, collections::IndexedSet};

// Kinds of tag IDs. They are used to define the behavior of tag sets.

/// A compile-time tag indicating that tag IDs are for event tags.
pub struct EventTagId;

/// A compile-time tag indicating that tag IDs are for workflow tags.
pub struct WorkflowTagId;

#[derive(Default)]
pub struct Tag {
    pub id: u32,
    pub name: String,
}

/// A set of tags. `T` represents the removal behavior. When a tag is removed,
/// `TagSet<T>::remove` removes all the references to the tag in the database.
pub struct TagSet<'a, IdKind> {
    set: IndexedSet<'a>, // will be needed when we implement write operations
    tags: Vec<Tag>,
    _phantom: std::marker::PhantomData<IdKind>,
}

impl<'a, IdKind> TagSet<'a, IdKind> {
    pub(crate) fn new(set: IndexedSet<'a>) -> anyhow::Result<Self> {
        use anyhow::Context;

        let index = set.index()?;
        let mut tags = Vec::new();
        for (id, name) in index.iter() {
            tags.push(Tag {
                id,
                name: String::from_utf8(name.to_vec()).context("invalid data")?,
            });
        }
        Ok(Self {
            set,
            tags,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Inserts a new tag into the set, returning its ID.
    ///
    /// # Errors
    ///
    /// Returns an error if any database operation fails.
    pub fn insert(&mut self, name: &str) -> anyhow::Result<u32> {
        // TODO: Reject a duplicate name. Not implemented yet, because it
        // requires searching the name in the set. We need to convert the format
        // so that keys are stored as actual RocksDB keys.
        self.set.insert(name.as_bytes())
    }

    /// Updates an old tag name to a new one for the given ID.
    ///
    /// It returns `true` if the name was updated successfully, and `false` if
    /// the old name was different from what was stored or not found.
    ///
    /// # Errors
    ///
    /// Returns an error if `id` is invalid or any database operation fails.
    pub fn update(&mut self, id: u32, old: &str, new: &str) -> anyhow::Result<bool> {
        self.set.update(id, old.as_bytes(), new.as_bytes())
    }

    /// Returns an iterator over the tags in the set.
    #[must_use]
    pub fn tags(&self) -> Tags<'_> {
        Tags {
            tags: self.tags.as_slice(),
            index: 0,
        }
    }
}

impl TagSet<'_, EventTagId> {
    /// Removes a tag from the event tag set, returning its name.
    ///
    /// # Errors
    ///
    /// Returns an error if `id` is invalid or any database operation fails.
    pub fn remove_event_tag(
        &mut self,
        id: u32,
        triage_responses: &IndexedTable<TriageResponse>,
    ) -> anyhow::Result<String> {
        let key = self.set.deactivate(id)?;
        triage_responses.remove_tag(id)?;
        self.set.clear_inactive()?;

        let name = String::from_utf8(key)?;
        Ok(name)
    }
}

impl TagSet<'_, WorkflowTagId> {
    /// Removes a tag from the workflow tag set, returning its name.
    ///
    /// # Errors
    ///
    /// Returns an error if `id` is invalid or any database operation fails.
    pub fn remove_workflow_tag(&mut self, id: u32) -> anyhow::Result<String> {
        let key = self.set.remove(id)?;
        let name = String::from_utf8(key)?;
        Ok(name)
    }
}

/// An iterator over the tags in a `TagSet`.
pub struct Tags<'a> {
    tags: &'a [Tag],
    index: usize,
}

impl<'a> Iterator for Tags<'a> {
    type Item = &'a Tag;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.tags.len() {
            let tag = &self.tags[self.index];
            self.index += 1;
            Some(tag)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TagSet;
    use crate::{tags::WorkflowTagId, test};

    #[test]
    fn workflow_tag_set() {
        let db = test::Store::new();
        let set = db.indexed_set();
        let mut tag_set = TagSet::<WorkflowTagId>::new(set).unwrap();

        let id = tag_set.insert("tag1").unwrap();
        assert_eq!(id, 0);
        let id = tag_set.insert("tag2").unwrap();
        assert_eq!(id, 1);
        let id = tag_set.insert("tag3").unwrap();
        assert_eq!(id, 2);

        assert!(tag_set.remove_workflow_tag(5).is_err());
        let removed_name = tag_set.remove_workflow_tag(1).unwrap();
        assert_eq!(removed_name, "tag2");
        assert!(tag_set.remove_workflow_tag(1).is_err());

        let updated = tag_set.update(2, "tag3", "tag3.1").unwrap();
        assert!(updated);
        let updated = tag_set.update(2, "tag3", "tag3.2").unwrap();
        assert!(!updated);
        let updated = tag_set.update(2, "tag5", "tag5.1").unwrap();
        assert!(!updated);
    }
}
