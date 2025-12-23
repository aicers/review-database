use crate::{IndexedTable, Network, TriageResponse, collections::IndexedSet};

// Kinds of tag IDs. They are used to define the behavior of tag sets.

/// A compile-time tag indicating that tag IDs are for event tags.
pub struct EventTagId;

/// A compile-time tag indicating that tag IDs are for network tags.
pub struct NetworkTagId;

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

/// A customer-scoped set of network tags.
///
/// Tags are stored with a key format of `{customer_id}\0{tag_name}` to ensure
/// uniqueness within each customer's scope. The `customer_id` is encoded as
/// ASCII decimal followed by a null byte separator.
pub struct CustomerTagSet<'a, IdKind> {
    set: IndexedSet<'a>,
    customer_id: u32,
    tags: Vec<Tag>,
    _phantom: std::marker::PhantomData<IdKind>,
}

impl<'a, IdKind> CustomerTagSet<'a, IdKind> {
    /// Creates a new `CustomerTagSet` for the specified customer.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or the data is invalid.
    pub(crate) fn new(set: IndexedSet<'a>, customer_id: u32) -> anyhow::Result<Self> {
        use anyhow::Context;

        let prefix = Self::make_prefix(customer_id);
        let index = set.index()?;
        let mut tags = Vec::new();

        for (id, key) in index.iter() {
            // Only include tags that belong to this customer
            if let Some(name_bytes) = key.strip_prefix(prefix.as_bytes()) {
                let name = String::from_utf8(name_bytes.to_vec()).context("invalid data")?;
                tags.push(Tag { id, name });
            }
        }

        Ok(Self {
            set,
            customer_id,
            tags,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Returns the customer ID associated with this tag set.
    #[must_use]
    pub fn customer_id(&self) -> u32 {
        self.customer_id
    }

    /// Inserts a new tag into the set, returning its ID.
    ///
    /// # Errors
    ///
    /// Returns an error if any database operation fails.
    pub fn insert(&mut self, name: &str) -> anyhow::Result<u32> {
        let prefixed_key = self.make_prefixed_key(name);
        self.set.insert(prefixed_key.as_bytes())
    }

    /// Updates an old tag name to a new one for the given ID.
    ///
    /// Returns `true` if the name was updated successfully, and `false` if
    /// the old name was different from what was stored or not found.
    ///
    /// # Errors
    ///
    /// Returns an error if `id` is invalid or any database operation fails.
    pub fn update(&mut self, id: u32, old: &str, new: &str) -> anyhow::Result<bool> {
        let old_prefixed = self.make_prefixed_key(old);
        let new_prefixed = self.make_prefixed_key(new);
        self.set
            .update(id, old_prefixed.as_bytes(), new_prefixed.as_bytes())
    }

    /// Returns an iterator over the tags in the set.
    #[must_use]
    pub fn tags(&self) -> Tags<'_> {
        Tags {
            tags: self.tags.as_slice(),
            index: 0,
        }
    }

    /// Removes a tag from the network tag set, returning its name.
    ///
    /// # Errors
    ///
    /// Returns an error if `id` is invalid or any database operation fails.
    pub fn remove_network_tag(
        &mut self,
        id: u32,
        networks: &IndexedTable<Network>,
    ) -> anyhow::Result<String> {
        let key = self.set.deactivate(id)?;
        networks.remove_tag(id)?;
        self.set.clear_inactive()?;

        // Strip the customer prefix to get the actual tag name
        let prefix = Self::make_prefix(self.customer_id);
        let name = if let Some(name_bytes) = key.strip_prefix(prefix.as_bytes()) {
            String::from_utf8(name_bytes.to_vec())?
        } else {
            // Fallback: return the full key if prefix doesn't match
            String::from_utf8(key)?
        };

        Ok(name)
    }

    /// Creates the prefix for a customer ID: `{customer_id}\0`
    fn make_prefix(customer_id: u32) -> String {
        format!("{customer_id}\0")
    }

    /// Creates a prefixed key for a tag name: `{customer_id}\0{tag_name}`
    fn make_prefixed_key(&self, name: &str) -> String {
        format!("{}\0{name}", self.customer_id)
    }
}

#[cfg(test)]
mod tests {
    use super::TagSet;
    use crate::{
        tags::{NetworkTagId, WorkflowTagId},
        test,
    };

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

    #[test]
    fn customer_tag_set_insert_and_list() {
        use super::CustomerTagSet;
        let store = test::Store::new();
        let indexed_set = store.indexed_set();

        let customer_id = 42;
        let mut tag_set = CustomerTagSet::<NetworkTagId>::new(indexed_set, customer_id).unwrap();

        // Insert tags
        let id1 = tag_set.insert("network-tag-1").unwrap();
        assert_eq!(id1, 0);
        let id2 = tag_set.insert("network-tag-2").unwrap();
        assert_eq!(id2, 1);

        // Verify customer_id is correct
        assert_eq!(tag_set.customer_id(), customer_id);

        // Re-create the tag set to test loading
        let indexed_set = store.indexed_set();
        let tag_set = CustomerTagSet::<NetworkTagId>::new(indexed_set, customer_id).unwrap();

        // Verify tags were persisted and can be retrieved
        let tags: Vec<_> = tag_set.tags().collect();
        assert_eq!(tags.len(), 2);

        // Check the tags have correct names (stripped of prefix)
        let names: Vec<_> = tags.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"network-tag-1"));
        assert!(names.contains(&"network-tag-2"));
    }

    #[test]
    fn customer_tag_set_different_customers() {
        use super::CustomerTagSet;
        let store = test::Store::new();

        // Customer 1 inserts tags
        let customer_1_id = 100;
        let indexed_set = store.indexed_set();
        let mut customer_1_tags =
            CustomerTagSet::<NetworkTagId>::new(indexed_set, customer_1_id).unwrap();
        customer_1_tags.insert("shared-name").unwrap();
        customer_1_tags.insert("tag-a").unwrap();

        // Customer 2 inserts tags with same name
        let customer_2_id = 200;
        let indexed_set = store.indexed_set();
        let mut customer_2_tags =
            CustomerTagSet::<NetworkTagId>::new(indexed_set, customer_2_id).unwrap();
        customer_2_tags.insert("shared-name").unwrap(); // Same name, different customer
        customer_2_tags.insert("tag-b").unwrap();

        // Re-create tag sets and verify isolation
        let indexed_set = store.indexed_set();
        let customer_1_tags =
            CustomerTagSet::<NetworkTagId>::new(indexed_set, customer_1_id).unwrap();
        let tags_1: Vec<_> = customer_1_tags.tags().collect();
        assert_eq!(tags_1.len(), 2);
        let names_1: Vec<_> = tags_1.iter().map(|t| t.name.as_str()).collect();
        assert!(names_1.contains(&"shared-name"));
        assert!(names_1.contains(&"tag-a"));
        assert!(!names_1.contains(&"tag-b"));

        let indexed_set = store.indexed_set();
        let customer_2_tags =
            CustomerTagSet::<NetworkTagId>::new(indexed_set, customer_2_id).unwrap();
        let tags_2: Vec<_> = customer_2_tags.tags().collect();
        assert_eq!(tags_2.len(), 2);
        let names_2: Vec<_> = tags_2.iter().map(|t| t.name.as_str()).collect();
        assert!(names_2.contains(&"shared-name"));
        assert!(names_2.contains(&"tag-b"));
        assert!(!names_2.contains(&"tag-a"));
    }

    #[test]
    fn customer_tag_set_update() {
        use super::CustomerTagSet;
        let store = test::Store::new();

        let customer_id = 50;
        let indexed_set = store.indexed_set();
        let mut tag_set = CustomerTagSet::<NetworkTagId>::new(indexed_set, customer_id).unwrap();

        // Insert and update a tag
        let id = tag_set.insert("old-name").unwrap();
        let updated = tag_set.update(id, "old-name", "new-name").unwrap();
        assert!(updated);

        // Verify the update was successful by re-loading
        let indexed_set = store.indexed_set();
        let tag_set = CustomerTagSet::<NetworkTagId>::new(indexed_set, customer_id).unwrap();
        let tags: Vec<_> = tag_set.tags().collect();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].name, "new-name");
    }
}
