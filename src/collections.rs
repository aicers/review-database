mod indexed_map;
mod indexed_set;
mod map;

use std::{borrow::Cow, cmp::Ordering, convert::TryFrom, mem};

use anyhow::{Context, Result, bail};
use bincode::Options;
use serde::{Deserialize, Serialize};

pub use self::{indexed_map::IndexedMap, indexed_set::IndexedSet, map::Map};
use super::types::FromKeyValue;
use crate::EXCLUSIVE;

#[derive(Deserialize, Serialize)]
enum KeyIndexEntry {
    Key(Vec<u8>),
    Index(u32),
    Inactive(Option<u32>),
}

#[derive(Default, Deserialize, Serialize)]
pub(crate) struct KeyIndex {
    keys: Vec<KeyIndexEntry>,
    available: u32,
    inactive: Option<u32>,
}

impl KeyIndex {
    /// Deserializes a `KeyIndex` from a byte slice.
    pub(crate) fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        bincode::DefaultOptions::new()
            .deserialize_from(bytes.as_ref())
            .context("invalid serialized form")
    }

    /// Returns the number of entries containing `Key`.
    pub(crate) fn count(&self) -> usize {
        self.keys
            .iter()
            .filter(|entry| matches!(entry, KeyIndexEntry::Key(_)))
            .count()
    }

    /// Retrieves the key corresponding to the given index.
    fn get(&self, index: u32) -> Result<Option<&[u8]>> {
        let i = usize::try_from(index).context("index out of range")?;
        Ok(match self.keys.get(i) {
            Some(KeyIndexEntry::Inactive(_) | KeyIndexEntry::Index(_)) | None => None,
            Some(KeyIndexEntry::Key(key)) => Some(key),
        })
    }

    pub(crate) fn iter(&self) -> KeyIndexIterator<'_> {
        KeyIndexIterator {
            entries: &self.keys,
            i: 0,
        }
    }

    /// Deactivate the key at the given index.
    fn deactivate(&mut self, id: u32) -> Result<Vec<u8>> {
        let i = usize::try_from(id).context("index out of range")?;
        let key = match self.keys.get_mut(i) {
            Some(KeyIndexEntry::Key(key)) => mem::take(key),
            Some(KeyIndexEntry::Inactive(_) | KeyIndexEntry::Index(_)) => {
                bail!("no such ID");
            }
            None => bail!("index out of range"),
        };
        self.keys[i] = KeyIndexEntry::Inactive(self.inactive);
        self.inactive = Some(id);
        Ok(key)
    }

    /// Makes deactivated indices available.
    fn clear_inactive(&mut self) -> Result<()> {
        while let Some(inactive) = self.inactive {
            let i = usize::try_from(inactive).context("invalid inactive list")?;
            self.inactive = match self.keys.get(i) {
                Some(KeyIndexEntry::Inactive(next)) => *next,
                _ => bail!("invalid inactive list"),
            };
            self.keys[i] = KeyIndexEntry::Index(self.available);
            self.available = inactive;
        }
        Ok(())
    }

    /// Inserts a new key and returns its index.
    pub(crate) fn insert(&mut self, key: &[u8]) -> Result<u32> {
        let id = self.available;
        match u32::try_from(self.keys.len())
            .context("corrupt index")?
            .cmp(&id)
        {
            Ordering::Equal => {
                if id == u32::MAX {
                    bail!("index is full");
                }
                self.keys.push(KeyIndexEntry::Key(key.to_vec()));
                self.available += 1;
            }
            Ordering::Greater => {
                let i = usize::try_from(id).context("too many keys")?;
                self.available = match self.keys.get(i) {
                    Some(KeyIndexEntry::Key(_)) => bail!("corrupt index"),
                    Some(KeyIndexEntry::Index(i)) => *i,
                    _ => unreachable!(),
                };
                self.keys[i] = KeyIndexEntry::Key(key.to_vec());
            }
            Ordering::Less => {
                bail!("corrupt index");
            }
        }
        Ok(id)
    }

    /// Removes a key at the given index.
    fn remove(&mut self, id: u32) -> Result<Vec<u8>> {
        let i = usize::try_from(id).context("index out of range")?;
        let key = match self.keys.get_mut(i) {
            Some(KeyIndexEntry::Key(key)) => mem::take(key),
            Some(KeyIndexEntry::Inactive(_) | KeyIndexEntry::Index(_)) => {
                bail!("no such ID");
            }
            None => bail!("index out of range"),
        };
        self.keys[i] = KeyIndexEntry::Index(self.available);
        self.available = id;
        Ok(key)
    }

    /// Updates a key for the given index to a new one.
    pub(crate) fn update(&mut self, id: u32, key: &[u8]) -> Result<Vec<u8>> {
        let i = usize::try_from(id).context("index out of range")?;
        let key = match self.keys.get_mut(i) {
            Some(KeyIndexEntry::Key(old_key)) => mem::replace(old_key, key.to_vec()),
            Some(KeyIndexEntry::Inactive(_) | KeyIndexEntry::Index(_)) => {
                bail!("no such ID");
            }
            None => bail!("index out of range"),
        };
        Ok(key)
    }
}

pub struct KeyIndexIterator<'a> {
    entries: &'a [KeyIndexEntry],
    i: usize,
}

impl<'a> Iterator for KeyIndexIterator<'a> {
    type Item = (u32, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let entry = self.entries.get(self.i)?;
            if let KeyIndexEntry::Key(key) = entry {
                let id = u32::try_from(self.i).expect("not exceeding u32::MAX");
                self.i += 1;
                return Some((id, key.as_slice()));
            }
            self.i += 1;
        }
    }
}

pub trait Indexable
where
    Self: Sized,
{
    fn key(&self) -> Cow<'_, [u8]>;
    fn index(&self) -> u32;
    fn indexed_key(&self) -> Cow<'_, [u8]> {
        Self::make_indexed_key(self.key(), self.index())
    }
    fn make_indexed_key(key: Cow<[u8]>, index: u32) -> Cow<[u8]>;
    fn value(&self) -> Vec<u8>;
    fn set_index(&mut self, index: u32);
}

pub trait Indexed {
    fn db(&self) -> &rocksdb::OptimisticTransactionDB;
    fn cf(&self) -> &rocksdb::ColumnFamily;

    /// Returns the index.
    ///
    /// # Errors
    ///
    /// Returns an error if the index is not found or the database operation fails.
    fn index(&self) -> Result<KeyIndex> {
        let Some(value) = self.db().get_cf(self.cf(), []).context("database error")? else {
            return Ok(KeyIndex::default());
        };
        KeyIndex::from_bytes(value).context("invalid index in database")
    }

    /// Returns the index in a transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the index is not found or the database operation fails.
    fn index_in_transaction(
        &self,
        txn: &rocksdb::Transaction<rocksdb::OptimisticTransactionDB>,
    ) -> Result<KeyIndex> {
        let Some(value) = txn
            .get_for_update_cf(self.cf(), [], EXCLUSIVE)
            .context("database error")?
        else {
            return Ok(KeyIndex::default());
        };
        KeyIndex::from_bytes(value).context("invalid index in database")
    }

    /// Returns the number of entries in the index.
    ///
    /// # Errors
    ///
    /// Returns an error if the index is not found or the database operation fails.
    fn count(&self) -> Result<usize> {
        Ok(self.index()?.count())
    }

    /// Deactivates a key-value pair with the given ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    fn deactivate(&self, id: u32) -> Result<Vec<u8>> {
        let mut key;
        loop {
            let txn = self.db().transaction();
            let mut index = self
                .index_in_transaction(&txn)
                .context("cannot read index")?;
            key = index.deactivate(id).context("cannot deactivate key")?;
            if key.is_empty() {
                bail!("corrupt index");
            }
            txn.put_cf(
                self.cf(),
                [],
                bincode::DefaultOptions::new()
                    .serialize(&index)
                    .context("failed to serialize index")?,
            )
            .context("failed to update database index")?;
            txn.delete_cf(self.cf(), &key)
                .context("failed to remove entry")?;
            match txn.commit() {
                Ok(()) => break,
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to remove entry");
                    }
                }
            }
        }
        Ok(key)
    }

    /// Makes deactivated indices available.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    #[allow(unused)] // TODO: Make sure this functions is called when appropriate
    fn clear_inactive(&self) -> Result<()> {
        loop {
            let txn = self.db().transaction();
            let mut index = self
                .index_in_transaction(&txn)
                .context("cannot read index")?;
            index.clear_inactive()?;
            txn.put_cf(
                self.cf(),
                [],
                bincode::DefaultOptions::new()
                    .serialize(&index)
                    .context("failed to serialize index")?,
            )
            .context("failed to update database index")?;
            match txn.commit() {
                Ok(()) => break,
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to remove entry");
                    }
                }
            }
        }
        Ok(())
    }

    /// Gets an entry corresponding to the given index.
    ///
    /// # Errors
    ///
    /// Returns an error if the index is invalid or cannot be read.
    fn get_by_id<T: Indexable + FromKeyValue>(&self, id: u32) -> Result<Option<T>> {
        let index = self.index()?;
        let Some(key) = index.get(id).context("invalid ID")? else {
            return Ok(None);
        };
        let key = T::make_indexed_key(Cow::Borrowed(key), id);
        self.db()
            .get_cf(self.cf(), &key)
            .context("cannot read entry")?
            .map(|value| T::from_key_value(&key, &value))
            .transpose()
    }

    /// Inserts a new key-value pair.
    ///
    /// # Errors
    ///
    /// Returns an error if the key already exists.
    fn insert<T: Indexable>(&self, mut entry: T) -> Result<u32> {
        if entry.key().is_empty() {
            bail!("key shouldn't be empty");
        }
        let mut i;
        loop {
            let txn = self.db().transaction();
            let mut index = self.index_in_transaction(&txn)?;
            i = index.insert(&entry.key()).context("cannot insert key")?;
            entry.set_index(i);
            if txn
                .get_for_update_cf(self.cf(), entry.indexed_key(), super::EXCLUSIVE)
                .context("cannot read from database")?
                .is_some()
            {
                bail!("key already exists");
            }
            txn.put_cf(
                self.cf(),
                [],
                bincode::DefaultOptions::new()
                    .serialize(&index)
                    .expect("serializable"),
            )
            .context("failed to update database index")?;
            txn.put_cf(self.cf(), entry.indexed_key(), entry.value())
                .context("failed to write new entry")?;
            match txn.commit() {
                Ok(()) => break,
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to store new entry");
                    }
                }
            }
        }
        Ok(i)
    }

    /// Inserts a new key-value pair within a transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the key already exists.
    fn insert_with_transaction<T: Indexable>(
        &self,
        mut entry: T,
        txn: &rocksdb::Transaction<rocksdb::OptimisticTransactionDB>,
    ) -> Result<u32> {
        if entry.key().is_empty() {
            bail!("key shouldn't be empty");
        }
        let mut index = self.index_in_transaction(txn)?;
        let i = index.insert(&entry.key()).context("cannot insert key")?;
        entry.set_index(i);
        if txn
            .get_for_update_cf(self.cf(), entry.indexed_key(), super::EXCLUSIVE)
            .context("cannot read from database")?
            .is_some()
        {
            bail!("key already exists");
        }
        txn.put_cf(
            self.cf(),
            [],
            bincode::DefaultOptions::new()
                .serialize(&index)
                .expect("serializable"),
        )
        .context("failed to update database index")?;
        txn.put_cf(self.cf(), entry.indexed_key(), entry.value())
            .context("failed to write new entry")?;
        Ok(i)
    }

    /// Removes a key-value pair with the given ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    fn remove<T: Indexable>(&self, id: u32) -> Result<Vec<u8>> {
        let mut key;
        loop {
            let txn = self.db().transaction();
            let mut index = self
                .index_in_transaction(&txn)
                .context("cannot read index")?;
            key = index.remove(id).context("cannot remove key")?;
            if key.is_empty() {
                bail!("corrupt index");
            }
            let indexed_key = T::make_indexed_key(Cow::Borrowed(&key), id);
            txn.put_cf(
                self.cf(),
                [],
                bincode::DefaultOptions::new()
                    .serialize(&index)
                    .context("failed to serialize index")?,
            )
            .context("failed to update database index")?;
            txn.delete_cf(self.cf(), indexed_key)
                .context("failed to remove entry")?;
            match txn.commit() {
                Ok(()) => break,
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to remove entry");
                    }
                }
            }
        }
        Ok(key)
    }

    /// Removes a key-value pair with the given ID within a transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    fn remove_with_transaction<T: Indexable>(
        &self,
        id: u32,
        txn: &rocksdb::Transaction<rocksdb::OptimisticTransactionDB>,
    ) -> Result<Vec<u8>> {
        let mut index = self
            .index_in_transaction(txn)
            .context("cannot read index")?;
        let key = index.remove(id).context("cannot remove key")?;
        if key.is_empty() {
            bail!("corrupt index");
        }
        let indexed_key = T::make_indexed_key(Cow::Borrowed(&key), id);
        txn.put_cf(
            self.cf(),
            [],
            bincode::DefaultOptions::new()
                .serialize(&index)
                .context("failed to serialize index")?,
        )
        .context("failed to update database index")?;
        txn.delete_cf(self.cf(), indexed_key)
            .context("failed to remove entry")?;
        Ok(key)
    }

    /// Overwrites the value of an existing key-value pair.
    ///
    /// # Errors
    ///
    /// Returns an error if the key doesn't exist.
    fn overwrite<T: Indexable>(&self, entry: &T) -> Result<()> {
        loop {
            let txn = self.db().transaction();
            if entry.indexed_key().is_empty() {
                bail!("key shouldn't be empty");
            }
            if txn
                .get_for_update_cf(self.cf(), entry.indexed_key(), super::EXCLUSIVE)
                .context("cannot read from database")?
                .is_none()
            {
                bail!("key doesn't exist");
            }
            txn.put_cf(self.cf(), entry.indexed_key(), entry.value())
                .context("failed to write new entry")?;
            match txn.commit() {
                Ok(()) => break,
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to store new entry");
                    }
                }
            }
        }
        Ok(())
    }

    /// Updates an old key-value pair to a new one.
    ///
    /// # Errors
    ///
    /// Returns an error if the `id` is invalid or the database operation fails.
    fn update<O, V>(&self, id: u32, old: &O, new: &V) -> Result<()>
    where
        O: IndexedMapUpdate,
        O::Entry: Indexable + FromKeyValue,
        V: IndexedMapUpdate,
        V::Entry: Indexable + From<O::Entry>,
    {
        loop {
            let txn = self.db().transaction();
            let mut index = self
                .index_in_transaction(&txn)
                .context("cannot read index")?;
            let cur_key = if let Some(key) = new.key() {
                if key.is_empty() {
                    bail!("key shouldn't be empty");
                }
                index.update(id, &key).context("cannot update index")?
            } else {
                Vec::new()
            };
            let key = if new.key().is_some() {
                V::Entry::make_indexed_key(Cow::Owned(cur_key), id)
            } else if let Some(key) = index.get(id).context("invalid ID")? {
                V::Entry::make_indexed_key(Cow::Borrowed(key), id)
            } else {
                bail!("no such ID");
            };

            let entry = if let Some(value) = txn
                .get_for_update_cf(self.cf(), &key, super::EXCLUSIVE)
                .context("cannot read entry")?
            {
                O::Entry::from_key_value(&key, &value).context("invalid entry in database")?
            } else {
                bail!("corrupt index");
            };
            if !old.verify(&entry) {
                bail!("entry changed");
            }
            let new_key = if let Some(new_key) = new.key() {
                let new_key = V::Entry::make_indexed_key(new_key, id);

                if new_key != key {
                    txn.delete_cf(self.cf(), &key)
                        .context("failed to delete old entry")?;
                    if txn
                        .get_pinned_cf(self.cf(), &new_key)
                        .context("cannot read from database")?
                        .is_some()
                    {
                        bail!("new key already exists");
                    }
                }
                new_key
            } else {
                key
            };

            let new_entry = new.apply(entry.into());
            txn.put_cf(self.cf(), new_key, new_entry?.value())
                .context("failed to write updated entry")?;
            txn.put_cf(
                self.cf(),
                [],
                bincode::DefaultOptions::new()
                    .serialize(&index)
                    .context("failed to serialize index")?,
            )
            .context("failed to update database index")?;
            match txn.commit() {
                Ok(()) => break,
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to update entry");
                    }
                }
            }
        }
        Ok(())
    }

    /// Updates an old key-value pair to a new one within a transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the `id` is invalid or the database operation fails.
    fn update_with_transaction<O, V>(
        &self,
        id: u32,
        old: &O,
        new: &V,
        txn: &rocksdb::Transaction<rocksdb::OptimisticTransactionDB>,
    ) -> Result<()>
    where
        O: IndexedMapUpdate,
        O::Entry: Indexable + FromKeyValue,
        V: IndexedMapUpdate,
        V::Entry: Indexable + From<O::Entry>,
    {
        let mut index = self
            .index_in_transaction(txn)
            .context("cannot read index")?;
        let cur_key = if let Some(key) = new.key() {
            if key.is_empty() {
                bail!("key shouldn't be empty");
            }
            index.update(id, &key).context("cannot update index")?
        } else {
            Vec::new()
        };
        let key = if new.key().is_some() {
            V::Entry::make_indexed_key(Cow::Owned(cur_key), id)
        } else if let Some(key) = index.get(id).context("invalid ID")? {
            V::Entry::make_indexed_key(Cow::Borrowed(key), id)
        } else {
            bail!("no such ID");
        };

        let entry = if let Some(value) = txn
            .get_for_update_cf(self.cf(), &key, super::EXCLUSIVE)
            .context("cannot read entry")?
        {
            O::Entry::from_key_value(&key, &value).context("invalid entry in database")?
        } else {
            bail!("corrupt index");
        };
        if !old.verify(&entry) {
            bail!("entry changed");
        }
        let new_key = if let Some(new_key) = new.key() {
            let new_key = V::Entry::make_indexed_key(new_key, id);

            if new_key != key {
                txn.delete_cf(self.cf(), &key)
                    .context("failed to delete old entry")?;
                if txn
                    .get_pinned_cf(self.cf(), &new_key)
                    .context("cannot read from database")?
                    .is_some()
                {
                    bail!("new key already exists");
                }
            }
            new_key
        } else {
            key
        };

        let new_entry = new.apply(entry.into());
        txn.put_cf(self.cf(), new_key, new_entry?.value())
            .context("failed to write updated entry")?;
        txn.put_cf(
            self.cf(),
            [],
            bincode::DefaultOptions::new()
                .serialize(&index)
                .context("failed to serialize index")?,
        )
        .context("failed to update database index")?;
        Ok(())
    }
}

pub trait IndexedMapUpdate {
    type Entry;

    /// Returns the key of itself.
    fn key(&self) -> Option<Cow<'_, [u8]>>;

    /// Applies the changes to the value.
    ///
    /// # Errors
    ///
    /// Returns an error if the changes are invalid or the database operation fails.
    fn apply(&self, value: Self::Entry) -> Result<Self::Entry>;

    /// Verifies that the values to change match with the current entry.
    fn verify(&self, value: &Self::Entry) -> bool;
}

#[cfg(test)]
mod tests {
    #[test]
    fn index_clear_inactive() {
        let mut index = super::KeyIndex::default();
        let id_a = index.insert(b"a").unwrap();
        assert_eq!(index.count(), 1);

        let key = index.deactivate(id_a).unwrap();
        assert_eq!(key, b"a");
        assert_eq!(index.count(), 0);

        index.clear_inactive().unwrap();
        assert_eq!(index.count(), 0);
    }
}
