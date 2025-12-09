//! The accounts table.

use std::net::IpAddr;

use anyhow::{Context, bail};
use bincode::Options;
use chrono::Utc;
use rocksdb::OptimisticTransactionDB;

use crate::{
    EXCLUSIVE, Map, Role, Table,
    types::{Account, FromKeyValue},
};

impl FromKeyValue for Account {
    fn from_key_value(_key: &[u8], value: &[u8]) -> anyhow::Result<Self> {
        super::deserialize(value)
    }
}

/// Functions for the accounts table.
impl<'d> Table<'d, Account> {
    /// Opens the accounts table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::ACCOUNTS).map(Table::new)
    }

    /// Returns `true` if the table contains an account with the given username.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn contains(&self, username: &str) -> Result<bool, anyhow::Error> {
        self.map.get(username.as_bytes()).map(|v| v.is_some())
    }

    /// Deletes an account with the given username.
    ///
    /// # Errors
    ///
    /// Returns an error if the account does not exist or the database operation fails.
    pub fn delete(&self, username: &str) -> Result<(), anyhow::Error> {
        self.map.delete(username.as_bytes())
    }

    /// Returns an account with the given username.
    ///
    /// # Errors
    ///
    /// Returns an error if the account does not exist or the database operation fails.
    pub fn get(&self, username: &str) -> Result<Option<Account>, anyhow::Error> {
        let Some(value) = self.map.get(username.as_bytes())? else {
            return Ok(None);
        };
        Ok(Some(super::deserialize(value.as_ref())?))
    }

    /// Updates an entry in account map.
    ///
    /// # Errors
    ///
    /// Returns an error in the following cases:
    ///
    /// * The account stored in the database in invalid.
    /// * Random number generation for a password salt fails.
    /// * The old values do not match the values in the database.
    /// * The underlying database operation fails.
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    pub fn update(
        &self,
        username: &[u8],
        new_password: &Option<String>,
        role: Option<(Role, Role)>,
        name: &Option<(String, String)>,
        department: &Option<(String, String)>,
        language: &Option<(Option<String>, Option<String>)>,
        theme: &Option<(Option<String>, Option<String>)>,
        allow_access_from: &Option<(Option<Vec<IpAddr>>, Option<Vec<IpAddr>>)>,
        max_parallel_sessions: &Option<(Option<u8>, Option<u8>)>,
        customer_ids: &Option<(Option<Vec<u32>>, Option<Vec<u32>>)>,
    ) -> Result<(), anyhow::Error> {
        loop {
            let txn = self.map.db.transaction();
            if let Some(old_value) = txn
                .get_for_update_cf(self.map.cf, username, EXCLUSIVE)
                .context("cannot read old entry")?
            {
                let mut account = super::deserialize::<Account>(old_value.as_ref())?;

                if let Some(password) = &new_password {
                    account.update_password(password)?;
                }

                if let Some((old, new)) = &role {
                    if account.role != *old {
                        bail!("old value mismatch");
                    }
                    account.role = *new;
                }
                if let Some((old, new)) = &name {
                    if account.name != *old {
                        bail!("old value mismatch");
                    }
                    account.name.clone_from(new);
                }
                if let Some((old, new)) = &department {
                    if account.department != *old {
                        bail!("old value mismatch");
                    }
                    account.department.clone_from(new);
                }
                if let Some((old, new)) = language {
                    if account.language != *old {
                        bail!("old value mismatch");
                    }
                    account.language.clone_from(new);
                }
                if let Some((old, new)) = theme {
                    if account.theme != *old {
                        bail!("old value mismatch");
                    }
                    account.theme.clone_from(new);
                }
                if let Some((old, new)) = &allow_access_from {
                    if account.allow_access_from != *old {
                        bail!("old value mismatch");
                    }
                    account.allow_access_from.clone_from(new);
                }
                if let Some((old, new)) = max_parallel_sessions {
                    if account.max_parallel_sessions != *old {
                        bail!("old value mismatch");
                    }
                    account.max_parallel_sessions = *new;
                }
                if let Some((old, new)) = customer_ids {
                    if account.customer_ids != *old {
                        bail!("old value mismatch");
                    }
                    account.customer_ids.clone_from(new);
                }

                let value = bincode::DefaultOptions::new().serialize(&account)?;
                txn.put_cf(self.map.cf, username, value)
                    .context("failed to write new entry")?;
            } else {
                bail!("no such entry");
            }

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

    /// Increments the failed login attempts for an account with the given username.
    /// If the account reaches the lockout threshold, it will be locked out.
    ///
    /// # Errors
    ///
    /// Returns an error if the account does not exist or the database operation fails.
    pub fn increment_failed_login(&self, username: &str) -> Result<(), anyhow::Error> {
        const LOCKOUT_THRESHOLD: u8 = 5;
        const LOCKOUT_DURATION_MINUTES: i64 = 30;

        loop {
            let txn = self.map.db.transaction();
            if let Some(old_value) = txn
                .get_for_update_cf(self.map.cf, username.as_bytes(), EXCLUSIVE)
                .context("cannot read old entry")?
            {
                let options = bincode::DefaultOptions::new();
                let Ok(mut account) = options.deserialize::<Account>(old_value.as_ref()) else {
                    return Err(anyhow::anyhow!("Failed to deserialize account data"));
                };

                account.failed_login_attempts = account.failed_login_attempts.saturating_add(1);

                if account.failed_login_attempts >= LOCKOUT_THRESHOLD {
                    account.locked_out_until =
                        Some(Utc::now() + chrono::Duration::minutes(LOCKOUT_DURATION_MINUTES));
                }

                let value = bincode::DefaultOptions::new().serialize(&account)?;
                txn.put_cf(self.map.cf, username.as_bytes(), value)
                    .context("failed to write updated entry")?;
            } else {
                bail!("no such entry");
            }

            match txn.commit() {
                Ok(()) => break,
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to increment failed login");
                    }
                }
            }
        }
        Ok(())
    }

    /// Clears the failed login attempts for an account with the given username.
    /// Also unlocks the account if it was locked out.
    ///
    /// # Errors
    ///
    /// Returns an error if the account does not exist or the database operation fails.
    pub fn clear_failed_logins(&self, username: &str) -> Result<(), anyhow::Error> {
        loop {
            let txn = self.map.db.transaction();
            if let Some(old_value) = txn
                .get_for_update_cf(self.map.cf, username.as_bytes(), EXCLUSIVE)
                .context("cannot read old entry")?
            {
                let options = bincode::DefaultOptions::new();
                let Ok(mut account) = options.deserialize::<Account>(old_value.as_ref()) else {
                    return Err(anyhow::anyhow!("Failed to deserialize account data"));
                };

                account.failed_login_attempts = 0;
                account.locked_out_until = None;

                let value = bincode::DefaultOptions::new().serialize(&account)?;
                txn.put_cf(self.map.cf, username.as_bytes(), value)
                    .context("failed to write updated entry")?;
            } else {
                bail!("no such entry");
            }

            match txn.commit() {
                Ok(()) => break,
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to clear failed logins");
                    }
                }
            }
        }
        Ok(())
    }

    /// Checks if an account is currently locked out.
    /// Automatically unlocks accounts whose lockout period has expired.
    ///
    /// # Errors
    ///
    /// Returns an error if the account does not exist or the database operation fails.
    pub fn is_account_locked(&self, username: &str) -> Result<bool, anyhow::Error> {
        let Some(account) = self.get(username)? else {
            bail!("no such entry");
        };

        if let Some(locked_until) = account.locked_out_until {
            if Utc::now() >= locked_until {
                self.clear_failed_logins(username)?;
                Ok(false)
            } else {
                Ok(true)
            }
        } else {
            Ok(false)
        }
    }

    /// Suspends an account with the given username.
    ///
    /// # Errors
    ///
    /// Returns an error if the account does not exist or the database operation fails.
    pub fn suspend_account(&self, username: &str) -> Result<(), anyhow::Error> {
        loop {
            let txn = self.map.db.transaction();
            if let Some(old_value) = txn
                .get_for_update_cf(self.map.cf, username.as_bytes(), EXCLUSIVE)
                .context("cannot read old entry")?
            {
                let options = bincode::DefaultOptions::new();
                let Ok(mut account) = options.deserialize::<Account>(old_value.as_ref()) else {
                    return Err(anyhow::anyhow!("Failed to deserialize account data"));
                };

                account.is_suspended = true;

                let value = bincode::DefaultOptions::new().serialize(&account)?;
                txn.put_cf(self.map.cf, username.as_bytes(), value)
                    .context("failed to write updated entry")?;
            } else {
                bail!("no such entry");
            }

            match txn.commit() {
                Ok(()) => break,
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to suspend account");
                    }
                }
            }
        }
        Ok(())
    }

    /// Unsuspends an account with the given username.
    ///
    /// # Errors
    ///
    /// Returns an error if the account does not exist or the database operation fails.
    pub fn unsuspend_account(&self, username: &str) -> Result<(), anyhow::Error> {
        loop {
            let txn = self.map.db.transaction();
            if let Some(old_value) = txn
                .get_for_update_cf(self.map.cf, username.as_bytes(), EXCLUSIVE)
                .context("cannot read old entry")?
            {
                let options = bincode::DefaultOptions::new();
                let Ok(mut account) = options.deserialize::<Account>(old_value.as_ref()) else {
                    return Err(anyhow::anyhow!("Failed to deserialize account data"));
                };

                account.is_suspended = false;

                let value = bincode::DefaultOptions::new().serialize(&account)?;
                txn.put_cf(self.map.cf, username.as_bytes(), value)
                    .context("failed to write updated entry")?;
            } else {
                bail!("no such entry");
            }

            match txn.commit() {
                Ok(()) => break,
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to unsuspend account");
                    }
                }
            }
        }
        Ok(())
    }

    /// Returns all accounts with their security status information.
    /// This method is useful for administrative dashboards showing user security states.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn get_accounts_with_security_status(&self) -> Result<Vec<Account>, anyhow::Error> {
        use crate::Iterable;

        let mut accounts = Vec::new();
        let iter = self.iter(rocksdb::Direction::Forward, None);

        for account in iter {
            accounts.push(account?);
        }

        Ok(accounts)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{Role, Store, tables::Direction, types::Account};

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        (permit, store)
    }

    #[test]
    fn put_delete() {
        let (_permit, store) = setup_store();
        let table = store.account_map();

        assert!(!table.contains("user1").unwrap());
        let acc1 = Account::new(
            "user1",
            "password",
            Role::SystemAdministrator,
            "User 1".to_string(),
            "Department 1".to_string(),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        table.put(&acc1).unwrap();
        assert!(table.contains("user1").unwrap());

        let acc2 = Account::new(
            "user2",
            "password",
            Role::SystemAdministrator,
            "User 2".to_string(),
            "Department 2".to_string(),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        table.put(&acc2).unwrap();
        assert!(table.contains("user2").unwrap());

        table.delete("user1").unwrap();
        assert!(!table.contains("user1").unwrap());
    }

    #[test]
    fn iter() {
        use crate::Iterable;

        let (_permit, store) = setup_store();
        let table = store.account_map();

        let mut iter = table.iter(Direction::Forward, None);
        assert!(iter.next().is_none());

        let acc1 = Account::new(
            "user1",
            "password",
            Role::SystemAdministrator,
            "User 1".to_string(),
            "Department 1".to_string(),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        table.put(&acc1).unwrap();

        let mut iter = table.iter(Direction::Forward, None);
        let acc = iter.next().unwrap().unwrap();
        assert_eq!(acc.username, "user1");
        assert!(iter.next().is_none());

        let acc2 = Account::new(
            "user2",
            "password",
            Role::SystemAdministrator,
            "User 2".to_string(),
            "Department 2".to_string(),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        table.put(&acc2).unwrap();

        let mut iter = table.iter(Direction::Forward, Some(b"user2"));
        let acc = iter.next().unwrap().unwrap();
        assert_eq!(acc.username, "user2");

        let mut iter = table.iter(Direction::Reverse, None);
        let acc = iter.next().unwrap().unwrap();
        assert_eq!(acc.username, "user2");

        let mut iter = table.iter(Direction::Reverse, Some(b"user1"));
        let acc = iter.next().unwrap().unwrap();
        assert_eq!(acc.username, "user1");
    }

    #[test]
    fn put_duplicate_key() {
        use crate::Iterable;

        let (_permit, store) = setup_store();
        let table = store.account_map();

        // Insert first account
        let acc1 = Account::new(
            "user1",
            "password1",
            Role::SystemAdministrator,
            "User 1".to_string(),
            "Department 1".to_string(),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        table.put(&acc1).unwrap();
        assert!(table.contains("user1").unwrap());

        // Get the first account to verify it was stored
        let retrieved_acc1 = table.get("user1").unwrap().unwrap();
        assert_eq!(retrieved_acc1.username, "user1");
        assert_eq!(retrieved_acc1.name, "User 1");
        assert_eq!(retrieved_acc1.department, "Department 1");

        // Insert second account with same username but different data
        let acc2 = Account::new(
            "user1",     // Same username
            "password2", // Different password
            Role::SystemAdministrator,
            "User 1 Updated".to_string(), // Different name
            "Department 2".to_string(),   // Different department
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        table.put(&acc2).unwrap();

        // Verify the account was overwritten with new data
        let retrieved_acc2 = table.get("user1").unwrap().unwrap();
        assert_eq!(retrieved_acc2.username, "user1");
        assert_eq!(retrieved_acc2.name, "User 1 Updated");
        assert_eq!(retrieved_acc2.department, "Department 2");

        // Verify password was updated by checking the passwords match the respective accounts
        assert!(!retrieved_acc2.verify_password("password1")); // Old password should not work
        assert!(retrieved_acc2.verify_password("password2")); // New password should work

        // Verify there's only one entry in the table (the duplicate key overwrote the original)
        let mut iter = table.iter(Direction::Forward, None);
        let first_entry = iter.next().unwrap().unwrap();
        assert_eq!(first_entry.username, "user1");
        assert_eq!(first_entry.name, "User 1 Updated"); // Should have the updated data
        assert!(iter.next().is_none()); // Should be no more entries
    }

    #[test]
    fn test_failed_login_attempts() {
        let (_permit, store) = setup_store();
        let table = store.account_map();

        let account = Account::new(
            "user1",
            "password",
            Role::SystemAdministrator,
            "User 1".to_string(),
            "Department 1".to_string(),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        table.put(&account).unwrap();

        assert!(!table.is_account_locked("user1").unwrap());

        table.increment_failed_login("user1").unwrap();
        let retrieved = table.get("user1").unwrap().unwrap();
        assert_eq!(retrieved.failed_login_attempts, 1);
        assert!(retrieved.locked_out_until.is_none());

        for _ in 0..4 {
            table.increment_failed_login("user1").unwrap();
        }

        let locked_account = table.get("user1").unwrap().unwrap();
        assert_eq!(locked_account.failed_login_attempts, 5);
        assert!(locked_account.locked_out_until.is_some());
        assert!(table.is_account_locked("user1").unwrap());

        table.clear_failed_logins("user1").unwrap();
        let cleared_account = table.get("user1").unwrap().unwrap();
        assert_eq!(cleared_account.failed_login_attempts, 0);
        assert!(cleared_account.locked_out_until.is_none());
        assert!(!table.is_account_locked("user1").unwrap());
    }

    #[test]
    fn test_account_suspension() {
        let (_permit, store) = setup_store();
        let table = store.account_map();

        let account = Account::new(
            "user1",
            "password",
            Role::SystemAdministrator,
            "User 1".to_string(),
            "Department 1".to_string(),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        table.put(&account).unwrap();

        let initial_account = table.get("user1").unwrap().unwrap();
        assert!(!initial_account.is_suspended);

        table.suspend_account("user1").unwrap();
        let suspended_account = table.get("user1").unwrap().unwrap();
        assert!(suspended_account.is_suspended);

        table.unsuspend_account("user1").unwrap();
        let unsuspended_account = table.get("user1").unwrap().unwrap();
        assert!(!unsuspended_account.is_suspended);
    }

    #[test]
    fn test_get_accounts_with_security_status() {
        let (_permit, store) = setup_store();
        let table = store.account_map();

        let account1 = Account::new(
            "user1",
            "password",
            Role::SystemAdministrator,
            "User 1".to_string(),
            "Department 1".to_string(),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        table.put(&account1).unwrap();

        let account2 = Account::new(
            "user2",
            "password",
            Role::SecurityMonitor,
            "User 2".to_string(),
            "Department 2".to_string(),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        table.put(&account2).unwrap();

        table.suspend_account("user1").unwrap();
        table.increment_failed_login("user2").unwrap();

        let security_accounts = table.get_accounts_with_security_status().unwrap();
        assert_eq!(security_accounts.len(), 2);

        let user1 = security_accounts
            .iter()
            .find(|a| a.username == "user1")
            .unwrap();
        assert!(user1.is_suspended);
        assert_eq!(user1.failed_login_attempts, 0);

        let user2 = security_accounts
            .iter()
            .find(|a| a.username == "user2")
            .unwrap();
        assert!(!user2.is_suspended);
        assert_eq!(user2.failed_login_attempts, 1);
    }

    #[test]
    fn test_lockout_expiration() {
        use std::{thread, time::Duration};

        let (_permit, store) = setup_store();
        let table = store.account_map();

        let mut account = Account::new(
            "user1",
            "password",
            Role::SystemAdministrator,
            "User 1".to_string(),
            "Department 1".to_string(),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        account.failed_login_attempts = 5;
        account.locked_out_until = Some(chrono::Utc::now() + chrono::Duration::milliseconds(100));
        table.put(&account).unwrap();

        assert!(table.is_account_locked("user1").unwrap());

        thread::sleep(Duration::from_millis(200));

        assert!(!table.is_account_locked("user1").unwrap());

        let unlocked_account = table.get("user1").unwrap().unwrap();
        assert_eq!(unlocked_account.failed_login_attempts, 0);
        assert!(unlocked_account.locked_out_until.is_none());
    }
}
