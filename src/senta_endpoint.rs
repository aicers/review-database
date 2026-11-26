//! The multi-table writes of the Clumit Endpoint (`senta`) tables (taco RFC
//! 0016 §4.4, §4.6, §7), and the stores of detection events about an
//! endpoint, which check the endpoint, the engine's customer and the
//! customer's data deletion job in the same transaction.
//!
//! # Transactions
//!
//! Every method here is one optimistic transaction, restarted from the
//! beginning on a commit conflict: it writes all of its rows or none, and a
//! refusal returns without committing.
//!
//! Every method that writes a row of a customer first checks the customer's
//! data deletion job: it reads the job row for update and refuses if there is
//! one. A job created after that read makes the method's commit conflict, and
//! its retry is refused, so no row a deletion removes is written back once the
//! deletion has started.
//!
//! [`Store::put_endpoint_detection_event`] and
//! [`Store::put_endpoint_detection_event_unless_stored`] write a detection
//! event record of an endpoint's customer, so they check the same way: they
//! read the endpoint row, the engine's node row for update and the deletion
//! job row of the endpoint's customer for update, and write the record, its
//! arrival index row and the last arrival time in the same transaction.
//! [`Store::create_customer_data_deletion_job`] writes that job row, so a
//! store racing it conflicts, retries and is refused, and a store committed
//! before it is removed by the deletion's
//! [`EventDb::remove_by_sensors`](crate::EventDb::remove_by_sensors) on the
//! customer's endpoint IDs. A job creation that no longer wrote the job row
//! would let an endpoint detection event of the customer survive its
//! deletion. These two methods also hold the arrival lock from before their
//! first attempt until their commit, as [`EventDb::put`](crate::EventDb::put)
//! does.
//!
//! A scan is not tracked by the transaction it runs in. Where a method acts on
//! the rows it found by a scan, it first reads a row for update that every
//! writer of a row the scan could find writes too, as `model_guard` does for
//! indicators:
//!
//! - [`Store::create_customer_data_deletion_job`] reads the customer row for
//!   update before it scans the endpoint table, and
//!   [`Store::approve_senta_endpoint_enrollment`], the only writer of a new
//!   endpoint row, writes the customer row back unchanged. An approval that
//!   commits after that read makes the job creation conflict and scan again;
//!   one that commits before it is in the scan; and one that commits after
//!   the job conflicts on the job row it read and is refused on its retry. So
//!   the approved endpoint is either in the job's `endpoint_ids` or the
//!   approval is refused.
//!   [`Store::replace_senta_endpoint_enrollment_result`] writes the customer
//!   row back unchanged too, so a replacement that commits after that read
//!   makes the job creation conflict and run again, and one that commits
//!   after the job is refused.
//! - [`Store::rotate_senta_endpoint_recovery_key`] reads the install row for
//!   update before it scans the customer table, and
//!   [`Store::register_senta_endpoint_customer`], the only writer of a new
//!   customer row, writes the install row back unchanged, so a customer
//!   registered concurrently is either in the scan or refused for its
//!   recovery key version.

use anyhow::{Context, anyhow};
use review_protocol::types::DetectionEvent;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    CustomerDataDeletionJob, DetectionEventStamp, PutOutcome, SentaEndpoint,
    SentaEndpointAddressRoot, SentaEndpointCommand, SentaEndpointCommandState,
    SentaEndpointCurrentDocument, SentaEndpointCustomer, SentaEndpointDeletionState,
    SentaEndpointEnrollmentAttempt, SentaEndpointEnrollmentResult, SentaEndpointError,
    SentaEndpointInstall, SentaEndpointKeysetDocument, SentaEndpointRecoveryKeyDocument, Store,
    Table,
    tables::{
        SentaEndpointTxn as Txn, is_senta_endpoint_conflict as is_conflict,
        senta_endpoint_keys as keys,
    },
};

/// The points of the transaction methods at which the tests' hook runs.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HookPoint {
    /// Before the commit of the named method, after its reads and writes.
    BeforeCommit(Method),
    /// In [`Store::create_customer_data_deletion_job`], after it read the
    /// customer row and before it scans the endpoint table.
    DeletionJobBeforeScan,
}

/// The transaction methods, as a commit error and the tests' hook name them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Method {
    RegisterCustomer,
    ReceiveKeysetDocument,
    WriteCurrentDocument,
    InsertCommand,
    RotateRecoveryKey,
    ApproveEnrollment,
    ReplaceEnrollmentResult,
    CreateDeletionJob,
    /// [`Store::put_endpoint_detection_event`] and
    /// [`Store::put_endpoint_detection_event_unless_stored`].
    PutEndpointDetectionEvent,
}

/// Why an endpoint detection event was not stored by
/// [`Store::put_endpoint_detection_event`] or
/// [`Store::put_endpoint_detection_event_unless_stored`].
///
/// Every variant but [`Database`](Self::Database) is a refusal, after which
/// nothing was written.
#[derive(Debug, Error)]
pub enum EndpointDetectionEventError {
    /// The endpoint has no row.
    #[error("no senta endpoint {endpoint_id}")]
    UnknownEndpoint { endpoint_id: Uuid },
    /// The endpoint's customer is not the current customer of the engine's
    /// node, which is `None` when the node has no row or no applied profile.
    #[error(
        "senta endpoint {endpoint_id} of customer {endpoint_customer} does not belong to the \
         engine's customer {}",
        engine_customer.map_or_else(|| "(none)".to_string(), |id| id.to_string())
    )]
    EndpointOfAnotherCustomer {
        endpoint_id: Uuid,
        endpoint_customer: u32,
        engine_customer: Option<u32>,
    },
    /// The endpoint's customer has a data deletion job, unfinished or done.
    #[error("customer {customer_id} of senta endpoint {endpoint_id} has a data deletion job")]
    EndpointCustomerDeleted { endpoint_id: Uuid, customer_id: u32 },
    /// The database read or write failed, a stored row was invalid, or the
    /// event could not be stored.
    #[error(transparent)]
    Database(#[from] anyhow::Error),
}

/// A hook the tests run at every [`HookPoint`] of the transaction methods,
/// with the store running the method; an error it returns ends the method
/// with that error.
#[cfg(test)]
pub(crate) type SentaEndpointHook =
    std::sync::Arc<dyn Fn(&Store, HookPoint) -> anyhow::Result<()> + Send + Sync>;

impl Store {
    /// Returns the table of the trust state of each customer.
    #[must_use]
    pub fn senta_endpoint_customer_map(&self) -> Table<'_, SentaEndpointCustomer> {
        self.states.senta_endpoint_table()
    }

    /// Returns the table of the recovery keys of each install.
    #[must_use]
    pub fn senta_endpoint_install_map(&self) -> Table<'_, SentaEndpointInstall> {
        self.states.senta_endpoint_table()
    }

    /// Returns the table of the enrolled endpoints.
    #[must_use]
    pub fn senta_endpoint_map(&self) -> Table<'_, SentaEndpoint> {
        self.states.senta_endpoint_table()
    }

    /// Returns the table of the enrollment attempts.
    #[must_use]
    pub fn senta_endpoint_enrollment_attempt_map(
        &self,
    ) -> Table<'_, SentaEndpointEnrollmentAttempt> {
        self.states.senta_endpoint_table()
    }

    /// Returns the table of the keyset documents of each customer.
    #[must_use]
    pub fn senta_endpoint_keyset_document_map(&self) -> Table<'_, SentaEndpointKeysetDocument> {
        self.states.senta_endpoint_table()
    }

    /// Returns the table of the recovery-key documents of each install.
    #[must_use]
    pub fn senta_endpoint_recovery_key_document_map(
        &self,
    ) -> Table<'_, SentaEndpointRecoveryKeyDocument> {
        self.states.senta_endpoint_table()
    }

    /// Returns the table of the current documents of each customer.
    #[must_use]
    pub fn senta_endpoint_current_document_map(&self) -> Table<'_, SentaEndpointCurrentDocument> {
        self.states.senta_endpoint_table()
    }

    /// Returns the table of the root certificates the address documents of
    /// each customer name.
    #[must_use]
    pub fn senta_endpoint_address_root_map(&self) -> Table<'_, SentaEndpointAddressRoot> {
        self.states.senta_endpoint_table()
    }

    /// Returns the table of the commands of the endpoints.
    #[must_use]
    pub fn senta_endpoint_command_map(&self) -> Table<'_, SentaEndpointCommand> {
        self.states.senta_endpoint_table()
    }

    /// Registers a customer: writes its row and its first keyset document.
    ///
    /// The install the customer row names is read for update and written back
    /// unchanged, so that a concurrent recovery-key rotation of the install
    /// that scanned its customers before this commit conflicts and scans
    /// again. A keyset document already stored under the document's key is not
    /// written again.
    ///
    /// # Errors
    ///
    /// Returns, writing nothing:
    ///
    /// - [`SentaEndpointError::DocumentOfAnotherCustomer`] if the document is
    ///   of another customer than the row;
    /// - [`SentaEndpointError::CustomerDeletion`] if the customer has a data
    ///   deletion job;
    /// - [`SentaEndpointError::InstallNotFound`] if the install has no row;
    /// - [`SentaEndpointError::RecoveryKeyVersionMismatch`] if the install's
    ///   current recovery key version is not the row's recovery key version;
    /// - [`SentaEndpointError::CustomerExists`] if the customer has a row;
    /// - [`SentaEndpointError::Database`] if a database operation fails or a
    ///   stored row is invalid.
    pub fn register_senta_endpoint_customer(
        &self,
        customer: &SentaEndpointCustomer,
        keyset_document: &SentaEndpointKeysetDocument,
    ) -> Result<(), SentaEndpointError> {
        let customer_id = customer.customer_id;
        if keyset_document.customer_id != customer_id {
            return Err(SentaEndpointError::DocumentOfAnotherCustomer { customer_id });
        }
        let customers = self.senta_endpoint_customer_map();
        let installs = self.senta_endpoint_install_map();
        let documents = self.senta_endpoint_keyset_document_map();
        self.write_senta_endpoint(Method::RegisterCustomer, |txn| {
            self.check_deletion_job(txn, customer_id)?;
            let install_key = keys::install(&customer.install_id);
            let Some(install) = installs.row_for_update(txn, &install_key)? else {
                return Err(SentaEndpointError::InstallNotFound {
                    install_id: customer.install_id.clone(),
                });
            };
            if install.current_recovery_key_version != customer.recovery_key_version {
                return Err(SentaEndpointError::RecoveryKeyVersionMismatch {
                    install_id: customer.install_id.clone(),
                    install_version: install.current_recovery_key_version,
                    customer_version: customer.recovery_key_version,
                });
            }
            installs.write_row(txn, &install)?;
            if customers.exists_for_update(txn, &keys::customer(customer_id))? {
                return Err(SentaEndpointError::CustomerExists { customer_id });
            }
            customers.write_row(txn, customer)?;
            write_keyset_document(&documents, txn, keyset_document)?;
            Ok(())
        })
    }

    /// Receives a keyset document of a customer, and returns whether the
    /// document row was written.
    ///
    /// A document already stored under the document's key (customer, recovery
    /// epoch, keyset version, signing key ID) is not written again, and its
    /// stored JWS stays as it is. With `customer`, the customer's row is
    /// replaced by it, which may change its trust state and copy columns;
    /// without it, the method only archives the document.
    ///
    /// # Errors
    ///
    /// Returns, writing nothing:
    ///
    /// - [`SentaEndpointError::DocumentOfAnotherCustomer`] if `customer` is of
    ///   another customer than the document;
    /// - [`SentaEndpointError::CustomerDeletion`] if the customer has a data
    ///   deletion job;
    /// - [`SentaEndpointError::CustomerNotFound`] if the customer has no row;
    /// - [`SentaEndpointError::CustomerColumnChanged`] if `customer` changes
    ///   the install ID or the recovery key version of the stored row, which
    ///   only registration and a recovery-key rotation set;
    /// - [`SentaEndpointError::Database`] if a database operation fails or a
    ///   stored row is invalid.
    pub fn receive_senta_endpoint_keyset_document(
        &self,
        document: &SentaEndpointKeysetDocument,
        customer: Option<&SentaEndpointCustomer>,
    ) -> Result<bool, SentaEndpointError> {
        let customer_id = document.customer_id;
        if customer.is_some_and(|row| row.customer_id != customer_id) {
            return Err(SentaEndpointError::DocumentOfAnotherCustomer { customer_id });
        }
        let customers = self.senta_endpoint_customer_map();
        let documents = self.senta_endpoint_keyset_document_map();
        self.write_senta_endpoint(Method::ReceiveKeysetDocument, |txn| {
            self.check_deletion_job(txn, customer_id)?;
            let Some(stored) = customers.row_for_update(txn, &keys::customer(customer_id))? else {
                return Err(SentaEndpointError::CustomerNotFound { customer_id });
            };
            if let Some(customer) = customer {
                if customer.install_id != stored.install_id {
                    return Err(SentaEndpointError::CustomerColumnChanged {
                        customer_id,
                        column: "install ID",
                    });
                }
                if customer.recovery_key_version != stored.recovery_key_version {
                    return Err(SentaEndpointError::CustomerColumnChanged {
                        customer_id,
                        column: "recovery key version",
                    });
                }
                customers.write_row(txn, customer)?;
            }
            write_keyset_document(&documents, txn, document)
        })
    }

    /// Writes the current document of a customer for its `typ` and target,
    /// and returns whether it was written.
    ///
    /// The stored document is replaced only when the new one's (recovery
    /// epoch, version) is greater in lexicographic order, or when there is
    /// none; otherwise nothing is written and `Ok(false)` is returned. This
    /// guards against a concurrent writer putting an older document back; it
    /// does not choose the current document, which is the caller's choice.
    ///
    /// When the document is written, one address-document root row is written
    /// for each fingerprint of `address_roots`, under the customer and the
    /// document's recovery epoch and version. An address document is written
    /// with its roots; any other document with none.
    ///
    /// # Errors
    ///
    /// Returns, writing nothing, [`SentaEndpointError::CustomerDeletion`] if
    /// the customer has a data deletion job, or
    /// [`SentaEndpointError::Database`] if a database operation fails or a
    /// stored row is invalid.
    pub fn write_senta_endpoint_current_document(
        &self,
        document: &SentaEndpointCurrentDocument,
        address_roots: &[[u8; 32]],
    ) -> Result<bool, SentaEndpointError> {
        let customer_id = document.customer_id;
        let documents = self.senta_endpoint_current_document_map();
        let roots = self.senta_endpoint_address_root_map();
        self.write_senta_endpoint(Method::WriteCurrentDocument, |txn| {
            self.check_deletion_job(txn, customer_id)?;
            let key = keys::current_document(customer_id, &document.typ, &document.target);
            if let Some(stored) = documents.row_for_update(txn, &key)?
                && (document.recovery_epoch, document.version)
                    <= (stored.recovery_epoch, stored.version)
            {
                return Ok(false);
            }
            documents.write_row(txn, document)?;
            for fingerprint in address_roots {
                roots.write_row(
                    txn,
                    &SentaEndpointAddressRoot {
                        customer_id,
                        recovery_epoch: document.recovery_epoch,
                        version: document.version,
                        fingerprint: *fingerprint,
                    },
                )?;
            }
            Ok(true)
        })
    }

    /// Inserts a pending command for an endpoint of `customer_id`.
    ///
    /// # Errors
    ///
    /// Returns, writing nothing:
    ///
    /// - [`SentaEndpointError::CommandNotPending`] if the command is not
    ///   pending or carries a result;
    /// - [`SentaEndpointError::CustomerDeletion`] if the customer has a data
    ///   deletion job;
    /// - [`SentaEndpointError::EndpointNotFound`] if the endpoint the command
    ///   names has no row;
    /// - [`SentaEndpointError::EndpointOfAnotherCustomer`] if that endpoint
    ///   belongs to another customer;
    /// - [`SentaEndpointError::CommandExists`] if the command ID has a row;
    /// - [`SentaEndpointError::Database`] if a database operation fails or a
    ///   stored row is invalid.
    pub fn insert_senta_endpoint_command(
        &self,
        customer_id: u32,
        command: &SentaEndpointCommand,
    ) -> Result<(), SentaEndpointError> {
        let command_id = command.command_id;
        if command.state != SentaEndpointCommandState::Pending || command.result.is_some() {
            return Err(SentaEndpointError::CommandNotPending { command_id });
        }
        let endpoints = self.senta_endpoint_map();
        let commands = self.senta_endpoint_command_map();
        self.write_senta_endpoint(Method::InsertCommand, |txn| {
            self.check_deletion_job(txn, customer_id)?;
            let endpoint_id = command.endpoint_id;
            let Some(endpoint) = endpoints.row_for_update(txn, &keys::endpoint(endpoint_id))?
            else {
                return Err(SentaEndpointError::EndpointNotFound { endpoint_id });
            };
            if endpoint.customer_id != customer_id {
                return Err(SentaEndpointError::EndpointOfAnotherCustomer {
                    endpoint_id,
                    customer_id,
                });
            }
            if commands.exists_for_update(txn, &keys::command(command_id))? {
                return Err(SentaEndpointError::CommandExists { command_id });
            }
            commands.write_row(txn, command)?;
            Ok(())
        })
    }

    /// Receives a recovery-key rotation of an install, and returns the IDs of
    /// the customers whose rows were written, in ascending order.
    ///
    /// The install and the new recovery key version are those of `document`.
    /// The method writes the document, sets the install's current recovery key
    /// to `current_recovery_key` at the document's version, leaving its first
    /// key as it is, and replaces the row of every customer of the install
    /// that has no data deletion job by the one `customers` gives for it. A
    /// customer with a deletion job is not written, and a row `customers`
    /// gives for it is ignored. An install with no customer is valid.
    ///
    /// # Errors
    ///
    /// Returns, writing nothing:
    ///
    /// - [`SentaEndpointError::DuplicateCustomerRow`] if `customers` has two
    ///   rows of one customer;
    /// - [`SentaEndpointError::InstallNotFound`] if the install has no row;
    /// - [`SentaEndpointError::CustomerNotOfInstall`] if a row of `customers`
    ///   is of a customer that is not a customer of the install, or a row to
    ///   be written names another install;
    /// - [`SentaEndpointError::CustomerRecoveryKeyVersion`] if a row to be
    ///   written carries another recovery key version than the document's;
    /// - [`SentaEndpointError::CustomerRowMissing`] if a customer of the
    ///   install with no deletion job has no row in `customers`;
    /// - [`SentaEndpointError::Database`] if a database operation fails or a
    ///   stored row is invalid.
    pub fn rotate_senta_endpoint_recovery_key(
        &self,
        document: &SentaEndpointRecoveryKeyDocument,
        current_recovery_key: &str,
        customers: &[SentaEndpointCustomer],
    ) -> Result<Vec<u32>, SentaEndpointError> {
        let install_id = document.install_id.as_str();
        let version = document.recovery_key_version;
        let mut given = std::collections::BTreeMap::new();
        for row in customers {
            let customer_id = row.customer_id;
            if given.insert(customer_id, row).is_some() {
                return Err(SentaEndpointError::DuplicateCustomerRow { customer_id });
            }
        }

        let customer_table = self.senta_endpoint_customer_map();
        let installs = self.senta_endpoint_install_map();
        let documents = self.senta_endpoint_recovery_key_document_map();
        self.write_senta_endpoint(Method::RotateRecoveryKey, |txn| {
            let Some(mut install) = installs.row_for_update(txn, &keys::install(install_id))?
            else {
                return Err(SentaEndpointError::InstallNotFound {
                    install_id: install_id.to_string(),
                });
            };
            let mut written = Vec::new();
            let mut skipped = Vec::new();
            for scanned in customer_table.rows_where(|row| row.install_id == install_id)? {
                let customer_id = scanned.customer_id;
                // The row was found by an untracked scan and may have changed
                // since; the row read for update decides.
                let Some(stored) =
                    customer_table.row_for_update(txn, &keys::customer(customer_id))?
                else {
                    continue;
                };
                if stored.install_id != install_id {
                    continue;
                }
                if self.deletion_job_state(txn, customer_id)?.is_some() {
                    skipped.push(customer_id);
                    continue;
                }
                let Some(row) = given.get(&customer_id) else {
                    return Err(SentaEndpointError::CustomerRowMissing { customer_id });
                };
                // Only a row to be written is checked: one given for a
                // customer with a deletion job is ignored, whatever it holds.
                if row.install_id != install_id {
                    return Err(SentaEndpointError::CustomerNotOfInstall {
                        customer_id,
                        install_id: install_id.to_string(),
                    });
                }
                if row.recovery_key_version != version {
                    return Err(SentaEndpointError::CustomerRecoveryKeyVersion {
                        customer_id,
                        expected: version,
                        found: row.recovery_key_version,
                    });
                }
                written.push(*row);
            }
            if let Some(&customer_id) = given.keys().find(|customer_id| {
                !written.iter().any(|row| row.customer_id == **customer_id)
                    && !skipped.contains(customer_id)
            }) {
                return Err(SentaEndpointError::CustomerNotOfInstall {
                    customer_id,
                    install_id: install_id.to_string(),
                });
            }

            documents.write_row(txn, document)?;
            current_recovery_key.clone_into(&mut install.current_recovery_key);
            install.current_recovery_key_version = version;
            installs.write_row(txn, &install)?;
            for row in &written {
                customer_table.write_row(txn, row)?;
            }
            Ok(written.iter().map(|row| row.customer_id).collect())
        })
    }

    /// Approves an enrollment attempt: sets its result to approved with the
    /// enrollment-result JWS `enrollment_result` and writes the new endpoint
    /// row.
    ///
    /// The row of the endpoint's customer is read for update and written back
    /// unchanged, so that a deletion job created concurrently either lists the
    /// endpoint or refuses this approval.
    ///
    /// # Errors
    ///
    /// Returns, writing nothing:
    ///
    /// - [`SentaEndpointError::AttemptMismatch`] if the endpoint's SPKI hash
    ///   is not the attempt's, or the attempt is of another customer than the
    ///   endpoint;
    /// - [`SentaEndpointError::CustomerDeletion`] if the endpoint's customer
    ///   has a data deletion job;
    /// - [`SentaEndpointError::CustomerNotFound`] if the customer has no row;
    /// - [`SentaEndpointError::AttemptNotFound`] if the attempt has no row;
    /// - [`SentaEndpointError::AttemptApproved`] if the attempt is already
    ///   approved;
    /// - [`SentaEndpointError::EndpointExists`] if the endpoint ID has a row;
    /// - [`SentaEndpointError::Database`] if a database operation fails or a
    ///   stored row is invalid.
    pub fn approve_senta_endpoint_enrollment(
        &self,
        spki_hash: &[u8; 32],
        attempt_id: Uuid,
        enrollment_result: &str,
        endpoint: &SentaEndpoint,
    ) -> Result<(), SentaEndpointError> {
        if endpoint.spki_hash != *spki_hash {
            return Err(SentaEndpointError::AttemptMismatch { attempt_id });
        }
        let customer_id = endpoint.customer_id;
        let customers = self.senta_endpoint_customer_map();
        let attempts = self.senta_endpoint_enrollment_attempt_map();
        let endpoints = self.senta_endpoint_map();
        self.write_senta_endpoint(Method::ApproveEnrollment, |txn| {
            self.check_deletion_job(txn, customer_id)?;
            let Some(customer) = customers.row_for_update(txn, &keys::customer(customer_id))?
            else {
                return Err(SentaEndpointError::CustomerNotFound { customer_id });
            };
            customers.write_row(txn, &customer)?;
            let Some(mut attempt) =
                attempts.row_for_update(txn, &keys::attempt(spki_hash, attempt_id))?
            else {
                return Err(SentaEndpointError::AttemptNotFound { attempt_id });
            };
            if attempt.customer_id != customer_id {
                return Err(SentaEndpointError::AttemptMismatch { attempt_id });
            }
            if matches!(
                attempt.result,
                SentaEndpointEnrollmentResult::Approved { .. }
            ) {
                return Err(SentaEndpointError::AttemptApproved { attempt_id });
            }
            let endpoint_id = endpoint.endpoint_id;
            if endpoints.exists_for_update(txn, &keys::endpoint(endpoint_id))? {
                return Err(SentaEndpointError::EndpointExists { endpoint_id });
            }
            attempt.result = SentaEndpointEnrollmentResult::Approved {
                result: enrollment_result.to_string(),
            };
            attempts.write_row(txn, &attempt)?;
            endpoints.write_row(txn, endpoint)?;
            Ok(())
        })
    }

    /// Replaces the enrollment-result JWS of an approved enrollment attempt.
    ///
    /// The attempt's result becomes `Approved { result: enrollment_result }`,
    /// and nothing else of the attempt row changes. `endpoint_id` names the
    /// endpoint the approval enrolled, whose row must carry the attempt's SPKI
    /// hash and customer; that row is read for update and not written. The
    /// JWS is stored as given: it is not parsed, decoded or verified here.
    /// Replacing a result with the one already stored succeeds and leaves the
    /// row as it is.
    ///
    /// The customer row is read for update and written back unchanged, as
    /// [`Self::approve_senta_endpoint_enrollment`] does, so that a data
    /// deletion job created concurrently either makes this replacement
    /// conflict and be refused on its retry, or itself conflicts and runs
    /// again.
    ///
    /// # Errors
    ///
    /// Returns, writing nothing:
    ///
    /// - [`SentaEndpointError::AttemptNotFound`] if the attempt has no row;
    /// - [`SentaEndpointError::AttemptNotApproved`] if the attempt is pending
    ///   or denied;
    /// - [`SentaEndpointError::CustomerDeletion`] if the attempt's customer
    ///   has a data deletion job;
    /// - [`SentaEndpointError::EndpointNotFound`] if the endpoint has no row;
    /// - [`SentaEndpointError::AttemptMismatch`] if the endpoint's SPKI hash
    ///   or customer is not the attempt's;
    /// - [`SentaEndpointError::CustomerNotFound`] if the customer has no row;
    /// - [`SentaEndpointError::Database`] if a database operation fails or a
    ///   stored row is invalid.
    pub fn replace_senta_endpoint_enrollment_result(
        &self,
        spki_hash: &[u8; 32],
        attempt_id: Uuid,
        endpoint_id: Uuid,
        enrollment_result: &str,
    ) -> Result<(), SentaEndpointError> {
        let customers = self.senta_endpoint_customer_map();
        let attempts = self.senta_endpoint_enrollment_attempt_map();
        let endpoints = self.senta_endpoint_map();
        self.write_senta_endpoint(Method::ReplaceEnrollmentResult, |txn| {
            let Some(mut attempt) =
                attempts.row_for_update(txn, &keys::attempt(spki_hash, attempt_id))?
            else {
                return Err(SentaEndpointError::AttemptNotFound { attempt_id });
            };
            if !matches!(
                attempt.result,
                SentaEndpointEnrollmentResult::Approved { .. }
            ) {
                return Err(SentaEndpointError::AttemptNotApproved { attempt_id });
            }
            let customer_id = attempt.customer_id;
            self.check_deletion_job(txn, customer_id)?;
            let Some(endpoint) = endpoints.row_for_update(txn, &keys::endpoint(endpoint_id))?
            else {
                return Err(SentaEndpointError::EndpointNotFound { endpoint_id });
            };
            if endpoint.spki_hash != attempt.spki_hash || endpoint.customer_id != customer_id {
                return Err(SentaEndpointError::AttemptMismatch { attempt_id });
            }
            let Some(customer) = customers.row_for_update(txn, &keys::customer(customer_id))?
            else {
                return Err(SentaEndpointError::CustomerNotFound { customer_id });
            };
            customers.write_row(txn, &customer)?;
            attempt.result = SentaEndpointEnrollmentResult::Approved {
                result: enrollment_result.to_string(),
            };
            attempts.write_row(txn, &attempt)?;
            Ok(())
        })
    }

    /// Creates the data deletion job of a customer for the first time, and
    /// returns the stored job.
    ///
    /// The job is stored as given, except for its `endpoint_ids`, which are
    /// replaced by the IDs of every endpoint row of the customer, sorted and
    /// without duplicates. The customer's endpoint-customer row is read for
    /// update before the endpoint table is scanned, so that an enrollment
    /// approved concurrently either is in the list or is refused; a customer
    /// with no endpoint-customer row gets an empty list.
    ///
    /// The job row this method writes is the conflict boundary with
    /// [`Store::put_endpoint_detection_event`] and
    /// [`Store::put_endpoint_detection_event_unless_stored`], which read it
    /// for update: a store of an endpoint detection event of the customer
    /// racing this creation conflicts, retries and is refused, and one
    /// committed before it is removed by the deletion's
    /// [`EventDb::remove_by_sensors`] on the job's `endpoint_ids`. Changing
    /// this method so that it no longer writes that row breaks this rule, and
    /// an endpoint detection event of the customer could survive its deletion.
    ///
    /// [`EventDb::remove_by_sensors`]: crate::EventDb::remove_by_sensors
    ///
    /// # Errors
    ///
    /// Returns, writing nothing:
    ///
    /// - [`SentaEndpointError::InvalidDeletionJob`] if a service result or the
    ///   abandoned hosts of the job are invalid;
    /// - [`SentaEndpointError::DeletionJobExists`] if the customer has a job,
    ///   telling whether it is unfinished or done;
    /// - [`SentaEndpointError::Database`] if a database operation fails or a
    ///   stored row is invalid.
    pub fn create_customer_data_deletion_job(
        &self,
        job: &CustomerDataDeletionJob,
    ) -> Result<CustomerDataDeletionJob, SentaEndpointError> {
        job.validate()
            .map_err(SentaEndpointError::InvalidDeletionJob)?;
        let customer_id = job.customer_id;
        let jobs = self.customer_data_deletion_map();
        let customers = self.senta_endpoint_customer_map();
        let endpoints = self.senta_endpoint_map();
        self.write_senta_endpoint(Method::CreateDeletionJob, |txn| {
            if let Some(state) = self.deletion_job_state(txn, customer_id)? {
                return Err(SentaEndpointError::DeletionJobExists { customer_id, state });
            }
            let has_customer = customers.exists_for_update(txn, &keys::customer(customer_id))?;
            #[cfg(test)]
            self.run_senta_endpoint_hook(HookPoint::DeletionJobBeforeScan)?;
            let mut endpoint_ids = if has_customer {
                endpoints
                    .rows_where(|row| row.customer_id == customer_id)?
                    .into_iter()
                    .map(|row| row.endpoint_id)
                    .collect()
            } else {
                Vec::new()
            };
            endpoint_ids.sort_unstable();
            endpoint_ids.dedup();
            let stored = CustomerDataDeletionJob {
                endpoint_ids,
                ..job.clone()
            };
            jobs.put_with_transaction(&stored, txn)?;
            Ok(stored)
        })
    }

    /// Stores a detection event about an endpoint, as [`EventDb::put`] stores
    /// it, and returns the record's key.
    ///
    /// `endpoint_id` is the endpoint the event is about, whose `Display` form
    /// is the event's `sensor`. The event is stored only if the endpoint has
    /// a row, whatever its standing; its customer is the current customer of
    /// the engine's node, which is the customer of the applied profile of
    /// node `stamp.engine_instance.node_id`; and that customer has no data
    /// deletion job. The node's customer is read within the write, never
    /// taken from the caller.
    ///
    /// The write is one optimistic transaction. It reads the endpoint row,
    /// then the node row and the customer's deletion job row, each for
    /// update, and writes the record, its row in the arrival index and the
    /// last arrival time as [`EventDb::put`] does. On a commit conflict it
    /// runs again from the start, reading the endpoint, node and job rows
    /// again, so a node whose customer changed or a job created in between
    /// refuses the retry. The arrival lock is held from before the first
    /// attempt until the commit, and every attempt stamps its own arrival
    /// time.
    ///
    /// The deletion job row is the conflict boundary with
    /// [`Store::create_customer_data_deletion_job`], which writes it: a store
    /// racing the job's creation conflicts, retries and is refused, and one
    /// committed before it is removed by the deletion's
    /// [`EventDb::remove_by_sensors`] on the customer's endpoint IDs. So no
    /// endpoint detection event of a customer survives its deletion. Changing
    /// the job creation so that it no longer writes that row breaks this rule.
    /// [`Store::put_endpoint_detection_event_unless_stored`] is the
    /// request-path form of this method.
    ///
    /// [`EventDb::put`]: crate::EventDb::put
    /// [`EventDb::remove_by_sensors`]: crate::EventDb::remove_by_sensors
    ///
    /// # Errors
    ///
    /// Returns, writing nothing:
    ///
    /// - [`EndpointDetectionEventError::UnknownEndpoint`] if the endpoint has
    ///   no row;
    /// - [`EndpointDetectionEventError::EndpointOfAnotherCustomer`] if the
    ///   node has no row or no applied profile, or its profile's customer is
    ///   not the endpoint's;
    /// - [`EndpointDetectionEventError::EndpointCustomerDeleted`] if the
    ///   endpoint's customer has a data deletion job, unfinished or done;
    /// - [`EndpointDetectionEventError::Database`] if the event cannot be
    ///   serialized, if no key is free at its time and detection model, or if
    ///   a database operation fails.
    pub fn put_endpoint_detection_event(
        &self,
        event: &DetectionEvent,
        stamp: &DetectionEventStamp,
        endpoint_id: Uuid,
    ) -> Result<i128, EndpointDetectionEventError> {
        match self.put_endpoint_event(event, stamp, endpoint_id, false)? {
            PutOutcome::Stored(key) => Ok(key),
            PutOutcome::Rejected(reason) => {
                Err(EndpointDetectionEventError::Database(anyhow!(reason)))
            }
            PutOutcome::AlreadyStored => Err(EndpointDetectionEventError::Database(anyhow!(
                "a write not checking for a stored event found one"
            ))),
        }
    }

    /// Stores a detection event about an endpoint unless the same event is
    /// already stored, as [`EventDb::put_unless_stored`] stores it.
    ///
    /// The event is stored, or refused, as
    /// [`Store::put_endpoint_detection_event`] tells, in one optimistic
    /// transaction on the same conflict boundary with
    /// [`Store::create_customer_data_deletion_job`]: that job creation writes
    /// the deletion job row this method reads for update, so a store racing it
    /// is refused on its retry, and one committed before it is removed by the
    /// deletion's [`EventDb::remove_by_sensors`] on the customer's endpoint
    /// IDs. Changing the job creation so that it no longer writes that row
    /// breaks this rule.
    ///
    /// Once the endpoint, node and deletion job pass, the outcome is the one
    /// [`EventDb::put_unless_stored`] returns: [`PutOutcome::AlreadyStored`]
    /// if the same event is stored, [`PutOutcome::Rejected`] if it can never
    /// be stored, and [`PutOutcome::Stored`] with its key otherwise. Only a
    /// stored event gets a row in the arrival index.
    ///
    /// [`EventDb::put_unless_stored`]: crate::EventDb::put_unless_stored
    /// [`EventDb::remove_by_sensors`]: crate::EventDb::remove_by_sensors
    ///
    /// # Errors
    ///
    /// Returns, writing nothing:
    ///
    /// - [`EndpointDetectionEventError::UnknownEndpoint`] if the endpoint has
    ///   no row;
    /// - [`EndpointDetectionEventError::EndpointOfAnotherCustomer`] if the
    ///   node has no row or no applied profile, or its profile's customer is
    ///   not the endpoint's;
    /// - [`EndpointDetectionEventError::EndpointCustomerDeleted`] if the
    ///   endpoint's customer has a data deletion job, unfinished or done;
    /// - [`EndpointDetectionEventError::Database`] if a database operation
    ///   fails.
    pub fn put_endpoint_detection_event_unless_stored(
        &self,
        event: &DetectionEvent,
        stamp: &DetectionEventStamp,
        endpoint_id: Uuid,
    ) -> Result<PutOutcome, EndpointDetectionEventError> {
        self.put_endpoint_event(event, stamp, endpoint_id, true)
    }

    /// Writes an endpoint detection event as
    /// [`Store::put_endpoint_detection_event`] tells, checking for the same
    /// event stored if `unless_stored`, and returns the outcome of the write.
    fn put_endpoint_event(
        &self,
        event: &DetectionEvent,
        stamp: &DetectionEventStamp,
        endpoint_id: Uuid,
        unless_stored: bool,
    ) -> Result<PutOutcome, EndpointDetectionEventError> {
        const METHOD: Method = Method::PutEndpointDetectionEvent;
        let events = self.events();
        let endpoints = self.senta_endpoint_map();
        let nodes = self.node_map();
        let node_id = stamp.engine_instance.node_id;
        let db = self.states.db();
        // Held until the write commits, so that the records commit in the
        // order of their arrival times.
        let mut last = events.lock_arrival();
        loop {
            let txn = db.transaction();
            let Some(endpoint) =
                endpoints.row_in_transaction(&txn, &keys::endpoint(endpoint_id))?
            else {
                return Err(EndpointDetectionEventError::UnknownEndpoint { endpoint_id });
            };
            let endpoint_customer = endpoint.customer_id;
            let engine_customer = nodes
                .applied_profile_in_transaction(node_id, &txn)?
                .map(|profile| profile.customer_id);
            if engine_customer != Some(endpoint_customer) {
                return Err(EndpointDetectionEventError::EndpointOfAnotherCustomer {
                    endpoint_id,
                    endpoint_customer,
                    engine_customer,
                });
            }
            if self
                .deletion_job_state(&txn, endpoint_customer)
                .map_err(database_error)?
                .is_some()
            {
                return Err(EndpointDetectionEventError::EndpointCustomerDeleted {
                    endpoint_id,
                    customer_id: endpoint_customer,
                });
            }
            let arrival = events.stamp_arrival(&mut last)?;
            let outcome = events.write_event(&txn, event, stamp, arrival, unless_stored)?;
            if !matches!(outcome, PutOutcome::Stored(_)) {
                return Ok(outcome);
            }
            #[cfg(test)]
            self.run_senta_endpoint_hook(HookPoint::BeforeCommit(METHOD))
                .map_err(database_error)?;
            match txn.commit() {
                Ok(()) => {
                    *last = Some(arrival);
                    return Ok(outcome);
                }
                Err(e) if is_conflict(&e) => {}
                Err(e) => {
                    return Err(EndpointDetectionEventError::Database(
                        anyhow::Error::from(e).context(format!("failed to commit {METHOD:?}")),
                    ));
                }
            }
        }
    }

    /// Returns, within `txn`, the state of the data deletion job of
    /// `customer_id`, read for update, or `None` if it has none.
    fn deletion_job_state(
        &self,
        txn: &Txn<'_>,
        customer_id: u32,
    ) -> Result<Option<SentaEndpointDeletionState>, SentaEndpointError> {
        let job = self
            .customer_data_deletion_map()
            .get_for_update(txn, customer_id)?;
        Ok(job.map(|job| {
            if job.is_unfinished() {
                SentaEndpointDeletionState::InProgress
            } else {
                SentaEndpointDeletionState::AlreadyDeleted
            }
        }))
    }

    /// Refuses, within `txn`, a write for `customer_id` if the customer has a
    /// data deletion job.
    fn check_deletion_job(
        &self,
        txn: &Txn<'_>,
        customer_id: u32,
    ) -> Result<(), SentaEndpointError> {
        match self.deletion_job_state(txn, customer_id)? {
            Some(state) => Err(SentaEndpointError::CustomerDeletion { customer_id, state }),
            None => Ok(()),
        }
    }

    /// Runs `attempt` in an optimistic transaction and commits it, retrying
    /// from the start on a commit conflict. A refusal `attempt` returns ends
    /// the write without committing.
    fn write_senta_endpoint<T>(
        &self,
        method: Method,
        mut attempt: impl FnMut(&Txn<'_>) -> Result<T, SentaEndpointError>,
    ) -> Result<T, SentaEndpointError> {
        let db = self.states.db();
        loop {
            let txn = db.transaction();
            let value = attempt(&txn)?;
            #[cfg(test)]
            self.run_senta_endpoint_hook(HookPoint::BeforeCommit(method))?;
            match txn.commit() {
                Ok(()) => return Ok(value),
                Err(e) if is_conflict(&e) => {}
                Err(e) => {
                    return Err(anyhow::Error::from(e)
                        .context(format!("failed to commit {method:?}"))
                        .into());
                }
            }
        }
    }
}

/// Returns `error`, of a read or write of the Clumit Endpoint tables, as the
/// error of a database operation in an endpoint detection-event write.
fn database_error(error: SentaEndpointError) -> anyhow::Error {
    match error {
        SentaEndpointError::Database(error) => error,
        error => anyhow::Error::from(error),
    }
}

/// Writes `document` within `txn` unless a document is stored under its key,
/// and returns whether it was written.
fn write_keyset_document(
    documents: &Table<'_, SentaEndpointKeysetDocument>,
    txn: &Txn<'_>,
    document: &SentaEndpointKeysetDocument,
) -> Result<bool, SentaEndpointError> {
    let key = keys::keyset_document(
        document.customer_id,
        document.recovery_epoch,
        document.keyset_version,
        &document.signing_kid,
    );
    if documents.exists_for_update(txn, &key)? {
        return Ok(false);
    }
    documents
        .write_row(txn, document)
        .context("failed to write the keyset document")?;
    Ok(true)
}

#[cfg(test)]
impl Store {
    pub(crate) fn set_senta_endpoint_hook(&self, hook: Option<SentaEndpointHook>) {
        *self
            .senta_endpoint_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = hook;
    }

    fn run_senta_endpoint_hook(&self, point: HookPoint) -> Result<(), SentaEndpointError> {
        let hook = self
            .senta_endpoint_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        hook.map_or(Ok(()), |hook| hook(self, point).map_err(Into::into))
    }
}

#[cfg(test)]
mod detection_event_tests;

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };

    use super::*;
    use crate::{
        CustomerDataDeletionService, CustomerDataDeletionServiceResult, CustomerDataDeletionStatus,
        SentaEndpointKeysetVersion,
        tables::{ADDED_WITHIN_FORMAT, CUSTOMER_DELETION_JOBS},
        test::{DbGuard, acquire_db_permit},
    };

    const INSTALL: &str = "install";
    const CUSTOMER: u32 = 1;
    const SPKI: [u8; 32] = [7; 32];

    fn setup_store() -> (
        DbGuard<'static>,
        tempfile::TempDir,
        tempfile::TempDir,
        Store,
    ) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Store::new(db_dir.path(), backup_dir.path(), None).unwrap();
        (permit, db_dir, backup_dir, store)
    }

    /// A stored key and value.
    type RawRow = (Box<[u8]>, Box<[u8]>);

    /// Every key and value of the Clumit Endpoint families and the deletion
    /// jobs, by family.
    fn dump(store: &Store) -> Vec<(&'static str, Vec<RawRow>)> {
        let db = store.states.db();
        ADDED_WITHIN_FORMAT
            .into_iter()
            .chain([CUSTOMER_DELETION_JOBS])
            .map(|name| {
                let cf = db.cf_handle(name).unwrap();
                let rows = db
                    .iterator_cf(cf, rocksdb::IteratorMode::Start)
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                (name, rows)
            })
            .collect()
    }

    fn customer(
        customer_id: u32,
        install_id: &str,
        recovery_key_version: u64,
    ) -> SentaEndpointCustomer {
        SentaEndpointCustomer {
            customer_id,
            trust_state: vec![0, 1, 2, 0xff, customer_id.to_be_bytes()[3]],
            customer_endpoint_id: Uuid::from_u128(u128::from(customer_id) + 500),
            customer_key_name: format!("key-{customer_id}"),
            install_id: install_id.to_string(),
            last_keyset: SentaEndpointKeysetVersion {
                recovery_epoch: 1,
                keyset_version: 1,
            },
            recovery_key_version,
        }
    }

    fn keyset(customer_id: u32, version: u64, kid: &str, jws: &str) -> SentaEndpointKeysetDocument {
        SentaEndpointKeysetDocument {
            customer_id,
            recovery_epoch: 1,
            keyset_version: version,
            signing_kid: kid.to_string(),
            jws: jws.to_string(),
        }
    }

    fn current(
        customer_id: u32,
        recovery_epoch: u64,
        version: u64,
    ) -> SentaEndpointCurrentDocument {
        SentaEndpointCurrentDocument {
            customer_id,
            typ: "address".to_string(),
            target: "endpoints".to_string(),
            recovery_epoch,
            version,
            jws: format!("address-{recovery_epoch}-{version}"),
            put_at: 5,
        }
    }

    fn endpoint(id: u128, customer_id: u32) -> SentaEndpoint {
        SentaEndpoint {
            endpoint_id: Uuid::from_u128(id),
            customer_id,
            customer_endpoint_id: Uuid::from_u128(id + 100),
            spki_hash: SPKI,
            standing: "active".to_string(),
            host_name: "host".to_string(),
            os: "linux".to_string(),
            senta_version: "1.0.0".to_string(),
            bundle: "bundle".to_string(),
            enrolled_at: 1,
            last_connected_at: 1,
            connected: true,
        }
    }

    fn attempt(id: u128, customer_id: u32) -> SentaEndpointEnrollmentAttempt {
        SentaEndpointEnrollmentAttempt {
            spki_hash: SPKI,
            attempt_id: Uuid::from_u128(id),
            customer_id,
            request: vec![4, 5],
            source_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            received_at: 1,
            result: SentaEndpointEnrollmentResult::Pending {
                reason: "review".to_string(),
            },
        }
    }

    fn command(id: u128, endpoint_id: u128) -> SentaEndpointCommand {
        SentaEndpointCommand {
            command_id: Uuid::from_u128(id),
            endpoint_id: Uuid::from_u128(endpoint_id),
            sequence: 1,
            jws: "command".to_string(),
            expires_at: 9,
            state: SentaEndpointCommandState::Pending,
            result: None,
        }
    }

    fn job(customer_id: u32, status: CustomerDataDeletionStatus) -> CustomerDataDeletionJob {
        CustomerDataDeletionJob::new(
            customer_id,
            vec![CustomerDataDeletionServiceResult {
                service: CustomerDataDeletionService::Review,
                host_fqdns: Vec::new(),
                status,
                requested_at: 1,
                completed_at: None,
                error: None,
            }],
        )
    }

    /// Registers `INSTALL` at recovery key version 1 and `CUSTOMER` of it.
    fn register_customer(store: &Store) -> SentaEndpointCustomer {
        store
            .senta_endpoint_install_map()
            .register(INSTALL, "{\"first\":1}", 1)
            .unwrap();
        let row = customer(CUSTOMER, INSTALL, 1);
        store
            .register_senta_endpoint_customer(&row, &keyset(CUSTOMER, 1, "kid", "first"))
            .unwrap();
        row
    }

    /// Asserts that `result` is a refusal for a deletion job of `customer_id`
    /// in `state`.
    fn assert_deletion<T: std::fmt::Debug>(
        result: Result<T, SentaEndpointError>,
        customer_id: u32,
        state: SentaEndpointDeletionState,
    ) {
        match result {
            Err(SentaEndpointError::CustomerDeletion {
                customer_id: refused,
                state: found,
            }) => {
                assert_eq!(refused, customer_id);
                assert_eq!(found, state);
            }
            other => panic!("expected a deletion refusal, got {other:?}"),
        }
    }

    /// Installs a hook that runs `action` once, at the first `point`.
    fn hook_once(store: &Store, point: HookPoint, action: impl Fn(&Store) + Send + Sync + 'static) {
        let fired = AtomicBool::new(false);
        store.set_senta_endpoint_hook(Some(Arc::new(move |store, at| {
            if at == point && !fired.swap(true, Ordering::SeqCst) {
                action(store);
            }
            Ok(())
        })));
    }

    /// Installs a hook that runs `action` once, at the first `point`, and
    /// returns the number of times the hook has run at `counted`.
    fn hook_counting(
        store: &Store,
        point: HookPoint,
        counted: HookPoint,
        action: impl Fn(&Store) + Send + Sync + 'static,
    ) -> Arc<AtomicUsize> {
        let fired = AtomicBool::new(false);
        let count = Arc::new(AtomicUsize::new(0));
        let runs = Arc::clone(&count);
        store.set_senta_endpoint_hook(Some(Arc::new(move |store, at| {
            if at == counted {
                runs.fetch_add(1, Ordering::SeqCst);
            }
            if at == point && !fired.swap(true, Ordering::SeqCst) {
                action(store);
            }
            Ok(())
        })));
        count
    }

    const DELETION_STATES: [(CustomerDataDeletionStatus, SentaEndpointDeletionState); 2] = [
        (
            CustomerDataDeletionStatus::InProgress,
            SentaEndpointDeletionState::InProgress,
        ),
        (
            CustomerDataDeletionStatus::Succeeded,
            SentaEndpointDeletionState::AlreadyDeleted,
        ),
    ];

    #[test]
    fn registers_a_customer_with_its_first_keyset_document() {
        let (_permit, _db, _backup, store) = setup_store();
        let row = register_customer(&store);
        assert_eq!(
            store.senta_endpoint_customer_map().get(CUSTOMER).unwrap(),
            Some(row.clone())
        );
        assert_eq!(
            store
                .senta_endpoint_keyset_document_map()
                .of_customer(CUSTOMER)
                .unwrap(),
            vec![keyset(CUSTOMER, 1, "kid", "first")]
        );

        let before = dump(&store);
        assert!(matches!(
            store.register_senta_endpoint_customer(&row, &keyset(CUSTOMER, 2, "kid", "second")),
            Err(SentaEndpointError::CustomerExists {
                customer_id: CUSTOMER
            })
        ));
        assert!(matches!(
            store.register_senta_endpoint_customer(
                &customer(2, INSTALL, 1),
                &keyset(3, 1, "kid", "x")
            ),
            Err(SentaEndpointError::DocumentOfAnotherCustomer { customer_id: 2 })
        ));
        assert!(matches!(
            store.register_senta_endpoint_customer(
                &customer(2, "absent", 1),
                &keyset(2, 1, "kid", "x")
            ),
            Err(SentaEndpointError::InstallNotFound { install_id }) if install_id == "absent"
        ));
        assert!(matches!(
            store.register_senta_endpoint_customer(
                &customer(2, INSTALL, 2),
                &keyset(2, 1, "kid", "x")
            ),
            Err(SentaEndpointError::RecoveryKeyVersionMismatch {
                install_version: 1,
                customer_version: 2,
                ..
            })
        ));
        assert_eq!(dump(&store), before);
    }

    #[test]
    fn registration_is_refused_after_the_install_rotates() {
        let (_permit, _db, _backup, store) = setup_store();
        store
            .senta_endpoint_install_map()
            .register(INSTALL, "{}", 1)
            .unwrap();
        store
            .rotate_senta_endpoint_recovery_key(
                &SentaEndpointRecoveryKeyDocument {
                    install_id: INSTALL.to_string(),
                    recovery_key_version: 2,
                    jws: "rotation".to_string(),
                },
                "{\"k\":2}",
                &[],
            )
            .unwrap();
        let before = dump(&store);
        assert!(matches!(
            store.register_senta_endpoint_customer(
                &customer(CUSTOMER, INSTALL, 1),
                &keyset(CUSTOMER, 1, "kid", "x")
            ),
            Err(SentaEndpointError::RecoveryKeyVersionMismatch {
                install_version: 2,
                customer_version: 1,
                ..
            })
        ));
        assert_eq!(dump(&store), before);
        store
            .register_senta_endpoint_customer(
                &customer(CUSTOMER, INSTALL, 2),
                &keyset(CUSTOMER, 1, "kid", "x"),
            )
            .unwrap();
    }

    #[test]
    fn registration_and_rotation_conflict_in_either_order() {
        let rotation = || SentaEndpointRecoveryKeyDocument {
            install_id: INSTALL.to_string(),
            recovery_key_version: 2,
            jws: "rotation".to_string(),
        };

        // The rotation commits while the registration is in flight: the
        // registration retries and sees the new version.
        let (_permit, _db, _backup, store) = setup_store();
        store
            .senta_endpoint_install_map()
            .register(INSTALL, "{}", 1)
            .unwrap();
        hook_once(
            &store,
            HookPoint::BeforeCommit(Method::RegisterCustomer),
            move |store| {
                assert_eq!(
                    store
                        .rotate_senta_endpoint_recovery_key(&rotation(), "{\"k\":2}", &[])
                        .unwrap(),
                    Vec::<u32>::new()
                );
            },
        );
        assert!(matches!(
            store.register_senta_endpoint_customer(
                &customer(CUSTOMER, INSTALL, 1),
                &keyset(CUSTOMER, 1, "kid", "x")
            ),
            Err(SentaEndpointError::RecoveryKeyVersionMismatch { .. })
        ));
        assert_eq!(
            store.senta_endpoint_customer_map().get(CUSTOMER).unwrap(),
            None
        );
        drop(store);

        // The registration commits while the rotation is in flight: the
        // rotation retries, finds the new customer and has no row for it.
        let (_permit, _db, _backup, store) = setup_store();
        store
            .senta_endpoint_install_map()
            .register(INSTALL, "{}", 1)
            .unwrap();
        hook_once(
            &store,
            HookPoint::BeforeCommit(Method::RotateRecoveryKey),
            |store| {
                store
                    .register_senta_endpoint_customer(
                        &customer(CUSTOMER, INSTALL, 1),
                        &keyset(CUSTOMER, 1, "kid", "x"),
                    )
                    .unwrap();
            },
        );
        assert!(matches!(
            store.rotate_senta_endpoint_recovery_key(&rotation(), "{\"k\":2}", &[]),
            Err(SentaEndpointError::CustomerRowMissing {
                customer_id: CUSTOMER
            })
        ));
        let install = store
            .senta_endpoint_install_map()
            .get(INSTALL)
            .unwrap()
            .unwrap();
        assert_eq!(install.current_recovery_key_version, 1);
        assert_eq!(
            store
                .senta_endpoint_recovery_key_document_map()
                .of_install(INSTALL)
                .unwrap(),
            vec![]
        );
    }

    #[test]
    fn receives_keyset_documents() {
        let (_permit, _db, _backup, store) = setup_store();
        let row = register_customer(&store);
        let documents = store.senta_endpoint_keyset_document_map();

        // Archive only: a second signed copy of the same version.
        assert!(
            store
                .receive_senta_endpoint_keyset_document(&keyset(CUSTOMER, 1, "kid-2", "copy"), None)
                .unwrap()
        );
        assert_eq!(
            store.senta_endpoint_customer_map().get(CUSTOMER).unwrap(),
            Some(row.clone())
        );

        // A new row with a changed key name and trust state.
        let new_row = SentaEndpointCustomer {
            trust_state: vec![9, 9, 0],
            customer_key_name: "renamed".to_string(),
            last_keyset: SentaEndpointKeysetVersion {
                recovery_epoch: 1,
                keyset_version: 2,
            },
            ..row.clone()
        };
        assert!(
            store
                .receive_senta_endpoint_keyset_document(
                    &keyset(CUSTOMER, 2, "kid", "second"),
                    Some(&new_row)
                )
                .unwrap()
        );
        assert_eq!(
            store.senta_endpoint_customer_map().get(CUSTOMER).unwrap(),
            Some(new_row.clone())
        );

        // Received again under an existing key: the stored JWS stays.
        assert!(
            !store
                .receive_senta_endpoint_keyset_document(&keyset(CUSTOMER, 1, "kid", "other"), None)
                .unwrap()
        );
        assert_eq!(
            documents.get(CUSTOMER, 1, 1, "kid").unwrap().unwrap().jws,
            "first"
        );
        assert_eq!(
            documents
                .of_customer(CUSTOMER)
                .unwrap()
                .iter()
                .map(|doc| (
                    doc.keyset_version,
                    doc.signing_kid.as_str(),
                    doc.jws.as_str()
                ))
                .collect::<Vec<_>>(),
            vec![
                (1, "kid", "first"),
                (1, "kid-2", "copy"),
                (2, "kid", "second")
            ]
        );

        let before = dump(&store);
        assert!(matches!(
            store.receive_senta_endpoint_keyset_document(&keyset(2, 1, "kid", "x"), None),
            Err(SentaEndpointError::CustomerNotFound { customer_id: 2 })
        ));
        assert!(matches!(
            store.receive_senta_endpoint_keyset_document(&keyset(2, 1, "kid", "x"), Some(&new_row)),
            Err(SentaEndpointError::DocumentOfAnotherCustomer { customer_id: 2 })
        ));
        let moved = SentaEndpointCustomer {
            install_id: "other".to_string(),
            ..new_row.clone()
        };
        assert!(matches!(
            store.receive_senta_endpoint_keyset_document(
                &keyset(CUSTOMER, 3, "kid", "x"),
                Some(&moved)
            ),
            Err(SentaEndpointError::CustomerColumnChanged {
                column: "install ID",
                ..
            })
        ));
        let rotated = SentaEndpointCustomer {
            recovery_key_version: 2,
            ..new_row
        };
        assert!(matches!(
            store.receive_senta_endpoint_keyset_document(
                &keyset(CUSTOMER, 3, "kid", "x"),
                Some(&rotated)
            ),
            Err(SentaEndpointError::CustomerColumnChanged {
                column: "recovery key version",
                ..
            })
        ));
        assert_eq!(dump(&store), before);
    }

    #[test]
    fn writes_a_current_document_only_over_an_older_one() {
        let (_permit, _db, _backup, store) = setup_store();
        let documents = store.senta_endpoint_current_document_map();
        let roots = store.senta_endpoint_address_root_map();

        assert!(
            store
                .write_senta_endpoint_current_document(
                    &current(CUSTOMER, 1, 5),
                    &[[1; 32], [2; 32]]
                )
                .unwrap()
        );
        assert_eq!(
            documents.get(CUSTOMER, "address", "endpoints").unwrap(),
            Some(current(CUSTOMER, 1, 5))
        );
        assert_eq!(
            roots
                .of_document(CUSTOMER, 1, 5)
                .unwrap()
                .iter()
                .map(|root| root.fingerprint)
                .collect::<Vec<_>>(),
            vec![[1; 32], [2; 32]]
        );

        // Neither the same nor an older (epoch, version) is written.
        let before = dump(&store);
        for (epoch, version) in [(1, 5), (1, 4), (0, 9)] {
            assert!(
                !store
                    .write_senta_endpoint_current_document(
                        &current(CUSTOMER, epoch, version),
                        &[[3; 32]]
                    )
                    .unwrap()
            );
        }
        assert_eq!(dump(&store), before);

        // A greater one replaces it, also with a lower version in a later
        // epoch.
        assert!(
            store
                .write_senta_endpoint_current_document(&current(CUSTOMER, 2, 0), &[[3; 32]])
                .unwrap()
        );
        assert_eq!(
            documents.get(CUSTOMER, "address", "endpoints").unwrap(),
            Some(current(CUSTOMER, 2, 0))
        );
        assert_eq!(roots.of_document(CUSTOMER, 2, 0).unwrap().len(), 1);
        assert_eq!(roots.of_customer(CUSTOMER).unwrap().len(), 3);
        // Another target is another row.
        let other = SentaEndpointCurrentDocument {
            target: "endpoints-2".to_string(),
            ..current(CUSTOMER, 1, 1)
        };
        assert!(
            store
                .write_senta_endpoint_current_document(&other, &[])
                .unwrap()
        );
        assert_eq!(
            documents
                .of_customer_typ(CUSTOMER, "address")
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn concurrent_current_document_writers_leave_the_newer_one() {
        for older_first in [true, false] {
            let (_permit, _db, _backup, store) = setup_store();
            let (outer, inner) = if older_first {
                (current(CUSTOMER, 1, 1), current(CUSTOMER, 1, 2))
            } else {
                (current(CUSTOMER, 1, 2), current(CUSTOMER, 1, 1))
            };
            let in_hook = inner.clone();
            hook_once(
                &store,
                HookPoint::BeforeCommit(Method::WriteCurrentDocument),
                move |store| {
                    assert!(
                        store
                            .write_senta_endpoint_current_document(&in_hook, &[])
                            .unwrap()
                    );
                },
            );
            let written = store
                .write_senta_endpoint_current_document(&outer, &[])
                .unwrap();
            // The outer writer conflicts and retries: the older one then
            // finds the newer stored and writes nothing; the newer one
            // replaces the older.
            assert_eq!(written, !older_first);
            assert_eq!(
                store
                    .senta_endpoint_current_document_map()
                    .get(CUSTOMER, "address", "endpoints")
                    .unwrap(),
                Some(current(CUSTOMER, 1, 2))
            );
        }
    }

    #[test]
    fn inserts_a_command_for_an_endpoint_of_the_customer() {
        let (_permit, _db, _backup, store) = setup_store();
        register_customer(&store);
        store
            .senta_endpoint_enrollment_attempt_map()
            .insert(&attempt(1, CUSTOMER))
            .unwrap();
        store
            .approve_senta_endpoint_enrollment(
                &SPKI,
                Uuid::from_u128(1),
                "ok",
                &endpoint(10, CUSTOMER),
            )
            .unwrap();

        store
            .insert_senta_endpoint_command(CUSTOMER, &command(20, 10))
            .unwrap();
        assert_eq!(
            store
                .senta_endpoint_command_map()
                .get(Uuid::from_u128(20))
                .unwrap(),
            Some(command(20, 10))
        );

        let before = dump(&store);
        assert!(matches!(
            store.insert_senta_endpoint_command(CUSTOMER, &command(20, 10)),
            Err(SentaEndpointError::CommandExists { .. })
        ));
        assert!(matches!(
            store.insert_senta_endpoint_command(CUSTOMER, &command(21, 11)),
            Err(SentaEndpointError::EndpointNotFound { .. })
        ));
        assert!(matches!(
            store.insert_senta_endpoint_command(2, &command(21, 10)),
            Err(SentaEndpointError::EndpointOfAnotherCustomer { customer_id: 2, .. })
        ));
        let sent = SentaEndpointCommand {
            state: SentaEndpointCommandState::Sent,
            ..command(21, 10)
        };
        assert!(matches!(
            store.insert_senta_endpoint_command(CUSTOMER, &sent),
            Err(SentaEndpointError::CommandNotPending { .. })
        ));
        let with_result = SentaEndpointCommand {
            result: Some(vec![1]),
            ..command(21, 10)
        };
        assert!(matches!(
            store.insert_senta_endpoint_command(CUSTOMER, &with_result),
            Err(SentaEndpointError::CommandNotPending { .. })
        ));
        assert_eq!(dump(&store), before);
    }

    // One scenario per deletion state: the rows the deletion's last stage
    // removes, then every write that could bring one back.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn writes_of_a_customer_with_a_deletion_job_are_refused() {
        for (status, state) in DELETION_STATES {
            let (_permit, _db, _backup, store) = setup_store();
            let row = register_customer(&store);
            store
                .senta_endpoint_enrollment_attempt_map()
                .insert(&attempt(1, CUSTOMER))
                .unwrap();
            store
                .approve_senta_endpoint_enrollment(
                    &SPKI,
                    Uuid::from_u128(1),
                    "ok",
                    &endpoint(10, CUSTOMER),
                )
                .unwrap();
            store
                .senta_endpoint_enrollment_attempt_map()
                .insert(&attempt(2, CUSTOMER))
                .unwrap();
            store
                .write_senta_endpoint_current_document(&current(CUSTOMER, 1, 1), &[[1; 32]])
                .unwrap();
            let created = store
                .create_customer_data_deletion_job(&job(CUSTOMER, status))
                .unwrap();
            assert_eq!(created.endpoint_ids, vec![Uuid::from_u128(10)]);

            // The deletion's last stage removes the customer's rows.
            assert_eq!(
                store
                    .senta_endpoint_customer_map()
                    .delete(CUSTOMER)
                    .unwrap(),
                ()
            );
            store
                .senta_endpoint_keyset_document_map()
                .delete_customer(CUSTOMER)
                .unwrap();
            store
                .senta_endpoint_current_document_map()
                .delete_customer(CUSTOMER)
                .unwrap();
            store
                .senta_endpoint_address_root_map()
                .delete_customer(CUSTOMER)
                .unwrap();
            for endpoint_id in &created.endpoint_ids {
                store.senta_endpoint_map().delete(*endpoint_id).unwrap();
            }
            let before = dump(&store);

            assert_deletion(
                store.register_senta_endpoint_customer(&row, &keyset(CUSTOMER, 1, "kid", "x")),
                CUSTOMER,
                state,
            );
            assert_deletion(
                store.receive_senta_endpoint_keyset_document(
                    &keyset(CUSTOMER, 2, "kid", "x"),
                    Some(&row),
                ),
                CUSTOMER,
                state,
            );
            assert_deletion(
                store.write_senta_endpoint_current_document(&current(CUSTOMER, 2, 1), &[[2; 32]]),
                CUSTOMER,
                state,
            );
            assert_deletion(
                store.insert_senta_endpoint_command(CUSTOMER, &command(20, 10)),
                CUSTOMER,
                state,
            );
            assert_deletion(
                store.approve_senta_endpoint_enrollment(
                    &SPKI,
                    Uuid::from_u128(2),
                    "ok",
                    &endpoint(11, CUSTOMER),
                ),
                CUSTOMER,
                state,
            );
            assert_deletion(
                store.replace_senta_endpoint_enrollment_result(
                    &SPKI,
                    Uuid::from_u128(1),
                    Uuid::from_u128(10),
                    "resigned",
                ),
                CUSTOMER,
                state,
            );
            assert!(matches!(
                store.create_customer_data_deletion_job(&job(CUSTOMER, status)),
                Err(SentaEndpointError::DeletionJobExists {
                    customer_id: CUSTOMER,
                    state: found,
                }) if found == state
            ));
            assert_eq!(dump(&store), before);
            assert_eq!(
                store.senta_endpoint_customer_map().get(CUSTOMER).unwrap(),
                None
            );
            assert_eq!(
                store
                    .senta_endpoint_keyset_document_map()
                    .of_customer(CUSTOMER)
                    .unwrap(),
                vec![]
            );
        }
    }

    #[test]
    fn a_job_with_no_service_result_is_reported_as_deleted() {
        let (_permit, _db, _backup, store) = setup_store();
        store
            .customer_data_deletion_map()
            .put(&CustomerDataDeletionJob::new(CUSTOMER, Vec::new()))
            .unwrap();
        assert_deletion(
            store.write_senta_endpoint_current_document(&current(CUSTOMER, 1, 1), &[]),
            CUSTOMER,
            SentaEndpointDeletionState::AlreadyDeleted,
        );
    }

    #[test]
    fn a_deletion_job_created_mid_write_refuses_the_write() {
        let (_permit, _db, _backup, store) = setup_store();
        register_customer(&store);
        hook_once(
            &store,
            HookPoint::BeforeCommit(Method::ReceiveKeysetDocument),
            |store| {
                store
                    .create_customer_data_deletion_job(&job(
                        CUSTOMER,
                        CustomerDataDeletionStatus::InProgress,
                    ))
                    .unwrap();
            },
        );
        assert_deletion(
            store.receive_senta_endpoint_keyset_document(&keyset(CUSTOMER, 2, "kid", "x"), None),
            CUSTOMER,
            SentaEndpointDeletionState::InProgress,
        );
        assert_eq!(
            store
                .senta_endpoint_keyset_document_map()
                .get(CUSTOMER, 1, 2, "kid")
                .unwrap(),
            None
        );
    }

    fn rotation(version: u64) -> SentaEndpointRecoveryKeyDocument {
        SentaEndpointRecoveryKeyDocument {
            install_id: INSTALL.to_string(),
            recovery_key_version: version,
            jws: format!("rotation-{version}"),
        }
    }

    #[test]
    fn rotates_the_recovery_key_of_an_install_with_no_customer() {
        let (_permit, _db, _backup, store) = setup_store();
        let installs = store.senta_endpoint_install_map();
        installs.register(INSTALL, "{\"first\":1}", 1).unwrap();
        assert_eq!(
            store
                .rotate_senta_endpoint_recovery_key(&rotation(2), "{\"k\":2}", &[])
                .unwrap(),
            Vec::<u32>::new()
        );
        let install = installs.get(INSTALL).unwrap().unwrap();
        assert_eq!(install.first_recovery_key, "{\"first\":1}");
        assert_eq!(install.first_recovery_key_version, 1);
        assert_eq!(install.current_recovery_key, "{\"k\":2}");
        assert_eq!(install.current_recovery_key_version, 2);
        assert_eq!(
            store
                .senta_endpoint_recovery_key_document_map()
                .of_install(INSTALL)
                .unwrap(),
            vec![rotation(2)]
        );
        // Registering the install again with its first key writes nothing.
        assert!(!installs.register(INSTALL, "{\"first\":1}", 1).unwrap());
        assert_eq!(installs.get(INSTALL).unwrap(), Some(install));

        assert!(matches!(
            store.rotate_senta_endpoint_recovery_key(
                &SentaEndpointRecoveryKeyDocument {
                    install_id: "absent".to_string(),
                    ..rotation(3)
                },
                "{}",
                &[]
            ),
            Err(SentaEndpointError::InstallNotFound { .. })
        ));
    }

    #[test]
    fn rotates_every_customer_of_the_install_without_a_deletion_job() {
        let (_permit, _db, _backup, store) = setup_store();
        let installs = store.senta_endpoint_install_map();
        installs.register(INSTALL, "{}", 1).unwrap();
        installs.register("other", "{}", 1).unwrap();
        for customer_id in [1, 2, 3] {
            store
                .register_senta_endpoint_customer(
                    &customer(customer_id, INSTALL, 1),
                    &keyset(customer_id, 1, "kid", "x"),
                )
                .unwrap();
        }
        store
            .register_senta_endpoint_customer(&customer(4, "other", 1), &keyset(4, 1, "kid", "x"))
            .unwrap();
        store
            .create_customer_data_deletion_job(&job(2, CustomerDataDeletionStatus::InProgress))
            .unwrap();

        let rotated = |customer_id| SentaEndpointCustomer {
            trust_state: vec![2, 2],
            ..customer(customer_id, INSTALL, 2)
        };
        let before = dump(&store);
        for (case, rows, expected) in [
            ("missing", vec![rotated(1)], "CustomerRowMissing"),
            (
                "mismatched version",
                vec![rotated(1), customer(3, INSTALL, 3)],
                "CustomerRecoveryKeyVersion",
            ),
            (
                "another install",
                vec![rotated(1), rotated(3), customer(4, "other", 2)],
                "CustomerNotOfInstall",
            ),
            (
                "row naming another install",
                vec![rotated(1), customer(3, "other", 2)],
                "CustomerNotOfInstall",
            ),
            (
                "not a customer",
                vec![rotated(1), rotated(3), rotated(5)],
                "CustomerNotOfInstall",
            ),
            (
                "duplicate",
                vec![rotated(1), rotated(1)],
                "DuplicateCustomerRow",
            ),
        ] {
            let error = store
                .rotate_senta_endpoint_recovery_key(&rotation(2), "{\"k\":2}", &rows)
                .unwrap_err();
            assert!(
                format!("{error:?}").starts_with(expected),
                "{case}: {error:?}"
            );
            assert_eq!(dump(&store), before, "{case} must write nothing");
        }

        // The row given for customer 2, which has a deletion job, is ignored,
        // also when it carries a stale recovery key version and names another
        // install.
        let stale = SentaEndpointCustomer {
            trust_state: vec![9],
            ..customer(2, "other", 1)
        };
        let written = store
            .rotate_senta_endpoint_recovery_key(
                &rotation(2),
                "{\"k\":2}",
                &[rotated(3), stale, rotated(1)],
            )
            .unwrap();
        assert_eq!(written, vec![1, 3]);
        let customers = store.senta_endpoint_customer_map();
        assert_eq!(customers.get(1).unwrap(), Some(rotated(1)));
        assert_eq!(customers.get(3).unwrap(), Some(rotated(3)));
        assert_eq!(customers.get(2).unwrap(), Some(customer(2, INSTALL, 1)));
        assert_eq!(customers.get(4).unwrap(), Some(customer(4, "other", 1)));
        assert_eq!(
            installs
                .get(INSTALL)
                .unwrap()
                .unwrap()
                .current_recovery_key_version,
            2
        );
        assert_eq!(customers.of_install(INSTALL).unwrap().len(), 3);
    }

    #[test]
    fn approves_an_enrollment() {
        let (_permit, _db, _backup, store) = setup_store();
        register_customer(&store);
        let attempts = store.senta_endpoint_enrollment_attempt_map();
        attempts.insert(&attempt(1, CUSTOMER)).unwrap();
        attempts.insert(&attempt(2, 2)).unwrap();

        let before = dump(&store);
        assert!(matches!(
            store.approve_senta_endpoint_enrollment(
                &SPKI,
                Uuid::from_u128(9),
                "ok",
                &endpoint(10, CUSTOMER)
            ),
            Err(SentaEndpointError::AttemptNotFound { .. })
        ));
        assert!(matches!(
            store.approve_senta_endpoint_enrollment(
                &SPKI,
                Uuid::from_u128(2),
                "ok",
                &endpoint(10, 2)
            ),
            Err(SentaEndpointError::CustomerNotFound { customer_id: 2 })
        ));
        assert!(matches!(
            store.approve_senta_endpoint_enrollment(
                &SPKI,
                Uuid::from_u128(2),
                "ok",
                &endpoint(10, CUSTOMER)
            ),
            Err(SentaEndpointError::AttemptMismatch { .. })
        ));
        assert!(matches!(
            store.approve_senta_endpoint_enrollment(
                &[8; 32],
                Uuid::from_u128(1),
                "ok",
                &endpoint(10, CUSTOMER)
            ),
            Err(SentaEndpointError::AttemptMismatch { .. })
        ));
        assert_eq!(dump(&store), before);

        store
            .approve_senta_endpoint_enrollment(
                &SPKI,
                Uuid::from_u128(1),
                "ok",
                &endpoint(10, CUSTOMER),
            )
            .unwrap();
        assert_eq!(
            attempts
                .get(&SPKI, Uuid::from_u128(1))
                .unwrap()
                .unwrap()
                .result,
            SentaEndpointEnrollmentResult::Approved {
                result: "ok".to_string()
            }
        );
        assert_eq!(
            store.senta_endpoint_map().get(Uuid::from_u128(10)).unwrap(),
            Some(endpoint(10, CUSTOMER))
        );

        let before = dump(&store);
        assert!(matches!(
            store.approve_senta_endpoint_enrollment(
                &SPKI,
                Uuid::from_u128(1),
                "again",
                &endpoint(11, CUSTOMER)
            ),
            Err(SentaEndpointError::AttemptApproved { .. })
        ));
        attempts.insert(&attempt(3, CUSTOMER)).unwrap();
        let before_existing = dump(&store);
        assert!(matches!(
            store.approve_senta_endpoint_enrollment(
                &SPKI,
                Uuid::from_u128(3),
                "ok",
                &endpoint(10, CUSTOMER)
            ),
            Err(SentaEndpointError::EndpointExists { .. })
        ));
        assert_eq!(dump(&store), before_existing);
        assert_ne!(before, before_existing);
    }

    #[test]
    fn creates_a_deletion_job_listing_the_customers_endpoints() {
        let (_permit, _db, _backup, store) = setup_store();
        register_customer(&store);
        store
            .register_senta_endpoint_customer(&customer(2, INSTALL, 1), &keyset(2, 1, "kid", "x"))
            .unwrap();
        let attempts = store.senta_endpoint_enrollment_attempt_map();
        for (attempt_id, endpoint_id, customer_id) in
            [(1, 30, 1), (2, 10, 1), (3, 20, 2), (4, 5, 1)]
        {
            attempts.insert(&attempt(attempt_id, customer_id)).unwrap();
            store
                .approve_senta_endpoint_enrollment(
                    &SPKI,
                    Uuid::from_u128(attempt_id),
                    "ok",
                    &endpoint(endpoint_id, customer_id),
                )
                .unwrap();
        }

        // The given list is replaced.
        let mut given = job(CUSTOMER, CustomerDataDeletionStatus::InProgress);
        given.endpoint_ids = vec![Uuid::from_u128(99)];
        let created = store.create_customer_data_deletion_job(&given).unwrap();
        assert_eq!(
            created.endpoint_ids,
            vec![Uuid::from_u128(5), Uuid::from_u128(10), Uuid::from_u128(30)]
        );
        assert_eq!(
            store.customer_data_deletion_map().get(CUSTOMER).unwrap(),
            Some(created)
        );

        // A customer with no endpoint-customer row gets an empty list.
        let created = store
            .create_customer_data_deletion_job(&job(3, CustomerDataDeletionStatus::InProgress))
            .unwrap();
        assert_eq!(created.endpoint_ids, Vec::<Uuid>::new());

        let before = dump(&store);
        assert!(matches!(
            store.create_customer_data_deletion_job(&job(3, CustomerDataDeletionStatus::Failed)),
            Err(SentaEndpointError::DeletionJobExists {
                customer_id: 3,
                state: SentaEndpointDeletionState::InProgress,
            })
        ));
        let mut invalid = job(4, CustomerDataDeletionStatus::InProgress);
        invalid.abandoned_hosts = vec!["absent.example".to_string()];
        assert!(matches!(
            store.create_customer_data_deletion_job(&invalid),
            Err(SentaEndpointError::InvalidDeletionJob(_))
        ));
        assert_eq!(dump(&store), before);
    }

    /// Prepares `CUSTOMER` with a pending enrollment attempt 1.
    fn setup_approval(store: &Store) {
        register_customer(store);
        store
            .senta_endpoint_enrollment_attempt_map()
            .insert(&attempt(1, CUSTOMER))
            .unwrap();
    }

    fn approve(store: &Store) -> Result<(), SentaEndpointError> {
        store.approve_senta_endpoint_enrollment(
            &SPKI,
            Uuid::from_u128(1),
            "ok",
            &endpoint(10, CUSTOMER),
        )
    }

    fn create_job(store: &Store) -> CustomerDataDeletionJob {
        store
            .create_customer_data_deletion_job(&job(
                CUSTOMER,
                CustomerDataDeletionStatus::InProgress,
            ))
            .unwrap()
    }

    #[test]
    fn approval_then_deletion_job_lists_the_endpoint() {
        let (_permit, _db, _backup, store) = setup_store();
        setup_approval(&store);
        approve(&store).unwrap();
        assert_eq!(create_job(&store).endpoint_ids, vec![Uuid::from_u128(10)]);
    }

    #[test]
    fn deletion_job_then_approval_refuses_the_approval() {
        let (_permit, _db, _backup, store) = setup_store();
        setup_approval(&store);
        assert_eq!(create_job(&store).endpoint_ids, Vec::<Uuid>::new());
        assert_deletion(
            approve(&store),
            CUSTOMER,
            SentaEndpointDeletionState::InProgress,
        );
        assert_eq!(
            store.senta_endpoint_map().get(Uuid::from_u128(10)).unwrap(),
            None
        );
    }

    #[test]
    fn a_deletion_job_committed_during_an_approval_refuses_it() {
        let (_permit, _db, _backup, store) = setup_store();
        setup_approval(&store);
        hook_once(
            &store,
            HookPoint::BeforeCommit(Method::ApproveEnrollment),
            |store| {
                assert_eq!(create_job(store).endpoint_ids, Vec::<Uuid>::new());
            },
        );
        assert_deletion(
            approve(&store),
            CUSTOMER,
            SentaEndpointDeletionState::InProgress,
        );
        assert_eq!(
            store.senta_endpoint_map().get(Uuid::from_u128(10)).unwrap(),
            None
        );
        assert_eq!(
            store
                .customer_data_deletion_map()
                .get(CUSTOMER)
                .unwrap()
                .unwrap()
                .endpoint_ids,
            Vec::<Uuid>::new()
        );
    }

    #[test]
    fn an_approval_committed_during_a_deletion_job_creation_is_listed() {
        for point in [
            HookPoint::DeletionJobBeforeScan,
            HookPoint::BeforeCommit(Method::CreateDeletionJob),
        ] {
            let (_permit, _db, _backup, store) = setup_store();
            setup_approval(&store);
            hook_once(&store, point, |store| approve(store).unwrap());
            assert_eq!(
                create_job(&store).endpoint_ids,
                vec![Uuid::from_u128(10)],
                "{point:?}"
            );
            assert_eq!(
                store.senta_endpoint_map().get(Uuid::from_u128(10)).unwrap(),
                Some(endpoint(10, CUSTOMER))
            );
        }
    }

    fn replace(store: &Store, endpoint_id: u128, jws: &str) -> Result<(), SentaEndpointError> {
        store.replace_senta_endpoint_enrollment_result(
            &SPKI,
            Uuid::from_u128(1),
            Uuid::from_u128(endpoint_id),
            jws,
        )
    }

    fn stored_result(store: &Store) -> SentaEndpointEnrollmentResult {
        store
            .senta_endpoint_enrollment_attempt_map()
            .get(&SPKI, Uuid::from_u128(1))
            .unwrap()
            .unwrap()
            .result
    }

    fn approved(jws: &str) -> SentaEndpointEnrollmentResult {
        SentaEndpointEnrollmentResult::Approved {
            result: jws.to_string(),
        }
    }

    /// Returns the keys whose values differ between two dumps of the same
    /// keys.
    fn changed_keys(
        before: &[(&'static str, Vec<RawRow>)],
        after: &[(&'static str, Vec<RawRow>)],
    ) -> Vec<(&'static str, Box<[u8]>)> {
        assert_eq!(before.len(), after.len());
        let mut changed = Vec::new();
        for ((family, old), (same, new)) in before.iter().zip(after) {
            assert_eq!(family, same);
            let old_keys: Vec<_> = old.iter().map(|(key, _)| key).collect();
            let new_keys: Vec<_> = new.iter().map(|(key, _)| key).collect();
            assert_eq!(old_keys, new_keys, "{family}");
            for ((key, old), (_, new)) in old.iter().zip(new) {
                if old != new {
                    changed.push((*family, key.clone()));
                }
            }
        }
        changed
    }

    #[test]
    fn replaces_an_approved_enrollment_result() {
        let (_permit, _db, _backup, store) = setup_store();
        setup_approval(&store);
        approve(&store).unwrap();
        let attempts = store.senta_endpoint_enrollment_attempt_map();
        let old = attempts.get(&SPKI, Uuid::from_u128(1)).unwrap().unwrap();
        let before = dump(&store);

        replace(&store, 10, "resigned").unwrap();
        let after = dump(&store);
        let changed = changed_keys(&before, &after);
        assert_eq!(changed.len(), 1);
        assert_eq!(
            &*changed[0].1,
            &keys::attempt(&SPKI, Uuid::from_u128(1))[..]
        );
        assert_eq!(
            attempts.get(&SPKI, Uuid::from_u128(1)).unwrap(),
            Some(SentaEndpointEnrollmentAttempt {
                result: approved("resigned"),
                ..old
            })
        );
        assert_eq!(
            store.senta_endpoint_map().get(Uuid::from_u128(10)).unwrap(),
            Some(endpoint(10, CUSTOMER))
        );

        // The same JWS again succeeds and changes nothing.
        replace(&store, 10, "resigned").unwrap();
        assert_eq!(dump(&store), after);

        // The approval and the attempt table still refuse to change it.
        assert!(matches!(
            store.approve_senta_endpoint_enrollment(
                &SPKI,
                Uuid::from_u128(1),
                "again",
                &endpoint(11, CUSTOMER)
            ),
            Err(SentaEndpointError::AttemptApproved { .. })
        ));
        assert!(matches!(
            attempts.set_result(
                &SPKI,
                Uuid::from_u128(1),
                &SentaEndpointEnrollmentResult::Denied {
                    reason: "no".to_string()
                }
            ),
            Err(SentaEndpointError::AttemptApproved { .. })
        ));
        assert_eq!(dump(&store), after);
    }

    #[allow(clippy::too_many_lines)]
    #[test]
    fn replacements_are_refused_writing_nothing() {
        let (_permit, _db, _backup, store) = setup_store();
        setup_approval(&store);
        approve(&store).unwrap();
        let attempts = store.senta_endpoint_enrollment_attempt_map();
        // Attempt 2 stays pending and attempt 3 is denied.
        attempts.insert(&attempt(2, CUSTOMER)).unwrap();
        attempts.insert(&attempt(3, CUSTOMER)).unwrap();
        attempts
            .set_result(
                &SPKI,
                Uuid::from_u128(3),
                &SentaEndpointEnrollmentResult::Denied {
                    reason: "no".to_string(),
                },
            )
            .unwrap();
        // Endpoint 20 has another SPKI hash, and endpoint 30 another customer.
        let other_spki = [8; 32];
        attempts
            .insert(&SentaEndpointEnrollmentAttempt {
                spki_hash: other_spki,
                ..attempt(4, CUSTOMER)
            })
            .unwrap();
        store
            .approve_senta_endpoint_enrollment(
                &other_spki,
                Uuid::from_u128(4),
                "ok",
                &SentaEndpoint {
                    spki_hash: other_spki,
                    ..endpoint(20, CUSTOMER)
                },
            )
            .unwrap();
        store
            .register_senta_endpoint_customer(&customer(2, INSTALL, 1), &keyset(2, 1, "kid", "x"))
            .unwrap();
        attempts.insert(&attempt(5, 2)).unwrap();
        store
            .approve_senta_endpoint_enrollment(&SPKI, Uuid::from_u128(5), "ok", &endpoint(30, 2))
            .unwrap();

        let before = dump(&store);
        let refuse = |attempt_id: u128, endpoint_id: u128| {
            store.replace_senta_endpoint_enrollment_result(
                &SPKI,
                Uuid::from_u128(attempt_id),
                Uuid::from_u128(endpoint_id),
                "resigned",
            )
        };
        assert!(matches!(
            refuse(9, 10),
            Err(SentaEndpointError::AttemptNotFound { attempt_id }) if attempt_id == Uuid::from_u128(9)
        ));
        assert!(matches!(
            store.replace_senta_endpoint_enrollment_result(
                &other_spki,
                Uuid::from_u128(1),
                Uuid::from_u128(10),
                "resigned",
            ),
            Err(SentaEndpointError::AttemptNotFound { .. })
        ));
        assert!(matches!(
            refuse(2, 10),
            Err(SentaEndpointError::AttemptNotApproved { attempt_id }) if attempt_id == Uuid::from_u128(2)
        ));
        assert!(matches!(
            refuse(3, 10),
            Err(SentaEndpointError::AttemptNotApproved { attempt_id }) if attempt_id == Uuid::from_u128(3)
        ));
        assert!(matches!(
            refuse(1, 99),
            Err(SentaEndpointError::EndpointNotFound { endpoint_id }) if endpoint_id == Uuid::from_u128(99)
        ));
        assert!(matches!(
            refuse(1, 20),
            Err(SentaEndpointError::AttemptMismatch { attempt_id }) if attempt_id == Uuid::from_u128(1)
        ));
        assert!(matches!(
            refuse(1, 30),
            Err(SentaEndpointError::AttemptMismatch { attempt_id }) if attempt_id == Uuid::from_u128(1)
        ));
        assert_eq!(dump(&store), before);

        // A customer with no row.
        store
            .senta_endpoint_customer_map()
            .delete(CUSTOMER)
            .unwrap();
        let before = dump(&store);
        assert!(matches!(
            refuse(1, 10),
            Err(SentaEndpointError::CustomerNotFound {
                customer_id: CUSTOMER
            })
        ));
        assert_eq!(dump(&store), before);
        assert_eq!(stored_result(&store), approved("ok"));
    }

    #[test]
    fn replacements_of_a_customer_with_a_deletion_job_are_refused() {
        for (status, state) in DELETION_STATES {
            let (_permit, _db, _backup, store) = setup_store();
            setup_approval(&store);
            approve(&store).unwrap();
            store
                .create_customer_data_deletion_job(&job(CUSTOMER, status))
                .unwrap();
            let before = dump(&store);
            assert_deletion(replace(&store, 10, "resigned"), CUSTOMER, state);
            assert_eq!(dump(&store), before);
        }
    }

    #[test]
    fn a_deletion_job_committed_during_a_replacement_refuses_it() {
        let (_permit, _db, _backup, store) = setup_store();
        setup_approval(&store);
        approve(&store).unwrap();
        hook_once(
            &store,
            HookPoint::BeforeCommit(Method::ReplaceEnrollmentResult),
            |store| {
                assert_eq!(create_job(store).endpoint_ids, vec![Uuid::from_u128(10)]);
            },
        );
        assert_deletion(
            replace(&store, 10, "resigned"),
            CUSTOMER,
            SentaEndpointDeletionState::InProgress,
        );
        assert_eq!(stored_result(&store), approved("ok"));
    }

    #[test]
    fn a_replacement_committed_during_a_deletion_job_creation_makes_it_run_again() {
        for point in [
            HookPoint::DeletionJobBeforeScan,
            HookPoint::BeforeCommit(Method::CreateDeletionJob),
        ] {
            let (_permit, _db, _backup, store) = setup_store();
            setup_approval(&store);
            approve(&store).unwrap();
            let scans = hook_counting(&store, point, HookPoint::DeletionJobBeforeScan, |store| {
                replace(store, 10, "resigned").unwrap();
            });
            assert_eq!(
                create_job(&store).endpoint_ids,
                vec![Uuid::from_u128(10)],
                "{point:?}"
            );
            assert_eq!(scans.load(Ordering::SeqCst), 2, "{point:?}");
            assert_eq!(stored_result(&store), approved("resigned"), "{point:?}");
            store.set_senta_endpoint_hook(None);
            assert_deletion(
                replace(&store, 10, "later"),
                CUSTOMER,
                SentaEndpointDeletionState::InProgress,
            );
        }
    }

    #[test]
    fn a_replacement_conflicting_on_the_attempt_row_runs_again() {
        let (_permit, _db, _backup, store) = setup_store();
        setup_approval(&store);
        approve(&store).unwrap();
        let point = HookPoint::BeforeCommit(Method::ReplaceEnrollmentResult);
        let commits = hook_counting(&store, point, point, |store| {
            // Writes the attempt row alone, so the conflict is on it only.
            let attempts = store.senta_endpoint_enrollment_attempt_map();
            let mut attempt = attempts.get(&SPKI, Uuid::from_u128(1)).unwrap().unwrap();
            attempt.result = approved("intervening");
            let txn = store.states.db().transaction();
            attempts.write_row(&txn, &attempt).unwrap();
            txn.commit().unwrap();
        });
        let customer_row = store.senta_endpoint_customer_map().get(CUSTOMER).unwrap();
        replace(&store, 10, "resigned").unwrap();
        // The first try and the retry.
        assert_eq!(commits.load(Ordering::SeqCst), 2);
        assert_eq!(stored_result(&store), approved("resigned"));
        assert_eq!(
            store.senta_endpoint_customer_map().get(CUSTOMER).unwrap(),
            customer_row
        );
    }
}
