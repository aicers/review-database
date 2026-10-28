//! The customer data deletion jobs table.

use anyhow::{Context, Result, bail};
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use crate::{EXCLUSIVE, Map, Table, UniqueKey, tables::Value as ValueTrait, types::FromKeyValue};

const RESOURCE_BUSY_PREFIX: &str = "Resource busy:";

/// The stored value of a customer deletion job: its service results, its
/// periodic time series IDs and its abandoned hosts.
pub(crate) type StoredCustomerDataDeletionJob = (
    Vec<CustomerDataDeletionServiceResult>,
    Vec<String>,
    Vec<String>,
);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomerDataDeletionJob {
    pub customer_id: u32,
    pub service_results: Vec<CustomerDataDeletionServiceResult>,
    /// The decimal IDs of the customer's sampling policies whose periodic time series the Data
    /// Store deletes. They are kept here because the policies themselves are removed in the
    /// Review stage.
    pub periodic_time_series_ids: Vec<String>,
    /// The hosts a System Administrator gave up on, sorted and without duplicates. Each one is a
    /// host FQDN of the job's `Review` result.
    pub abandoned_hosts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomerDataDeletionServiceResult {
    pub service: CustomerDataDeletionService,
    pub host_fqdns: Vec<String>,
    pub status: CustomerDataDeletionStatus,
    /// Records when the most recent deletion attempt was requested, in nanoseconds since the Unix
    /// epoch (UTC). A retry replaces the previous value.
    pub requested_at: i64,
    /// Stores the completion time in nanoseconds since the Unix epoch (UTC), or `None` if the
    /// deletion has not completed.
    pub completed_at: Option<i64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CustomerDataDeletionService {
    Review,
    Sensor,
    SemiSupervised,
    /// The deletion of the customer's data in the Data Store. Its result names the Data Store's
    /// server name, `<instance:03>.giganto.<hostname>`, as its only host FQDN.
    DataStore,
    /// The uninstall of the modules installed on one of the customer's hosts. Its result names
    /// that host as its only host FQDN.
    ModuleRemoval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CustomerDataDeletionStatus {
    InProgress,
    Succeeded,
    Failed,
}

impl CustomerDataDeletionJob {
    /// Creates a job with the given service results, no periodic time series IDs and no
    /// abandoned hosts.
    #[must_use]
    pub fn new(customer_id: u32, service_results: Vec<CustomerDataDeletionServiceResult>) -> Self {
        Self {
            customer_id,
            service_results,
            periodic_time_series_ids: Vec::new(),
            abandoned_hosts: Vec::new(),
        }
    }

    /// Validates every service result and the abandoned hosts.
    fn validate(&self) -> Result<()> {
        for (index, result) in self.service_results.iter().enumerate() {
            result.validate().with_context(|| {
                format!("invalid customer deletion service result at index {index}")
            })?;
        }
        self.validate_abandoned_hosts()
    }

    /// Checks that the abandoned hosts are sorted, without duplicates, and each a host FQDN of
    /// the `Review` result.
    fn validate_abandoned_hosts(&self) -> Result<()> {
        if self
            .abandoned_hosts
            .windows(2)
            .any(|pair| pair.first() >= pair.last())
        {
            bail!("abandoned hosts must be sorted and without duplicates");
        }
        let review_hosts = self
            .service_results
            .iter()
            .find(|result| result.service == CustomerDataDeletionService::Review)
            .map_or(&[][..], |result| result.host_fqdns.as_slice());
        if let Some(host) = self
            .abandoned_hosts
            .iter()
            .find(|host| !review_hosts.contains(host))
        {
            bail!("abandoned host {host} is not a host of the Review service result");
        }
        Ok(())
    }

    fn stored_value(&self) -> Result<Vec<u8>> {
        super::serialize(&(
            &self.service_results,
            &self.periodic_time_series_ids,
            &self.abandoned_hosts,
        ))
    }
}

impl CustomerDataDeletionServiceResult {
    fn validate(&self) -> Result<()> {
        if self.host_fqdns.iter().any(String::is_empty) {
            bail!("host FQDNs must not contain an empty value");
        }

        match self.service {
            CustomerDataDeletionService::Review => {}
            CustomerDataDeletionService::Sensor
            | CustomerDataDeletionService::SemiSupervised
            | CustomerDataDeletionService::DataStore
            | CustomerDataDeletionService::ModuleRemoval => {
                if self.host_fqdns.len() != 1 {
                    bail!(
                        "{:?} service result requires exactly one host FQDN",
                        self.service
                    );
                }
            }
        }
        Ok(())
    }

    fn matches(&self, existing: &Self) -> bool {
        match self.service {
            CustomerDataDeletionService::Review => {
                existing.service == CustomerDataDeletionService::Review
            }
            CustomerDataDeletionService::Sensor
            | CustomerDataDeletionService::SemiSupervised
            | CustomerDataDeletionService::DataStore
            | CustomerDataDeletionService::ModuleRemoval => {
                existing.service == self.service && existing.host_fqdns == self.host_fqdns
            }
        }
    }
}

impl UniqueKey for CustomerDataDeletionJob {
    type AsBytes<'a> = [u8; size_of::<u32>()];

    fn unique_key(&self) -> Self::AsBytes<'_> {
        self.customer_id.to_be_bytes()
    }
}

impl ValueTrait for CustomerDataDeletionJob {
    type AsBytes<'a> = Vec<u8>;

    fn value(&self) -> Self::AsBytes<'_> {
        self.stored_value()
            .expect("derived job fields serialize infallibly into an in-memory Vec")
    }
}

impl FromKeyValue for CustomerDataDeletionJob {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let customer_id = u32::from_be_bytes(
            key.try_into()
                .context("customer deletion job key must be four bytes")?,
        );
        let (service_results, periodic_time_series_ids, abandoned_hosts): StoredCustomerDataDeletionJob =
            super::deserialize(value)?;
        Ok(Self {
            customer_id,
            service_results,
            periodic_time_series_ids,
            abandoned_hosts,
        })
    }
}

/// Functions for the customer data deletion jobs table.
impl<'d> Table<'d, CustomerDataDeletionJob> {
    /// Opens the customer data deletion jobs table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::CUSTOMER_DELETION_JOBS).map(Table::new)
    }

    /// Returns the deletion job for the given customer.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored value is invalid or the database operation fails.
    pub fn get(&self, customer_id: u32) -> Result<Option<CustomerDataDeletionJob>> {
        let key = customer_id.to_be_bytes();
        let Some(value) = self.map.get(&key)? else {
            return Ok(None);
        };
        Ok(Some(CustomerDataDeletionJob::from_key_value(
            &key,
            value.as_ref(),
        )?))
    }

    /// Replaces a deletion job if its stored value has not changed.
    ///
    /// The service results, the periodic time series IDs and the abandoned hosts are compared and
    /// written together.
    ///
    /// # Errors
    ///
    /// Returns an error if the customer IDs differ, a new service result is invalid, the new
    /// abandoned hosts are not sorted, have duplicates or name a host outside the `Review` result,
    /// the job does not exist, the stored value does not match `old`, or a database operation
    /// fails.
    pub fn update(
        &self,
        old: &CustomerDataDeletionJob,
        new: &CustomerDataDeletionJob,
    ) -> Result<()> {
        check_same_customer(old, new)?;
        new.validate()?;

        let key = old.unique_key();
        self.map.update((&key, &old.value()), (&key, &new.value()))
    }

    /// Gives up on hosts of a deletion job, replacing the job if its stored value has not changed.
    ///
    /// `new` is written whole: its service results, which carry the retry's status reset, its
    /// periodic time series IDs, which may have been read again, and its abandoned hosts, which
    /// must keep every host of `old` and may add more.
    ///
    /// # Errors
    ///
    /// Returns an error if the customer IDs differ, a new service result is invalid, the new
    /// abandoned hosts are not sorted, have duplicates, name a host outside the `Review` result or
    /// leave out one of `old`'s, the service results of `new` differ from those of `old` in length
    /// or in the service or host FQDNs at any position, the job does not exist, the stored value
    /// does not match `old`, or a database operation fails.
    pub fn give_up(
        &self,
        old: &CustomerDataDeletionJob,
        new: &CustomerDataDeletionJob,
    ) -> Result<()> {
        check_same_customer(old, new)?;
        new.validate()?;
        let same_results = old.service_results.len() == new.service_results.len()
            && old
                .service_results
                .iter()
                .zip(&new.service_results)
                .all(|(old, new)| old.service == new.service && old.host_fqdns == new.host_fqdns);
        if !same_results {
            bail!("service results must keep the services and host FQDNs of the stored job");
        }
        if let Some(host) = old
            .abandoned_hosts
            .iter()
            .find(|host| new.abandoned_hosts.binary_search(host).is_err())
        {
            bail!("abandoned host {host} must remain abandoned");
        }

        let key = old.unique_key();
        self.map.update((&key, &old.value()), (&key, &new.value()))
    }

    /// Adds a service result to an existing customer deletion job.
    ///
    /// The job's periodic time series IDs and abandoned hosts are left unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error if the result is invalid, the customer does not exist, the service result
    /// already exists, the stored value is invalid, or the database operation fails.
    pub fn add_service(
        &self,
        customer_id: u32,
        result: &CustomerDataDeletionServiceResult,
    ) -> Result<()> {
        result.validate()?;
        let key = customer_id.to_be_bytes();

        loop {
            let txn = self.map.db.transaction();
            let Some(value) = txn
                .get_for_update_cf(self.map.cf, key, EXCLUSIVE)
                .context("cannot read customer deletion job")?
            else {
                bail!("customer deletion job does not exist");
            };
            let (mut service_results, periodic_time_series_ids, abandoned_hosts): StoredCustomerDataDeletionJob =
                super::deserialize(value.as_ref())?;
            if service_results
                .iter()
                .any(|existing| result.matches(existing))
            {
                bail!("customer deletion service result already exists");
            }
            service_results.push(result.clone());

            let value = super::serialize(&(
                &service_results,
                &periodic_time_series_ids,
                &abandoned_hosts,
            ))?;
            txn.put_cf(self.map.cf, key, value)
                .context("failed to write customer deletion job")?;
            match txn.commit() {
                Ok(()) => return Ok(()),
                Err(error) if error.as_ref().starts_with(RESOURCE_BUSY_PREFIX) => {}
                Err(error) => {
                    return Err(error).context("failed to add customer deletion service result");
                }
            }
        }
    }

    /// Updates a service result in an existing customer deletion job.
    ///
    /// The job's periodic time series IDs and abandoned hosts are left unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error if the result is invalid, the customer or service result does not exist,
    /// the stored value is invalid, or the database operation fails.
    pub fn update_service(
        &self,
        customer_id: u32,
        result: &CustomerDataDeletionServiceResult,
    ) -> Result<()> {
        result.validate()?;
        let key = customer_id.to_be_bytes();

        loop {
            let txn = self.map.db.transaction();
            let Some(value) = txn
                .get_for_update_cf(self.map.cf, key, EXCLUSIVE)
                .context("cannot read customer deletion job")?
            else {
                bail!("customer deletion job does not exist");
            };
            let (mut service_results, periodic_time_series_ids, abandoned_hosts): StoredCustomerDataDeletionJob =
                super::deserialize(value.as_ref())?;
            let Some(existing) = service_results
                .iter_mut()
                .find(|existing| result.matches(existing))
            else {
                bail!("customer deletion service result does not exist");
            };
            existing.status = result.status;
            existing.requested_at = result.requested_at;
            existing.completed_at = result.completed_at;
            existing.error.clone_from(&result.error);

            let value = super::serialize(&(
                &service_results,
                &periodic_time_series_ids,
                &abandoned_hosts,
            ))?;
            txn.put_cf(self.map.cf, key, value)
                .context("failed to write customer deletion job")?;
            match txn.commit() {
                Ok(()) => return Ok(()),
                Err(error) if error.as_ref().starts_with(RESOURCE_BUSY_PREFIX) => {}
                Err(error) => {
                    return Err(error).context("failed to update customer deletion service result");
                }
            }
        }
    }
}

fn check_same_customer(old: &CustomerDataDeletionJob, new: &CustomerDataDeletionJob) -> Result<()> {
    if old.customer_id != new.customer_id {
        bail!(
            "customer ID mismatch: old customer ID {} does not match new customer ID {}",
            old.customer_id,
            new.customer_id
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use rocksdb::Direction;

    use super::*;
    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{Iterable, Store};

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

    fn service_result(
        service: CustomerDataDeletionService,
        host_fqdns: &[&str],
        status: CustomerDataDeletionStatus,
        requested_at: i64,
    ) -> CustomerDataDeletionServiceResult {
        CustomerDataDeletionServiceResult {
            service,
            host_fqdns: host_fqdns
                .iter()
                .map(|host_fqdn| (*host_fqdn).to_owned())
                .collect(),
            status,
            requested_at,
            completed_at: None,
            error: None,
        }
    }

    #[test]
    fn stores_and_iterates_jobs_with_expected_encoding() {
        let (_permit, _db_dir, _backup_dir, store) = setup_store();
        let table = store.customer_data_deletion_map();
        let review = service_result(
            CustomerDataDeletionService::Review,
            &["review.example", "review-2.example"],
            CustomerDataDeletionStatus::InProgress,
            10,
        );
        let first = CustomerDataDeletionJob::new(0x0102_0304, vec![review.clone()]);
        let second = CustomerDataDeletionJob::new(7, Vec::new());

        assert_eq!(table.get(first.customer_id).unwrap(), None);
        table.insert(&first).unwrap();
        assert!(table.insert(&first).is_err());
        table.put(&second).unwrap();

        let overwritten = CustomerDataDeletionJob::new(
            first.customer_id,
            vec![
                review,
                service_result(
                    CustomerDataDeletionService::Sensor,
                    &["sensor.example"],
                    CustomerDataDeletionStatus::Succeeded,
                    20,
                ),
            ],
        );
        table.put(&overwritten).unwrap();
        assert_eq!(
            table.get(first.customer_id).unwrap(),
            Some(overwritten.clone())
        );

        let jobs = table
            .iter(Direction::Forward, None)
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_eq!(jobs, vec![second, overwritten.clone()]);

        let key = first.customer_id.to_be_bytes();
        assert_eq!(key, [1, 2, 3, 4]);
        let stored = table.map.db.get_cf(table.map.cf, key).unwrap().unwrap();
        assert_eq!(
            stored,
            super::super::serialize(&(
                &overwritten.service_results,
                Vec::<String>::new(),
                Vec::<String>::new(),
            ))
            .unwrap()
        );
    }

    #[test]
    fn validates_host_fqdns_for_each_service() {
        // A customer with no node left may still have records in the Central Manager.
        for host_fqdns in [
            &[][..],
            &["review.example"][..],
            &["review.example", "review-2.example"][..],
        ] {
            assert!(
                service_result(
                    CustomerDataDeletionService::Review,
                    host_fqdns,
                    CustomerDataDeletionStatus::InProgress,
                    1,
                )
                .validate()
                .is_ok()
            );
        }

        for host_fqdns in [&[""][..], &["review.example", ""][..]] {
            assert!(
                service_result(
                    CustomerDataDeletionService::Review,
                    host_fqdns,
                    CustomerDataDeletionStatus::InProgress,
                    1,
                )
                .validate()
                .is_err()
            );
        }

        for service in [
            CustomerDataDeletionService::Sensor,
            CustomerDataDeletionService::SemiSupervised,
            CustomerDataDeletionService::DataStore,
            CustomerDataDeletionService::ModuleRemoval,
        ] {
            assert!(
                service_result(
                    service,
                    &["sensor.example"],
                    CustomerDataDeletionStatus::InProgress,
                    1,
                )
                .validate()
                .is_ok()
            );

            for host_fqdns in [
                &[][..],
                &[""][..],
                &["sensor.example", "sensor-2.example"][..],
                &["sensor.example", ""][..],
            ] {
                assert!(
                    service_result(
                        service,
                        host_fqdns,
                        CustomerDataDeletionStatus::InProgress,
                        1,
                    )
                    .validate()
                    .is_err()
                );
            }
        }
    }

    #[test]
    fn identifies_service_results_by_service_and_host_fqdns() {
        let (_permit, _db_dir, _backup_dir, store) = setup_store();
        let table = store.customer_data_deletion_map();
        let customer_id = 1;
        table
            .insert(&CustomerDataDeletionJob::new(customer_id, Vec::new()))
            .unwrap();

        let review = service_result(
            CustomerDataDeletionService::Review,
            &["review.example", "review-2.example"],
            CustomerDataDeletionStatus::InProgress,
            1,
        );
        table.add_service(customer_id, &review).unwrap();
        assert!(
            table
                .add_service(
                    customer_id,
                    &service_result(
                        CustomerDataDeletionService::Review,
                        &["another-review.example"],
                        CustomerDataDeletionStatus::InProgress,
                        1,
                    ),
                )
                .is_err()
        );

        let sensor = service_result(
            CustomerDataDeletionService::Sensor,
            &["sensor.example"],
            CustomerDataDeletionStatus::InProgress,
            2,
        );
        table.add_service(customer_id, &sensor).unwrap();
        assert!(table.add_service(customer_id, &sensor).is_err());
        table
            .add_service(
                customer_id,
                &service_result(
                    CustomerDataDeletionService::Sensor,
                    &["sensor-2.example"],
                    CustomerDataDeletionStatus::InProgress,
                    3,
                ),
            )
            .unwrap();
        table
            .add_service(
                customer_id,
                &service_result(
                    CustomerDataDeletionService::SemiSupervised,
                    &["sensor.example"],
                    CustomerDataDeletionStatus::InProgress,
                    4,
                ),
            )
            .unwrap();

        assert!(
            table
                .update_service(
                    customer_id,
                    &service_result(
                        CustomerDataDeletionService::SemiSupervised,
                        &["missing.example"],
                        CustomerDataDeletionStatus::Failed,
                        5,
                    ),
                )
                .is_err()
        );
        assert!(table.add_service(999, &sensor).is_err());
        assert!(table.update_service(999, &sensor).is_err());

        let stored = table.get(customer_id).unwrap().unwrap();
        assert_eq!(stored.service_results.len(), 4);
    }

    #[test]
    fn updates_only_the_matching_service_result() {
        let (_permit, _db_dir, _backup_dir, store) = setup_store();
        let table = store.customer_data_deletion_map();
        let customer_id = 2;
        let review = service_result(
            CustomerDataDeletionService::Review,
            &["review.example", "review-2.example"],
            CustomerDataDeletionStatus::Succeeded,
            1,
        );
        let sensor = service_result(
            CustomerDataDeletionService::Sensor,
            &["sensor.example"],
            CustomerDataDeletionStatus::InProgress,
            2,
        );
        let semi_supervised = service_result(
            CustomerDataDeletionService::SemiSupervised,
            &["semi.example"],
            CustomerDataDeletionStatus::InProgress,
            3,
        );
        table
            .insert(&CustomerDataDeletionJob::new(
                customer_id,
                vec![review.clone(), sensor, semi_supervised.clone()],
            ))
            .unwrap();

        let update = CustomerDataDeletionServiceResult {
            service: CustomerDataDeletionService::Sensor,
            host_fqdns: vec!["sensor.example".to_owned()],
            status: CustomerDataDeletionStatus::Failed,
            requested_at: 20,
            completed_at: Some(30),
            error: Some("deletion failed".to_owned()),
        };
        table.update_service(customer_id, &update).unwrap();

        let stored = table.get(customer_id).unwrap().unwrap();
        assert_eq!(stored.service_results.len(), 3);
        assert!(stored.service_results.contains(&review));
        assert!(stored.service_results.contains(&semi_supervised));
        assert!(stored.service_results.contains(&update));
    }

    #[test]
    fn conditionally_updates_matching_job() {
        let (_permit, _db_dir, _backup_dir, store) = setup_store();
        let table = store.customer_data_deletion_map();
        let old = CustomerDataDeletionJob::new(
            6,
            vec![
                service_result(
                    CustomerDataDeletionService::Review,
                    &["review.example", "review-2.example"],
                    CustomerDataDeletionStatus::InProgress,
                    10,
                ),
                service_result(
                    CustomerDataDeletionService::Sensor,
                    &["sensor.example"],
                    CustomerDataDeletionStatus::InProgress,
                    20,
                ),
            ],
        );
        let mut new = old.clone();
        new.service_results = vec![
            CustomerDataDeletionServiceResult {
                service: CustomerDataDeletionService::Sensor,
                host_fqdns: vec!["sensor-new.example".to_owned()],
                status: CustomerDataDeletionStatus::Succeeded,
                requested_at: 30,
                completed_at: Some(40),
                error: None,
            },
            CustomerDataDeletionServiceResult {
                service: CustomerDataDeletionService::Review,
                host_fqdns: vec!["review-new.example".to_owned()],
                status: CustomerDataDeletionStatus::Failed,
                requested_at: 50,
                completed_at: Some(60),
                error: Some("deletion failed".to_owned()),
            },
        ];
        table.insert(&old).unwrap();

        table.update(&old, &new).unwrap();

        assert_eq!(table.get(old.customer_id).unwrap(), Some(new));
    }

    #[test]
    fn rejects_stale_job_after_single_service_update() {
        let (_permit, _db_dir, _backup_dir, store) = setup_store();
        let table = store.customer_data_deletion_map();
        let old = CustomerDataDeletionJob::new(
            7,
            vec![service_result(
                CustomerDataDeletionService::Sensor,
                &["sensor.example"],
                CustomerDataDeletionStatus::InProgress,
                10,
            )],
        );
        table.insert(&old).unwrap();
        let saved_result = CustomerDataDeletionServiceResult {
            service: CustomerDataDeletionService::Sensor,
            host_fqdns: vec!["sensor.example".to_owned()],
            status: CustomerDataDeletionStatus::Succeeded,
            requested_at: 20,
            completed_at: Some(30),
            error: None,
        };
        table
            .update_service(old.customer_id, &saved_result)
            .unwrap();
        let mut new = old.clone();
        new.service_results = vec![CustomerDataDeletionServiceResult {
            status: CustomerDataDeletionStatus::Failed,
            requested_at: 40,
            completed_at: Some(50),
            error: Some("stale failure".to_owned()),
            ..old.service_results.first().unwrap().clone()
        }];

        let error = table.update(&old, &new).unwrap_err();

        assert_eq!(error.to_string(), "old value mismatch");
        assert_eq!(
            table.get(old.customer_id).unwrap().unwrap().service_results,
            vec![saved_result]
        );
    }

    #[test]
    fn compares_every_service_result_field_and_order() {
        let (_permit, _db_dir, _backup_dir, store) = setup_store();
        let table = store.customer_data_deletion_map();
        let expected = vec![
            CustomerDataDeletionServiceResult {
                service: CustomerDataDeletionService::Review,
                host_fqdns: vec!["review.example".to_owned()],
                status: CustomerDataDeletionStatus::Failed,
                requested_at: 10,
                completed_at: Some(20),
                error: Some("original error".to_owned()),
            },
            service_result(
                CustomerDataDeletionService::Sensor,
                &["sensor.example"],
                CustomerDataDeletionStatus::InProgress,
                30,
            ),
        ];

        let mut requested_at = expected.clone();
        requested_at.first_mut().unwrap().requested_at = 11;
        let mut completed_at = expected.clone();
        completed_at.first_mut().unwrap().completed_at = Some(21);
        let mut error_detail = expected.clone();
        error_detail.first_mut().unwrap().error = Some("different error".to_owned());
        let mut status = expected.clone();
        status.first_mut().unwrap().status = CustomerDataDeletionStatus::Succeeded;
        let mut host_fqdns = expected.clone();
        host_fqdns.last_mut().unwrap().host_fqdns = vec!["sensor-2.example".to_owned()];
        let mut service = expected.clone();
        service.last_mut().unwrap().service = CustomerDataDeletionService::SemiSupervised;
        let mut order = expected.clone();
        order.reverse();
        // A stale update must not discard a result added after the caller's read.
        let mut extra_result = expected.clone();
        extra_result.push(service_result(
            CustomerDataDeletionService::SemiSupervised,
            &["semi-supervised.example"],
            CustomerDataDeletionStatus::InProgress,
            40,
        ));

        for (offset, (field, current_service_results)) in [
            ("requested_at", requested_at),
            ("completed_at", completed_at),
            ("error", error_detail),
            ("status", status),
            ("host_fqdns", host_fqdns),
            ("service", service),
            ("order", order),
            ("extra_result", extra_result),
        ]
        .into_iter()
        .enumerate()
        {
            let customer_id = 100 + u32::try_from(offset).unwrap();
            let old = CustomerDataDeletionJob::new(customer_id, expected.clone());
            let current = CustomerDataDeletionJob::new(customer_id, current_service_results);
            let mut new = old.clone();
            new.service_results.first_mut().unwrap().requested_at = 99;
            table.insert(&current).unwrap();

            let error = table.update(&old, &new).unwrap_err();

            assert_eq!(
                error.to_string(),
                "old value mismatch",
                "failed to detect mismatch in {field}"
            );
            assert_eq!(table.get(customer_id).unwrap(), Some(current));
        }
    }

    #[test]
    fn concurrent_conditional_updates_allow_only_one_winner() {
        let (_permit, _db_dir, _backup_dir, store) = setup_store();
        let store = Arc::new(store);
        let old = CustomerDataDeletionJob::new(
            8,
            vec![service_result(
                CustomerDataDeletionService::Review,
                &["review.example"],
                CustomerDataDeletionStatus::InProgress,
                10,
            )],
        );
        store.customer_data_deletion_map().insert(&old).unwrap();
        let candidates = [
            CustomerDataDeletionJob::new(
                old.customer_id,
                vec![CustomerDataDeletionServiceResult {
                    status: CustomerDataDeletionStatus::Succeeded,
                    requested_at: 20,
                    completed_at: Some(30),
                    ..old.service_results.first().unwrap().clone()
                }],
            ),
            CustomerDataDeletionJob::new(
                old.customer_id,
                vec![CustomerDataDeletionServiceResult {
                    status: CustomerDataDeletionStatus::Failed,
                    requested_at: 40,
                    completed_at: Some(50),
                    error: Some("competing failure".to_owned()),
                    ..old.service_results.first().unwrap().clone()
                }],
            ),
        ];
        let barrier = Arc::new(Barrier::new(3));
        let handles = candidates
            .into_iter()
            .map(|new| {
                let store = Arc::clone(&store);
                let old = old.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    let result = store.customer_data_deletion_map().update(&old, &new);
                    (new, result)
                })
            })
            .collect::<Vec<_>>();

        barrier.wait();
        let outcomes = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(
            outcomes.iter().filter(|(_, result)| result.is_ok()).count(),
            1
        );
        let winner = outcomes
            .iter()
            .find_map(|(job, result)| result.is_ok().then_some(job))
            .unwrap();
        let loser_error = outcomes
            .iter()
            .find_map(|(_, result)| result.as_ref().err())
            .unwrap();
        assert_eq!(loser_error.to_string(), "old value mismatch");
        assert_eq!(
            store
                .customer_data_deletion_map()
                .get(old.customer_id)
                .unwrap()
                .as_ref(),
            Some(winner)
        );
    }

    #[test]
    fn validates_conditional_update_inputs_without_modifying_database() {
        let (_permit, _db_dir, _backup_dir, store) = setup_store();
        let table = store.customer_data_deletion_map();
        let stored = CustomerDataDeletionJob::new(
            9,
            vec![service_result(
                CustomerDataDeletionService::Review,
                &["review.example"],
                CustomerDataDeletionStatus::InProgress,
                10,
            )],
        );
        table.insert(&stored).unwrap();

        let mut wrong_customer = stored.clone();
        wrong_customer.customer_id += 1;
        assert_eq!(
            table
                .update(&stored, &wrong_customer)
                .unwrap_err()
                .to_string(),
            "customer ID mismatch: old customer ID 9 does not match new customer ID 10"
        );
        assert_eq!(table.get(wrong_customer.customer_id).unwrap(), None);
        assert_eq!(table.get(stored.customer_id).unwrap(), Some(stored.clone()));

        let missing = CustomerDataDeletionJob::new(11, Vec::new());
        assert_eq!(
            table.update(&missing, &missing).unwrap_err().to_string(),
            "no such entry"
        );
        assert_eq!(table.get(stored.customer_id).unwrap(), Some(stored.clone()));

        let mut invalid = stored.clone();
        invalid.service_results.push(service_result(
            CustomerDataDeletionService::Sensor,
            &[],
            CustomerDataDeletionStatus::InProgress,
            20,
        ));
        assert!(
            table
                .update(&stored, &invalid)
                .unwrap_err()
                .to_string()
                .starts_with("invalid customer deletion service result at index 1")
        );
        assert_eq!(table.get(stored.customer_id).unwrap(), Some(stored));
    }

    #[test]
    fn concurrent_adds_retry_with_the_latest_value() {
        const RESULTS_PER_SERVICE: i64 = 32;

        let (_permit, _db_dir, _backup_dir, store) = setup_store();
        let store = Arc::new(store);
        let customer_id = 3;
        store
            .customer_data_deletion_map()
            .insert(&CustomerDataDeletionJob::new(customer_id, Vec::new()))
            .unwrap();
        let barrier = Arc::new(Barrier::new(3));

        let handles = [
            CustomerDataDeletionService::Sensor,
            CustomerDataDeletionService::SemiSupervised,
        ]
        .into_iter()
        .map(|service| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || -> Result<()> {
                let table = store.customer_data_deletion_map();
                barrier.wait();
                for index in 0..RESULTS_PER_SERVICE {
                    let host_fqdn = format!("{service:?}-{index}.example");
                    table.add_service(
                        customer_id,
                        &service_result(
                            service,
                            &[&host_fqdn],
                            CustomerDataDeletionStatus::InProgress,
                            index,
                        ),
                    )?;
                }
                Ok(())
            })
        })
        .collect::<Vec<_>>();

        barrier.wait();
        for handle in handles {
            handle.join().unwrap().unwrap();
        }

        let stored = store
            .customer_data_deletion_map()
            .get(customer_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.service_results.len(),
            usize::try_from(RESULTS_PER_SERVICE * 2).unwrap()
        );
    }

    #[test]
    fn concurrent_updates_preserve_both_services() {
        const UPDATE_COUNT: i64 = 32;

        let (_permit, _db_dir, _backup_dir, store) = setup_store();
        let store = Arc::new(store);
        let customer_id = 4;
        store
            .customer_data_deletion_map()
            .insert(&CustomerDataDeletionJob::new(
                customer_id,
                vec![
                    service_result(
                        CustomerDataDeletionService::Sensor,
                        &["sensor.example"],
                        CustomerDataDeletionStatus::InProgress,
                        0,
                    ),
                    service_result(
                        CustomerDataDeletionService::SemiSupervised,
                        &["semi.example"],
                        CustomerDataDeletionStatus::InProgress,
                        0,
                    ),
                ],
            ))
            .unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let services = [
            (CustomerDataDeletionService::Sensor, "sensor.example"),
            (CustomerDataDeletionService::SemiSupervised, "semi.example"),
        ];
        let handles = services
            .into_iter()
            .map(|(service, host_fqdn)| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || -> Result<()> {
                    let table = store.customer_data_deletion_map();
                    barrier.wait();
                    for index in 1..=UPDATE_COUNT {
                        table.update_service(
                            customer_id,
                            &service_result(
                                service,
                                &[host_fqdn],
                                CustomerDataDeletionStatus::Succeeded,
                                index,
                            ),
                        )?;
                    }
                    Ok(())
                })
            })
            .collect::<Vec<_>>();

        barrier.wait();
        for handle in handles {
            handle.join().unwrap().unwrap();
        }

        let stored = store
            .customer_data_deletion_map()
            .get(customer_id)
            .unwrap()
            .unwrap();
        assert_eq!(stored.service_results.len(), 2);
        assert!(stored.service_results.iter().all(|result| {
            result.status == CustomerDataDeletionStatus::Succeeded
                && result.requested_at == UPDATE_COUNT
        }));
    }

    #[test]
    fn jobs_persist_after_reopening_the_database() {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let job = CustomerDataDeletionJob::new(
            5,
            vec![service_result(
                CustomerDataDeletionService::Review,
                &["review.example", "review-2.example"],
                CustomerDataDeletionStatus::Succeeded,
                10,
            )],
        );
        {
            let store = Store::new(db_dir.path(), backup_dir.path(), None).unwrap();
            store.customer_data_deletion_map().put(&job).unwrap();
        }

        let reopened = Store::new(db_dir.path(), backup_dir.path(), None).unwrap();
        assert_eq!(
            reopened
                .customer_data_deletion_map()
                .get(job.customer_id)
                .unwrap(),
            Some(job)
        );
        drop(permit);
    }

    #[test]
    fn new_job_has_no_policy_ids_or_abandoned_hosts() {
        let job = CustomerDataDeletionJob::new(
            1,
            vec![service_result(
                CustomerDataDeletionService::Review,
                &[],
                CustomerDataDeletionStatus::InProgress,
                1,
            )],
        );

        assert_eq!(job.customer_id, 1);
        assert_eq!(job.service_results.len(), 1);
        assert_eq!(job.periodic_time_series_ids, Vec::<String>::new());
        assert_eq!(job.abandoned_hosts, Vec::<String>::new());
    }

    #[test]
    fn stores_module_removal_results_one_per_host() {
        let (_permit, _db_dir, _backup_dir, store) = setup_store();
        let table = store.customer_data_deletion_map();
        let customer_id = 20;
        let first = service_result(
            CustomerDataDeletionService::ModuleRemoval,
            &["a.example"],
            CustomerDataDeletionStatus::InProgress,
            1,
        );
        let second = service_result(
            CustomerDataDeletionService::ModuleRemoval,
            &["b.example"],
            CustomerDataDeletionStatus::InProgress,
            2,
        );
        table
            .insert(&CustomerDataDeletionJob::new(customer_id, Vec::new()))
            .unwrap();
        table.add_service(customer_id, &first).unwrap();
        table.add_service(customer_id, &second).unwrap();

        let same_host = service_result(
            CustomerDataDeletionService::ModuleRemoval,
            &["a.example"],
            CustomerDataDeletionStatus::Failed,
            3,
        );
        assert!(same_host.matches(&first));
        assert!(!same_host.matches(&second));
        assert!(table.add_service(customer_id, &same_host).is_err());
        for host_fqdns in [&[][..], &["a.example", "b.example"][..]] {
            assert!(
                table
                    .add_service(
                        customer_id,
                        &service_result(
                            CustomerDataDeletionService::ModuleRemoval,
                            host_fqdns,
                            CustomerDataDeletionStatus::InProgress,
                            4,
                        ),
                    )
                    .is_err()
            );
        }

        let job = CustomerDataDeletionJob::new(customer_id, vec![first, second]);
        assert_eq!(table.get(customer_id).unwrap(), Some(job.clone()));
        table.put(&job).unwrap();
        assert_eq!(table.get(customer_id).unwrap(), Some(job));
    }

    #[test]
    fn accepts_a_review_result_without_hosts() {
        let (_permit, _db_dir, _backup_dir, store) = setup_store();
        let table = store.customer_data_deletion_map();
        let customer_id = 21;
        let review = service_result(
            CustomerDataDeletionService::Review,
            &[],
            CustomerDataDeletionStatus::InProgress,
            1,
        );
        table
            .insert(&CustomerDataDeletionJob::new(customer_id, Vec::new()))
            .unwrap();

        table.add_service(customer_id, &review).unwrap();

        assert_eq!(
            table.get(customer_id).unwrap(),
            Some(CustomerDataDeletionJob::new(customer_id, vec![review]))
        );
    }

    #[test]
    fn identifies_data_store_results_by_server_name() {
        let (_permit, _db_dir, _backup_dir, store) = setup_store();
        let table = store.customer_data_deletion_map();
        let customer_id = 22;
        table
            .insert(&CustomerDataDeletionJob::new(customer_id, Vec::new()))
            .unwrap();
        let first = service_result(
            CustomerDataDeletionService::DataStore,
            &["001.giganto.a.example"],
            CustomerDataDeletionStatus::InProgress,
            1,
        );
        let second = service_result(
            CustomerDataDeletionService::DataStore,
            &["002.giganto.a.example"],
            CustomerDataDeletionStatus::InProgress,
            2,
        );
        table.add_service(customer_id, &first).unwrap();
        table.add_service(customer_id, &second).unwrap();

        let same_server = service_result(
            CustomerDataDeletionService::DataStore,
            &["001.giganto.a.example"],
            CustomerDataDeletionStatus::Succeeded,
            3,
        );
        assert!(same_server.matches(&first));
        assert!(!same_server.matches(&second));
        assert!(table.add_service(customer_id, &same_server).is_err());
        // A Sensor result for the same name is a different result.
        assert!(
            !service_result(
                CustomerDataDeletionService::Sensor,
                &["001.giganto.a.example"],
                CustomerDataDeletionStatus::InProgress,
                1,
            )
            .matches(&first)
        );
        for host_fqdns in [
            &[][..],
            &["001.giganto.a.example", "002.giganto.a.example"][..],
        ] {
            assert!(
                table
                    .add_service(
                        customer_id,
                        &service_result(
                            CustomerDataDeletionService::DataStore,
                            host_fqdns,
                            CustomerDataDeletionStatus::InProgress,
                            4,
                        ),
                    )
                    .is_err()
            );
        }

        assert_eq!(
            table.get(customer_id).unwrap().unwrap().service_results,
            vec![first, second]
        );
    }

    fn job_with_data_store(customer_id: u32) -> CustomerDataDeletionJob {
        CustomerDataDeletionJob {
            customer_id,
            service_results: vec![
                service_result(
                    CustomerDataDeletionService::Review,
                    &["a.example", "b.example"],
                    CustomerDataDeletionStatus::Succeeded,
                    1,
                ),
                service_result(
                    CustomerDataDeletionService::DataStore,
                    &["001.giganto.b.example"],
                    CustomerDataDeletionStatus::InProgress,
                    2,
                ),
                service_result(
                    CustomerDataDeletionService::ModuleRemoval,
                    &["a.example"],
                    CustomerDataDeletionStatus::Failed,
                    3,
                ),
                service_result(
                    CustomerDataDeletionService::ModuleRemoval,
                    &["b.example"],
                    CustomerDataDeletionStatus::Failed,
                    4,
                ),
            ],
            periodic_time_series_ids: vec!["3".to_owned(), "10".to_owned()],
            abandoned_hosts: vec!["a.example".to_owned()],
        }
    }

    #[test]
    fn stores_policy_ids_and_abandoned_hosts_with_the_results() {
        let (_permit, _db_dir, _backup_dir, store) = setup_store();
        let table = store.customer_data_deletion_map();
        let job = job_with_data_store(23);
        table.insert(&job).unwrap();
        assert_eq!(table.get(job.customer_id).unwrap(), Some(job.clone()));

        let key = job.customer_id.to_be_bytes();
        let stored = table.map.db.get_cf(table.map.cf, key).unwrap().unwrap();
        assert_eq!(
            stored,
            super::super::serialize(&(
                &job.service_results,
                &job.periodic_time_series_ids,
                &job.abandoned_hosts,
            ))
            .unwrap()
        );

        let data_store = CustomerDataDeletionServiceResult {
            status: CustomerDataDeletionStatus::Succeeded,
            requested_at: 20,
            completed_at: Some(30),
            ..job.service_results.get(1).unwrap().clone()
        };
        table.update_service(job.customer_id, &data_store).unwrap();
        let mut expected = job.clone();
        *expected.service_results.get_mut(1).unwrap() = data_store;
        assert_eq!(table.get(job.customer_id).unwrap(), Some(expected.clone()));

        table
            .add_service(
                job.customer_id,
                &service_result(
                    CustomerDataDeletionService::Sensor,
                    &["b.example"],
                    CustomerDataDeletionStatus::InProgress,
                    40,
                ),
            )
            .unwrap();
        let stored = table.get(job.customer_id).unwrap().unwrap();
        assert_eq!(
            stored.periodic_time_series_ids,
            job.periodic_time_series_ids
        );
        assert_eq!(stored.abandoned_hosts, job.abandoned_hosts);
        assert_eq!(
            stored.service_results.get(..4),
            Some(expected.service_results.as_slice())
        );
    }

    #[test]
    fn conditionally_updates_policy_ids() {
        let (_permit, _db_dir, _backup_dir, store) = setup_store();
        let table = store.customer_data_deletion_map();
        let old = job_with_data_store(24);
        table.insert(&old).unwrap();

        let mut new = old.clone();
        new.periodic_time_series_ids = vec!["3".to_owned(), "10".to_owned(), "12".to_owned()];
        table.update(&old, &new).unwrap();
        assert_eq!(table.get(old.customer_id).unwrap(), Some(new.clone()));

        // The stored lists are no longer `old`'s.
        let mut stale_ids = new.clone();
        stale_ids.periodic_time_series_ids = vec!["3".to_owned()];
        assert_eq!(
            table.update(&old, &stale_ids).unwrap_err().to_string(),
            "old value mismatch"
        );
        let mut stale_hosts = new.clone();
        stale_hosts.abandoned_hosts = Vec::new();
        assert_eq!(
            table.update(&stale_hosts, &new).unwrap_err().to_string(),
            "old value mismatch"
        );
        assert_eq!(table.get(old.customer_id).unwrap(), Some(new));
    }

    #[test]
    fn validates_abandoned_hosts_on_update() {
        let (_permit, _db_dir, _backup_dir, store) = setup_store();
        let table = store.customer_data_deletion_map();
        let old = job_with_data_store(25);
        table.insert(&old).unwrap();

        for abandoned_hosts in [
            &["b.example", "a.example"][..],
            &["a.example", "a.example"][..],
            &["c.example"][..],
            &["001.giganto.b.example"][..],
        ] {
            let mut new = old.clone();
            new.abandoned_hosts = abandoned_hosts
                .iter()
                .map(|host| (*host).to_owned())
                .collect();
            assert!(table.update(&old, &new).is_err(), "{abandoned_hosts:?}");
            assert!(table.give_up(&old, &new).is_err(), "{abandoned_hosts:?}");
        }

        // Without a Review result no host can be given up.
        let mut no_review = old.clone();
        no_review.service_results.remove(0);
        assert!(table.update(&old, &no_review).is_err());
        no_review.abandoned_hosts.clear();
        table.update(&old, &no_review).unwrap();
        assert_eq!(table.get(old.customer_id).unwrap(), Some(no_review));
    }

    #[test]
    fn gives_up_hosts_with_results_and_policy_ids_in_one_write() {
        let (_permit, _db_dir, _backup_dir, store) = setup_store();
        let table = store.customer_data_deletion_map();
        let old = job_with_data_store(26);
        table.insert(&old).unwrap();

        let mut new = old.clone();
        new.abandoned_hosts = vec!["a.example".to_owned(), "b.example".to_owned()];
        new.periodic_time_series_ids = vec!["3".to_owned(), "10".to_owned(), "11".to_owned()];
        for (index, result) in new.service_results.iter_mut().enumerate() {
            result.status = CustomerDataDeletionStatus::InProgress;
            result.requested_at = 100 + i64::try_from(index).unwrap();
            result.completed_at = None;
            result.error = None;
        }
        table.give_up(&old, &new).unwrap();
        assert_eq!(table.get(old.customer_id).unwrap(), Some(new.clone()));

        // `old` is now stale.
        assert_eq!(
            table.give_up(&old, &new).unwrap_err().to_string(),
            "old value mismatch"
        );
        assert_eq!(table.get(old.customer_id).unwrap(), Some(new));
    }

    #[test]
    fn refuses_invalid_give_ups_without_modifying_database() {
        let (_permit, _db_dir, _backup_dir, store) = setup_store();
        let table = store.customer_data_deletion_map();
        let old = job_with_data_store(27);
        table.insert(&old).unwrap();
        let give_up_b = || {
            let mut new = old.clone();
            new.abandoned_hosts = vec!["a.example".to_owned(), "b.example".to_owned()];
            new
        };

        let mut stale = old.clone();
        stale.periodic_time_series_ids.push("11".to_owned());
        let mut outside_review = old.clone();
        outside_review.abandoned_hosts = vec!["a.example".to_owned(), "c.example".to_owned()];
        let mut dropped_host = old.clone();
        dropped_host.abandoned_hosts = vec!["b.example".to_owned()];
        let mut wrong_customer = give_up_b();
        wrong_customer.customer_id += 1;
        let mut other_service = give_up_b();
        other_service.service_results.get_mut(1).unwrap().service =
            CustomerDataDeletionService::Sensor;
        let mut other_host = give_up_b();
        other_host.service_results.get_mut(3).unwrap().host_fqdns = vec!["c.example".to_owned()];
        let mut reordered = give_up_b();
        reordered.service_results.swap(2, 3);
        let mut removed = give_up_b();
        removed.service_results.pop();
        let mut added_module_removal = give_up_b();
        added_module_removal.service_results.push(service_result(
            CustomerDataDeletionService::ModuleRemoval,
            &["c.example"],
            CustomerDataDeletionStatus::InProgress,
            5,
        ));

        for (case, given_old, new) in [
            ("stale", &stale, give_up_b()),
            ("outside_review", &old, outside_review),
            ("dropped_host", &old, dropped_host),
            ("wrong_customer", &old, wrong_customer),
            ("other_service", &old, other_service),
            ("other_host", &old, other_host),
            ("reordered", &old, reordered),
            ("removed", &old, removed),
            ("added_module_removal", &old, added_module_removal),
        ] {
            assert!(
                table.give_up(given_old, &new).is_err(),
                "{case} must be refused"
            );
            assert_eq!(
                table.get(old.customer_id).unwrap().as_ref(),
                Some(&old),
                "{case} must change nothing"
            );
            assert_eq!(table.get(old.customer_id + 1).unwrap(), None);
        }
    }

    #[test]
    fn give_up_adds_no_module_removal_results() {
        let (_permit, _db_dir, _backup_dir, store) = setup_store();
        let table = store.customer_data_deletion_map();
        let old = CustomerDataDeletionJob::new(
            28,
            vec![
                service_result(
                    CustomerDataDeletionService::Review,
                    &["a.example", "b.example"],
                    CustomerDataDeletionStatus::Succeeded,
                    1,
                ),
                service_result(
                    CustomerDataDeletionService::Sensor,
                    &["a.example"],
                    CustomerDataDeletionStatus::Failed,
                    2,
                ),
            ],
        );
        table.insert(&old).unwrap();

        let mut new = old.clone();
        new.abandoned_hosts = vec!["a.example".to_owned()];
        for host in ["a.example", "b.example"] {
            new.service_results.push(service_result(
                CustomerDataDeletionService::ModuleRemoval,
                &[host],
                CustomerDataDeletionStatus::InProgress,
                3,
            ));
        }

        assert!(table.give_up(&old, &new).is_err());
        assert_eq!(table.get(old.customer_id).unwrap(), Some(old));
    }
}
