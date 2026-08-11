//! The customer data deletion jobs table.

use anyhow::{Context, Result, bail};
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use crate::{EXCLUSIVE, Map, Table, UniqueKey, tables::Value as ValueTrait, types::FromKeyValue};

const RESOURCE_BUSY_PREFIX: &str = "Resource busy:";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomerDataDeletionJob {
    pub customer_id: u32,
    pub service_results: Vec<CustomerDataDeletionServiceResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomerDataDeletionServiceResult {
    pub service: CustomerDataDeletionService,
    pub host_fqdns: Vec<String>,
    pub status: CustomerDataDeletionStatus,
    /// Stores the request time in nanoseconds since the Unix epoch (UTC).
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CustomerDataDeletionStatus {
    InProgress,
    Succeeded,
    Failed,
}

impl CustomerDataDeletionServiceResult {
    fn validate(&self) -> Result<()> {
        if self.host_fqdns.iter().any(String::is_empty) {
            bail!("host FQDNs must not contain an empty value");
        }

        match self.service {
            CustomerDataDeletionService::Review => {
                if self.host_fqdns.is_empty() {
                    bail!("Review service result requires at least one host FQDN");
                }
            }
            CustomerDataDeletionService::Sensor | CustomerDataDeletionService::SemiSupervised => {
                if self.host_fqdns.len() != 1 {
                    bail!(
                        "Sensor and SemiSupervised service results require exactly one host FQDN"
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
            CustomerDataDeletionService::Sensor | CustomerDataDeletionService::SemiSupervised => {
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
        super::serialize(&self.service_results)
            .expect("derived service-result fields serialize infallibly into an in-memory Vec")
    }
}

impl FromKeyValue for CustomerDataDeletionJob {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let customer_id = u32::from_be_bytes(
            key.try_into()
                .context("customer deletion job key must be four bytes")?,
        );
        let service_results = super::deserialize(value)?;
        Ok(Self {
            customer_id,
            service_results,
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

    /// Adds a service result to an existing customer deletion job.
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
            let mut service_results: Vec<CustomerDataDeletionServiceResult> =
                super::deserialize(value.as_ref())?;
            if service_results
                .iter()
                .any(|existing| result.matches(existing))
            {
                bail!("customer deletion service result already exists");
            }
            service_results.push(result.clone());

            let value = super::serialize(&service_results)?;
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
            let mut service_results: Vec<CustomerDataDeletionServiceResult> =
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

            let value = super::serialize(&service_results)?;
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
        let first = CustomerDataDeletionJob {
            customer_id: 0x0102_0304,
            service_results: vec![review.clone()],
        };
        let second = CustomerDataDeletionJob {
            customer_id: 7,
            service_results: Vec::new(),
        };

        assert_eq!(table.get(first.customer_id).unwrap(), None);
        table.insert(&first).unwrap();
        assert!(table.insert(&first).is_err());
        table.put(&second).unwrap();

        let overwritten = CustomerDataDeletionJob {
            customer_id: first.customer_id,
            service_results: vec![
                review,
                service_result(
                    CustomerDataDeletionService::Sensor,
                    &["sensor.example"],
                    CustomerDataDeletionStatus::Succeeded,
                    20,
                ),
            ],
        };
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
            super::super::serialize(&overwritten.service_results).unwrap()
        );
    }

    #[test]
    fn validates_host_fqdns_for_each_service() {
        for host_fqdns in [
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

        for host_fqdns in [&[][..], &[""][..], &["review.example", ""][..]] {
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
            .insert(&CustomerDataDeletionJob {
                customer_id,
                service_results: Vec::new(),
            })
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
            .insert(&CustomerDataDeletionJob {
                customer_id,
                service_results: vec![review.clone(), sensor, semi_supervised.clone()],
            })
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
    fn concurrent_adds_retry_with_the_latest_value() {
        const RESULTS_PER_SERVICE: i64 = 32;

        let (_permit, _db_dir, _backup_dir, store) = setup_store();
        let store = Arc::new(store);
        let customer_id = 3;
        store
            .customer_data_deletion_map()
            .insert(&CustomerDataDeletionJob {
                customer_id,
                service_results: Vec::new(),
            })
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
            .insert(&CustomerDataDeletionJob {
                customer_id,
                service_results: vec![
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
            })
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
        let job = CustomerDataDeletionJob {
            customer_id: 5,
            service_results: vec![service_result(
                CustomerDataDeletionService::Review,
                &["review.example", "review-2.example"],
                CustomerDataDeletionStatus::Succeeded,
                10,
            )],
        };
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
}
