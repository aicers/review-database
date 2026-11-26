//! Tests of the stores of endpoint detection events.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use review_protocol::types::DetectionEvent;
use uuid::Uuid;

use super::{EndpointDetectionEventError, HookPoint, Method};
use crate::{
    CustomerDataDeletionJob, CustomerDataDeletionService, CustomerDataDeletionServiceResult,
    CustomerDataDeletionStatus, DetectionEventStamp, ModelInstance, Node, NodeProfile, PutOutcome,
    SentaEndpoint, SentaEndpointCustomer, SentaEndpointKeysetVersion, Store,
    event::{
        EventFilter,
        fixture::{
            ENDPOINT_ID, FakeCountryLookup, endpoint_event, endpoint_sensor, ip, setup_store,
            setup_store_with_lookup, stamp,
        },
    },
    tables::{DETECTION_EVENT_ARRIVAL, LAST_DETECTION_EVENT_ARRIVAL, META},
};

const CUSTOMER: u32 = 1;
const OTHER_CUSTOMER: u32 = 2;
const A: &str = "10.0.0.1";
const B: &str = "10.0.0.2";
/// A read size and scan cap no test reaches.
const NO_CAP: usize = 1_000;

/// The two stores of an endpoint detection event.
#[derive(Clone, Copy, Debug)]
enum Way {
    /// [`Store::put_endpoint_detection_event`].
    Stream,
    /// [`Store::put_endpoint_detection_event_unless_stored`].
    Request,
}

const WAYS: [Way; 2] = [Way::Stream, Way::Request];

/// Stores `event` the `way` given, the stream path's key as
/// [`PutOutcome::Stored`].
fn put(
    store: &Store,
    way: Way,
    event: &DetectionEvent,
    stamp: &DetectionEventStamp,
    endpoint_id: Uuid,
) -> Result<PutOutcome, EndpointDetectionEventError> {
    match way {
        Way::Stream => store
            .put_endpoint_detection_event(event, stamp, endpoint_id)
            .map(PutOutcome::Stored),
        Way::Request => store.put_endpoint_detection_event_unless_stored(event, stamp, endpoint_id),
    }
}

fn stored_key(outcome: PutOutcome) -> i128 {
    match outcome {
        PutOutcome::Stored(key) => key,
        other => panic!("expected a stored event, got {other:?}"),
    }
}

/// Inserts a node named `name` whose applied profile is of `customer`, and
/// returns its ID.
fn insert_node(store: &Store, name: &str, customer: Option<u32>) -> u32 {
    let node = Node {
        id: 0,
        name: name.to_string(),
        name_draft: None,
        profile: customer.map(|customer_id| NodeProfile {
            customer_id,
            description: String::new(),
            hostname: format!("{name}.example"),
        }),
        profile_draft: None,
        agents: Vec::new(),
        external_services: Vec::new(),
        creation_time: jiff::Timestamp::now(),
    };
    store.node_map().put(&node).unwrap()
}

/// Changes the customer of the applied profile of node `node_id`.
fn set_node_customer(store: &Store, node_id: u32, customer_id: u32) {
    let node = store.node_map().get_by_id(node_id).unwrap().unwrap().0;
    let mut changed = node.clone();
    changed.profile.as_mut().unwrap().customer_id = customer_id;
    store
        .node_map()
        .update(node_id, &node.into(), &changed.into())
        .unwrap();
}

/// A stamp of an engine on node `node_id`.
fn stamp_of(node_id: u32) -> DetectionEventStamp {
    DetectionEventStamp {
        engine_instance: ModelInstance {
            node_id,
            ..stamp().engine_instance
        },
        ..stamp()
    }
}

/// Writes the endpoint row of [`ENDPOINT_ID`] for `customer_id` with
/// `standing`.
fn insert_endpoint(store: &Store, customer_id: u32, standing: &str) {
    let row = SentaEndpoint {
        endpoint_id: ENDPOINT_ID,
        customer_id,
        customer_endpoint_id: Uuid::from_u128(7),
        spki_hash: [7; 32],
        standing: standing.to_string(),
        host_name: "host".to_string(),
        os: "linux".to_string(),
        senta_version: "1.0.0".to_string(),
        bundle: "bundle".to_string(),
        enrolled_at: 1,
        last_connected_at: 1,
        connected: true,
    };
    let txn = store.states.db().transaction();
    store.senta_endpoint_map().write_row(&txn, &row).unwrap();
    txn.commit().unwrap();
}

/// Writes the endpoint-customer row of `customer_id`, so that its deletion
/// job lists its endpoints.
fn insert_customer(store: &Store, customer_id: u32) {
    let row = SentaEndpointCustomer {
        customer_id,
        trust_state: vec![1],
        customer_endpoint_id: Uuid::from_u128(500),
        customer_key_name: "key".to_string(),
        install_id: "install".to_string(),
        last_keyset: SentaEndpointKeysetVersion {
            recovery_epoch: 1,
            keyset_version: 1,
        },
        recovery_key_version: 1,
    };
    let txn = store.states.db().transaction();
    store
        .senta_endpoint_customer_map()
        .write_row(&txn, &row)
        .unwrap();
    txn.commit().unwrap();
}

fn create_job(
    store: &Store,
    customer_id: u32,
    status: CustomerDataDeletionStatus,
) -> CustomerDataDeletionJob {
    store
        .create_customer_data_deletion_job(&CustomerDataDeletionJob::new(
            customer_id,
            vec![CustomerDataDeletionServiceResult {
                service: CustomerDataDeletionService::Review,
                host_fqdns: Vec::new(),
                status,
                requested_at: 1,
                completed_at: None,
                error: None,
            }],
        ))
        .unwrap()
}

/// An event about [`ENDPOINT_ID`] whose subject has the address `addr`.
fn event(addr: &str) -> DetectionEvent {
    endpoint_event(&[addr], None, Vec::new())
}

/// A store with a node of [`CUSTOMER`] and the endpoint of [`CUSTOMER`],
/// with the node's ID.
struct Fixture {
    _permit: crate::test::DbGuard<'static>,
    store: Arc<Store>,
    node: u32,
}

fn setup() -> Fixture {
    let (permit, store) = setup_store();
    let node = insert_node(&store, "node", Some(CUSTOMER));
    insert_endpoint(&store, CUSTOMER, "active");
    Fixture {
        _permit: permit,
        store,
        node,
    }
}

/// The keys of the event records, in key order.
fn record_keys(store: &Store) -> Vec<i128> {
    store
        .events()
        .iter_forward()
        .map(|item| item.unwrap().0)
        .collect()
}

/// The event keys of the arrival index rows, in arrival order.
fn index_keys(store: &Store) -> Vec<i128> {
    let db = store.states.db();
    db.iterator_cf(
        db.cf_handle(DETECTION_EVENT_ARRIVAL).unwrap(),
        rocksdb::IteratorMode::Start,
    )
    .map(|row| {
        crate::ArrivalKey::try_from(&*row.unwrap().0)
            .unwrap()
            .event_key()
    })
    .collect()
}

/// The stored last arrival time, as stored.
fn last_arrival(store: &Store) -> Option<Vec<u8>> {
    let db = store.states.db();
    db.get_cf(db.cf_handle(META).unwrap(), LAST_DETECTION_EVENT_ARRIVAL)
        .unwrap()
}

/// The stored value of the record `key`.
fn raw_record(store: &Store, key: i128) -> Vec<u8> {
    store.states.db().get(key.to_be_bytes()).unwrap().unwrap()
}

/// The event keys the arrival-order read returns.
fn read_by_arrival(store: &Store) -> Vec<i128> {
    let all = EventFilter::new(
        None, None, None, None, None, None, None, None, None, None, None, None, None,
    );
    store
        .events()
        .read_by_arrival(&all, None, NO_CAP, NO_CAP)
        .unwrap()
        .events
        .into_iter()
        .map(|(key, _)| key)
        .collect()
}

/// Asserts that a refusal wrote nothing: the records, the index rows and
/// the last arrival time are as before it.
fn assert_unchanged(store: &Store, records: &[i128], last: Option<&[u8]>) {
    assert_eq!(record_keys(store), records);
    assert_eq!(index_keys(store), records);
    assert_eq!(last_arrival(store).as_deref(), last);
}

/// Installs a hook that runs `action` once, at the first commit of an
/// endpoint detection-event store, and returns how many commits the hook
/// has seen.
fn hook_once(store: &Store, action: impl Fn(&Store) + Send + Sync + 'static) -> Arc<AtomicUsize> {
    let fired = AtomicBool::new(false);
    let count = Arc::new(AtomicUsize::new(0));
    let runs = Arc::clone(&count);
    store.set_senta_endpoint_hook(Some(Arc::new(move |store, at| {
        if at == HookPoint::BeforeCommit(Method::PutEndpointDetectionEvent) {
            runs.fetch_add(1, Ordering::SeqCst);
            if !fired.swap(true, Ordering::SeqCst) {
                action(store);
            }
        }
        Ok(())
    })));
    count
}

#[test]
fn refusals_write_nothing() {
    for way in WAYS {
        let f = setup();
        let store = &*f.store;
        let other_node = insert_node(store, "other-node", Some(OTHER_CUSTOMER));
        let bare_node = insert_node(store, "bare-node", None);
        // A record stored before, so that the last arrival time is set.
        let before = store.events().put(&event(B), &stamp_of(f.node)).unwrap();
        let last = last_arrival(store);
        assert!(last.is_some());
        let unchanged = |store: &Store| assert_unchanged(store, &[before], last.as_deref());

        let unknown = Uuid::from_u128(99);
        match put(store, way, &event(A), &stamp_of(f.node), unknown) {
            Err(EndpointDetectionEventError::UnknownEndpoint { endpoint_id }) => {
                assert_eq!(endpoint_id, unknown);
            }
            other => panic!("{way:?}: expected an unknown endpoint, got {other:?}"),
        }
        unchanged(store);

        for (node, engine) in [
            (other_node, Some(OTHER_CUSTOMER)),
            (bare_node, None),
            (u32::MAX, None),
        ] {
            match put(store, way, &event(A), &stamp_of(node), ENDPOINT_ID) {
                Err(EndpointDetectionEventError::EndpointOfAnotherCustomer {
                    endpoint_id,
                    endpoint_customer,
                    engine_customer,
                }) => {
                    assert_eq!(endpoint_id, ENDPOINT_ID);
                    assert_eq!(endpoint_customer, CUSTOMER);
                    assert_eq!(engine_customer, engine, "{way:?}, node {node}");
                }
                other => panic!("{way:?}: expected another customer, got {other:?}"),
            }
            unchanged(store);
        }
    }
}

#[test]
fn a_customer_with_a_deletion_job_is_refused() {
    for way in WAYS {
        for status in [
            CustomerDataDeletionStatus::InProgress,
            CustomerDataDeletionStatus::Succeeded,
        ] {
            let f = setup();
            let store = &*f.store;
            let before = store.events().put(&event(B), &stamp_of(f.node)).unwrap();
            let last = last_arrival(store);
            let job = create_job(store, CUSTOMER, status);
            assert_eq!(
                job.is_unfinished(),
                status == CustomerDataDeletionStatus::InProgress
            );
            match put(store, way, &event(A), &stamp_of(f.node), ENDPOINT_ID) {
                Err(EndpointDetectionEventError::EndpointCustomerDeleted {
                    endpoint_id,
                    customer_id,
                }) => {
                    assert_eq!(endpoint_id, ENDPOINT_ID);
                    assert_eq!(customer_id, CUSTOMER);
                }
                other => panic!("{way:?}, {status:?}: expected a deletion, got {other:?}"),
            }
            assert_unchanged(store, &[before], last.as_deref());
        }
    }
}

#[test]
fn a_refusal_on_an_empty_database_writes_no_last_arrival_time() {
    for way in WAYS {
        let (_permit, store) = setup_store();
        let node = insert_node(&store, "node", Some(CUSTOMER));
        assert!(matches!(
            put(&store, way, &event(A), &stamp_of(node), ENDPOINT_ID),
            Err(EndpointDetectionEventError::UnknownEndpoint { .. })
        ));
        assert_unchanged(&store, &[], None);
    }
}

#[test]
fn a_suspended_endpoint_is_accepted() {
    for way in WAYS {
        let (_permit, store) = setup_store();
        let node = insert_node(&store, "node", Some(CUSTOMER));
        insert_endpoint(&store, CUSTOMER, "suspended");
        let key = stored_key(put(&store, way, &event(A), &stamp_of(node), ENDPOINT_ID).unwrap());
        assert_eq!(record_keys(&store), [key]);
        assert_eq!(index_keys(&store), [key]);
    }
}

/// The stores write the key, the value and the country codes `put` and
/// `put_unless_stored` write for the same event.
#[test]
fn stores_what_put_stores() {
    let lookup = FakeCountryLookup {
        codes: HashMap::from([(ip(A), *b"KR")]),
    };
    let (_permit, store) = setup_store_with_lookup(lookup);
    let node = insert_node(&store, "node", Some(CUSTOMER));
    insert_endpoint(&store, CUSTOMER, "active");
    let event = event(A);
    let stamp = stamp_of(node);
    let sensors = [endpoint_sensor()];

    let mut written = Vec::new();
    for way in WAYS {
        let key = stored_key(put(&store, way, &event, &stamp, ENDPOINT_ID).unwrap());
        written.push((key, raw_record(&store, key)));
        store.events().remove_by_sensors(&sensors).unwrap();
    }
    let key = store.events().put(&event, &stamp).unwrap();
    written.push((key, raw_record(&store, key)));
    store.events().remove_by_sensors(&sensors).unwrap();
    let key = stored_key(store.events().put_unless_stored(&event, &stamp).unwrap());
    written.push((key, raw_record(&store, key)));

    assert!(written.windows(2).all(|pair| pair[0] == pair[1]));
    let (key, _) = &written[0];
    let record = store.events().iter_forward().next().unwrap().unwrap();
    assert_eq!(record.0, *key);
    assert_eq!(record.1.event(), &event);
    assert_eq!(record.1.stamp(), &stamp);
    assert_eq!(
        record.1.country_codes().collect::<Vec<_>>(),
        [(ip(A), *b"KR")]
    );
}

#[test]
fn the_unless_stored_store_stores_an_event_once() {
    let f = setup();
    let store = &*f.store;
    let key = stored_key(
        store
            .put_endpoint_detection_event_unless_stored(&event(A), &stamp_of(f.node), ENDPOINT_ID)
            .unwrap(),
    );
    let last = last_arrival(store);
    assert_eq!(
        store
            .put_endpoint_detection_event_unless_stored(&event(A), &stamp_of(f.node), ENDPOINT_ID)
            .unwrap(),
        PutOutcome::AlreadyStored
    );
    assert_unchanged(store, &[key], last.as_deref());
}

#[test]
fn stored_events_are_read_in_arrival_order() {
    let f = setup();
    let store = &*f.store;
    let stamp = stamp_of(f.node);
    let addrs = ["10.0.1.1", "10.0.1.2", "10.0.1.3", "10.0.1.4", "10.0.1.5"];
    let mut keys = vec![
        store.events().put(&event(addrs[0]), &stamp).unwrap(),
        store
            .put_endpoint_detection_event(&event(addrs[1]), &stamp, ENDPOINT_ID)
            .unwrap(),
        stored_key(
            store
                .events()
                .put_unless_stored(&event(addrs[2]), &stamp)
                .unwrap(),
        ),
        stored_key(
            store
                .put_endpoint_detection_event_unless_stored(&event(addrs[3]), &stamp, ENDPOINT_ID)
                .unwrap(),
        ),
    ];
    // A duplicate and a refusal add no row between the stored ones.
    assert_eq!(
        store
            .put_endpoint_detection_event_unless_stored(&event(addrs[3]), &stamp, ENDPOINT_ID)
            .unwrap(),
        PutOutcome::AlreadyStored
    );
    let bare = insert_node(store, "bare-node", None);
    assert!(
        store
            .put_endpoint_detection_event(&event(addrs[4]), &stamp_of(bare), ENDPOINT_ID)
            .is_err()
    );
    keys.push(
        store
            .put_endpoint_detection_event(&event(addrs[4]), &stamp, ENDPOINT_ID)
            .unwrap(),
    );

    // Every event has the same time and model, so all but the first take a
    // key from a random start, and only the index gives the arrival order.
    assert_eq!(read_by_arrival(store), keys);
    assert_eq!(index_keys(store), keys);
    assert_eq!(record_keys(store).len(), keys.len());
}

/// (a) A deletion job committed after a store read the job row makes the
/// store retry and be refused.
#[test]
fn a_deletion_job_created_before_the_commit_refuses_the_store() {
    for way in WAYS {
        let f = setup();
        let store = &*f.store;
        let commits = hook_once(store, |store| {
            create_job(store, CUSTOMER, CustomerDataDeletionStatus::InProgress);
        });
        match put(store, way, &event(A), &stamp_of(f.node), ENDPOINT_ID) {
            Err(EndpointDetectionEventError::EndpointCustomerDeleted { customer_id, .. }) => {
                assert_eq!(customer_id, CUSTOMER);
            }
            other => panic!("{way:?}: expected a deletion, got {other:?}"),
        }
        assert_eq!(commits.load(Ordering::SeqCst), 1);
        assert_unchanged(store, &[], None);
        store.set_senta_endpoint_hook(None);
    }
}

/// (b) An event stored before the deletion job is created is removed by the
/// deletion's removal of the job's endpoints.
#[test]
fn an_event_stored_before_the_deletion_job_is_removed_by_the_deletion() {
    for way in WAYS {
        let f = setup();
        let store = &*f.store;
        insert_customer(store, CUSTOMER);
        let commits = hook_once(store, |_| {});
        stored_key(put(store, way, &event(A), &stamp_of(f.node), ENDPOINT_ID).unwrap());
        assert_eq!(commits.load(Ordering::SeqCst), 1);
        let job = create_job(store, CUSTOMER, CustomerDataDeletionStatus::InProgress);
        assert_eq!(job.endpoint_ids, [ENDPOINT_ID]);

        let sensors: Vec<String> = job.endpoint_ids.iter().map(Uuid::to_string).collect();
        store.events().remove_by_sensors(&sensors).unwrap();
        assert_eq!(record_keys(store), [] as [i128; 0]);
        assert_eq!(index_keys(store), [] as [i128; 0]);
        assert!(matches!(
            put(store, way, &event(B), &stamp_of(f.node), ENDPOINT_ID),
            Err(EndpointDetectionEventError::EndpointCustomerDeleted { .. })
        ));
        assert_eq!(record_keys(store), [] as [i128; 0]);
        store.set_senta_endpoint_hook(None);
    }
}

/// (c) A node customer change committed after a store read the node row
/// makes the retry compare against the new customer.
#[test]
fn a_node_customer_change_before_the_commit_refuses_the_store() {
    for way in WAYS {
        let f = setup();
        let store = &*f.store;
        let node = f.node;
        let commits = hook_once(store, move |store| {
            set_node_customer(store, node, OTHER_CUSTOMER);
        });
        match put(store, way, &event(A), &stamp_of(f.node), ENDPOINT_ID) {
            Err(EndpointDetectionEventError::EndpointOfAnotherCustomer {
                endpoint_customer,
                engine_customer,
                ..
            }) => {
                assert_eq!(endpoint_customer, CUSTOMER);
                assert_eq!(engine_customer, Some(OTHER_CUSTOMER));
            }
            other => panic!("{way:?}: expected another customer, got {other:?}"),
        }
        assert_eq!(commits.load(Ordering::SeqCst), 1);
        assert_unchanged(store, &[], None);
        store.set_senta_endpoint_hook(None);
    }
}

/// `put` and `put_unless_stored` do not read the deletion job row: they
/// store an event of a customer that has a job.
#[test]
fn put_and_put_unless_stored_ignore_the_deletion_job() {
    let f = setup();
    let store = &*f.store;
    create_job(store, CUSTOMER, CustomerDataDeletionStatus::InProgress);
    let stamp = stamp_of(f.node);
    let first = store.events().put(&event(A), &stamp).unwrap();
    let second = stored_key(store.events().put_unless_stored(&event(B), &stamp).unwrap());
    assert_eq!(index_keys(store), [first, second]);
}
