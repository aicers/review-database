//! Tests of the operator operations on the DAI devices: import, merge,
//! split, state change and service removal, and of the MAC ownership
//! history they leave.

use super::super::device::{
    Origin, decode_address_key, decode_device_binding_key, decode_device_key, device_prefix,
    software_key,
};
use super::super::operator::{set_before_operation_commit_hook, set_import_asset_read_hook};
use super::*;
use crate::{
    DAI_IMPORT_MAX_ROWS, DaiActivityChange, DaiDeviceError, DaiIdentifier, DaiIdentifierKind,
    DaiImportOutcome, DaiImportRow, DaiImportRowError, DaiVerdict,
};

/// The time of an operation, an hour after [`NOON`].
const NOW: i64 = NOON + HOUR;

/// Returns an import row of `asset` holding the MACs numbered `macs`.
fn row(asset: &str, macs: &[u8]) -> DaiImportRow {
    DaiImportRow {
        asset_id: asset.to_string(),
        macs: macs.iter().map(|n| mac(*n)).collect(),
        ..DaiImportRow::default()
    }
}

/// Returns the operator asset id `value` as an identifier.
fn asset(value: &str) -> Identifier {
    Identifier {
        kind: IdentifierKind::OperatorAssetId,
        value: value.to_string(),
    }
}

/// Returns the device of a row that was not refused.
fn device_of(outcome: &DaiImportOutcome) -> Uuid {
    match outcome {
        DaiImportOutcome::Created { device }
        | DaiImportOutcome::Updated { device }
        | DaiImportOutcome::Attached { device } => *device,
        DaiImportOutcome::Error(error) => panic!("the row was refused: {error}"),
    }
}

/// Returns the refusal of an operation.
fn refusal<T: std::fmt::Debug>(result: anyhow::Result<T>) -> DaiDeviceError {
    result
        .unwrap_err()
        .downcast::<DaiDeviceError>()
        .expect("a refusal")
}

/// An ACK of MAC `n` at `addr` with a lease of a day, so its binding lasts
/// two days.
fn long(time: i64, addr: &'static str, n: u8) -> Lease {
    Lease {
        secs: Some(86_400),
        ..Lease::ack(time, addr, n)
    }
}

/// Returns an O7 body: a TCP service on `port` at `addr`.
fn service(addr: &str, port: u16, external_client: bool) -> DaiObservationBody {
    DaiObservationBody::Service {
        server_ip: ip(addr),
        port,
        proto: 6,
        external_client,
    }
}

/// Queues and applies, in a transaction of its own on `db`, an observation
/// of sensor [`A`].
fn apply_in(db: &rocksdb::OptimisticTransactionDB, body: &DaiObservationBody, first: i64) {
    let dai = Dai::open(db).unwrap();
    let slot = slot_floor(first).unwrap();
    enqueue_in(&dai, A, slot, body, first, first);
    dai.apply_slot(A, slot, DAI_APPLY_DEFAULT_MAX_COUNT, NOON)
        .unwrap();
}

impl Fixture {
    /// Returns [`CUSTOMER`]'s default site, the site of sensor [`A`].
    fn site(&self) -> String {
        self.store
            .dai_sites(CUSTOMER)
            .unwrap()
            .into_iter()
            .find(|site| site.is_default)
            .unwrap()
            .token
    }

    fn import_at(&self, now: i64, rows: &[DaiImportRow]) -> Vec<DaiImportOutcome> {
        self.dai().import_devices(CUSTOMER, rows, &now).unwrap()
    }

    fn import(&self, row: DaiImportRow) -> DaiImportOutcome {
        self.import_at(NOW, &[row]).remove(0)
    }

    fn merge(&self, survivor: Uuid, others: &[Uuid]) -> anyhow::Result<Uuid> {
        self.dai().merge_devices(CUSTOMER, survivor, others, &NOW)
    }

    fn split(&self, device: Uuid, ids: &[Identifier]) -> anyhow::Result<Uuid> {
        let ids: Vec<DaiIdentifier> = ids.iter().map(Into::into).collect();
        self.dai().split_device(CUSTOMER, device, &ids, &NOW)
    }

    fn set_states(
        &self,
        devices: &[Uuid],
        verdict: Option<DaiVerdict>,
        activity: Option<DaiActivityChange>,
    ) -> anyhow::Result<()> {
        self.dai()
            .set_device_states(CUSTOMER, devices, verdict, activity, &NOW)
    }

    fn remove_service(&self, device: Uuid, port: u16) -> anyhow::Result<()> {
        self.dai().remove_service(CUSTOMER, device, port, 6)
    }

    /// Returns the fixed IPs of [`CUSTOMER`].
    fn fixed_ips(&self) -> BTreeMap<(String, IpAddr), Uuid> {
        self.rows_of(super::super::super::DAI_FIXED_IPS, CUSTOMER)
            .into_iter()
            .map(|(key, value)| {
                let (_, site, ip) = decode_address_key(&key).unwrap();
                (
                    (site, ip),
                    super::super::super::deserialize(&value).unwrap(),
                )
            })
            .collect()
    }

    /// Returns the device aliases of [`CUSTOMER`].
    fn aliases(&self) -> BTreeMap<Uuid, AliasRow> {
        self.rows_of(super::super::super::DAI_DEVICE_ALIASES, CUSTOMER)
            .into_iter()
            .map(|(key, value)| {
                let (_, device) = decode_device_key(&key).unwrap();
                (device, super::super::super::deserialize(&value).unwrap())
            })
            .collect()
    }

    /// Returns the TCP service of `device` on `port`, if any.
    fn service_row(&self, device: Uuid, port: u16) -> Option<ServiceRow> {
        let dai = self.dai();
        dai.read(|txn| Dai::get_row(txn, &dai.services, &service_key(CUSTOMER, device, port, 6)))
            .unwrap()
    }

    /// Returns the (device, IP, start) of each reverse index row of
    /// [`CUSTOMER`]'s bindings.
    fn reverse_index(&self) -> Vec<(Uuid, IpAddr, i64)> {
        self.rows_of(super::super::super::DAI_DEVICE_BINDINGS, CUSTOMER)
            .into_iter()
            .map(|(key, _)| {
                let (_, device, _, ip, start) = decode_device_binding_key(&key).unwrap();
                (device, ip, start)
            })
            .collect()
    }

    /// Returns whether a row of `family` is keyed by `device`.
    fn has_rows_of_device(&self, family: &str, device: Uuid) -> bool {
        self.rows(family)
            .iter()
            .any(|(key, _)| key.starts_with(&device_prefix(CUSTOMER, device)))
    }

    /// Returns the (start, device) of each binding at `addr`.
    fn bound_at(&self, addr: &str) -> Vec<(i64, Uuid)> {
        self.bindings()
            .into_iter()
            .filter(|b| b.1 == ip(addr))
            .map(|b| (b.2, b.5))
            .collect()
    }
}

// ---- Import ----

#[test]
#[allow(clippy::too_many_lines)] // The three outcomes, one after the other.
fn import_creates_attaches_and_updates() {
    let f = setup();
    let site = f.site();

    // A row matching nothing creates a device.
    let created = f.import(DaiImportRow {
        name: Some("printer".to_string()),
        memo: Some("3F".to_string()),
        fixed_ips: vec![(site.clone(), ip("10.0.0.50"))],
        ..row("asset-1", &[1])
    });
    let DaiImportOutcome::Created { device } = created else {
        panic!("not created: {created:?}");
    };
    assert_eq!(device.get_version_num(), 4);
    let stored = f.device(device);
    assert_eq!(stored.identifiers, [asset("asset-1"), mac_id(1)]);
    assert_eq!(
        (stored.first_seen, stored.last_seen, stored.created),
        (None, None, NOW)
    );
    assert_eq!(
        (stored.verdict, stored.activity, stored.origin),
        (Verdict::Observed, Activity::Active, Origin::Import)
    );
    assert_eq!(stored.operator_asset_id.as_deref(), Some("asset-1"));
    assert_eq!(stored.memo, "3F");
    assert_eq!(stored.representative_name(), Some("printer"));
    assert_eq!(stored.version, 1);
    let changes = f.changes(device);
    assert_eq!(changes.len(), 1);
    assert_eq!(
        (changes[0].1.kind, changes[0].1.source, changes[0].1.time),
        (ChangeKind::Created, ChangeSource::Import, NOW)
    );
    assert_eq!(f.owner(1), device);
    assert_eq!(f.identifier(&mac_id(1)).unwrap().last_confirmed, NOW);
    assert_eq!(
        f.identifier(&asset("asset-1")).unwrap().device,
        Some(device)
    );
    assert_eq!(
        f.fixed_ips(),
        BTreeMap::from([((site.clone(), ip("10.0.0.50")), device)])
    );

    // A row whose MAC belongs to an observed device attaches its asset id.
    f.applied(A, &Lease::ack(m(0), "10.0.0.2", 2));
    let observed = f.owner(2);
    assert_eq!(
        f.import(row("asset-2", &[2])),
        DaiImportOutcome::Attached { device: observed }
    );
    let stored = f.device(observed);
    assert_eq!(stored.origin, Origin::Observation);
    assert_eq!(stored.operator_asset_id.as_deref(), Some("asset-2"));
    assert_eq!(stored.identifiers, [mac_id(2), asset("asset-2")]);
    assert_eq!(stored.version, 2);
    let (_, attached) = f.changes(observed).pop().unwrap();
    assert_eq!(
        (attached.kind, attached.source),
        (ChangeKind::Changed, ChangeSource::Import)
    );
    assert_eq!(
        f.identifier(&asset("asset-2")).unwrap().device,
        Some(observed)
    );

    // Re-importing the asset id replaces the name, MACs, fixed IPs and memo.
    assert_eq!(
        f.import(DaiImportRow {
            name: Some("printer-2".to_string()),
            fixed_ips: vec![(site.clone(), ip("10.0.0.51"))],
            ..row("asset-1", &[3])
        }),
        DaiImportOutcome::Updated { device }
    );
    let stored = f.device(device);
    assert_eq!(stored.identifiers, [asset("asset-1"), mac_id(3)]);
    assert_eq!(
        stored
            .names
            .iter()
            .map(|name| (name.value.as_str(), name.source))
            .collect::<Vec<_>>(),
        [("printer-2", NameSource::Operator)]
    );
    assert_eq!(stored.memo, "");
    assert_eq!(stored.origin, Origin::Import);
    assert_eq!(stored.version, 2);
    assert_eq!(f.changes(device).len(), 2);
    assert_eq!(f.identifier(&mac_id(1)).unwrap().device, None);
    assert_eq!(f.owner(3), device);
    assert_eq!(
        f.fixed_ips(),
        BTreeMap::from([((site.clone(), ip("10.0.0.51")), device)])
    );
    assert_eq!(stored.fixed_ips, BTreeSet::from([(site, ip("10.0.0.51"))]));
    assert_eq!(f.devices().len(), 2);
}

#[test]
#[allow(clippy::too_many_lines)] // Every reason, in one request.
fn each_refused_row_has_its_reason_and_writes_nothing() {
    let f = setup();
    let site = f.site();
    f.applied(A, &Lease::ack(m(0), "10.0.0.1", 1));
    let one = f.owner(1);
    f.applied(A, &Lease::ack(m(0), "10.0.0.2", 2));
    let two = f.owner(2);
    let held = device_of(&f.import(DaiImportRow {
        name: Some("held".to_string()),
        memo: Some("memo".to_string()),
        fixed_ips: vec![(site.clone(), ip("10.0.0.60"))],
        ..row("asset-held", &[3])
    }));
    let devices = f.devices();
    let identifiers = f.count(super::super::super::DAI_DEVICE_IDENTIFIERS);
    let fixed = f.fixed_ips();

    let invalid = |asset: &str, chaddr: Vec<u8>| DaiImportRow {
        macs: vec![chaddr],
        ..row(asset, &[])
    };
    let outcomes = f.import_at(
        NOW,
        &[
            row("", &[4]),
            row("asset-ok", &[5]),
            row("asset-ok", &[6]),
            invalid("asset-short", vec![2, 0, 0, 0, 0]),
            invalid("asset-zero", vec![0; 6]),
            invalid("asset-ones", vec![0xff; 6]),
            invalid("asset-group", vec![1, 0, 0, 0, 0, 9]),
            DaiImportRow {
                fixed_ips: vec![("nosite00".to_string(), ip("10.0.0.61"))],
                ..row("asset-site", &[])
            },
            row("asset-two", &[1, 2]),
            row("asset-held", &[1]),
            DaiImportRow {
                fixed_ips: vec![(site.clone(), ip("10.0.0.60"))],
                ..row("asset-fixed", &[])
            },
            row("asset-new", &[3]),
        ],
    );
    let mut pair = vec![one, two];
    pair.sort_unstable();
    let mut held_pair = vec![held, one];
    held_pair.sort_unstable();
    let ok = device_of(&outcomes[1]);
    assert_eq!(
        outcomes,
        [
            DaiImportOutcome::Error(DaiImportRowError::EmptyAssetId),
            DaiImportOutcome::Created { device: ok },
            DaiImportOutcome::Error(DaiImportRowError::DuplicateAssetId {
                asset_id: "asset-ok".to_string()
            }),
            DaiImportOutcome::Error(DaiImportRowError::InvalidMac {
                mac: vec![2, 0, 0, 0, 0]
            }),
            DaiImportOutcome::Error(DaiImportRowError::InvalidMac { mac: vec![0; 6] }),
            DaiImportOutcome::Error(DaiImportRowError::InvalidMac { mac: vec![0xff; 6] }),
            DaiImportOutcome::Error(DaiImportRowError::InvalidMac {
                mac: vec![1, 0, 0, 0, 0, 9]
            }),
            DaiImportOutcome::Error(DaiImportRowError::UnknownSite {
                site: "nosite00".to_string()
            }),
            DaiImportOutcome::Error(DaiImportRowError::MergeFirst { devices: pair }),
            DaiImportOutcome::Error(DaiImportRowError::MergeFirst { devices: held_pair }),
            DaiImportOutcome::Error(DaiImportRowError::FixedIpHeld {
                site,
                ip: ip("10.0.0.60"),
                device: held
            }),
            DaiImportOutcome::Error(DaiImportRowError::AssetIdMismatch {
                device: held,
                asset_id: "asset-held".to_string()
            }),
        ]
    );
    // Only the accepted row wrote: its device, asset id and MAC.
    let mut after = f.devices();
    assert!(after.remove(&ok).is_some());
    assert_eq!(after, devices);
    assert_eq!(
        f.count(super::super::super::DAI_DEVICE_IDENTIFIERS),
        identifiers + 2
    );
    assert_eq!(f.fixed_ips(), fixed);
    assert_eq!(f.owner(1), one);
    assert_eq!(f.owner(3), held);
    assert_eq!(f.identifier(&asset("asset-new")), None);
}

#[test]
fn an_import_of_too_many_rows_is_refused_and_writes_nothing() {
    let f = setup();
    let rows: Vec<DaiImportRow> = (0..=DAI_IMPORT_MAX_ROWS)
        .map(|i| row(&format!("asset-{i}"), &[]))
        .collect();
    assert_eq!(
        refusal(f.dai().import_devices(CUSTOMER, &rows, &NOW)),
        DaiDeviceError::TooManyImportRows {
            count: DAI_IMPORT_MAX_ROWS + 1
        }
    );
    assert_eq!(f.devices().len(), 0);
    assert_eq!(f.count(super::super::super::DAI_DEVICE_IDENTIFIERS), 0);
}

#[test]
fn a_later_row_sees_the_earlier_rows() {
    let f = setup();
    let site = f.site();
    let fixed = (site.clone(), ip("10.0.0.70"));
    let outcomes = f.import_at(
        NOW,
        &[
            DaiImportRow {
                fixed_ips: vec![fixed.clone()],
                ..row("asset-1", &[1])
            },
            row("asset-2", &[1]),
            DaiImportRow {
                fixed_ips: vec![fixed.clone()],
                ..row("asset-3", &[])
            },
            row("asset-4", &[2]),
            row("asset-5", &[2, 3]),
        ],
    );
    let first = device_of(&outcomes[0]);
    let fourth = device_of(&outcomes[3]);
    assert_eq!(
        outcomes[1..3],
        [
            DaiImportOutcome::Error(DaiImportRowError::AssetIdMismatch {
                device: first,
                asset_id: "asset-1".to_string()
            }),
            DaiImportOutcome::Error(DaiImportRowError::FixedIpHeld {
                site,
                ip: ip("10.0.0.70"),
                device: first
            }),
        ]
    );
    assert_eq!(
        outcomes[4],
        DaiImportOutcome::Error(DaiImportRowError::AssetIdMismatch {
            device: fourth,
            asset_id: "asset-4".to_string()
        })
    );
    assert_eq!(f.devices().len(), 2);
}

#[test]
fn an_identical_re_import_writes_no_version_or_history() {
    let f = setup();
    let site = f.site();
    let imported = DaiImportRow {
        name: Some("nas".to_string()),
        memo: Some("rack 2".to_string()),
        fixed_ips: vec![(site.clone(), ip("10.0.0.80"))],
        ..row("asset-1", &[1, 2])
    };
    let device = device_of(&f.import(imported.clone()));
    let stored = f.device(device);
    let identifiers = f.rows(super::super::super::DAI_DEVICE_IDENTIFIERS);
    // Later, and with its duplicates collapsed, the row is the same.
    let again = DaiImportRow {
        macs: vec![mac(2), mac(1), mac(2)],
        fixed_ips: vec![(site.clone(), ip("10.0.0.80")), (site, ip("10.0.0.80"))],
        ..imported.clone()
    };
    for row in [imported, again] {
        assert_eq!(
            f.import_at(NOW + DAY, &[row]),
            [DaiImportOutcome::Updated { device }]
        );
        assert_eq!(f.device(device), stored);
        assert_eq!(f.changes(device).len(), 1);
        assert_eq!(
            f.rows(super::super::super::DAI_DEVICE_IDENTIFIERS),
            identifiers
        );
    }
}

#[test]
fn an_imported_device_is_seen_from_its_first_observation_and_expires_from_its_creation() {
    let f = setup();
    let seen = device_of(&f.import_at(NOON, &[row("asset-1", &[1])])[0]);
    let unseen = device_of(&f.import_at(NOON + 2 * DAY, &[row("asset-2", &[2])])[0]);
    f.retention(NOON + 89 * DAY);
    assert_eq!(f.device(seen).activity, Activity::Active);

    // The first observation applied sets the seen times.
    f.applied(A, &Lease::ack(NOON + 90 * DAY, "10.0.0.1", 1));
    let row = f.device(seen);
    assert_eq!(
        (row.first_seen, row.last_seen, row.activity, row.version),
        (
            Some(NOON + 90 * DAY),
            Some(NOON + 90 * DAY),
            Activity::Active,
            1
        )
    );
    // 91 days after its creation, the unseen device is still within 90 days
    // of it.
    f.retention(NOON + 91 * DAY);
    assert_eq!(f.device(unseen).activity, Activity::Active);
    f.retention(NOON + 93 * DAY);
    assert_eq!(f.device(seen).activity, Activity::Active);
    let row = f.device(unseen);
    assert_eq!((row.activity, row.version), (Activity::NotSeen, 2));
    let (_, expired) = f.changes(unseen).pop().unwrap();
    assert_eq!(expired.source, ChangeSource::Expiry);
    // Observed at last, it is active again.
    f.applied(A, &Lease::ack(NOON + 94 * DAY, "10.0.0.2", 2));
    let row = f.device(unseen);
    assert_eq!(
        (row.first_seen, row.activity, row.version),
        (Some(NOON + 94 * DAY), Activity::Active, 3)
    );
}

// ---- MAC ownership after import ----

#[test]
fn a_mac_removed_by_import_keeps_its_history() {
    let f = setup();
    f.applied(A, &long(m(0), "10.0.0.1", 1));
    let device = f.owner(1);
    f.applied(A, &long(m(20), "10.0.0.1", 1));
    assert_eq!(
        f.import_at(m(30), &[row("asset-1", &[1])]),
        [DaiImportOutcome::Attached { device }]
    );
    let removal = m(40);
    assert_eq!(
        f.import_at(removal, &[row("asset-1", &[2])]),
        [DaiImportOutcome::Updated { device }]
    );
    let history = f.identifier(&mac_id(1)).unwrap();
    assert_eq!(history.device, None);
    assert_eq!(history.owner_at(removal - 1), Some(device));
    assert_eq!(history.owner_at(removal), None);
    assert!(!f.device(device).identifiers.contains(&mac_id(1)));
    assert_eq!(f.bound_at("10.0.0.1"), [(m(0), device)]);

    // A late ACK timed before the removal recomputes the address and binds
    // the device that held the MAC then.
    f.applied(A, &long(m(10), "10.0.0.1", 1));
    assert_eq!(f.bound_at("10.0.0.1"), [(m(0), device)]);
    assert_eq!(f.binding("10.0.0.1", m(0)).last_strong, m(20));
    assert_eq!(f.devices().len(), 1);

    // The first ACK timed after the removal creates a device...
    f.applied(A, &long(m(60), "10.0.0.2", 1));
    let next = f.owner(1);
    assert_ne!(next, device);
    assert_eq!(f.device(next).origin, Origin::Observation);
    // ...which holds the MAC from the removal on: an ACK timed between them,
    // applied afterwards, binds it, and one before still binds the first.
    f.applied(A, &long(m(50), "10.0.0.3", 1));
    f.applied(A, &long(m(15), "10.0.0.4", 1));
    assert_eq!(f.bound_at("10.0.0.3"), [(m(50), next)]);
    assert_eq!(f.bound_at("10.0.0.4"), [(m(15), device)]);
    assert_eq!(f.devices().len(), 2);
    let history = f.identifier(&mac_id(1)).unwrap();
    assert_eq!(history.device, Some(next));
    assert_eq!(
        history
            .earlier_owners
            .iter()
            .map(|owner| (owner.device, owner.left))
            .collect::<Vec<_>>(),
        [(device, removal)]
    );
    assert_eq!(f.device(next).first_seen, Some(m(50)));
}

#[test]
fn a_removal_before_a_later_stamped_aging_move_ends_the_holding_at_the_removal() {
    let f = setup();
    f.update_settings(|update| update.evidence_aging_secs = 86_400);
    f.applied(A, &long(m(0), "10.0.0.1", 1));
    let first = f.owner(1);
    // Evidence aging moves the MAC at an observation time later than the
    // import's clock.
    let moved = NOON + 2 * DAY;
    f.applied(A, &long(moved, "10.0.0.2", 1));
    let aged = f.owner(1);
    assert_ne!(aged, first);
    let removal = NOON + DAY;
    f.import_at(removal, &[row("asset-1", &[1])]);
    f.import_at(removal, &[row("asset-1", &[])]);
    let history = f.identifier(&mac_id(1)).unwrap();
    assert_eq!(history.device, None);
    assert_eq!(history.owner_at(removal - 1), Some(first));
    assert_eq!(history.owner_at(removal), None);
    assert_eq!(history.owner_at(moved), None);

    // An ACK timed between the removal and the aging move creates the next
    // holder, which holds the MAC from the removal on.
    f.applied(A, &long(removal + HOUR, "10.0.0.3", 1));
    let next = f.owner(1);
    assert!(next != first && next != aged);
    f.applied(A, &long(removal + 2 * HOUR, "10.0.0.4", 1));
    f.applied(A, &long(m(10), "10.0.0.5", 1));
    assert_eq!(f.bound_at("10.0.0.3"), [(removal + HOUR, next)]);
    assert_eq!(f.bound_at("10.0.0.4"), [(removal + 2 * HOUR, next)]);
    assert_eq!(f.bound_at("10.0.0.5"), [(m(10), first)]);
    assert_eq!(f.devices().len(), 3);
}

#[test]
fn a_later_import_takes_a_removed_mac_from_the_removal_on() {
    let f = setup();
    let first = device_of(&f.import_at(m(0), &[row("asset-1", &[1])])[0]);
    f.import_at(m(10), &[row("asset-1", &[])]);
    let second = device_of(&f.import_at(m(20), &[row("asset-2", &[1])])[0]);
    assert_ne!(first, second);
    let history = f.identifier(&mac_id(1)).unwrap();
    assert_eq!(history.device, Some(second));
    assert_eq!(history.last_confirmed, m(20));
    // An ACK between the removal and the second import binds the second.
    f.applied(A, &long(m(15), "10.0.0.1", 1));
    f.applied(A, &long(m(5), "10.0.0.2", 1));
    assert_eq!(f.bound_at("10.0.0.1"), [(m(15), second)]);
    assert_eq!(f.bound_at("10.0.0.2"), [(m(5), first)]);
    assert_eq!(f.devices().len(), 2);
}

#[test]
fn retention_keeps_an_earlier_owner_of_a_removed_mac_while_it_binds() {
    let f = setup();
    f.applied(
        A,
        &Lease {
            secs: Some(u32::MAX),
            ..Lease::ack(NOON, "10.0.0.1", 1)
        },
    );
    f.applied(A, &Lease::ack(NOON, "10.0.0.2", 2));
    let kept = f.owner(1);
    let gone = f.owner(2);
    f.import_at(NOW, &[row("asset-1", &[1]), row("asset-2", &[2])]);
    f.import_at(NOW + HOUR, &[row("asset-1", &[]), row("asset-2", &[])]);
    f.retention(NOON + 181 * DAY);
    let history = f.identifier(&mac_id(1)).unwrap();
    assert_eq!(history.device, None);
    assert_eq!(
        history
            .earlier_owners
            .iter()
            .map(|owner| owner.device)
            .collect::<Vec<_>>(),
        [kept]
    );
    // The other device's binding with the MAC ended long ago and is gone.
    assert_eq!(f.bound_at("10.0.0.2"), []);
    let history = f.identifier(&mac_id(2)).unwrap();
    assert_eq!((history.device, history.earlier_owners), (None, Vec::new()));
    assert!(f.devices().contains_key(&gone));
}

// ---- Merge ----

#[test]
#[allow(clippy::too_many_lines)] // Every table a merge moves.
fn a_merge_moves_everything_to_the_survivor() {
    let f = setup();
    let site = f.site();
    f.applied(A, &long(m(0), "10.0.0.1", 1));
    let survivor = f.owner(1);
    f.applied(
        A,
        &Lease {
            hostname: Some("x-host"),
            ..long(m(5), "10.0.0.2", 2)
        },
    );
    let absorbed = f.owner(2);
    f.observed(A, &service("10.0.0.1", 22, false), m(10), m(11));
    f.observed(A, &service("10.0.0.2", 22, true), m(12), m(13));
    f.observed(A, &service("10.0.0.2", 80, false), m(12), m(12));
    f.remove_service(survivor, 22).unwrap();
    f.remove_service(absorbed, 80).unwrap();
    f.observed(A, &software("10.0.0.2", "SSH-2.0-X"), m(14), m(14));
    f.observed(A, &software("10.0.0.1", "SSH-2.0-X"), m(15), m(16));
    f.observed(
        A,
        &DaiObservationBody::DhcpServer {
            server_ip: ip("10.0.0.2"),
            server_id: None,
        },
        m(17),
        m(17),
    );
    assert_eq!(
        f.import(DaiImportRow {
            memo: Some("rack 3".to_string()),
            fixed_ips: vec![(site.clone(), ip("10.0.0.70"))],
            ..row("asset-x", &[2])
        }),
        DaiImportOutcome::Attached { device: absorbed }
    );
    let survivor_version = f.device(survivor).version;
    let absorbed_version = f.device(absorbed).version;

    assert_eq!(f.merge(survivor, &[absorbed]).unwrap(), survivor);

    let row = f.device(survivor);
    assert_eq!(row.identifiers, [mac_id(1), mac_id(2), asset("asset-x")]);
    assert!(
        row.names
            .iter()
            .any(|name| name.value == "x-host" && name.source == NameSource::Dhcp)
    );
    assert!(row.was_dhcp_server);
    assert_eq!(row.operator_asset_id.as_deref(), Some("asset-x"));
    assert_eq!(row.memo, "rack 3");
    assert_eq!((row.first_seen, row.last_seen), (Some(m(0)), Some(m(17))));
    assert_eq!(
        (row.verdict, row.activity, row.origin),
        (Verdict::Observed, Activity::Active, Origin::Observation)
    );
    assert_eq!(row.version, survivor_version + 1);
    assert!(!f.devices().contains_key(&absorbed));

    // Bindings with their reverse index, identifiers, services, software
    // strings and fixed IPs.
    assert!(f.bindings().iter().all(|b| b.5 == survivor));
    assert_eq!(
        f.reverse_index(),
        [
            (survivor, ip("10.0.0.1"), m(0)),
            (survivor, ip("10.0.0.2"), m(5))
        ]
    );
    assert_eq!(f.owner(2), survivor);
    assert_eq!(
        f.identifier(&asset("asset-x")).unwrap().device,
        Some(survivor)
    );
    assert_eq!(
        f.service_row(survivor, 22),
        Some(ServiceRow {
            external_client: true,
            first_seen: m(10),
            last_seen: m(13),
            removed: false,
        })
    );
    assert!(f.service_row(survivor, 80).unwrap().removed);
    for family in [
        super::super::super::DAI_SERVICES,
        super::super::super::DAI_SOFTWARE_STRINGS,
        super::super::super::DAI_DEVICE_BINDINGS,
    ] {
        assert!(!f.has_rows_of_device(family, absorbed));
    }
    let software = f.software_of(CUSTOMER);
    assert_eq!(software.len(), 1);
    assert_eq!(
        (&*software[0].0, software[0].1, software[0].2),
        (
            &*software_key(CUSTOMER, survivor, 1, 0, "SSH-2.0-X"),
            m(14),
            m(16)
        )
    );
    assert_eq!(
        f.fixed_ips(),
        BTreeMap::from([((site.clone(), ip("10.0.0.70")), survivor)])
    );
    assert_eq!(
        f.device(survivor).fixed_ips,
        BTreeSet::from([(site, ip("10.0.0.70"))])
    );

    // The alias and the history of both sides.
    assert_eq!(
        f.aliases(),
        BTreeMap::from([(
            absorbed,
            AliasRow {
                current: survivor,
                time: NOW,
                reason: AliasReason::Merged
            }
        )])
    );
    let (version, entry) = f.changes(survivor).pop().unwrap();
    assert_eq!(version, survivor_version + 1);
    assert_eq!(
        (entry.kind, entry.related_device, entry.source, entry.time),
        (
            ChangeKind::Merged,
            Some(absorbed),
            ChangeSource::Operator,
            NOW
        )
    );
    let (version, entry) = f.changes(absorbed).pop().unwrap();
    assert_eq!(version, absorbed_version + 1);
    assert_eq!(
        (entry.kind, entry.related_device, entry.source),
        (ChangeKind::Merged, Some(survivor), ChangeSource::Operator)
    );
}

#[test]
fn merges_re_point_aliases_and_conflicts_and_accept_old_ids() {
    let f = setup();
    for n in 1..=4 {
        f.applied(A, &Lease::ack(m(0), "10.0.0.1", n));
    }
    let [first, second, third, fourth] = [1, 2, 3, 4].map(|n| f.owner(n));
    let account = Identifier {
        kind: IdentifierKind::MachineAccount,
        value: format!("HOST$@{REALM}"),
    };
    let conflict_key = identifier_key(CUSTOMER, &account);
    f.put(
        super::super::super::DAI_CONFLICTS,
        &conflict_key,
        &ConflictRow {
            devices: [first, fourth].into(),
            first: m(0),
            last: m(1),
        },
    );
    let conflict = || -> ConflictRow {
        let dai = f.dai();
        dai.read(|txn| Dai::get_row(txn, &dai.conflicts, &conflict_key))
            .unwrap()
            .unwrap()
    };

    assert_eq!(f.merge(second, &[first]).unwrap(), second);
    assert_eq!(conflict().devices, [second, fourth].into());
    // The old id of the absorbed device names the survivor.
    let later = NOW + MINUTE;
    assert_eq!(
        f.dai()
            .merge_devices(CUSTOMER, third, &[first, first], &later)
            .unwrap(),
        third
    );
    assert_eq!(conflict().devices, [third, fourth].into());
    assert_eq!(f.merge(first, &[fourth]).unwrap(), third);
    assert_eq!(conflict().devices, [third].into());
    let merged = AliasReason::Merged;
    assert_eq!(
        f.aliases()
            .into_iter()
            .map(|(old, alias)| (old, (alias.current, alias.time, alias.reason)))
            .collect::<BTreeMap<_, _>>(),
        BTreeMap::from([
            (first, (third, NOW, merged)),
            (second, (third, later, merged)),
            (fourth, (third, NOW, merged))
        ])
    );
    assert_eq!(f.devices().keys().copied().collect::<Vec<_>>(), [third]);
    assert!(f.bindings().iter().all(|second| second.5 == third));
}

#[test]
fn a_merge_is_refused_for_different_asset_ids_unknown_devices_and_the_survivor() {
    let f = setup();
    let first = device_of(&f.import(row("asset-1", &[1])));
    let second = device_of(&f.import(row("asset-2", &[2])));
    f.applied(A, &Lease::ack(m(0), "10.0.0.3", 3));
    let third = f.owner(3);
    let devices = f.devices();
    let mut carrying = vec![
        (first, "asset-1".to_string()),
        (second, "asset-2".to_string()),
    ];
    carrying.sort_unstable();
    assert_eq!(
        refusal(f.merge(third, &[first, second])),
        DaiDeviceError::AssetIdConflict { devices: carrying }
    );
    let unknown = Uuid::from_bytes([7; 16]);
    assert_eq!(
        refusal(f.merge(unknown, &[first])),
        DaiDeviceError::UnknownDevice { device: unknown }
    );
    assert_eq!(
        refusal(f.merge(first, &[unknown])),
        DaiDeviceError::UnknownDevice { device: unknown }
    );
    assert_eq!(
        refusal(f.merge(first, &[third, first])),
        DaiDeviceError::SurvivorAmongOthers { device: first }
    );
    assert_eq!(
        refusal(f.merge(first, &[])),
        DaiDeviceError::NoDevicesToMerge
    );
    assert_eq!(f.devices(), devices);
    assert_eq!(f.aliases(), BTreeMap::new());
    // Through an alias, the survivor is still among the others.
    f.merge(first, &[third]).unwrap();
    assert_eq!(
        refusal(f.merge(first, &[third])),
        DaiDeviceError::SurvivorAmongOthers { device: third }
    );
}

#[test]
fn an_ack_of_an_absorbed_mac_binds_the_survivor() {
    let f = setup();
    f.applied(A, &long(m(0), "10.0.0.1", 1));
    let survivor = f.owner(1);
    f.applied(A, &long(m(0), "10.0.0.2", 2));
    let absorbed = f.owner(2);
    f.merge(survivor, &[absorbed]).unwrap();
    f.applied(A, &long(m(10), "10.0.0.2", 2));
    assert_eq!(f.bound_at("10.0.0.2"), [(m(0), survivor)]);
    assert_eq!(f.binding("10.0.0.2", m(0)).last_strong, m(10));
    f.applied(A, &long(m(20), "10.0.0.3", 2));
    assert_eq!(f.bound_at("10.0.0.3"), [(m(20), survivor)]);
    assert_eq!(f.devices().len(), 1);
}

#[test]
fn a_recomputation_after_a_merge_keeps_the_survivor_also_for_an_aged_mac() {
    let f = setup();
    f.update_settings(|update| update.evidence_aging_secs = 86_400);
    f.applied(A, &long(NOON, "10.0.0.1", 1));
    let absorbed = f.owner(1);
    // Evidence aging moves the MAC to a new device.
    f.applied(A, &long(NOON + 2 * DAY, "10.0.0.1", 1));
    let aged = f.owner(1);
    assert_ne!(aged, absorbed);
    f.applied(A, &long(NOON, "10.0.0.5", 5));
    let survivor = f.owner(5);
    f.merge(survivor, &[absorbed]).unwrap();
    let history = f.identifier(&mac_id(1)).unwrap();
    assert_eq!(history.device, Some(aged));
    assert_eq!(history.owner_at(NOON), Some(survivor));

    // A late ACK before the move recomputes the address.
    f.applied(A, &long(NOON + HOUR, "10.0.0.1", 1));
    assert_eq!(
        f.bound_at("10.0.0.1"),
        [(NOON, survivor), (NOON + 2 * DAY, aged)]
    );
    assert_eq!(f.binding("10.0.0.1", NOON).last_strong, NOON + HOUR);
    assert_eq!(f.devices().len(), 2);
    assert_eq!(f.device(survivor).last_seen, Some(NOON + HOUR));
}

#[test]
fn a_merge_derives_the_bindings_a_recomputation_derives() {
    // MAC 1 starts a binding with a 10-minute inactivity time and MAC 2,
    // of another device, takes the address over with a 60-minute one. Once
    // both MACs name one device, MAC 2's ACK extends the binding MAC 1
    // started instead of starting its own, as a recomputation replays it;
    // so the merge leaves that binding, whichever device survives.
    for survives_first in [true, false] {
        let f = setup();
        f.applied(A, &Lease::ack(m(0), "10.0.0.1", 1));
        let first = f.owner(1);
        let takeover = Lease {
            secs: Some(1_800),
            ..Lease::ack(m(6), "10.0.0.1", 2)
        };
        f.applied(A, &takeover);
        let second = f.owner(2);
        assert_eq!(f.bound_at("10.0.0.1"), [(m(0), first), (m(6), second)]);

        let (survivor, absorbed) = if survives_first {
            (first, second)
        } else {
            (second, first)
        };
        f.merge(survivor, &[absorbed]).unwrap();
        assert_eq!(f.bound_at("10.0.0.1"), [(m(0), survivor)]);
        let merged = f.binding("10.0.0.1", m(0));
        assert_eq!(merged.end, None);
        assert_eq!(merged.last_strong, m(6));
        assert_eq!(merged.inactivity, 10 * MINUTE);
        assert_eq!(merged.evidence_identifier, mac_id(1));
        assert_eq!(
            f.reverse_index(),
            [(survivor, ip("10.0.0.1"), m(0))],
            "survivor {survives_first}"
        );

        // A late ACK replaying the address leaves the same binding.
        f.applied(A, &Lease::ack(m(3), "10.0.0.1", 1));
        assert_eq!(f.bound_at("10.0.0.1"), [(m(0), survivor)]);
        assert_eq!(f.binding("10.0.0.1", m(0)), merged);
        assert_eq!(f.devices().len(), 1);
    }
}

#[test]
fn a_merge_derives_the_bindings_of_the_survivor_a_moved_account_extends() {
    // The absorbed device acquires a machine account at one address; a
    // verified O4 of that account at an address only the survivor is bound
    // at records a conflict and extends nothing. Once the account names the
    // survivor, a recomputation of that address replays the O4 as the
    // survivor's evidence and extends the binding, so the merge derives
    // the binding that way, and a late ACK adding no newer evidence leaves
    // it.
    let f = setup();
    f.applied(A, &Lease::ack(m(0), "10.0.0.2", 2));
    let absorbed = f.owner(2);
    f.observed(A, &verified("10.0.0.2", "HOST2$"), m(1), m(1));
    let account = Identifier {
        kind: IdentifierKind::MachineAccount,
        value: format!("HOST2$@{REALM}"),
    };
    assert_eq!(f.identifier(&account).unwrap().device, Some(absorbed));
    f.applied(A, &Lease::ack(m(0), "10.0.0.1", 1));
    let survivor = f.owner(1);
    f.applied(A, &Lease::ack(m(4), "10.0.0.1", 1));
    f.observed(A, &verified("10.0.0.1", "HOST2$"), m(6), m(6));
    assert_eq!(f.binding("10.0.0.1", m(0)).last_strong, m(4));

    f.merge(survivor, &[absorbed]).unwrap();
    assert_eq!(f.bound_at("10.0.0.1"), [(m(0), survivor)]);
    let merged = f.binding("10.0.0.1", m(0));
    assert_eq!(merged.last_strong, m(6));
    assert_eq!(f.device(survivor).last_seen, Some(m(6)));

    // A late ACK replaying the address leaves the same binding.
    f.applied(A, &Lease::ack(m(2), "10.0.0.1", 1));
    assert_eq!(f.bound_at("10.0.0.1"), [(m(0), survivor)]);
    assert_eq!(f.binding("10.0.0.1", m(0)), merged);
    assert_eq!(f.devices().len(), 1);
}

// ---- Split ----

#[test]
fn a_split_moves_the_chosen_identifiers_and_their_bindings() {
    let f = setup();
    let site = f.site();
    f.applied(A, &long(m(0), "10.0.0.1", 1));
    let device = f.owner(1);
    assert_eq!(
        f.import(DaiImportRow {
            name: Some("nas".to_string()),
            memo: Some("memo".to_string()),
            fixed_ips: vec![(site.clone(), ip("10.0.0.80"))],
            ..row("asset-1", &[1, 2])
        }),
        DaiImportOutcome::Attached { device }
    );
    f.applied(A, &long(m(10), "10.0.0.2", 2));
    f.observed(A, &service("10.0.0.1", 22, false), m(11), m(11));
    let version = f.device(device).version;

    let new = f.split(device, &[mac_id(2), mac_id(2)]).unwrap();
    assert_ne!(new, device);
    assert_eq!(new.get_version_num(), 4);
    let row = f.device(new);
    assert_eq!(row.identifiers, [mac_id(2)]);
    assert_eq!(
        (row.origin, row.verdict, row.activity),
        (Origin::Observation, Verdict::Observed, Activity::Active)
    );
    assert_eq!((row.first_seen, row.last_seen), (Some(m(10)), Some(m(10))));
    assert_eq!(
        (row.operator_asset_id, row.names, row.memo),
        (None, Vec::new(), String::new())
    );
    let original = f.device(device);
    assert_eq!(original.identifiers, [mac_id(1), asset("asset-1")]);
    assert_eq!(original.memo, "memo");
    assert_eq!(original.representative_name(), Some("nas"));
    assert_eq!(original.version, version + 1);
    assert_eq!(f.bound_at("10.0.0.1"), [(m(0), device)]);
    assert_eq!(f.bound_at("10.0.0.2"), [(m(10), new)]);
    assert_eq!(
        f.reverse_index().into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([(device, ip("10.0.0.1"), m(0)), (new, ip("10.0.0.2"), m(10))])
    );
    assert_eq!(f.owner(2), new);
    assert!(f.service_row(device, 22).is_some());
    assert_eq!(
        f.fixed_ips(),
        BTreeMap::from([((site, ip("10.0.0.80")), device)])
    );
    let (_, entry) = f.changes(device).pop().unwrap();
    assert_eq!(
        (entry.kind, entry.related_device, entry.source),
        (ChangeKind::Split, Some(new), ChangeSource::Operator)
    );
    let changes = f.changes(new);
    assert_eq!(changes.len(), 1);
    assert_eq!(
        (changes[0].0, changes[0].1.kind, changes[0].1.related_device),
        (1, ChangeKind::Split, Some(device))
    );

    // Moving the operator asset id makes an imported device.
    let imported = f.split(device, &[asset("asset-1")]).unwrap();
    let row = f.device(imported);
    assert_eq!(row.origin, Origin::Import);
    assert_eq!(row.operator_asset_id.as_deref(), Some("asset-1"));
    assert_eq!((row.first_seen, row.last_seen), (Some(NOW), Some(NOW)));
    assert_eq!(f.device(device).operator_asset_id, None);
    assert_eq!(
        f.identifier(&asset("asset-1")).unwrap().device,
        Some(imported)
    );
}

#[test]
fn a_split_is_refused_for_no_all_or_foreign_identifiers() {
    let f = setup();
    f.applied(A, &Lease::ack(m(0), "10.0.0.1", 1));
    let device = f.owner(1);
    f.import(row("asset-1", &[1]));
    let devices = f.devices();
    assert_eq!(refusal(f.split(device, &[])), DaiDeviceError::EmptySplit);
    assert_eq!(
        refusal(f.split(device, &[mac_id(9)])),
        DaiDeviceError::IdentifierNotOnDevice {
            identifier: (&mac_id(9)).into()
        }
    );
    assert_eq!(
        refusal(f.split(device, &[mac_id(1), asset("asset-1")])),
        DaiDeviceError::SplitAllIdentifiers
    );
    let unknown = Uuid::from_bytes([7; 16]);
    assert_eq!(
        refusal(f.split(unknown, &[mac_id(1)])),
        DaiDeviceError::UnknownDevice { device: unknown }
    );
    assert_eq!(f.devices(), devices);
}

#[test]
fn a_recomputation_after_a_split_keeps_the_new_device() {
    let f = setup();
    f.applied(A, &long(m(0), "10.0.0.1", 1));
    let device = f.owner(1);
    f.import(row("asset-1", &[1, 2]));
    f.applied(A, &long(m(10), "10.0.0.2", 2));
    f.applied(A, &long(m(30), "10.0.0.2", 2));
    let new = f.split(device, &[mac_id(2)]).unwrap();
    f.applied(A, &long(m(20), "10.0.0.2", 2));
    assert_eq!(f.bound_at("10.0.0.2"), [(m(10), new)]);
    assert_eq!(f.binding("10.0.0.2", m(10)).last_strong, m(30));
    assert_eq!(f.owner(2), new);
    assert_eq!(f.devices().len(), 2);
    // A late ACK of the MAC that stayed leaves its binding too.
    f.applied(A, &long(m(5), "10.0.0.1", 1));
    assert_eq!(f.bound_at("10.0.0.1"), [(m(0), device)]);
}

#[test]
fn a_split_divides_a_binding_two_macs_contributed_to() {
    // MAC 1 starts the binding and MAC 2 extends it; moving either divides
    // it where the stayed MAC's ACK takes over, as a recomputation does.
    for moved in [1, 2] {
        let f = setup();
        f.applied(A, &long(m(0), "10.0.0.1", 1));
        let device = f.owner(1);
        f.import(row("asset-1", &[1, 2]));
        f.applied(A, &long(m(10), "10.0.0.1", 2));
        assert_eq!(f.bound_at("10.0.0.1"), [(m(0), device)]);
        assert_eq!(f.binding("10.0.0.1", m(0)).last_strong, m(10));

        let new = f.split(device, &[mac_id(moved)]).unwrap();
        let (earlier, later) = if moved == 1 {
            (new, device)
        } else {
            (device, new)
        };
        let split = [(m(0), earlier), (m(10), later)];
        assert_eq!(f.bound_at("10.0.0.1"), split);
        assert_eq!(f.binding("10.0.0.1", m(0)).end, Some(m(10)));
        assert_eq!(f.binding("10.0.0.1", m(10)).evidence_identifier, mac_id(2));
        assert_eq!(
            f.reverse_index().into_iter().collect::<BTreeSet<_>>(),
            BTreeSet::from([
                (earlier, ip("10.0.0.1"), m(0)),
                (later, ip("10.0.0.1"), m(10))
            ])
        );
        let row = f.device(new);
        let first = if moved == 1 { m(0) } else { m(10) };
        assert_eq!((row.first_seen, row.last_seen), (Some(first), Some(first)));

        // A late ACK replaying the address leaves the same assignment.
        f.applied(A, &long(m(5), "10.0.0.1", 1));
        assert_eq!(f.bound_at("10.0.0.1"), split);
        assert_eq!(f.devices().len(), 2);
    }
}

#[test]
fn a_split_credits_an_o4_extension_to_the_device_keeping_the_account() {
    // MAC 1 starts the binding and a verified O4 of the same device's
    // machine account extends it. The split moves only the MAC: the O4 is
    // the account's evidence, which stays with the original device, so the
    // moved binding is derived without it, as applying the observations in
    // order by the new ownership would, and a recomputation agrees.
    let f = setup();
    f.applied(A, &Lease::ack(m(0), "10.0.0.1", 1));
    let device = f.owner(1);
    f.observed(A, &verified("10.0.0.1", "HOST1$"), m(6), m(6));
    let account = Identifier {
        kind: IdentifierKind::MachineAccount,
        value: format!("HOST1$@{REALM}"),
    };
    assert!(f.device(device).identifiers.contains(&account));
    assert_eq!(f.binding("10.0.0.1", m(0)).last_strong, m(6));

    let new = f.split(device, &[mac_id(1)]).unwrap();
    assert_eq!(f.bound_at("10.0.0.1"), [(m(0), new)]);
    assert_eq!(f.binding("10.0.0.1", m(0)).last_strong, m(0));
    assert_eq!(f.identifier(&account).unwrap().device, Some(device));
    let row = f.device(new);
    assert_eq!((row.first_seen, row.last_seen), (Some(m(0)), Some(m(0))));
    assert_eq!(f.device(device).last_seen, Some(m(6)));

    // A late ACK replaying the address credits the O4 the same way.
    f.applied(A, &Lease::ack(m(3), "10.0.0.1", 1));
    assert_eq!(f.bound_at("10.0.0.1"), [(m(0), new)]);
    assert_eq!(f.binding("10.0.0.1", m(0)).last_strong, m(3));
    assert_eq!(f.devices().len(), 2);
}

// ---- State change and service removal ----

#[test]
fn a_state_change_writes_one_entry_per_changed_device() {
    let f = setup();
    for n in 1..=4 {
        f.applied(A, &Lease::ack(m(0), "10.0.0.1", n));
    }
    let [first, second, third, fourth] = [1, 2, 3, 4].map(|n| f.owner(n));
    let bindings = f.bindings();
    f.set_states(&[first, second], Some(DaiVerdict::Confirmed), None)
        .unwrap();
    f.set_states(
        &[first, second, third],
        Some(DaiVerdict::Confirmed),
        Some(DaiActivityChange::Hidden),
    )
    .unwrap();
    let versions = |devices: &[Uuid]| -> Vec<u64> {
        devices
            .iter()
            .map(|device| f.device(*device).version)
            .collect()
    };
    assert_eq!(versions(&[first, second, third, fourth]), vec![3, 3, 2, 1]);
    let (_, entry) = f.changes(third).pop().unwrap();
    assert_eq!(
        (entry.fields.len(), entry.source, entry.kind),
        (2, ChangeSource::Operator, ChangeKind::Changed)
    );
    assert_eq!(f.device(third).verdict, Verdict::Confirmed);
    assert_eq!(f.device(third).activity, Activity::Hidden);
    // The same values again change nothing.
    f.set_states(&[first, third], Some(DaiVerdict::Confirmed), None)
        .unwrap();
    assert_eq!(versions(&[first, second, third, fourth]), vec![3, 3, 2, 1]);
    // One unknown id, or too many, refuses the whole call.
    let unknown = Uuid::from_bytes([7; 16]);
    assert_eq!(
        refusal(f.set_states(&[fourth, unknown], Some(DaiVerdict::Ignored), None)),
        DaiDeviceError::UnknownDevice { device: unknown }
    );
    assert_eq!(
        refusal(f.set_states(&[fourth; 1_001], Some(DaiVerdict::Ignored), None)),
        DaiDeviceError::TooManyDevices { count: 1_001 }
    );
    assert_eq!(f.device(fourth).verdict, Verdict::Observed);
    // "Not seen" becomes active.
    let mut not_seen = f.device(fourth);
    not_seen.activity = Activity::NotSeen;
    f.put(
        super::super::super::DAI_DEVICES,
        &device_key(CUSTOMER, fourth),
        &not_seen,
    );
    f.set_states(&[fourth], None, Some(DaiActivityChange::Active))
        .unwrap();
    assert_eq!(
        (f.device(fourth).activity, f.device(fourth).version),
        (Activity::Active, 2)
    );
    assert_eq!(f.bindings(), bindings);
}

#[test]
fn a_service_removal_sets_the_flag_and_keeps_the_version() {
    let f = setup();
    f.applied(A, &long(m(0), "10.0.0.1", 1));
    let device = f.owner(1);
    f.observed(A, &service("10.0.0.1", 22, false), m(10), m(10));
    let version = f.device(device).version;
    f.remove_service(device, 22).unwrap();
    assert!(f.service_row(device, 22).unwrap().removed);
    f.observed(A, &service("10.0.0.1", 22, false), m(20), m(20));
    let row = f.service_row(device, 22).unwrap();
    assert!(row.removed);
    assert_eq!(row.last_seen, m(20));
    assert_eq!(f.device(device).version, version);
    assert_eq!(f.changes(device).len(), 1);
    assert_eq!(
        refusal(f.remove_service(device, 23)),
        DaiDeviceError::UnknownService {
            device,
            port: 23,
            protocol: 6
        }
    );
    let unknown = Uuid::from_bytes([7; 16]);
    assert_eq!(
        refusal(f.remove_service(unknown, 22)),
        DaiDeviceError::UnknownDevice { device: unknown }
    );
}

#[test]
fn every_operation_accepts_an_old_device_id() {
    let f = setup();
    f.applied(A, &long(m(0), "10.0.0.1", 1));
    let survivor = f.owner(1);
    f.applied(A, &long(m(0), "10.0.0.2", 2));
    let old = f.owner(2);
    f.observed(A, &service("10.0.0.2", 80, false), m(1), m(1));
    f.merge(survivor, &[old]).unwrap();

    f.set_states(&[old], Some(DaiVerdict::Ignored), None)
        .unwrap();
    assert_eq!(f.device(survivor).verdict, Verdict::Ignored);
    f.remove_service(old, 80).unwrap();
    assert!(f.service_row(survivor, 80).unwrap().removed);
    let new = f.split(old, &[mac_id(2)]).unwrap();
    assert_eq!(f.owner(2), new);
    assert_eq!(f.merge(old, &[new]).unwrap(), survivor);
    assert_eq!(f.owner(2), survivor);
}

#[test]
fn the_store_methods_run_each_operation_at_the_current_time() {
    let f = setup();
    f.applied(A, &long(m(0), "10.0.0.1", 1));
    let first = f.owner(1);
    f.applied(A, &long(m(0), "10.0.0.2", 2));
    let second = f.owner(2);
    f.observed(A, &service("10.0.0.2", 80, false), m(1), m(1));
    let store = &f.store;

    let outcomes = store
        .import_dai_devices(CUSTOMER, &[row("asset-1", &[1])])
        .unwrap();
    assert_eq!(outcomes, [DaiImportOutcome::Attached { device: first }]);
    assert_eq!(
        store.merge_dai_devices(CUSTOMER, first, &[second]).unwrap(),
        first
    );
    store.remove_dai_service(CUSTOMER, second, 80, 6).unwrap();
    assert!(f.service_row(first, 80).unwrap().removed);
    store
        .set_dai_device_states(
            CUSTOMER,
            &[second],
            Some(DaiVerdict::Observed),
            Some(DaiActivityChange::Hidden),
        )
        .unwrap();
    assert_eq!(f.device(first).activity, Activity::Hidden);
    let moved = DaiIdentifier::from(&mac_id(2));
    let new = store.split_dai_device(CUSTOMER, first, &[moved]).unwrap();
    assert_eq!(f.owner(2), new);

    // Each operation is timed by the clock, long after the observations.
    let alias = f.aliases().remove(&second).unwrap();
    assert!(alias.time > NOW);
    assert!(f.device(new).first_seen.unwrap() < alias.time);
}

#[test]
fn refusals_name_what_was_refused() {
    let device = Uuid::from_bytes([1; 16]);
    let other = Uuid::from_bytes([2; 16]);
    let cases: [(Box<dyn std::error::Error>, String); 9] = [
        (
            Box::new(DaiImportRowError::InvalidMac {
                mac: vec![0x01, 0, 0, 0, 0, 0x0a],
            }),
            "01:00:00:00:00:0a is not a valid MAC address".to_string(),
        ),
        (
            Box::new(DaiImportRowError::MergeFirst {
                devices: vec![device, other],
            }),
            format!("the row names devices {device}, {other}; merge them first"),
        ),
        (
            Box::new(DaiImportRowError::DuplicateAssetId {
                asset_id: "asset-1".to_string(),
            }),
            "operator asset id \"asset-1\" is used by an earlier row".to_string(),
        ),
        (
            Box::new(DaiDeviceError::AssetIdConflict {
                devices: vec![
                    (device, "asset-1".to_string()),
                    (other, "asset-2".to_string()),
                ],
            }),
            format!(
                "the devices to merge carry different operator asset ids: \
                 {device} (\"asset-1\"), {other} (\"asset-2\")"
            ),
        ),
        (
            Box::new(DaiDeviceError::IdentifierNotOnDevice {
                identifier: DaiIdentifier {
                    kind: DaiIdentifierKind::MachineAccount,
                    value: "HOST1$@EXAMPLE.COM".to_string(),
                },
            }),
            "identifier MachineAccount \"HOST1$@EXAMPLE.COM\" is not on the device".to_string(),
        ),
        (
            Box::new(DaiDeviceError::TooManyImportRows { count: 10_001 }),
            "an import takes at most 10000 rows, not 10001".to_string(),
        ),
        (
            Box::new(DaiDeviceError::TooManyDevices { count: 1_001 }),
            "a state change takes at most 1000 devices, not 1001".to_string(),
        ),
        (
            Box::new(DaiDeviceError::SurvivorAmongOthers { device }),
            format!("device {device} is the survivor of the merge"),
        ),
        (
            Box::new(DaiDeviceError::UnknownService {
                device,
                port: 22,
                protocol: 6,
            }),
            format!("device {device} has no service on port 22 of protocol 6"),
        ),
    ];
    for (error, message) in cases {
        assert_eq!(error.to_string(), message);
    }
}

#[test]
fn identifiers_and_verdicts_convert_both_ways() {
    for kind in [
        DaiIdentifierKind::Mac,
        DaiIdentifierKind::OperatorAssetId,
        DaiIdentifierKind::MachineAccount,
    ] {
        let id = DaiIdentifier {
            kind,
            value: "value".to_string(),
        };
        assert_eq!(DaiIdentifier::from(&Identifier::from(&id)), id);
    }
    for (verdict, stored) in [
        (DaiVerdict::Observed, Verdict::Observed),
        (DaiVerdict::Confirmed, Verdict::Confirmed),
        (DaiVerdict::Ignored, Verdict::Ignored),
    ] {
        assert_eq!(Verdict::from(verdict), stored);
    }
}

// ---- Concurrency ----

#[test]
fn an_operation_and_an_apply_racing_on_one_device_keep_both_changes() {
    let f = setup();
    f.applied(A, &long(m(0), "10.0.0.1", 1));
    let device = f.owner(1);
    f.import(row("asset-1", &[1]));
    assert_eq!(f.device(device).version, 2);

    // An apply adding a name commits inside an import changing the memo.
    set_before_operation_commit_hook(Box::new(|db| {
        apply_in(db, &dns("racer.example", "10.0.0.1"), m(5));
    }));
    assert_eq!(
        f.import(DaiImportRow {
            memo: Some("new memo".to_string()),
            ..row("asset-1", &[1])
        }),
        DaiImportOutcome::Updated { device }
    );
    let row = f.device(device);
    assert_eq!(row.memo, "new memo");
    assert!(row.names.iter().any(|name| name.value == "racer.example"));
    let sources: Vec<(u64, ChangeSource)> = f
        .changes(device)
        .into_iter()
        .map(|(version, entry)| (version, entry.source))
        .collect();
    assert_eq!(
        sources[2..],
        [
            (3, ChangeSource::Observation(22)),
            (4, ChangeSource::Import)
        ]
    );

    // A state change commits inside an apply adding another name.
    set_before_apply_commit_hook(Box::new(move |db| {
        Dai::open(db)
            .unwrap()
            .set_device_states(CUSTOMER, &[device], Some(DaiVerdict::Confirmed), None, &NOW)
            .unwrap();
    }));
    f.observed(A, &dns("second.example", "10.0.0.1"), m(6), m(6));
    let row = f.device(device);
    assert_eq!(row.verdict, Verdict::Confirmed);
    assert!(row.names.iter().any(|name| name.value == "second.example"));
    assert_eq!(row.version, 6);

    // Neither writes a version when it changes no device value: a state
    // change to the stored verdict racing an apply moving the seen times.
    set_before_operation_commit_hook(Box::new(|db| {
        apply_in(db, &long(m(7), "10.0.0.1", 1).body(), m(7));
    }));
    f.set_states(&[device], Some(DaiVerdict::Confirmed), None)
        .unwrap();
    let row = f.device(device);
    assert_eq!((row.version, row.last_seen), (6, Some(m(7))));
}

#[test]
fn an_import_row_reading_across_a_merge_is_retried_not_refused() {
    let f = setup();
    f.applied(A, &Lease::ack(m(0), "10.0.0.1", 1));
    f.applied(A, &Lease::ack(m(0), "10.0.0.2", 2));
    let (absorbed, survivor) = (f.owner(1), f.owner(2));
    f.import(row("asset-1", &[1]));
    // The row reads its asset id on the absorbed device and, after the
    // merge commits, its MAC on the survivor: no state names two devices.
    set_import_asset_read_hook(Box::new(move |db| {
        Dai::open(db)
            .unwrap()
            .merge_devices(CUSTOMER, survivor, &[absorbed], &NOW)
            .unwrap();
    }));
    assert_eq!(
        f.import(row("asset-1", &[1])),
        DaiImportOutcome::Updated { device: survivor }
    );
    assert_eq!(f.owner(1), survivor);
    assert_eq!(f.devices().len(), 1);
}

#[test]
fn an_import_row_whose_device_a_merge_deletes_is_retried() {
    let f = setup();
    f.applied(A, &Lease::ack(m(0), "10.0.0.1", 1));
    f.applied(A, &Lease::ack(m(0), "10.0.0.2", 2));
    let (absorbed, survivor) = (f.owner(1), f.owner(2));
    f.import(row("asset-1", &[1]));
    // The row reads its asset id on the absorbed device, which the merge
    // then deletes: with no MAC to read, the row next reads the device row,
    // finds none, and is retried rather than failing the whole import.
    set_import_asset_read_hook(Box::new(move |db| {
        Dai::open(db)
            .unwrap()
            .merge_devices(CUSTOMER, survivor, &[absorbed], &NOW)
            .unwrap();
    }));
    assert_eq!(
        f.import(row("asset-1", &[])),
        DaiImportOutcome::Updated { device: survivor }
    );
    assert_eq!(f.devices().len(), 1);
    let device = f.device(survivor);
    assert_eq!(device.operator_asset_id.as_deref(), Some("asset-1"));
    assert!(
        device
            .identifiers
            .iter()
            .all(|id| id.kind != IdentifierKind::Mac)
    );
}

#[test]
fn a_refusal_decided_before_a_concurrent_commit_is_retried() {
    let f = setup();
    f.applied(A, &Lease::ack(m(0), "10.0.0.1", 1));
    f.applied(A, &Lease::ack(m(0), "10.0.0.2", 2));
    let (first, second) = (f.owner(1), f.owner(2));
    // The row names two devices when it reads them, which a merge then
    // makes one: the refusal is not returned, and the retry attaches.
    set_before_operation_commit_hook(Box::new(move |db| {
        Dai::open(db)
            .unwrap()
            .merge_devices(CUSTOMER, first, &[second], &NOW)
            .unwrap();
    }));
    assert_eq!(
        f.import(row("asset-1", &[1, 2])),
        DaiImportOutcome::Attached { device: first }
    );
    // An operation's refusal is checked the same way: the asset id of the
    // device to merge conflicts when read, and a split moves it off before
    // the refusal commits.
    let f = setup();
    f.applied(A, &Lease::ack(m(0), "10.0.0.1", 1));
    f.applied(A, &Lease::ack(m(0), "10.0.0.2", 2));
    let (survivor, absorbed) = (f.owner(1), f.owner(2));
    f.import(row("asset-1", &[1]));
    f.import(row("asset-2", &[2]));
    set_before_operation_commit_hook(Box::new(move |db| {
        let ids = [(&asset("asset-2")).into()];
        Dai::open(db)
            .unwrap()
            .split_device(CUSTOMER, absorbed, &ids, &NOW)
            .unwrap();
    }));
    assert_eq!(f.merge(survivor, &[absorbed]).unwrap(), survivor);
    assert_eq!(f.owner(2), survivor);
    assert_eq!(
        f.device(survivor).operator_asset_id.as_deref(),
        Some("asset-1")
    );
}

#[test]
fn a_merge_racing_an_apply_at_an_address_it_moves_keeps_both() {
    let f = setup();
    f.applied(A, &long(m(0), "10.0.0.1", 1));
    let survivor = f.owner(1);
    f.applied(A, &long(m(0), "10.0.0.2", 2));
    let absorbed = f.owner(2);
    // The apply extends the absorbed device's binding at the address.
    set_before_operation_commit_hook(Box::new(|db| {
        apply_in(db, &long(m(10), "10.0.0.2", 2).body(), m(10));
    }));
    f.merge(survivor, &[absorbed]).unwrap();
    assert_eq!(f.bound_at("10.0.0.2"), [(m(0), survivor)]);
    assert_eq!(f.binding("10.0.0.2", m(0)).last_strong, m(10));
    assert!(!f.has_rows_of_device(super::super::super::DAI_DEVICE_BINDINGS, absorbed));
}

#[test]
fn a_merge_racing_an_apply_binding_the_absorbed_device_elsewhere_moves_that_binding() {
    let f = setup();
    f.applied(A, &long(m(0), "10.0.0.1", 1));
    let survivor = f.owner(1);
    f.applied(A, &long(m(0), "10.0.0.2", 2));
    f.applied(A, &long(m(30), "10.0.0.2", 2));
    let absorbed = f.owner(2);
    // A late ACK within the device's seen times binds it at a new address,
    // writing neither its identifier nor, but for the lock, its row.
    set_before_operation_commit_hook(Box::new(|db| {
        apply_in(db, &long(m(20), "10.0.0.9", 2).body(), m(20));
    }));
    f.merge(survivor, &[absorbed]).unwrap();
    assert_eq!(f.bound_at("10.0.0.9"), [(m(20), survivor)]);
    assert!(!f.has_rows_of_device(super::super::super::DAI_DEVICE_BINDINGS, absorbed));
}

#[test]
fn a_split_racing_an_apply_at_its_addresses_keeps_both() {
    let f = setup();
    f.applied(A, &long(m(0), "10.0.0.1", 1));
    let device = f.owner(1);
    f.import(row("asset-1", &[1, 2, 3]));
    for n in [2, 3] {
        let addr = if n == 2 { "10.0.0.2" } else { "10.0.0.3" };
        f.applied(A, &long(m(0), addr, n));
        f.applied(A, &long(m(30), addr, n));
    }
    // An apply extends a binding the split moves.
    set_before_operation_commit_hook(Box::new(|db| {
        apply_in(db, &long(m(40), "10.0.0.2", 2).body(), m(40));
    }));
    let second = f.split(device, &[mac_id(2)]).unwrap();
    assert_eq!(f.bound_at("10.0.0.2"), [(m(0), second)]);
    assert_eq!(f.binding("10.0.0.2", m(0)).last_strong, m(40));
    // A late ACK within the device's seen times binds a MAC the split moves
    // at a new address, writing neither its identifier nor, but for the
    // lock, its row.
    set_before_operation_commit_hook(Box::new(|db| {
        apply_in(db, &long(m(20), "10.0.0.9", 3).body(), m(20));
    }));
    let third = f.split(device, &[mac_id(3)]).unwrap();
    assert_eq!(f.bound_at("10.0.0.9"), [(m(20), third)]);
    assert_eq!(f.bound_at("10.0.0.3"), [(m(0), third)]);
    assert_eq!(f.bound_at("10.0.0.1"), [(m(0), device)]);
}

#[test]
fn a_merge_racing_an_o7_creating_a_service_of_the_absorbed_device_moves_it() {
    let f = setup();
    f.applied(A, &long(m(0), "10.0.0.1", 1));
    let survivor = f.owner(1);
    f.applied(A, &long(m(0), "10.0.0.2", 2));
    f.applied(A, &long(m(30), "10.0.0.2", 2));
    let absorbed = f.owner(2);
    // Within the device's seen times, the O7 writes only the new service
    // and, for the lock, the device's row.
    set_before_operation_commit_hook(Box::new(|db| {
        apply_in(db, &service("10.0.0.2", 443, false), m(20));
        apply_in(db, &software("10.0.0.2", "SSH-2.0-Y"), m(20));
    }));
    f.merge(survivor, &[absorbed]).unwrap();
    assert!(f.service_row(survivor, 443).is_some());
    assert_eq!(f.software_of(CUSTOMER).len(), 1);
    for family in [
        super::super::super::DAI_SERVICES,
        super::super::super::DAI_SOFTWARE_STRINGS,
    ] {
        assert!(!f.has_rows_of_device(family, absorbed));
    }
}

#[test]
fn two_operations_racing_on_one_device_keep_both_changes() {
    let f = setup();
    let device = device_of(&f.import(row("asset-1", &[1])));
    set_before_operation_commit_hook(Box::new(move |db| {
        Dai::open(db)
            .unwrap()
            .set_device_states(CUSTOMER, &[device], Some(DaiVerdict::Ignored), None, &NOW)
            .unwrap();
    }));
    f.import(DaiImportRow {
        name: Some("renamed".to_string()),
        ..row("asset-1", &[1])
    });
    let row = f.device(device);
    assert_eq!(row.verdict, Verdict::Ignored);
    assert_eq!(row.representative_name(), Some("renamed"));
    assert_eq!(row.version, 3);
    let sources: Vec<ChangeSource> = f
        .changes(device)
        .into_iter()
        .map(|(_, entry)| entry.source)
        .collect();
    assert_eq!(
        sources,
        [
            ChangeSource::Import,
            ChangeSource::Operator,
            ChangeSource::Import
        ]
    );
}

#[test]
fn a_service_removal_racing_an_o7_keeps_the_flag_and_the_version() {
    let f = setup();
    f.applied(A, &long(m(0), "10.0.0.1", 1));
    let device = f.owner(1);
    f.observed(A, &service("10.0.0.1", 22, false), m(10), m(10));
    f.observed(A, &service("10.0.0.1", 80, false), m(10), m(10));
    let version = f.device(device).version;
    // An O7 commits inside the removal...
    set_before_operation_commit_hook(Box::new(|db| {
        apply_in(db, &service("10.0.0.1", 22, true), m(20));
    }));
    f.remove_service(device, 22).unwrap();
    let row = f.service_row(device, 22).unwrap();
    assert!(row.removed && row.external_client);
    assert_eq!(row.last_seen, m(20));
    // ...and a removal inside an O7.
    set_before_apply_commit_hook(Box::new(move |db| {
        Dai::open(db)
            .unwrap()
            .remove_service(CUSTOMER, device, 80, 6)
            .unwrap();
    }));
    f.observed(A, &service("10.0.0.1", 80, false), m(30), m(30));
    let row = f.service_row(device, 80).unwrap();
    assert!(row.removed);
    assert_eq!(row.last_seen, m(30));
    assert_eq!(f.device(device).version, version);
}
