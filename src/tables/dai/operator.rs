//! The operator operations on the DAI device tables: import, merge, split,
//! state change and service removal.
//!
//! Each is one optimistic transaction per unit (a whole call, or one import
//! row), retried from the start on a commit conflict, that reads every row
//! it changes for update, including the absent keys it creates. An attempt
//! that refuses, or fails otherwise before writing anything, commits its
//! transaction too, writing nothing, so that the rows it was decided from
//! are checked like those of a change. One that moves or rewrites bindings
//! reads the `dai ip state` row of each address whose bindings it changes
//! for update before reading them, and writes it back, as every writer of
//! the bindings does. Every operation first resolves each device id it is
//! given through `dai device aliases`.
//!
//! The rows a merge or a split moves that are keyed by device (bindings'
//! reverse index rows, services, software strings) or that name a device
//! (aliases, conflicts, identifier rows) are found by untracked scans; a
//! device's fixed IPs, by the index its row keeps of them. Every writer that
//! adds such a row for a device also writes the device's row (see
//! [`Dai::lock_device`]), which the operation reads for update, so the two
//! conflict whichever commits first.

use std::{
    collections::{BTreeSet, HashSet},
    net::IpAddr,
};

use anyhow::{Context, Result};
use thiserror::Error;
use uuid::Uuid;

use super::{
    Clock, Dai, Txn,
    binding::Bindings,
    customer_key,
    device::{
        Activity, AliasReason, AliasRow, ChangeKind, ChangeSource, ConflictRow, DeviceEdits,
        DeviceRow, FixedIpRow, Identifier, IdentifierKind, IdentifierRow, Origin, SeenTimes,
        ServiceRow, Verdict, address_key, alias_key, decode_device_binding_key, decode_service_key,
        decode_software_key, device_prefix, service_key, software_key, valid_mac,
    },
};
use crate::EXCLUSIVE;

/// The most rows one [`Store::import_dai_devices`](crate::Store::import_dai_devices)
/// call takes.
pub const DAI_IMPORT_MAX_ROWS: usize = 10_000;
/// The most device ids one
/// [`Store::set_dai_device_states`](crate::Store::set_dai_device_states)
/// call takes.
pub const DAI_STATE_CHANGE_MAX_DEVICES: usize = 1_000;

/// A row of an operator device import, already parsed.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DaiImportRow {
    /// The operator asset id; required, so an empty one is an error.
    pub asset_id: String,
    /// The operator name; `None` or empty for none.
    pub name: Option<String>,
    /// The MAC addresses, each 6 bytes.
    pub macs: Vec<Vec<u8>>,
    /// The fixed IPs, each a (site token, IP).
    pub fixed_ips: Vec<(String, IpAddr)>,
    /// The memo; `None` or empty for none.
    pub memo: Option<String>,
}

/// The result of one row of an import.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DaiImportOutcome {
    /// A new device was created for the row.
    Created { device: Uuid },
    /// The device holding the row's operator asset id was updated, or was
    /// already as the row says.
    Updated { device: Uuid },
    /// The row's operator asset id was attached to the device holding its
    /// MACs.
    Attached { device: Uuid },
    /// The row was refused and wrote nothing.
    Error(DaiImportRowError),
}

/// Why a row of an import was refused.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DaiImportRowError {
    /// The operator asset id is empty.
    #[error("the operator asset id is empty")]
    EmptyAssetId,
    /// An earlier row of the same request has the operator asset id.
    #[error("operator asset id {asset_id:?} is used by an earlier row")]
    DuplicateAssetId { asset_id: String },
    /// A MAC is not exactly 6 bytes, is all `00` or all `FF`, or has the
    /// group bit of its first byte set.
    #[error("{} is not a valid MAC address", hex(.mac))]
    InvalidMac { mac: Vec<u8> },
    /// A fixed IP names a token that is not one of the customer's sites.
    #[error("no site has token {site:?}")]
    UnknownSite { site: String },
    /// The row's operator asset id and MACs name two or more devices, which
    /// have to be merged first.
    #[error("the row names devices {}; merge them first", list(.devices))]
    MergeFirst {
        /// The devices, ordered by id.
        devices: Vec<Uuid>,
    },
    /// A fixed IP of the row is fixed to another device.
    #[error("{ip} at site {site:?} is fixed to device {device}")]
    FixedIpHeld {
        site: String,
        ip: IpAddr,
        device: Uuid,
    },
    /// The row's operator asset id is new, but its MACs belong to a device
    /// that has another operator asset id.
    #[error("device {device} holding the row's MACs has operator asset id {asset_id:?}")]
    AssetIdMismatch { device: Uuid, asset_id: String },
}

/// The kind of a strong identifier of a device.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DaiIdentifierKind {
    /// A MAC address, as lowercase colon-separated hex.
    Mac,
    /// An operator asset id, as imported.
    OperatorAssetId,
    /// A machine account, as `<CNAME>@<REALM>` ASCII-uppercased.
    MachineAccount,
}

/// A strong identifier of a device: its kind and its value.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DaiIdentifier {
    /// The kind of the identifier.
    pub kind: DaiIdentifierKind,
    /// The value, in the form its kind describes.
    pub value: String,
}

impl std::fmt::Display for DaiIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} {:?}", self.kind, self.value)
    }
}

/// The operator's verdict on a device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaiVerdict {
    /// Seen by observation only.
    Observed,
    /// Confirmed by an operator.
    Confirmed,
    /// Ignored by an operator.
    Ignored,
}

/// An activity an operator can set on a device. "Not seen" is set by
/// retention only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaiActivityChange {
    /// Active; a device that is "not seen" or hidden becomes active.
    Active,
    /// Hidden; neither observation nor expiry changes it.
    Hidden,
}

/// A refusal of an operator operation on the DAI devices.
///
/// It is returned inside the `anyhow::Error` of the refusing method, so a
/// caller can `downcast_ref` it. A refused operation writes nothing.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DaiDeviceError {
    /// An import has more than [`DAI_IMPORT_MAX_ROWS`] rows.
    #[error("an import takes at most {DAI_IMPORT_MAX_ROWS} rows, not {count}")]
    TooManyImportRows { count: usize },
    /// A state change names more than [`DAI_STATE_CHANGE_MAX_DEVICES`]
    /// devices.
    #[error("a state change takes at most {DAI_STATE_CHANGE_MAX_DEVICES} devices, not {count}")]
    TooManyDevices { count: usize },
    /// The id names no device of the customer, directly or as an alias.
    #[error("no device has id {device}")]
    UnknownDevice { device: Uuid },
    /// A merge names no device to merge into the survivor.
    #[error("a merge needs at least one device to merge into the survivor")]
    NoDevicesToMerge,
    /// A device to merge is, or is an alias of, the survivor.
    #[error("device {device} is the survivor of the merge")]
    SurvivorAmongOthers { device: Uuid },
    /// Two devices of a merge carry different operator asset ids.
    #[error("the devices to merge carry different operator asset ids: {}", list_assets(.devices))]
    AssetIdConflict {
        /// Each device of the merge carrying an operator asset id, with it,
        /// ordered by device id.
        devices: Vec<(Uuid, String)>,
    },
    /// A split chooses no identifier.
    #[error("a split needs at least one identifier to move")]
    EmptySplit,
    /// A chosen identifier is not on the device.
    #[error("identifier {identifier} is not on the device")]
    IdentifierNotOnDevice { identifier: DaiIdentifier },
    /// A split chooses every identifier of the device.
    #[error("a split cannot move every identifier of the device")]
    SplitAllIdentifiers,
    /// The device has no service of the port and protocol.
    #[error("device {device} has no service on port {port} of protocol {protocol}")]
    UnknownService {
        device: Uuid,
        port: u16,
        protocol: u8,
    },
}

/// Lists `devices` for an error message.
fn list(devices: &[Uuid]) -> String {
    devices
        .iter()
        .map(Uuid::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Lists `devices` with their asset ids for an error message.
fn list_assets(devices: &[(Uuid, String)]) -> String {
    devices
        .iter()
        .map(|(device, asset)| format!("{device} ({asset:?})"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Returns `bytes` as hex for an error message.
fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

impl From<DaiIdentifierKind> for IdentifierKind {
    fn from(kind: DaiIdentifierKind) -> Self {
        match kind {
            DaiIdentifierKind::Mac => Self::Mac,
            DaiIdentifierKind::OperatorAssetId => Self::OperatorAssetId,
            DaiIdentifierKind::MachineAccount => Self::MachineAccount,
        }
    }
}

impl From<IdentifierKind> for DaiIdentifierKind {
    fn from(kind: IdentifierKind) -> Self {
        match kind {
            IdentifierKind::Mac => Self::Mac,
            IdentifierKind::OperatorAssetId => Self::OperatorAssetId,
            IdentifierKind::MachineAccount => Self::MachineAccount,
        }
    }
}

impl From<&DaiIdentifier> for Identifier {
    fn from(id: &DaiIdentifier) -> Self {
        Self {
            kind: id.kind.into(),
            value: id.value.clone(),
        }
    }
}

impl From<&Identifier> for DaiIdentifier {
    fn from(id: &Identifier) -> Self {
        Self {
            kind: id.kind.into(),
            value: id.value.clone(),
        }
    }
}

impl From<DaiVerdict> for Verdict {
    fn from(verdict: DaiVerdict) -> Self {
        match verdict {
            DaiVerdict::Observed => Self::Observed,
            DaiVerdict::Confirmed => Self::Confirmed,
            DaiVerdict::Ignored => Self::Ignored,
        }
    }
}

impl From<DaiActivityChange> for Activity {
    fn from(activity: DaiActivityChange) -> Self {
        match activity {
            DaiActivityChange::Active => Self::Active,
            DaiActivityChange::Hidden => Self::Hidden,
        }
    }
}

#[cfg(test)]
thread_local! {
    /// A hook the tests run once, in the thread that set it, right before
    /// the next operator operation (or import row) in that thread commits,
    /// whether it refuses or not.
    static BEFORE_OPERATION_COMMIT: std::cell::RefCell<Option<super::TestHook>> =
        const { std::cell::RefCell::new(None) };
    /// A hook the tests run once, in the thread that set it, in the next
    /// import row in that thread, right after it reads the identifier row of
    /// its operator asset id and before it reads those of its MACs.
    static IMPORT_ASSET_READ: std::cell::RefCell<Option<super::TestHook>> =
        const { std::cell::RefCell::new(None) };
}

/// Sets the hook the next import row in this thread runs between its reads
/// of the identifier rows of its asset id and of its MACs.
#[cfg(test)]
pub(super) fn set_import_asset_read_hook(hook: super::TestHook) {
    IMPORT_ASSET_READ.with(|cell| *cell.borrow_mut() = Some(hook));
}

/// Sets the hook the next operator operation in this thread runs before it
/// commits.
#[cfg(test)]
pub(super) fn set_before_operation_commit_hook(hook: super::TestHook) {
    BEFORE_OPERATION_COMMIT.with(|cell| *cell.borrow_mut() = Some(hook));
}

/// Runs, and clears, the before-operation-commit hook set in this thread,
/// if any.
#[cfg(test)]
fn run_before_operation_commit_hook(db: &rocksdb::OptimisticTransactionDB) {
    if let Some(hook) = BEFORE_OPERATION_COMMIT.with(|cell| cell.borrow_mut().take()) {
        hook(db);
    }
}

/// An import row that passed the checks that read nothing: its asset id
/// non-empty and new in the request, its MACs valid, duplicates collapsed.
struct CheckedRow<'r> {
    asset_id: &'r str,
    /// `None` for no name.
    name: Option<&'r str>,
    /// The MACs, in row order.
    macs: Vec<String>,
    fixed_ips: BTreeSet<(String, IpAddr)>,
    memo: &'r str,
}

/// Checks what of `row` reads nothing, given the asset ids of the earlier
/// rows of the request.
fn check_row<'r>(
    row: &'r DaiImportRow,
    earlier: &HashSet<&str>,
) -> Result<CheckedRow<'r>, DaiImportRowError> {
    if row.asset_id.is_empty() {
        return Err(DaiImportRowError::EmptyAssetId);
    }
    if earlier.contains(row.asset_id.as_str()) {
        return Err(DaiImportRowError::DuplicateAssetId {
            asset_id: row.asset_id.clone(),
        });
    }
    let mut macs = Vec::with_capacity(row.macs.len());
    for chaddr in &row.macs {
        let Some(mac) = valid_mac(chaddr) else {
            return Err(DaiImportRowError::InvalidMac {
                mac: chaddr.clone(),
            });
        };
        if !macs.contains(&mac) {
            macs.push(mac);
        }
    }
    Ok(CheckedRow {
        asset_id: &row.asset_id,
        name: row.name.as_deref().filter(|name| !name.is_empty()),
        macs,
        fixed_ips: row.fixed_ips.iter().cloned().collect(),
        memo: row.memo.as_deref().unwrap_or_default(),
    })
}

/// Returns whether `row` names a device of `devices`, as its holder or an
/// earlier owner.
fn names_any(row: &IdentifierRow, devices: &BTreeSet<Uuid>) -> bool {
    row.device.is_some_and(|device| devices.contains(&device))
        || row
            .earlier_owners
            .iter()
            .any(|owner| devices.contains(&owner.device))
}

impl Dai<'_> {
    /// Runs `attempt` in an optimistic transaction and commits it, retrying
    /// from the start on a commit conflict, as [`Dai::write`] does, except
    /// that an attempt failing before it writes anything commits too.
    ///
    /// Such a failure (a refusal, a [`DaiDeviceError`] or an import row's
    /// error, or an error such as a device row missing that the rows read
    /// before it named) is decided from rows the attempt read for update,
    /// and the store's transactions take no snapshot: rows read before and
    /// after a concurrent commit can together support a failure that no
    /// single state does. Committing the attempt writes nothing but checks
    /// every row it read, so a conflict retries it against the new state,
    /// and only a failure every row read still supports is returned. A
    /// refusal is always decided before anything is written.
    fn write_operation<T>(&self, mut attempt: impl FnMut(&Txn<'_>) -> Result<T>) -> Result<T> {
        loop {
            let txn = self.db.transaction();
            let result = attempt(&txn);
            if let Err(error) = &result
                && !txn.get_writebatch().is_empty()
            {
                debug_assert!(
                    error.downcast_ref::<DaiDeviceError>().is_none(),
                    "an operation writes nothing before it refuses"
                );
                return result;
            }
            #[cfg(test)]
            run_before_operation_commit_hook(self.db);
            match txn.commit() {
                Ok(()) => return result,
                Err(e)
                    if matches!(
                        e.kind(),
                        rocksdb::ErrorKind::Busy | rocksdb::ErrorKind::TryAgain
                    ) => {}
                Err(e) => {
                    return result.and(Err(e).context("failed to commit DAI changes"));
                }
            }
        }
    }

    /// Imports `rows` for the customer, each at the time `clock` gives in its
    /// transaction, as
    /// [`Store::import_dai_devices`](crate::Store::import_dai_devices)
    /// describes.
    pub(crate) fn import_devices(
        &self,
        customer: u32,
        rows: &[DaiImportRow],
        clock: &dyn Clock,
    ) -> Result<Vec<DaiImportOutcome>> {
        if rows.len() > DAI_IMPORT_MAX_ROWS {
            return Err(DaiDeviceError::TooManyImportRows { count: rows.len() }.into());
        }
        let mut earlier: HashSet<&str> = HashSet::new();
        let mut outcomes = Vec::with_capacity(rows.len());
        for row in rows {
            let checked = check_row(row, &earlier);
            if !row.asset_id.is_empty() {
                earlier.insert(&row.asset_id);
            }
            let outcome = match checked {
                Err(error) => DaiImportOutcome::Error(error),
                Ok(checked) => self
                    .write_operation(|txn| {
                        let now = clock.now()?;
                        self.import_row(txn, customer, &checked, now)
                    })?
                    .unwrap_or_else(DaiImportOutcome::Error),
            };
            outcomes.push(outcome);
        }
        Ok(outcomes)
    }

    /// Applies one checked import row within `txn` at `now`, or returns the
    /// reason it is refused, having written nothing then.
    #[allow(clippy::too_many_lines)] // One row's rules, in the order they apply.
    fn import_row(
        &self,
        txn: &Txn<'_>,
        customer: u32,
        row: &CheckedRow<'_>,
        now: i64,
    ) -> Result<Result<DaiImportOutcome, DaiImportRowError>> {
        // A site write racing the import conflicts with it.
        txn.get_for_update_cf(self.guard.cf, customer_key(customer), EXCLUSIVE)
            .map_err(anyhow::Error::from)?;
        let sites = self.sites_in(txn, customer)?;
        for (site, _) in &row.fixed_ips {
            if !sites.iter().any(|known| known.token == *site) {
                return Ok(Err(DaiImportRowError::UnknownSite { site: site.clone() }));
            }
        }

        let asset = Identifier {
            kind: IdentifierKind::OperatorAssetId,
            value: row.asset_id.to_string(),
        };
        let asset_row = self.identifier_in(txn, customer, &asset)?;
        let asset_holder = asset_row.as_ref().and_then(|stored| stored.device);
        #[cfg(test)]
        if let Some(hook) = IMPORT_ASSET_READ.with(|cell| cell.borrow_mut().take()) {
            hook(self.db);
        }
        let mut mac_rows = Vec::with_capacity(row.macs.len());
        for mac in &row.macs {
            let id = Identifier::mac(mac);
            let stored = self.identifier_in(txn, customer, &id)?;
            mac_rows.push((id, stored));
        }
        let named: BTreeSet<Uuid> = asset_holder
            .into_iter()
            .chain(
                mac_rows
                    .iter()
                    .filter_map(|(_, stored)| stored.as_ref()?.device),
            )
            .collect();
        if named.len() > 1 {
            return Ok(Err(DaiImportRowError::MergeFirst {
                devices: named.into_iter().collect(),
            }));
        }

        let mut edits = DeviceEdits::default();
        let (device, outcome): (Uuid, fn(Uuid) -> DaiImportOutcome) =
            if let Some(device) = asset_holder {
                (device, |device| DaiImportOutcome::Updated { device })
            } else if let Some(&device) = named.first() {
                let edit = edits.existing(self, txn, customer, device)?;
                if let Some(other) = &edit.row.operator_asset_id {
                    return Ok(Err(DaiImportRowError::AssetIdMismatch {
                        device,
                        asset_id: other.clone(),
                    }));
                }
                (device, |device| DaiImportOutcome::Attached { device })
            } else {
                let device = edits.new_id(self, txn, customer)?;
                edits.insert(
                    device,
                    DeviceRow {
                        identifiers: Vec::new(),
                        names: Vec::new(),
                        was_dhcp_server: false,
                        first_seen: None,
                        last_seen: None,
                        created: now,
                        verdict: Verdict::Observed,
                        activity: Activity::Active,
                        origin: Origin::Import,
                        operator_asset_id: None,
                        memo: String::new(),
                        fixed_ips: BTreeSet::new(),
                        version: 0,
                    },
                    true,
                );
                (device, |device| DaiImportOutcome::Created { device })
            };

        // The device's fixed IPs, and the row's, none fixed to another one.
        let held_fixed = edits
            .existing(self, txn, customer, device)?
            .row
            .fixed_ips
            .clone();
        for (site, ip) in &held_fixed {
            Self::get_row::<FixedIpRow>(txn, &self.fixed_ips, &address_key(customer, site, *ip))?;
        }
        for (site, ip) in &row.fixed_ips {
            let key = address_key(customer, site, *ip);
            if let Some(holder) = Self::get_row::<FixedIpRow>(txn, &self.fixed_ips, &key)?
                && holder != device
            {
                return Ok(Err(DaiImportRowError::FixedIpHeld {
                    site: site.clone(),
                    ip: *ip,
                    device: holder,
                }));
            }
        }

        let edit = edits.existing(self, txn, customer, device)?;
        edit.add_identifier(&asset);
        edit.set_asset_id(Some(row.asset_id));
        if asset_holder != Some(device) {
            let earlier_owners = asset_row.map(|stored| stored.earlier_owners);
            self.put_identifier(
                txn,
                customer,
                &asset,
                &IdentifierRow {
                    device: Some(device),
                    last_confirmed: now,
                    earlier_owners: earlier_owners.unwrap_or_default(),
                },
            )?;
        }
        for (id, stored) in mac_rows {
            edit.add_identifier(&id);
            if stored.as_ref().and_then(|stored| stored.device) == Some(device) {
                continue;
            }
            // A MAC no device holds keeps its history; the device holds it
            // from the time it was removed from its last holder on.
            let mut taken = stored.unwrap_or(IdentifierRow {
                device: None,
                last_confirmed: now,
                earlier_owners: Vec::new(),
            });
            taken.device = Some(device);
            taken.last_confirmed = now;
            self.put_identifier(txn, customer, &id, &taken)?;
        }
        let removed: Vec<Identifier> = edit
            .row
            .identifiers
            .iter()
            .filter(|id| id.kind == IdentifierKind::Mac && !row.macs.contains(&id.value))
            .cloned()
            .collect();
        for id in removed {
            edit.remove_identifier(&id);
            if let Some(mut stored) = self.identifier_in(txn, customer, &id)?
                && stored.device == Some(device)
            {
                stored.release(now);
                self.put_identifier(txn, customer, &id, &stored)?;
            }
        }
        edit.set_operator_name(row.name, now);
        edit.set_memo(row.memo);

        for (site, ip) in held_fixed.difference(&row.fixed_ips) {
            Self::delete_row(txn, &self.fixed_ips, &address_key(customer, site, *ip))?;
        }
        for (site, ip) in row.fixed_ips.difference(&held_fixed) {
            Self::put_row(
                txn,
                &self.fixed_ips,
                &address_key(customer, site, *ip),
                &device,
            )?;
        }
        edit.set_fixed_ips(row.fixed_ips.clone());
        edits.flush(self, txn, customer, ChangeSource::Import, now)?;
        Ok(Ok(outcome(device)))
    }

    /// Merges `others` into `survivor` at the time `clock` gives, as
    /// [`Store::merge_dai_devices`](crate::Store::merge_dai_devices)
    /// describes, and returns the survivor's current id.
    pub(crate) fn merge_devices(
        &self,
        customer: u32,
        survivor: Uuid,
        others: &[Uuid],
        clock: &dyn Clock,
    ) -> Result<Uuid> {
        if others.is_empty() {
            return Err(DaiDeviceError::NoDevicesToMerge.into());
        }
        self.write_operation(|txn| {
            let now = clock.now()?;
            self.merge_attempt(txn, customer, survivor, others, now)
        })
    }

    /// Runs one attempt of [`merge_devices`](Self::merge_devices) within
    /// `txn` at `now`.
    #[allow(clippy::too_many_lines)] // Every table a merge moves, in turn.
    fn merge_attempt(
        &self,
        txn: &Txn<'_>,
        customer: u32,
        survivor: Uuid,
        others: &[Uuid],
        now: i64,
    ) -> Result<Uuid> {
        let survivor = self
            .resolve_device(txn, customer, survivor)?
            .ok_or(DaiDeviceError::UnknownDevice { device: survivor })?;
        let mut absorbed: Vec<Uuid> = Vec::with_capacity(others.len());
        for &other in others {
            let device = self
                .resolve_device(txn, customer, other)?
                .ok_or(DaiDeviceError::UnknownDevice { device: other })?;
            if device == survivor {
                return Err(DaiDeviceError::SurvivorAmongOthers { device: other }.into());
            }
            if !absorbed.contains(&device) {
                absorbed.push(device);
            }
        }
        let Some(&first_absorbed) = absorbed.first() else {
            return Err(DaiDeviceError::NoDevicesToMerge.into());
        };
        let absorbed_set: BTreeSet<Uuid> = absorbed.iter().copied().collect();

        let mut edits = DeviceEdits::default();
        let mut rows = Vec::with_capacity(absorbed.len());
        for &device in &absorbed {
            rows.push(edits.existing(self, txn, customer, device)?.row.clone());
        }
        let mut assets: Vec<(Uuid, String)> = Vec::new();
        if let Some(asset) = &edits
            .existing(self, txn, customer, survivor)?
            .row
            .operator_asset_id
        {
            assets.push((survivor, asset.clone()));
        }
        for (device, row) in absorbed.iter().zip(&rows) {
            if let Some(asset) = &row.operator_asset_id {
                assets.push((*device, asset.clone()));
            }
        }
        if assets
            .first()
            .is_some_and(|(_, first)| assets.iter().any(|(_, asset)| asset != first))
        {
            assets.sort_unstable();
            return Err(DaiDeviceError::AssetIdConflict { devices: assets }.into());
        }

        // The device rows.
        let edit = edits.existing(self, txn, customer, survivor)?;
        for row in &rows {
            for id in &row.identifiers {
                edit.add_identifier(id);
            }
            for name in &row.names {
                edit.add_name(&name.value, name.source, name.last_seen);
            }
            if row.was_dhcp_server {
                edit.set_dhcp_server();
            }
            edit.widen_seen(row.first_seen, row.last_seen);
            if edit.row.operator_asset_id.is_none()
                && let Some(asset) = &row.operator_asset_id
            {
                edit.set_asset_id(Some(asset));
            }
            if edit.row.memo.is_empty() && !row.memo.is_empty() {
                edit.set_memo(&row.memo);
            }
            let fixed_ips = edit.row.fixed_ips.union(&row.fixed_ips).cloned().collect();
            edit.set_fixed_ips(fixed_ips);
        }
        edit.mark(ChangeKind::Merged, first_absorbed);
        for &device in &absorbed {
            let edit = edits.existing(self, txn, customer, device)?;
            edit.mark(ChangeKind::Merged, survivor);
            edit.delete();
        }

        let prefix = customer_key(customer);
        // The identifiers and the ownership history.
        for (key, value) in Self::scan(&self.identifiers, txn, &prefix)? {
            if !names_any(&super::super::deserialize(&value)?, &absorbed_set) {
                continue;
            }
            if let Some(mut row) = Self::get_row::<IdentifierRow>(txn, &self.identifiers, &key)?
                && row.rename(&absorbed_set, survivor)
            {
                Self::put_row(txn, &self.identifiers, &key, &row)?;
            }
        }

        // The bindings, address by address. Once the absorbed devices'
        // identifiers name the survivor, an ACK of one of them may extend a
        // binding of the survivor or of another absorbed device instead of
        // starting its own, and an O4 of a moved machine account may extend
        // a binding of the survivor at an address no absorbed device was
        // bound at, where it only recorded a conflict before. So the
        // bindings of each address any merged device is bound at are
        // derived again from the earliest one of any merged device on, by
        // the ownership just written: a later recomputation then reproduces
        // them.
        let mut reverse = Vec::new();
        let mut addresses = BTreeSet::new();
        for (key, _) in Self::scan(
            &self.device_bindings,
            txn,
            &device_prefix(customer, survivor),
        )? {
            let (_, _, site, ip, _) = decode_device_binding_key(&key)?;
            addresses.insert((site, ip));
        }
        for &device in &absorbed {
            for (key, _) in
                Self::scan(&self.device_bindings, txn, &device_prefix(customer, device))?
            {
                let (_, _, site, ip, _) = decode_device_binding_key(&key)?;
                addresses.insert((site, ip));
                reverse.push(key);
            }
        }
        for (site, ip) in &addresses {
            let lock = self.lock_ip_state(txn, customer, site, *ip)?;
            let stored = self.bindings_in(txn, customer, site, *ip)?;
            let Some(replay_from) = stored
                .iter()
                .find(|(_, row)| row.device == survivor || absorbed_set.contains(&row.device))
                .map(|(start, _)| *start)
            else {
                continue;
            };
            let mut current = Bindings(stored.clone());
            for row in current.0.values_mut() {
                if absorbed_set.contains(&row.device) {
                    row.device = survivor;
                }
            }
            self.replay_bindings(txn, customer, (site, *ip), &mut current, replay_from, now)?;
            if self.write_bindings(txn, customer, site, *ip, &stored, &current.0)? {
                self.write_ip_state(txn, &lock)?;
            }
        }
        // Reverse index rows no binding backs go with their device.
        for key in reverse {
            Self::delete_row(txn, &self.device_bindings, &key)?;
        }

        // The services and software strings.
        for &device in &absorbed {
            for (key, _) in Self::scan(&self.services, txn, &device_prefix(customer, device))? {
                let Some(moved) = Self::get_row::<ServiceRow>(txn, &self.services, &key)? else {
                    continue;
                };
                let (_, port, proto) = decode_service_key(&key)?;
                let target = service_key(customer, survivor, port, proto);
                let row = match Self::get_row::<ServiceRow>(txn, &self.services, &target)? {
                    Some(kept) => ServiceRow {
                        external_client: kept.external_client || moved.external_client,
                        first_seen: kept.first_seen.min(moved.first_seen),
                        last_seen: kept.last_seen.max(moved.last_seen),
                        removed: kept.removed && moved.removed,
                    },
                    None => moved,
                };
                Self::put_row(txn, &self.services, &target, &row)?;
                Self::delete_row(txn, &self.services, &key)?;
            }
            for (key, _) in Self::scan(&self.software, txn, &device_prefix(customer, device))? {
                let Some(moved) = Self::get_row::<SeenTimes>(txn, &self.software, &key)? else {
                    continue;
                };
                let (_, side, source, text) = decode_software_key(&key)?;
                let target = software_key(customer, survivor, side, source, &text);
                let row = match Self::get_row::<SeenTimes>(txn, &self.software, &target)? {
                    Some(kept) => SeenTimes {
                        first_seen: kept.first_seen.min(moved.first_seen),
                        last_seen: kept.last_seen.max(moved.last_seen),
                    },
                    None => moved,
                };
                Self::put_row(txn, &self.software, &target, &row)?;
                Self::delete_row(txn, &self.software, &key)?;
            }
        }

        // The rows naming an absorbed device.
        for row in &rows {
            for (site, ip) in &row.fixed_ips {
                let key = address_key(customer, site, *ip);
                Self::get_row::<FixedIpRow>(txn, &self.fixed_ips, &key)?;
                Self::put_row(txn, &self.fixed_ips, &key, &survivor)?;
            }
        }
        for (key, value) in Self::scan(&self.aliases, txn, &prefix)? {
            if !absorbed_set.contains(&super::super::deserialize::<AliasRow>(&value)?.current) {
                continue;
            }
            if let Some(mut alias) = Self::get_row::<AliasRow>(txn, &self.aliases, &key)?
                && absorbed_set.contains(&alias.current)
            {
                alias.current = survivor;
                Self::put_row(txn, &self.aliases, &key, &alias)?;
            }
        }
        for &device in &absorbed {
            let key = alias_key(customer, device);
            Self::get_row::<AliasRow>(txn, &self.aliases, &key)?;
            let alias = AliasRow {
                current: survivor,
                time: now,
                reason: AliasReason::Merged,
            };
            Self::put_row(txn, &self.aliases, &key, &alias)?;
        }
        for (key, value) in Self::scan(&self.conflicts, txn, &prefix)? {
            let named = |row: &ConflictRow| row.devices.iter().any(|d| absorbed_set.contains(d));
            if !named(&super::super::deserialize(&value)?) {
                continue;
            }
            if let Some(mut row) = Self::get_row::<ConflictRow>(txn, &self.conflicts, &key)?
                && named(&row)
            {
                row.devices.retain(|device| !absorbed_set.contains(device));
                row.devices.insert(survivor);
                Self::put_row(txn, &self.conflicts, &key, &row)?;
            }
        }

        edits.flush(self, txn, customer, ChangeSource::Operator, now)?;
        Ok(survivor)
    }

    /// Moves `identifiers` of `device` to a new device at the time `clock`
    /// gives, as [`Store::split_dai_device`](crate::Store::split_dai_device)
    /// describes, and returns the new device's id.
    pub(crate) fn split_device(
        &self,
        customer: u32,
        device: Uuid,
        identifiers: &[DaiIdentifier],
        clock: &dyn Clock,
    ) -> Result<Uuid> {
        let mut chosen: Vec<Identifier> = Vec::with_capacity(identifiers.len());
        for id in identifiers {
            let id = Identifier::from(id);
            if !chosen.contains(&id) {
                chosen.push(id);
            }
        }
        if chosen.is_empty() {
            return Err(DaiDeviceError::EmptySplit.into());
        }
        self.write_operation(|txn| {
            let now = clock.now()?;
            self.split_attempt(txn, customer, device, &chosen, now)
        })
    }

    /// Runs one attempt of [`split_device`](Self::split_device) within `txn`
    /// at `now`.
    #[allow(clippy::too_many_lines)] // Every table a split moves, in turn.
    fn split_attempt(
        &self,
        txn: &Txn<'_>,
        customer: u32,
        device: Uuid,
        chosen: &[Identifier],
        now: i64,
    ) -> Result<Uuid> {
        let original = self
            .resolve_device(txn, customer, device)?
            .ok_or(DaiDeviceError::UnknownDevice { device })?;
        let mut edits = DeviceEdits::default();
        let held = edits
            .existing(self, txn, customer, original)?
            .row
            .identifiers
            .clone();
        if let Some(id) = chosen.iter().find(|id| !held.contains(id)) {
            return Err(DaiDeviceError::IdentifierNotOnDevice {
                identifier: id.into(),
            }
            .into());
        }
        if held.iter().all(|id| chosen.contains(id)) {
            return Err(DaiDeviceError::SplitAllIdentifiers.into());
        }
        let asset = chosen
            .iter()
            .find(|id| id.kind == IdentifierKind::OperatorAssetId)
            .map(|id| id.value.clone());
        let new = edits.new_id(self, txn, customer)?;

        // The moved identifiers belonged to the new device whenever they
        // belonged to the original one.
        let from = BTreeSet::from([original]);
        for id in chosen {
            if let Some(mut row) = self.identifier_in(txn, customer, id)?
                && row.rename(&from, new)
            {
                self.put_identifier(txn, customer, id, &row)?;
            }
        }

        // The bindings whose evidence identifier moves, address by address.
        // A binding one identifier started may have been extended by
        // another of the same device, so the bindings of each address the
        // original device holds are derived again from its earliest one on,
        // by the ownership just written: a later recomputation then
        // reproduces them.
        let mut addresses = BTreeSet::new();
        for (key, _) in Self::scan(
            &self.device_bindings,
            txn,
            &device_prefix(customer, original),
        )? {
            let (_, _, site, ip, _) = decode_device_binding_key(&key)?;
            addresses.insert((site, ip));
        }
        let mut seen: Option<(i64, i64)> = None;
        for (site, ip) in &addresses {
            let lock = self.lock_ip_state(txn, customer, site, *ip)?;
            let stored = self.bindings_in(txn, customer, site, *ip)?;
            let Some(replay_from) = stored
                .iter()
                .find(|(_, row)| row.device == original)
                .map(|(start, _)| *start)
            else {
                continue;
            };
            let mut current = Bindings(stored.clone());
            for row in current.0.values_mut() {
                if row.device == original && chosen.contains(&row.evidence_identifier) {
                    row.device = new;
                }
            }
            self.replay_bindings(txn, customer, (site, *ip), &mut current, replay_from, now)?;
            for (start, row) in current.0.iter().filter(|(_, row)| row.device == new) {
                seen = Some(seen.map_or((*start, row.last_strong), |(first, last)| {
                    (first.min(*start), last.max(row.last_strong))
                }));
            }
            if self.write_bindings(txn, customer, site, *ip, &stored, &current.0)? {
                self.write_ip_state(txn, &lock)?;
            }
        }

        let (first_seen, last_seen) = seen.unwrap_or((now, now));
        let edit = edits.insert(
            new,
            DeviceRow {
                identifiers: Vec::new(),
                names: Vec::new(),
                was_dhcp_server: false,
                first_seen: Some(first_seen),
                last_seen: Some(last_seen),
                created: now,
                verdict: Verdict::Observed,
                activity: Activity::Active,
                origin: if asset.is_some() {
                    Origin::Import
                } else {
                    Origin::Observation
                },
                operator_asset_id: None,
                memo: String::new(),
                fixed_ips: BTreeSet::new(),
                version: 0,
            },
            false,
        );
        for id in held.iter().filter(|id| chosen.contains(id)) {
            edit.add_identifier(id);
        }
        if let Some(asset) = &asset {
            edit.set_asset_id(Some(asset));
        }
        edit.mark(ChangeKind::Split, original);
        let edit = edits.existing(self, txn, customer, original)?;
        for id in chosen {
            edit.remove_identifier(id);
        }
        if asset.is_some() {
            edit.set_asset_id(None);
        }
        edit.mark(ChangeKind::Split, new);

        edits.flush(self, txn, customer, ChangeSource::Operator, now)?;
        Ok(new)
    }

    /// Sets the verdict and the activity of `devices` at the time `clock`
    /// gives, as
    /// [`Store::set_dai_device_states`](crate::Store::set_dai_device_states)
    /// describes.
    pub(crate) fn set_device_states(
        &self,
        customer: u32,
        devices: &[Uuid],
        verdict: Option<DaiVerdict>,
        activity: Option<DaiActivityChange>,
        clock: &dyn Clock,
    ) -> Result<()> {
        if devices.len() > DAI_STATE_CHANGE_MAX_DEVICES {
            return Err(DaiDeviceError::TooManyDevices {
                count: devices.len(),
            }
            .into());
        }
        self.write_operation(|txn| {
            let now = clock.now()?;
            let mut edits = DeviceEdits::default();
            for &given in devices {
                let device = self
                    .resolve_device(txn, customer, given)?
                    .ok_or(DaiDeviceError::UnknownDevice { device: given })?;
                let edit = edits.existing(self, txn, customer, device)?;
                if let Some(verdict) = verdict {
                    edit.set_verdict(verdict.into());
                }
                if let Some(activity) = activity {
                    edit.set_activity(activity.into());
                }
            }
            edits.flush(self, txn, customer, ChangeSource::Operator, now)?;
            Ok(())
        })
    }

    /// Sets the operator-removed flag of the service on `port` of `protocol`
    /// of `device`, as
    /// [`Store::remove_dai_service`](crate::Store::remove_dai_service)
    /// describes.
    pub(crate) fn remove_service(
        &self,
        customer: u32,
        device: Uuid,
        port: u16,
        protocol: u8,
    ) -> Result<()> {
        self.write_operation(|txn| {
            let current = self
                .resolve_device(txn, customer, device)?
                .ok_or(DaiDeviceError::UnknownDevice { device })?;
            let key = service_key(customer, current, port, protocol);
            let Some(mut row) = Self::get_row::<ServiceRow>(txn, &self.services, &key)? else {
                return Err(DaiDeviceError::UnknownService {
                    device,
                    port,
                    protocol,
                }
                .into());
            };
            if !row.removed {
                row.removed = true;
                Self::put_row(txn, &self.services, &key, &row)?;
            }
            Ok(())
        })
    }
}
