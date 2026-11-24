//! Slot application: turning a sensor's queued (`dai pending`) observations
//! into devices, bindings and device attributes.
//!
//! One call takes up to `max_count` pending rows of one (sensor, slot) in
//! apply order, applies them by the rules of
//! [`Store::apply_dai_slot`](crate::Store::apply_dai_slot), deletes them,
//! recomputes the earliest pending slot of every (sensor, kind) it took rows
//! of, and sets the sensor's resolver point, all in one optimistic
//! transaction retried from the start on a commit conflict.
//!
//! The rules read only the pending row (body, first seen, last seen), never
//! `dai observations` or the summaries.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::IpAddr,
};

use anyhow::{Result, bail};
use review_protocol::types::{
    DaiDhcpMsg, DaiObservationBody, DaiObservationKind, DaiSide, DaiSoftwareSource,
};
use uuid::Uuid;

use super::{
    Assignment, Dai, DaiSettings, FIVE_MINUTES, KINDS, KeyWriter, Txn,
    binding::{Bindings, NewBinding},
    cursor::{decode_pair_key, pair_key},
    customer_key,
    device::{
        BindingRow, ChangeSource, DeviceEdits, EarlierOwner, EvidenceRow, Identifier,
        IdentifierKind, IdentifierRow, IpStateLock, NameSource, OrderKey, SeenTimes, ServiceRow,
        address_key, decode_evidence_key, evidence_key, is_binding_evidence, machine_account,
        resolver_point_key, secs_to_nanos, service_key, software_key, valid_mac,
    },
    kind_number,
    observation::{DaiCounterKind, IdHash, SeenRow, decode_pending_key, merge_body},
};
use crate::EXCLUSIVE;

/// The default number of pending rows one
/// [`Store::apply_dai_slot`](crate::Store::apply_dai_slot) call applies.
pub const DAI_APPLY_DEFAULT_MAX_COUNT: usize = 500;
/// The Kerberos message type of an AS-REP.
const KRB_AS_REP: u8 = 11;
/// The Kerberos pre-authentication type of an encrypted timestamp.
const KRB_PREAUTH_ENC_TIMESTAMP: u8 = 2;

/// A sensor with pending observations and its earliest pending slot start,
/// any kind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiPendingHead {
    /// The sensor name.
    pub sensor: String,
    /// The earliest slot start among the sensor's pending observations, in
    /// nanoseconds since the UNIX epoch.
    pub slot_start: i64,
}

#[cfg(test)]
thread_local! {
    /// A hook the tests run once, in the thread that set it, right before
    /// the next slot application in that thread commits.
    static BEFORE_APPLY_COMMIT: std::cell::RefCell<Option<super::TestHook>> =
        const { std::cell::RefCell::new(None) };
    /// A hook the tests run once, in the thread that set it, in the next
    /// slot application in that thread, right after its scan of the slot's
    /// pending rows.
    static APPLY_SCANNED: std::cell::RefCell<Option<super::TestHook>> =
        const { std::cell::RefCell::new(None) };
}

/// Sets the hook the next slot application in this thread runs before it
/// commits.
#[cfg(test)]
pub(super) fn set_before_apply_commit_hook(hook: super::TestHook) {
    BEFORE_APPLY_COMMIT.with(|cell| *cell.borrow_mut() = Some(hook));
}

/// Sets the hook the next slot application in this thread runs after its
/// scan of the slot's pending rows.
#[cfg(test)]
pub(super) fn set_apply_scanned_hook(hook: super::TestHook) {
    APPLY_SCANNED.with(|cell| *cell.borrow_mut() = Some(hook));
}

/// Returns the byte a `dai software strings` key holds for `side`.
fn side_number(side: DaiSide) -> u8 {
    match side {
        DaiSide::Client => 0,
        DaiSide::Server => 1,
    }
}

/// Returns the byte a `dai software strings` key holds for `source`.
fn software_source_number(source: DaiSoftwareSource) -> u8 {
    match source {
        DaiSoftwareSource::Ssh => 0,
        DaiSoftwareSource::HttpUserAgent => 1,
        DaiSoftwareSource::TlsCertSubject => 2,
    }
}

/// Returns the machine account of `body` if it is a verified O4 under
/// `settings`: an AS-REP, accepted, of pre-authentication type 2, whose
/// realm is, ignoring ASCII case, one of the customer's confirmed realms and
/// whose `cname` is one component of at least two characters ending in `$`.
fn verified_machine_account(body: &DaiObservationBody, settings: &DaiSettings) -> Option<String> {
    let DaiObservationBody::Kerberos {
        realm,
        msg_type,
        accepted,
        preauth,
        ..
    } = body
    else {
        return None;
    };
    if *msg_type != KRB_AS_REP || !*accepted || *preauth != KRB_PREAUTH_ENC_TIMESTAMP {
        return None;
    }
    if !settings
        .kerberos_preauth_realms
        .iter()
        .any(|confirmed| confirmed.eq_ignore_ascii_case(realm))
    {
        return None;
    }
    machine_account(body)
}

/// The site an observation is applied at.
enum SiteOf {
    Site(String),
    /// A relayed O1 of a multi-site customer whose relay site table has no
    /// entry for it.
    RelayUnknown,
    /// The customer has no default site.
    None,
}

/// An address an application reads or writes: its IP state, read for
/// update, and its bindings as stored and as the application leaves them.
struct Address {
    lock: IpStateLock,
    stored: BTreeMap<i64, BindingRow>,
    bindings: Bindings,
    /// Whether the application wrote an evidence row of the address.
    written: bool,
}

/// The addresses one application touched, keyed by (site, IP).
#[derive(Default)]
struct Addresses(HashMap<(String, IpAddr), Address>);

/// How a verified O4 is applied.
#[derive(Clone, Copy, Eq, PartialEq)]
enum O4Mode {
    /// Replayed by a recomputation: it moves the binding's last strong
    /// evidence time unless its machine account belongs to another device
    /// (as applying it in order would, attaching an unowned account first),
    /// and writes nothing else.
    Replay,
    /// Applied: it attaches its machine account, records a conflict and
    /// confirms; `extend` tells whether it also moves the binding's last
    /// strong evidence time, which an O4 applied again does not.
    Live { extend: bool },
}

/// What one application reads once: the customer, its settings, its relay
/// site table, whether it is multi-site, and the sensor's site.
struct Env<'e> {
    dai: &'e Dai<'e>,
    txn: &'e Txn<'e>,
    customer: u32,
    settings: DaiSettings,
    relays: HashMap<(IpAddr, IpAddr), String>,
    multi_site: bool,
    sensor_site: Option<String>,
    now: i64,
}

/// One pending row being applied.
struct Pending<'p> {
    sensor: &'p str,
    slot_start: i64,
    kind: DaiObservationKind,
    hash: &'p IdHash,
    order: OrderKey,
    row: &'p SeenRow,
}

impl<'e> Env<'e> {
    /// Reads, within `txn`, what an application of `sensor`'s slot starting
    /// at `slot_start` for `customer` reads once: first the customer's guard
    /// for update, without incrementing it, then the settings, the sites,
    /// the relay site table and the sensor's site.
    fn new(
        dai: &'e Dai<'e>,
        txn: &'e Txn<'e>,
        customer: u32,
        sensor: &str,
        slot_start: i64,
        now: i64,
    ) -> Result<Self> {
        txn.get_for_update_cf(dai.guard.cf, customer_key(customer), EXCLUSIVE)
            .map_err(anyhow::Error::from)?;
        let settings = dai.stored_settings(txn, customer)?.unwrap_or_default();
        let multi_site = dai.is_multi_site_in(txn, customer)?;
        let relays = dai
            .relay_entries(txn, customer)?
            .into_iter()
            .map(|entry| ((entry.dhcp_server, entry.giaddr), entry.site))
            .collect();
        let sensor_site = dai.sensor_site_in(txn, customer, sensor, slot_start)?;
        Ok(Self {
            dai,
            txn,
            customer,
            settings,
            relays,
            multi_site,
            sensor_site,
            now,
        })
    }

    /// Returns the site an observation of `body` is applied at.
    fn site_of(&self, body: &DaiObservationBody) -> SiteOf {
        if let DaiObservationBody::DhcpLease {
            server_ip, giaddr, ..
        } = body
            && !giaddr.is_unspecified()
        {
            if let Some(site) = self.relays.get(&(*server_ip, *giaddr)) {
                return SiteOf::Site(site.clone());
            }
            if self.multi_site {
                return SiteOf::RelayUnknown;
            }
        }
        match &self.sensor_site {
            Some(site) => SiteOf::Site(site.clone()),
            None => SiteOf::None,
        }
    }

    /// Returns the inactivity time, in nanoseconds, of a binding an ACK with
    /// `lease_secs` starts.
    fn inactivity(&self, lease_secs: Option<u32>) -> i64 {
        match lease_secs {
            Some(lease) if lease != 0 => secs_to_nanos(
                u64::from(lease).saturating_mul(u64::from(self.settings.inactivity_multiplier)),
            ),
            _ => secs_to_nanos(self.settings.no_lease_inactivity_secs),
        }
    }

    /// Returns the address (`site`, `ip`), reading its IP state for update
    /// and then its bindings the first time.
    ///
    /// Retention removes an IP state whose order key is old enough even
    /// while a binding of the address and the evidence a recomputation may
    /// replay are kept. An address that has stored bindings but no IP state
    /// therefore takes, as the order key it decides lateness from, the
    /// latest order key among its stored binding evidence, so late binding
    /// evidence still replays what came after it.
    fn address<'a>(
        &self,
        addresses: &'a mut Addresses,
        site: &str,
        ip: IpAddr,
    ) -> Result<&'a mut Address> {
        let key = (site.to_string(), ip);
        if !addresses.0.contains_key(&key) {
            let mut lock = self.dai.lock_ip_state(self.txn, self.customer, site, ip)?;
            let stored = self.dai.bindings_in(self.txn, self.customer, site, ip)?;
            if lock.current.is_none() && !stored.is_empty() {
                for (order, _, _) in self.binding_evidence(site, ip)? {
                    lock.raise(order);
                }
            }
            let bindings = Bindings(stored.clone());
            addresses.0.insert(
                key.clone(),
                Address {
                    lock,
                    stored,
                    bindings,
                    written: false,
                },
            );
        }
        Ok(addresses
            .0
            .get_mut(&key)
            .expect("the address was inserted above"))
    }

    /// Writes the bindings and IP states of every address the application
    /// changed.
    fn flush(&self, addresses: Addresses) -> Result<()> {
        for ((site, ip), address) in addresses.0 {
            let changed = self.dai.write_bindings(
                self.txn,
                self.customer,
                &site,
                ip,
                &address.stored,
                &address.bindings.0,
            )?;
            if changed || address.written || address.lock.current != address.lock.stored {
                self.dai.write_ip_state(self.txn, &address.lock)?;
            }
        }
        Ok(())
    }

    /// Applies one pending row.
    fn apply(&self, addresses: &mut Addresses, pending: &Pending<'_>) -> Result<()> {
        let site = match self.site_of(&pending.row.body) {
            SiteOf::Site(site) => site,
            SiteOf::RelayUnknown => {
                return self.dai.add_counter(
                    self.txn,
                    self.customer,
                    DaiCounterKind::RelaySiteUnknown,
                    self.now,
                    1,
                );
            }
            SiteOf::None => {
                tracing::warn!(
                    "deleting a pending DAI observation of sensor {:?} unapplied: customer {} \
                     has no default site",
                    pending.sensor,
                    self.customer
                );
                return self.dai.add_counter(
                    self.txn,
                    self.customer,
                    DaiCounterKind::NotApplied,
                    self.now,
                    1,
                );
            }
        };
        let mut edits = DeviceEdits::default();
        let row = pending.row;
        let (first, last) = (row.first_seen, row.last_seen);
        match &row.body {
            DaiObservationBody::DhcpLease { .. } => {
                self.apply_lease(addresses, &mut edits, &site, pending)?;
            }
            DaiObservationBody::Kerberos { client_ip, .. } => {
                self.apply_kerberos(addresses, &mut edits, &site, *client_ip, pending)?;
            }
            DaiObservationBody::Ntlm { ip, .. } => {
                let address = self.address(addresses, &site, *ip)?;
                self.index_evidence(address, &site, *ip, pending, false)?;
                if let Some(device) = covering_device(address, first, last) {
                    self.touch(&mut edits, device, first, last)?;
                }
            }
            DaiObservationBody::DhcpServer { .. }
            | DaiObservationBody::Service { .. }
            | DaiObservationBody::SoftwareString { .. }
            | DaiObservationBody::DnsName { .. } => {
                self.apply_attribute(addresses, &mut edits, &site, row)?;
            }
            DaiObservationBody::IpActivity { .. } => {}
        }
        edits.flush(
            self.dai,
            self.txn,
            self.customer,
            ChangeSource::Observation(kind_number(pending.kind)),
            pending.order.time,
        )
    }

    /// Applies an O3, O7, O8 or O22 at `site` through the binding covering
    /// it.
    fn apply_attribute(
        &self,
        addresses: &mut Addresses,
        edits: &mut DeviceEdits,
        site: &str,
        row: &SeenRow,
    ) -> Result<()> {
        let (first, last) = (row.first_seen, row.last_seen);
        match &row.body {
            DaiObservationBody::DhcpServer { server_ip, .. } => {
                let address = self.address(addresses, site, *server_ip)?;
                if let Some(device) = covering_device(address, first, last)
                    && let Some(edit) = edits.get(self.dai, self.txn, self.customer, device)?
                {
                    edit.touch(first, last);
                    edit.set_dhcp_server();
                }
            }
            DaiObservationBody::Service {
                server_ip,
                port,
                proto,
                external_client,
            } => {
                let address = self.address(addresses, site, *server_ip)?;
                if let Some(device) = covering_device(address, first, last) {
                    self.touch(edits, device, first, last)?;
                    self.widen_service(device, *port, *proto, *external_client, first, last)?;
                }
            }
            DaiObservationBody::SoftwareString {
                ip,
                side,
                source,
                text,
            } => {
                let address = self.address(addresses, site, *ip)?;
                if let Some(device) = covering_device(address, first, last) {
                    self.touch(edits, device, first, last)?;
                    let key = software_key(
                        self.customer,
                        device,
                        side_number(*side),
                        software_source_number(*source),
                        text,
                    );
                    self.widen_times(&key, first, last)?;
                }
            }
            DaiObservationBody::DnsName { name, ip } => {
                let address = self.address(addresses, site, *ip)?;
                if let Some(device) = covering_device(address, first, last)
                    && let Some(edit) = edits.get(self.dai, self.txn, self.customer, device)?
                {
                    edit.touch(first, last);
                    if !name.is_empty() {
                        edit.add_name(name, NameSource::Dns, last);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Widens the first and last seen times of `device` and returns it to
    /// active if it is not seen.
    fn touch(&self, edits: &mut DeviceEdits, device: Uuid, first: i64, last: i64) -> Result<()> {
        if let Some(edit) = edits.get(self.dai, self.txn, self.customer, device)? {
            edit.touch(first, last);
        }
        Ok(())
    }

    /// Writes the evidence row of `pending` at (`site`, `ip`), merging it
    /// into the row of the same slot, kind and identifier hash if there is
    /// one, and returns whether there was.
    fn index_evidence(
        &self,
        address: &mut Address,
        site: &str,
        ip: IpAddr,
        pending: &Pending<'_>,
        verified: bool,
    ) -> Result<bool> {
        let prefix = || KeyWriter::default().u32(self.customer).str(site).ip(ip);
        let from = prefix().i64(pending.slot_start).finish();
        let to = prefix()
            .i64(pending.slot_start.saturating_add(FIVE_MINUTES))
            .finish();
        let mut existing = None;
        for (key, _) in Dai::scan_range(&self.dai.evidence, self.txn, &from, &to)? {
            let decoded = decode_evidence_key(&key)?;
            if decoded.kind != pending.kind || decoded.hash != *pending.hash {
                continue;
            }
            let Some(stored) = Dai::get_row::<EvidenceRow>(self.txn, &self.dai.evidence, &key)?
            else {
                continue;
            };
            if stored.slot_start == pending.slot_start {
                existing = Some((key, decoded.last_seen, stored));
                break;
            }
        }
        let row = pending.row;
        let (merged, last_seen) = match &existing {
            Some((key, last_seen, stored)) => {
                Dai::delete_row(self.txn, &self.dai.evidence, key)?;
                (
                    EvidenceRow {
                        slot_start: pending.slot_start,
                        sensor: pending.sensor.to_string(),
                        body: merge_body(&stored.body, &row.body),
                        first_seen: stored.first_seen.min(row.first_seen),
                        verified: stored.verified || verified,
                    },
                    (*last_seen).max(row.last_seen),
                )
            }
            None => (
                EvidenceRow {
                    slot_start: pending.slot_start,
                    sensor: pending.sensor.to_string(),
                    body: row.body.clone(),
                    first_seen: row.first_seen,
                    verified,
                },
                row.last_seen,
            ),
        };
        let key = evidence_key(
            self.customer,
            site,
            ip,
            last_seen,
            pending.kind,
            pending.hash,
        );
        Dai::put_row(self.txn, &self.dai.evidence, &key, &merged)?;
        address.written = true;
        Ok(existing.is_some())
    }

    /// Applies an O1.
    fn apply_lease(
        &self,
        addresses: &mut Addresses,
        edits: &mut DeviceEdits,
        site: &str,
        pending: &Pending<'_>,
    ) -> Result<()> {
        let DaiObservationBody::DhcpLease {
            time,
            msg,
            ip,
            chaddr,
            server_id,
            hostname,
            lease_secs,
            ..
        } = &pending.row.body
        else {
            return Ok(());
        };
        let time = *time;
        let mac = valid_mac(chaddr);
        let address = self.address(addresses, site, *ip)?;
        let existed = self.index_evidence(address, site, *ip, pending, false)?;

        // The identifier steps.
        let device = match (msg, &mac) {
            (DaiDhcpMsg::Ack, Some(mac)) => Some(self.ack_identifier(edits, mac, time)?),
            _ => None,
        };

        // The binding steps.
        if is_binding_evidence(&pending.row.body, false) && !existed {
            let late = address
                .lock
                .current
                .is_some_and(|latest| pending.order < latest);
            if late {
                self.recompute(address, site, *ip, time)?;
            } else {
                match (msg, &mac, device) {
                    (DaiDhcpMsg::Ack, Some(mac), Some(device)) => address.bindings.ack(
                        time,
                        &NewBinding {
                            device,
                            mac,
                            server_id: *server_id,
                        },
                        || self.inactivity(*lease_secs),
                    ),
                    (DaiDhcpMsg::Ack, _, _) => address.bindings.invalid_ack(time),
                    (DaiDhcpMsg::Release | DaiDhcpMsg::Decline, _, _) => {
                        address.bindings.release(time, mac.as_deref(), *server_id);
                    }
                    (DaiDhcpMsg::InformAck, _, _) => {}
                }
                address.lock.raise(pending.order);
            }
        }

        // The other effects.
        let hostname = hostname.as_deref().filter(|name| !name.is_empty());
        let confirmed = match (msg, &mac) {
            (DaiDhcpMsg::Ack, _) => device,
            (DaiDhcpMsg::InformAck, Some(mac)) => {
                let bound = address
                    .bindings
                    .open_at(time)
                    .and_then(|start| address.bindings.get(start))
                    .filter(|binding| binding.evidence_identifier == Identifier::mac(mac))
                    .map(|binding| binding.device);
                if bound.is_some() {
                    let id = Identifier::mac(mac);
                    if let Some(mut row) = self.dai.identifier_in(self.txn, self.customer, &id)?
                        && time > row.last_confirmed
                    {
                        row.last_confirmed = time;
                        self.dai
                            .put_identifier(self.txn, self.customer, &id, &row)?;
                    }
                }
                bound
            }
            _ => None,
        };
        if let Some(device) = confirmed
            && let Some(edit) = edits.get(self.dai, self.txn, self.customer, device)?
        {
            edit.touch(time, time);
            if let Some(name) = hostname {
                edit.add_name(name, NameSource::Dhcp, time);
            }
        }
        Ok(())
    }

    /// Runs the identifier steps of an ACK with the MAC `mac` at `time`
    /// (device creation, evidence aging and the MAC's last confirmed time),
    /// and returns the device the ACK applies to: the one that holds the MAC
    /// at `time` once they ran.
    fn ack_identifier(&self, edits: &mut DeviceEdits, mac: &str, time: i64) -> Result<Uuid> {
        let id = Identifier::mac(mac);
        let Some(mut row) = self.dai.identifier_in(self.txn, self.customer, &id)? else {
            let (device, _) = edits.create(&id, time);
            let row = IdentifierRow {
                device,
                last_confirmed: time,
                earlier_owners: Vec::new(),
            };
            self.dai
                .put_identifier(self.txn, self.customer, &id, &row)?;
            return Ok(device);
        };
        let aging = secs_to_nanos(self.settings.evidence_aging_secs);
        if time > row.last_confirmed.saturating_add(aging) {
            let old = row.device;
            let keeps = edits
                .get(self.dai, self.txn, self.customer, old)?
                .is_some_and(|edit| edit.row.keeps_identifiers());
            row.last_confirmed = time;
            if keeps {
                self.dai
                    .put_identifier(self.txn, self.customer, &id, &row)?;
                return Ok(old);
            }
            let (device, edit) = edits.create(&id, time);
            edit.relate(old);
            if let Some(old_edit) = edits.get(self.dai, self.txn, self.customer, old)? {
                old_edit.remove_identifier(&id);
                old_edit.relate(device);
            }
            row.earlier_owners.push(EarlierOwner {
                device: old,
                left: time,
            });
            row.device = device;
            self.dai
                .put_identifier(self.txn, self.customer, &id, &row)?;
            return Ok(device);
        }
        let owner = row.owner_at(time);
        if time > row.last_confirmed {
            row.last_confirmed = time;
            self.dai
                .put_identifier(self.txn, self.customer, &id, &row)?;
        } else if owner != row.device {
            // The ACK may bind an earlier owner, which retention keeps only
            // while it has such a binding; writing the row, unchanged, makes
            // retention removing that owner conflict with this application.
            self.dai
                .put_identifier(self.txn, self.customer, &id, &row)?;
        }
        Ok(owner)
    }

    /// Applies an O4 at (`site`, `ip`).
    fn apply_kerberos(
        &self,
        addresses: &mut Addresses,
        edits: &mut DeviceEdits,
        site: &str,
        ip: IpAddr,
        pending: &Pending<'_>,
    ) -> Result<()> {
        let body = &pending.row.body;
        let (first, last) = (pending.row.first_seen, pending.row.last_seen);
        let verified = verified_machine_account(body, &self.settings).is_some();
        let address = self.address(addresses, site, ip)?;
        let existed = self.index_evidence(address, site, ip, pending, verified)?;
        if !verified {
            if let Some(device) = covering_device(address, first, last) {
                self.touch(edits, device, first, last)?;
            }
            return Ok(());
        }
        if existed {
            return self.verified_o4(
                address,
                edits,
                body,
                first,
                last,
                O4Mode::Live { extend: false },
            );
        }
        let late = address
            .lock
            .current
            .is_some_and(|latest| pending.order < latest);
        if late {
            // The replay moves the bindings only, this O4 among them; its
            // remaining effects apply against the recomputed bindings.
            self.recompute(address, site, ip, pending.order.time)?;
            self.verified_o4(
                address,
                edits,
                body,
                first,
                last,
                O4Mode::Live { extend: false },
            )
        } else {
            self.verified_o4(
                address,
                edits,
                body,
                first,
                last,
                O4Mode::Live { extend: true },
            )?;
            address.lock.raise(pending.order);
            Ok(())
        }
    }

    /// Applies a verified O4 of `body` seen from `first` to `last` to the
    /// bindings of `address` as `mode` says.
    fn verified_o4(
        &self,
        address: &mut Address,
        edits: &mut DeviceEdits,
        body: &DaiObservationBody,
        first: i64,
        last: i64,
        mode: O4Mode,
    ) -> Result<()> {
        let Some(start) = address.bindings.covering(first, last) else {
            return Ok(());
        };
        let Some(binding) = address.bindings.get(start) else {
            return Ok(());
        };
        let device = binding.device;
        let attaches = binding.evidence_kind == kind_number(DaiObservationKind::DhcpLease);
        let live = mode != O4Mode::Replay;
        if let (true, Some(account)) = (attaches, machine_account(body)) {
            let id = Identifier {
                kind: IdentifierKind::MachineAccount,
                value: account,
            };
            let owned = match self.dai.identifier_in(self.txn, self.customer, &id)? {
                None if live => {
                    let row = IdentifierRow {
                        device,
                        last_confirmed: last,
                        earlier_owners: Vec::new(),
                    };
                    self.dai
                        .put_identifier(self.txn, self.customer, &id, &row)?;
                    if let Some(edit) = edits.get(self.dai, self.txn, self.customer, device)? {
                        edit.add_identifier(&id);
                    }
                    true
                }
                // Applied in order, the O4 would attach the unowned account
                // and then extend; the replay writes no identifier, but the
                // binding moves the same.
                None => true,
                Some(mut row) if row.device == device => {
                    if live && last > row.last_confirmed {
                        row.last_confirmed = last;
                        self.dai
                            .put_identifier(self.txn, self.customer, &id, &row)?;
                    }
                    true
                }
                Some(row) => {
                    if live {
                        self.dai.record_conflict(
                            self.txn,
                            self.customer,
                            &id,
                            [row.device, device],
                            (first, last),
                        )?;
                    }
                    false
                }
            };
            if owned && mode != (O4Mode::Live { extend: false }) {
                address.bindings.extend(start, last);
            }
        }
        if live {
            self.touch(edits, device, first, last)?;
        }
        Ok(())
    }

    /// Recomputes the bindings of `address` (`site`, `ip`) for a late
    /// observation at `time`: deletes the bindings starting at or after the
    /// replay start and derives them again by replaying the binding evidence
    /// of the address from it, in order-key order. The replay moves bindings
    /// only: it changes no device, identifier, conflict or change history,
    /// not even for the late observation itself, whose remaining effects
    /// the caller applies against the result. It writes back, unchanged,
    /// the identifier row of each replayed ACK that binds an earlier owner,
    /// so retention removing that owner conflicts with it.
    fn recompute(&self, address: &mut Address, site: &str, ip: IpAddr, time: i64) -> Result<()> {
        let from = address.bindings.replay_start(time);
        let removed = address.bindings.split_off(from);
        let mut events = self.binding_evidence(site, ip)?;
        events.retain(|(order, _, _)| order.time >= from);
        events.sort_unstable_by_key(|(order, _, _)| *order);
        // A replayed O4 reads and writes no device; it is never flushed.
        let mut edits = DeviceEdits::default();
        for (_, last_seen, row) in events {
            match &row.body {
                DaiObservationBody::DhcpLease {
                    time,
                    msg,
                    chaddr,
                    server_id,
                    lease_secs,
                    ..
                } => {
                    let mac = valid_mac(chaddr);
                    match (msg, &mac) {
                        (DaiDhcpMsg::Ack, Some(mac)) => {
                            let id = Identifier::mac(mac);
                            let Some(owner) =
                                self.dai.identifier_in(self.txn, self.customer, &id)?
                            else {
                                continue;
                            };
                            let device = owner.owner_at(*time);
                            if device != owner.device {
                                // As in the identifier steps of a live ACK:
                                // retention removing the earlier owner this
                                // binds conflicts with the replay.
                                self.dai
                                    .put_identifier(self.txn, self.customer, &id, &owner)?;
                            }
                            let kept = removed.get(&(*time, device)).copied();
                            address.bindings.ack(
                                *time,
                                &NewBinding {
                                    device,
                                    mac,
                                    server_id: *server_id,
                                },
                                || kept.unwrap_or_else(|| self.inactivity(*lease_secs)),
                            );
                        }
                        (DaiDhcpMsg::Ack, None) => address.bindings.invalid_ack(*time),
                        (DaiDhcpMsg::Release | DaiDhcpMsg::Decline, _) => {
                            address.bindings.release(*time, mac.as_deref(), *server_id);
                        }
                        (DaiDhcpMsg::InformAck, _) => {}
                    }
                }
                DaiObservationBody::Kerberos { .. } => {
                    self.verified_o4(
                        address,
                        &mut edits,
                        &row.body,
                        row.first_seen,
                        last_seen,
                        O4Mode::Replay,
                    )?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Returns the binding evidence stored at (`site`, `ip`), each with its
    /// order key and last seen time, in no particular order.
    ///
    /// The caller has read the address's IP state for update.
    fn binding_evidence(
        &self,
        site: &str,
        ip: IpAddr,
    ) -> Result<Vec<(OrderKey, i64, EvidenceRow)>> {
        let mut events = Vec::new();
        for (key, value) in Dai::scan(
            &self.dai.evidence,
            self.txn,
            &address_key(self.customer, site, ip),
        )? {
            let decoded = decode_evidence_key(&key)?;
            let row: EvidenceRow = super::super::deserialize(&value)?;
            if row.is_binding_evidence() {
                let order = OrderKey::of(&row.body, row.first_seen, &decoded.hash);
                events.push((order, decoded.last_seen, row));
            }
        }
        Ok(events)
    }

    /// Widens the `dai services` row of (`device`, `port`, `proto`) by an
    /// observation from `first` to `last`.
    fn widen_service(
        &self,
        device: Uuid,
        port: u16,
        proto: u8,
        external_client: bool,
        first: i64,
        last: i64,
    ) -> Result<()> {
        let key = service_key(self.customer, device, port, proto);
        let stored: Option<ServiceRow> = Dai::get_row(self.txn, &self.dai.services, &key)?;
        let row = match &stored {
            Some(stored) => ServiceRow {
                external_client: stored.external_client || external_client,
                first_seen: stored.first_seen.min(first),
                last_seen: stored.last_seen.max(last),
                removed: stored.removed,
            },
            None => ServiceRow {
                external_client,
                first_seen: first,
                last_seen: last,
                removed: false,
            },
        };
        if stored.as_ref() != Some(&row) {
            Dai::put_row(self.txn, &self.dai.services, &key, &row)?;
        }
        Ok(())
    }

    /// Widens the `dai software strings` row under `key` by an observation
    /// from `first` to `last`.
    fn widen_times(&self, key: &[u8], first: i64, last: i64) -> Result<()> {
        let stored: Option<SeenTimes> = Dai::get_row(self.txn, &self.dai.software, key)?;
        let row = stored.map_or(
            SeenTimes {
                first_seen: first,
                last_seen: last,
            },
            |stored| SeenTimes {
                first_seen: stored.first_seen.min(first),
                last_seen: stored.last_seen.max(last),
            },
        );
        if stored != Some(row) {
            Dai::put_row(self.txn, &self.dai.software, key, &row)?;
        }
        Ok(())
    }
}

/// Returns the device of the binding of `address` in effect over the whole
/// of `[first, last]`, if any.
fn covering_device(address: &Address, first: i64, last: i64) -> Option<Uuid> {
    address
        .bindings
        .covering(first, last)
        .and_then(|start| address.bindings.get(start))
        .map(|binding| binding.device)
}

impl Dai<'_> {
    /// Applies up to `max_count` pending observations of `sensor`'s slot
    /// starting at `slot_start`, as
    /// [`Store::apply_dai_slot`](crate::Store::apply_dai_slot) describes,
    /// and returns the sensor's resolver point.
    pub(crate) fn apply_slot(
        &self,
        sensor: &str,
        slot_start: i64,
        max_count: usize,
        now: i64,
    ) -> Result<Option<i64>> {
        if max_count == 0 {
            bail!("the number of pending DAI observations to apply must be at least 1");
        }
        self.write(|txn| self.apply_attempt(txn, sensor, slot_start, max_count, now))
    }

    /// Runs one attempt of [`apply_slot`](Self::apply_slot) within `txn`.
    fn apply_attempt(
        &self,
        txn: &Txn<'_>,
        sensor: &str,
        slot_start: i64,
        max_count: usize,
        now: i64,
    ) -> Result<Option<i64>> {
        // Every write that adds a pending row writes its pair's earliest
        // pending row, so reading them all for update before the untracked
        // scan below makes a store adding a row the scan misses conflict
        // with this attempt; otherwise an observation decided before the
        // missed row would never be decided again.
        self.resolver_point_in(txn, sensor)?;

        // The rows of the slot, by the order key of their scanned content;
        // each taken row is read again for update below.
        let prefix = KeyWriter::default().str(sensor).i64(slot_start).finish();
        let mut candidates = Vec::new();
        for (key, value) in Self::scan(&self.pending, txn, &prefix)? {
            let (_, _, _, hash) = decode_pending_key(&key)?;
            let row: SeenRow = super::super::deserialize(&value)?;
            candidates.push((OrderKey::of(&row.body, row.first_seen, &hash), key));
        }
        candidates.sort_unstable();
        candidates.truncate(max_count);
        #[cfg(test)]
        if let Some(hook) = APPLY_SCANNED.with(|cell| cell.borrow_mut().take()) {
            hook(self.db);
        }

        let customer = self.customer_sensors_in(txn)?.customer(sensor);
        let env = match customer {
            Some(customer) => Some(Env::new(self, txn, customer, sensor, slot_start, now)?),
            None => None,
        };

        let mut taken = Vec::new();
        for (_, key) in candidates {
            let Some(row) = Self::get_row::<SeenRow>(txn, &self.pending, &key)? else {
                continue;
            };
            let (_, _, kind, hash) = decode_pending_key(&key)?;
            let order = OrderKey::of(&row.body, row.first_seen, &hash);
            taken.push((order, kind, hash, key, row));
        }
        taken.sort_unstable_by_key(|(order, ..)| *order);

        let mut kinds = BTreeSet::new();
        let mut addresses = Addresses::default();
        for (order, kind, hash, key, row) in &taken {
            Self::delete_row(txn, &self.pending, key)?;
            kinds.insert(*kind);
            if let Some(env) = &env {
                env.apply(
                    &mut addresses,
                    &Pending {
                        sensor,
                        slot_start,
                        kind: *kind,
                        hash,
                        order: *order,
                        row,
                    },
                )?;
            }
        }
        if env.is_none() && !taken.is_empty() {
            tracing::warn!(
                "deleting {} pending DAI observations of sensor {sensor:?} unapplied: it is not \
                 a customer sensor",
                taken.len()
            );
        }
        if let Some(env) = &env {
            env.flush(addresses)?;
        }
        for kind in kinds {
            self.recompute_earliest_pending(txn, sensor, kind)?;
        }
        let point = self.write_resolver_point(txn, sensor)?;
        #[cfg(test)]
        if let Some(hook) = BEFORE_APPLY_COMMIT.with(|cell| cell.borrow_mut().take()) {
            hook(self.db);
        }
        Ok(point)
    }

    /// Returns, within `txn`, the resolver point of `sensor`: the earliest
    /// slot start among its `dai earliest pending` rows, each read for
    /// update, or `None`, "caught up", if it has none.
    pub(super) fn resolver_point_in(&self, txn: &Txn<'_>, sensor: &str) -> Result<Option<i64>> {
        let mut point: Option<i64> = None;
        for kind in KINDS {
            if let Some(slot_start) =
                Self::get_row::<i64>(txn, &self.earliest_pending, &pair_key(sensor, kind))?
            {
                point = Some(point.map_or(slot_start, |point| point.min(slot_start)));
            }
        }
        Ok(point)
    }

    /// Writes, within `txn`, the resolver point of `sensor` as
    /// [`resolver_point_in`](Self::resolver_point_in) computes it, and
    /// returns it.
    pub(super) fn write_resolver_point(&self, txn: &Txn<'_>, sensor: &str) -> Result<Option<i64>> {
        let point = self.resolver_point_in(txn, sensor)?;
        let key = resolver_point_key(sensor);
        Self::get_row::<Option<i64>>(txn, &self.resolver_points, &key)?;
        Self::put_row(txn, &self.resolver_points, &key, &point)?;
        Ok(point)
    }

    /// Returns, ordered by sensor name, every sensor with `dai earliest
    /// pending` rows and the earliest of them.
    pub(crate) fn pending_heads(&self) -> Result<Vec<DaiPendingHead>> {
        let mut heads: BTreeMap<String, i64> = BTreeMap::new();
        for (key, value) in self.scan_rows(&self.earliest_pending, &[], |_, _| Ok(true))? {
            let (sensor, _) = decode_pair_key(&key)?;
            let slot_start: i64 = super::super::deserialize(&value)?;
            heads
                .entry(sensor)
                .and_modify(|earliest| *earliest = (*earliest).min(slot_start))
                .or_insert(slot_start);
        }
        Ok(heads
            .into_iter()
            .map(|(sensor, slot_start)| DaiPendingHead { sensor, slot_start })
            .collect())
    }

    /// Returns, within `txn`, whether the customer is multi-site: under the
    /// current site table its sensors (its sensors per the node table and
    /// every sensor its sites list) fall in two or more sites, a sensor no
    /// site lists counting as in the default site.
    pub(crate) fn is_multi_site_in(&self, txn: &Txn<'_>, customer_id: u32) -> Result<bool> {
        let sites = self.sites_in(txn, customer_id)?;
        let assignment = Assignment::new(&sites);
        let mut seen = BTreeSet::new();
        for sensor in self.customer_sensors(txn, customer_id, &sites, &[])? {
            seen.insert(assignment.site(&sensor).to_string());
            if seen.len() > 1 {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
