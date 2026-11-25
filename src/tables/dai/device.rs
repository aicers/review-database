//! The device tables of device identification (DAI): their keys and values,
//! and the reads and writes every writer of them shares.
//!
//! A *device* is identified by a random UUID v4, shown lowercase
//! hyphenated, and holds strong identifiers (a MAC, an operator asset id, a
//! machine account), each of which belongs to one device of the customer at
//! a time. A *binding* is a device holding an IP address at a site from a
//! start to an end. A (site, IP) with no binding at a time is an *IP
//! device*, a placeholder that is never a row.
//!
//! Every key starts with the customer id, so a prefix read by customer id
//! returns exactly that customer's rows; a binding or evidence key then
//! holds the site token and the IP address, so a read by (customer, site,
//! IP) returns exactly the rows of that address.
//!
//! # The IP state lock
//!
//! The store's transactions take no snapshot and a scan is not tracked, so a
//! transaction that decides from the bindings or evidence of a (customer,
//! site, IP) first reads its `dai ip state` row for update, and every
//! transaction that adds, removes or rewrites one of those rows also writes
//! the `dai ip state` row, unchanged if need be, or deletes its key when
//! there is none. Two such transactions on one address therefore conflict
//! whichever commits first. [`IpStateLock`] is that protocol.

use std::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    net::IpAddr,
};

use anyhow::{Context, Result};
use review_protocol::types::{DaiObservationBody, DaiObservationKind};
use rocksdb::IteratorMode;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Dai, KeyReader, KeyWriter, RawRow, Txn, kind_number, observation::IdHash, sensor_key};
use crate::Map;

/// The number of bytes of a MAC address.
const MAC_LEN: usize = 6;
/// The group (multicast) bit of the first byte of a MAC address.
const MAC_GROUP_BIT: u8 = 0x01;
/// The rank of an O1 DECLINE in the apply order.
const RANK_DECLINE: u8 = 0;
/// The rank of an O1 RELEASE in the apply order.
const RANK_RELEASE: u8 = 1;
/// The rank of an O1 ACK in the apply order.
const RANK_ACK: u8 = 2;
/// The rank of an O1 INFORM ACK in the apply order.
const RANK_INFORM_ACK: u8 = 3;
/// The rank of an observation of another kind is this plus its kind number,
/// so it ranks after every O1 message.
const RANK_OTHER_KINDS: u8 = 4;
/// The number of nanoseconds in a second.
const NANOS_PER_SEC: u64 = 1_000_000_000;

/// The kind of a strong identifier of a device, with the byte its keys hold.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) enum IdentifierKind {
    /// A MAC address, as lowercase colon-separated hex.
    Mac,
    /// An operator asset id, as given.
    OperatorAssetId,
    /// A machine account, as `<CNAME>@<REALM>` ASCII-uppercased.
    MachineAccount,
}

impl IdentifierKind {
    /// Returns the byte the keys hold for the kind.
    pub(crate) fn number(self) -> u8 {
        match self {
            Self::Mac => 1,
            Self::OperatorAssetId => 2,
            Self::MachineAccount => 3,
        }
    }

    /// Returns the kind whose key byte is `number`, or `None` if none is.
    pub(crate) fn from_number(number: u8) -> Option<Self> {
        [Self::Mac, Self::OperatorAssetId, Self::MachineAccount]
            .into_iter()
            .find(|kind| kind.number() == number)
    }

    fn json_name(self) -> &'static str {
        match self {
            Self::Mac => "mac",
            Self::OperatorAssetId => "operator_asset_id",
            Self::MachineAccount => "machine_account",
        }
    }
}

/// A strong identifier: its kind and its value.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) struct Identifier {
    pub(crate) kind: IdentifierKind,
    pub(crate) value: String,
}

impl Identifier {
    pub(crate) fn mac(value: &str) -> Self {
        Self {
            kind: IdentifierKind::Mac,
            value: value.to_string(),
        }
    }

    fn json(&self) -> String {
        serde_json::json!({ "kind": self.kind.json_name(), "value": self.value }).to_string()
    }
}

/// The source of a name of a device, lowest first: the representative name
/// is the most recently seen value of the highest source.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) enum NameSource {
    /// A DNS name resolved to the device's address.
    Dns,
    /// A DHCP hostname.
    Dhcp,
    /// A name an operator set; it never expires.
    Operator,
}

impl NameSource {
    fn json_name(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Dhcp => "dhcp",
            Self::Operator => "operator",
        }
    }
}

/// A name of a device, with its source and when it was last seen.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct DeviceName {
    pub(crate) value: String,
    pub(crate) source: NameSource,
    pub(crate) last_seen: i64,
}

impl DeviceName {
    fn json(&self) -> String {
        serde_json::json!({ "value": self.value, "source": self.source.json_name() }).to_string()
    }
}

/// The operator's verdict on a device.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) enum Verdict {
    /// Seen by observation only.
    Observed,
    /// Confirmed by an operator.
    Confirmed,
    /// Ignored by an operator.
    Ignored,
}

impl Verdict {
    fn json(self) -> String {
        let name = match self {
            Self::Observed => "observed",
            Self::Confirmed => "confirmed",
            Self::Ignored => "ignored",
        };
        serde_json::Value::from(name).to_string()
    }
}

/// Whether a device is seen.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) enum Activity {
    /// Seen within the last 90 days, or never expired.
    Active,
    /// Not seen for 90 days.
    NotSeen,
    /// Hidden by an operator; neither observation nor expiry changes it.
    Hidden,
}

impl Activity {
    fn json(self) -> String {
        let name = match self {
            Self::Active => "active",
            Self::NotSeen => "not_seen",
            Self::Hidden => "hidden",
        };
        serde_json::Value::from(name).to_string()
    }
}

/// How a device came to be.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) enum Origin {
    /// Created by an observation.
    Observation,
    /// Created by an operator import.
    Import,
}

/// The stored value of a `dai devices` row, keyed by (customer, device).
///
/// A device id with no row is either an alias (a `dai device aliases` row
/// under the same key names the current device) or unknown.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct DeviceRow {
    /// The strong identifiers the device holds, in the order they were
    /// added. Each has a `dai device identifiers` row naming this device as
    /// its current holder.
    pub(crate) identifiers: Vec<Identifier>,
    /// The names, each value once per source. Those of source operator are
    /// the names an import set, which leaves at most one; a merge keeps
    /// those of every device it merges.
    pub(crate) names: Vec<DeviceName>,
    /// Whether the device was seen as a DHCP server.
    pub(crate) was_dhcp_server: bool,
    /// The earliest time an observation applied to the device saw it;
    /// `None` until one does, as for a device an import created.
    pub(crate) first_seen: Option<i64>,
    /// The latest time an observation applied to the device saw it; `None`
    /// until one does.
    pub(crate) last_seen: Option<i64>,
    /// When the device was created: the order-key time of the observation
    /// that created it, or the time of the import or split that did.
    /// Retention measures a device with no last seen time from it.
    pub(crate) created: i64,
    pub(crate) verdict: Verdict,
    pub(crate) activity: Activity,
    pub(crate) origin: Origin,
    /// The operator asset id, also held as an identifier of kind operator
    /// asset id.
    pub(crate) operator_asset_id: Option<String>,
    /// The operator's memo; empty for none.
    pub(crate) memo: String,
    /// The addresses `dai fixed ips` fixes to the device, each a (site
    /// token, IP): the device-side index of that table, written with it.
    /// It is not a device value: changing it changes no version.
    pub(crate) fixed_ips: BTreeSet<(String, IpAddr)>,
    /// Incremented by each substantive change; the version of the latest
    /// `dai device changes` entry.
    pub(crate) version: u64,
}

impl DeviceRow {
    /// Returns the representative name: the most recently seen value of the
    /// highest source, operator > DHCP > DNS, or `None` if it has no name.
    pub(crate) fn representative_name(&self) -> Option<&str> {
        self.names
            .iter()
            .max_by_key(|name| (name.source, name.last_seen))
            .map(|name| name.value.as_str())
    }

    /// Returns whether evidence aging leaves the device's identifiers on it:
    /// it has an operator asset id or an operator confirmed it.
    pub(super) fn keeps_identifiers(&self) -> bool {
        self.verdict == Verdict::Confirmed
            || self.operator_asset_id.is_some()
            || self
                .identifiers
                .iter()
                .any(|id| id.kind == IdentifierKind::OperatorAssetId)
    }

    /// Returns whether the device holds a MAC or an operator asset id.
    pub(super) fn has_strong_hardware_identifier(&self) -> bool {
        self.operator_asset_id.is_some()
            || self.identifiers.iter().any(|id| {
                matches!(
                    id.kind,
                    IdentifierKind::Mac | IdentifierKind::OperatorAssetId
                )
            })
    }
}

/// An earlier owner of an identifier, which held it until `left`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct EarlierOwner {
    pub(crate) device: Uuid,
    /// When the identifier left the device: from then on the next owner
    /// held it.
    pub(crate) left: i64,
}

/// The stored value of a `dai device identifiers` row, keyed by (customer,
/// kind, value): the identifier's ownership history.
///
/// The identifier belonged to each earlier owner until it left it, and from
/// the time the last one left (or always, if there is none) to `device`. A
/// row whose `device` is `None` is the history of a MAC an import removed
/// from its device, which no device has taken since: no device holds it
/// from the time its last earlier owner left on, and the next device to
/// take it, by an observation creating a device or by an import, becomes
/// `device` and holds it from that time on.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct IdentifierRow {
    /// The device holding the identifier now, or `None` if none does.
    pub(crate) device: Option<Uuid>,
    /// The latest time an observation confirmed the identifier, or an
    /// import gave it to its device.
    pub(crate) last_confirmed: i64,
    /// The devices that held it before, ordered by the time it left them.
    pub(crate) earlier_owners: Vec<EarlierOwner>,
}

impl IdentifierRow {
    /// Returns the device that held the identifier at the time `time`, or
    /// `None` if no device did.
    pub(crate) fn owner_at(&self, time: i64) -> Option<Uuid> {
        self.earlier_owners
            .iter()
            .find(|owner| owner.left > time)
            .map_or(self.device, |owner| Some(owner.device))
    }

    /// Records that the identifier left its current holder at `time`, after
    /// which no device holds it: the holder becomes the last earlier owner,
    /// leaving at `time`, and the owner at every earlier time stays.
    ///
    /// An earlier owner recorded as leaving after `time` (an evidence aging
    /// move stamped with an observation time later than `time`) leaves at
    /// `time` instead, and the owners after it, which held the identifier
    /// only after `time`, are dropped: from `time` on, no device holds it.
    pub(crate) fn release(&mut self, time: i64) {
        let Some(device) = self.device.take() else {
            return;
        };
        if let Some(cut) = self
            .earlier_owners
            .iter()
            .position(|owner| owner.left > time)
        {
            self.earlier_owners.truncate(cut + 1);
            if let Some(last) = self.earlier_owners.last_mut() {
                last.left = time;
            }
        }
        if self
            .earlier_owners
            .last()
            .is_none_or(|last| last.device != device || last.left < time)
        {
            self.earlier_owners
                .push(EarlierOwner { device, left: time });
        }
    }

    /// Replaces `from` by `to` as the holder and in the earlier owners, and
    /// returns whether it changed anything.
    ///
    /// Consecutive earlier owners that become the same device are one, and
    /// trailing ones that are the current holder are dropped: the owner at
    /// every time stays what the replacement makes it.
    pub(crate) fn rename(&mut self, from: &BTreeSet<Uuid>, to: Uuid) -> bool {
        let mut changed = false;
        if self.device.is_some_and(|device| from.contains(&device)) {
            self.device = Some(to);
            changed = true;
        }
        for owner in &mut self.earlier_owners {
            if from.contains(&owner.device) {
                owner.device = to;
                changed = true;
            }
        }
        if changed {
            let mut compacted: Vec<EarlierOwner> = Vec::with_capacity(self.earlier_owners.len());
            for owner in self.earlier_owners.drain(..) {
                match compacted.last_mut() {
                    // The earlier entry's span ends where this one's starts.
                    Some(last) if last.device == owner.device => last.left = owner.left,
                    _ => compacted.push(owner),
                }
            }
            while compacted
                .last()
                .is_some_and(|last| Some(last.device) == self.device)
            {
                compacted.pop();
            }
            self.earlier_owners = compacted;
        }
        changed
    }
}

/// Why a device id became an alias of another.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) enum AliasReason {
    /// The device was merged into the current one.
    Merged,
    /// An import replaced the device by the current one.
    Imported,
}

/// The stored value of a `dai device aliases` row, keyed by (customer, old
/// device id), the key of the `dai devices` row the old id had.
///
/// `current` is always a device with a `dai devices` row: a merge absorbing
/// it re-points every alias naming it to the survivor, so an alias is
/// resolved in one step.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct AliasRow {
    /// The device the old id now names.
    pub(crate) current: Uuid,
    /// When the old id became an alias.
    pub(crate) time: i64,
    pub(crate) reason: AliasReason,
}

/// The stored value of a `dai bindings` row, keyed by (customer, site, IP,
/// start).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct BindingRow {
    /// When the binding ended; `None` while it has not.
    pub(crate) end: Option<i64>,
    pub(crate) device: Uuid,
    /// The kind number of the observation that started it.
    pub(crate) evidence_kind: u8,
    /// The identifier that observation bound.
    pub(crate) evidence_identifier: Identifier,
    /// The `server_id` of the latest ACK applied to it.
    pub(crate) server_id: Option<IpAddr>,
    /// The latest time strong evidence extended it.
    pub(crate) last_strong: i64,
    /// How long after `last_strong` the binding ends, in nanoseconds; fixed
    /// when it starts.
    pub(crate) inactivity: i64,
    /// Whether `end` is an estimate retention wrote, `last_strong +
    /// inactivity`, rather than a close.
    pub(crate) end_estimated: bool,
}

impl BindingRow {
    /// Returns when the binding stops being in effect: its non-estimated end
    /// or `last_strong + inactivity`, whichever is earlier.
    pub(crate) fn effective_end(&self) -> i64 {
        let inactive = self.last_strong.saturating_add(self.inactivity);
        match self.end {
            Some(end) if !self.end_estimated => end.min(inactive),
            _ => inactive,
        }
    }
}

/// The order key of an observation: the order slot application applies
/// observations in, and the `dai ip state` value.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) struct OrderKey {
    /// `DhcpLease.time` for O1, `first_seen` otherwise.
    pub(crate) time: i64,
    /// DECLINE, RELEASE, ACK and INFORM ACK among O1 messages, then the
    /// other kinds by kind number.
    pub(crate) rank: u8,
    pub(crate) hash: IdHash,
}

impl OrderKey {
    /// Returns the order key of an observation of `body` first seen at
    /// `first_seen`, whose identifier hash is `hash`.
    pub(crate) fn of(body: &DaiObservationBody, first_seen: i64, hash: &IdHash) -> Self {
        use review_protocol::types::DaiDhcpMsg;
        let (time, rank) = match body {
            DaiObservationBody::DhcpLease { time, msg, .. } => (
                *time,
                match msg {
                    DaiDhcpMsg::Decline => RANK_DECLINE,
                    DaiDhcpMsg::Release => RANK_RELEASE,
                    DaiDhcpMsg::Ack => RANK_ACK,
                    DaiDhcpMsg::InformAck => RANK_INFORM_ACK,
                },
            ),
            other => (
                first_seen,
                RANK_OTHER_KINDS.saturating_add(kind_number(super::observation::body_kind(other))),
            ),
        };
        Self {
            time,
            rank,
            hash: *hash,
        }
    }
}

/// The stored value of a `dai evidence` row, keyed by (customer, site, IP,
/// last seen, kind, identifier hash).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct EvidenceRow {
    /// The start of the slot the observation was applied from.
    pub(crate) slot_start: i64,
    /// The sensor of the latest application.
    pub(crate) sensor: String,
    pub(crate) body: DaiObservationBody,
    pub(crate) first_seen: i64,
    /// For O4, whether it was verified when applied; `false` otherwise.
    pub(crate) verified: bool,
}

impl EvidenceRow {
    /// Returns whether the row is binding evidence: an O1 ACK, RELEASE or
    /// DECLINE, or an O4 verified when applied.
    pub(crate) fn is_binding_evidence(&self) -> bool {
        is_binding_evidence(&self.body, self.verified)
    }
}

/// Returns whether an observation of `body`, `verified` if an O4 verified
/// when applied, is binding evidence.
pub(crate) fn is_binding_evidence(body: &DaiObservationBody, verified: bool) -> bool {
    match body {
        DaiObservationBody::DhcpLease { msg, .. } => {
            !matches!(msg, review_protocol::types::DaiDhcpMsg::InformAck)
        }
        DaiObservationBody::Kerberos { .. } => verified,
        _ => false,
    }
}

/// The stored value of a `dai conflicts` row.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ConflictRow {
    /// The devices involved: the holder of the identifier and every device
    /// that claimed it.
    pub(crate) devices: BTreeSet<Uuid>,
    pub(crate) first: i64,
    pub(crate) last: i64,
}

/// The stored value of a `dai services` row.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ServiceRow {
    /// Whether a client outside the customer's registered networks was seen.
    pub(crate) external_client: bool,
    pub(crate) first_seen: i64,
    pub(crate) last_seen: i64,
    /// Whether an operator removed the service.
    pub(crate) removed: bool,
}

/// The stored value of a `dai software strings` row.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct SeenTimes {
    pub(crate) first_seen: i64,
    pub(crate) last_seen: i64,
}

/// The kind of a `dai device changes` entry.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) enum ChangeKind {
    Created,
    Changed,
    Merged,
    Split,
}

/// The operation of a changed field.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) enum ChangeOp {
    Set,
    Add,
    Remove,
}

/// What made a change.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) enum ChangeSource {
    /// An observation of the kind of this number.
    Observation(u8),
    Import,
    Operator,
    /// Retention.
    Expiry,
}

/// A field a change changed, with its values before and after as JSON
/// text, `null` for none.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct FieldChange {
    pub(crate) path: String,
    pub(crate) op: ChangeOp,
    pub(crate) before: String,
    pub(crate) after: String,
}

/// The stored value of a `dai device changes` row, keyed by (customer,
/// device, version).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ChangeEntry {
    pub(crate) kind: ChangeKind,
    /// The other device of the change: for a creation by an evidence aging
    /// move the device the identifier left, and for the entry of that device
    /// the one it went to.
    pub(crate) related_device: Option<Uuid>,
    /// Every field the change changed.
    pub(crate) fields: Vec<FieldChange>,
    /// The time of the change: the observation's order-key time, or "now"
    /// for retention.
    pub(crate) time: i64,
    pub(crate) source: ChangeSource,
}

/// The stored value of a `dai fixed ips` row, keyed by (customer, site, IP)
/// as [`address_key`] encodes it: the device an import fixed at the
/// address. A merge re-points it to the survivor, so it always names a
/// device with a `dai devices` row.
pub(crate) type FixedIpRow = Uuid;

/// The JSON text of no value.
const JSON_NULL: &str = "null";

/// Returns `value` as JSON text, `null` for an empty string.
fn json_text(value: &str) -> String {
    if value.is_empty() {
        JSON_NULL.to_string()
    } else {
        serde_json::Value::from(value).to_string()
    }
}

// ---- Values ----

/// Returns `chaddr` as a MAC address, lowercase colon-separated hex, if it is
/// one: exactly 6 bytes, not all `00`, not all `FF`, and the group bit of its
/// first byte 0.
pub(crate) fn valid_mac(chaddr: &[u8]) -> Option<String> {
    let bytes: &[u8; MAC_LEN] = chaddr.try_into().ok()?;
    if bytes.iter().all(|b| *b == 0x00) || bytes.iter().all(|b| *b == 0xFF) {
        return None;
    }
    if bytes[0] & MAC_GROUP_BIT != 0 {
        return None;
    }
    Some(
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// Returns a new random device id, a UUID v4.
pub(crate) fn new_device_id() -> Uuid {
    uuid::Builder::from_random_bytes(rand::random()).into_uuid()
}

/// Returns `secs` seconds in nanoseconds, saturating at `i64::MAX`.
pub(crate) fn secs_to_nanos(secs: u64) -> i64 {
    i64::try_from(secs.saturating_mul(NANOS_PER_SEC)).unwrap_or(i64::MAX)
}

/// Returns the machine account `<CNAME>@<REALM>`, ASCII-uppercased, of an O4
/// whose `cname` is one component of at least two characters ending in `$`,
/// or `None` for any other body.
pub(crate) fn machine_account(body: &DaiObservationBody) -> Option<String> {
    let DaiObservationBody::Kerberos { realm, cname, .. } = body else {
        return None;
    };
    let [name] = cname.as_slice() else {
        return None;
    };
    if name.chars().count() < 2 || !name.ends_with('$') {
        return None;
    }
    Some(format!(
        "{}@{}",
        name.to_ascii_uppercase(),
        realm.to_ascii_uppercase()
    ))
}

// ---- Keys ----

pub(super) fn device_key(customer: u32, device: Uuid) -> Vec<u8> {
    KeyWriter::default().u32(customer).uuid(device).finish()
}

/// Returns the key of the `dai device aliases` row of the old id `device`.
pub(super) fn alias_key(customer: u32, device: Uuid) -> Vec<u8> {
    device_key(customer, device)
}

/// Decodes the key of a `dai devices` or `dai device aliases` row.
pub(super) fn decode_device_key(key: &[u8]) -> Result<(u32, Uuid)> {
    let mut reader = KeyReader::new(key);
    let customer = reader.u32()?;
    let device = reader.uuid()?;
    reader.finish()?;
    Ok((customer, device))
}

/// Decodes the key of a `dai device identifiers` row.
pub(super) fn decode_identifier_key(key: &[u8]) -> Result<(u32, Identifier)> {
    let mut reader = KeyReader::new(key);
    let customer = reader.u32()?;
    let number = reader.byte()?;
    let value = reader.str()?;
    reader.finish()?;
    let kind = IdentifierKind::from_number(number)
        .ok_or_else(|| anyhow::anyhow!("invalid DAI identifier kind {number} in the key"))?;
    Ok((customer, Identifier { kind, value }))
}

/// Decodes the key of a `dai ip state` or `dai fixed ips` row.
pub(super) fn decode_address_key(key: &[u8]) -> Result<(u32, String, IpAddr)> {
    let mut reader = KeyReader::new(key);
    let customer = reader.u32()?;
    let site = reader.str()?;
    let ip = reader.ip()?;
    reader.finish()?;
    Ok((customer, site, ip))
}

pub(super) fn identifier_key(customer: u32, id: &Identifier) -> Vec<u8> {
    KeyWriter::default()
        .u32(customer)
        .byte(id.kind.number())
        .str(&id.value)
        .finish()
}

/// Returns the key prefix of the rows of (customer, site, IP) of the
/// bindings, evidence, IP state and fixed IP tables; it is the whole key of
/// the last two.
pub(super) fn address_key(customer: u32, site: &str, ip: IpAddr) -> Vec<u8> {
    KeyWriter::default().u32(customer).str(site).ip(ip).finish()
}

pub(super) fn binding_key(customer: u32, site: &str, ip: IpAddr, start: i64) -> Vec<u8> {
    KeyWriter::default()
        .u32(customer)
        .str(site)
        .ip(ip)
        .i64(start)
        .finish()
}

/// Decodes the key of a `dai bindings` row.
pub(super) fn decode_binding_key(key: &[u8]) -> Result<(u32, String, IpAddr, i64)> {
    let mut reader = KeyReader::new(key);
    let customer = reader.u32()?;
    let site = reader.str()?;
    let ip = reader.ip()?;
    let start = reader.i64()?;
    reader.finish()?;
    Ok((customer, site, ip, start))
}

pub(super) fn device_binding_key(
    customer: u32,
    device: Uuid,
    site: &str,
    ip: IpAddr,
    start: i64,
) -> Vec<u8> {
    KeyWriter::default()
        .u32(customer)
        .uuid(device)
        .str(site)
        .ip(ip)
        .i64(start)
        .finish()
}

/// Decodes the key of a `dai device bindings` row.
pub(super) fn decode_device_binding_key(key: &[u8]) -> Result<(u32, Uuid, String, IpAddr, i64)> {
    let mut reader = KeyReader::new(key);
    let customer = reader.u32()?;
    let device = reader.uuid()?;
    let site = reader.str()?;
    let ip = reader.ip()?;
    let start = reader.i64()?;
    reader.finish()?;
    Ok((customer, device, site, ip, start))
}

pub(super) fn evidence_key(
    customer: u32,
    site: &str,
    ip: IpAddr,
    last_seen: i64,
    kind: DaiObservationKind,
    hash: &IdHash,
) -> Vec<u8> {
    KeyWriter::default()
        .u32(customer)
        .str(site)
        .ip(ip)
        .i64(last_seen)
        .dai_kind(kind)
        .hash(hash)
        .finish()
}

/// Returns the prefix of the `dai evidence` keys of (`customer`, `site`,
/// `ip`) last seen at `last_seen`, which orders before every such key last
/// seen later.
pub(super) fn evidence_key_prefix(
    customer: u32,
    site: &str,
    ip: IpAddr,
    last_seen: i64,
) -> Vec<u8> {
    KeyWriter::default()
        .u32(customer)
        .str(site)
        .ip(ip)
        .i64(last_seen)
        .finish()
}

/// The decoded key of a `dai evidence` row.
pub(super) struct EvidenceKey {
    pub(super) customer: u32,
    pub(super) site: String,
    pub(super) ip: IpAddr,
    pub(super) last_seen: i64,
    pub(super) kind: DaiObservationKind,
    pub(super) hash: IdHash,
}

/// Decodes the key of a `dai evidence` row.
pub(super) fn decode_evidence_key(key: &[u8]) -> Result<EvidenceKey> {
    let mut reader = KeyReader::new(key);
    let customer = reader.u32()?;
    let site = reader.str()?;
    let ip = reader.ip()?;
    let last_seen = reader.i64()?;
    let kind = reader.dai_kind()?;
    let hash = reader.hash()?;
    reader.finish()?;
    Ok(EvidenceKey {
        customer,
        site,
        ip,
        last_seen,
        kind,
        hash,
    })
}

pub(super) fn service_key(customer: u32, device: Uuid, port: u16, proto: u8) -> Vec<u8> {
    KeyWriter::default()
        .u32(customer)
        .uuid(device)
        .u16(port)
        .byte(proto)
        .finish()
}

/// Decodes the key of a `dai services` row into its device, port and
/// protocol.
pub(super) fn decode_service_key(key: &[u8]) -> Result<(Uuid, u16, u8)> {
    let mut reader = KeyReader::new(key);
    reader.u32()?;
    let device = reader.uuid()?;
    let port = reader.u16()?;
    let proto = reader.byte()?;
    reader.finish()?;
    Ok((device, port, proto))
}

/// Decodes the key of a `dai software strings` row into its device, side,
/// source and text.
pub(super) fn decode_software_key(key: &[u8]) -> Result<(Uuid, u8, u8, String)> {
    let mut reader = KeyReader::new(key);
    reader.u32()?;
    let device = reader.uuid()?;
    let side = reader.byte()?;
    let source = reader.byte()?;
    let text = reader.str()?;
    reader.finish()?;
    Ok((device, side, source, text))
}

/// Returns the key prefix of the rows of `device` in the tables keyed by
/// (customer, device, ...).
pub(super) fn device_prefix(customer: u32, device: Uuid) -> Vec<u8> {
    device_key(customer, device)
}

pub(super) fn software_key(
    customer: u32,
    device: Uuid,
    side: u8,
    source: u8,
    text: &str,
) -> Vec<u8> {
    KeyWriter::default()
        .u32(customer)
        .uuid(device)
        .byte(side)
        .byte(source)
        .str(text)
        .finish()
}

pub(super) fn change_key(customer: u32, device: Uuid, version: u64) -> Vec<u8> {
    KeyWriter::default()
        .u32(customer)
        .uuid(device)
        .u64(version)
        .finish()
}

pub(super) fn resolver_point_key(sensor: &str) -> Vec<u8> {
    sensor_key(sensor)
}

// ---- Reads and writes ----

/// The `dai ip state` row of a (customer, site, IP), read for update, with
/// the value a transaction leaves it at.
pub(crate) struct IpStateLock {
    key: Vec<u8>,
    /// The order key as read.
    pub(crate) stored: Option<OrderKey>,
    /// The order key to leave.
    pub(crate) current: Option<OrderKey>,
}

impl IpStateLock {
    /// Raises the order key to `order` if that is later.
    pub(crate) fn raise(&mut self, order: OrderKey) {
        if self.current.is_none_or(|current| current < order) {
            self.current = Some(order);
        }
    }
}

impl Dai<'_> {
    /// Reads the `dai ip state` row of (`customer`, `site`, `ip`) for update
    /// within `txn`.
    ///
    /// A transaction calls this before it reads the bindings or evidence of
    /// the address, and, if it adds, removes or rewrites one of them, calls
    /// [`write_ip_state`](Self::write_ip_state) before it commits.
    pub(crate) fn lock_ip_state(
        &self,
        txn: &Txn<'_>,
        customer: u32,
        site: &str,
        ip: IpAddr,
    ) -> Result<IpStateLock> {
        let key = address_key(customer, site, ip);
        let stored = Self::get_row(txn, &self.ip_state, &key)?;
        Ok(IpStateLock {
            key,
            stored,
            current: stored,
        })
    }

    /// Writes, within `txn`, the `dai ip state` row `lock` holds, unchanged
    /// if need be, or deletes its key if it holds none, which conflicts like
    /// a put.
    pub(crate) fn write_ip_state(&self, txn: &Txn<'_>, lock: &IpStateLock) -> Result<()> {
        match &lock.current {
            Some(order) => Self::put_row(txn, &self.ip_state, &lock.key, order),
            None => Self::delete_row(txn, &self.ip_state, &lock.key),
        }
    }

    /// Returns the bindings of (`customer`, `site`, `ip`) as `txn` sees
    /// them, keyed by start, each read for update.
    ///
    /// The caller has read the address's IP state for update.
    pub(crate) fn bindings_in(
        &self,
        txn: &Txn<'_>,
        customer: u32,
        site: &str,
        ip: IpAddr,
    ) -> Result<BTreeMap<i64, BindingRow>> {
        let mut bindings = BTreeMap::new();
        for (key, _) in Self::scan(&self.bindings, txn, &address_key(customer, site, ip))? {
            let (_, _, _, start) = decode_binding_key(&key)?;
            if let Some(row) = Self::get_row(txn, &self.bindings, &key)? {
                bindings.insert(start, row);
            }
        }
        Ok(bindings)
    }

    /// Writes, within `txn`, the bindings of (`customer`, `site`, `ip`) as
    /// `current` holds them, given the ones `stored` held, with their reverse
    /// index rows, and returns whether it changed any.
    pub(crate) fn write_bindings(
        &self,
        txn: &Txn<'_>,
        customer: u32,
        site: &str,
        ip: IpAddr,
        stored: &BTreeMap<i64, BindingRow>,
        current: &BTreeMap<i64, BindingRow>,
    ) -> Result<bool> {
        let mut changed = false;
        for (start, old) in stored {
            if !current.contains_key(start) {
                Self::delete_row(
                    txn,
                    &self.bindings,
                    &binding_key(customer, site, ip, *start),
                )?;
                Self::delete_row(
                    txn,
                    &self.device_bindings,
                    &device_binding_key(customer, old.device, site, ip, *start),
                )?;
                changed = true;
            }
        }
        for (start, row) in current {
            let old = stored.get(start);
            if old == Some(row) {
                continue;
            }
            Self::put_row(
                txn,
                &self.bindings,
                &binding_key(customer, site, ip, *start),
                row,
            )?;
            if let Some(old) = old
                && old.device != row.device
            {
                Self::delete_row(
                    txn,
                    &self.device_bindings,
                    &device_binding_key(customer, old.device, site, ip, *start),
                )?;
            }
            if old.is_none_or(|old| old.device != row.device) {
                Self::put_row(
                    txn,
                    &self.device_bindings,
                    &device_binding_key(customer, row.device, site, ip, *start),
                    &(),
                )?;
                self.lock_device(txn, customer, row.device)?;
            }
            changed = true;
        }
        Ok(changed)
    }

    /// Writes back, within `txn`, the `dai devices` row of `device`,
    /// unchanged, if it has one.
    ///
    /// A row of a table keyed by device that a transaction adds (a binding's
    /// reverse index row, a service, a software string, a conflict naming
    /// the device) is found by an untracked scan in a
    /// transaction that moves the device's rows, a merge or a split, which
    /// reads the device row for update. Writing the device row whenever such
    /// a row is added makes the two conflict whichever commits first, so the
    /// retried one sees the row.
    pub(crate) fn lock_device(&self, txn: &Txn<'_>, customer: u32, device: Uuid) -> Result<()> {
        let key = device_key(customer, device);
        if let Some(row) = Self::get_row::<DeviceRow>(txn, &self.devices, &key)? {
            Self::put_row(txn, &self.devices, &key, &row)?;
        }
        Ok(())
    }

    /// Returns the current device the id `device` names within `txn`: the
    /// device itself if it has a `dai devices` row, else the current device
    /// of its alias, or `None` if it names no device. Every row it reads is
    /// read for update.
    pub(crate) fn resolve_device(
        &self,
        txn: &Txn<'_>,
        customer: u32,
        device: Uuid,
    ) -> Result<Option<Uuid>> {
        if self.device_in(txn, customer, device)?.is_some() {
            return Ok(Some(device));
        }
        let Some(alias) =
            Self::get_row::<AliasRow>(txn, &self.aliases, &alias_key(customer, device))?
        else {
            return Ok(None);
        };
        Ok(self
            .device_in(txn, customer, alias.current)?
            .is_some()
            .then_some(alias.current))
    }

    /// Returns the rows of `map` whose keys are in `[from, to)`, as `txn`
    /// sees them, in key order. The scan is not tracked.
    pub(super) fn scan_range(
        map: &Map<'_>,
        txn: &Txn<'_>,
        from: &[u8],
        to: &[u8],
    ) -> Result<Vec<RawRow>> {
        let mut opts = rocksdb::ReadOptions::default();
        opts.set_iterate_range(from.to_vec()..to.to_vec());
        txn.iterator_cf_opt(map.cf, opts, IteratorMode::Start)
            .map(|entry| entry.context("cannot read DAI tables"))
            .collect()
    }

    /// Returns the device `device` of `customer`, read for update within
    /// `txn`, or `None` if there is none.
    pub(crate) fn device_in(
        &self,
        txn: &Txn<'_>,
        customer: u32,
        device: Uuid,
    ) -> Result<Option<DeviceRow>> {
        Self::get_row(txn, &self.devices, &device_key(customer, device))
    }

    /// Returns the identifier row of `id` of `customer`, read for update
    /// within `txn`, or `None` if no device holds it.
    pub(crate) fn identifier_in(
        &self,
        txn: &Txn<'_>,
        customer: u32,
        id: &Identifier,
    ) -> Result<Option<IdentifierRow>> {
        Self::get_row(txn, &self.identifiers, &identifier_key(customer, id))
    }

    pub(crate) fn put_identifier(
        &self,
        txn: &Txn<'_>,
        customer: u32,
        id: &Identifier,
        row: &IdentifierRow,
    ) -> Result<()> {
        Self::put_row(txn, &self.identifiers, &identifier_key(customer, id), row)
    }

    /// Records within `txn` that the second device of `devices` claimed
    /// `id`, which the first holds, in an observation seen from the first to
    /// the second time of `seen`, widening the conflict's devices and times.
    pub(crate) fn record_conflict(
        &self,
        txn: &Txn<'_>,
        customer: u32,
        id: &Identifier,
        devices: [Uuid; 2],
        seen: (i64, i64),
    ) -> Result<()> {
        let (first, last) = seen;
        let key = identifier_key(customer, id);
        let stored: Option<ConflictRow> = Self::get_row(txn, &self.conflicts, &key)?;
        let mut row = stored.clone().unwrap_or(ConflictRow {
            devices: BTreeSet::new(),
            first,
            last,
        });
        for device in devices {
            if row.devices.insert(device) {
                // A merge re-points the devices of every conflict naming an
                // absorbed device, found by an untracked scan.
                self.lock_device(txn, customer, device)?;
            }
        }
        row.first = row.first.min(first);
        row.last = row.last.max(last);
        if stored.as_ref() != Some(&row) {
            Self::put_row(txn, &self.conflicts, &key, &row)?;
        }
        Ok(())
    }
}

// ---- Device edits ----

/// The changes one observation, one retention step or one operator
/// operation makes to one device.
pub(crate) struct DeviceEdit {
    pub(crate) row: DeviceRow,
    /// The kind of the change entry if the change always writes one: a
    /// creation, a merge or a split. Otherwise it writes one of kind changed
    /// if a field changes.
    kind: Option<ChangeKind>,
    /// Whether the change deletes the row: the device was merged away.
    deleted: bool,
    related_device: Option<Uuid>,
    fields: Vec<FieldChange>,
    /// Whether the row differs from the stored one.
    dirty: bool,
}

impl DeviceEdit {
    fn new(row: DeviceRow, created: bool) -> Self {
        Self {
            row,
            kind: created.then_some(ChangeKind::Created),
            deleted: false,
            related_device: None,
            fields: Vec::new(),
            dirty: created,
        }
    }

    fn change(&mut self, path: &str, op: ChangeOp, before: String, after: String) {
        self.fields.push(FieldChange {
            path: path.to_string(),
            op,
            before,
            after,
        });
        self.dirty = true;
    }

    /// Widens the first and last seen times by `[first, last]`, and returns
    /// a device that is not seen to active.
    pub(crate) fn touch(&mut self, first: i64, last: i64) {
        self.widen_seen(Some(first), Some(last));
        if self.row.activity == Activity::NotSeen {
            self.set_activity(Activity::Active);
        }
    }

    /// Widens the first and last seen times by `first` and `last`; a time
    /// the device has none of takes the given one.
    pub(crate) fn widen_seen(&mut self, first: Option<i64>, last: Option<i64>) {
        if let Some(first) = first
            && self.row.first_seen.is_none_or(|seen| first < seen)
        {
            self.row.first_seen = Some(first);
            self.dirty = true;
        }
        if let Some(last) = last
            && self.row.last_seen.is_none_or(|seen| last > seen)
        {
            self.row.last_seen = Some(last);
            self.dirty = true;
        }
    }

    pub(crate) fn set_activity(&mut self, activity: Activity) {
        if self.row.activity == activity {
            return;
        }
        let before = self.row.activity.json();
        self.row.activity = activity;
        self.change("activity", ChangeOp::Set, before, activity.json());
    }

    pub(crate) fn set_verdict(&mut self, verdict: Verdict) {
        if self.row.verdict == verdict {
            return;
        }
        let before = self.row.verdict.json();
        self.row.verdict = verdict;
        self.change("verdict", ChangeOp::Set, before, verdict.json());
    }

    /// Sets the operator asset id field, `None` removing it.
    pub(crate) fn set_asset_id(&mut self, asset_id: Option<&str>) {
        if self.row.operator_asset_id.as_deref() == asset_id {
            return;
        }
        let before = json_text(self.row.operator_asset_id.as_deref().unwrap_or_default());
        self.row.operator_asset_id = asset_id.map(str::to_string);
        self.change(
            "operator_asset_id",
            ChangeOp::Set,
            before,
            json_text(asset_id.unwrap_or_default()),
        );
    }

    /// Sets the memo, an empty one removing it.
    pub(crate) fn set_memo(&mut self, memo: &str) {
        if self.row.memo == memo {
            return;
        }
        let before = json_text(&self.row.memo);
        self.row.memo = memo.to_string();
        self.change("memo", ChangeOp::Set, before, json_text(memo));
    }

    /// Makes `name` the one name of source operator, seen at `seen` if it is
    /// new, or removes every name of that source if it is `None`.
    pub(crate) fn set_operator_name(&mut self, name: Option<&str>, seen: i64) {
        self.remove_names(|held| held.source == NameSource::Operator && Some(&*held.value) != name);
        if let Some(name) = name
            && !self
                .row
                .names
                .iter()
                .any(|held| held.source == NameSource::Operator && held.value == name)
        {
            self.add_name(name, NameSource::Operator, seen);
        }
    }

    /// Adds `id` to the identifiers if the device does not hold it.
    pub(crate) fn add_identifier(&mut self, id: &Identifier) {
        if self.row.identifiers.contains(id) {
            return;
        }
        self.row.identifiers.push(id.clone());
        self.change(
            "identifiers",
            ChangeOp::Add,
            JSON_NULL.to_string(),
            id.json(),
        );
    }

    /// Removes `id` from the identifiers if the device holds it.
    pub(crate) fn remove_identifier(&mut self, id: &Identifier) {
        let before = self.row.identifiers.len();
        self.row.identifiers.retain(|held| held != id);
        if self.row.identifiers.len() != before {
            self.change(
                "identifiers",
                ChangeOp::Remove,
                id.json(),
                JSON_NULL.to_string(),
            );
        }
    }

    /// Adds the name `value` of `source` seen at `seen`, or, if the device
    /// has it, moves its last seen time to `seen` if that is later.
    pub(crate) fn add_name(&mut self, value: &str, source: NameSource, seen: i64) {
        if let Some(name) = self
            .row
            .names
            .iter_mut()
            .find(|name| name.value == value && name.source == source)
        {
            if seen > name.last_seen {
                name.last_seen = seen;
                self.dirty = true;
            }
            return;
        }
        let name = DeviceName {
            value: value.to_string(),
            source,
            last_seen: seen,
        };
        let after = name.json();
        self.row.names.push(name);
        self.change("names", ChangeOp::Add, JSON_NULL.to_string(), after);
    }

    /// Removes the names `expired` selects.
    pub(crate) fn remove_names(&mut self, expired: impl Fn(&DeviceName) -> bool) {
        let (gone, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut self.row.names)
            .into_iter()
            .partition(|name| expired(name));
        self.row.names = kept;
        for name in gone {
            self.change(
                "names",
                ChangeOp::Remove,
                name.json(),
                JSON_NULL.to_string(),
            );
        }
    }

    pub(crate) fn set_dhcp_server(&mut self) {
        if self.row.was_dhcp_server {
            return;
        }
        self.row.was_dhcp_server = true;
        self.change(
            "was_dhcp_server",
            ChangeOp::Set,
            serde_json::Value::from(false).to_string(),
            serde_json::Value::from(true).to_string(),
        );
    }

    /// Names `device` as the other device of the change.
    pub(crate) fn relate(&mut self, device: Uuid) {
        self.related_device = Some(device);
    }

    /// Makes the change a merge or a split with `device`, which writes one
    /// change entry of that kind naming it whatever else changes.
    pub(crate) fn mark(&mut self, kind: ChangeKind, device: Uuid) {
        self.kind = Some(kind);
        self.relate(device);
        self.dirty = true;
    }

    /// Deletes the row when the edits are written, after its change entry.
    pub(crate) fn delete(&mut self) {
        self.deleted = true;
        self.dirty = true;
    }

    /// Sets the fixed IP index, which records no field change.
    pub(crate) fn set_fixed_ips(&mut self, fixed_ips: BTreeSet<(String, IpAddr)>) {
        if self.row.fixed_ips != fixed_ips {
            self.row.fixed_ips = fixed_ips;
            self.dirty = true;
        }
    }
}

/// The devices one observation, one retention step or one operator
/// operation changes, written together by [`flush`](Self::flush).
#[derive(Default)]
pub(crate) struct DeviceEdits {
    edits: BTreeMap<Uuid, DeviceEdit>,
}

impl DeviceEdits {
    /// Returns the edit of `device`, reading the device for update within
    /// `txn` the first time, or `None` if the customer has no such device.
    pub(crate) fn get(
        &mut self,
        dai: &Dai<'_>,
        txn: &Txn<'_>,
        customer: u32,
        device: Uuid,
    ) -> Result<Option<&mut DeviceEdit>> {
        match self.edits.entry(device) {
            Entry::Occupied(entry) => Ok(Some(entry.into_mut())),
            Entry::Vacant(entry) => {
                let Some(row) = dai.device_in(txn, customer, device)? else {
                    return Ok(None);
                };
                Ok(Some(entry.insert(DeviceEdit::new(row, false))))
            }
        }
    }

    /// Returns the edit of `device`, which the caller knows exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the customer has no such device, or the database
    /// operation fails.
    pub(crate) fn existing(
        &mut self,
        dai: &Dai<'_>,
        txn: &Txn<'_>,
        customer: u32,
        device: Uuid,
    ) -> Result<&mut DeviceEdit> {
        self.get(dai, txn, customer, device)?
            .with_context(|| format!("DAI device {device} of customer {customer} has no row"))
    }

    /// Returns a device id that is neither stored nor edited here, read for
    /// update within `txn` with its alias key.
    pub(crate) fn new_id(&self, dai: &Dai<'_>, txn: &Txn<'_>, customer: u32) -> Result<Uuid> {
        loop {
            let device = new_device_id();
            if !self.edits.contains_key(&device)
                && dai.resolve_device(txn, customer, device)?.is_none()
            {
                return Ok(device);
            }
        }
    }

    /// Adds `device`, a new id, as a device of the row `row`; `created`
    /// tells whether its change entry is of kind created.
    pub(crate) fn insert(
        &mut self,
        device: Uuid,
        row: DeviceRow,
        created: bool,
    ) -> &mut DeviceEdit {
        self.edits
            .entry(device)
            .or_insert(DeviceEdit::new(row, created))
    }

    /// Creates a device of origin observation, verdict observed and activity
    /// active holding `id`, created and first and last seen at `time`, and
    /// returns its id and edit.
    pub(crate) fn create(&mut self, id: &Identifier, time: i64) -> (Uuid, &mut DeviceEdit) {
        let device = loop {
            let device = new_device_id();
            if !self.edits.contains_key(&device) {
                break device;
            }
        };
        let mut edit = DeviceEdit::new(
            DeviceRow {
                identifiers: Vec::new(),
                names: Vec::new(),
                was_dhcp_server: false,
                first_seen: Some(time),
                last_seen: Some(time),
                created: time,
                verdict: Verdict::Observed,
                activity: Activity::Active,
                origin: Origin::Observation,
                operator_asset_id: None,
                memo: String::new(),
                fixed_ips: BTreeSet::new(),
                version: 0,
            },
            true,
        );
        edit.add_identifier(id);
        let edit = self.edits.entry(device).or_insert(edit);
        (device, edit)
    }

    /// Writes every edited device within `txn`, each substantive change
    /// incrementing the device's version and writing one change entry of
    /// `source` at `time`, and deletes each device an edit deletes after
    /// writing its entry.
    pub(crate) fn flush(
        self,
        dai: &Dai<'_>,
        txn: &Txn<'_>,
        customer: u32,
        source: ChangeSource,
        time: i64,
    ) -> Result<()> {
        for (device, mut edit) in self.edits {
            if !edit.dirty {
                continue;
            }
            if edit.kind.is_some() || !edit.fields.is_empty() {
                edit.row.version = edit.row.version.wrapping_add(1);
                let entry = ChangeEntry {
                    kind: edit.kind.unwrap_or(ChangeKind::Changed),
                    related_device: edit.related_device,
                    fields: edit.fields,
                    time,
                    source,
                };
                let key = change_key(customer, device, edit.row.version);
                Dai::get_row::<ChangeEntry>(txn, &dai.changes, &key)?;
                Dai::put_row(txn, &dai.changes, &key, &entry)?;
            }
            let key = device_key(customer, device);
            if edit.deleted {
                Dai::delete_row(txn, &dai.devices, &key)?;
            } else {
                Dai::put_row(txn, &dai.devices, &key, &edit.row)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_rules() {
        assert_eq!(
            valid_mac(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf0]).as_deref(),
            Some("aa:bb:cc:dd:ee:f0")
        );
        assert_eq!(
            valid_mac(&[0x02, 0, 0, 0, 0, 1]).as_deref(),
            Some("02:00:00:00:00:01")
        );
        assert_eq!(valid_mac(&[0; 6]), None);
        assert_eq!(valid_mac(&[0xff; 6]), None);
        assert_eq!(valid_mac(&[0x01, 0, 0, 0, 0, 1]), None);
        assert_eq!(valid_mac(&[0xab, 0, 0, 0, 0, 1]), None);
        assert_eq!(valid_mac(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee]), None);
        assert_eq!(valid_mac(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf0, 0]), None);
        assert_eq!(valid_mac(&[]), None);
    }

    #[test]
    fn device_ids_are_v4() {
        let id = new_device_id();
        assert_eq!(id.get_version_num(), 4);
        assert_ne!(id, new_device_id());
        assert_eq!(id.to_string(), id.hyphenated().to_string().to_lowercase());
    }

    #[test]
    fn machine_accounts() {
        let body = |realm: &str, cname: &[&str]| DaiObservationBody::Kerberos {
            client_ip: "10.0.0.1".parse().unwrap(),
            realm: realm.to_string(),
            cname: cname.iter().map(ToString::to_string).collect(),
            sname: Vec::new(),
            msg_type: 11,
            accepted: true,
            preauth: 2,
            error_code: None,
        };
        assert_eq!(
            machine_account(&body("corp.example", &["host1$"])).as_deref(),
            Some("HOST1$@CORP.EXAMPLE")
        );
        assert_eq!(
            machine_account(&body("c", &["a$"])).as_deref(),
            Some("A$@C")
        );
        assert_eq!(machine_account(&body("c", &["$"])), None);
        assert_eq!(machine_account(&body("c", &["host"])), None);
        assert_eq!(machine_account(&body("c", &["host$", "x"])), None);
        assert_eq!(machine_account(&body("c", &[])), None);
    }

    #[test]
    fn owners_by_time() {
        let a = Uuid::from_bytes([1; 16]);
        let b = Uuid::from_bytes([2; 16]);
        let c = Uuid::from_bytes([3; 16]);
        let row = IdentifierRow {
            device: Some(c),
            last_confirmed: 30,
            earlier_owners: vec![
                EarlierOwner {
                    device: a,
                    left: 10,
                },
                EarlierOwner {
                    device: b,
                    left: 20,
                },
            ],
        };
        assert_eq!(row.owner_at(0), Some(a));
        assert_eq!(row.owner_at(9), Some(a));
        assert_eq!(row.owner_at(10), Some(b));
        assert_eq!(row.owner_at(19), Some(b));
        assert_eq!(row.owner_at(20), Some(c));
        assert_eq!(row.owner_at(40), Some(c));
        // Released, no device holds it from then on.
        let mut released = row.clone();
        released.release(30);
        assert_eq!(released.device, None);
        assert_eq!(released.owner_at(29), Some(c));
        assert_eq!(released.owner_at(30), None);
        // A release earlier than the last move ends the holding at the
        // release: the owners before it stay, and none holds it after.
        let mut early = row.clone();
        early.release(15);
        assert_eq!(early.device, None);
        assert_eq!(early.owner_at(9), Some(a));
        assert_eq!(early.owner_at(14), Some(b));
        assert_eq!(early.owner_at(15), None);
        assert_eq!(early.owner_at(25), None);
        assert!(
            early
                .earlier_owners
                .windows(2)
                .all(|w| w[0].left <= w[1].left)
        );
        assert_eq!(
            early.earlier_owners.last().map(|o| (o.device, o.left)),
            Some((c, 15))
        );
        // The next device to take it holds it from the release on.
        let d = Uuid::from_bytes([4; 16]);
        early.device = Some(d);
        assert_eq!(early.owner_at(14), Some(b));
        assert_eq!(early.owner_at(15), Some(d));
        assert_eq!(early.owner_at(25), Some(d));
    }

    #[test]
    fn renaming_owners_keeps_the_owner_at_every_time() {
        let a = Uuid::from_bytes([1; 16]);
        let b = Uuid::from_bytes([2; 16]);
        let s = Uuid::from_bytes([9; 16]);
        let row = IdentifierRow {
            device: Some(b),
            last_confirmed: 30,
            earlier_owners: vec![
                EarlierOwner {
                    device: a,
                    left: 10,
                },
                EarlierOwner {
                    device: s,
                    left: 20,
                },
            ],
        };
        let mut renamed = row.clone();
        assert!(renamed.rename(&BTreeSet::from([a]), s));
        assert_eq!(
            renamed.earlier_owners,
            [EarlierOwner {
                device: s,
                left: 20
            }]
        );
        for time in [0, 15, 25] {
            let expected = row.owner_at(time).map(|d| if d == a { s } else { d });
            assert_eq!(renamed.owner_at(time), expected);
        }
        let mut merged_all = row.clone();
        assert!(merged_all.rename(&BTreeSet::from([a, b]), s));
        assert_eq!(merged_all.device, Some(s));
        assert_eq!(merged_all.earlier_owners, []);
        let mut untouched = row.clone();
        assert!(!untouched.rename(&BTreeSet::from([Uuid::from_bytes([7; 16])]), s));
        assert_eq!(untouched, row);
    }

    #[test]
    fn representative_name_follows_source_then_recency() {
        let name = |value: &str, source, last_seen| DeviceName {
            value: value.to_string(),
            source,
            last_seen,
        };
        let mut row = DeviceRow {
            identifiers: Vec::new(),
            names: vec![
                name("dns-new", NameSource::Dns, 30),
                name("dhcp-old", NameSource::Dhcp, 10),
            ],
            was_dhcp_server: false,
            first_seen: Some(0),
            last_seen: Some(0),
            created: 0,
            verdict: Verdict::Observed,
            activity: Activity::Active,
            origin: Origin::Observation,
            operator_asset_id: None,
            memo: String::new(),
            fixed_ips: BTreeSet::new(),
            version: 1,
        };
        assert_eq!(row.representative_name(), Some("dhcp-old"));
        row.names.push(name("dhcp-new", NameSource::Dhcp, 20));
        assert_eq!(row.representative_name(), Some("dhcp-new"));
        row.names.push(name("operator", NameSource::Operator, 0));
        assert_eq!(row.representative_name(), Some("operator"));
        row.names.clear();
        assert_eq!(row.representative_name(), None);
    }

    #[test]
    fn order_keys_rank_o1_messages_then_kinds() {
        use review_protocol::types::DaiDhcpMsg;
        let lease = |msg| DaiObservationBody::DhcpLease {
            time: 5,
            msg,
            ip: "10.0.0.1".parse().unwrap(),
            chaddr: vec![2, 0, 0, 0, 0, 1],
            xid: 1,
            server_ip: "10.0.0.254".parse().unwrap(),
            server_id: None,
            giaddr: "0.0.0.0".parse().unwrap(),
            client_id: None,
            hostname: None,
            lease_secs: None,
            subnet_mask: None,
            routers: Vec::new(),
        };
        let hash = [0; 16];
        let keys: Vec<OrderKey> = [
            lease(DaiDhcpMsg::Decline),
            lease(DaiDhcpMsg::Release),
            lease(DaiDhcpMsg::Ack),
            lease(DaiDhcpMsg::InformAck),
            DaiObservationBody::DhcpServer {
                server_ip: "10.0.0.254".parse().unwrap(),
                server_id: None,
            },
            DaiObservationBody::DnsName {
                name: "x".to_string(),
                ip: "10.0.0.1".parse().unwrap(),
            },
        ]
        .iter()
        .map(|body| OrderKey::of(body, 5, &hash))
        .collect();
        assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));
        // The O1 time, not the first seen time, orders an O1.
        assert_eq!(OrderKey::of(&lease(DaiDhcpMsg::Ack), 0, &hash).time, 5);
    }
}
