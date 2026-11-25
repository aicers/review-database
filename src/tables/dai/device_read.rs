//! The device reads of device identification: the device list, the IP
//! device rows, the device detail and search.

use std::{collections::BTreeSet, net::IpAddr};

use anyhow::{Context, Result};
use ipnet::IpNet;
use review_protocol::types::{DaiObservationKind, DaiSide, DaiSoftwareSource};
use uuid::Uuid;

use super::{
    Dai, DaiIdentifier, DaiRead, DaiVerdict, KeyReader, Snapshot,
    apply::{side_number, software_source_number},
    cursor::DAY,
    customer_key,
    device::{
        Activity, AliasReason, AliasRow, BindingRow, ChangeEntry, ChangeKind, ChangeOp,
        ChangeSource, DeviceRow, FixedIpRow, Identifier, IdentifierKind, IdentifierRow, NameSource,
        Origin, SeenTimes, ServiceRow, Verdict, address_key, binding_key, decode_address_key,
        decode_device_binding_key, decode_device_key, decode_service_key, decode_software_key,
        device_key, device_prefix, identifier_key,
    },
    kind_from_number,
    observation::ActivityRow,
    view::{CustomerView, in_effect_at, reported_end},
};

/// How long an IP device row stays listed after its last seen time: 30
/// days.
const IP_DEVICE_DAYS: i64 = 30 * DAY;
/// How long after its last seen time a service is shown as not seen: 30
/// days.
const SERVICE_NOT_SEEN_AFTER: i64 = 30 * DAY;
/// The most matches one search returns.
pub const DAI_SEARCH_MAX_MATCHES: usize = 100;

/// Whether a device is seen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaiActivity {
    /// Seen within the last 90 days, or not expired yet.
    Active,
    /// Not seen for 90 days.
    NotSeen,
    /// Hidden by an operator.
    Hidden,
}

impl From<Activity> for DaiActivity {
    fn from(activity: Activity) -> Self {
        match activity {
            Activity::Active => Self::Active,
            Activity::NotSeen => Self::NotSeen,
            Activity::Hidden => Self::Hidden,
        }
    }
}

impl From<Verdict> for DaiVerdict {
    fn from(verdict: Verdict) -> Self {
        match verdict {
            Verdict::Observed => Self::Observed,
            Verdict::Confirmed => Self::Confirmed,
            Verdict::Ignored => Self::Ignored,
        }
    }
}

/// How a device came to be.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaiOrigin {
    /// Created by an observation.
    Observation,
    /// Created by an operator import.
    Import,
}

impl From<Origin> for DaiOrigin {
    fn from(origin: Origin) -> Self {
        match origin {
            Origin::Observation => Self::Observation,
            Origin::Import => Self::Import,
        }
    }
}

/// The source of a name of a device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaiNameSource {
    /// A DNS name resolved to the device's address.
    Dns,
    /// A DHCP hostname.
    Dhcp,
    /// A name an operator set.
    Operator,
}

impl From<NameSource> for DaiNameSource {
    fn from(source: NameSource) -> Self {
        match source {
            NameSource::Dns => Self::Dns,
            NameSource::Dhcp => Self::Dhcp,
            NameSource::Operator => Self::Operator,
        }
    }
}

/// Why a device id became an alias of another.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaiAliasReason {
    /// The device was merged into the current one.
    Merged,
    /// An import replaced the device by the current one.
    Imported,
}

impl From<AliasReason> for DaiAliasReason {
    fn from(reason: AliasReason) -> Self {
        match reason {
            AliasReason::Merged => Self::Merged,
            AliasReason::Imported => Self::Imported,
        }
    }
}

/// The kind of a device change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaiChangeKind {
    Created,
    Changed,
    Merged,
    Split,
}

impl From<ChangeKind> for DaiChangeKind {
    fn from(kind: ChangeKind) -> Self {
        match kind {
            ChangeKind::Created => Self::Created,
            ChangeKind::Changed => Self::Changed,
            ChangeKind::Merged => Self::Merged,
            ChangeKind::Split => Self::Split,
        }
    }
}

/// The operation of a changed field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaiChangeOp {
    Set,
    Add,
    Remove,
}

impl From<ChangeOp> for DaiChangeOp {
    fn from(op: ChangeOp) -> Self {
        match op {
            ChangeOp::Set => Self::Set,
            ChangeOp::Add => Self::Add,
            ChangeOp::Remove => Self::Remove,
        }
    }
}

/// What made a device change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaiChangeSource {
    /// An observation of the kind; `None` for a kind number no kind has.
    Observation(Option<DaiObservationKind>),
    /// An operator import.
    Import,
    /// Another operator operation.
    Operator,
    /// Retention.
    Expiry,
}

impl From<ChangeSource> for DaiChangeSource {
    fn from(source: ChangeSource) -> Self {
        match source {
            ChangeSource::Observation(number) => Self::Observation(kind_from_number(number)),
            ChangeSource::Import => Self::Import,
            ChangeSource::Operator => Self::Operator,
            ChangeSource::Expiry => Self::Expiry,
        }
    }
}

/// A closed time range, `[from, to]`, in nanoseconds since the UNIX epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaiTimeRange {
    pub from: i64,
    pub to: i64,
}

impl DaiTimeRange {
    /// Returns whether `[first, last]` overlaps the range.
    fn overlaps(self, first: i64, last: i64) -> bool {
        first <= self.to && last >= self.from
    }
}

/// The direction a page is read in from its starting key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaiPageDirection {
    /// The rows after the starting key, in order.
    Forward,
    /// The rows before the starting key, the nearest ones, returned in
    /// order.
    Backward,
}

/// A page to read: up to `limit` rows from the key `from`, exclusive, in
/// `direction`; with no key, from the first row forward or the last row
/// backward.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiPageRequest<K> {
    pub from: Option<K>,
    pub direction: DaiPageDirection,
    pub limit: usize,
}

/// A page of rows, in order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiPage<T> {
    pub rows: Vec<T>,
    /// Whether more matching rows lie beyond the page in its direction.
    pub has_more: bool,
    /// The number of matching rows, on every page.
    pub total: usize,
}

/// Returns the page `request` selects of `rows`, which are in key order.
fn page<K: Ord, T>(rows: Vec<(K, T)>, request: &DaiPageRequest<K>) -> DaiPage<T> {
    let total = rows.len();
    let limit = request.limit;
    match request.direction {
        DaiPageDirection::Forward => {
            let mut after: Vec<T> = rows
                .into_iter()
                .filter(|(key, _)| request.from.as_ref().is_none_or(|from| key > from))
                .map(|(_, row)| row)
                .collect();
            let has_more = after.len() > limit;
            after.truncate(limit);
            DaiPage {
                rows: after,
                has_more,
                total,
            }
        }
        DaiPageDirection::Backward => {
            let mut before: Vec<T> = rows
                .into_iter()
                .filter(|(key, _)| request.from.as_ref().is_none_or(|from| key < from))
                .map(|(_, row)| row)
                .collect();
            let has_more = before.len() > limit;
            let rows = before.split_off(before.len().saturating_sub(limit));
            DaiPage {
                rows,
                has_more,
                total,
            }
        }
    }
}

/// The filter of the device list; each field absent matches every device.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DaiDeviceFilter {
    /// The site tokens; matched against the device's current IPs, or its
    /// latest binding when it has none.
    pub sites: Option<Vec<String>>,
    pub verdicts: Option<Vec<DaiVerdict>>,
    pub activities: Option<Vec<DaiActivity>>,
    /// A network; matched like `sites`, a location matching both when both
    /// are given.
    pub network: Option<IpNet>,
    /// Matches a device whose `[first seen, last seen]` overlaps it; a
    /// device with no seen times never matches.
    pub seen: Option<DaiTimeRange>,
}

/// An IP address a device holds now.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiCurrentIp {
    pub site: String,
    pub ip: IpAddr,
    /// The start of the binding in effect now.
    pub start: i64,
}

/// A binding of a device, with its end as reads report it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiBindingSpan {
    pub site: String,
    pub ip: IpAddr,
    pub start: i64,
    /// The effective end; `None` while the binding is open.
    pub end: Option<i64>,
    /// Whether `end` is an estimate rather than a stored close.
    pub end_estimated: bool,
}

/// A row of the device list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiDeviceListRow {
    pub device: Uuid,
    pub verdict: DaiVerdict,
    pub activity: DaiActivity,
    pub representative_name: Option<String>,
    /// `None` for a device no observation has applied to.
    pub first_seen: Option<i64>,
    pub last_seen: Option<i64>,
    /// The bindings in effect now, ordered by site, IP and start.
    pub current_ips: Vec<DaiCurrentIp>,
    /// The binding with the latest start, for a device with no current IP
    /// that has a binding.
    pub latest_binding: Option<DaiBindingSpan>,
}

/// The filter of the IP device rows; each field absent matches every row.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DaiIpDeviceFilter {
    pub sites: Option<Vec<String>>,
    pub network: Option<IpNet>,
    /// Matches a row whose `[first seen, last seen]` overlaps it.
    pub seen: Option<DaiTimeRange>,
}

/// An address active with no device: a `dai ip activity` row with no
/// binding in effect at its last seen time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiIpDeviceRow {
    pub site: String,
    pub ip: IpAddr,
    pub first_seen: i64,
    pub last_seen: i64,
}

/// A strong identifier a device holds, with when it was last confirmed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiDeviceIdentifier {
    pub identifier: DaiIdentifier,
    /// `None` if the identifier has no ownership row.
    pub last_confirmed: Option<i64>,
}

/// A name of a device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiDeviceName {
    pub value: String,
    pub source: DaiNameSource,
    pub last_seen: i64,
}

/// A binding in a device's IP history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiDeviceBinding {
    pub site: String,
    pub ip: IpAddr,
    pub start: i64,
    /// The effective end; `None` while the binding is open.
    pub end: Option<i64>,
    pub end_estimated: bool,
    /// The kind of the observation that started it; `None` for a kind
    /// number no kind has.
    pub evidence_kind: Option<DaiObservationKind>,
    /// The identifier that observation bound.
    pub evidence_identifier: DaiIdentifier,
}

/// A service of a device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiService {
    pub port: u16,
    /// The IP protocol number.
    pub protocol: u8,
    pub external_client: bool,
    pub first_seen: i64,
    pub last_seen: i64,
    /// Whether an operator removed it.
    pub removed: bool,
    /// Whether it was last seen more than 30 days before now.
    pub not_seen: bool,
}

/// A software string of a device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiSoftware {
    pub side: DaiSide,
    pub source: DaiSoftwareSource,
    pub text: String,
    pub first_seen: i64,
    pub last_seen: i64,
}

/// A field a device change changed, its values as JSON text, `null` for
/// none.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiFieldChange {
    pub path: String,
    pub op: DaiChangeOp,
    pub before: String,
    pub after: String,
}

/// An entry of a device's change history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiDeviceChange {
    /// The device version the change made.
    pub version: u64,
    pub kind: DaiChangeKind,
    /// The other device of the change, as its current device id. A merge
    /// entry therefore names the device itself; the absorbed ids are in
    /// the detail's aliases.
    pub related_device: Option<Uuid>,
    pub fields: Vec<DaiFieldChange>,
    pub time: i64,
    pub source: DaiChangeSource,
}

/// An old device id that now names the device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiDeviceAlias {
    pub device: Uuid,
    /// When it became an alias.
    pub time: i64,
    pub reason: DaiAliasReason,
}

/// A device in detail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiDeviceDetail {
    /// The id asked for.
    pub requested: Uuid,
    /// The current device id.
    pub device: Uuid,
    /// Whether `requested` is an old id followed through its alias.
    pub alias_followed: bool,
    /// The identifiers the device holds, machine accounts included, in the
    /// order they were added.
    pub identifiers: Vec<DaiDeviceIdentifier>,
    pub names: Vec<DaiDeviceName>,
    pub representative_name: Option<String>,
    pub was_dhcp_server: bool,
    pub verdict: DaiVerdict,
    pub activity: DaiActivity,
    pub origin: DaiOrigin,
    pub operator_asset_id: Option<String>,
    /// Empty for none.
    pub memo: String,
    pub version: u64,
    pub first_seen: Option<i64>,
    pub last_seen: Option<i64>,
    /// The addresses fixed to the device, as (site token, IP), in order.
    pub fixed_ips: Vec<(String, IpAddr)>,
    /// Every binding of the device, newest start first.
    pub ip_history: Vec<DaiDeviceBinding>,
    /// Ordered by port and protocol.
    pub services: Vec<DaiService>,
    pub software: Vec<DaiSoftware>,
    /// In version order.
    pub changes: Vec<DaiDeviceChange>,
    /// The old ids aliased to it, ordered by time and then id.
    pub aliases: Vec<DaiDeviceAlias>,
}

/// What a search text matched.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaiSearchMatchKind {
    Ip,
    Mac,
    AssetId,
    DeviceId,
    OldDeviceId,
    Name,
}

/// What a search match names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DaiSearchTarget {
    /// A current device id.
    Device(Uuid),
    /// An address active with no binding in effect at its last seen time.
    IpDevice {
        site: String,
        ip: IpAddr,
        last_seen: i64,
    },
}

/// One search match.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiSearchMatch {
    pub matched: DaiSearchMatchKind,
    pub target: DaiSearchTarget,
}

/// The result of a search.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DaiSearchResult {
    /// At most [`DAI_SEARCH_MAX_MATCHES`] matches.
    pub matches: Vec<DaiSearchMatch>,
    /// Whether more matches were found than returned.
    pub truncated: bool,
}

/// A binding of a device as the reads hold it: (site, IP, start, row).
type DeviceBinding = (String, IpAddr, i64, BindingRow);

/// Returns whether a location (site, IP) matches the site and network
/// filters.
fn location_matches(
    sites: Option<&[String]>,
    network: Option<&IpNet>,
    site: &str,
    ip: IpAddr,
) -> bool {
    sites.is_none_or(|sites| sites.iter().any(|s| s == site))
        && network.is_none_or(|network| network.contains(&ip))
}

/// Returns the MAC address `text` spells as `aa:bb:cc:dd:ee:ff`,
/// `aa-bb-cc-dd-ee-ff` or `aabb.ccdd.eeff`, in any case, as lowercase
/// colon-separated hex, or `None` if it spells none.
fn parse_mac(text: &str) -> Option<String> {
    let groups: Vec<&str> = if text.contains(':') {
        text.split(':').collect()
    } else if text.contains('-') {
        text.split('-').collect()
    } else {
        text.split('.').collect()
    };
    let group_len = match groups.len() {
        6 => 2,
        3 if text.contains('.') => 4,
        _ => return None,
    };
    let mut hex = String::with_capacity(12);
    for group in groups {
        if group.len() != group_len || !group.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        hex.push_str(&group.to_ascii_lowercase());
    }
    let pairs: Vec<&str> = (0..6).filter_map(|i| hex.get(i * 2..i * 2 + 2)).collect();
    Some(pairs.join(":"))
}

/// Returns the side whose `dai software strings` key byte is `number`.
fn side_from_number(number: u8) -> Option<DaiSide> {
    [DaiSide::Client, DaiSide::Server]
        .into_iter()
        .find(|side| side_number(*side) == number)
}

/// Returns the source whose `dai software strings` key byte is `number`.
fn source_from_number(number: u8) -> Option<DaiSoftwareSource> {
    [
        DaiSoftwareSource::Ssh,
        DaiSoftwareSource::HttpUserAgent,
        DaiSoftwareSource::TlsCertSubject,
    ]
    .into_iter()
    .find(|source| software_source_number(*source) == number)
}

impl Dai<'_> {
    /// Returns the customer's devices as `snapshot` holds them, in id
    /// order.
    fn devices_in(&self, snapshot: &Snapshot<'_>, customer: u32) -> Result<Vec<(Uuid, DeviceRow)>> {
        Self::scan(&self.devices, snapshot, &customer_key(customer))?
            .into_iter()
            .map(|(key, value)| {
                let (_, device) = decode_device_key(&key)?;
                Ok((device, super::super::deserialize(&value)?))
            })
            .collect()
    }

    /// Returns every binding of `device` as `snapshot` holds it, ordered by
    /// site, IP and start.
    fn device_bindings_in(
        &self,
        snapshot: &Snapshot<'_>,
        customer: u32,
        device: Uuid,
    ) -> Result<Vec<DeviceBinding>> {
        let mut bindings = Vec::new();
        for (key, _) in Self::scan(
            &self.device_bindings,
            snapshot,
            &device_prefix(customer, device),
        )? {
            let (_, _, site, ip, start) = decode_device_binding_key(&key)?;
            if let Some(row) = Self::value_in::<BindingRow>(
                snapshot,
                &self.bindings,
                &binding_key(customer, &site, ip, start),
            )? {
                bindings.push((site, ip, start, row));
            }
        }
        Ok(bindings)
    }

    /// Returns the customer's devices that match `filter`, at `now`, as the
    /// page `request` selects, as
    /// [`Store::dai_devices`](crate::Store::dai_devices) describes.
    pub(crate) fn device_list(
        &self,
        customer: u32,
        filter: &DaiDeviceFilter,
        request: &DaiPageRequest<Uuid>,
        now: i64,
    ) -> Result<DaiPage<DaiDeviceListRow>> {
        let snapshot = self.db.snapshot();
        // A starting id is followed through its alias like any other device
        // id, so a page from an old id starts where the current device is.
        let request = DaiPageRequest {
            from: request
                .from
                .map(|from| self.current_or_same(&snapshot, customer, from))
                .transpose()?,
            direction: request.direction,
            limit: request.limit,
        };
        let sites = filter.sites.as_deref();
        let network = filter.network.as_ref();
        let mut rows = Vec::new();
        for (device, row) in self.devices_in(&snapshot, customer)? {
            let verdict = DaiVerdict::from(row.verdict);
            let activity = DaiActivity::from(row.activity);
            if filter
                .verdicts
                .as_ref()
                .is_some_and(|verdicts| !verdicts.contains(&verdict))
                || filter
                    .activities
                    .as_ref()
                    .is_some_and(|activities| !activities.contains(&activity))
            {
                continue;
            }
            if let Some(range) = filter.seen {
                let (Some(first), Some(last)) = (row.first_seen, row.last_seen) else {
                    continue;
                };
                if !range.overlaps(first, last) {
                    continue;
                }
            }
            let bindings = self.device_bindings_in(&snapshot, customer, device)?;
            let current_ips: Vec<DaiCurrentIp> = bindings
                .iter()
                .filter(|(_, _, start, row)| in_effect_at(*start, row, now))
                .map(|(site, ip, start, _)| DaiCurrentIp {
                    site: site.clone(),
                    ip: *ip,
                    start: *start,
                })
                .collect();
            let latest_binding = if current_ips.is_empty() {
                bindings
                    .iter()
                    .max_by(|a, b| (a.2, &a.0, a.1).cmp(&(b.2, &b.0, b.1)))
                    .map(|(site, ip, start, row)| {
                        let (end, end_estimated) = reported_end(row, now);
                        DaiBindingSpan {
                            site: site.clone(),
                            ip: *ip,
                            start: *start,
                            end,
                            end_estimated,
                        }
                    })
            } else {
                None
            };
            if sites.is_some() || network.is_some() {
                let matched = if current_ips.is_empty() {
                    latest_binding
                        .as_ref()
                        .is_some_and(|b| location_matches(sites, network, &b.site, b.ip))
                } else {
                    current_ips
                        .iter()
                        .any(|c| location_matches(sites, network, &c.site, c.ip))
                };
                if !matched {
                    continue;
                }
            }
            rows.push((
                device,
                DaiDeviceListRow {
                    device,
                    verdict,
                    activity,
                    representative_name: row.representative_name().map(str::to_string),
                    first_seen: row.first_seen,
                    last_seen: row.last_seen,
                    current_ips,
                    latest_binding,
                },
            ));
        }
        Ok(page(rows, &request))
    }

    /// Returns the customer's IP device rows that match `filter`, at `now`,
    /// as the page `request` selects, as
    /// [`Store::dai_ip_only_devices`](crate::Store::dai_ip_only_devices)
    /// describes.
    pub(crate) fn ip_device_list(
        &self,
        customer: u32,
        filter: &DaiIpDeviceFilter,
        request: &DaiPageRequest<(String, IpAddr)>,
        now: i64,
    ) -> Result<DaiPage<DaiIpDeviceRow>> {
        let snapshot = self.db.snapshot();
        let oldest = now.saturating_sub(IP_DEVICE_DAYS);
        let mut rows = Vec::new();
        for (key, value) in Self::scan(&self.ip_activity, &snapshot, &customer_key(customer))? {
            let (_, site, ip) = decode_address_key(&key)?;
            let activity: ActivityRow = super::super::deserialize(&value)?;
            if !(oldest..=now).contains(&activity.last_seen)
                || !location_matches(filter.sites.as_deref(), filter.network.as_ref(), &site, ip)
                || filter
                    .seen
                    .is_some_and(|range| !range.overlaps(activity.first_seen, activity.last_seen))
            {
                continue;
            }
            if self.bound_at(&snapshot, customer, &site, ip, activity.last_seen)? {
                continue;
            }
            rows.push((
                (site.clone(), ip),
                DaiIpDeviceRow {
                    site,
                    ip,
                    first_seen: activity.first_seen,
                    last_seen: activity.last_seen,
                },
            ));
        }
        rows.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        Ok(page(rows, request))
    }

    /// Returns whether a binding of (`customer`, `site`, `ip`) is in effect
    /// at `time` as `snapshot` holds them.
    fn bound_at(
        &self,
        snapshot: &Snapshot<'_>,
        customer: u32,
        site: &str,
        ip: IpAddr,
        time: i64,
    ) -> Result<bool> {
        Ok(self
            .address_bindings(snapshot, customer, site, ip)?
            .iter()
            .any(|(start, row)| in_effect_at(*start, row, time)))
    }

    /// Returns the current device `device` names, in detail, at `now`, or
    /// `None` if it names no device of the customer, as
    /// [`Store::dai_device`](crate::Store::dai_device) describes.
    pub(crate) fn device_detail(
        &self,
        customer: u32,
        device: Uuid,
        now: i64,
    ) -> Result<Option<DaiDeviceDetail>> {
        let snapshot = self.db.snapshot();
        let Some(current) = self.current_device_in(&snapshot, customer, device)? else {
            return Ok(None);
        };
        let Some(row) =
            Self::value_in::<DeviceRow>(&snapshot, &self.devices, &device_key(customer, current))?
        else {
            return Ok(None);
        };

        let mut identifiers = Vec::with_capacity(row.identifiers.len());
        for id in &row.identifiers {
            let held: Option<IdentifierRow> =
                Self::value_in(&snapshot, &self.identifiers, &identifier_key(customer, id))?;
            identifiers.push(DaiDeviceIdentifier {
                identifier: DaiIdentifier::from(id),
                last_confirmed: held.map(|held| held.last_confirmed),
            });
        }

        let mut ip_history: Vec<DaiDeviceBinding> = self
            .device_bindings_in(&snapshot, customer, current)?
            .into_iter()
            .map(|(site, ip, start, binding)| {
                let (end, end_estimated) = reported_end(&binding, now);
                DaiDeviceBinding {
                    site,
                    ip,
                    start,
                    end,
                    end_estimated,
                    evidence_kind: kind_from_number(binding.evidence_kind),
                    evidence_identifier: DaiIdentifier::from(&binding.evidence_identifier),
                }
            })
            .collect();
        ip_history.sort_unstable_by(|a, b| {
            b.start
                .cmp(&a.start)
                .then_with(|| a.site.cmp(&b.site))
                .then_with(|| a.ip.cmp(&b.ip))
        });

        let prefix = device_prefix(customer, current);
        let (services, software) = self.device_services(&snapshot, &prefix, now)?;
        let (changes, aliases) = self.device_history(&snapshot, customer, current, &prefix)?;

        Ok(Some(DaiDeviceDetail {
            requested: device,
            device: current,
            alias_followed: current != device,
            identifiers,
            names: row
                .names
                .iter()
                .map(|name| DaiDeviceName {
                    value: name.value.clone(),
                    source: name.source.into(),
                    last_seen: name.last_seen,
                })
                .collect(),
            representative_name: row.representative_name().map(str::to_string),
            was_dhcp_server: row.was_dhcp_server,
            verdict: row.verdict.into(),
            activity: row.activity.into(),
            origin: row.origin.into(),
            operator_asset_id: row.operator_asset_id.clone(),
            memo: row.memo.clone(),
            version: row.version,
            first_seen: row.first_seen,
            last_seen: row.last_seen,
            fixed_ips: row.fixed_ips.iter().cloned().collect(),
            ip_history,
            services,
            software,
            changes,
            aliases,
        }))
    }

    /// Returns the services and software strings of the device whose rows
    /// have the key prefix `prefix`, each service not seen when last seen
    /// more than 30 days before `now`.
    fn device_services(
        &self,
        snapshot: &Snapshot<'_>,
        prefix: &[u8],
        now: i64,
    ) -> Result<(Vec<DaiService>, Vec<DaiSoftware>)> {
        let not_seen_before = now.saturating_sub(SERVICE_NOT_SEEN_AFTER);
        let mut services = Vec::new();
        for (key, value) in Self::scan(&self.services, snapshot, prefix)? {
            let (_, port, protocol) = decode_service_key(&key)?;
            let service: ServiceRow = super::super::deserialize(&value)?;
            services.push(DaiService {
                port,
                protocol,
                external_client: service.external_client,
                first_seen: service.first_seen,
                last_seen: service.last_seen,
                removed: service.removed,
                not_seen: service.last_seen < not_seen_before,
            });
        }
        let mut software = Vec::new();
        for (key, value) in Self::scan(&self.software, snapshot, prefix)? {
            let (_, side, source, text) = decode_software_key(&key)?;
            let times: SeenTimes = super::super::deserialize(&value)?;
            software.push(DaiSoftware {
                side: side_from_number(side)
                    .with_context(|| format!("invalid DAI software side {side}"))?,
                source: source_from_number(source)
                    .with_context(|| format!("invalid DAI software source {source}"))?,
                text,
                first_seen: times.first_seen,
                last_seen: times.last_seen,
            });
        }
        Ok((services, software))
    }

    /// Returns the change history of `current`, whose rows have the key
    /// prefix `prefix`, and the old ids aliased to it.
    fn device_history(
        &self,
        snapshot: &Snapshot<'_>,
        customer: u32,
        current: Uuid,
        prefix: &[u8],
    ) -> Result<(Vec<DaiDeviceChange>, Vec<DaiDeviceAlias>)> {
        let mut changes = Vec::new();
        for (key, value) in Self::scan(&self.changes, snapshot, prefix)? {
            let mut reader = KeyReader::new(&key);
            reader.u32()?;
            reader.uuid()?;
            let version = reader.u64()?;
            reader.finish()?;
            let entry: ChangeEntry = super::super::deserialize(&value)?;
            let related_device = entry
                .related_device
                .map(|device| self.current_or_same(snapshot, customer, device))
                .transpose()?;
            changes.push(DaiDeviceChange {
                version,
                kind: entry.kind.into(),
                related_device,
                fields: entry
                    .fields
                    .into_iter()
                    .map(|field| DaiFieldChange {
                        path: field.path,
                        op: field.op.into(),
                        before: field.before,
                        after: field.after,
                    })
                    .collect(),
                time: entry.time,
                source: entry.source.into(),
            });
        }
        let mut aliases = Vec::new();
        for (key, value) in Self::scan(&self.aliases, snapshot, &customer_key(customer))? {
            let alias: AliasRow = super::super::deserialize(&value)?;
            if alias.current == current {
                let (_, old) = decode_device_key(&key)?;
                aliases.push(DaiDeviceAlias {
                    device: old,
                    time: alias.time,
                    reason: alias.reason.into(),
                });
            }
        }
        aliases.sort_unstable_by_key(|alias| (alias.time, alias.device));
        Ok((changes, aliases))
    }

    /// Searches the customer's devices and IP device rows for `text`, as
    /// [`Store::dai_search`](crate::Store::dai_search) describes.
    pub(crate) fn search(&self, customer: u32, text: &str, now: i64) -> Result<DaiSearchResult> {
        if text.is_empty() {
            return Ok(DaiSearchResult::default());
        }
        let snapshot = self.db.snapshot();
        let view = self.customer_view(&snapshot, customer)?;
        let mut found = Found::default();
        // An operator asset id is stored as imported, surrounding spaces
        // included, so it is matched against the text as given; every
        // other rule takes the text trimmed.
        let given = text;
        let text = text.trim();

        if let Ok(ip) = text.parse::<IpAddr>() {
            self.search_ip(&snapshot, &view, ip, now, &mut found)?;
        }
        if let Some(mac) = parse_mac(text) {
            self.search_identifier(&snapshot, customer, &Identifier::mac(&mac), &mut found)?;
        }
        self.search_identifier(
            &snapshot,
            customer,
            &Identifier {
                kind: IdentifierKind::OperatorAssetId,
                value: given.to_string(),
            },
            &mut found,
        )?;
        if text.is_empty() {
            return Ok(found.finish());
        }
        if let Ok(id) = Uuid::parse_str(text) {
            if snapshot
                .value(&self.devices, &device_key(customer, id))
                .context("cannot read DAI devices")?
                .is_some()
            {
                found.push(DaiSearchMatchKind::DeviceId, DaiSearchTarget::Device(id));
            } else if let Some(current) = self.current_device_in(&snapshot, customer, id)? {
                found.push(
                    DaiSearchMatchKind::OldDeviceId,
                    DaiSearchTarget::Device(current),
                );
            }
        }
        let needle = text.to_lowercase();
        for (device, row) in self.devices_in(&snapshot, customer)? {
            if row
                .names
                .iter()
                .any(|name| name.value.to_lowercase().contains(&needle))
            {
                found.push(DaiSearchMatchKind::Name, DaiSearchTarget::Device(device));
            }
        }
        Ok(found.finish())
    }

    /// Adds the matches of the IP `ip` to `found`: the devices with a
    /// binding or a fixed IP at it in any site, removed sites included, and
    /// its IP device rows at `now`.
    fn search_ip(
        &self,
        snapshot: &Snapshot<'_>,
        view: &CustomerView,
        ip: IpAddr,
        now: i64,
        found: &mut Found,
    ) -> Result<()> {
        let customer = view.customer;
        let oldest = now.saturating_sub(IP_DEVICE_DAYS);
        // Every site a row of the IP may be stored under: the stored sites
        // and any token the address-keyed tables still hold, such as that
        // of a site removed after its bindings were made.
        let mut sites: BTreeSet<String> =
            view.sites.iter().map(|site| site.token.clone()).collect();
        for map in [&self.bindings, &self.fixed_ips, &self.ip_activity] {
            sites.extend(Self::sites_of_rows(snapshot, map, customer)?);
        }
        let mut ip_rows = Vec::new();
        for site in &sites {
            let key = address_key(customer, site, ip);
            let bindings = self.address_bindings(snapshot, customer, site, ip)?;
            let mut devices = BTreeSet::new();
            for (_, row) in &bindings {
                devices.insert(self.current_or_same(snapshot, customer, row.device)?);
            }
            if let Some(fixed) = Self::value_in::<FixedIpRow>(snapshot, &self.fixed_ips, &key)? {
                devices.insert(self.current_or_same(snapshot, customer, fixed)?);
            }
            for device in devices {
                found.push(DaiSearchMatchKind::Ip, DaiSearchTarget::Device(device));
            }
            if let Some(activity) =
                Self::value_in::<ActivityRow>(snapshot, &self.ip_activity, &key)?
                && (oldest..=now).contains(&activity.last_seen)
                && !bindings
                    .iter()
                    .any(|(start, row)| in_effect_at(*start, row, activity.last_seen))
            {
                ip_rows.push(DaiSearchTarget::IpDevice {
                    site: site.clone(),
                    ip,
                    last_seen: activity.last_seen,
                });
            }
        }
        for target in ip_rows {
            found.push(DaiSearchMatchKind::Ip, target);
        }
        Ok(())
    }

    /// Adds the device holding `id` now, if any, to `found`.
    fn search_identifier(
        &self,
        snapshot: &Snapshot<'_>,
        customer: u32,
        id: &Identifier,
        found: &mut Found,
    ) -> Result<()> {
        let held: Option<IdentifierRow> =
            Self::value_in(snapshot, &self.identifiers, &identifier_key(customer, id))?;
        if let Some(device) = held.and_then(|held| held.device) {
            let matched = match id.kind {
                IdentifierKind::Mac => DaiSearchMatchKind::Mac,
                IdentifierKind::OperatorAssetId => DaiSearchMatchKind::AssetId,
                IdentifierKind::MachineAccount => return Ok(()),
            };
            let device = self.current_or_same(snapshot, customer, device)?;
            found.push(matched, DaiSearchTarget::Device(device));
        }
        Ok(())
    }
}

/// The matches of a search so far, each once, in the order found, up to
/// one past [`DAI_SEARCH_MAX_MATCHES`]: enough to tell the result was
/// truncated without collecting, and comparing against, every match a short
/// name substring finds.
#[derive(Default)]
struct Found {
    matches: Vec<DaiSearchMatch>,
}

impl Found {
    fn push(&mut self, matched: DaiSearchMatchKind, target: DaiSearchTarget) {
        if self.matches.len() > DAI_SEARCH_MAX_MATCHES {
            return;
        }
        let found = DaiSearchMatch { matched, target };
        if !self.matches.contains(&found) {
            self.matches.push(found);
        }
    }

    fn finish(mut self) -> DaiSearchResult {
        let truncated = self.matches.len() > DAI_SEARCH_MAX_MATCHES;
        self.matches.truncate(DAI_SEARCH_MAX_MATCHES);
        DaiSearchResult {
            matches: self.matches,
            truncated,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_formats() {
        for text in [
            "aa:bb:cc:dd:ee:0f",
            "AA-BB-CC-DD-EE-0F",
            "aabb.ccdd.ee0f",
            "AaBb.CcDd.Ee0F",
        ] {
            assert_eq!(
                parse_mac(text).as_deref(),
                Some("aa:bb:cc:dd:ee:0f"),
                "{text}"
            );
        }
        for text in [
            "aa:bb:cc:dd:ee",
            "aa:bb:cc:dd:ee:0g",
            "aabbccddee0f",
            "aa-bb-cc:dd-ee-0f",
            "aab.bccdd.ee0f",
            "a:bb:cc:dd:ee:0ff",
            "",
        ] {
            assert_eq!(parse_mac(text), None, "{text}");
        }
    }

    #[test]
    fn pages_both_ways() {
        let rows: Vec<(u8, u8)> = (1..=5).map(|n| (n, n)).collect();
        let request = |from, direction, limit| DaiPageRequest {
            from,
            direction,
            limit,
        };
        let forward = page(rows.clone(), &request(None, DaiPageDirection::Forward, 2));
        assert_eq!(
            (forward.rows, forward.has_more, forward.total),
            (vec![1, 2], true, 5)
        );
        let forward = page(
            rows.clone(),
            &request(Some(2), DaiPageDirection::Forward, 2),
        );
        assert_eq!((forward.rows, forward.has_more), (vec![3, 4], true));
        let forward = page(
            rows.clone(),
            &request(Some(4), DaiPageDirection::Forward, 2),
        );
        assert_eq!((forward.rows, forward.has_more), (vec![5], false));
        let backward = page(rows.clone(), &request(None, DaiPageDirection::Backward, 2));
        assert_eq!((backward.rows, backward.has_more), (vec![4, 5], true));
        let backward = page(
            rows.clone(),
            &request(Some(4), DaiPageDirection::Backward, 2),
        );
        assert_eq!((backward.rows, backward.has_more), (vec![2, 3], true));
        let backward = page(rows, &request(Some(2), DaiPageDirection::Backward, 2));
        assert_eq!(
            (backward.rows, backward.has_more, backward.total),
            (vec![1], false, 5)
        );
    }
}
