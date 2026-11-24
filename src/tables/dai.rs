//! The configuration tables of device identification (DAI).
//!
//! Device identification resolves sensor observations to devices per customer
//! and per *site*, a part of a customer's network in which an IP address names
//! one device at a time. Six column families hold its configuration:
//!
//! - `dai customer settings`: the settings of each customer, keyed by
//!   customer id;
//! - `dai sites`: the sites of each customer, keyed by customer id and site
//!   token;
//! - `dai relay sites`: the site of each DHCP relay of a customer, keyed by
//!   customer id, DHCP server IP and `giaddr`;
//! - `dai sensor sites`: the history of each sensor's site, keyed by sensor
//!   name and effective time;
//! - `dai site policy guard`: a revision per customer that every write of the
//!   customer's DAI configuration, and every time series generation policy
//!   save, reads for update and increments;
//! - `dai sensor state`: the configuration epoch and configuration hash of
//!   each sensor, keyed by sensor name.
//!
//! Keys use the component encoding of the `senta` endpoint observation tables
//! (see `senta_endpoint`), so a prefix read by customer id or by sensor name
//! returns exactly that customer's or that sensor's rows. Times are `i64`
//! nanoseconds since the UNIX epoch (UTC).
//!
//! # Transactions
//!
//! Every writer is one optimistic transaction, retried from the start on a
//! commit conflict, and a refusal commits nothing. The store's transactions
//! take no snapshot, and a scan is not tracked, so every writer of a
//! customer's DAI configuration, and every policy save that checks the site
//! condition, first reads the customer's `dai site policy guard` row for
//! update and increments it, before it reads any site, sensor site, relay
//! entry or policy its checks use. Two such writes for one customer
//! therefore conflict whichever commits first, and the retried one checks
//! again against the new state.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::IpAddr,
};

use anyhow::{Context, Result, anyhow};
use rocksdb::{IteratorMode, OptimisticTransactionDB, Transaction};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::senta_endpoint::{KeyReader, KeyWriter};
use crate::{
    EXCLUSIVE, IndexedTable, Map, NodeTable, TimeSeriesGenerationPolicy,
    TimeSeriesGenerationPolicyError,
};

/// The length of a 5-minute period, in nanoseconds; a site change takes
/// effect at the first whole multiple of it after the change.
const FIVE_MINUTES: i64 = 300 * 1_000_000_000;
/// The default inactivity multiplier of the lease time.
const DEFAULT_INACTIVITY_MULTIPLIER: u32 = 2;
/// The default inactivity time when there is no lease: 24 hours, in seconds.
const DEFAULT_NO_LEASE_INACTIVITY_SECS: u64 = 24 * 60 * 60;
/// The default evidence aging time: 180 days, in seconds.
const DEFAULT_EVIDENCE_AGING_SECS: u64 = 180 * 24 * 60 * 60;
/// The number of characters of a site token.
const SITE_TOKEN_LEN: usize = 8;
/// The characters a site token is drawn from.
const SITE_TOKEN_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
/// The characters a site's display name may not contain.
const FORBIDDEN_SITE_NAME_CHARS: [char; 4] = ['|', ';', ',', '"'];

pub(crate) type Txn<'a> = Transaction<'a, OptimisticTransactionDB>;

/// Sensors grouped by site: each site token with its sensors.
type SiteGroups = Vec<(String, Vec<String>)>;

/// A raw key and value.
type RawRow = (Box<[u8]>, Box<[u8]>);

/// The device identification (DAI) settings of a customer.
///
/// A customer with no stored settings has the [`Default`] ones: disabled,
/// never enabled, the default durations, no realm, and both revisions 0.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DaiSettings {
    /// Whether device account identification is enabled.
    pub device_account_identification: bool,
    /// When `device_account_identification` was last turned on, in
    /// nanoseconds since the UNIX epoch; `None` if it never was.
    pub last_enabled_time: Option<i64>,
    /// The multiple of a lease time after which a device with a lease is
    /// inactive.
    pub inactivity_multiplier: u32,
    /// The time, in seconds, after which a device without a lease is
    /// inactive.
    pub no_lease_inactivity_secs: u64,
    /// The time, in seconds, after which evidence ages out.
    pub evidence_aging_secs: u64,
    /// The Kerberos realms confirmed to enforce pre-authentication, in the
    /// order given.
    pub kerberos_preauth_realms: Vec<String>,
    /// The settings revision, incremented by every settings write.
    pub revision: u64,
    /// The relay site table revision, incremented by every replacement of
    /// the table.
    pub relay_revision: u64,
}

impl Default for DaiSettings {
    fn default() -> Self {
        Self {
            device_account_identification: false,
            last_enabled_time: None,
            inactivity_multiplier: DEFAULT_INACTIVITY_MULTIPLIER,
            no_lease_inactivity_secs: DEFAULT_NO_LEASE_INACTIVITY_SECS,
            evidence_aging_secs: DEFAULT_EVIDENCE_AGING_SECS,
            kerberos_preauth_realms: Vec::new(),
            revision: 0,
            relay_revision: 0,
        }
    }
}

/// The settable fields of [`DaiSettings`], for
/// [`Store::set_dai_settings`](crate::Store::set_dai_settings).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiSettingsUpdate {
    pub device_account_identification: bool,
    /// At least 1.
    pub inactivity_multiplier: u32,
    /// At least 1.
    pub no_lease_inactivity_secs: u64,
    /// At least 1.
    pub evidence_aging_secs: u64,
    /// Non-empty names.
    pub kerberos_preauth_realms: Vec<String>,
}

/// A site of a customer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiSite {
    /// The 8 characters of `[a-z0-9]` assigned to the site at its creation.
    pub token: String,
    /// The display name; empty for the default site only.
    pub name: String,
    /// The sensors listed in the site. The default site lists none: a sensor
    /// of the customer that no site lists is in the default site.
    pub sensors: Vec<String>,
    /// Whether this is the customer's default site.
    pub is_default: bool,
}

/// An entry of a customer's relay site table: the site of the hosts whose
/// DHCP traffic the relay `giaddr` forwards to `dhcp_server`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiRelaySite {
    pub dhcp_server: IpAddr,
    pub giaddr: IpAddr,
    /// The token of the site.
    pub site: String,
}

/// A customer's relay site table and its revision.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DaiRelaySites {
    /// The entries, ordered by DHCP server IP and then `giaddr`, `IPv4`
    /// before `IPv6`.
    pub entries: Vec<DaiRelaySite>,
    /// The relay site table revision of the customer's settings.
    pub revision: u64,
}

/// A refusal of a write of a customer's DAI settings, sites or relay site
/// table.
///
/// It is returned inside the `anyhow::Error` of the refusing method, so a
/// caller can `downcast_ref` it. A refused write commits nothing.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DaiConfigError {
    /// The expected revision is not the stored one.
    #[error("the expected revision is not the stored revision {stored}")]
    StaleRevision { stored: u64 },
    /// A settings field is out of range or empty.
    #[error("the DAI setting {field} is out of range or empty")]
    InvalidSettings {
        /// The name of the [`DaiSettingsUpdate`] field.
        field: &'static str,
    },
    /// A display name is empty or contains one of `|`, `;`, `,` and `"`.
    #[error("site name {name:?} is empty or contains one of |;,\"")]
    InvalidSiteName { name: String },
    /// Another site of the customer has the display name.
    #[error("another site is named {name:?}")]
    DuplicateSiteName { name: String },
    /// The default site cannot be updated or removed.
    #[error("site {token:?} is the default site, which cannot be updated or removed")]
    DefaultSiteFixed { token: String },
    /// The customer has no site of the token.
    #[error("no site has token {token:?}")]
    SiteNotFound { token: String },
    /// A listed name is not a sensor of the customer.
    #[error("{sensor:?} is not a sensor of the customer")]
    NotSensorOfCustomer { sensor: String },
    /// A list names the sensor twice.
    #[error("sensor {sensor:?} is listed twice")]
    DuplicateSensor { sensor: String },
    /// Another site of the customer lists the sensor.
    #[error("sensor {sensor:?} is in site {site_name:?} ({site_token})")]
    SensorInOtherSite {
        sensor: String,
        site_token: String,
        site_name: String,
    },
    /// The site to remove lists sensors.
    #[error("site {token:?} still lists sensors")]
    SiteHasSensors { token: String },
    /// The relay site table names the site to remove.
    #[error("the relay site table names site {token:?}")]
    SiteInRelayTable { token: String },
    /// The assignment in effect, or a scheduled one, still puts a sensor in
    /// the site to remove.
    #[error("a sensor is still assigned to site {token:?}")]
    SiteStillAssigned { token: String },
    /// A relay entry's `giaddr` is unspecified (`0.0.0.0` or `::`).
    #[error("the giaddr of the relay entry for DHCP server {dhcp_server} is unspecified")]
    UnspecifiedGiaddr { dhcp_server: IpAddr },
    /// Two relay entries have the same DHCP server IP and `giaddr`.
    #[error("DHCP server {dhcp_server} and giaddr {giaddr} are listed twice")]
    DuplicateRelayEntry { dhcp_server: IpAddr, giaddr: IpAddr },
    /// A relay entry names a token that is not one of the customer's sites.
    #[error("no site has token {site:?}")]
    UnknownRelaySite { site: String },
    /// The site write would make time series generation policies of the
    /// customer read sensors of two sites.
    #[error(
        "the site change would make time series generation policies {} read sensors of more \
         than one site",
        list_policies(.policies)
    )]
    PolicyWouldSpanSites {
        /// The id and name of each such policy, ordered by id.
        policies: Vec<(u32, String)>,
    },
}

/// Lists `policies` for an error message.
fn list_policies(policies: &[(u32, String)]) -> String {
    policies
        .iter()
        .map(|(id, name)| format!("{id} ({name:?})"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The stored value of a site.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct SiteValue {
    name: String,
    sensors: Vec<String>,
    is_default: bool,
}

/// The stored value of a `dai sensor sites` row: the sensor's site from the
/// row's effective time on.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct SensorSite {
    customer_id: u32,
    site: String,
}

/// The stored value of a `dai sensor state` row.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct SensorState {
    /// The configuration epoch.
    epoch: u64,
    /// The hash of the sensor's configuration content, as last recorded.
    config_hash: Option<Vec<u8>>,
}

/// A site table: the site each sensor is in, as the sites list them.
struct Assignment {
    /// The default site's token; empty if the customer has none.
    default: String,
    /// The site of each listed sensor.
    listed: HashMap<String, String>,
}

impl Assignment {
    fn new(sites: &[DaiSite]) -> Self {
        let mut default = String::new();
        let mut listed = HashMap::new();
        for site in sites {
            if site.is_default {
                default.clone_from(&site.token);
            }
            for sensor in &site.sensors {
                listed.insert(sensor.clone(), site.token.clone());
            }
        }
        Self { default, listed }
    }

    /// Returns the site of `sensor`.
    fn site(&self, sensor: &str) -> &str {
        self.listed
            .get(sensor)
            .map_or(&self.default, String::as_str)
    }
}

/// Groups `sensors` by the site `site_of` gives each, sites ordered by token
/// and sensors in the given order, and returns the groups if there is more
/// than one.
fn spanned_sites(
    sensors: &[String],
    mut site_of: impl FnMut(&str) -> Result<String>,
) -> Result<Option<SiteGroups>> {
    let mut sites: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for sensor in sensors {
        sites
            .entry(site_of(sensor)?)
            .or_default()
            .push(sensor.clone());
    }
    Ok((sites.len() > 1).then(|| sites.into_iter().collect()))
}

/// A hook the tests run once, in the thread that set it, right after the
/// next site condition check of a policy save or a site write, before that
/// write commits.
#[cfg(test)]
type AfterChecksHook = Box<dyn FnOnce(&OptimisticTransactionDB)>;

#[cfg(test)]
thread_local! {
    static AFTER_CHECKS: std::cell::RefCell<Option<AfterChecksHook>> =
        const { std::cell::RefCell::new(None) };
}

/// Sets the hook the next site condition check in this thread runs.
#[cfg(test)]
fn set_after_checks_hook(hook: AfterChecksHook) {
    AFTER_CHECKS.with(|cell| *cell.borrow_mut() = Some(hook));
}

/// Runs, and clears, the hook set in this thread, if any.
#[cfg(test)]
fn run_after_checks_hook(db: &OptimisticTransactionDB) {
    if let Some(hook) = AFTER_CHECKS.with(|cell| cell.borrow_mut().take()) {
        hook(db);
    }
}

/// Returns the current time in nanoseconds since the UNIX epoch.
pub(crate) fn now_nanos() -> Result<i64> {
    i64::try_from(jiff::Timestamp::now().as_nanosecond())
        .context("the current time is out of the range of nanosecond timestamps")
}

/// Returns the first 5-minute boundary strictly after `now`.
fn next_boundary(now: i64) -> Result<i64> {
    now.div_euclid(FIVE_MINUTES)
        .checked_add(1)
        .and_then(|periods| periods.checked_mul(FIVE_MINUTES))
        .ok_or_else(|| anyhow!("time {now} has no 5-minute boundary after it"))
}

/// Returns a new site token, one `is_taken` does not refuse.
fn new_site_token(is_taken: impl Fn(&str) -> bool) -> String {
    loop {
        let token: String = (0..SITE_TOKEN_LEN)
            .map(|_| {
                // The index is drawn below the length of the slice it indexes.
                char::from(SITE_TOKEN_CHARS[rand::random_range(0..SITE_TOKEN_CHARS.len())])
            })
            .collect();
        if !is_taken(&token) {
            return token;
        }
    }
}

fn customer_key(customer_id: u32) -> Vec<u8> {
    KeyWriter::default().u32(customer_id).finish()
}

fn site_key(customer_id: u32, token: &str) -> Vec<u8> {
    KeyWriter::default().u32(customer_id).str(token).finish()
}

fn relay_key(customer_id: u32, dhcp_server: IpAddr, giaddr: IpAddr) -> Vec<u8> {
    KeyWriter::default()
        .u32(customer_id)
        .ip(dhcp_server)
        .ip(giaddr)
        .finish()
}

fn sensor_key(sensor: &str) -> Vec<u8> {
    KeyWriter::default().str(sensor).finish()
}

fn sensor_site_key(sensor: &str, effective: i64) -> Vec<u8> {
    KeyWriter::default().str(sensor).i64(effective).finish()
}

/// Decodes a site row.
fn decode_site(key: &[u8], value: &[u8]) -> Result<(u32, DaiSite)> {
    let mut reader = KeyReader::new(key);
    let customer_id = reader.u32()?;
    let token = reader.str()?;
    reader.finish()?;
    let value: SiteValue = super::deserialize(value)?;
    Ok((
        customer_id,
        DaiSite {
            token,
            name: value.name,
            sensors: value.sensors,
            is_default: value.is_default,
        },
    ))
}

/// Decodes a relay site row.
fn decode_relay(key: &[u8], value: &[u8]) -> Result<DaiRelaySite> {
    let mut reader = KeyReader::new(key);
    reader.u32()?;
    let dhcp_server = reader.ip()?;
    let giaddr = reader.ip()?;
    reader.finish()?;
    Ok(DaiRelaySite {
        dhcp_server,
        giaddr,
        site: super::deserialize(value)?,
    })
}

/// Decodes a `dai sensor sites` row.
fn decode_sensor_site(key: &[u8], value: &[u8]) -> Result<(String, i64, SensorSite)> {
    let mut reader = KeyReader::new(key);
    let sensor = reader.str()?;
    let effective = reader.i64()?;
    reader.finish()?;
    Ok((sensor, effective, super::deserialize(value)?))
}

/// The six DAI configuration column families, with the node and policy
/// tables their checks read.
pub(crate) struct Dai<'d> {
    db: &'d OptimisticTransactionDB,
    settings: Map<'d>,
    sites: Map<'d>,
    relay_sites: Map<'d>,
    sensor_sites: Map<'d>,
    guard: Map<'d>,
    sensor_state: Map<'d>,
}

impl<'d> Dai<'d> {
    /// Opens the DAI configuration tables, or returns `None` if one of them
    /// does not exist.
    pub(crate) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Some(Self {
            db,
            settings: Map::open(db, super::DAI_CUSTOMER_SETTINGS)?,
            sites: Map::open(db, super::DAI_SITES)?,
            relay_sites: Map::open(db, super::DAI_RELAY_SITES)?,
            sensor_sites: Map::open(db, super::DAI_SENSOR_SITES)?,
            guard: Map::open(db, super::DAI_SITE_POLICY_GUARD)?,
            sensor_state: Map::open(db, super::DAI_SENSOR_STATE)?,
        })
    }

    fn nodes(&self) -> Result<NodeTable<'d>> {
        NodeTable::open(self.db).context("node table must be present")
    }

    fn policies(&self) -> Result<IndexedTable<'d, TimeSeriesGenerationPolicy>> {
        IndexedTable::<TimeSeriesGenerationPolicy>::open(self.db)
            .context("time series generation policy table must be present")
    }

    /// Runs `attempt` in an optimistic transaction and commits it, retrying
    /// from the start on a commit conflict. A refusal `attempt` returns ends
    /// the write without committing.
    fn write<T>(&self, mut attempt: impl FnMut(&Txn<'_>) -> Result<T>) -> Result<T> {
        loop {
            let txn = self.db.transaction();
            let value = attempt(&txn)?;
            match txn.commit() {
                Ok(()) => return Ok(value),
                Err(e)
                    if matches!(
                        e.kind(),
                        rocksdb::ErrorKind::Busy | rocksdb::ErrorKind::TryAgain
                    ) => {}
                Err(e) => return Err(e).context("failed to commit DAI configuration changes"),
            }
        }
    }

    /// Runs `read` in a transaction that is never committed.
    fn read<T>(&self, read: impl FnOnce(&Txn<'_>) -> Result<T>) -> Result<T> {
        let txn = self.db.transaction();
        read(&txn)
    }

    /// Returns the rows of `map` whose key starts with `prefix`, as `txn`
    /// sees them, in key order. The scan is not tracked.
    fn scan(map: &Map<'_>, txn: &Txn<'_>, prefix: &[u8]) -> Result<Vec<RawRow>> {
        let mode = IteratorMode::Start;
        let iter = if prefix.is_empty() {
            txn.iterator_cf(map.cf, mode)
        } else {
            let mut opts = rocksdb::ReadOptions::default();
            opts.set_iterate_range(rocksdb::PrefixRange(prefix));
            txn.iterator_cf_opt(map.cf, opts, mode)
        };
        iter.map(|entry| entry.context("cannot read DAI configuration"))
            .collect()
    }

    // ---- The guard ----

    /// Reads the customer's `dai site policy guard` row for update and
    /// increments it within `txn`.
    ///
    /// Every write of the customer's DAI configuration, and every policy
    /// save that checks the site condition, calls this before it reads any
    /// site, sensor site, relay entry or policy its checks use, so two of
    /// them for one customer conflict whichever commits first.
    pub(crate) fn lock_customer(&self, txn: &Txn<'_>, customer_id: u32) -> Result<()> {
        let key = customer_key(customer_id);
        let revision: u64 = txn
            .get_for_update_cf(self.guard.cf, &key, EXCLUSIVE)
            .context("cannot read the DAI site policy guard")?
            .map(|value| super::deserialize(&value))
            .transpose()?
            .unwrap_or_default();
        let next = revision.wrapping_add(1);
        txn.put_cf(self.guard.cf, &key, super::serialize(&next)?)
            .context("cannot write the DAI site policy guard")
    }

    // ---- Settings ----

    /// Returns the customer's stored settings as `txn` sees them, reading
    /// them for update, or `None` if it has none.
    fn stored_settings(&self, txn: &Txn<'_>, customer_id: u32) -> Result<Option<DaiSettings>> {
        txn.get_for_update_cf(self.settings.cf, customer_key(customer_id), EXCLUSIVE)
            .context("cannot read DAI customer settings")?
            .map(|value| super::deserialize(&value))
            .transpose()
    }

    fn put_settings(&self, txn: &Txn<'_>, customer_id: u32, settings: &DaiSettings) -> Result<()> {
        txn.put_cf(
            self.settings.cf,
            customer_key(customer_id),
            super::serialize(settings)?,
        )
        .context("cannot write DAI customer settings")
    }

    /// Returns the customer's settings, or the defaults if it has none.
    pub(crate) fn settings(&self, customer_id: u32) -> Result<DaiSettings> {
        self.read(|txn| Ok(self.stored_settings(txn, customer_id)?.unwrap_or_default()))
    }

    /// Writes the customer's settings, given the expected settings revision,
    /// as [`Store::set_dai_settings`](crate::Store::set_dai_settings)
    /// describes, at the time `now`, and returns the stored settings.
    pub(crate) fn set_settings(
        &self,
        customer_id: u32,
        expected_revision: u64,
        update: &DaiSettingsUpdate,
        now: i64,
    ) -> Result<DaiSettings> {
        check_settings(update)?;
        self.write(|txn| {
            self.lock_customer(txn, customer_id)?;
            let stored = self.stored_settings(txn, customer_id)?.unwrap_or_default();
            if stored.revision != expected_revision {
                return Err(DaiConfigError::StaleRevision {
                    stored: stored.revision,
                }
                .into());
            }
            let toggled =
                stored.device_account_identification != update.device_account_identification;
            let last_enabled_time =
                if update.device_account_identification && !stored.device_account_identification {
                    Some(now)
                } else {
                    stored.last_enabled_time
                };
            let settings = DaiSettings {
                device_account_identification: update.device_account_identification,
                last_enabled_time,
                inactivity_multiplier: update.inactivity_multiplier,
                no_lease_inactivity_secs: update.no_lease_inactivity_secs,
                evidence_aging_secs: update.evidence_aging_secs,
                kerberos_preauth_realms: update.kerberos_preauth_realms.clone(),
                revision: stored.revision.wrapping_add(1),
                relay_revision: stored.relay_revision,
            };
            let mut sites = self.sites_in(txn, customer_id)?;
            self.ensure_default_site_in(txn, customer_id, &mut sites)?;
            if toggled {
                let sensors = self.customer_sensors(txn, customer_id, &sites, &[])?;
                self.bump_epochs(txn, &sensors)?;
            }
            self.put_settings(txn, customer_id, &settings)?;
            Ok(settings)
        })
    }

    // ---- Sites ----

    /// Returns the customer's sites as `txn` sees them, in token order.
    fn sites_in(&self, txn: &Txn<'_>, customer_id: u32) -> Result<Vec<DaiSite>> {
        Self::scan(&self.sites, txn, &customer_key(customer_id))?
            .into_iter()
            .map(|(key, value)| decode_site(&key, &value).map(|(_, site)| site))
            .collect()
    }

    fn put_site(&self, txn: &Txn<'_>, customer_id: u32, site: &DaiSite) -> Result<()> {
        let value = SiteValue {
            name: site.name.clone(),
            sensors: site.sensors.clone(),
            is_default: site.is_default,
        };
        txn.put_cf(
            self.sites.cf,
            site_key(customer_id, &site.token),
            super::serialize(&value)?,
        )
        .context("cannot write DAI site")
    }

    /// Creates the customer's default site within `txn` if `sites`, the
    /// customer's sites as `txn` sees them, has none, adds it to `sites`, and
    /// returns its token.
    fn ensure_default_site_in(
        &self,
        txn: &Txn<'_>,
        customer_id: u32,
        sites: &mut Vec<DaiSite>,
    ) -> Result<String> {
        if let Some(site) = sites.iter().find(|site| site.is_default) {
            return Ok(site.token.clone());
        }
        let token = new_site_token(|token| sites.iter().any(|site| site.token == token));
        let site = DaiSite {
            token: token.clone(),
            name: String::new(),
            sensors: Vec::new(),
            is_default: true,
        };
        self.put_site(txn, customer_id, &site)?;
        sites.push(site);
        sites.sort_unstable_by(|a, b| a.token.cmp(&b.token));
        Ok(token)
    }

    /// Creates the customer's default site if it has none, and returns its
    /// token.
    pub(crate) fn ensure_default_site(&self, customer_id: u32) -> Result<String> {
        self.write(|txn| {
            self.lock_customer(txn, customer_id)?;
            let mut sites = self.sites_in(txn, customer_id)?;
            self.ensure_default_site_in(txn, customer_id, &mut sites)
        })
    }

    /// Returns the customer's stored sites, in token order.
    pub(crate) fn sites(&self, customer_id: u32) -> Result<Vec<DaiSite>> {
        self.read(|txn| self.sites_in(txn, customer_id))
    }

    /// Returns the customer's site `token`, or `None` if it has none.
    pub(crate) fn site(&self, customer_id: u32, token: &str) -> Result<Option<DaiSite>> {
        self.read(|txn| {
            txn.get_cf(self.sites.cf, site_key(customer_id, token))
                .context("cannot read DAI site")?
                .map(|value| decode_site(&site_key(customer_id, token), &value).map(|(_, s)| s))
                .transpose()
        })
    }

    /// Creates a site at the time `now` and returns its token.
    pub(crate) fn create_site(
        &self,
        customer_id: u32,
        name: &str,
        sensors: &[String],
        now: i64,
    ) -> Result<String> {
        self.write(|txn| self.write_site(txn, customer_id, None, name, sensors, now))
    }

    /// Updates site `token` at the time `now`.
    pub(crate) fn update_site(
        &self,
        customer_id: u32,
        token: &str,
        name: &str,
        sensors: &[String],
        now: i64,
    ) -> Result<()> {
        self.write(|txn| {
            self.write_site(txn, customer_id, Some(token), name, sensors, now)
                .map(|_| ())
        })
    }

    /// Creates a site, or updates site `token`, within `txn` at the time
    /// `now`, and returns its token.
    fn write_site(
        &self,
        txn: &Txn<'_>,
        customer_id: u32,
        token: Option<&str>,
        name: &str,
        sensors: &[String],
        now: i64,
    ) -> Result<String> {
        self.lock_customer(txn, customer_id)?;
        let mut before = self.sites_in(txn, customer_id)?;
        self.ensure_default_site_in(txn, customer_id, &mut before)?;
        if let Some(token) = token {
            match before.iter().find(|site| site.token == token) {
                None => {
                    return Err(DaiConfigError::SiteNotFound {
                        token: token.to_string(),
                    }
                    .into());
                }
                Some(site) if site.is_default => {
                    return Err(DaiConfigError::DefaultSiteFixed {
                        token: token.to_string(),
                    }
                    .into());
                }
                Some(_) => {}
            }
        }
        check_site_name(name)?;
        let others = || {
            before
                .iter()
                .filter(move |site| Some(site.token.as_str()) != token)
        };
        if others().any(|site| site.name == name) {
            return Err(DaiConfigError::DuplicateSiteName {
                name: name.to_string(),
            }
            .into());
        }
        let nodes = self.nodes()?;
        let mut seen = BTreeSet::new();
        for sensor in sensors {
            if !seen.insert(sensor.as_str()) {
                return Err(DaiConfigError::DuplicateSensor {
                    sensor: sensor.clone(),
                }
                .into());
            }
            if !nodes.is_sensor_name_in_transaction(txn, customer_id, sensor)? {
                return Err(DaiConfigError::NotSensorOfCustomer {
                    sensor: sensor.clone(),
                }
                .into());
            }
            if let Some(site) = others().find(|site| site.sensors.contains(sensor)) {
                return Err(DaiConfigError::SensorInOtherSite {
                    sensor: sensor.clone(),
                    site_token: site.token.clone(),
                    site_name: site.name.clone(),
                }
                .into());
            }
        }

        let token = token.map_or_else(
            || new_site_token(|token| before.iter().any(|site| site.token == token)),
            str::to_string,
        );
        let site = DaiSite {
            token: token.clone(),
            name: name.to_string(),
            sensors: sensors.to_vec(),
            is_default: false,
        };
        let mut after: Vec<DaiSite> = others().cloned().collect();
        after.push(site.clone());

        let policies = self.policies_spanning_sites(txn, customer_id, &Assignment::new(&after))?;
        #[cfg(test)]
        run_after_checks_hook(self.db);
        if !policies.is_empty() {
            return Err(DaiConfigError::PolicyWouldSpanSites { policies }.into());
        }

        self.schedule_changes(txn, customer_id, &before, &after, now)?;
        let sensors = self.customer_sensors(txn, customer_id, &before, &after)?;
        self.bump_epochs(txn, &sensors)?;
        self.put_site(txn, customer_id, &site)?;
        Ok(token)
    }

    /// Removes site `token` at the time `now`.
    pub(crate) fn remove_site(&self, customer_id: u32, token: &str, now: i64) -> Result<()> {
        self.write(|txn| {
            self.lock_customer(txn, customer_id)?;
            let mut before = self.sites_in(txn, customer_id)?;
            self.ensure_default_site_in(txn, customer_id, &mut before)?;
            let Some(site) = before.iter().find(|site| site.token == token) else {
                return Err(DaiConfigError::SiteNotFound {
                    token: token.to_string(),
                }
                .into());
            };
            if site.is_default {
                return Err(DaiConfigError::DefaultSiteFixed {
                    token: token.to_string(),
                }
                .into());
            }
            if !site.sensors.is_empty() {
                return Err(DaiConfigError::SiteHasSensors {
                    token: token.to_string(),
                }
                .into());
            }
            if self
                .relay_entries(txn, customer_id)?
                .iter()
                .any(|entry| entry.site == token)
            {
                return Err(DaiConfigError::SiteInRelayTable {
                    token: token.to_string(),
                }
                .into());
            }
            if self.site_still_assigned(txn, customer_id, token, now)? {
                return Err(DaiConfigError::SiteStillAssigned {
                    token: token.to_string(),
                }
                .into());
            }
            let after: Vec<DaiSite> = before
                .iter()
                .filter(|site| site.token != token)
                .cloned()
                .collect();
            let sensors = self.customer_sensors(txn, customer_id, &before, &after)?;
            self.bump_epochs(txn, &sensors)?;
            txn.delete_cf(self.sites.cf, site_key(customer_id, token))
                .context("cannot delete DAI site")
        })
    }

    /// Returns whether the assignment in effect at `now`, or one scheduled
    /// after it, puts a sensor in the customer's site `token`.
    fn site_still_assigned(
        &self,
        txn: &Txn<'_>,
        customer_id: u32,
        token: &str,
        now: i64,
    ) -> Result<bool> {
        // The latest row at or before `now` naming the customer, per sensor.
        let mut in_effect: BTreeMap<String, SensorSite> = BTreeMap::new();
        for (key, value) in Self::scan(&self.sensor_sites, txn, &[])? {
            let (sensor, effective, row) = decode_sensor_site(&key, &value)?;
            if row.customer_id != customer_id {
                continue;
            }
            if effective > now {
                if row.site == token {
                    return Ok(true);
                }
            } else {
                in_effect.insert(sensor, row);
            }
        }
        Ok(in_effect.values().any(|row| row.site == token))
    }

    // ---- Sensor site history ----

    /// Writes, within `txn`, a `dai sensor sites` row effective at the first
    /// 5-minute boundary after `now` for each sensor whose site in `before`
    /// is not its site in `after`, replacing a row scheduled at that
    /// boundary.
    fn schedule_changes(
        &self,
        txn: &Txn<'_>,
        customer_id: u32,
        before: &[DaiSite],
        after: &[DaiSite],
        now: i64,
    ) -> Result<()> {
        let old = Assignment::new(before);
        let new = Assignment::new(after);
        let sensors: BTreeSet<&String> = old.listed.keys().chain(new.listed.keys()).collect();
        let effective = next_boundary(now)?;
        for sensor in sensors {
            let site = new.site(sensor);
            if old.site(sensor) == site {
                continue;
            }
            let row = SensorSite {
                customer_id,
                site: site.to_string(),
            };
            txn.put_cf(
                self.sensor_sites.cf,
                sensor_site_key(sensor, effective),
                super::serialize(&row)?,
            )
            .context("cannot write DAI sensor site")?;
        }
        Ok(())
    }

    /// Returns the site token of `sensor` at the time `time` from the
    /// `dai sensor sites` rows naming the customer, or `None` if no row of
    /// the sensor at or before `time` names it.
    fn history_site(
        &self,
        txn: &Txn<'_>,
        customer_id: u32,
        sensor: &str,
        time: i64,
    ) -> Result<Option<String>> {
        let mut site = None;
        for (key, value) in Self::scan(&self.sensor_sites, txn, &sensor_key(sensor))? {
            let (_, effective, row) = decode_sensor_site(&key, &value)?;
            if effective > time {
                break;
            }
            if row.customer_id == customer_id {
                site = Some(row.site);
            }
        }
        Ok(site)
    }

    /// Returns the site token of `sensor` in the customer's network at the
    /// time `time`, or `None` if the customer has no default site.
    pub(crate) fn sensor_site(
        &self,
        customer_id: u32,
        sensor: &str,
        time: i64,
    ) -> Result<Option<String>> {
        self.read(|txn| {
            if let Some(site) = self.history_site(txn, customer_id, sensor, time)? {
                return Ok(Some(site));
            }
            Ok(self
                .sites_in(txn, customer_id)?
                .into_iter()
                .find(|site| site.is_default)
                .map(|site| site.token))
        })
    }

    // ---- Relay site table ----

    /// Returns the customer's relay entries as `txn` sees them, in key order.
    fn relay_entries(&self, txn: &Txn<'_>, customer_id: u32) -> Result<Vec<DaiRelaySite>> {
        Self::scan(&self.relay_sites, txn, &customer_key(customer_id))?
            .into_iter()
            .map(|(key, value)| decode_relay(&key, &value))
            .collect()
    }

    /// Returns the customer's relay site table and its revision.
    pub(crate) fn relay_sites(&self, customer_id: u32) -> Result<DaiRelaySites> {
        self.read(|txn| {
            Ok(DaiRelaySites {
                entries: self.relay_entries(txn, customer_id)?,
                revision: self
                    .stored_settings(txn, customer_id)?
                    .unwrap_or_default()
                    .relay_revision,
            })
        })
    }

    /// Replaces the customer's relay site table, given the expected relay
    /// revision, and returns the new revision.
    pub(crate) fn replace_relay_sites(
        &self,
        customer_id: u32,
        expected_revision: u64,
        entries: &[DaiRelaySite],
    ) -> Result<u64> {
        self.write(|txn| {
            self.lock_customer(txn, customer_id)?;
            let mut settings = self.stored_settings(txn, customer_id)?.unwrap_or_default();
            if settings.relay_revision != expected_revision {
                return Err(DaiConfigError::StaleRevision {
                    stored: settings.relay_revision,
                }
                .into());
            }
            let sites = self.sites_in(txn, customer_id)?;
            let mut seen = BTreeSet::new();
            for entry in entries {
                if entry.giaddr.is_unspecified() {
                    return Err(DaiConfigError::UnspecifiedGiaddr {
                        dhcp_server: entry.dhcp_server,
                    }
                    .into());
                }
                if !seen.insert((entry.dhcp_server, entry.giaddr)) {
                    return Err(DaiConfigError::DuplicateRelayEntry {
                        dhcp_server: entry.dhcp_server,
                        giaddr: entry.giaddr,
                    }
                    .into());
                }
                if !sites.iter().any(|site| site.token == entry.site) {
                    return Err(DaiConfigError::UnknownRelaySite {
                        site: entry.site.clone(),
                    }
                    .into());
                }
            }
            for (key, _) in Self::scan(&self.relay_sites, txn, &customer_key(customer_id))? {
                txn.delete_cf(self.relay_sites.cf, key)
                    .context("cannot delete DAI relay site")?;
            }
            for entry in entries {
                txn.put_cf(
                    self.relay_sites.cf,
                    relay_key(customer_id, entry.dhcp_server, entry.giaddr),
                    super::serialize(&entry.site)?,
                )
                .context("cannot write DAI relay site")?;
            }
            settings.relay_revision = settings.relay_revision.wrapping_add(1);
            self.put_settings(txn, customer_id, &settings)?;
            let sensors = self.customer_sensors(txn, customer_id, &sites, &[])?;
            self.bump_epochs(txn, &sensors)?;
            Ok(settings.relay_revision)
        })
    }

    // ---- Configuration epochs ----

    /// Returns the sensors of the customer: its sensors per the node table,
    /// as `txn` sees it, and every sensor `before` or `after` lists.
    fn customer_sensors(
        &self,
        txn: &Txn<'_>,
        customer_id: u32,
        before: &[DaiSite],
        after: &[DaiSite],
    ) -> Result<BTreeSet<String>> {
        let mut sensors: BTreeSet<String> = self
            .nodes()?
            .sensor_names_in_transaction(txn)?
            .into_iter()
            .filter_map(|(customer, name)| (customer == customer_id).then_some(name))
            .collect();
        for site in before.iter().chain(after) {
            sensors.extend(site.sensors.iter().cloned());
        }
        Ok(sensors)
    }

    /// Returns the state of `sensor` as `txn` sees it, read for update.
    fn sensor_state_for_update(&self, txn: &Txn<'_>, sensor: &str) -> Result<SensorState> {
        Ok(txn
            .get_for_update_cf(self.sensor_state.cf, sensor_key(sensor), EXCLUSIVE)
            .context("cannot read DAI sensor state")?
            .map(|value| super::deserialize(&value))
            .transpose()?
            .unwrap_or_default())
    }

    fn put_sensor_state(&self, txn: &Txn<'_>, sensor: &str, state: &SensorState) -> Result<()> {
        txn.put_cf(
            self.sensor_state.cf,
            sensor_key(sensor),
            super::serialize(state)?,
        )
        .context("cannot write DAI sensor state")
    }

    /// Increments, within `txn`, the configuration epoch of every sensor of
    /// `sensors`.
    fn bump_epochs(&self, txn: &Txn<'_>, sensors: &BTreeSet<String>) -> Result<()> {
        for sensor in sensors {
            let mut state = self.sensor_state_for_update(txn, sensor)?;
            state.epoch = state.epoch.wrapping_add(1);
            self.put_sensor_state(txn, sensor, &state)?;
        }
        Ok(())
    }

    /// Returns the configuration epoch of `sensor`.
    pub(crate) fn config_epoch(&self, sensor: &str) -> Result<u64> {
        self.read(|txn| {
            Ok(txn
                .get_cf(self.sensor_state.cf, sensor_key(sensor))
                .context("cannot read DAI sensor state")?
                .map(|value| super::deserialize::<SensorState>(&value))
                .transpose()?
                .unwrap_or_default()
                .epoch)
        })
    }

    /// Records the configuration content hash of `sensor`, incrementing its
    /// configuration epoch if the hash is not the stored one, and returns
    /// the epoch.
    pub(crate) fn record_config_hash(&self, sensor: &str, hash: &[u8]) -> Result<u64> {
        self.write(|txn| {
            let mut state = self.sensor_state_for_update(txn, sensor)?;
            if state.config_hash.as_deref() != Some(hash) {
                state.config_hash = Some(hash.to_vec());
                state.epoch = state.epoch.wrapping_add(1);
                self.put_sensor_state(txn, sensor, &state)?;
            }
            Ok(state.epoch)
        })
    }

    // ---- The site condition ----

    /// Checks, within `txn` at the time `now`, the site condition of a
    /// policy of the customer reading `sensors`: under the assignment in
    /// effect at `now` and under the one the site table states, the sensors
    /// are in one site of the customer. A customer with no stored site
    /// passes.
    ///
    /// The caller has called [`lock_customer`](Self::lock_customer) in
    /// `txn` before.
    ///
    /// # Errors
    ///
    /// Returns [`TimeSeriesGenerationPolicyError::SensorsSpanSites`] inside
    /// the error if the condition fails, listing the sites of the assignment
    /// in effect if that one fails and of the scheduled one otherwise.
    pub(crate) fn check_policy_sites(
        &self,
        txn: &Txn<'_>,
        customer_id: u32,
        sensors: &[String],
        now: i64,
    ) -> Result<()> {
        let sites = self.sites_in(txn, customer_id)?;
        let checked = self.policy_sites(txn, customer_id, sensors, now, &sites);
        #[cfg(test)]
        run_after_checks_hook(self.db);
        checked
    }

    /// Checks the site condition of a policy as
    /// [`check_policy_sites`](Self::check_policy_sites) describes, given the
    /// customer's sites.
    fn policy_sites(
        &self,
        txn: &Txn<'_>,
        customer_id: u32,
        sensors: &[String],
        now: i64,
        sites: &[DaiSite],
    ) -> Result<()> {
        if sites.is_empty() {
            return Ok(());
        }
        let scheduled = Assignment::new(sites);
        let in_effect = spanned_sites(sensors, |sensor| {
            Ok(self
                .history_site(txn, customer_id, sensor, now)?
                .unwrap_or_else(|| scheduled.default.clone()))
        })?;
        let failing = match in_effect {
            Some(sites) => Some(sites),
            None => spanned_sites(sensors, |sensor| Ok(scheduled.site(sensor).to_string()))?,
        };
        match failing {
            Some(sites) => {
                Err(TimeSeriesGenerationPolicyError::SensorsSpanSites { customer_id, sites }.into())
            }
            None => Ok(()),
        }
    }

    /// Returns the id and name of every policy of the customer, as `txn`
    /// sees them, whose sensors are in more than one site under
    /// `assignment`, ordered by id.
    fn policies_spanning_sites(
        &self,
        txn: &Txn<'_>,
        customer_id: u32,
        assignment: &Assignment,
    ) -> Result<Vec<(u32, String)>> {
        let mut policies = Vec::new();
        for policy in self.policies()?.scan(txn)? {
            if policy.customer_id != customer_id {
                continue;
            }
            if spanned_sites(&policy.sensors, |sensor| {
                Ok(assignment.site(sensor).to_string())
            })?
            .is_some()
            {
                policies.push((policy.id, policy.name));
            }
        }
        policies.sort_unstable();
        Ok(policies)
    }

    // ---- Customer deletion ----

    /// Deletes the customer's rows from the six DAI configuration tables, as
    /// [`Store::delete_dai_customer`](crate::Store::delete_dai_customer)
    /// describes.
    pub(crate) fn delete_customer(&self, customer_id: u32, sensors: &[String]) -> Result<()> {
        self.delete_sensor_rows(customer_id, sensors)?;
        self.delete_customer_rows(customer_id)
    }

    /// Deletes, in one transaction, every `dai sensor sites` row naming the
    /// customer, and the `dai sensor state` rows of `sensors`, the names the
    /// customer's sites list and the customer's sensors per the node table,
    /// except a name the node table shows as a sensor of another customer.
    fn delete_sensor_rows(&self, customer_id: u32, sensors: &[String]) -> Result<()> {
        let (names, of_others) = self.read(|txn| {
            let mut names: BTreeSet<String> = sensors.iter().cloned().collect();
            for site in self.sites_in(txn, customer_id)? {
                names.extend(site.sensors);
            }
            let mut of_others = BTreeSet::new();
            for (customer, name) in self.nodes()?.sensor_names_in_transaction(txn)? {
                if customer == customer_id {
                    names.insert(name);
                } else {
                    of_others.insert(name);
                }
            }
            Ok((names, of_others))
        })?;

        self.write(|txn| {
            for (key, value) in Self::scan(&self.sensor_sites, txn, &[])? {
                let (_, _, row) = decode_sensor_site(&key, &value)?;
                if row.customer_id == customer_id {
                    txn.delete_cf(self.sensor_sites.cf, key)
                        .context("cannot delete DAI sensor site")?;
                }
            }
            for name in names.difference(&of_others) {
                txn.delete_cf(self.sensor_state.cf, sensor_key(name))
                    .context("cannot delete DAI sensor state")?;
            }
            Ok(())
        })
    }

    /// Deletes, in one transaction, the customer's settings, sites, relay
    /// site table and site policy guard.
    fn delete_customer_rows(&self, customer_id: u32) -> Result<()> {
        self.write(|txn| {
            let key = customer_key(customer_id);
            txn.get_for_update_cf(self.guard.cf, &key, EXCLUSIVE)
                .context("cannot read the DAI site policy guard")?;
            for map in [&self.sites, &self.relay_sites] {
                for (key, _) in Self::scan(map, txn, &key)? {
                    txn.delete_cf(map.cf, key)
                        .context("cannot delete DAI configuration")?;
                }
            }
            txn.delete_cf(self.settings.cf, &key)
                .context("cannot delete DAI customer settings")?;
            txn.delete_cf(self.guard.cf, &key)
                .context("cannot delete the DAI site policy guard")
        })
    }
}

/// Checks the ranges of a settings update.
fn check_settings(update: &DaiSettingsUpdate) -> Result<(), DaiConfigError> {
    let field = if update.inactivity_multiplier < 1 {
        Some("inactivity_multiplier")
    } else if update.no_lease_inactivity_secs < 1 {
        Some("no_lease_inactivity_secs")
    } else if update.evidence_aging_secs < 1 {
        Some("evidence_aging_secs")
    } else if update.kerberos_preauth_realms.iter().any(String::is_empty) {
        Some("kerberos_preauth_realms")
    } else {
        None
    };
    field.map_or(Ok(()), |field| {
        Err(DaiConfigError::InvalidSettings { field })
    })
}

/// Checks the display name of a site other than the default site.
fn check_site_name(name: &str) -> Result<(), DaiConfigError> {
    if name.is_empty() || name.contains(FORBIDDEN_SITE_NAME_CHARS) {
        return Err(DaiConfigError::InvalidSiteName {
            name: name.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
