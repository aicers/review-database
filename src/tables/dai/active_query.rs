//! Active query configuration, target selection and display-only answer storage.

use std::{cmp::Reverse, net::IpAddr};

use anyhow::{Context, Result};
use ipnet::IpNet;
use rocksdb::{OptimisticTransactionOptions, ReadOptions, WriteOptions};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

use super::{
    Dai, DaiRead, DaiSettings, KeyReader, KeyWriter, Map, Txn,
    cursor::{DAY, date_of},
    customer_key,
    device::{address_key, decode_address_key},
    observation::ActivityRow,
    site_key,
    view::in_effect_at,
};
use crate::{CustomerDataDeletionJob, OwnedNetworkTable, types::FromKeyValue};

#[cfg(test)]
thread_local! {
    static ACTIVE_QUERY_RANGES_SCANNED: std::cell::RefCell<Option<std::sync::Arc<std::sync::Barrier>>> = const { std::cell::RefCell::new(None) };
}

const ACTIVE_QUERY_MAX_EXCLUDED_RANGES: usize = 256;
const ACTIVE_QUERY_MAX_QUERY_RANGES: usize = 64;
const ACTIVE_QUERY_MAX_DNS_SERVERS: usize = 4;
const ACTIVE_QUERY_MAX_PTR_NAMES: usize = 8;
const ACTIVE_QUERY_MAX_MDNS_SERVICES: usize = 32;
const ACTIVE_QUERY_MAX_SSDP_RESPONSES: usize = 16;
const ACTIVE_QUERY_DEFAULT_RATE: u32 = 20;
const ACTIVE_QUERY_MIN_RATE: u32 = 1;
const ACTIVE_QUERY_MAX_RATE: u32 = 100;
const ACTIVE_QUERY_IP_DEVICE_AGE: i64 = 30 * DAY;
const ACTIVE_QUERY_NO_ANSWER_WAIT: i64 = 7 * DAY;
const ACTIVE_QUERY_DAILY_AGE_DAYS: i64 = 30;
const ACTIVE_QUERY_GUARD_KEY: &[u8] = b"revision";
const ACTIVE_QUERY_KINDS: [DaiActiveQueryKind; 4] = [
    DaiActiveQueryKind::Ptr,
    DaiActiveQueryKind::Nbns,
    DaiActiveQueryKind::Mdns,
    DaiActiveQueryKind::Ssdp,
];
const ACTIVE_QUERY_HISTORY_AGE: i64 = 180 * DAY;
const ACTIVE_QUERY_INTERVAL: i64 = 2 * DAY;
const ACTIVE_QUERY_RESOLUTION_DELAY: i64 = 15 * 60 * 1_000_000_000;

/// The active query settings of a customer; absent settings are disabled.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DaiActiveQuerySettings {
    /// Whether active queries are enabled.
    pub enabled: bool,
    /// Networks whose addresses must not be queried.
    pub excluded_ranges: Vec<IpNet>,
    /// The revision of these settings.
    pub revision: u64,
}

/// The active query settings of a stored site.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DaiActiveQuerySite {
    /// The site's token.
    pub token: String,
    /// The networks available for targeted queries.
    pub query_ranges: Vec<IpNet>,
    /// DNS servers, in the order they should be tried.
    pub dns_servers: Vec<IpAddr>,
    /// The maximum packet rate per second.
    pub rate: u32,
    /// The revision of these settings.
    pub revision: u64,
}

impl DaiActiveQuerySite {
    fn absent(token: &str) -> Self {
        Self {
            token: token.to_owned(),
            query_ranges: Vec::new(),
            dns_servers: Vec::new(),
            rate: ACTIVE_QUERY_DEFAULT_RATE,
            revision: 0,
        }
    }
}

/// An enabled site and the parameters needed to send its queries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiActiveQueryEnabledSite {
    /// The customer's id.
    pub customer_id: u32,
    /// The site's token.
    pub token: String,
    /// The packet rate per second.
    pub rate: u32,
    /// DNS servers, in the order they should be tried.
    pub dns_servers: Vec<IpAddr>,
}

/// A refusal of an active query settings or round write.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DaiActiveQueryError {
    /// The expected revision differs from the stored revision.
    #[error("stale active query settings revision; stored revision is {stored}")]
    StaleRevision {
        /// The stored revision.
        stored: u64,
    },
    /// The customer has no site with this token.
    #[error("active query site not found: {token}")]
    SiteNotFound {
        /// The requested token.
        token: String,
    },
    /// A setting fails validation.
    #[error("invalid active query setting: {field}")]
    InvalidSetting {
        /// The offending field's name.
        field: &'static str,
    },
    /// Query networks overlap those of another site.
    #[error("active query ranges overlap: {ranges:?}")]
    RangesOverlap {
        /// The narrower network of each overlapping pair, without site identities.
        ranges: Vec<IpNet>,
    },
}

/// The four active query kinds, in their stored order.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DaiActiveQueryKind {
    /// Reverse DNS.
    Ptr,
    /// `NetBIOS` node status.
    Nbns,
    /// Unicast multicast DNS.
    Mdns,
    /// Unicast Simple Service Discovery Protocol.
    Ssdp,
}

impl DaiActiveQueryKind {
    fn number(self) -> u8 {
        match self {
            Self::Ptr => 0,
            Self::Nbns => 1,
            Self::Mdns => 2,
            Self::Ssdp => 3,
        }
    }
}

/// The result of one active query kind in a round.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum DaiActiveQueryResult<T> {
    /// An answer supplied by the caller, compared exactly as given.
    Value(T),
    /// The target replied without a name.
    NoName,
    /// No response arrived.
    NoResponse,
    /// No packet was sent.
    #[default]
    NotSent,
}

/// A `NetBIOS` node status answer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DaiActiveQueryNbns {
    /// The computer name, if present.
    pub computer_name: Option<String>,
    /// The workgroup or domain, if present.
    pub workgroup_or_domain: Option<String>,
    /// The hardware address, if present.
    pub mac: Option<[u8; 6]>,
}

/// A unicast mDNS answer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DaiActiveQueryMdns {
    /// The host name, if present.
    pub host_name: Option<String>,
    /// At most 32 service types.
    pub service_types: Vec<String>,
}

/// A single SSDP response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DaiActiveQuerySsdp {
    /// The ST header.
    pub st: String,
    /// The USN header.
    pub usn: String,
    /// The SERVER header.
    pub server: String,
}

/// The four results for one IP in an active query round.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DaiActiveQueryRound {
    /// The queried address.
    pub ip: IpAddr,
    /// Reverse DNS names, at most eight.
    pub ptr: DaiActiveQueryResult<Vec<String>>,
    /// `NetBIOS` node status.
    pub nbns: DaiActiveQueryResult<DaiActiveQueryNbns>,
    /// Unicast mDNS.
    pub mdns: DaiActiveQueryResult<DaiActiveQueryMdns>,
    /// At most sixteen SSDP responses.
    pub ssdp: DaiActiveQueryResult<Vec<DaiActiveQuerySsdp>>,
}

/// A display-only active query answer, in stored variant order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DaiActiveQueryValue {
    /// Reverse DNS names.
    Ptr(Vec<String>),
    /// A `NetBIOS` node status answer.
    Nbns(DaiActiveQueryNbns),
    /// A unicast mDNS answer.
    Mdns(DaiActiveQueryMdns),
    /// Unicast SSDP responses.
    Ssdp(Vec<DaiActiveQuerySsdp>),
}

type ActiveQueryResult = DaiActiveQueryResult<DaiActiveQueryValue>;

#[derive(Debug, Deserialize, Serialize)]
struct ActiveQueryIp {
    last_query: i64,
    had_answer: bool,
    results: [ActiveQueryResult; 4],
}

#[derive(Debug, Deserialize, Serialize)]
struct ActiveQueryAnswer {
    value: ActiveQueryResult,
    last_seen: i64,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct ActiveQueryDaily {
    sent: u64,
    with_value: u64,
}

impl<T> DaiActiveQueryResult<T> {
    fn map<U>(&self, map: impl FnOnce(&T) -> U) -> DaiActiveQueryResult<U> {
        match self {
            Self::Value(value) => DaiActiveQueryResult::Value(map(value)),
            Self::NoName => DaiActiveQueryResult::NoName,
            Self::NoResponse => DaiActiveQueryResult::NoResponse,
            Self::NotSent => DaiActiveQueryResult::NotSent,
        }
    }

    fn has_value(&self) -> bool {
        matches!(self, Self::Value(_))
    }
    fn sent(&self) -> bool {
        !matches!(self, Self::NotSent)
    }
}

impl DaiActiveQueryRound {
    fn validate(&self) -> Result<()> {
        if matches!(&self.ptr, DaiActiveQueryResult::Value(v) if v.len() > ACTIVE_QUERY_MAX_PTR_NAMES)
        {
            return invalid("ptr");
        }
        if matches!(&self.mdns, DaiActiveQueryResult::Value(v) if v.service_types.len() > ACTIVE_QUERY_MAX_MDNS_SERVICES)
        {
            return invalid("mdns");
        }
        if matches!(&self.ssdp, DaiActiveQueryResult::Value(v) if v.len() > ACTIVE_QUERY_MAX_SSDP_RESPONSES)
        {
            return invalid("ssdp");
        }
        Ok(())
    }

    fn results(&self) -> [ActiveQueryResult; 4] {
        [
            self.ptr.map(|v| DaiActiveQueryValue::Ptr(v.clone())),
            self.nbns.map(|v| DaiActiveQueryValue::Nbns(v.clone())),
            self.mdns.map(|v| DaiActiveQueryValue::Mdns(v.clone())),
            self.ssdp.map(|v| DaiActiveQueryValue::Ssdp(v.clone())),
        ]
    }
}

fn invalid<T>(field: &'static str) -> Result<T> {
    Err(DaiActiveQueryError::InvalidSetting { field }.into())
}

fn normalize(ranges: &[IpNet], cap: usize, field: &'static str) -> Result<Vec<IpNet>> {
    let mut ranges: Vec<_> = ranges.iter().map(IpNet::trunc).collect();
    ranges.sort_unstable();
    ranges.dedup();
    if ranges.len() > cap {
        return invalid(field);
    }
    Ok(ranges)
}

fn contains(ranges: &[IpNet], ip: IpAddr) -> bool {
    ranges.iter().any(|range| range.contains(&ip))
}

fn queryable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let first = ip.octets()[0];
            first != 0 && first != 127 && first < 224
        }
        IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast(),
    }
}

mod read;
pub use read::{
    DaiActiveAnswer, DaiActiveQueryKindCounts, DaiActiveQuerySiteState, DaiActiveQueryStatus,
    DaiIpActiveKind, DaiIpActiveQuery, DaiSiteActiveQuery,
};

impl Dai<'_> {
    /// Runs an active query operation against one transaction snapshot, retrying conflicts.
    fn active_query_transaction<T>(
        &self,
        mut attempt: impl FnMut(&Txn<'_>) -> Result<T>,
    ) -> Result<T> {
        loop {
            let mut options = OptimisticTransactionOptions::default();
            options.set_snapshot(true);
            let txn = self.db.transaction_opt(&WriteOptions::default(), &options);
            let value = match attempt(&txn) {
                Ok(value) => value,
                Err(error)
                    if error
                        .downcast_ref::<rocksdb::Error>()
                        .is_some_and(active_query_conflict) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
            match txn.commit() {
                Ok(()) => return Ok(value),
                Err(e) if active_query_conflict(&e) => {}
                Err(e) => return Err(e).context("committing active query transaction"),
            }
        }
    }

    fn active_query_get<T: DeserializeOwned>(
        txn: &Txn<'_>,
        map: &Map<'_>,
        key: &[u8],
    ) -> Result<Option<T>> {
        let snapshot = txn.snapshot();
        let mut options = ReadOptions::default();
        options.set_snapshot(&snapshot);
        txn.get_for_update_cf_opt(map.cf, key, crate::EXCLUSIVE, &options)
            .context("reading active query row for update")?
            .map(|v| super::super::deserialize(&v))
            .transpose()
    }

    pub(crate) fn active_query_settings(&self, customer: u32) -> Result<DaiActiveQuerySettings> {
        self.active_query_transaction(|txn| {
            Ok(Self::value_in(
                &txn.snapshot(),
                &self.active_query_settings,
                &customer_key(customer),
            )?
            .unwrap_or_default())
        })
    }

    pub(crate) fn set_active_query_settings(
        &self,
        customer: u32,
        expected: u64,
        enabled: bool,
        ranges: &[IpNet],
    ) -> Result<DaiActiveQuerySettings> {
        self.active_query_transaction(|txn| {
            let key = customer_key(customer);
            let stored: DaiActiveQuerySettings =
                Self::active_query_get(txn, &self.active_query_settings, &key)?.unwrap_or_default();
            check_revision(expected, stored.revision)?;
            let next = DaiActiveQuerySettings {
                enabled,
                excluded_ranges: normalize(
                    ranges,
                    ACTIVE_QUERY_MAX_EXCLUDED_RANGES,
                    "excluded_ranges",
                )?,
                revision: stored
                    .revision
                    .checked_add(1)
                    .context("active query settings revision overflow")?,
            };
            Self::put_row(txn, &self.active_query_settings, &key, &next)?;
            Ok(next)
        })
    }

    pub(crate) fn active_query_sites(&self, customer: u32) -> Result<Vec<DaiActiveQuerySite>> {
        self.active_query_transaction(|txn| {
            let snapshot = txn.snapshot();
            self.sites_in(&snapshot, customer)?
                .into_iter()
                .map(|site| {
                    Ok(Self::value_in(
                        &snapshot,
                        &self.active_query_sites,
                        &site_key(customer, &site.token),
                    )?
                    .unwrap_or_else(|| DaiActiveQuerySite::absent(&site.token)))
                })
                .collect()
        })
    }

    pub(crate) fn set_active_query_site(
        &self,
        customer: u32,
        token: &str,
        expected: u64,
        ranges: &[IpNet],
        dns: &[IpAddr],
        rate: u32,
    ) -> Result<DaiActiveQuerySite> {
        self.active_query_transaction(|txn| {
            self.lock_customer(txn, customer)?;
            let key = site_key(customer, token);
            if txn
                .snapshot()
                .value(&self.sites, &key)
                .with_context(|| {
                    format!("reading active query site {token} of customer {customer}")
                })?
                .is_none()
            {
                return Err(DaiActiveQueryError::SiteNotFound {
                    token: token.to_owned(),
                }
                .into());
            }
            let stored: DaiActiveQuerySite =
                Self::active_query_get(txn, &self.active_query_sites, &key)?
                    .unwrap_or_else(|| DaiActiveQuerySite::absent(token));
            check_revision(expected, stored.revision)?;
            let query_ranges = normalize(ranges, ACTIVE_QUERY_MAX_QUERY_RANGES, "query_ranges")?;
            if query_ranges.iter().any(|r| r.prefix_len() == 0) {
                return invalid("query_ranges");
            }
            let mut dns_servers = Vec::new();
            for ip in dns {
                if !contains(&query_ranges, *ip) || !queryable(*ip) {
                    return invalid("dns_servers");
                }
                if !dns_servers.contains(ip) {
                    dns_servers.push(*ip);
                }
            }
            if dns_servers.len() > ACTIVE_QUERY_MAX_DNS_SERVERS {
                return invalid("dns_servers");
            }
            if !(ACTIVE_QUERY_MIN_RATE..=ACTIVE_QUERY_MAX_RATE).contains(&rate) {
                return invalid("rate");
            }
            let guard: u64 = Self::active_query_get(
                txn,
                &self.active_query_range_guard,
                ACTIVE_QUERY_GUARD_KEY,
            )?
            .unwrap_or_default();
            Self::put_row(
                txn,
                &self.active_query_range_guard,
                ACTIVE_QUERY_GUARD_KEY,
                &guard.wrapping_add(1),
            )?;
            let mut overlaps = Vec::new();
            if !query_ranges.is_empty() {
                for (other_key, value) in
                    Self::scan(&self.active_query_sites, &txn.snapshot(), &[])?
                {
                    if other_key.as_ref() == key {
                        continue;
                    }
                    let other: DaiActiveQuerySite = super::super::deserialize(&value)?;
                    for a in &query_ranges {
                        for b in &other.query_ranges {
                            if a.contains(&b.network()) || b.contains(&a.network()) {
                                overlaps.push(if a.prefix_len() >= b.prefix_len() {
                                    *a
                                } else {
                                    *b
                                });
                            }
                        }
                    }
                }
            }
            #[cfg(test)]
            ACTIVE_QUERY_RANGES_SCANNED.with(|hook| {
                if let Some(barrier) = hook.borrow_mut().take() {
                    barrier.wait();
                }
            });
            if !overlaps.is_empty() {
                overlaps.sort_unstable();
                overlaps.dedup();
                return Err(DaiActiveQueryError::RangesOverlap { ranges: overlaps }.into());
            }
            let next = DaiActiveQuerySite {
                token: token.to_owned(),
                query_ranges,
                dns_servers,
                rate,
                revision: stored
                    .revision
                    .checked_add(1)
                    .context("active query site revision overflow")?,
            };
            Self::put_row(txn, &self.active_query_sites, &key, &next)?;
            Ok(next)
        })
    }

    fn active_query_deleting(&self, reader: &impl DaiRead, customer: u32) -> Result<bool> {
        let map = Map::open(self.db, super::super::CUSTOMER_DELETION_JOBS)
            .context("opening customer deletion jobs")?;
        match reader
            .value(&map, &customer.to_be_bytes())
            .context("reading active query customer deletion job")?
        {
            Some(value) => Ok(CustomerDataDeletionJob::from_key_value(
                &customer.to_be_bytes(),
                &value,
            )?
            .is_unfinished()),
            None => Ok(false),
        }
    }

    fn active_query_enabled(&self, reader: &impl DaiRead, customer: u32) -> Result<bool> {
        let settings: DaiSettings =
            Self::value_in(reader, &self.settings, &customer_key(customer))?.unwrap_or_default();
        let active: DaiActiveQuerySettings =
            Self::value_in(reader, &self.active_query_settings, &customer_key(customer))?
                .unwrap_or_default();
        Ok(settings.device_account_identification
            && active.enabled
            && !self.active_query_deleting(reader, customer)?)
    }

    pub(crate) fn active_query_sites_enabled(&self) -> Result<Vec<DaiActiveQueryEnabledSite>> {
        self.active_query_transaction(|txn| {
            let snapshot = txn.snapshot();
            let mut sites = Vec::new();
            for (key, value) in Self::scan(&self.active_query_sites, &snapshot, &[])? {
                let customer = KeyReader::new(&key).u32()?;
                let site: DaiActiveQuerySite = super::super::deserialize(&value)?;
                if !site.query_ranges.is_empty()
                    && self.active_query_enabled(&snapshot, customer)?
                {
                    sites.push(DaiActiveQueryEnabledSite {
                        customer_id: customer,
                        token: site.token,
                        rate: site.rate,
                        dns_servers: site.dns_servers,
                    });
                }
            }
            Ok(sites)
        })
    }

    pub(crate) fn active_query_send_allowed(
        &self,
        customer: u32,
        token: &str,
        target: IpAddr,
        dns: Option<IpAddr>,
    ) -> Result<bool> {
        self.active_query_transaction(|txn| {
            let snapshot = txn.snapshot();
            if !self.active_query_enabled(&snapshot, customer)? {
                return Ok(false);
            }
            let Some(site) = Self::value_in::<DaiActiveQuerySite>(
                &snapshot,
                &self.active_query_sites,
                &site_key(customer, token),
            )?
            else {
                return Ok(false);
            };
            let active: DaiActiveQuerySettings = Self::value_in(
                &snapshot,
                &self.active_query_settings,
                &customer_key(customer),
            )?
            .unwrap_or_default();
            let internal = OwnedNetworkTable::open(self.db)
                .context("opening customer networks")?
                .get_with(&snapshot, customer)?;
            Ok(contains(&site.query_ranges, target)
                && !contains(&active.excluded_ranges, target)
                && internal.is_some_and(|set| {
                    set.internal_groups()
                        .iter()
                        .any(|group| group.contains(target))
                })
                && dns.is_none_or(|dns| {
                    site.dns_servers.contains(&dns) && contains(&site.query_ranges, dns)
                }))
        })
    }

    pub(crate) fn active_query_targets(
        &self,
        customer: u32,
        token: &str,
        now: i64,
        max: usize,
    ) -> Result<Vec<IpAddr>> {
        self.active_query_transaction(|txn| {
            self.active_query_targets_in(&txn.snapshot(), customer, token, now, max)
        })
    }

    pub(super) fn active_query_targets_in(
        &self,
        snapshot: &super::Snapshot<'_, impl rocksdb::DBAccess>,
        customer: u32,
        token: &str,
        now: i64,
        max: usize,
    ) -> Result<Vec<IpAddr>> {
        if max == 0 || !self.active_query_enabled(snapshot, customer)? {
            return Ok(Vec::new());
        }
        let Some(site) = Self::value_in::<DaiActiveQuerySite>(
            snapshot,
            &self.active_query_sites,
            &site_key(customer, token),
        )?
        else {
            return Ok(Vec::new());
        };
        if site.query_ranges.is_empty() {
            return Ok(Vec::new());
        }
        let active: DaiActiveQuerySettings = Self::value_in(
            snapshot,
            &self.active_query_settings,
            &customer_key(customer),
        )?
        .unwrap_or_default();
        let view = self.customer_view(snapshot, customer)?;
        let collections = self.collections(snapshot, &view)?;
        let mut targets = Vec::new();
        for (key, value) in Self::scan(&self.ip_activity, snapshot, &site_key(customer, token))? {
            let (_, _, ip) = decode_address_key(&key)?;
            let activity: ActivityRow = super::super::deserialize(&value)?;
            if !(now.saturating_sub(ACTIVE_QUERY_IP_DEVICE_AGE)..=now).contains(&activity.last_seen)
                || !self.active_query_target_in(snapshot, &view, &site, &active, ip)?
            {
                continue;
            }
            if self
                .address_bindings(snapshot, customer, token, ip)?
                .iter()
                .any(|(start, row)| {
                    in_effect_at(*start, row, activity.last_seen) || in_effect_at(*start, row, now)
                })
            {
                continue;
            }
            let time = activity
                .first_seen
                .saturating_add(ACTIVE_QUERY_RESOLUTION_DELAY);
            if view
                .select(&collections, token, time, now)
                .compared
                .is_some_and(|c| c.time < time)
            {
                continue;
            }
            let state: Option<ActiveQueryIp> =
                Self::value_in(snapshot, &self.active_query_ips, &key)?;
            if state.as_ref().is_some_and(|s| {
                s.last_query
                    > now.saturating_sub(if s.had_answer {
                        DAY
                    } else {
                        ACTIVE_QUERY_NO_ANSWER_WAIT
                    })
            }) {
                continue;
            }
            targets.push((state.map(|s| s.last_query), Reverse(activity.last_seen), ip));
        }
        targets.sort_unstable();
        Ok(targets.into_iter().take(max).map(|(_, _, ip)| ip).collect())
    }

    pub(crate) fn store_active_query_round(
        &self,
        customer: u32,
        token: &str,
        time: i64,
        rounds: &[DaiActiveQueryRound],
    ) -> Result<()> {
        self.active_query_transaction(|txn| {
            // Validate the entire round before writing anything, including dropped IPs.
            for round in rounds {
                round.validate()?;
            }
            let Some(site) = Self::active_query_get::<DaiActiveQuerySite>(
                txn,
                &self.active_query_sites,
                &site_key(customer, token),
            )?
            else {
                return Ok(());
            };
            if site.query_ranges.is_empty() {
                return Ok(());
            }
            for round in rounds {
                if !contains(&site.query_ranges, round.ip) {
                    continue;
                }
                let key = address_key(customer, token, round.ip);
                let previous: Option<ActiveQueryIp> =
                    Self::active_query_get(txn, &self.active_query_ips, &key)?;
                // A round at the stored time is stale too: its answer key would replace the
                // row that round wrote, and its daily counts would be added a second time.
                if previous.is_some_and(|p| time <= p.last_query) {
                    continue;
                }
                let results = round.results();
                if !results.iter().any(DaiActiveQueryResult::sent) {
                    continue;
                }
                for (kind, result) in ACTIVE_QUERY_KINDS
                    .into_iter()
                    .zip(&results)
                    .filter(|(_, result)| result.sent())
                {
                    let kind = kind.number();
                    let prefix = active_query_answer_prefix(customer, token, round.ip, kind);
                    let mut options = ReadOptions::default();
                    options.set_iterate_range(rocksdb::PrefixRange(prefix));
                    let latest = txn
                        .snapshot()
                        .iter_rows(&self.active_answers, options, rocksdb::IteratorMode::End)
                        .next()
                        .transpose()
                        .context("reading latest active query answer")?;
                    let answer_key = if let Some((key, value)) = latest {
                        let answer: ActiveQueryAnswer = super::super::deserialize(&value)?;
                        if answer.value == *result
                            && time <= answer.last_seen.saturating_add(ACTIVE_QUERY_INTERVAL)
                        {
                            key.to_vec()
                        } else {
                            active_query_answer_key(customer, token, round.ip, kind, time)
                        }
                    } else {
                        active_query_answer_key(customer, token, round.ip, kind, time)
                    };
                    Self::put_row(
                        txn,
                        &self.active_answers,
                        &answer_key,
                        &ActiveQueryAnswer {
                            value: result.clone(),
                            last_seen: time,
                        },
                    )?;
                    let daily_key = KeyWriter::default()
                        .u32(customer)
                        .str(token)
                        .date(date_of(time)?)
                        .byte(kind)
                        .finish();
                    let mut daily: ActiveQueryDaily =
                        Self::active_query_get(txn, &self.active_query_daily, &daily_key)?
                            .unwrap_or_default();
                    daily.sent = daily
                        .sent
                        .checked_add(1)
                        .context("active query daily sent count overflow")?;
                    daily.with_value = daily
                        .with_value
                        .checked_add(u64::from(result.has_value()))
                        .context("active query daily answer count overflow")?;
                    Self::put_row(txn, &self.active_query_daily, &daily_key, &daily)?;
                }
                let state = ActiveQueryIp {
                    last_query: time,
                    had_answer: results.iter().any(DaiActiveQueryResult::has_value),
                    results,
                };
                Self::put_row(txn, &self.active_query_ips, &key, &state)?;
            }
            Ok(())
        })
    }

    pub(super) fn apply_active_query_retention(&self, now: i64) -> Result<()> {
        let oldest = now.saturating_sub(ACTIVE_QUERY_HISTORY_AGE);
        self.delete_where(&self.active_answers, |_, v| {
            Ok(super::super::deserialize::<ActiveQueryAnswer>(v)?.last_seen < oldest)
        })?;
        self.delete_where(&self.active_query_ips, |_, v| {
            Ok(super::super::deserialize::<ActiveQueryIp>(v)?.last_query < oldest)
        })?;
        let oldest_date = i64::from(date_of(now)?) - ACTIVE_QUERY_DAILY_AGE_DAYS;
        self.delete_where(&self.active_query_daily, |key, _| {
            let mut reader = KeyReader::new(key);
            reader.u32()?;
            reader.str()?;
            Ok(i64::from(reader.date()?) < oldest_date)
        })
    }

    pub(super) fn delete_active_query_customer(&self, customer: u32) -> Result<()> {
        for map in [
            &self.active_query_settings,
            &self.active_query_sites,
            &self.active_query_ips,
            &self.active_answers,
            &self.active_query_daily,
        ] {
            self.delete_prefix(map, &customer_key(customer))?;
        }
        Ok(())
    }
}

fn active_query_conflict(error: &rocksdb::Error) -> bool {
    matches!(
        error.kind(),
        rocksdb::ErrorKind::Busy | rocksdb::ErrorKind::TryAgain
    )
}

fn check_revision(expected: u64, stored: u64) -> Result<()> {
    if expected != stored {
        return Err(DaiActiveQueryError::StaleRevision { stored }.into());
    }
    Ok(())
}

fn active_query_answer_prefix(customer: u32, token: &str, ip: IpAddr, kind: u8) -> Vec<u8> {
    KeyWriter::default()
        .u32(customer)
        .str(token)
        .ip(ip)
        .byte(kind)
        .finish()
}

fn active_query_answer_key(customer: u32, token: &str, ip: IpAddr, kind: u8, time: i64) -> Vec<u8> {
    KeyWriter::default()
        .u32(customer)
        .str(token)
        .ip(ip)
        .byte(kind)
        .i64(time)
        .finish()
}

#[cfg(test)]
mod tests;
