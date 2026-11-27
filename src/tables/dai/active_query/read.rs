//! Snapshot reads of display-only active query answers and query state.

use std::net::IpAddr;

use anyhow::{Context, Result};

use super::{
    ACTIVE_QUERY_INTERVAL, ACTIVE_QUERY_KINDS, ActiveQueryAnswer, ActiveQueryDaily, ActiveQueryIp,
    Dai, DaiActiveQueryKind, DaiActiveQueryResult, DaiActiveQuerySettings, DaiActiveQuerySite,
    DaiActiveQueryValue, DaiRead, KeyReader, contains, customer_key, date_of, queryable, site_key,
};
use crate::tables::dai::{Snapshot, device::address_key, view::CustomerView};

const WAITING_IP_LIMIT: usize = 10_000;

/// One stored active query result interval.
///
/// A row is valid from `first_seen` through 48 hours after `last_seen`,
/// inclusive, cut short by the next row of its kind other than `NoResponse`.
/// Only a valid `Value` is shown as an answer; history includes all results.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiActiveAnswer {
    /// The query kind.
    pub kind: DaiActiveQueryKind,
    /// The stored result; never `NotSent`, and always `Value` for a valid answer.
    pub value: DaiActiveQueryResult<DaiActiveQueryValue>,
    /// The first observation time, in nanoseconds since the UNIX epoch.
    pub first_seen: i64,
    /// The last observation time, in nanoseconds since the UNIX epoch.
    pub last_seen: i64,
}

/// Why an IP is not currently being queried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaiActiveQueryStatus {
    /// Queries are disabled for the customer or site.
    QueriesOff,
    /// Target selection always excludes this address.
    NotQueryTarget,
    /// The address has never been queried.
    NotQueriedYet,
}

/// An IP's valid answer and last round result for one query kind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiIpActiveKind {
    /// The query kind.
    pub kind: DaiActiveQueryKind,
    /// The value valid at the read time, if any.
    pub answer: Option<DaiActiveAnswer>,
    /// The result in the last round, including `NotSent`.
    pub last_result: Option<DaiActiveQueryResult<DaiActiveQueryValue>>,
}

/// The active query state of an IP device row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiIpActiveQuery {
    /// The reason queries are off, excluded, or not yet sent, in that precedence.
    pub status: Option<DaiActiveQueryStatus>,
    /// The last round time, even when queries are disabled.
    pub last_query: Option<i64>,
    /// Exactly four entries: PTR, NBNS, mDNS, SSDP.
    pub kinds: Vec<DaiIpActiveKind>,
}

/// Whether active queries are enabled at a site.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaiActiveQuerySiteState {
    /// DAI or active queries are off, or customer deletion is unfinished.
    CustomerOff,
    /// The site has no configured query ranges.
    NoQueryRanges,
    /// Queries are enabled.
    On,
}

/// The daily and thirty-day counts for one query kind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiActiveQueryKindCounts {
    /// The query kind.
    pub kind: DaiActiveQueryKind,
    /// Queries sent on today's UTC date.
    pub sent_today: u64,
    /// Today's results that held a value.
    pub answered_today: u64,
    /// Queries sent on the thirty UTC dates ending today.
    pub sent_last_30_days: u64,
    /// Results holding a value on the thirty UTC dates ending today.
    pub answered_last_30_days: u64,
}

/// A site's active query configuration, progress and counters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiSiteActiveQuery {
    /// The customer and site enable state.
    pub state: DaiActiveQuerySiteState,
    /// Whether the site has no configured DNS server.
    pub no_dns_servers: bool,
    /// The latest stored query time at the site.
    pub last_query: Option<i64>,
    /// Exactly four entries: PTR, NBNS, mDNS, SSDP.
    pub kinds: Vec<DaiActiveQueryKindCounts>,
    /// The number of waiting targets, capped at 10,000.
    pub waiting_ips: usize,
    /// Whether more than 10,000 IPs are waiting.
    pub waiting_ips_over_limit: bool,
}

impl Dai<'_> {
    /// Applies the target conditions independent of age, bindings and retry timing.
    pub(in crate::tables::dai) fn active_query_target_in(
        &self,
        reader: &impl DaiRead,
        view: &CustomerView,
        site: &DaiActiveQuerySite,
        active: &DaiActiveQuerySettings,
        ip: IpAddr,
    ) -> Result<bool> {
        Ok(contains(&site.query_ranges, ip)
            && view.is_internal(ip)
            && !contains(&active.excluded_ranges, ip)
            && queryable(ip)
            && reader
                .value(
                    &self.fixed_ips,
                    &address_key(view.customer, &site.token, ip),
                )
                .with_context(|| format!("reading fixed IP {ip} at site {}", site.token))?
                .is_none())
    }

    pub(crate) fn active_answers(
        &self,
        customer: u32,
        site: &str,
        ip: IpAddr,
    ) -> Result<Vec<DaiActiveAnswer>> {
        self.active_answers_in(&self.db.snapshot(), customer, site, ip)
    }

    pub(in crate::tables::dai) fn active_answers_in(
        &self,
        reader: &impl DaiRead,
        customer: u32,
        site: &str,
        ip: IpAddr,
    ) -> Result<Vec<DaiActiveAnswer>> {
        let mut answers = Vec::new();
        for (key, value) in Self::scan(
            &self.active_answers,
            reader,
            &address_key(customer, site, ip),
        )? {
            let mut key = KeyReader::new(&key);
            key.u32()?;
            key.str()?;
            key.ip()?;
            let number = key.byte()?;
            let kind = ACTIVE_QUERY_KINDS
                .get(usize::from(number))
                .copied()
                .context("invalid active query answer kind")?;
            let first_seen = key.i64()?;
            key.finish()?;
            let row: ActiveQueryAnswer = super::super::super::deserialize(&value)?;
            answers.push(DaiActiveAnswer {
                kind,
                value: row.value,
                first_seen,
                last_seen: row.last_seen,
            });
        }
        answers.sort_unstable_by_key(|row| (std::cmp::Reverse(row.first_seen), row.kind.number()));
        Ok(answers)
    }

    pub(in crate::tables::dai) fn active_answers_at(
        &self,
        reader: &impl DaiRead,
        customer: u32,
        site: &str,
        ip: IpAddr,
        time: i64,
    ) -> Result<Vec<DaiActiveAnswer>> {
        let rows = self.active_answers_in(reader, customer, site, ip)?;
        // History is newest first. The latest non-no-response row at or before
        // the time cuts off every older such row, even if it has expired.
        Ok(ACTIVE_QUERY_KINDS
            .into_iter()
            .filter_map(|kind| {
                rows.iter()
                    .find(|row| {
                        row.kind == kind
                            && row.first_seen <= time
                            && !matches!(row.value, DaiActiveQueryResult::NoResponse)
                    })
                    .filter(|row| {
                        row.value.has_value()
                            && time <= row.last_seen.saturating_add(ACTIVE_QUERY_INTERVAL)
                    })
                    .cloned()
            })
            .collect())
    }

    pub(in crate::tables::dai) fn ip_active_query_in(
        &self,
        snapshot: &Snapshot<'_>,
        view: &CustomerView,
        site: &str,
        ip: IpAddr,
        now: i64,
    ) -> Result<DaiIpActiveQuery> {
        let customer = view.customer;
        let config = Self::value_in::<DaiActiveQuerySite>(
            snapshot,
            &self.active_query_sites,
            &site_key(customer, site),
        )?;
        let active: DaiActiveQuerySettings = Self::value_in(
            snapshot,
            &self.active_query_settings,
            &customer_key(customer),
        )?
        .unwrap_or_default();
        let stored: Option<ActiveQueryIp> = Self::value_in(
            snapshot,
            &self.active_query_ips,
            &address_key(customer, site, ip),
        )?;
        let status = if !self.active_query_enabled(snapshot, customer)?
            || config.as_ref().is_none_or(|s| s.query_ranges.is_empty())
        {
            Some(DaiActiveQueryStatus::QueriesOff)
        } else if let Some(config) = &config
            && !self.active_query_target_in(snapshot, view, config, &active, ip)?
        {
            Some(DaiActiveQueryStatus::NotQueryTarget)
        } else if stored.is_none() {
            Some(DaiActiveQueryStatus::NotQueriedYet)
        } else {
            None
        };
        let answers = self.active_answers_at(snapshot, customer, site, ip, now)?;
        Ok(DaiIpActiveQuery {
            status,
            last_query: stored.as_ref().map(|s| s.last_query),
            kinds: ACTIVE_QUERY_KINDS
                .into_iter()
                .enumerate()
                .map(|(index, kind)| DaiIpActiveKind {
                    kind,
                    answer: answers.iter().find(|a| a.kind == kind).cloned(),
                    last_result: stored.as_ref().and_then(|s| s.results.get(index)).cloned(),
                })
                .collect(),
        })
    }

    pub(in crate::tables::dai) fn site_active_query_in(
        &self,
        snapshot: &Snapshot<'_>,
        customer: u32,
        site: &str,
        now: i64,
    ) -> Result<DaiSiteActiveQuery> {
        let prefix = site_key(customer, site);
        let config: Option<DaiActiveQuerySite> =
            Self::value_in(snapshot, &self.active_query_sites, &prefix)?;
        let state = if !self.active_query_enabled(snapshot, customer)? {
            DaiActiveQuerySiteState::CustomerOff
        } else if config.as_ref().is_none_or(|s| s.query_ranges.is_empty()) {
            DaiActiveQuerySiteState::NoQueryRanges
        } else {
            DaiActiveQuerySiteState::On
        };
        let mut last_query = None;
        for (_, value) in Self::scan(&self.active_query_ips, snapshot, &prefix)? {
            let row: ActiveQueryIp = super::super::super::deserialize(&value)?;
            last_query =
                Some(last_query.map_or(row.last_query, |time: i64| time.max(row.last_query)));
        }
        let today = i64::from(date_of(now)?);
        let mut kinds: Vec<_> = ACTIVE_QUERY_KINDS
            .into_iter()
            .map(|kind| DaiActiveQueryKindCounts {
                kind,
                sent_today: 0,
                answered_today: 0,
                sent_last_30_days: 0,
                answered_last_30_days: 0,
            })
            .collect();
        for (key, value) in Self::scan(&self.active_query_daily, snapshot, &prefix)? {
            let mut key = KeyReader::new(&key);
            key.u32()?;
            key.str()?;
            let date = i64::from(key.date()?);
            let number = key.byte()?;
            key.finish()?;
            if !(today - 29..=today).contains(&date) {
                continue;
            }
            let counts = kinds
                .get_mut(usize::from(number))
                .context("invalid active query daily kind")?;
            let row: ActiveQueryDaily = super::super::super::deserialize(&value)?;
            counts.sent_last_30_days = counts
                .sent_last_30_days
                .checked_add(row.sent)
                .context("active query sent count overflow")?;
            counts.answered_last_30_days = counts
                .answered_last_30_days
                .checked_add(row.with_value)
                .context("active query answer count overflow")?;
            if date == today {
                counts.sent_today = row.sent;
                counts.answered_today = row.with_value;
            }
        }
        let waiting = if state == DaiActiveQuerySiteState::On {
            self.active_query_targets_in(snapshot, customer, site, now, WAITING_IP_LIMIT + 1)?
                .len()
        } else {
            0
        };
        Ok(DaiSiteActiveQuery {
            state,
            no_dns_servers: config.as_ref().is_none_or(|s| s.dns_servers.is_empty()),
            last_query,
            kinds,
            waiting_ips: waiting.min(WAITING_IP_LIMIT),
            waiting_ips_over_limit: waiting > WAITING_IP_LIMIT,
        })
    }
}
