//! The state the DAI reads answer from: one customer's configuration, its
//! sensors' collection state and the evidence gap rules, read from one
//! database snapshot.
//!
//! Core DAI transactions take no snapshot, so their reads can see writes
//! committed between them. Every read here instead uses one [`Snapshot`],
//! taken directly from the database or from an active query transaction,
//! and so answers from one consistent state.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use anyhow::{Context, Result};
use review_protocol::types::DaiObservationKind;
use rocksdb::IteratorMode;
use serde::de::DeserializeOwned;
use uuid::Uuid;

use super::{
    Assignment, CustomerSensors, Dai, DaiRead, DaiSettings, DaiSite, KINDS, KeyReader, KeyWriter,
    Map, RawRow, SensorState, Snapshot,
    cursor::{CursorRow, DAY, pair_key},
    customer_key, decode_sensor_site,
    device::{AliasRow, BindingRow, address_key, alias_key, decode_binding_key, device_key},
    observation::decode_gap_key,
    sensor_key,
};
use crate::{HostNetworkGroup, OwnedNetworkTable};

/// The observation kinds whose collection decides an evidence gap: O1, O4
/// and O5.
pub(super) const EVIDENCE_KINDS: [DaiObservationKind; 3] = [
    DaiObservationKind::DhcpLease,
    DaiObservationKind::Kerberos,
    DaiObservationKind::Ntlm,
];
/// How recent a sensor's last received record time must be for the sensor
/// to count toward its site's compared time: 24 hours, ending at "now"; a
/// time after "now" is not recent.
pub(super) const QUIET_AFTER: i64 = DAY;

/// The value of a sensor that set its compared time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaiComparedValue {
    /// The cursor of the sensor's pair of the kind.
    Cursor(DaiObservationKind),
    /// The earliest pending slot start of the sensor's pair of the kind.
    EarliestPending(DaiObservationKind),
    /// The sensor's last received record time.
    LastRecordTime,
    /// The sensor's resolver point: the point up to which resolution has
    /// processed its pending observations.
    ResolverPoint,
}

/// A compared time: the time, the sensor whose value set it and which value
/// that was.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Compared {
    pub(super) sensor: String,
    pub(super) value: DaiComparedValue,
    pub(super) time: i64,
}

/// A sensor's collection state, as the evidence gap and the collection
/// status read it.
#[derive(Clone, Debug, Default)]
pub(super) struct SensorCollection {
    /// Its last received record time.
    pub(super) last_record_time: Option<i64>,
    /// The cursor of each kind with a cursor row, in kind order.
    pub(super) cursors: Vec<(DaiObservationKind, i64)>,
    /// The O1, O4 and O5 pairs with a cursor row whose first send has not
    /// finished, in kind order.
    pub(super) unsent: Vec<DaiObservationKind>,
    /// Its compared time, the earliest of its values, or `None` if none of
    /// its O1, O4 and O5 pairs is included.
    pub(super) compared: Option<(i64, DaiComparedValue)>,
}

/// A catch-up gap: a range a (sensor, kind) skipped by the catch-up limit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Gap {
    pub(super) sensor: String,
    pub(super) kind: DaiObservationKind,
    pub(super) start: i64,
    pub(super) end: i64,
}

/// How a site's compared time at a time was chosen.
#[derive(Debug, Default)]
pub(super) struct SiteSelection {
    /// The compared time, or `None` if no sensor considered has one.
    pub(super) compared: Option<Compared>,
    /// The sensors of the site left out by the 24-hour rule, in name order.
    pub(super) quiet: Vec<String>,
}

/// One customer's DAI configuration and sensors, as one snapshot holds
/// them.
pub(super) struct CustomerView {
    pub(super) customer: u32,
    pub(super) settings: DaiSettings,
    /// The stored sites, in token order.
    pub(super) sites: Vec<DaiSite>,
    /// The default site's token, if the customer has one.
    pub(super) default_site: Option<String>,
    /// Whether the customer is multi-site, as `Dai::is_multi_site_in`
    /// computes it.
    pub(super) multi_site: bool,
    /// The one site in use of a customer that is not multi-site: the site
    /// holding its sensors, or the default site if it has none.
    pub(super) single_site: Option<String>,
    /// The customer's sensors: the customer sensors of the customer (a name
    /// the node table gives for this customer only) and every sensor its
    /// sites list.
    pub(super) sensors: BTreeSet<String>,
    /// The groups of the customer's internal networks.
    pub(super) internal: Vec<HostNetworkGroup>,
    /// The `dai sensor sites` rows of each sensor naming the customer, as
    /// (effective time, site token), in time order.
    histories: BTreeMap<String, Vec<(i64, String)>>,
}

impl CustomerView {
    /// Returns whether `token` is one of the customer's stored sites.
    pub(super) fn has_site(&self, token: &str) -> bool {
        self.sites.iter().any(|site| site.token == token)
    }

    /// Returns the site `sensor` was in at the time `time`: the site of its
    /// latest sensor site row naming the customer effective at or before
    /// `time`, else the default site, as `Dai::sensor_site` gives it.
    pub(super) fn site_at(&self, sensor: &str, time: i64) -> Option<&str> {
        self.histories
            .get(sensor)
            .and_then(|rows| {
                rows.iter()
                    .take_while(|(effective, _)| *effective <= time)
                    .last()
                    .map(|(_, site)| site.as_str())
            })
            .or(self.default_site.as_deref())
    }

    /// Returns whether `sensor` was in `site` at some time of `[from, to)`.
    pub(super) fn in_site_during(&self, sensor: &str, site: &str, from: i64, to: i64) -> bool {
        if from >= to {
            return false;
        }
        if self.site_at(sensor, from) == Some(site) {
            return true;
        }
        self.histories.get(sensor).is_some_and(|rows| {
            rows.iter().any(|(effective, row_site)| {
                *effective > from && *effective < to && row_site == site
            })
        })
    }

    /// Returns whether `ip` lies in one of the customer's internal networks.
    pub(super) fn is_internal(&self, ip: IpAddr) -> bool {
        self.internal.iter().any(|group| group.contains(ip))
    }

    /// Returns the sensors whose site at `time` is `site`, in name order.
    pub(super) fn sensors_in(&self, site: &str, time: i64) -> impl Iterator<Item = &str> {
        self.sensors
            .iter()
            .map(String::as_str)
            .filter(move |sensor| self.site_at(sensor, time) == Some(site))
    }

    /// Chooses the compared time of `site` at the time `time` among
    /// `collections`, the sensors' collection states, at `now`.
    ///
    /// Of the sensors whose site at `time` is `site`, those whose last
    /// received record time is within [`QUIET_AFTER`] before `now`, and not
    /// after `now`, count,
    /// and the earliest of their compared times is the site's; if none
    /// does, the one with the latest last received record time decides.
    pub(super) fn select(
        &self,
        collections: &BTreeMap<String, SensorCollection>,
        site: &str,
        time: i64,
        now: i64,
    ) -> SiteSelection {
        let recent_from = now.saturating_sub(QUIET_AFTER);
        let mut active = Vec::new();
        let mut quiet = Vec::new();
        for sensor in self.sensors_in(site, time) {
            let Some(collection) = collections.get(sensor) else {
                continue;
            };
            if collection
                .last_record_time
                .is_some_and(|last| (recent_from..=now).contains(&last))
            {
                active.push((sensor, collection));
            } else {
                quiet.push((sensor, collection));
            }
        }
        let compared_of = |(sensor, collection): (&str, &SensorCollection)| {
            collection.compared.map(|(time, value)| Compared {
                sensor: sensor.to_string(),
                value,
                time,
            })
        };
        if active.is_empty() {
            // The quiet sensor with the latest last received record time
            // decides; of two with one time, the one with a compared time,
            // then the earlier compared time.
            let decider = quiet
                .iter()
                .enumerate()
                .max_by_key(|(_, (_, collection))| {
                    (
                        collection.last_record_time,
                        collection.compared.is_some(),
                        std::cmp::Reverse(collection.compared.map(|(time, _)| time)),
                    )
                })
                .map(|(index, _)| index);
            let Some(index) = decider else {
                return SiteSelection::default();
            };
            let decider = quiet.remove(index);
            return SiteSelection {
                compared: compared_of(decider),
                quiet: quiet.into_iter().map(|(s, _)| s.to_string()).collect(),
            };
        }
        SiteSelection {
            compared: active
                .into_iter()
                .filter_map(compared_of)
                .min_by_key(|compared| compared.time),
            quiet: quiet.into_iter().map(|(s, _)| s.to_string()).collect(),
        }
    }
}

impl Dai<'_> {
    /// Returns the value of `map` stored under `key` as `reader` sees it,
    /// or `None` if there is none.
    pub(super) fn value_in<T: DeserializeOwned>(
        reader: &(impl DaiRead + ?Sized),
        map: &Map<'_>,
        key: &[u8],
    ) -> Result<Option<T>> {
        reader
            .value(map, key)
            .context("cannot read DAI tables")?
            .map(|value| super::super::deserialize(&value))
            .transpose()
    }

    /// Returns the rows of `map` whose keys are in `[from, to)` as `reader`
    /// sees them, in key order, or in reverse key order if `reverse`, at
    /// most `limit` of them.
    pub(super) fn range_in(
        reader: &(impl DaiRead + ?Sized),
        map: &Map<'_>,
        from: &[u8],
        to: &[u8],
        reverse: bool,
        limit: usize,
    ) -> Result<Vec<RawRow>> {
        let mut opts = rocksdb::ReadOptions::default();
        opts.set_iterate_range(from.to_vec()..to.to_vec());
        let mode = if reverse {
            IteratorMode::End
        } else {
            IteratorMode::Start
        };
        reader
            .iter_rows(map, opts, mode)
            .take(limit)
            .map(|entry| entry.context("cannot read DAI tables"))
            .collect()
    }

    /// Returns the customer's configuration and sensors as `snapshot` holds
    /// them.
    pub(super) fn customer_view(
        &self,
        snapshot: &Snapshot<'_, impl rocksdb::DBAccess>,
        customer: u32,
    ) -> Result<CustomerView> {
        let settings: DaiSettings =
            Self::value_in(snapshot, &self.settings, &customer_key(customer))?.unwrap_or_default();
        let sites = self.sites_in(snapshot, customer)?;
        let default_site = sites
            .iter()
            .find(|site| site.is_default)
            .map(|site| site.token.clone());
        let names = self.nodes()?.sensor_names_in_snapshot(snapshot)?;
        let listed = sites.iter().flat_map(|site| site.sensors.iter().cloned());
        // Multi-site counts every name the node table gives for the
        // customer, as `Dai::is_multi_site_in` does.
        let all_named: BTreeSet<String> = names
            .iter()
            .filter(|(owner, _)| *owner == customer)
            .map(|(_, name)| name.clone())
            .chain(listed.clone())
            .collect();
        let sensors: BTreeSet<String> = CustomerSensors::new(names)
            .iter()
            .filter(|(_, owner)| *owner == customer)
            .map(|(name, _)| name.to_string())
            .chain(listed)
            .collect();
        let assignment = Assignment::new(&sites);
        let in_use: BTreeSet<&str> = all_named
            .iter()
            .map(|sensor| assignment.site(sensor))
            .collect();
        let multi_site = in_use.len() > 1;
        let single_site = if multi_site {
            None
        } else {
            in_use
                .into_iter()
                .next()
                .filter(|site| !site.is_empty())
                .map(str::to_string)
                .or_else(|| default_site.clone())
        };
        let internal = OwnedNetworkTable::open(self.db)
            .context("customer network table must be present")?
            .get_with(snapshot, customer)?
            .map_or_else(Vec::new, |set| set.internal_groups());
        let mut histories = BTreeMap::new();
        for sensor in &sensors {
            let mut rows = Vec::new();
            for (key, value) in Self::scan(&self.sensor_sites, snapshot, &sensor_key(sensor))? {
                let (_, effective, row) = decode_sensor_site(&key, &value)?;
                if row.customer_id == customer {
                    rows.push((effective, row.site));
                }
            }
            histories.insert(sensor.clone(), rows);
        }
        Ok(CustomerView {
            customer,
            settings,
            sites,
            default_site,
            multi_site,
            single_site,
            sensors,
            internal,
            histories,
        })
    }

    /// Returns the collection state of each of the customer's sensors as
    /// `snapshot` holds it.
    pub(super) fn collections(
        &self,
        snapshot: &Snapshot<'_, impl rocksdb::DBAccess>,
        view: &CustomerView,
    ) -> Result<BTreeMap<String, SensorCollection>> {
        view.sensors
            .iter()
            .map(|sensor| Ok((sensor.clone(), self.collection(snapshot, sensor)?)))
            .collect()
    }

    /// Returns the collection state of `sensor` as `snapshot` holds it.
    ///
    /// Its compared time is the earliest of: the cursors of its O1, O4 and
    /// O5 pairs, its last received record time, its resolver point and the
    /// earliest pending slots of its O1, O4 and O5 pairs, leaving out each
    /// pair whose first send has not finished since its cursor row was
    /// created; it has none if no pair is left in. A stored resolver point
    /// of `None` sets no limit; a sensor with none stored takes the earliest
    /// of its earliest pending slots of every kind.
    fn collection(
        &self,
        snapshot: &Snapshot<'_, impl rocksdb::DBAccess>,
        sensor: &str,
    ) -> Result<SensorCollection> {
        let state: SensorState =
            Self::value_in(snapshot, &self.sensor_state, &sensor_key(sensor))?.unwrap_or_default();
        let mut collection = SensorCollection {
            last_record_time: state.last_record_time,
            ..SensorCollection::default()
        };
        let mut earliest_pending = BTreeMap::new();
        let mut included = Vec::new();
        for kind in KINDS {
            let key = pair_key(sensor, kind);
            if let Some(slot_start) = Self::value_in::<i64>(snapshot, &self.earliest_pending, &key)?
            {
                earliest_pending.insert(super::kind_number(kind), (kind, slot_start));
            }
            let Some(row) = Self::value_in::<CursorRow>(snapshot, &self.cursors, &key)? else {
                continue;
            };
            collection.cursors.push((kind, row.cursor));
            if EVIDENCE_KINDS.contains(&kind) {
                if row.first_send_finished {
                    included.push((kind, row.cursor));
                } else {
                    collection.unsent.push(kind);
                }
            }
        }
        if included.is_empty() {
            return Ok(collection);
        }
        let resolver_point = match Self::value_in::<Option<i64>>(
            snapshot,
            &self.resolver_points,
            &super::device::resolver_point_key(sensor),
        )? {
            Some(stored) => stored,
            None => earliest_pending.values().map(|(_, start)| *start).min(),
        };
        let mut values: Vec<(i64, DaiComparedValue)> = included
            .iter()
            .map(|(kind, cursor)| (*cursor, DaiComparedValue::Cursor(*kind)))
            .collect();
        values.extend(
            state
                .last_record_time
                .map(|time| (time, DaiComparedValue::LastRecordTime)),
        );
        values.extend(resolver_point.map(|time| (time, DaiComparedValue::ResolverPoint)));
        for (kind, _) in &included {
            if let Some((_, start)) = earliest_pending.get(&super::kind_number(*kind)) {
                values.push((*start, DaiComparedValue::EarliestPending(*kind)));
            }
        }
        // The first of equal values is the one reported.
        collection.compared = values.into_iter().reduce(|earliest, value| {
            if value.0 < earliest.0 {
                value
            } else {
                earliest
            }
        });
        Ok(collection)
    }

    /// Returns the catch-up gaps of the customer's sensors as `snapshot`
    /// holds them, ordered by sensor, kind and start.
    pub(super) fn customer_gaps(
        &self,
        snapshot: &Snapshot<'_>,
        view: &CustomerView,
    ) -> Result<Vec<Gap>> {
        let mut gaps = Vec::new();
        for sensor in &view.sensors {
            for (key, value) in Self::scan(&self.catchup_gaps, snapshot, &sensor_key(sensor))? {
                let (sensor, kind, start) = decode_gap_key(&key)?;
                gaps.push(Gap {
                    sensor,
                    kind,
                    start,
                    end: super::super::deserialize(&value)?,
                });
            }
        }
        Ok(gaps)
    }

    /// Returns the current device the id `device` names as `snapshot` holds
    /// it: the device itself if it has a row, else the current device of its
    /// alias, or `None` if it names no device of the customer.
    pub(super) fn current_device_in(
        &self,
        snapshot: &Snapshot<'_>,
        customer: u32,
        device: Uuid,
    ) -> Result<Option<Uuid>> {
        if snapshot
            .value(&self.devices, &device_key(customer, device))
            .context("cannot read DAI devices")?
            .is_some()
        {
            return Ok(Some(device));
        }
        Ok(
            Self::value_in::<AliasRow>(snapshot, &self.aliases, &alias_key(customer, device))?
                .map(|alias| alias.current),
        )
    }

    /// Returns `device`, a device id a stored row holds, as the current
    /// device: followed through its alias if it has one, else as it is.
    pub(super) fn current_or_same(
        &self,
        snapshot: &Snapshot<'_>,
        customer: u32,
        device: Uuid,
    ) -> Result<Uuid> {
        Ok(self
            .current_device_in(snapshot, customer, device)?
            .unwrap_or(device))
    }

    /// Returns the site tokens the customer's rows of `map`, keyed by
    /// (customer, site, ...), name as `snapshot` holds them, in key order.
    ///
    /// It seeks past each site's rows, so it reads one row per site rather
    /// than every row. A site removed from the site table keeps the rows
    /// stored under its token, so they are found here too.
    pub(super) fn sites_of_rows(
        snapshot: &Snapshot<'_>,
        map: &Map<'_>,
        customer: u32,
    ) -> Result<Vec<String>> {
        let prefix = customer_key(customer);
        let mut opts = rocksdb::ReadOptions::default();
        opts.set_iterate_range(rocksdb::PrefixRange(prefix.as_slice()));
        let mut iter = snapshot.raw_iterator_cf_opt(map.cf, opts);
        iter.seek(&prefix);
        let mut sites = Vec::new();
        while let Some(key) = iter.key() {
            let mut reader = KeyReader::new(key);
            reader.u32()?;
            let site = reader.str()?;
            // Every key of the site starts with its encoded token, which
            // ends in the string terminator; the successor of that prefix
            // orders after all of them and before the next site's keys.
            let mut next = KeyWriter::default().u32(customer).str(&site).finish();
            let last = next
                .last_mut()
                .context("an encoded site token ends in its terminator")?;
            *last = last
                .checked_add(1)
                .context("the string terminator is not the largest byte")?;
            sites.push(site);
            iter.seek(&next);
        }
        iter.status().context("cannot read DAI tables")?;
        Ok(sites)
    }

    /// Returns the bindings of (`customer`, `site`, `ip`) as `snapshot`
    /// holds them, as (start, row) in start order.
    pub(super) fn address_bindings(
        &self,
        snapshot: &Snapshot<'_, impl rocksdb::DBAccess>,
        customer: u32,
        site: &str,
        ip: IpAddr,
    ) -> Result<Vec<(i64, BindingRow)>> {
        Self::scan(&self.bindings, snapshot, &address_key(customer, site, ip))?
            .into_iter()
            .map(|(key, value)| {
                let (_, _, _, start) = decode_binding_key(&key)?;
                Ok((start, super::super::deserialize(&value)?))
            })
            .collect()
    }
}

/// Returns whether `binding`, starting at `start`, is in effect at `time`:
/// `start <= time` and `time` is before its effective end.
pub(super) fn in_effect_at(start: i64, binding: &BindingRow, time: i64) -> bool {
    start <= time && time < binding.effective_end()
}

/// Returns the end of `binding` as a read reports it at `now`, and whether
/// it is estimated: a stored end that is not estimated and is its effective
/// end as it is; no end while it has no stored end and its effective end is
/// after `now`; otherwise its effective end, estimated.
pub(super) fn reported_end(binding: &BindingRow, now: i64) -> (Option<i64>, bool) {
    let effective = binding.effective_end();
    match binding.end {
        Some(end) if !binding.end_estimated && end == effective => (Some(end), false),
        None if effective > now => (None, false),
        _ => (Some(effective), true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tables::dai::device::Identifier;

    fn binding(end: Option<i64>, estimated: bool, last_strong: i64, inactivity: i64) -> BindingRow {
        BindingRow {
            end,
            device: Uuid::nil(),
            evidence_kind: 1,
            evidence_identifier: Identifier::mac("02:00:00:00:00:01"),
            server_id: None,
            last_strong,
            inactivity,
            end_estimated: estimated,
        }
    }

    #[test]
    fn reported_ends() {
        // Open and still in effect.
        assert_eq!(
            reported_end(&binding(None, false, 10, 10), 15),
            (None, false)
        );
        // Open past its inactivity end, before retention writes it.
        assert_eq!(
            reported_end(&binding(None, false, 10, 10), 25),
            (Some(20), true)
        );
        // Written by retention.
        assert_eq!(
            reported_end(&binding(Some(20), true, 10, 10), 25),
            (Some(20), true)
        );
        // A close earlier than the inactivity end.
        assert_eq!(
            reported_end(&binding(Some(15), false, 10, 10), 25),
            (Some(15), false)
        );
        // A close later than the inactivity end ends at the inactivity end.
        assert_eq!(
            reported_end(&binding(Some(30), false, 10, 10), 35),
            (Some(20), true)
        );
    }

    #[test]
    fn site_history_reads_like_the_sensor_site_lookup() {
        let view = CustomerView {
            customer: 1,
            settings: DaiSettings::default(),
            sites: Vec::new(),
            default_site: Some("default".to_string()),
            multi_site: true,
            single_site: None,
            sensors: BTreeSet::from(["s".to_string()]),
            internal: Vec::new(),
            histories: BTreeMap::from([(
                "s".to_string(),
                vec![(10, "east".to_string()), (20, "west".to_string())],
            )]),
        };
        assert_eq!(view.site_at("s", 9), Some("default"));
        assert_eq!(view.site_at("s", 10), Some("east"));
        assert_eq!(view.site_at("s", 25), Some("west"));
        assert_eq!(view.site_at("other", 25), Some("default"));
        assert!(view.in_site_during("s", "east", 0, 11));
        assert!(!view.in_site_during("s", "east", 0, 10));
        assert!(view.in_site_during("s", "west", 15, 21));
        assert!(!view.in_site_during("s", "west", 15, 20));
        assert!(!view.in_site_during("s", "default", 10, 30));
        assert!(view.in_site_during("s", "default", 5, 30));
    }
}
