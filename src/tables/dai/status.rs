//! The collection status of device identification: what each site and
//! sensor has received, what the evidence gap leaves out, the catch-up
//! gaps, the daily counters and the number of candidate ranges.

use anyhow::Result;
use review_protocol::types::DaiObservationKind;

use super::{
    Dai,
    cursor::pair_key,
    customer_key,
    observation::{DaiCounterKind, decode_counter_key},
    view::EVIDENCE_KINDS,
};

/// The latest receipt of a kind's observations at a site.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiKindReceipt {
    pub kind: DaiObservationKind,
    /// The latest time a send carrying observations of the kind finished
    /// for one of the site's current sensors; `None` if none ever did.
    pub time: Option<i64>,
    /// The sensor of that send.
    pub sensor: Option<String>,
}

/// The collection state of a site.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiSiteCollection {
    /// The site token.
    pub site: String,
    /// The latest receipt of each of DHCP (O1), Kerberos (O4) and NTLM
    /// (O5), in that order.
    pub receipts: Vec<DaiKindReceipt>,
    /// The site's current sensors left out of its compared time by the
    /// 24-hour rule, in name order.
    pub quiet_sensors: Vec<String>,
    /// The (sensor, kind) pairs of the site's current sensors left out
    /// because their first send has not finished, ordered by sensor and
    /// kind number.
    pub unsent_pairs: Vec<(String, DaiObservationKind)>,
}

/// The cursor of a (sensor, kind) and how far it lags.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiCursorLag {
    pub kind: DaiObservationKind,
    pub cursor: i64,
    /// `now` minus the cursor.
    pub lag: i64,
}

/// The collection state of a sensor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiSensorCollection {
    pub sensor: String,
    /// The sensor's current site; `None` if the customer has no default
    /// site.
    pub site: Option<String>,
    pub last_record_time: Option<i64>,
    /// The cursor of each kind with a cursor row, in kind number order.
    pub cursors: Vec<DaiCursorLag>,
}

/// A range a (sensor, kind) skipped by the catch-up limit, `[start, end)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiCatchupGap {
    pub sensor: String,
    pub kind: DaiObservationKind,
    pub start: i64,
    pub end: i64,
}

/// A count of a date, days since the UNIX epoch in UTC.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaiDailyCount {
    pub date: i32,
    pub count: u64,
}

/// The collection status of a customer.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DaiCollectionStatus {
    /// Each stored site, in token order.
    pub sites: Vec<DaiSiteCollection>,
    /// Each sensor of the customer, in name order.
    pub sensors: Vec<DaiSensorCollection>,
    /// The catch-up gaps of the customer's sensors still stored, ordered by
    /// sensor, kind number and start.
    pub catchup_gaps: Vec<DaiCatchupGap>,
    /// The slots skipped by the catch-up limit, per date, in date order.
    pub skipped_by_catchup: Vec<DaiDailyCount>,
    /// The relay DHCP observations whose site could not be determined, per
    /// date.
    pub relay_site_unknown: Vec<DaiDailyCount>,
    /// The observations filtered at receipt, per date.
    pub filtered_at_receipt: Vec<DaiDailyCount>,
    /// The pending observations deleted before they were applied, per
    /// date.
    pub not_applied: Vec<DaiDailyCount>,
    /// The number of candidate unregistered ranges.
    pub candidate_ranges: usize,
}

impl Dai<'_> {
    /// Returns the customer's collection status at `now`, as
    /// [`Store::dai_collection_status`](crate::Store::dai_collection_status)
    /// describes.
    pub(crate) fn collection_status(&self, customer: u32, now: i64) -> Result<DaiCollectionStatus> {
        let snapshot = self.db.snapshot();
        let view = self.customer_view(&snapshot, customer)?;
        let collections = self.collections(&snapshot, &view)?;

        let mut sites = Vec::with_capacity(view.sites.len());
        for site in &view.sites {
            let current: Vec<&str> = view.sensors_in(&site.token, now).collect();
            let mut receipts = Vec::with_capacity(EVIDENCE_KINDS.len());
            for kind in EVIDENCE_KINDS {
                let mut latest: Option<(i64, &str)> = None;
                for sensor in &current {
                    let time: Option<i64> = Self::value_in(
                        &snapshot,
                        &self.sensor_kind_state,
                        &pair_key(sensor, kind),
                    )?;
                    if let Some(time) = time
                        && latest.is_none_or(|(held, _)| time > held)
                    {
                        latest = Some((time, sensor));
                    }
                }
                receipts.push(DaiKindReceipt {
                    kind,
                    time: latest.map(|(time, _)| time),
                    sensor: latest.map(|(_, sensor)| sensor.to_string()),
                });
            }
            let unsent_pairs = current
                .iter()
                .filter_map(|sensor| {
                    collections
                        .get(*sensor)
                        .map(|collection| (sensor, &collection.unsent))
                })
                .flat_map(|(sensor, kinds)| kinds.iter().map(|kind| (sensor.to_string(), *kind)))
                .collect();
            sites.push(DaiSiteCollection {
                site: site.token.clone(),
                receipts,
                quiet_sensors: view.select(&collections, &site.token, now, now).quiet,
                unsent_pairs,
            });
        }

        let sensors = collections
            .iter()
            .map(|(sensor, collection)| DaiSensorCollection {
                sensor: sensor.clone(),
                site: view.site_at(sensor, now).map(str::to_string),
                last_record_time: collection.last_record_time,
                cursors: collection
                    .cursors
                    .iter()
                    .map(|(kind, cursor)| DaiCursorLag {
                        kind: *kind,
                        cursor: *cursor,
                        lag: now.saturating_sub(*cursor),
                    })
                    .collect(),
            })
            .collect();

        let catchup_gaps = self
            .customer_gaps(&snapshot, &view)?
            .into_iter()
            .map(|gap| DaiCatchupGap {
                sensor: gap.sensor,
                kind: gap.kind,
                start: gap.start,
                end: gap.end,
            })
            .collect();

        let mut status = DaiCollectionStatus {
            sites,
            sensors,
            catchup_gaps,
            ..DaiCollectionStatus::default()
        };
        for (key, value) in Self::scan(&self.counters, &snapshot, &customer_key(customer))? {
            let (_, counter, date) = decode_counter_key(&key)?;
            let count = DaiDailyCount {
                date,
                count: super::super::deserialize(&value)?,
            };
            let list = if counter == DaiCounterKind::SkippedByCatchup.number() {
                &mut status.skipped_by_catchup
            } else if counter == DaiCounterKind::RelaySiteUnknown.number() {
                &mut status.relay_site_unknown
            } else if counter == DaiCounterKind::FilteredAtReceipt.number() {
                &mut status.filtered_at_receipt
            } else if counter == DaiCounterKind::NotApplied.number() {
                &mut status.not_applied
            } else {
                continue;
            };
            list.push(count);
        }
        status.candidate_ranges = self.range_candidates_in(&snapshot, customer, now)?.len();
        Ok(status)
    }
}
