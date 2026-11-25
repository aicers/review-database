//! Selecting stored detection events with an [`EventFilter`], and counting
//! the selected ones.

use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    net::IpAddr,
};

use anyhow::Result;
use review_protocol::types::{DetectionModel, RawEventKind};
use serde::{Deserialize, Serialize};

use super::{FlowKind, StoredDetectionEvent, TrafficDirection, TriageScore};
use crate::{
    EventCategory, Network, TriagePolicyInput, properties,
    types::{Endpoint, HostNetworkGroup},
};

/// The number of distinct buckets an event's count keeps track of without
/// allocating; past it a hash set takes over.
const INLINE_DEDUP_LIMIT: usize = 8;

/// Machine Learning Method.
#[derive(Clone, Copy, Eq, PartialEq, Deserialize, Serialize, Debug)]
pub enum LearningMethod {
    Unsupervised,
    SemiSupervised,
}

/// The networks whose addresses count as internal for the `directions` field
/// of an [`EventFilter`].
///
/// The groups of a sensor are its customer's internal addresses by the
/// narrowest-network rule of
/// [`OwnedNetworkSet::internal_groups`](crate::OwnedNetworkSet::internal_groups):
/// an address is internal when the narrowest owned network containing it is
/// an `Intranet` or `Gateway` network, and no `Extranet` network contains it
/// as narrowly.
#[derive(Clone, Debug, PartialEq)]
pub enum InternalNetworks {
    /// Groups keyed by the event's sensor. An event whose sensor is not a key,
    /// or that has no sensor, has no internal address.
    PerSensor(HashMap<String, Vec<HostNetworkGroup>>),
}

impl InternalNetworks {
    /// Returns the groups an event from `sensor` is tested against.
    pub(crate) fn groups_for(&self, sensor: Option<&str>) -> &[HostNetworkGroup] {
        let Some(sensor) = sensor else {
            return &[];
        };
        match self {
            Self::PerSensor(groups) => groups.get(sensor).map_or(&[], Vec::as_slice),
        }
    }
}

/// A filter used to query stored detection events.
///
/// Every condition that is `Some` must hold for an event to match.
///
/// # Notes
///
/// The address conditions apply to the event's endpoint addresses, in two
/// sets: the originator side is a raw event body's `orig_addr`, or a
/// subject's related IPs observed as the source together with its host IP;
/// the responder side is the body's `resp_addr`, or the related IPs observed
/// as the destination together with the host IP. A host subject's IP is
/// therefore on both sides, and a sensor, cluster or network subject is
/// matched through its related IPs only.
///
/// - `endpoints` matches when some listed endpoint's network contains an
///   originator-side address (`From`), a responder-side address (`To`), or
///   either (no direction).
/// - `originator` and `responder` match when the address is on that side.
/// - `directions` classifies an event by whether an originator-side and a
///   responder-side address fall within the [`InternalNetworks`] of its
///   sensor: both is `Internal`, only the originator side `Outbound`, and
///   only the responder side `Inbound`. An event with neither side internal,
///   including every event with no sensor, never matches.
/// - `countries` compares the stored two-byte codes of the endpoint
///   addresses directly. This includes the [`crate::COUNTRY_CODE_UNKNOWN`]
///   and [`crate::COUNTRY_CODE_UNRESOLVED`] placeholders, which callers may
///   filter explicitly.
///
/// `detection_models`, `raw_event_kinds`, `categories`, `learning_methods`
/// and `sensors` select an event exactly when its value is listed, so an
/// empty list selects no event. `None` in `categories` selects an event with
/// no category, and an event with no sensor never matches `sensors`.
/// `learning_methods` reads the learning method of the event's detection
/// model from [`properties`]. `score_min` and `score_max` are inclusive
/// bounds on the event's `score`, compared exactly.
///
/// A non-empty `triage_policies` selects an event only when at least one
/// policy qualifies, as [`StoredDetectionEvent::score_against_policies`]
/// scores it.
#[allow(clippy::module_name_repetitions)]
pub struct EventFilter {
    pub(super) endpoints: Option<Vec<Endpoint>>,
    pub(super) directions: Option<(Vec<FlowKind>, InternalNetworks)>,
    pub(super) originator: Option<IpAddr>,
    pub(super) responder: Option<IpAddr>,
    pub(super) countries: Option<Vec<[u8; 2]>>,
    pub(super) categories: Option<Vec<Option<EventCategory>>>,
    pub(super) detection_models: Option<Vec<DetectionModel>>,
    pub(super) raw_event_kinds: Option<Vec<RawEventKind>>,
    pub(super) learning_methods: Option<Vec<LearningMethod>>,
    pub(super) sensors: Option<Vec<String>>,
    pub(super) score_min: Option<f64>,
    pub(super) score_max: Option<f64>,
    pub(super) triage_policies: Option<Vec<TriagePolicyInput>>,
}

impl EventFilter {
    /// Creates a new `EventFilter`.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        endpoints: Option<Vec<Endpoint>>,
        directions: Option<(Vec<FlowKind>, InternalNetworks)>,
        originator: Option<IpAddr>,
        responder: Option<IpAddr>,
        countries: Option<Vec<[u8; 2]>>,
        categories: Option<Vec<Option<EventCategory>>>,
        detection_models: Option<Vec<DetectionModel>>,
        raw_event_kinds: Option<Vec<RawEventKind>>,
        learning_methods: Option<Vec<LearningMethod>>,
        sensors: Option<Vec<String>>,
        score_min: Option<f64>,
        score_max: Option<f64>,
        triage_policies: Option<Vec<TriagePolicyInput>>,
    ) -> Self {
        Self {
            endpoints,
            directions,
            originator,
            responder,
            countries,
            categories,
            detection_models,
            raw_event_kinds,
            learning_methods,
            sensors,
            score_min,
            score_max,
            triage_policies,
        }
    }

    /// Returns whether the filter has a `countries` condition.
    #[must_use]
    pub fn has_country(&self) -> bool {
        self.countries.is_some()
    }
}

/// Calls `f` once for each distinct key `keys` yields, in the order each
/// first appears.
fn for_each_distinct<K: Copy + Eq + Hash>(keys: impl IntoIterator<Item = K>, mut f: impl FnMut(K)) {
    let mut inline: [Option<K>; INLINE_DEDUP_LIMIT] = [None; INLINE_DEDUP_LIMIT];
    let mut inline_len = 0;
    let mut spilled: Option<HashSet<K>> = None;
    for key in keys {
        let fresh = if let Some(seen) = &mut spilled {
            seen.insert(key)
        } else if inline
            .iter()
            .take(inline_len)
            .any(|seen| *seen == Some(key))
        {
            false
        } else if let Some(slot) = inline.get_mut(inline_len) {
            *slot = Some(key);
            inline_len += 1;
            true
        } else {
            let mut seen: HashSet<K> = inline.iter().flatten().copied().collect();
            seen.insert(key);
            spilled = Some(seen);
            true
        };
        if fresh {
            f(key);
        }
    }
}

/// Adds one to the bucket of each distinct key `keys` yields.
fn add_distinct<K: Copy + Eq + Hash>(
    counter: &mut HashMap<K, usize>,
    keys: impl IntoIterator<Item = K>,
) {
    for_each_distinct(keys, |key| *counter.entry(key).or_insert(0) += 1);
}

/// Returns the id of the first of `networks` that contains `ip`.
fn find_network(ip: IpAddr, networks: &[Network]) -> Option<u32> {
    networks
        .iter()
        .find(|net| net.networks.contains(ip))
        .map(|net| net.id)
}

/// Returns whether `score` lies within the inclusive bounds. A `NaN` score
/// lies within no bound.
fn within_bounds(score: f64, min: Option<f64>, max: Option<f64>) -> bool {
    min.is_none_or(|min| min <= score) && max.is_none_or(|max| score <= max)
}

impl StoredDetectionEvent {
    /// Returns the addresses on either side, possibly repeated.
    fn all_addrs(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.originator_addrs().chain(self.responder_addrs())
    }

    /// Returns the ordered (originator-side, responder-side) pairs,
    /// possibly repeated.
    fn addr_pairs(&self) -> impl Iterator<Item = (IpAddr, IpAddr)> + '_ {
        self.originator_addrs()
            .flat_map(|orig| self.responder_addrs().map(move |resp| (orig, resp)))
    }

    /// Returns whether the event meets every condition of `filter` other than
    /// `triage_policies`.
    #[allow(clippy::too_many_lines)]
    fn meets_conditions(&self, filter: &EventFilter) -> bool {
        let event = &self.event;

        if let Some(models) = &filter.detection_models
            && !models.contains(&event.detection_model)
        {
            return false;
        }

        if let Some(kinds) = &filter.raw_event_kinds
            && !kinds.contains(&event.raw_event_kind)
        {
            return false;
        }

        if !within_bounds(event.score, filter.score_min, filter.score_max) {
            return false;
        }

        if let Some(categories) = &filter.categories
            && !categories.contains(&self.category())
        {
            return false;
        }

        if let Some(learning_methods) = &filter.learning_methods
            && !learning_methods.contains(&properties(event.detection_model).learning_method)
        {
            return false;
        }

        if let Some(sensors) = &filter.sensors
            && !event
                .sensor
                .as_ref()
                .is_some_and(|sensor| sensors.contains(sensor))
        {
            return false;
        }

        if let Some(endpoints) = &filter.endpoints
            && !endpoints.iter().any(|endpoint| {
                let contains = |addr: IpAddr| endpoint.network.contains(addr);
                match endpoint.direction {
                    Some(TrafficDirection::From) => self.originator_addrs().any(contains),
                    Some(TrafficDirection::To) => self.responder_addrs().any(contains),
                    None => self.all_addrs().any(contains),
                }
            })
        {
            return false;
        }

        if let Some(addr) = filter.originator
            && !self.originator_addrs().any(|orig| orig == addr)
        {
            return false;
        }

        if let Some(addr) = filter.responder
            && !self.responder_addrs().any(|resp| resp == addr)
        {
            return false;
        }

        if let Some((kinds, internal)) = &filter.directions {
            let internal = internal.groups_for(event.sensor.as_deref());
            let is_internal = |addr: IpAddr| internal.iter().any(|net| net.contains(addr));
            let flow = match (
                self.originator_addrs().any(is_internal),
                self.responder_addrs().any(is_internal),
            ) {
                (true, true) => FlowKind::Internal,
                (true, false) => FlowKind::Outbound,
                (false, true) => FlowKind::Inbound,
                (false, false) => return false,
            };
            if !kinds.contains(&flow) {
                return false;
            }
        }

        if let Some(countries) = &filter.countries
            && !countries.iter().any(|country| {
                self.stored_country_codes()
                    .iter()
                    .any(|&code| crate::util::stored_country_code_matches(code, *country))
            })
        {
            return false;
        }

        true
    }

    /// Returns whether the event matches the filter, and, when the filter has
    /// a non-empty `triage_policies`, the scores of the policies that qualify.
    ///
    /// An event matches a non-empty `triage_policies` only when at least one
    /// policy qualifies; scores are returned only for a matching event.
    ///
    /// # Errors
    ///
    /// Never returns an error; the `Result` is kept for callers that
    /// propagate matching failures.
    pub fn matches(&self, filter: &EventFilter) -> Result<(bool, Option<Vec<TriageScore>>)> {
        if !self.meets_conditions(filter) {
            return Ok((false, None));
        }
        if let Some(policies) = &filter.triage_policies
            && !policies.is_empty()
        {
            let scores = self.score_against_policies(policies);
            if scores.is_empty() {
                return Ok((false, None));
            }
            return Ok((true, Some(scores)));
        }
        Ok((true, None))
    }

    /// Returns whether the event matches the filter.
    fn is_selected(&self, filter: &EventFilter) -> Result<bool> {
        Ok(self.matches(filter)?.0)
    }

    /// Counts a matching event once per distinct stored country code of its
    /// endpoint addresses.
    ///
    /// For codes that are two-byte ASCII, the bucket keys are exactly the
    /// country codes that make `EventFilter::countries` select the event. A
    /// record with no endpoint address yields no bucket.
    ///
    /// # Errors
    ///
    /// Returns an error if matching the event against the filter fails.
    pub fn count_country(
        &self,
        counter: &mut HashMap<String, usize>,
        filter: &EventFilter,
    ) -> Result<()> {
        if self.country_codes.is_empty() || !self.is_selected(filter)? {
            return Ok(());
        }
        for_each_distinct(
            self.country_codes
                .iter()
                .map(crate::util::country_code_as_str),
            |country| {
                if let Some(count) = counter.get_mut(country) {
                    *count += 1;
                } else {
                    counter.insert(country.to_string(), 1);
                }
            },
        );
        Ok(())
    }

    /// Counts matching events by their optional category.
    ///
    /// Keys use the same representation as the `categories` argument to
    /// [`EventFilter::new`]: `Some(category)` counts matching events that
    /// carry that category, while `None` counts matching events that carry no
    /// category. Every matching record counts, with or without an endpoint
    /// address.
    ///
    /// # Errors
    ///
    /// Returns an error if matching the event against the filter fails.
    pub fn count_category(
        &self,
        counter: &mut HashMap<Option<EventCategory>, usize>,
        filter: &EventFilter,
    ) -> Result<()> {
        if self.is_selected(filter)? {
            *counter.entry(self.category()).or_insert(0) += 1;
        }
        Ok(())
    }

    /// Counts matching events under their detection model.
    ///
    /// The keys can be passed back as the `detection_models` argument to
    /// [`EventFilter::new`] to select the events counted in each bucket.
    /// Every matching record counts, with or without an endpoint address.
    ///
    /// # Errors
    ///
    /// Returns an error if matching the event against the filter fails.
    pub fn count_detection_model(
        &self,
        counter: &mut HashMap<DetectionModel, usize>,
        filter: &EventFilter,
    ) -> Result<()> {
        if self.is_selected(filter)? {
            *counter.entry(self.event.detection_model).or_insert(0) += 1;
        }
        Ok(())
    }

    /// Counts a matching event once per distinct endpoint address on either
    /// side.
    ///
    /// Buckets are the union of the addresses selecting the event through
    /// `EventFilter::originator` or `EventFilter::responder`.
    ///
    /// # Errors
    ///
    /// Returns an error if matching the event against the filter fails.
    pub fn count_ip_address(
        &self,
        counter: &mut HashMap<IpAddr, usize>,
        filter: &EventFilter,
    ) -> Result<()> {
        if self.all_addrs().next().is_none() || !self.is_selected(filter)? {
            return Ok(());
        }
        add_distinct(counter, self.all_addrs());
        Ok(())
    }

    /// Counts a matching event once per distinct ordered pair of an
    /// originator-side and a responder-side address.
    ///
    /// Each pair selects the event through `EventFilter::originator` and
    /// `EventFilter::responder` together. An event with an empty side yields
    /// no pair.
    ///
    /// # Errors
    ///
    /// Returns an error if matching the event against the filter fails.
    pub fn count_ip_address_pair(
        &self,
        counter: &mut HashMap<(IpAddr, IpAddr), usize>,
        filter: &EventFilter,
    ) -> Result<()> {
        if self.addr_pairs().next().is_none() || !self.is_selected(filter)? {
            return Ok(());
        }
        add_distinct(counter, self.addr_pairs());
        Ok(())
    }

    /// Counts a matching event once per distinct address pair, as
    /// [`StoredDetectionEvent::count_ip_address_pair`] forms them, together
    /// with its detection model.
    ///
    /// # Errors
    ///
    /// Returns an error if matching the event against the filter fails.
    pub fn count_ip_address_pair_and_detection_model(
        &self,
        counter: &mut HashMap<(IpAddr, IpAddr, DetectionModel), usize>,
        filter: &EventFilter,
    ) -> Result<()> {
        if self.addr_pairs().next().is_none() || !self.is_selected(filter)? {
            return Ok(());
        }
        let model = self.event.detection_model;
        add_distinct(
            counter,
            self.addr_pairs().map(|(orig, resp)| (orig, resp, model)),
        );
        Ok(())
    }

    /// Counts a matching event once per distinct originator-side address.
    ///
    /// Bucket keys are exactly the addresses selecting the event through
    /// `EventFilter::originator`.
    ///
    /// # Errors
    ///
    /// Returns an error if matching the event against the filter fails.
    pub fn count_originator_ip_address(
        &self,
        counter: &mut HashMap<IpAddr, usize>,
        filter: &EventFilter,
    ) -> Result<()> {
        if self.originator_addrs().next().is_none() || !self.is_selected(filter)? {
            return Ok(());
        }
        add_distinct(counter, self.originator_addrs());
        Ok(())
    }

    /// Counts a matching event once per distinct responder-side address.
    ///
    /// Bucket keys are exactly the addresses selecting the event through
    /// `EventFilter::responder`.
    ///
    /// # Errors
    ///
    /// Returns an error if matching the event against the filter fails.
    pub fn count_responder_ip_address(
        &self,
        counter: &mut HashMap<IpAddr, usize>,
        filter: &EventFilter,
    ) -> Result<()> {
        if self.responder_addrs().next().is_none() || !self.is_selected(filter)? {
            return Ok(());
        }
        add_distinct(counter, self.responder_addrs());
        Ok(())
    }

    /// Counts a matching event once per distinct network of its endpoint
    /// addresses.
    ///
    /// Each address maps to the first of `networks`, in the given order, that
    /// contains it. An address outside every network yields no bucket, and a
    /// network shared by several addresses counts once.
    ///
    /// # Errors
    ///
    /// Returns an error if matching the event against the filter fails.
    pub fn count_network(
        &self,
        counter: &mut HashMap<u32, usize>,
        networks: &[Network],
        filter: &EventFilter,
    ) -> Result<()> {
        if self.all_addrs().next().is_none() || !self.is_selected(filter)? {
            return Ok(());
        }
        add_distinct(
            counter,
            self.all_addrs()
                .filter_map(|addr| find_network(addr, networks)),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, net::IpAddr};

    use review_protocol::types::{
        DetectionModel, EndpointRole::Destination, EndpointRole::Source, EventCategory as Protocol,
        PrimarySubject, RawEventKind, ThreatRole,
    };

    use super::{EventFilter, FlowKind, InternalNetworks, LearningMethod};
    use crate::{
        EventCategory, HostNetworkGroup, Network, OwnedNetwork, OwnedNetworkSet, Response,
        ResponseKind, ScoreCondition, TriagePolicyInput,
        event::{
            NetworkType, StoredDetectionEvent, TrafficDirection,
            fixture::{
                SENSOR, conn_event, host, ip, network_connect_body, raw_event_event, related,
                stored, stored_with, subject_event, time,
            },
        },
        types::Endpoint,
    };

    fn empty() -> EventFilter {
        EventFilter::new(
            None, None, None, None, None, None, None, None, None, None, None, None, None,
        )
    }

    fn selects(record: &StoredDetectionEvent, filter: &EventFilter) -> bool {
        record.matches(filter).unwrap().0
    }

    fn conn() -> StoredDetectionEvent {
        stored(conn_event("192.0.2.1", "198.51.100.1"))
    }

    /// A host subject at 192.0.2.9 with a source and a destination related IP.
    fn host_subject() -> StoredDetectionEvent {
        stored(subject_event(
            host("192.0.2.9"),
            vec![
                related("203.0.113.1", Source),
                related("203.0.113.2", Destination),
            ],
        ))
    }

    fn sensor_subject() -> StoredDetectionEvent {
        stored(subject_event(
            PrimarySubject::Sensor,
            vec![
                related("203.0.113.1", Source),
                related("203.0.113.2", Destination),
            ],
        ))
    }

    fn sysmon() -> StoredDetectionEvent {
        stored(raw_event_event(
            time(),
            SENSOR,
            network_connect_body(ip("192.0.2.1"), ip("198.51.100.1")),
        ))
    }

    fn group(entries: &[&str]) -> HostNetworkGroup {
        HostNetworkGroup::new(
            Vec::new(),
            entries.iter().map(|net| net.parse().unwrap()).collect(),
            Vec::new(),
        )
    }

    fn endpoint(direction: Option<TrafficDirection>, net: &str) -> Endpoint {
        Endpoint {
            direction,
            network: group(&[net]),
        }
    }

    #[test]
    fn an_empty_filter_selects_every_event() {
        for record in [conn(), host_subject(), sensor_subject(), sysmon()] {
            assert_eq!(record.matches(&empty()).unwrap(), (true, None));
            assert!(!empty().has_country());
        }
    }

    #[test]
    fn detection_models_and_raw_event_kinds_select_listed_values_only() {
        let record = conn();
        let models = |models: Vec<DetectionModel>| EventFilter {
            detection_models: Some(models),
            ..empty()
        };
        assert!(selects(&record, &models(vec![DetectionModel::NonBrowser])));
        assert!(selects(
            &record,
            &models(vec![DetectionModel::PortScan, DetectionModel::NonBrowser])
        ));
        assert!(!selects(&record, &models(vec![DetectionModel::PortScan])));
        assert!(!selects(&record, &models(Vec::new())));

        let kinds = |kinds: Vec<RawEventKind>| EventFilter {
            raw_event_kinds: Some(kinds),
            ..empty()
        };
        assert!(selects(&record, &kinds(vec![RawEventKind::Conn])));
        assert!(!selects(&record, &kinds(vec![RawEventKind::Http])));
        assert!(!selects(&record, &kinds(Vec::new())));
        // A subject event has a raw event kind too.
        assert!(selects(&host_subject(), &kinds(vec![RawEventKind::Conn])));
    }

    #[test]
    fn score_bounds_are_inclusive_and_exact() {
        // The conn fixture scores 0.75.
        let record = conn();
        let bounds = |min, max| EventFilter {
            score_min: min,
            score_max: max,
            ..empty()
        };
        assert!(selects(&record, &bounds(Some(0.75), None)));
        assert!(selects(&record, &bounds(None, Some(0.75))));
        assert!(selects(&record, &bounds(Some(0.75), Some(0.75))));
        assert!(!selects(&record, &bounds(Some(0.750_000_1), None)));
        assert!(!selects(&record, &bounds(None, Some(0.749_999_9))));
        assert!(!selects(&record, &bounds(Some(0.8), Some(0.7))));

        let mut nan = conn_event("192.0.2.1", "198.51.100.1");
        nan.score = f64::NAN;
        let nan = stored(nan);
        assert!(selects(&nan, &empty()));
        assert!(!selects(&nan, &bounds(Some(f64::MIN), None)));
        assert!(!selects(&nan, &bounds(None, Some(f64::MAX))));
    }

    #[test]
    fn categories_match_the_header_and_none_matches_no_category() {
        let record = conn();
        let categories = |categories: Vec<Option<EventCategory>>| EventFilter {
            categories: Some(categories),
            ..empty()
        };
        assert!(selects(
            &record,
            &categories(vec![Some(EventCategory::CommandAndControl)])
        ));
        assert!(!selects(
            &record,
            &categories(vec![Some(EventCategory::Impact), None])
        ));
        assert!(!selects(&record, &categories(Vec::new())));

        let mut uncategorized = conn_event("192.0.2.1", "198.51.100.1");
        uncategorized.category = None;
        let uncategorized = stored(uncategorized);
        assert!(selects(&uncategorized, &categories(vec![None])));
        assert!(!selects(
            &uncategorized,
            &categories(vec![Some(EventCategory::CommandAndControl)])
        ));
    }

    #[test]
    fn categories_map_every_protocol_category_by_name_and_number() {
        let pairs = [
            (Protocol::Reconnaissance, EventCategory::Reconnaissance),
            (Protocol::InitialAccess, EventCategory::InitialAccess),
            (Protocol::Execution, EventCategory::Execution),
            (Protocol::CredentialAccess, EventCategory::CredentialAccess),
            (Protocol::Discovery, EventCategory::Discovery),
            (Protocol::LateralMovement, EventCategory::LateralMovement),
            (
                Protocol::CommandAndControl,
                EventCategory::CommandAndControl,
            ),
            (Protocol::Exfiltration, EventCategory::Exfiltration),
            (Protocol::Impact, EventCategory::Impact),
            (Protocol::Collection, EventCategory::Collection),
            (Protocol::DefenseEvasion, EventCategory::DefenseEvasion),
            (Protocol::Persistence, EventCategory::Persistence),
            (
                Protocol::PrivilegeEscalation,
                EventCategory::PrivilegeEscalation,
            ),
            (
                Protocol::ResourceDevelopment,
                EventCategory::ResourceDevelopment,
            ),
        ];
        for (protocol, crate_category) in pairs {
            assert_eq!(EventCategory::from(protocol), crate_category);
            assert_eq!(protocol as u8, crate_category as u8);
            assert_eq!(format!("{protocol:?}"), format!("{crate_category:?}"));
        }
    }

    #[test]
    fn learning_methods_read_the_detection_model_properties() {
        let record = conn();
        let expected = crate::properties(DetectionModel::NonBrowser).learning_method;
        assert_eq!(expected, LearningMethod::SemiSupervised);
        let methods = |methods: Vec<LearningMethod>| EventFilter {
            learning_methods: Some(methods),
            ..empty()
        };
        assert!(selects(
            &record,
            &methods(vec![LearningMethod::SemiSupervised])
        ));
        assert!(!selects(
            &record,
            &methods(vec![LearningMethod::Unsupervised])
        ));
        assert!(!selects(&record, &methods(Vec::new())));
    }

    #[test]
    fn sensors_never_match_an_event_with_no_sensor() {
        let sensors = |sensors: Vec<&str>| EventFilter {
            sensors: Some(sensors.into_iter().map(str::to_string).collect()),
            ..empty()
        };
        let record = conn();
        assert!(selects(&record, &sensors(vec![SENSOR])));
        assert!(selects(&record, &sensors(vec!["other", SENSOR])));
        assert!(!selects(&record, &sensors(vec!["other"])));
        assert!(!selects(&record, &sensors(Vec::new())));

        let mut no_sensor = subject_event(host("192.0.2.9"), Vec::new());
        no_sensor.sensor = None;
        let no_sensor = stored(no_sensor);
        assert!(selects(&no_sensor, &empty()));
        assert!(!selects(&no_sensor, &sensors(vec![SENSOR])));
        assert!(!selects(&no_sensor, &sensors(vec![""])));
    }

    #[test]
    fn originator_and_responder_use_the_endpoint_address_sides() {
        let side = |orig: Option<&str>, resp: Option<&str>| EventFilter {
            originator: orig.map(ip),
            responder: resp.map(ip),
            ..empty()
        };
        let record = conn();
        assert!(selects(
            &record,
            &side(Some("192.0.2.1"), Some("198.51.100.1"))
        ));
        assert!(!selects(&record, &side(Some("198.51.100.1"), None)));
        assert!(!selects(&record, &side(None, Some("192.0.2.1"))));

        // A host subject's IP is on both sides.
        let host = host_subject();
        assert!(selects(&host, &side(Some("192.0.2.9"), None)));
        assert!(selects(&host, &side(None, Some("192.0.2.9"))));
        assert!(selects(&host, &side(Some("192.0.2.9"), Some("192.0.2.9"))));
        assert!(selects(
            &host,
            &side(Some("203.0.113.1"), Some("203.0.113.2"))
        ));
        assert!(!selects(&host, &side(Some("203.0.113.2"), None)));
        assert!(!selects(&host, &side(None, Some("203.0.113.1"))));

        // A sensor subject is matched through its related IPs only.
        let sensor = sensor_subject();
        assert!(selects(
            &sensor,
            &side(Some("203.0.113.1"), Some("203.0.113.2"))
        ));
        assert!(!selects(&sensor, &side(Some("203.0.113.2"), None)));

        // A Sysmon body has no endpoint address.
        assert!(!selects(&sysmon(), &side(Some("192.0.2.1"), None)));
        assert!(!selects(&sysmon(), &side(None, Some("198.51.100.1"))));
    }

    #[test]
    fn endpoints_match_some_listed_network_on_the_given_side() {
        let endpoints = |endpoints: Vec<Endpoint>| EventFilter {
            endpoints: Some(endpoints),
            ..empty()
        };
        let from = |net| endpoint(Some(TrafficDirection::From), net);
        let to = |net| endpoint(Some(TrafficDirection::To), net);
        let any = |net| endpoint(None, net);

        let record = conn();
        assert!(selects(&record, &endpoints(vec![from("192.0.2.0/24")])));
        assert!(!selects(&record, &endpoints(vec![to("192.0.2.0/24")])));
        assert!(selects(&record, &endpoints(vec![to("198.51.100.0/24")])));
        assert!(selects(&record, &endpoints(vec![any("198.51.100.0/24")])));
        assert!(selects(
            &record,
            &endpoints(vec![to("10.0.0.0/8"), from("192.0.2.0/24")])
        ));
        assert!(!selects(&record, &endpoints(vec![any("10.0.0.0/8")])));
        assert!(!selects(&record, &endpoints(Vec::new())));

        let host = host_subject();
        assert!(selects(&host, &endpoints(vec![to("192.0.2.9/32")])));
        assert!(selects(&host, &endpoints(vec![from("192.0.2.9/32")])));
        let sensor = sensor_subject();
        assert!(selects(&sensor, &endpoints(vec![from("203.0.113.1/32")])));
        assert!(!selects(&sensor, &endpoints(vec![to("203.0.113.1/32")])));
        assert!(!selects(&sysmon(), &endpoints(vec![any("0.0.0.0/0")])));
    }

    fn directions(kinds: Vec<FlowKind>, internal: &[&str]) -> EventFilter {
        EventFilter {
            directions: Some((
                kinds,
                InternalNetworks::PerSensor(HashMap::from([(
                    SENSOR.to_string(),
                    vec![group(internal)],
                )])),
            )),
            ..empty()
        }
    }

    #[test]
    fn directions_classify_by_the_internal_networks_of_the_sensor() {
        let all = || vec![FlowKind::Internal, FlowKind::Outbound, FlowKind::Inbound];
        let record = conn();
        let flow = |internal: &[&str]| -> Vec<FlowKind> {
            all()
                .into_iter()
                .filter(|kind| selects(&record, &directions(vec![*kind], internal)))
                .collect()
        };
        assert_eq!(
            flow(&["192.0.2.0/24", "198.51.100.0/24"]),
            [FlowKind::Internal]
        );
        assert_eq!(flow(&["192.0.2.0/24"]), [FlowKind::Outbound]);
        assert_eq!(flow(&["198.51.100.0/24"]), [FlowKind::Inbound]);
        assert_eq!(flow(&["10.0.0.0/8"]), Vec::<FlowKind>::new());

        // A host subject's IP is internal on both sides.
        assert!(selects(
            &host_subject(),
            &directions(vec![FlowKind::Internal], &["192.0.2.9/32"])
        ));
        // An event from another sensor, or from none, has no internal
        // address.
        let mut other = conn_event("192.0.2.1", "198.51.100.1");
        other.sensor = Some("sensor-2".to_string());
        assert!(!selects(&stored(other), &directions(all(), &["0.0.0.0/0"])));
        let mut no_sensor = conn_event("192.0.2.1", "198.51.100.1");
        no_sensor.sensor = None;
        assert!(!selects(
            &stored(no_sensor),
            &directions(all(), &["0.0.0.0/0"])
        ));
        assert!(!selects(&sysmon(), &directions(all(), &["0.0.0.0/0"])));
    }

    #[test]
    fn directions_follow_the_narrowest_owned_network() {
        let set = OwnedNetworkSet {
            revision: 1,
            networks: vec![
                OwnedNetwork {
                    name: "office".to_string(),
                    network_type: NetworkType::Intranet,
                    group: group(&["10.0.0.0/8"]),
                },
                OwnedNetwork {
                    name: "partner".to_string(),
                    network_type: NetworkType::Extranet,
                    group: group(&["10.200.0.0/16"]),
                },
            ],
            updated_at: jiff::Timestamp::now(),
        };
        let filter = |kind: FlowKind| EventFilter {
            directions: Some((
                vec![kind],
                InternalNetworks::PerSensor(HashMap::from([(
                    SENSOR.to_string(),
                    set.internal_groups(),
                )])),
            )),
            ..empty()
        };
        let flow = |orig: &str, resp: &str| -> Vec<FlowKind> {
            let record = stored(conn_event(orig, resp));
            [FlowKind::Internal, FlowKind::Outbound, FlowKind::Inbound]
                .into_iter()
                .filter(|kind| selects(&record, &filter(*kind)))
                .collect()
        };
        assert_eq!(flow("10.1.0.1", "10.200.0.1"), [FlowKind::Outbound]);
        assert_eq!(flow("10.200.0.1", "10.1.0.1"), [FlowKind::Inbound]);
        assert_eq!(flow("10.1.0.1", "10.2.0.1"), [FlowKind::Internal]);
    }

    #[test]
    fn countries_compare_the_stored_codes_of_endpoint_addresses() {
        let countries = |countries: Vec<[u8; 2]>| EventFilter {
            countries: Some(countries),
            ..empty()
        };
        let record = stored_with(
            conn_event("192.0.2.1", "198.51.100.1"),
            &[("192.0.2.1", *b"US"), ("198.51.100.1", *b"KR")],
        );
        assert!(countries(vec![*b"US"]).has_country());
        assert!(selects(&record, &countries(vec![*b"KR"])));
        assert!(selects(&record, &countries(vec![*b"DE", *b"US"])));
        assert!(!selects(&record, &countries(vec![*b"DE"])));
        assert!(!selects(&record, &countries(Vec::new())));

        let host = stored_with(
            subject_event(host("192.0.2.9"), vec![related("203.0.113.1", Destination)]),
            &[("192.0.2.9", *b"JP"), ("203.0.113.1", *b"DE")],
        );
        assert!(selects(&host, &countries(vec![*b"JP"])));
        assert!(selects(&host, &countries(vec![*b"DE"])));

        // Placeholder codes match themselves; a record without endpoint
        // addresses has no code.
        assert!(selects(
            &conn(),
            &countries(vec![crate::COUNTRY_CODE_UNRESOLVED])
        ));
        assert!(!selects(
            &sysmon(),
            &countries(vec![
                crate::COUNTRY_CODE_UNRESOLVED,
                crate::COUNTRY_CODE_UNKNOWN
            ])
        ));
    }

    fn policy(
        id: u32,
        minimum_scores: &[f64],
        conditions: Vec<ScoreCondition>,
    ) -> TriagePolicyInput {
        TriagePolicyInput {
            id,
            name: format!("policy-{id}"),
            creation_time: time(),
            triage_exclusion: Vec::new(),
            packet_attr: Vec::new(),
            score: conditions,
            response: minimum_scores
                .iter()
                .map(|&minimum_score| Response {
                    minimum_score,
                    kind: ResponseKind::Manual,
                })
                .collect(),
        }
    }

    fn non_browser_condition(weight: f64) -> ScoreCondition {
        ScoreCondition {
            threat_category: Some(EventCategory::CommandAndControl),
            detection_model: DetectionModel::NonBrowser,
            score: 0.5,
            weight: Some(weight),
        }
    }

    #[test]
    fn triage_policies_select_only_when_a_policy_qualifies() {
        let record = conn();
        let triage = |policies: Vec<TriagePolicyInput>| EventFilter {
            triage_policies: Some(policies),
            ..empty()
        };

        // No policy qualifies: rejected.
        assert_eq!(
            record
                .matches(&triage(vec![policy(
                    1,
                    &[5.0],
                    vec![non_browser_condition(2.0)]
                )]))
                .unwrap(),
            (false, None)
        );
        // A policy with no response never qualifies.
        assert_eq!(
            record
                .matches(&triage(vec![policy(
                    2,
                    &[],
                    vec![non_browser_condition(9.0)]
                )]))
                .unwrap(),
            (false, None)
        );
        // Only the qualifying policies' scores are returned.
        let (matched, scores) = record
            .matches(&triage(vec![
                policy(3, &[], vec![non_browser_condition(9.0)]),
                policy(4, &[5.0, 1.5], vec![non_browser_condition(2.0)]),
                policy(5, &[3.0], vec![non_browser_condition(2.0)]),
            ]))
            .unwrap();
        assert!(matched);
        let scores = scores.expect("scores of the qualifying policies");
        assert_eq!(scores.len(), 1);
        assert_eq!(scores[0].policy_id, 4);
        assert!((scores[0].score - 2.0).abs() < f64::EPSILON);

        // An empty list is no condition.
        assert_eq!(record.matches(&triage(Vec::new())).unwrap(), (true, None));
        // The other conditions still apply.
        let filter = EventFilter {
            detection_models: Some(vec![DetectionModel::PortScan]),
            ..triage(vec![policy(6, &[0.0], Vec::new())])
        };
        assert_eq!(record.matches(&filter).unwrap(), (false, None));
    }

    fn network(id: u32, nets: &[&str]) -> Network {
        let mut network = Network::new(format!("net-{id}"), String::new(), group(nets));
        network.id = id;
        network
    }

    #[allow(clippy::too_many_lines)]
    #[test]
    fn counts_over_a_raw_event_record() {
        let record = stored_with(
            conn_event("192.0.2.1", "198.51.100.1"),
            &[("192.0.2.1", *b"US"), ("198.51.100.1", *b"KR")],
        );
        let filter = empty();

        let mut countries = HashMap::new();
        record.count_country(&mut countries, &filter).unwrap();
        assert_eq!(
            countries,
            HashMap::from([("US".to_string(), 1), ("KR".to_string(), 1)])
        );

        let mut categories = HashMap::new();
        record.count_category(&mut categories, &filter).unwrap();
        assert_eq!(
            categories,
            HashMap::from([(Some(EventCategory::CommandAndControl), 1)])
        );

        let mut models = HashMap::new();
        record.count_detection_model(&mut models, &filter).unwrap();
        assert_eq!(models, HashMap::from([(DetectionModel::NonBrowser, 1)]));

        let mut addrs = HashMap::new();
        record.count_ip_address(&mut addrs, &filter).unwrap();
        assert_eq!(
            addrs,
            HashMap::from([(ip("192.0.2.1"), 1), (ip("198.51.100.1"), 1)])
        );

        let mut pairs = HashMap::new();
        record.count_ip_address_pair(&mut pairs, &filter).unwrap();
        assert_eq!(
            pairs,
            HashMap::from([((ip("192.0.2.1"), ip("198.51.100.1")), 1)])
        );

        let mut pair_models = HashMap::new();
        record
            .count_ip_address_pair_and_detection_model(&mut pair_models, &filter)
            .unwrap();
        assert_eq!(
            pair_models,
            HashMap::from([(
                (
                    ip("192.0.2.1"),
                    ip("198.51.100.1"),
                    DetectionModel::NonBrowser
                ),
                1
            )])
        );

        let mut origs = HashMap::new();
        record
            .count_originator_ip_address(&mut origs, &filter)
            .unwrap();
        assert_eq!(origs, HashMap::from([(ip("192.0.2.1"), 1)]));

        let mut resps = HashMap::new();
        record
            .count_responder_ip_address(&mut resps, &filter)
            .unwrap();
        assert_eq!(resps, HashMap::from([(ip("198.51.100.1"), 1)]));

        let mut networks = HashMap::new();
        record
            .count_network(
                &mut networks,
                &[
                    network(1, &["192.0.2.0/24"]),
                    network(2, &["198.51.100.0/24"]),
                ],
                &filter,
            )
            .unwrap();
        assert_eq!(networks, HashMap::from([(1, 1), (2, 1)]));
    }

    #[allow(clippy::too_many_lines)]
    #[test]
    fn counts_over_a_subject_record_follow_the_bucket_rules() {
        // The host IP is on both sides, and appears again as a related IP;
        // one source related IP repeats.
        let record = stored_with(
            subject_event(
                host("192.0.2.9"),
                vec![
                    related("203.0.113.1", Source),
                    related("203.0.113.1", Source),
                    related("192.0.2.9", Destination),
                    related("203.0.113.2", Destination),
                ],
            ),
            &[
                ("192.0.2.9", *b"JP"),
                ("203.0.113.1", *b"DE"),
                ("203.0.113.2", *b"DE"),
            ],
        );
        let filter = empty();
        let host = ip("192.0.2.9");
        let src = ip("203.0.113.1");
        let dst = ip("203.0.113.2");

        let mut countries = HashMap::new();
        record.count_country(&mut countries, &filter).unwrap();
        assert_eq!(
            countries,
            HashMap::from([("JP".to_string(), 1), ("DE".to_string(), 1)])
        );

        let mut categories = HashMap::new();
        record.count_category(&mut categories, &filter).unwrap();
        assert_eq!(
            categories,
            HashMap::from([(Some(EventCategory::Reconnaissance), 1)])
        );

        let mut models = HashMap::new();
        record.count_detection_model(&mut models, &filter).unwrap();
        assert_eq!(models, HashMap::from([(DetectionModel::PortScan, 1)]));

        let mut addrs = HashMap::new();
        record.count_ip_address(&mut addrs, &filter).unwrap();
        assert_eq!(addrs, HashMap::from([(host, 1), (src, 1), (dst, 1)]));

        let mut origs = HashMap::new();
        record
            .count_originator_ip_address(&mut origs, &filter)
            .unwrap();
        assert_eq!(origs, HashMap::from([(host, 1), (src, 1)]));

        let mut resps = HashMap::new();
        record
            .count_responder_ip_address(&mut resps, &filter)
            .unwrap();
        assert_eq!(resps, HashMap::from([(host, 1), (dst, 1)]));

        // Ordered pairs: (originator side, responder side), each once.
        let mut pairs = HashMap::new();
        record.count_ip_address_pair(&mut pairs, &filter).unwrap();
        assert_eq!(
            pairs,
            HashMap::from([
                ((host, host), 1),
                ((host, dst), 1),
                ((src, host), 1),
                ((src, dst), 1),
            ])
        );
        assert!(!pairs.contains_key(&(dst, src)));

        let mut pair_models = HashMap::new();
        record
            .count_ip_address_pair_and_detection_model(&mut pair_models, &filter)
            .unwrap();
        assert_eq!(pair_models.len(), 4);
        assert!(
            pair_models
                .iter()
                .all(|((_, _, model), count)| *model == DetectionModel::PortScan && *count == 1)
        );

        // Each address maps to the first network containing it, and a
        // network counts once per event.
        let mut networks = HashMap::new();
        record
            .count_network(
                &mut networks,
                &[
                    network(1, &["203.0.113.0/25"]),
                    network(2, &["203.0.113.0/24", "192.0.2.0/24"]),
                    network(3, &["0.0.0.0/0"]),
                ],
                &filter,
            )
            .unwrap();
        assert_eq!(networks, HashMap::from([(1, 1), (2, 1)]));

        // A second event adds one more to each of its buckets.
        record.count_ip_address(&mut addrs, &filter).unwrap();
        assert_eq!(addrs, HashMap::from([(host, 2), (src, 2), (dst, 2)]));
    }

    #[test]
    fn counts_deduplicate_beyond_the_inline_limit() {
        let related_ips: Vec<_> = (1..=20)
            .flat_map(|i| {
                let addr = format!("203.0.113.{i}");
                [related(&addr, Source), related(&addr, Destination)]
            })
            .collect();
        let record = stored(subject_event(PrimarySubject::Sensor, related_ips));
        let filter = empty();

        let mut addrs = HashMap::new();
        record.count_ip_address(&mut addrs, &filter).unwrap();
        assert_eq!(addrs.len(), 20);
        assert!(addrs.values().all(|count| *count == 1));

        let mut pairs = HashMap::new();
        record.count_ip_address_pair(&mut pairs, &filter).unwrap();
        assert_eq!(pairs.len(), 400);
        assert!(pairs.values().all(|count| *count == 1));

        let mut countries = HashMap::new();
        record.count_country(&mut countries, &filter).unwrap();
        assert_eq!(countries, HashMap::from([("XX".to_string(), 1)]));
    }

    #[test]
    fn counts_render_non_utf8_codes_as_one_bucket() {
        let record = stored_with(
            conn_event("192.0.2.1", "198.51.100.1"),
            &[("192.0.2.1", [0xff, 0xfe]), ("198.51.100.1", [0xfe, 0xff])],
        );
        let mut countries = HashMap::new();
        record.count_country(&mut countries, &empty()).unwrap();
        assert_eq!(countries, HashMap::from([("ZZ".to_string(), 1)]));
    }

    #[test]
    fn a_record_without_endpoint_addresses_counts_only_category_and_model() {
        let record = sysmon();
        let filter = empty();

        let mut categories = HashMap::new();
        record.count_category(&mut categories, &filter).unwrap();
        assert_eq!(
            categories,
            HashMap::from([(Some(EventCategory::CommandAndControl), 1)])
        );
        let mut models = HashMap::new();
        record.count_detection_model(&mut models, &filter).unwrap();
        assert_eq!(models, HashMap::from([(DetectionModel::NonBrowser, 1)]));

        let mut countries = HashMap::new();
        record.count_country(&mut countries, &filter).unwrap();
        assert!(countries.is_empty());
        let mut addrs: HashMap<IpAddr, usize> = HashMap::new();
        record.count_ip_address(&mut addrs, &filter).unwrap();
        record
            .count_originator_ip_address(&mut addrs, &filter)
            .unwrap();
        record
            .count_responder_ip_address(&mut addrs, &filter)
            .unwrap();
        assert!(addrs.is_empty());
        let mut pairs = HashMap::new();
        record.count_ip_address_pair(&mut pairs, &filter).unwrap();
        assert!(pairs.is_empty());
        let mut pair_models = HashMap::new();
        record
            .count_ip_address_pair_and_detection_model(&mut pair_models, &filter)
            .unwrap();
        assert!(pair_models.is_empty());
        let mut networks = HashMap::new();
        record
            .count_network(&mut networks, &[network(1, &["0.0.0.0/0"])], &filter)
            .unwrap();
        assert!(networks.is_empty());
    }

    #[test]
    fn a_subject_with_one_empty_side_yields_no_pair() {
        let record = stored(subject_event(
            PrimarySubject::Network {
                customer: 1,
                name: "office".to_string(),
                role: ThreatRole::Target,
            },
            vec![related("203.0.113.1", Source)],
        ));
        let mut pairs = HashMap::new();
        record.count_ip_address_pair(&mut pairs, &empty()).unwrap();
        assert!(pairs.is_empty());
        let mut resps = HashMap::new();
        record
            .count_responder_ip_address(&mut resps, &empty())
            .unwrap();
        assert!(resps.is_empty());
        let mut origs = HashMap::new();
        record
            .count_originator_ip_address(&mut origs, &empty())
            .unwrap();
        assert_eq!(origs, HashMap::from([(ip("203.0.113.1"), 1)]));
    }

    #[test]
    fn an_event_that_does_not_match_adds_nothing() {
        let filter = EventFilter {
            detection_models: Some(vec![DetectionModel::PortScan]),
            ..empty()
        };
        let record = conn();
        let mut countries = HashMap::from([("US".to_string(), 3)]);
        record.count_country(&mut countries, &filter).unwrap();
        assert_eq!(countries, HashMap::from([("US".to_string(), 3)]));
        let mut categories = HashMap::new();
        record.count_category(&mut categories, &filter).unwrap();
        assert!(categories.is_empty());
        let mut models = HashMap::new();
        record.count_detection_model(&mut models, &filter).unwrap();
        assert!(models.is_empty());
        let mut addrs = HashMap::new();
        record.count_ip_address(&mut addrs, &filter).unwrap();
        record
            .count_originator_ip_address(&mut addrs, &filter)
            .unwrap();
        record
            .count_responder_ip_address(&mut addrs, &filter)
            .unwrap();
        assert!(addrs.is_empty());
        let mut pairs = HashMap::new();
        record.count_ip_address_pair(&mut pairs, &filter).unwrap();
        assert!(pairs.is_empty());
        let mut pair_models = HashMap::new();
        record
            .count_ip_address_pair_and_detection_model(&mut pair_models, &filter)
            .unwrap();
        assert!(pair_models.is_empty());
        let mut networks = HashMap::new();
        record
            .count_network(&mut networks, &[network(1, &["0.0.0.0/0"])], &filter)
            .unwrap();
        assert!(networks.is_empty());

        // The selected events count, under the filter's detection models.
        let mut models = HashMap::new();
        for record in [conn(), host_subject(), sensor_subject()] {
            record.count_detection_model(&mut models, &filter).unwrap();
        }
        assert_eq!(models, HashMap::from([(DetectionModel::PortScan, 2)]));
    }
}
