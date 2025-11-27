#![allow(deprecated)]
use std::{cmp::Ordering, net::IpAddr, ops::RangeInclusive};

use anyhow::Result;
use chrono::{NaiveDateTime, naive::serde::ts_nanoseconds_option};
use ipnet::IpNet;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};
use strum_macros::Display;

pub use crate::account::{Account, Role};
use crate::event::TrafficDirection;

pub trait FromKeyValue: Sized + private::Sealed {
    /// Creates a new instance from the given key and value.
    ///
    /// # Errors
    ///
    /// Returns an error if the key or value cannot be deserialized.
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self>;
}

mod private {
    use crate::{tables, types};

    pub trait Sealed {}

    impl Sealed for tables::AccessToken {}
    impl Sealed for types::Account {}
    impl Sealed for tables::Agent {}
    impl Sealed for tables::AllowNetwork {}
    impl Sealed for tables::BackupConfig {}
    impl Sealed for crate::BatchInfo {}
    impl Sealed for tables::BlockNetwork {}
    impl Sealed for crate::Category {}
    impl Sealed for tables::Cluster {}
    impl Sealed for tables::CsvColumnExtra {}
    impl Sealed for tables::Customer {}
    impl Sealed for tables::DataSource {}
    impl Sealed for tables::Filter {}
    impl Sealed for tables::Host {}
    impl Sealed for tables::InnerNode {}
    impl Sealed for tables::Model {}
    impl Sealed for tables::ModelIndicator {}
    impl Sealed for tables::Network {}
    impl Sealed for tables::OutlierInfo {}
    impl Sealed for types::Qualifier {}
    impl Sealed for tables::ExternalService {}
    impl Sealed for tables::SamplingPolicy {}
    impl Sealed for types::Status {}
    impl Sealed for tables::Template {}
    impl Sealed for tables::LabelDb {}
    impl Sealed for tables::TimeSeries {}
    impl Sealed for tables::TorExitNode {}
    impl Sealed for tables::TrafficFilter {}
    impl Sealed for tables::TriageExclusionReason {}
    impl Sealed for tables::TriagePolicy {}
    impl Sealed for tables::TriageResponse {}
    impl Sealed for tables::TrustedDomain {}
    impl Sealed for tables::TrustedUserAgent {}
    impl Sealed for tables::ColumnStats {}
}

pub(crate) type Timestamp = i64;
pub(crate) type Sensor = String;
pub(crate) type Id = (Timestamp, Sensor);

pub struct PretrainedModel(pub Vec<u8>);

pub type EventCategory = EventCategoryV0_42;

#[derive(
    Debug,
    Display,
    Copy,
    Clone,
    Eq,
    Hash,
    PartialEq,
    Deserialize,
    Serialize,
    PartialOrd,
    Ord,
    FromPrimitive,
    ToPrimitive,
)]
#[repr(u8)]
pub enum EventCategoryV0_42 {
    Reconnaissance = 1,
    InitialAccess,
    Execution,
    CredentialAccess,
    Discovery,
    LateralMovement,
    CommandAndControl,
    Exfiltration,
    Impact,
    Collection,
    DefenseEvasion,
    Persistence,
    PrivilegeEscalation,
    ResourceDevelopment,
}

impl From<EventCategoryV0_41> for Option<EventCategoryV0_42> {
    fn from(value: EventCategoryV0_41) -> Self {
        match value {
            EventCategoryV0_41::Unknown => None,
            _ => EventCategoryV0_42::from_u8(value as u8),
        }
    }
}

#[derive(
    Debug,
    Display,
    Copy,
    Clone,
    Eq,
    Hash,
    PartialEq,
    Deserialize,
    Serialize,
    PartialOrd,
    Ord,
    FromPrimitive,
    ToPrimitive,
)]
#[repr(u8)]
pub(crate) enum EventCategoryV0_41 {
    Unknown = 0,
    Reconnaissance = 1,
    InitialAccess,
    Execution,
    CredentialAccess,
    Discovery,
    LateralMovement,
    CommandAndControl,
    Exfiltration,
    Impact,
    Collection,
    DefenseEvasion,
    Persistence,
    PrivilegeEscalation,
    ResourceDevelopment,
}

#[derive(Deserialize)]
pub struct Cluster {
    pub id: i32,
    pub cluster_id: u32,
    pub category_id: i32,
    pub detector_id: i32,
    pub event_ids: Vec<Timestamp>,
    pub sensors: Vec<Sensor>,
    pub labels: Option<Vec<String>>,
    pub qualifier_id: i32,
    pub status_id: i32,
    pub signature: String,
    pub size: i64,
    pub score: Option<f64>,
    #[serde(with = "ts_nanoseconds_option")]
    pub last_modification_time: Option<NaiveDateTime>,
    pub model_id: u32,
}

#[derive(Deserialize, Serialize)]
pub struct Endpoint {
    pub direction: Option<TrafficDirection>,
    pub network: HostNetworkGroup,
}

// `hosts` and `networks` must be kept sorted.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostNetworkGroup {
    hosts: Vec<IpAddr>,
    networks: Vec<IpNet>,
    ip_ranges: Vec<RangeInclusive<IpAddr>>,
}

impl PartialOrd for HostNetworkGroup {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HostNetworkGroup {
    fn cmp(&self, other: &Self) -> Ordering {
        self.hosts
            .cmp(&other.hosts)
            .then_with(|| self.networks.cmp(&other.networks))
            .then_with(|| compare_ip_ranges(&self.ip_ranges, &other.ip_ranges))
    }
}

impl HostNetworkGroup {
    #[must_use]
    pub fn new(
        mut hosts: Vec<IpAddr>,
        mut networks: Vec<IpNet>,
        mut ip_ranges: Vec<RangeInclusive<IpAddr>>,
    ) -> Self {
        hosts.sort_unstable();
        hosts.dedup();
        networks.sort_unstable();
        networks.dedup();
        ip_ranges.sort_unstable_by(|a, b| match a.start().cmp(b.start()) {
            Ordering::Less => Ordering::Less,
            Ordering::Equal => a.end().cmp(b.end()),
            Ordering::Greater => Ordering::Greater,
        });
        ip_ranges.dedup();
        Self {
            hosts,
            networks,
            ip_ranges,
        }
    }

    #[must_use]
    pub fn hosts(&self) -> &[IpAddr] {
        &self.hosts
    }

    #[must_use]
    pub fn ip_ranges(&self) -> &[RangeInclusive<IpAddr>] {
        &self.ip_ranges
    }

    #[must_use]
    pub fn networks(&self) -> &[IpNet] {
        &self.networks
    }

    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        if self.contains_host(addr) {
            return true;
        }

        if self.networks.iter().any(|net| net.contains(&addr)) {
            return true;
        }

        if self.ip_ranges.iter().any(|range| range.contains(&addr)) {
            return true;
        }

        false
    }

    #[must_use]
    pub fn contains_host(&self, host: IpAddr) -> bool {
        self.hosts.binary_search(&host).is_ok()
    }

    #[must_use]
    pub fn contains_ip_range(&self, ip_range: &RangeInclusive<IpAddr>) -> bool {
        self.ip_ranges.contains(ip_range)
    }

    #[must_use]
    pub fn contains_network(&self, network: &IpNet) -> bool {
        self.networks.binary_search(network).is_ok()
    }
}

fn compare_ip_ranges(
    a: &[std::ops::RangeInclusive<std::net::IpAddr>],
    b: &[std::ops::RangeInclusive<std::net::IpAddr>],
) -> Ordering {
    let len_cmp = a.len().cmp(&b.len());
    if len_cmp != Ordering::Equal {
        return len_cmp;
    }
    for (range_a, range_b) in a.iter().zip(b.iter()) {
        let cmp = range_a
            .start()
            .cmp(range_b.start())
            .then_with(|| range_a.end().cmp(range_b.end()));
        if cmp != Ordering::Equal {
            return cmp;
        }
    }
    Ordering::Equal
}

#[derive(Deserialize)]
pub struct Outlier {
    pub id: i32,
    #[serde(with = "serde_bytes")]
    pub raw_event: Vec<u8>,
    pub event_ids: Vec<Timestamp>,
    pub sensors: Vec<Sensor>,
    pub size: i64,
    pub model_id: u32,
}

pub type SeqNo = usize;
pub type ModelScores = std::collections::HashMap<SeqNo, f64>;

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct ModelBatchInfo {
    pub id: i64,
    pub earliest: i64,
    pub latest: i64,
    pub size: usize,
    pub sensors: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Status {
    pub id: u32,
    pub description: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Qualifier {
    pub id: u32,
    pub description: String,
}
