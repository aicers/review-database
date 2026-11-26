//! Triage policy types used by the event matching engine.

use std::cmp::Ordering;

use jiff::Timestamp;
use review_protocol::types::{DetectionModel, RawEventKind};
use serde::{Deserialize, Serialize};

use crate::types::EventCategory;

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
pub enum ValueKind {
    String,
    Integer,  // range: i64::MAX
    UInteger, // range: u64::MAX
    Vector,
    Float,
    IpAddr,
    Bool,
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
pub enum AttrCmpKind {
    Less,
    Equal,
    Greater,
    LessOrEqual,
    GreaterOrEqual,
    Contain,
    OpenRange,
    CloseRange,
    LeftOpenRange,
    RightOpenRange,
    NotEqual,
    NotContain,
    NotOpenRange,
    NotCloseRange,
    NotLeftOpenRange,
    NotRightOpenRange,
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
pub enum ResponseKind {
    Manual,
    Watchlist,
    ExclusionList,
}

#[derive(Clone)]
pub struct TriagePolicyInput {
    pub id: u32,
    pub name: String,
    pub creation_time: Timestamp,
    pub packet_attr: Vec<PacketAttr>,
    pub score: Vec<ScoreCondition>,
    pub response: Vec<Response>,
}

/// A condition on an attribute of a raw event.
///
/// `raw_event_kind` is serialized as the kind's number.
#[derive(Clone, PartialEq, Deserialize, Serialize)]
pub struct PacketAttr {
    pub raw_event_kind: RawEventKind,
    pub attr_name: String,
    pub value_kind: ValueKind,
    pub cmp_kind: AttrCmpKind,
    pub first_value: Vec<u8>,
    pub second_value: Option<Vec<u8>>,
    pub weight: Option<f64>,
}

impl Eq for PacketAttr {}

impl PartialOrd for PacketAttr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PacketAttr {
    fn cmp(&self, other: &Self) -> Ordering {
        let first = self.attr_name.cmp(&other.attr_name);
        if first != Ordering::Equal {
            return first;
        }
        let second = self.value_kind.cmp(&other.value_kind);
        if second != Ordering::Equal {
            return second;
        }
        let third = self.cmp_kind.cmp(&other.cmp_kind);
        if third != Ordering::Equal {
            return third;
        }
        let fourth = self.first_value.cmp(&other.first_value);
        if fourth != Ordering::Equal {
            return fourth;
        }
        let fifth = self.second_value.cmp(&other.second_value);
        if fifth != Ordering::Equal {
            return fifth;
        }
        match (self.weight, other.weight) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(s), Some(o)) => s.total_cmp(&o),
        }
    }
}

/// A condition on a detection event's category, detection model and score.
///
/// The condition holds when the event's category is `threat_category`, its
/// detection model is `detection_model` and its score is at least `score`.
/// `detection_model` is serialized, and ordered, by its number.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct ScoreCondition {
    pub threat_category: Option<EventCategory>,
    pub detection_model: DetectionModel,
    pub score: f64,
    pub weight: Option<f64>,
}

impl Eq for ScoreCondition {}

impl PartialOrd for ScoreCondition {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScoreCondition {
    fn cmp(&self, other: &Self) -> Ordering {
        let first = self.threat_category.cmp(&other.threat_category);
        if first != Ordering::Equal {
            return first;
        }
        let second = u32::from(self.detection_model).cmp(&u32::from(other.detection_model));
        if second != Ordering::Equal {
            return second;
        }
        let third = self.score.total_cmp(&other.score);
        if third != Ordering::Equal {
            return third;
        }
        match (self.weight, other.weight) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(s), Some(o)) => s.total_cmp(&o),
        }
    }
}

#[derive(Clone, PartialEq, Deserialize, Serialize)]
pub struct Response {
    pub minimum_score: f64,
    pub kind: ResponseKind,
}

impl Eq for Response {}

impl PartialOrd for Response {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Response {
    fn cmp(&self, other: &Self) -> Ordering {
        let first = self.minimum_score.total_cmp(&other.minimum_score);
        if first != Ordering::Equal {
            return first;
        }
        self.kind.cmp(&other.kind)
    }
}

#[cfg(test)]
mod test {
    // =========================================================================
    // ScoreCondition: serialization, ordering, and optional threat_category
    // =========================================================================

    use review_protocol::types::{DetectionModel, RawEventKind};

    use crate::{AttrCmpKind, EventCategory, PacketAttr, ScoreCondition, ValueKind};

    fn make_condition(
        category: Option<EventCategory>,
        detection_model: DetectionModel,
        score: f64,
        weight: Option<f64>,
    ) -> ScoreCondition {
        ScoreCondition {
            threat_category: category,
            detection_model,
            score,
            weight,
        }
    }

    #[test]
    fn score_condition_bincode_roundtrip_some() {
        use bincode::Options;

        let condition = make_condition(
            Some(EventCategory::Reconnaissance),
            DetectionModel::PortScan,
            0.9,
            Some(2.0),
        );
        let bytes = bincode::DefaultOptions::new()
            .serialize(&condition)
            .unwrap();
        let back: ScoreCondition = bincode::DefaultOptions::new().deserialize(&bytes).unwrap();
        assert_eq!(condition, back);
    }

    #[test]
    fn score_condition_bincode_roundtrip_none() {
        use bincode::Options;

        let condition = make_condition(None, DetectionModel::NonBrowser, 0.5, None);
        let bytes = bincode::DefaultOptions::new()
            .serialize(&condition)
            .unwrap();
        let back: ScoreCondition = bincode::DefaultOptions::new().deserialize(&bytes).unwrap();
        assert_eq!(condition, back);
    }

    #[test]
    fn score_condition_serializes_detection_model_as_number() {
        let condition = make_condition(None, DetectionModel::UnusualDestinationPattern, 1.5, None);
        let json = serde_json::to_value(&condition).unwrap();
        assert_eq!(json["detection_model"], serde_json::json!(17));
        let back: ScoreCondition = serde_json::from_value(json).unwrap();
        assert_eq!(back, condition);
    }

    #[test]
    fn score_condition_ordering_none_less_than_some() {
        let none = make_condition(None, DetectionModel::PortScan, 0.5, None);
        let some = make_condition(
            Some(EventCategory::Reconnaissance),
            DetectionModel::PortScan,
            0.5,
            None,
        );
        assert!(none < some);
        assert!(some > none);
    }

    #[test]
    fn score_condition_ordering_some_vs_some_preserves_category_order() {
        let recon = make_condition(
            Some(EventCategory::Reconnaissance),
            DetectionModel::PortScan,
            0.5,
            None,
        );
        let exec = make_condition(
            Some(EventCategory::Execution),
            DetectionModel::PortScan,
            0.5,
            None,
        );
        // EventCategory derives Ord from repr(u8) order:
        // Reconnaissance = 1, Execution = 3
        assert!(recon < exec);
    }

    #[test]
    fn score_condition_ordering_orders_detection_models_by_number() {
        // WatchlistMatch = 0, PortScan = 4, UnusualDestinationPattern = 17.
        let watchlist = make_condition(None, DetectionModel::WatchlistMatch, 9.0, None);
        let port_scan = make_condition(None, DetectionModel::PortScan, 0.5, None);
        let unusual = make_condition(None, DetectionModel::UnusualDestinationPattern, 0.1, None);
        assert!(watchlist < port_scan);
        assert!(port_scan < unusual);
        let mut sorted = vec![unusual.clone(), watchlist.clone(), port_scan.clone()];
        sorted.sort_unstable();
        assert_eq!(sorted, [watchlist, port_scan, unusual]);
    }

    #[test]
    fn score_condition_ordering_falls_through_to_score_and_weight() {
        let low = make_condition(None, DetectionModel::PortScan, 0.5, None);
        let high = make_condition(None, DetectionModel::PortScan, 0.7, None);
        assert!(low < high);
        let weighted = make_condition(None, DetectionModel::PortScan, 0.5, Some(1.0));
        assert!(low < weighted);
        assert_eq!(low.cmp(&low.clone()), std::cmp::Ordering::Equal);
    }

    #[test]
    fn packet_attr_serializes_raw_event_kind_as_number() {
        let attr = PacketAttr {
            raw_event_kind: RawEventKind::NetworkConnect,
            attr_name: "Source IP".to_string(),
            value_kind: ValueKind::IpAddr,
            cmp_kind: AttrCmpKind::Equal,
            first_value: vec![1, 2],
            second_value: None,
            weight: Some(0.5),
        };
        let json = serde_json::to_value(&attr).unwrap();
        assert_eq!(json["raw_event_kind"], serde_json::json!(33));

        let bytes = bincode::serialize(&attr).unwrap();
        assert_eq!(bytes[..4], 33_u32.to_le_bytes());
        let back: PacketAttr = bincode::deserialize(&bytes).unwrap();
        assert!(back == attr);
    }

    #[test]
    fn packet_attr_stores_the_endpoint_kinds_by_number() {
        for (kind, number) in [
            (RawEventKind::DriverLoad, 36_u32),
            (RawEventKind::CreateRemoteThread, 38),
            (RawEventKind::RawAccessRead, 39),
            (RawEventKind::ProcessAccess, 40),
            (RawEventKind::RegistryObjectAddDel, 42),
            (RawEventKind::WindowsEventLog, 80),
            (RawEventKind::Journald, 81),
            (RawEventKind::Auditd, 82),
        ] {
            let attr = PacketAttr {
                raw_event_kind: kind,
                attr_name: "Agent Name".to_string(),
                value_kind: ValueKind::String,
                cmp_kind: AttrCmpKind::Contain,
                first_value: vec![1, 2],
                second_value: None,
                weight: None,
            };
            let json = serde_json::to_value(&attr).unwrap();
            assert_eq!(
                json["raw_event_kind"],
                serde_json::json!(number),
                "{kind:?}"
            );
            let bytes = bincode::serialize(&attr).unwrap();
            assert_eq!(bytes[..4], number.to_le_bytes(), "{kind:?}");
            let back: PacketAttr = bincode::deserialize(&bytes).unwrap();
            assert!(back == attr, "{kind:?}");
            let back: PacketAttr = serde_json::from_value(json).unwrap();
            assert!(back == attr, "{kind:?}");
        }
    }
}
