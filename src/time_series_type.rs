//! The catalog of time-series types: fixed recipes for generating time series
//! from one network raw event kind and training a timeseries model on them.
//!
//! A time-series generation policy either names a type, in which case the
//! type's generation-spec values cannot be changed and the policy may not
//! filter by IP, or is custom, in which case the operator sets every value.
//! Like the clustering model type catalog, the catalog is code that ships
//! with this crate's releases; it is never stored in the database, and
//! operators do not edit it. It holds only the current version of each type.

use review_protocol::types::{
    CounterpartScope, DetectionModel, EndpointRole, GroupByUnit, Measure, RawEventKind, ThreatRole,
};

use crate::{FixedValue, ModelMethod, SlotSize, TypeOperatorValue, WindowSize};

/// A time-series type: a fixed recipe for generating time series from one
/// raw event kind and training a timeseries model on them.
///
/// The values a policy's operator sets whatever the type (its name, its
/// sensors, its assigned generator and its `utc_offset`) are not part of a
/// type.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TimeSeriesType {
    /// The snake-case identifier, never changed.
    pub id: &'static str,
    /// The version, raised by 1 whenever the fixed values or the allowed
    /// detection models change.
    pub version: u32,
    /// The position in the catalog.
    pub order: u32,
    /// The kind of the raw events the policy counts.
    pub raw_event_kind: RawEventKind,
    /// The clustering method of the model trained on the series.
    pub method: ModelMethod,
    /// The value counted per slot.
    pub measure: Measure,
    /// The endpoint whose IP splits the series. Every type splits by one.
    pub group_by: EndpointRole,
    /// The unit `group_by` splits by.
    pub group_by_unit: GroupByUnit,
    /// The filter on whether the other endpoint is internal.
    pub counterpart_scope: CounterpartScope,
    /// The length of one slot.
    pub slot_size: SlotSize,
    /// The length of one window, which is one series sample.
    pub window_size: WindowSize,
    /// The threat role of the primary subject of the type's detections.
    pub threat_role: ThreatRole,
    /// The training definition keys the type fixes, with their values.
    pub fixed: &'static [FixedValue],
    /// The training definition values the operator sets.
    pub operator_values: &'static [TypeOperatorValue],
    /// The detection models allowed to run on the model, in
    /// [`DetectionModel`] order.
    pub detection_models: &'static [DetectionModel],
    /// The names of the IP columns, kept in the series table but not used as
    /// features.
    pub ip_columns: &'static [&'static str],
    /// What the type counts and what its limits are, in English.
    pub description_en: &'static str,
    /// What the type counts and what its limits are, in Korean.
    pub description_ko: &'static str,
}

/// Returns every time-series type, in catalog order.
#[must_use]
pub fn time_series_types() -> &'static [TimeSeriesType] {
    CATALOG
}

/// Returns the time-series type `id`, or `None` if the catalog has no type of
/// that id. The version is not compared.
#[must_use]
pub fn time_series_type(id: &str) -> Option<&'static TimeSeriesType> {
    find(CATALOG, id)
}

/// Returns the type `id` of `catalog`, or `None` if it has none of that id.
pub(crate) fn find<'c>(catalog: &'c [TimeSeriesType], id: &str) -> Option<&'c TimeSeriesType> {
    catalog.iter().find(|t| t.id == id)
}

/// The shipped catalog. It is empty until the types are defined.
const CATALOG: &[TimeSeriesType] = &[];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_catalog_is_empty() {
        assert_eq!(time_series_types(), []);
        for id in ["", "conn_count", "custom", "http_url"] {
            assert_eq!(time_series_type(id), None, "{id:?}");
        }
    }
}
