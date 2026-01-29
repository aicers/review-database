//! Old data structures for migration purposes.
//!
//! These structures represent the schemas from previous releases
//! and must not be modified. They are used to migrate data from
//! old formats to new formats.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::HostNetworkGroup;

/// Network value structure from version 0.43.x
///
/// This structure represents the old serialized value format where:
/// - The key was `name + id.to_be_bytes()` (name followed by 4-byte big-endian id)
/// - The value contained `customer_ids` field (now removed)
/// - The value did NOT contain `id` field (id was in the key)
#[derive(Serialize, Deserialize)]
pub(crate) struct NetworkValueV0_43 {
    pub(crate) description: String,
    pub(crate) networks: HostNetworkGroup,
    pub(crate) customer_ids: Vec<u32>,
    pub(crate) tag_ids: Vec<u32>,
    pub(crate) creation_time: DateTime<Utc>,
}
