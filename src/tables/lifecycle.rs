//! The install/run lifecycle of a package on a host.

use num_derive::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};
use strum_macros::EnumString;

/// The install and run state of a package on a host.
///
/// This is **actual** state — what the host reports — and never intent. It is
/// orthogonal to [`Status`](super::node::Status), which records the outcome of a
/// configuration reload: a service may be `Running` while its last reload was
/// `ReloadFailed`. The two types are deliberately distinct, and nothing converts
/// between them.
///
/// `UpdateAvailable` is not a variant. It is computed by comparing an installed
/// build against the latest one in the store, and is never stored.
///
/// # Storage
///
/// A stored lifecycle is the **variant index** (`NotInstalled` = 0 through
/// `Unknown` = 6), not the `#[repr(u8)]` discriminant, so `Unknown` reaches disk
/// as `6` rather than `255`. The `u8::MAX` discriminant is house style, matching
/// [`Status`](super::node::Status), and carries no meaning on disk.
///
/// This encoding is this crate's own. `review-protocol`'s wire `Lifecycle` pins
/// its own numbers to its own discriminants; the variant sets match but the
/// numbers do not, so a value read from one side must never be interpreted as
/// the other. The mapping between them belongs in `review`.
///
/// The only two places a `Lifecycle` crosses to or from a stored number are
/// `Lifecycle::to_stored_index` and `Lifecycle::from_stored_index`, both
/// crate-private: the encoding is this crate's own and nothing outside it reads
/// or writes the number.
///
/// # Unknown values
///
/// A stored number this build does not recognize reads back as `Unknown`, never
/// as `NotInstalled`: `Unknown` says "this build cannot interpret what is
/// stored", which is the truth for a record written by a newer build or read
/// after a partial rollback. Reporting such a host as having nothing installed
/// would invite an install where a remediation is due.
///
/// For the same reason the type has no `Default` and no `#[default]` variant:
/// every construction site states its value.
///
/// # `FromPrimitive` and `ToPrimitive`
///
/// The `FromPrimitive` / `ToPrimitive` derives exist for consistency with
/// [`Status`](super::node::Status). Nothing in this crate may use them on a
/// stored lifecycle: `num_derive` maps the **discriminant**, so `from_u8(6)` is
/// `None` for the very number `Unknown` is stored as, while `from_u8(255)`
/// answers a number this encoding never writes.
#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Copy,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    EnumString,
    FromPrimitive,
    ToPrimitive,
)]
#[repr(u8)]
#[strum(serialize_all = "snake_case")]
pub enum Lifecycle {
    NotInstalled = 0,
    Installing = 1,
    Running = 2,
    Stopped = 3,
    Failed = 4,
    Removing = 5,
    Unknown = u8::MAX,
}

impl Lifecycle {
    /// Returns the number this lifecycle is stored as.
    ///
    /// The number is the **variant index**, not the `#[repr(u8)]` discriminant,
    /// so `Unknown` becomes `6` and not `255`. The mapping is written out as an
    /// explicit `match` rather than through `ToPrimitive::to_u8`, which would
    /// yield the discriminant instead.
    ///
    /// This is one of exactly two functions that move a `Lifecycle` between the
    /// enum and its stored number; [`Lifecycle::from_stored_index`] is the
    /// other.
    #[must_use]
    pub(crate) fn to_stored_index(self) -> u8 {
        match self {
            Self::NotInstalled => 0,
            Self::Installing => 1,
            Self::Running => 2,
            Self::Stopped => 3,
            Self::Failed => 4,
            Self::Removing => 5,
            Self::Unknown => 6,
        }
    }

    /// Returns the lifecycle stored as `index`, or `Unknown` if this build does
    /// not recognize the number.
    ///
    /// `index` is a **variant index** as written by
    /// [`Lifecycle::to_stored_index`], not a `#[repr(u8)]` discriminant. The
    /// mapping is an explicit `match` rather than `FromPrimitive::from_u8`,
    /// which maps discriminants: it would answer `None` for `6`, the number
    /// `Unknown` is stored as, and would answer `Unknown` for `255`, a number
    /// this encoding never writes. It agrees with the indices only by
    /// coincidence today, and would start returning a different variant the
    /// moment one is inserted before `Unknown`.
    ///
    /// Every number outside the mapping resolves to `Unknown` — including the
    /// wildcard arm, which must never fall back to `NotInstalled`. A record
    /// written by a newer build is then readable and honest about what it is,
    /// instead of claiming that nothing is installed on a host that may in fact
    /// be running or failed.
    #[must_use]
    pub(crate) fn from_stored_index(index: u8) -> Self {
        match index {
            0 => Self::NotInstalled,
            1 => Self::Installing,
            2 => Self::Running,
            3 => Self::Stopped,
            4 => Self::Failed,
            5 => Self::Removing,
            _ => Self::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use super::*;

    const ALL: [Lifecycle; 7] = [
        Lifecycle::NotInstalled,
        Lifecycle::Installing,
        Lifecycle::Running,
        Lifecycle::Stopped,
        Lifecycle::Failed,
        Lifecycle::Removing,
        Lifecycle::Unknown,
    ];

    #[test]
    fn serde_round_trip() {
        for variant in ALL {
            let serialized = crate::tables::serialize(&variant).unwrap();
            let deserialized: Lifecycle = crate::tables::deserialize(&serialized).unwrap();
            assert_eq!(variant, deserialized);
        }
    }

    /// Pins the bytes each variant serializes to under this crate's bincode
    /// configuration.
    ///
    /// The byte is the variant index, so `Unknown` is stored as `6` and *not* as
    /// `255`, its `#[repr(u8)]` discriminant. This encoding is this crate's own
    /// and is independent of `review-protocol`'s wire `Lifecycle`, which numbers
    /// the same variants differently.
    #[test]
    fn pinned_stored_bytes() {
        let expected: [(Lifecycle, &[u8]); 7] = [
            (Lifecycle::NotInstalled, &[0]),
            (Lifecycle::Installing, &[1]),
            (Lifecycle::Running, &[2]),
            (Lifecycle::Stopped, &[3]),
            (Lifecycle::Failed, &[4]),
            (Lifecycle::Removing, &[5]),
            (Lifecycle::Unknown, &[6]),
        ];
        for (variant, bytes) in expected {
            assert_eq!(crate::tables::serialize(&variant).unwrap(), bytes);
            assert_eq!(
                crate::tables::serialize(&variant.to_stored_index()).unwrap(),
                bytes
            );
        }
    }

    /// Names the expected index of every variant literally, so inserting a
    /// variant cannot silently shift the stored mapping.
    #[test]
    fn stored_index_round_trip() {
        let expected = [
            (Lifecycle::NotInstalled, 0_u8),
            (Lifecycle::Installing, 1),
            (Lifecycle::Running, 2),
            (Lifecycle::Stopped, 3),
            (Lifecycle::Failed, 4),
            (Lifecycle::Removing, 5),
            (Lifecycle::Unknown, 6),
        ];
        for (variant, index) in expected {
            assert_eq!(variant.to_stored_index(), index);
            assert_eq!(Lifecycle::from_stored_index(index), variant);
        }
    }

    #[test]
    fn unrecognized_index_reads_back_as_unknown() {
        for index in [7_u8, 8, 42, 254, 255] {
            assert_eq!(Lifecycle::from_stored_index(index), Lifecycle::Unknown);
        }
    }

    /// Fails if any source file in the crate falls back to the "nothing is
    /// installed" variant for a value it could not interpret.
    ///
    /// The needles are assembled at run time so this file does not trip its own
    /// check. Both they and the source have every space removed before the
    /// comparison, so a site that `rustfmt` has wrapped across lines is caught
    /// just the same as one written on a single line.
    #[test]
    fn no_source_falls_back_to_not_installed() {
        let ty = "Lifecycle";
        let variant = "NotInstalled";
        let qualified = [format!("{ty}::{variant}"), format!("Self::{variant}")];
        let forbidden: Vec<String> = qualified
            .iter()
            .flat_map(|q| {
                [
                    // Open-ended on the right: a wrapped call carries a trailing
                    // comma before its closing parenthesis.
                    format!("unwrap_or({q}"),
                    format!("unwrap_or_else(||{q}"),
                    format!("_=>{q}"),
                ]
            })
            .collect();

        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        collect_rust_files(&root, &mut files);
        assert!(!files.is_empty(), "no source files found under {root:?}");

        for path in files {
            let source = fs::read_to_string(&path).unwrap();
            let normalized: String = source.split_whitespace().collect();
            for needle in &forbidden {
                assert!(
                    !normalized.contains(needle.as_str()),
                    "{}: an uninterpretable lifecycle must resolve to Unknown, found `{needle}`",
                    path.display()
                );
            }
            for line in source.lines() {
                assert!(
                    !(line.contains(ty) && line.contains("unwrap_or_default")),
                    "{}: a lifecycle has no default; use Unknown explicitly",
                    path.display()
                );
            }
        }
    }

    fn collect_rust_files(dir: &Path, files: &mut Vec<std::path::PathBuf>) {
        let entries = fs::read_dir(dir).unwrap();
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect_rust_files(&path, files);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }
}
