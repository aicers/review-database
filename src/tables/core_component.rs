//! The `core_component` table.
//!
//! The platform's own host-fixed infrastructure — `review`, `aice-web-next`,
//! `roxyd` and `bootroot` — is neither an agent nor an external service. This
//! table is its registry: one row per `(component, host)`, recording which
//! build is installed there and what install or run state it is in.

use std::borrow::Cow;

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use super::Lifecycle;
use crate::{Map, Table, UniqueKey, tables::Value as ValueTrait, types::FromKeyValue};

/// A core component installed, or due to be installed, on a host.
///
/// Core components are host-fixed infrastructure: `roxyd` runs on every host,
/// `review` and `aice-web-next` are singletons, and `bootroot` is the
/// installer-managed trust anchor. Several rows therefore share
/// `component = "roxyd"` with distinct hosts, while the singletons have one row
/// each.
///
/// # Identity
///
/// The row is keyed by `(component, host)`. Core components are
/// single-instance, so — unlike an agent — there is no instance dimension in
/// the key, and v1 holds at most one row per pair. A second install for a pair
/// that already has a row is refused rather than given another number: there is
/// deliberately no counter, no reservation, and no release rule. Use
/// [`Table::insert`](crate::Table::insert), which fails on an existing key,
/// rather than a blind put.
///
/// # Why `component` is a `String`
///
/// The four package-ids look like a finite set, but the registry that defines
/// them is owned by the platform's packaging layer, not by this crate. An
/// `enum` here would fork that registry into this crate's persisted schema,
/// would need a data migration and a format bump for what is really just a new
/// row, and would have to be translated at both boundaries — `review` and
/// `review-web` already exchange package-ids as strings. The cost is accepted
/// deliberately: an invalid package-id is not rejected at the type level, and
/// the `component` half of the key stays variable-length, which is what makes
/// the key's unambiguous encoding mandatory rather than optional.
///
/// Validating that `component` is a known package-id, or that `host` is a
/// well-formed DNS name, is not this table's job; it stores what it is given.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CoreComponent {
    /// The canonical package-id: `review`, `aice-web-next`, `roxyd` or
    /// `bootroot`.
    pub component: String,
    /// The host the component is installed on.
    pub host: String,
    /// The version of the build installed on the host, as the host reports it.
    ///
    /// An opaque display label, not required to be semver. Build identity is
    /// `(installed_version, installed_commit)`; the version alone does not
    /// identify a build, because the same version may carry different commits —
    /// a pre-release rebuilt from a new commit, or a hotfix without a version
    /// bump.
    pub installed_version: Option<String>,
    /// The commit of the build installed on the host, as the host reports it.
    pub installed_commit: Option<String>,
    /// The install and run state of the build on the host.
    pub lifecycle: Lifecycle,
    /// Whether the row is excluded from UI-driven update.
    ///
    /// `true` for `bootroot`, which is the installer-managed trust anchor and
    /// must never be offered for update through the UI. This crate only stores
    /// the flag; enforcing the exclusion is `review-web`'s job.
    pub installer_managed: bool,
}

impl UniqueKey for CoreComponent {
    type AsBytes<'a> = Vec<u8>;

    fn unique_key(&self) -> Vec<u8> {
        Key::new(&self.component, &self.host).to_bytes()
    }
}

impl ValueTrait for CoreComponent {
    type AsBytes<'a> = Vec<u8>;

    fn value(&self) -> Vec<u8> {
        let value = Value {
            installed_version: self.installed_version.as_deref().map(Cow::Borrowed),
            installed_commit: self.installed_commit.as_deref().map(Cow::Borrowed),
            lifecycle: self.lifecycle.to_stored_index(),
            installer_managed: self.installer_managed,
        };
        super::serialize(&value).expect("serializable")
    }
}

impl FromKeyValue for CoreComponent {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let (component, host) = Key::from_bytes(key)?;
        let value: Value = super::deserialize(value)?;

        Ok(Self {
            component,
            host,
            installed_version: value.installed_version.map(Cow::into_owned),
            installed_commit: value.installed_commit.map(Cow::into_owned),
            lifecycle: Lifecycle::from_stored_index(value.lifecycle),
            installer_managed: value.installer_managed,
        })
    }
}

/// The `(component, host)` key of a [`CoreComponent`] row.
///
/// # Encoding
///
/// The key is a **length-prefixed serialized tuple**, written by
/// [`Key::to_bytes`] and read back by its exact inverse [`Key::from_bytes`].
/// Both halves are variable-length strings, so concatenating their bytes would
/// collide: `("ab", "c")` and `("a", "bc")` would produce the same key. The
/// length prefix each half carries removes the ambiguity, and `("ab", "c")` and
/// `("a", "bc")` therefore land on distinct keys.
///
/// The prefixes come from the crate's own bincode configuration — the same
/// `serialize` / `deserialize` helpers the values use — rather than a
/// hand-rolled framing, so there is one encoder, one decoder, and no second
/// configuration to keep in step. A delimiter byte would have been acceptable
/// too, but only with a validation this table deliberately does not perform:
/// it stores whatever `component` and `host` it is given.
///
/// Every read and write path goes through this pair, so `get`, `delete` and
/// [`UniqueKey::unique_key`] cannot drift apart.
struct Key<'a> {
    component: &'a str,
    host: &'a str,
}

impl<'a> Key<'a> {
    fn new(component: &'a str, host: &'a str) -> Self {
        Self { component, host }
    }

    fn to_bytes(&self) -> Vec<u8> {
        // A pair of string slices has no unserializable value, and the
        // configuration sets no size limit, so this cannot fail.
        super::serialize(&(self.component, self.host)).expect("serializable")
    }

    /// Decodes the `(component, host)` pair [`Key::to_bytes`] wrote.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not a key this encoder produced.
    fn from_bytes(bytes: &[u8]) -> Result<(String, String)> {
        super::deserialize(bytes)
    }
}

/// The persisted form of everything but the key.
///
/// `lifecycle` is the [`Lifecycle`] variant index rather than the enum itself:
/// a derived enum field fails the whole row when it meets a variant index this
/// build does not know, whereas a `u8` reads back and resolves to
/// [`Lifecycle::Unknown`]. The bytes are the same either way.
///
/// The string fields are `Cow` so that a write borrows them from the record and
/// a read owns them, without a second struct whose field order could silently
/// drift from this one: bincode writes no field names, so a field present on
/// one side and missing on the other would be dropped on read rather than
/// rejected.
#[derive(Deserialize, Serialize)]
struct Value<'a> {
    installed_version: Option<Cow<'a, str>>,
    installed_commit: Option<Cow<'a, str>>,
    lifecycle: u8,
    installer_managed: bool,
}

/// Functions for the `core_component` table.
///
/// Iteration comes from the blanket [`Iterable`](crate::Iterable)
/// implementation on [`Table`], whose keys are the encoded `(component, host)`
/// pairs.
impl<'d> Table<'d, CoreComponent> {
    /// Opens the `core_component` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    // Allowed as unused because the column family is not in `MAP_NAMES` yet:
    // registering it and adding the `Store` accessor that calls this belong with
    // the database format bump. Until then only the tests below open the table.
    #[allow(dead_code)]
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::CORE_COMPONENTS).map(Table::new)
    }

    /// Returns the row for the given `(component, host)` pair, or `None` if no
    /// such row exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored row is invalid or the database operation
    /// fails.
    pub fn get(&self, component: &str, host: &str) -> Result<Option<CoreComponent>> {
        let key = Key::new(component, host).to_bytes();
        let Some(value) = self.map.get(&key)? else {
            return Ok(None);
        };
        Ok(Some(CoreComponent::from_key_value(&key, value.as_ref())?))
    }

    /// Deletes the row for the given `(component, host)` pair.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete(&self, component: &str, host: &str) -> Result<()> {
        self.map.delete(&Key::new(component, host).to_bytes())
    }

    /// Replaces `old` with `new`.
    ///
    /// # Errors
    ///
    /// Returns an error if `old` does not match the stored row, if it does not
    /// exist, or if the database operation fails.
    pub fn update(&self, old: &CoreComponent, new: &CoreComponent) -> Result<()> {
        let (ok, ov) = (old.unique_key(), old.value());
        let (nk, nv) = (new.unique_key(), new.value());
        self.map.update((&ok, &ov), (&nk, &nv))
    }
}

#[cfg(test)]
mod tests {
    use rocksdb::Direction;

    use super::*;
    use crate::Iterable;
    use crate::test::{DbGuard, acquire_db_permit};

    const ALL_LIFECYCLES: [Lifecycle; 7] = [
        Lifecycle::NotInstalled,
        Lifecycle::Installing,
        Lifecycle::Running,
        Lifecycle::Stopped,
        Lifecycle::Failed,
        Lifecycle::Removing,
        Lifecycle::Unknown,
    ];

    /// A lifecycle index no variant is stored as.
    const UNRECOGNIZED_LIFECYCLE: u8 = 9;

    /// A database carrying this table's column family, which `StateDb::open`
    /// does not yet create because the name is not in `MAP_NAMES`.
    struct TestDb {
        db: OptimisticTransactionDB,
        _dir: tempfile::TempDir,
        _permit: DbGuard<'static>,
    }

    impl TestDb {
        fn new() -> Self {
            let permit = acquire_db_permit();
            let dir = tempfile::tempdir().unwrap();
            let mut opts = rocksdb::Options::default();
            opts.create_if_missing(true);
            opts.create_missing_column_families(true);
            let mut column_families = super::super::MAP_NAMES.to_vec();
            column_families.push(super::super::CORE_COMPONENTS);
            let db = OptimisticTransactionDB::open_cf(
                &opts,
                dir.path().join("states.db"),
                column_families,
            )
            .unwrap();
            Self {
                db,
                _dir: dir,
                _permit: permit,
            }
        }

        fn table(&self) -> Table<'_, CoreComponent> {
            Table::<CoreComponent>::open(&self.db).unwrap()
        }
    }

    fn installed(component: &str, host: &str) -> CoreComponent {
        CoreComponent {
            component: component.to_string(),
            host: host.to_string(),
            installed_version: Some("0.46.0".to_string()),
            installed_commit: Some("c0ffee".to_string()),
            lifecycle: Lifecycle::Running,
            installer_managed: false,
        }
    }

    fn round_trip(record: &CoreComponent) -> CoreComponent {
        CoreComponent::from_key_value(&record.unique_key(), &record.value()).unwrap()
    }

    #[test]
    fn value_round_trips_every_field() {
        let mut record = installed("review", "host-01.example.com");
        assert_eq!(round_trip(&record), record);

        record.installed_version = None;
        record.installed_commit = None;
        assert_eq!(round_trip(&record), record);

        record.installed_version = Some("2026.03-rc1".to_string());
        record.installed_commit = None;
        assert_eq!(round_trip(&record), record);

        record.installed_commit = Some("deadbeef".to_string());
        record.installer_managed = true;
        assert_eq!(round_trip(&record), record);
    }

    #[test]
    fn lifecycle_round_trips_every_variant() {
        for lifecycle in ALL_LIFECYCLES {
            let mut record = installed("roxyd", "host-01.example.com");
            record.lifecycle = lifecycle;
            assert_eq!(round_trip(&record).lifecycle, lifecycle);
        }
    }

    /// A row whose stored lifecycle number this build does not recognize stays
    /// readable: the number resolves to `Unknown` and every other field
    /// survives.
    #[test]
    fn unrecognized_lifecycle_reads_back_as_unknown() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let record = installed("roxyd", "host-02.example.com");
        table.insert(&record).unwrap();

        let key = record.unique_key();
        let stored = record.value();
        let tampered = crate::tables::serialize(&Value {
            installed_version: record.installed_version.as_deref().map(Cow::Borrowed),
            installed_commit: record.installed_commit.as_deref().map(Cow::Borrowed),
            lifecycle: UNRECOGNIZED_LIFECYCLE,
            installer_managed: record.installer_managed,
        })
        .unwrap();
        // Only the lifecycle byte differs, so the write below is the same row
        // with an unrecognized lifecycle rather than a differently shaped value.
        assert_eq!(stored.len(), tampered.len());
        assert_eq!(
            stored
                .iter()
                .zip(tampered.iter())
                .filter(|(a, b)| a != b)
                .count(),
            1
        );
        table.map.put(&key, &tampered).unwrap();

        let read = table.get("roxyd", "host-02.example.com").unwrap().unwrap();
        assert_eq!(read.lifecycle, Lifecycle::Unknown);
        assert_eq!(read.component, record.component);
        assert_eq!(read.host, record.host);
        assert_eq!(read.installed_version, record.installed_version);
        assert_eq!(read.installed_commit, record.installed_commit);
        assert_eq!(read.installer_managed, record.installer_managed);
    }

    /// The two halves of the key are variable-length, so a naive concatenation
    /// would map these pairs onto the same bytes.
    #[test]
    fn key_encoding_is_collision_safe() {
        assert_ne!(
            Key::new("ab", "c").to_bytes(),
            Key::new("a", "bc").to_bytes()
        );

        let test_db = TestDb::new();
        let table = test_db.table();

        let first = installed("ab", "c");
        let second = installed("a", "bc");
        table.insert(&first).unwrap();
        table.insert(&second).unwrap();

        assert_eq!(table.get("ab", "c").unwrap(), Some(first));
        assert_eq!(table.get("a", "bc").unwrap(), Some(second));
    }

    #[test]
    fn key_round_trips() {
        for (component, host) in [
            ("roxyd", "host-01.example.com"),
            ("ab", "c"),
            ("a", "bc"),
            ("bootroot", "a"),
        ] {
            let bytes = Key::new(component, host).to_bytes();
            assert_eq!(
                Key::from_bytes(&bytes).unwrap(),
                (component.to_string(), host.to_string())
            );
        }
    }

    /// A key with anything appended is not a key this encoder produced, so the
    /// decoder rejects it rather than silently ignoring the tail.
    #[test]
    fn key_decoding_rejects_bytes_this_encoder_never_wrote() {
        let mut trailing = Key::new("roxyd", "host-01.example.com").to_bytes();
        trailing.push(0);
        assert!(Key::from_bytes(&trailing).is_err());

        // A length prefix that runs past the end of the input.
        assert!(Key::from_bytes(b"\x01a").is_err());
        assert!(Key::from_bytes(b"").is_err());
    }

    #[test]
    fn reports_an_undecodable_value_and_tolerates_a_missing_key() {
        let test_db = TestDb::new();
        let table = test_db.table();

        table
            .map
            .put(
                &Key::new("roxyd", "host-01.example.com").to_bytes(),
                b"not a stored value",
            )
            .unwrap();
        assert!(table.get("roxyd", "host-01.example.com").is_err());

        // Deleting a pair that was never written is not an error, so a
        // re-driven cleanup need not check first.
        table.delete("roxyd", "host-99.example.com").unwrap();
    }

    /// `get` and `delete` build their key from the pair they are given, so
    /// iteration is the one path that hands `from_key_value` raw bytes.
    #[test]
    fn reports_a_key_that_is_not_an_encoded_pair() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let record = installed("roxyd", "host-01.example.com");
        table.map.put(b"\x01a", &record.value()).unwrap();

        assert!(
            table
                .iter(Direction::Forward, None)
                .collect::<Result<Vec<_>>>()
                .is_err()
        );
    }

    /// `update` is a compare-and-set: it refuses an `old` that does not match
    /// what is stored, so a caller working from a stale read cannot overwrite a
    /// change it never saw.
    #[test]
    fn update_refuses_a_stale_or_missing_old_row() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let stored = installed("roxyd", "host-01.example.com");
        table.insert(&stored).unwrap();

        let mut stale = stored.clone();
        stale.lifecycle = Lifecycle::Stopped;
        let mut new = stored.clone();
        new.lifecycle = Lifecycle::Failed;
        assert!(table.update(&stale, &new).is_err());
        assert_eq!(
            table.get("roxyd", "host-01.example.com").unwrap(),
            Some(stored)
        );

        let absent = installed("roxyd", "host-99.example.com");
        let mut absent_new = absent.clone();
        absent_new.lifecycle = Lifecycle::Failed;
        assert!(table.update(&absent, &absent_new).is_err());
        assert_eq!(table.get("roxyd", "host-99.example.com").unwrap(), None);
    }

    /// An update that changes the key moves the row: the pair it was stored
    /// under is left empty rather than keeping a stale copy.
    #[test]
    fn update_to_a_different_pair_moves_the_row() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let old = installed("roxyd", "host-01.example.com");
        let new = installed("roxyd", "host-02.example.com");
        table.insert(&old).unwrap();
        table.update(&old, &new).unwrap();

        assert_eq!(table.get("roxyd", "host-01.example.com").unwrap(), None);
        assert_eq!(
            table.get("roxyd", "host-02.example.com").unwrap(),
            Some(new)
        );
        assert_eq!(table.iter(Direction::Forward, None).count(), 1);
    }

    /// `update` is the other path that could put a second row on a pair that
    /// already has one, so it refuses a move onto an occupied pair just as
    /// `insert` refuses a duplicate. Both rows survive unchanged.
    #[test]
    fn update_onto_an_occupied_pair_is_refused() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let old = installed("roxyd", "host-01.example.com");
        let occupant = installed("roxyd", "host-02.example.com");
        table.insert(&old).unwrap();
        table.insert(&occupant).unwrap();

        let mut moved = old.clone();
        moved.host = occupant.host.clone();
        moved.lifecycle = Lifecycle::Failed;
        assert!(table.update(&old, &moved).is_err());

        assert_eq!(
            table.get("roxyd", "host-01.example.com").unwrap(),
            Some(old)
        );
        assert_eq!(
            table.get("roxyd", "host-02.example.com").unwrap(),
            Some(occupant)
        );
        assert_eq!(table.iter(Direction::Forward, None).count(), 2);
    }

    #[test]
    fn crud_and_iteration() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let mut record = installed("review", "host-01.example.com");
        record.installed_version = None;
        record.installed_commit = None;
        record.lifecycle = Lifecycle::NotInstalled;
        table.insert(&record).unwrap();
        assert_eq!(
            table.get("review", "host-01.example.com").unwrap(),
            Some(record.clone())
        );
        assert_eq!(table.get("review", "host-99.example.com").unwrap(), None);

        let mut updated = record.clone();
        updated.installed_version = Some("0.46.0".to_string());
        updated.installed_commit = Some("c0ffee".to_string());
        updated.lifecycle = Lifecycle::Running;
        table.update(&record, &updated).unwrap();
        assert_eq!(
            table.get("review", "host-01.example.com").unwrap(),
            Some(updated.clone())
        );

        let stored = table
            .iter(Direction::Forward, None)
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_eq!(stored, vec![updated]);

        table.delete("review", "host-01.example.com").unwrap();
        assert_eq!(table.get("review", "host-01.example.com").unwrap(), None);
        assert_eq!(table.iter(Direction::Forward, None).count(), 0);
    }

    /// `roxyd` runs on every host, so its rows are distinguished by host alone.
    #[test]
    fn roxyd_rows_coexist_per_host() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let hosts = [
            "host-01.example.com",
            "host-02.example.com",
            "host-03.example.com",
        ];
        for host in hosts {
            table.insert(&installed("roxyd", host)).unwrap();
        }
        for host in hosts {
            assert_eq!(
                table.get("roxyd", host).unwrap(),
                Some(installed("roxyd", host))
            );
        }

        table.delete("roxyd", "host-02.example.com").unwrap();
        assert_eq!(table.get("roxyd", "host-02.example.com").unwrap(), None);
        assert_eq!(
            table.get("roxyd", "host-01.example.com").unwrap(),
            Some(installed("roxyd", "host-01.example.com"))
        );
        assert_eq!(
            table.get("roxyd", "host-03.example.com").unwrap(),
            Some(installed("roxyd", "host-03.example.com"))
        );
    }

    #[test]
    fn installer_managed_round_trips() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let mut bootroot = installed("bootroot", "host-01.example.com");
        bootroot.installer_managed = true;
        let review = installed("review", "host-01.example.com");
        table.insert(&bootroot).unwrap();
        table.insert(&review).unwrap();

        assert!(
            table
                .get("bootroot", "host-01.example.com")
                .unwrap()
                .unwrap()
                .installer_managed
        );
        assert!(
            !table
                .get("review", "host-01.example.com")
                .unwrap()
                .unwrap()
                .installer_managed
        );
    }

    /// v1 refuses a second install for a pair that already has a row instead of
    /// allocating another instance number.
    #[test]
    fn duplicate_insert_is_refused() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let first = installed("roxyd", "host-01.example.com");
        table.insert(&first).unwrap();

        let mut second = first.clone();
        second.installed_version = Some("0.47.0".to_string());
        second.installed_commit = Some("deadbee".to_string());
        second.lifecycle = Lifecycle::Installing;
        assert!(table.insert(&second).is_err());

        assert_eq!(
            table.get("roxyd", "host-01.example.com").unwrap(),
            Some(first)
        );
        assert_eq!(table.iter(Direction::Forward, None).count(), 1);
    }
}
