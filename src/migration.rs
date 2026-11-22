//! Routines to check the database format version of the data and backup
//! directories.
use std::{
    fs::{File, create_dir_all, remove_file, rename},
    io::{Read, Write},
    path::Path,
    sync::Arc,
};

use anyhow::{Context, Result, anyhow};
use semver::{Version, VersionReq};
use tracing::info;

/// The database format marker written to `VERSION`.
///
/// It names the current database format and is independent of the crate
/// package version: a release does not move it.
///
/// The marker is raised to 0.63.0 once, for a format deployed by a fresh
/// install only: no data directory or backup of 0.62 or any earlier format is
/// migrated to it, and [`migrate_data_dir`] refuses every one of them. Later
/// format changes in the same series keep the marker at `"0.63.0"` and
/// [`COMPATIBLE_VERSION_REQ`] as it is, and add no migration step.
///
/// The online restore (`StateDb::restore_from_backup`) recognizes a backup in
/// this format by its column families, which must be exactly `MAP_NAMES`. The
/// empty `format 0.63` family is what every backup taken before 0.63 lacks,
/// so the check refuses all of them.
pub(crate) const DATABASE_FORMAT_VERSION: &str = "0.63.0";

/// The range of format markers that use the current database format.
///
/// The versions here are database format markers, independent of the crate
/// version. [`DATABASE_FORMAT_VERSION`] names the current format as a stable
/// `X.Y.0`. The range is set to `">=0.63.0,<0.64.0"` once, together with the
/// marker, for the fresh-install 0.63 format, which has no migration from any
/// earlier format. Later format changes in the same series leave both as they
/// are and add no migration step, as does a release or any change without a
/// format change. No build writes a prerelease marker, and none matches this
/// range.
const COMPATIBLE_VERSION_REQ: &str = ">=0.63.0,<0.64.0";

/// The name of the file recording the database format version.
const VERSION_FILE_NAME: &str = "VERSION";

/// The name of the temporary file that [`create_version_file`] renames over
/// [`VERSION_FILE_NAME`].
///
/// The name is fixed rather than unique, so every writer of a marker in one
/// directory collides with every other. Both writers this crate has require
/// exclusive access to each directory they touch for that reason:
/// `migrate_data_dir` runs once at startup, and [`write_version_markers`] is a
/// rollback step the caller serializes against it and against any other
/// rollback. In exchange, an interrupted write can leave behind only this one
/// file, which the next start recognizes.
const VERSION_TMP_FILE_NAME: &str = "VERSION.tmp";

/// The state of a data or backup directory, as [`inspect_version_dir`] finds
/// it without changing anything.
#[derive(Debug, PartialEq, Eq)]
enum DirState {
    /// The directory is missing, empty, or holds nothing but a
    /// [`VERSION_TMP_FILE_NAME`] left by an interrupted marker write.
    Fresh,
    /// The directory holds a `VERSION` file recording this format marker.
    Marked(Version),
}

/// Checks that the data and backup directories are in the current database
/// format, initializing a fresh one.
///
/// The versions this function reads, compares and writes are database format
/// markers, independent of the crate version: `DATABASE_FORMAT_VERSION`
/// names the current format. No earlier format is migrated: the 0.63 format is
/// deployed by a fresh install only, so this function migrates nothing and
/// opens no database.
///
/// A directory is fresh when it is missing, empty, or holds nothing but a
/// `VERSION.tmp` left by an interrupted marker write. Both directories are
/// inspected before anything is written, and the pair is accepted in these
/// cases only:
///
/// * both are fresh: both are initialized with `DATABASE_FORMAT_VERSION`;
/// * both record the same marker within `COMPATIBLE_VERSION_REQ`: nothing is
///   written;
/// * one records exactly `DATABASE_FORMAT_VERSION` and the other is fresh: the
///   fresh one is initialized with it.
///
/// Initializing a directory creates it, with any missing parent, if it is
/// missing, and writes its `VERSION`, replacing a leftover `VERSION.tmp`.
///
/// `ip2location` is not used. It is kept so that the signature stays the same
/// as when this function ran the migration chain of earlier formats.
///
/// # Errors
///
/// Returns an error, and creates, changes or removes nothing in either
/// directory, if:
///
/// * a directory that is not fresh has no `VERSION` file that can be read and
///   parsed;
/// * the two directories record different markers, or one records a marker
///   within `COMPATIBLE_VERSION_REQ` other than `DATABASE_FORMAT_VERSION` and
///   the other is fresh ("mismatched database version");
/// * a recorded marker is outside `COMPATIBLE_VERSION_REQ`, such as that of
///   0.62 or an earlier format, or a prerelease ("database format ... is not
///   supported").
///
/// Returns an error if a fresh directory cannot be initialized.
pub fn migrate_data_dir<P: AsRef<Path>>(
    data_dir: P,
    backup_dir: P,
    _ip2location: Option<Arc<ip2location::DB>>,
) -> Result<()> {
    let data_dir = data_dir.as_ref();
    let backup_dir = backup_dir.as_ref();

    let Ok(compatible) = VersionReq::parse(COMPATIBLE_VERSION_REQ) else {
        unreachable!("COMPATIBLE_VERSION_REQ must be valid")
    };
    let current = Version::parse(DATABASE_FORMAT_VERSION)?;

    let data = inspect_version_dir(data_dir)?;
    let backup = inspect_version_dir(backup_dir)?;

    let mismatched = |data_ver: &Version, backup_ver: &Version| {
        anyhow!("mismatched database version {data_ver} and backup version {backup_ver}")
    };
    let unsupported = |version: &Version| {
        anyhow!(
            "database format {version} is not supported: this build opens only format \
             {COMPATIBLE_VERSION_REQ}, which is installed fresh and not migrated to"
        )
    };

    match (data, backup) {
        (DirState::Fresh, DirState::Fresh) => {
            initialize_version_dir(data_dir)?;
            initialize_version_dir(backup_dir)
        }
        (DirState::Marked(data_ver), DirState::Marked(backup_ver)) => {
            if data_ver != backup_ver {
                Err(mismatched(&data_ver, &backup_ver))
            } else if compatible.matches(&data_ver) {
                Ok(())
            } else {
                Err(unsupported(&data_ver))
            }
        }
        // A fresh side is reported as the marker it would have been given.
        (DirState::Marked(data_ver), DirState::Fresh) => {
            if data_ver == current {
                initialize_version_dir(backup_dir)
            } else if compatible.matches(&data_ver) {
                Err(mismatched(&data_ver, &current))
            } else {
                Err(unsupported(&data_ver))
            }
        }
        (DirState::Fresh, DirState::Marked(backup_ver)) => {
            if backup_ver == current {
                initialize_version_dir(data_dir)
            } else if compatible.matches(&backup_ver) {
                Err(mismatched(&current, &backup_ver))
            } else {
                Err(unsupported(&backup_ver))
            }
        }
    }
}

/// Returns the state of the data or backup directory at `path`, reading it
/// without creating or changing anything.
///
/// # Errors
///
/// Returns an error if the directory exists but cannot be listed, or if it is
/// not fresh and its VERSION file cannot be read or parsed.
fn inspect_version_dir(path: &Path) -> Result<DirState> {
    if !path.exists() {
        return Ok(DirState::Fresh);
    }

    // A temporary left behind by an interrupted write must not make an
    // otherwise empty directory look populated, or VERSION would never be
    // created here and the read below would fail on a fresh data directory.
    // Only that one name is forgiven: a directory holding anything else but
    // no VERSION stays an error, since creating one would stamp the current
    // version onto an existing tree of unknown format.
    let tmp = path.join(VERSION_TMP_FILE_NAME);
    let populated = path
        .read_dir()
        .context("cannot read data dir")?
        .any(|entry| match entry {
            Ok(entry) => entry.path() != tmp,
            Err(_) => true,
        });
    if !populated {
        return Ok(DirState::Fresh);
    }

    read_version_file(&path.join(VERSION_FILE_NAME)).map(DirState::Marked)
}

/// Initializes the fresh directory at `path` with the current format marker,
/// creating the directory, with any missing parent, if it is missing.
///
/// # Errors
///
/// Returns an error if the directory cannot be created or VERSION cannot be
/// written.
fn initialize_version_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        create_dir_all(path)?;
    }
    info!(
        "Initializing {} with database format {DATABASE_FORMAT_VERSION}",
        path.display()
    );
    create_version_file(&path.join(VERSION_FILE_NAME), DATABASE_FORMAT_VERSION)
}

/// Writes `version` to the VERSION file at `path`, creating it if it does not
/// exist.
///
/// The file is replaced rather than rewritten: the version goes to a
/// temporary in the same directory and is renamed over VERSION, so an
/// interrupted write cannot leave VERSION empty or partial.
///
/// `version` is written verbatim, so every caller passes a string it has
/// already validated: `DATABASE_FORMAT_VERSION` from [`migrate_data_dir`], and
/// the canonical form of a parsed [`Version`] from [`write_version_markers`].
///
/// # Errors
///
/// Returns an error if the temporary file cannot be created, written, or
/// flushed, if it cannot be renamed over the VERSION file, or if the
/// containing directory cannot be flushed.
fn create_version_file(path: &Path, version: &str) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(VERSION_TMP_FILE_NAME);

    // No mode is requested here. `rename` installs this inode at the
    // destination, so the temporary's mode becomes VERSION's, and
    // `File::create` asks for `0o666` and lets the umask narrow it — which is
    // what VERSION has had all along. It records a format version, not a
    // secret, so there is nothing to tighten.
    let mut f = File::create(&tmp).context("cannot create temporary VERSION")?;
    f.write_all(version.as_bytes())
        .context("cannot write temporary VERSION")?;

    // Flush before the rename. The next start reads VERSION back to decide
    // whether the directory may be opened, so a rename reaching disk ahead of
    // these bytes would leave a version that cannot be parsed and a database
    // that will not open.
    f.sync_all().context("cannot flush temporary VERSION")?;
    drop(f);

    if let Err(rename_err) = rename(&tmp, path) {
        // Leave nothing behind that would make an empty data directory look
        // populated to `inspect_version_dir`.
        return match remove_file(&tmp) {
            Ok(()) => Err(rename_err).context("cannot replace VERSION"),
            Err(remove_err) => {
                Err(remove_err).context("cannot remove temporary VERSION after a failed rename")
            }
        };
    }

    // Flush the directory as well: the rename is what makes the new version
    // visible, and until that directory entry is on disk a power loss can
    // still lose it, leaving the directory recorded as the version it held
    // before the write.
    File::open(dir)
        .and_then(|dir| dir.sync_all())
        .context("cannot flush the directory holding VERSION")?;

    Ok(())
}

/// Reads the VERSION file in the data directory and returns its contents.
///
/// # Errors
///
/// Returns an error if the VERSION file cannot be read or parsed.
fn read_version_file(path: &Path) -> Result<Version> {
    let mut ver = String::new();
    File::open(path)
        .context("cannot open VERSION")?
        .read_to_string(&mut ver)
        .context("cannot read VERSION")?;
    Version::parse(&ver).context("cannot parse VERSION")
}

/// Records `version` as the database format version of both `data_dir` and
/// `backup_dir`.
///
/// This is the metadata companion to restoring a rollback snapshot. A
/// snapshot covers `data_dir/states.db` only, while the format version lives
/// beside it in the two `VERSION` files, so restoring the snapshot taken
/// before an update puts the older database back under markers that still
/// name the newer format, which the earlier binary does not accept. After restoring the snapshot, the caller
/// passes the format version it recorded before the update — the
/// `pre_update_version` of the operation attempt — and both markers again
/// describe the restored contents.
///
/// `version` is parsed as a [`semver::Version`] before anything is written,
/// and it is the parsed value's canonical `to_string()` form that reaches each
/// file, with no trailing bytes. Validation is syntactic only: this function
/// does not read `states.db`, does not read the markers it replaces, and does
/// not judge whether any binary accepts `version`. Choosing a version the
/// rollback binary supports remains the caller's responsibility.
///
/// A missing directory, and any missing component of its path, is created.
/// Each marker is replaced through the same write-to-a-temporary, sync,
/// rename, and directory-sync path [`migrate_data_dir`] uses, so an interruption cannot
/// leave a marker empty or partially written. The two files can live on
/// different filesystems, so there is no cross-directory atomic commit: a
/// failure on the second leaves the first already updated. The operation is
/// idempotent — correct the filesystem failure and call it again with the same
/// paths and version, and both markers end up canonical and equal.
///
/// `VERSION.tmp`, the temporary each replacement goes through, is a fixed name,
/// so the caller must serialize this call against [`migrate_data_dir`] and
/// against any other marker write for each directory involved.
///
/// # Errors
///
/// Returns an error if `version` is not a complete semantic version, if either
/// directory is missing and cannot be created, or if either marker cannot be
/// written, renamed into place, or flushed. The error identifies which of the
/// two directories the failing operation belonged to.
pub fn write_version_markers<P: AsRef<Path>, Q: AsRef<Path>>(
    data_dir: P,
    backup_dir: Q,
    version: &str,
) -> Result<()> {
    let parsed = Version::parse(version)
        .with_context(|| format!("cannot parse the requested format version {version}"))?;
    let canonical = parsed.to_string();

    let data_dir = data_dir.as_ref();
    let backup_dir = backup_dir.as_ref();

    write_version_marker(data_dir, &canonical).with_context(|| {
        format!(
            "cannot write the data directory VERSION in {}",
            data_dir.display()
        )
    })?;
    write_version_marker(backup_dir, &canonical).with_context(|| {
        format!(
            "cannot write the backup directory VERSION in {}",
            backup_dir.display()
        )
    })
}

/// Creates `dir` if it is missing and replaces the VERSION file in it with
/// `version`.
///
/// # Errors
///
/// Returns an error if `dir` cannot be created or if the marker cannot be
/// replaced.
fn write_version_marker(dir: &Path, version: &str) -> Result<()> {
    create_dir_all(dir).context("cannot create the directory")?;
    create_version_file(&dir.join(VERSION_FILE_NAME), version)
}

#[cfg(test)]
mod tests {
    use std::{
        io::Write,
        path::{Path, PathBuf},
    };

    use semver::{Version, VersionReq};

    use super::{
        COMPATIBLE_VERSION_REQ, DATABASE_FORMAT_VERSION, DirState, VERSION_FILE_NAME,
        VERSION_TMP_FILE_NAME, create_version_file, inspect_version_dir, migrate_data_dir,
        read_version_file, write_version_markers,
    };

    /// The leftover of an interrupted marker write the fresh cases carry.
    const STALE_TMP: &[u8] = b"0.6";

    /// Helper to write a specific version to a VERSION file.
    fn write_version(path: &Path, version: &str) {
        let version_file = path.join(VERSION_FILE_NAME);
        let mut f = std::fs::File::create(&version_file).unwrap();
        f.write_all(version.as_bytes()).unwrap();
    }

    /// The ways a directory can be fresh.
    #[derive(Clone, Copy, Debug)]
    enum Fresh {
        Empty,
        Missing,
        TmpOnly,
    }

    const FRESH_KINDS: [Fresh; 3] = [Fresh::Empty, Fresh::Missing, Fresh::TmpOnly];

    /// The state a test puts one side of the pair in.
    #[derive(Clone, Copy, Debug)]
    enum Side {
        Fresh(Fresh),
        Marked(&'static str),
        /// A directory holding a file other than VERSION and no VERSION.
        PopulatedWithoutVersion,
        /// A directory whose VERSION does not parse.
        UnparsableVersion,
    }

    /// Puts the directory at `path`, which does not exist yet, in `side`.
    fn prepare(path: &Path, side: Side) {
        match side {
            Side::Fresh(Fresh::Missing) => {}
            Side::Fresh(Fresh::Empty) => std::fs::create_dir(path).unwrap(),
            Side::Fresh(Fresh::TmpOnly) => {
                std::fs::create_dir(path).unwrap();
                std::fs::write(path.join(VERSION_TMP_FILE_NAME), STALE_TMP).unwrap();
            }
            Side::Marked(version) => {
                std::fs::create_dir(path).unwrap();
                write_version(path, version);
            }
            Side::PopulatedWithoutVersion => {
                std::fs::create_dir(path).unwrap();
                std::fs::write(path.join("states.db"), b"not a version file").unwrap();
            }
            Side::UnparsableVersion => {
                std::fs::create_dir(path).unwrap();
                write_version(path, "not-a-valid-version");
            }
        }
    }

    /// A data and a backup directory under one temporary root, so that a
    /// snapshot of the root covers a directory that is missing too.
    struct Pair {
        root: tempfile::TempDir,
    }

    impl Pair {
        fn new(data: Side, backup: Side) -> Self {
            let pair = Self {
                root: tempfile::tempdir().unwrap(),
            };
            prepare(&pair.data(), data);
            prepare(&pair.backup(), backup);
            pair
        }

        fn data(&self) -> PathBuf {
            self.root.path().join("data")
        }

        fn backup(&self) -> PathBuf {
            self.root.path().join("backup")
        }

        fn migrate(&self) -> anyhow::Result<()> {
            migrate_data_dir(self.data(), self.backup(), None)
        }

        /// Every directory and file under the root, with each file's contents.
        fn snapshot(&self) -> Vec<(PathBuf, Option<Vec<u8>>)> {
            fn walk(root: &Path, dir: &Path, out: &mut Vec<(PathBuf, Option<Vec<u8>>)>) {
                for entry in std::fs::read_dir(dir).unwrap() {
                    let path = entry.unwrap().path();
                    let relative = path.strip_prefix(root).unwrap().to_path_buf();
                    if path.is_dir() {
                        out.push((relative, None));
                        walk(root, &path, out);
                    } else {
                        out.push((relative, Some(std::fs::read(&path).unwrap())));
                    }
                }
            }

            let mut out = Vec::new();
            walk(self.root.path(), self.root.path(), &mut out);
            out.sort_unstable();
            out
        }
    }

    fn marker(dir: &Path) -> String {
        std::fs::read_to_string(dir.join(VERSION_FILE_NAME)).unwrap()
    }

    /// Asserts that the pair is refused with an error containing `expected`
    /// and that nothing under either directory changed.
    fn assert_rejected(data: Side, backup: Side, expected: &str) {
        let pair = Pair::new(data, backup);
        let before = pair.snapshot();

        let err = format!("{:#}", pair.migrate().unwrap_err());

        assert!(
            err.contains(expected),
            "data {data:?}, backup {backup:?}: expected an error containing {expected:?}, got \
             {err:?}"
        );
        assert_eq!(
            pair.snapshot(),
            before,
            "data {data:?}, backup {backup:?}: a refused pair must be left as it was"
        );
    }

    fn unsupported(version: &str) -> String {
        format!("database format {version} is not supported")
    }

    fn mismatched(data: &str, backup: &str) -> String {
        format!("mismatched database version {data} and backup version {backup}")
    }

    #[test]
    fn format_marker_is_the_fresh_install_format() {
        assert_eq!(DATABASE_FORMAT_VERSION, "0.63.0");
        assert_eq!(COMPATIBLE_VERSION_REQ, ">=0.63.0,<0.64.0");
        let compatible = VersionReq::parse(COMPATIBLE_VERSION_REQ).unwrap();
        assert!(compatible.matches(&Version::parse(DATABASE_FORMAT_VERSION).unwrap()));
    }

    /// Both sides fresh, in every combination of the ways a side can be fresh,
    /// are initialized with the current marker and then reopen unchanged.
    #[test]
    fn fresh_pairs_are_initialized_and_reopen() {
        for data in FRESH_KINDS {
            for backup in FRESH_KINDS {
                let pair = Pair::new(Side::Fresh(data), Side::Fresh(backup));

                pair.migrate().unwrap();

                for dir in [pair.data(), pair.backup()] {
                    assert_eq!(
                        marker(&dir),
                        DATABASE_FORMAT_VERSION,
                        "{data:?}, {backup:?}"
                    );
                    assert!(!dir.join(VERSION_TMP_FILE_NAME).exists());
                }
                let initialized = pair.snapshot();
                assert_eq!(initialized.len(), 4, "only the two directories and markers");

                pair.migrate().unwrap();
                assert_eq!(pair.snapshot(), initialized);
            }
        }
    }

    /// Both sides holding the current marker open, and nothing is written.
    #[test]
    fn current_markers_open_unchanged() {
        let pair = Pair::new(
            Side::Marked(DATABASE_FORMAT_VERSION),
            Side::Marked(DATABASE_FORMAT_VERSION),
        );
        let before = pair.snapshot();

        pair.migrate().unwrap();

        assert_eq!(pair.snapshot(), before);
    }

    /// One side holding the current marker opens with a fresh counterpart,
    /// which alone is initialized, on each side in turn.
    #[test]
    fn current_marker_initializes_a_fresh_counterpart() {
        for fresh in FRESH_KINDS {
            for marked_is_data in [true, false] {
                let (data, backup) = if marked_is_data {
                    (Side::Marked(DATABASE_FORMAT_VERSION), Side::Fresh(fresh))
                } else {
                    (Side::Fresh(fresh), Side::Marked(DATABASE_FORMAT_VERSION))
                };
                let pair = Pair::new(data, backup);
                let (marked_dir, fresh_dir) = if marked_is_data {
                    (pair.data(), pair.backup())
                } else {
                    (pair.backup(), pair.data())
                };
                let marked_before = std::fs::read(marked_dir.join(VERSION_FILE_NAME)).unwrap();

                pair.migrate().unwrap();

                assert_eq!(
                    marker(&fresh_dir),
                    DATABASE_FORMAT_VERSION,
                    "{data:?}, {backup:?}"
                );
                assert!(!fresh_dir.join(VERSION_TMP_FILE_NAME).exists());
                assert_eq!(
                    std::fs::read(marked_dir.join(VERSION_FILE_NAME)).unwrap(),
                    marked_before
                );
                assert_eq!(
                    pair.snapshot().len(),
                    4,
                    "only the two directories and markers"
                );
            }
        }
    }

    /// Markers of 0.62 and earlier formats, and prereleases, are refused as an
    /// unsupported format on both sides alike, and nothing is changed.
    #[test]
    fn older_and_prerelease_markers_are_refused() {
        for version in [
            "0.30.0",
            "0.61.0",
            "0.62.0",
            "0.62.1",
            "0.63.0-alpha.1",
            "0.64.0",
        ] {
            assert_rejected(
                Side::Marked(version),
                Side::Marked(version),
                &unsupported(version),
            );
        }
    }

    /// A 0.62 marker on one side is refused with a fresh counterpart, which
    /// gets no VERSION and keeps any leftover VERSION.tmp, on each side in
    /// turn.
    #[test]
    fn older_marker_with_a_fresh_counterpart_is_refused() {
        for fresh in FRESH_KINDS {
            assert_rejected(
                Side::Marked("0.62.0"),
                Side::Fresh(fresh),
                &unsupported("0.62.0"),
            );
            assert_rejected(
                Side::Fresh(fresh),
                Side::Marked("0.62.0"),
                &unsupported("0.62.0"),
            );
        }
    }

    /// Two differing markers are a mismatch, whether both are in range or
    /// not, in either order.
    #[test]
    fn differing_markers_are_refused() {
        for (data, backup) in [
            ("0.63.0", "0.63.1"),
            ("0.63.1", "0.63.0"),
            ("0.62.0", "0.63.0"),
            ("0.63.0", "0.62.0"),
            ("0.61.0", "0.62.0"),
        ] {
            assert_rejected(
                Side::Marked(data),
                Side::Marked(backup),
                &mismatched(data, backup),
            );
        }
    }

    /// An in-range marker other than the current one is a mismatch with a
    /// fresh counterpart, on each side in turn.
    #[test]
    fn other_in_range_marker_with_a_fresh_counterpart_is_refused() {
        for fresh in FRESH_KINDS {
            assert_rejected(
                Side::Marked("0.63.1"),
                Side::Fresh(fresh),
                &mismatched("0.63.1", DATABASE_FORMAT_VERSION),
            );
            assert_rejected(
                Side::Fresh(fresh),
                Side::Marked("0.63.1"),
                &mismatched(DATABASE_FORMAT_VERSION, "0.63.1"),
            );
        }
    }

    /// A populated directory without VERSION, or with one that does not
    /// parse, is a read error, and a fresh counterpart is left as it is, on
    /// each side in turn.
    #[test]
    fn unreadable_marker_is_refused() {
        for fresh in FRESH_KINDS {
            for (side, expected) in [
                (Side::PopulatedWithoutVersion, "cannot open VERSION"),
                (Side::UnparsableVersion, "cannot parse VERSION"),
            ] {
                assert_rejected(side, Side::Fresh(fresh), expected);
                assert_rejected(Side::Fresh(fresh), side, expected);
            }
        }
        assert_rejected(
            Side::PopulatedWithoutVersion,
            Side::Marked(DATABASE_FORMAT_VERSION),
            "cannot open VERSION",
        );
        assert_rejected(
            Side::Marked(DATABASE_FORMAT_VERSION),
            Side::UnparsableVersion,
            "cannot parse VERSION",
        );
    }

    /// Inspecting a directory tells the fresh states from a marked one and
    /// creates nothing.
    #[test]
    fn inspection_creates_nothing() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing");
        assert_eq!(inspect_version_dir(&missing).unwrap(), DirState::Fresh);
        assert!(!missing.exists());

        let tmp_only = root.path().join("tmp_only");
        prepare(&tmp_only, Side::Fresh(Fresh::TmpOnly));
        assert_eq!(inspect_version_dir(&tmp_only).unwrap(), DirState::Fresh);
        assert!(!tmp_only.join(VERSION_FILE_NAME).exists());
        assert_eq!(
            std::fs::read(tmp_only.join(VERSION_TMP_FILE_NAME)).unwrap(),
            STALE_TMP
        );

        let marked = root.path().join("marked");
        prepare(&marked, Side::Marked("0.62.0"));
        assert_eq!(
            inspect_version_dir(&marked).unwrap(),
            DirState::Marked(Version::parse("0.62.0").unwrap())
        );
    }

    /// Test `read_version_file` and `create_version_file` helper functions.
    #[test]
    fn version_file_helpers() {
        let temp = tempfile::tempdir().unwrap();
        let version_path = temp.path().join(VERSION_FILE_NAME);

        create_version_file(&version_path, DATABASE_FORMAT_VERSION).unwrap();

        let version = read_version_file(&version_path).unwrap();
        assert_eq!(version, Version::parse(DATABASE_FORMAT_VERSION).unwrap());
    }

    /// Test that writing over an existing `VERSION` leaves the current version
    /// readable and no temporary behind.
    ///
    /// The ordering the flushes in `create_version_file` buy cannot be
    /// observed without fault injection, so this covers the states a test can
    /// reach: the replacement itself, and the directory it leaves.
    #[test]
    fn version_file_is_replaced() {
        let temp = tempfile::tempdir().unwrap();
        write_version(temp.path(), "0.62.0");
        let version_path = temp.path().join(VERSION_FILE_NAME);

        create_version_file(&version_path, DATABASE_FORMAT_VERSION).unwrap();

        assert_eq!(
            read_version_file(&version_path).unwrap(),
            Version::parse(DATABASE_FORMAT_VERSION).unwrap()
        );
        assert!(!temp.path().join(VERSION_TMP_FILE_NAME).exists());
    }

    /// Test that reading a non-existent `VERSION` file returns an error.
    #[test]
    fn read_nonexistent_version_file_error() {
        let temp = tempfile::tempdir().unwrap();
        let version_path = temp.path().join("NONEXISTENT_VERSION");

        let result = read_version_file(&version_path);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("cannot open VERSION"));
    }

    /// Test that the public marker writer puts the canonical form of the
    /// parsed version in both directories, byte for byte.
    #[test]
    fn write_version_markers_writes_canonical_markers() {
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        write_version_markers(data_dir.path(), backup_dir.path(), DATABASE_FORMAT_VERSION).unwrap();

        let expected = Version::parse(DATABASE_FORMAT_VERSION).unwrap().to_string();
        for dir in [data_dir.path(), backup_dir.path()] {
            assert_eq!(marker(dir), expected);
        }
    }

    /// Test that markers written through the public API for the current
    /// format are accepted by the next start without being rewritten.
    #[test]
    fn markers_written_for_the_current_format_open() {
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        write_version_markers(data_dir.path(), backup_dir.path(), DATABASE_FORMAT_VERSION).unwrap();

        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        for dir in [data_dir.path(), backup_dir.path()] {
            assert_eq!(marker(dir), DATABASE_FORMAT_VERSION);
        }
    }

    /// Test that missing marker directories, including intermediate
    /// components, are created and receive their markers.
    #[test]
    fn write_version_markers_creates_missing_directories() {
        let root = tempfile::tempdir().unwrap();
        let data_dir = root.path().join("restored").join("data");
        let backup_dir = root.path().join("restored").join("backup");

        write_version_markers(&data_dir, &backup_dir, DATABASE_FORMAT_VERSION).unwrap();

        for dir in [&data_dir, &backup_dir] {
            assert!(dir.is_dir());
            assert_eq!(marker(dir), DATABASE_FORMAT_VERSION);
        }
    }

    /// Test that an unparsable version is rejected before any filesystem
    /// change: no directory appears, and an existing marker keeps its
    /// contents.
    #[test]
    fn write_version_markers_rejects_invalid_versions() {
        for invalid in ["", "0.63", "not a version", "0.63.0 ", "0.63.0extra"] {
            let root = tempfile::tempdir().unwrap();
            let data_dir = root.path().join("data");
            let backup_dir = root.path().join("backup");

            assert!(
                write_version_markers(&data_dir, &backup_dir, invalid).is_err(),
                "{invalid:?} must be rejected"
            );
            assert!(
                !data_dir.exists(),
                "{invalid:?} must not create a directory"
            );
            assert!(
                !backup_dir.exists(),
                "{invalid:?} must not create a directory"
            );

            let existing_data = tempfile::tempdir().unwrap();
            let existing_backup = tempfile::tempdir().unwrap();
            write_version(existing_data.path(), DATABASE_FORMAT_VERSION);
            write_version(existing_backup.path(), DATABASE_FORMAT_VERSION);

            assert!(
                write_version_markers(existing_data.path(), existing_backup.path(), invalid)
                    .is_err(),
                "{invalid:?} must be rejected"
            );
            for dir in [existing_data.path(), existing_backup.path()] {
                assert_eq!(
                    marker(dir),
                    DATABASE_FORMAT_VERSION,
                    "{invalid:?} must leave the existing marker alone"
                );
                assert!(!dir.join(VERSION_TMP_FILE_NAME).exists());
            }
        }
    }

    /// Test that an existing marker is replaced rather than appended to, even
    /// when it names a newer format or was not stored canonically.
    #[test]
    fn write_version_markers_replaces_existing_markers() {
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        write_version(data_dir.path(), "0.63.1");
        write_version(backup_dir.path(), "0.63.1\n");

        write_version_markers(data_dir.path(), backup_dir.path(), DATABASE_FORMAT_VERSION).unwrap();

        for dir in [data_dir.path(), backup_dir.path()] {
            assert_eq!(marker(dir), DATABASE_FORMAT_VERSION);
            assert!(!dir.join(VERSION_TMP_FILE_NAME).exists());
        }
    }

    /// Test that a failure on the backup marker names the backup directory and
    /// that the same call, repeated after the failure is corrected, leaves both
    /// markers canonical and equal.
    #[test]
    fn write_version_markers_reports_the_failing_directory_and_retries() {
        let root = tempfile::tempdir().unwrap();
        let data_dir = root.path().join("data");
        let backup_dir = root.path().join("backup");
        std::fs::write(&backup_dir, b"a regular file, not a directory").unwrap();

        let err = write_version_markers(&data_dir, &backup_dir, DATABASE_FORMAT_VERSION)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("backup directory VERSION"),
            "the error must name the backup directory, got {err}"
        );

        std::fs::remove_file(&backup_dir).unwrap();
        write_version_markers(&data_dir, &backup_dir, DATABASE_FORMAT_VERSION).unwrap();

        let data_marker = marker(&data_dir);
        assert_eq!(
            data_marker,
            Version::parse(DATABASE_FORMAT_VERSION).unwrap().to_string()
        );
        assert_eq!(data_marker, marker(&backup_dir));
    }

    /// Test that a failure on the data marker names the data directory and
    /// stops before the backup one, so the pair is never left describing two
    /// different formats.
    #[test]
    fn write_version_markers_reports_a_failing_data_directory() {
        let root = tempfile::tempdir().unwrap();
        let data_dir = root.path().join("data");
        std::fs::write(&data_dir, b"a regular file, not a directory").unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        write_version(backup_dir.path(), "0.63.1");

        let err = write_version_markers(&data_dir, backup_dir.path(), DATABASE_FORMAT_VERSION)
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("data directory VERSION"),
            "the error must name the data directory, got {err}"
        );
        assert_eq!(
            marker(backup_dir.path()),
            "0.63.1",
            "the backup marker must be left alone"
        );
        assert!(!backup_dir.path().join(VERSION_TMP_FILE_NAME).exists());
    }
}
