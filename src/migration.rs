//! Routines to check the database format version of a data directory and its
//! backup directory.
use std::{
    fs::{
        File, OpenOptions, canonicalize, create_dir_all, metadata, remove_dir, remove_file, rename,
        symlink_metadata,
    },
    io::{ErrorKind, Read, Write},
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, anyhow};
use semver::{Version, VersionReq};

/// The database format marker written to `VERSION`.
///
/// It names the current database format and is independent of the crate
/// package version: a release does not move it.
///
/// The marker is raised to 0.63.0 once, for a format deployed by a fresh
/// install only. No data directory or backup of format 0.62 or earlier is
/// migrated to it: [`migrate_data_dir`] refuses their markers, and the online
/// restore refuses their backups. The format changes that follow in the same
/// series (the new detection-event storage, the configuration history and the
/// tables related to them) keep this marker at `"0.63.0"` and
/// [`COMPATIBLE_VERSION_REQ`] as it is, and add no migration step.
///
/// The online restore (`StateDb::restore_from_backup`) recognizes a backup in
/// this format by its column families, which must be exactly `MAP_NAMES`. The
/// empty `format 0.63` family is in that set so that the comparison refuses
/// every backup taken before 0.63, including a 0.60 one, whose families would
/// otherwise be exactly the current set.
pub(crate) const DATABASE_FORMAT_VERSION: &str = "0.63.0";

/// The range of format markers that use the current database format.
///
/// The versions here are database format markers, independent of the crate
/// version. The range is set once, together with [`DATABASE_FORMAT_VERSION`],
/// when the marker is raised to 0.63.0 for a fresh-install format with no
/// migration from any earlier format. Later format changes in the same series
/// leave both constants as they are and add no migration step to
/// [`migrate_data_dir`]. No build writes a marker in this range other than
/// [`DATABASE_FORMAT_VERSION`], and no build writes a prerelease marker.
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
/// file, which the next start recognizes, unless it interrupts the recovery
/// from such a leftover; see [`VERSION_BESIDE_LEFTOVER_FILE_NAME`].
const VERSION_TMP_FILE_NAME: &str = "VERSION.tmp";

/// The name of the temporary that `migrate_data_dir` renames over
/// [`VERSION_FILE_NAME`] in a fresh directory that holds a leftover
/// [`VERSION_TMP_FILE_NAME`].
///
/// The leftover is left where it is until every marker of the pair is
/// written, so that a failed initialization finds it as it was: the same
/// directory entry, inode, links, bytes and mode, none of which can be put
/// back once it has been removed. The marker therefore needs another name.
/// The next start does not forgive this one, so an interruption between its
/// creation and its rename, which needs a crash during the recovery from an
/// earlier one, leaves a directory that is refused with the VERSION read
/// error until the two files are removed, rather than one stamped with a
/// format nothing checked.
const VERSION_BESIDE_LEFTOVER_FILE_NAME: &str = "VERSION.new";

/// Checks the database format of the data and backup directories, and records
/// the current format in a fresh one.
///
/// The versions this function reads, compares and writes are database format
/// markers, independent of the crate version: `DATABASE_FORMAT_VERSION`
/// names the current format, and the format is deployed by a fresh install
/// only, so no earlier format is migrated.
///
/// A directory is *fresh* when it is missing, empty, or holds nothing but a
/// `VERSION.tmp` left behind by an interrupted marker write, which is a regular
/// file; a subdirectory or a symbolic link of that name makes the directory
/// populated. A path that cannot be listed because a dangling symbolic link
/// stands at it or at one of its ancestors is not missing, since no directory
/// can be created through that link, and neither is one with a `..` after a
/// missing component, since creating that component would make it name
/// another directory. The pair is accepted when
///
/// * both directories are fresh: each is created if missing and given a
///   `VERSION` naming `DATABASE_FORMAT_VERSION`;
/// * both hold the same marker within `COMPATIBLE_VERSION_REQ`: nothing is
///   written;
/// * one holds exactly `DATABASE_FORMAT_VERSION` and the other is fresh: the
///   fresh one is given that marker.
///
/// Every other pair is refused, and neither directory is created, modified or
/// removed: a fresh directory gets no `VERSION`, a leftover `VERSION.tmp`
/// stays, and a missing directory stays missing. Both directories are read
/// before either is written for that reason. Two fresh directories that
/// overlap, where one is at or below the other's `VERSION`, its `VERSION.tmp`
/// or, beside a leftover, its `VERSION.new`, are told apart only by creating them, so the directories created for such
/// a pair are removed again before it is refused, and no marker is written.
/// The directory they were created in, such as an empty `store` beside
/// `store/VERSION`, keeps its contents but not its modification and status
/// change times, which creating and removing an entry in it updates.
///
/// `ip2location` is kept in the signature for callers, but no earlier format is
/// migrated, so it is unused.
///
/// # Errors
///
/// Returns an error, writing nothing, if
///
/// * the two directories hold different markers, or one holds a marker within
///   `COMPATIBLE_VERSION_REQ` other than `DATABASE_FORMAT_VERSION` and the
///   other is fresh: "mismatched database version {data} and backup version
///   {backup}", where a fresh side counts as `DATABASE_FORMAT_VERSION`;
/// * a marker outside `COMPATIBLE_VERSION_REQ`, prereleases included, is held
///   by both directories alike or by one with a fresh counterpart: "database
///   format {version} is not supported";
/// * a directory that is not fresh has no `VERSION` that can be read and
///   parsed, or a directory cannot be listed;
/// * a directory cannot be listed and is not missing either, such as a
///   dangling symbolic link, or a path whose nearest existing ancestor is not a
///   directory;
/// * a missing directory's path has a `..` after a missing component, such as
///   `missing/../old`, which would name a different directory once `missing`
///   was created;
/// * a directory path is empty, which names no directory;
/// * both directories are fresh and one is at or below the other's
///   `VERSION`, its `VERSION.tmp` or, where it holds a leftover `VERSION.tmp`,
///   its `VERSION.new` as the file system resolves names, such as `store`
///   beside `store/VERSION`, or `État` beside `état/VERSION` where the file
///   system folds case, so that writing one marker would stop the other from
///   being written;
/// * one directory is fresh and its leftover `VERSION.tmp` is the file the
///   other's `VERSION` is, through a symbolic or a hard link, so that
///   initializing the fresh one would take the other's marker away.
///
/// Returns an error if a fresh directory cannot be created or its `VERSION`
/// cannot be written. What the call created or wrote in either directory up
/// to then is undone first: each `VERSION` and temporary written is removed,
/// and a directory that was missing is removed again. A leftover `VERSION.tmp`
/// is never touched before both markers are written, and is removed only
/// then, so it is still there as it was, the same file with the same links.
/// As for a refused pair, only the modification and status change times of
/// the directories involved record the attempt. The error names the undo as
/// well if it fails too. A leftover that cannot be removed once both markers
/// are written is reported too, with the markers kept.
pub fn migrate_data_dir<P: AsRef<Path>>(
    data_dir: P,
    backup_dir: P,
    ip2location: Option<Arc<ip2location::DB>>,
) -> Result<()> {
    // The format is deployed by a fresh install only, so there is no step to
    // hand the database to and nothing for the resolver to serve.
    drop(ip2location);

    let data_dir = data_dir.as_ref();
    let backup_dir = backup_dir.as_ref();

    let Ok(compatible) = VersionReq::parse(COMPATIBLE_VERSION_REQ) else {
        unreachable!("COMPATIBLE_VERSION_REQ must be valid")
    };
    let current = Version::parse(DATABASE_FORMAT_VERSION)?;

    // Both sides are read before either is written, so a refused pair is left
    // exactly as it was found.
    let data_ver = read_marker(data_dir)?;
    let backup_ver = read_marker(backup_dir)?;

    match (data_ver, backup_ver) {
        (None, None) => initialize_fresh_dirs(&[data_dir, backup_dir]),
        (Some(data_ver), None) => {
            check_marker_beside_fresh(&data_ver, &current, &compatible, true)?;
            check_leftover_is_not_the_marker(backup_dir, data_dir)?;
            initialize_fresh_dirs(&[backup_dir])
        }
        (None, Some(backup_ver)) => {
            check_marker_beside_fresh(&backup_ver, &current, &compatible, false)?;
            check_leftover_is_not_the_marker(data_dir, backup_dir)?;
            initialize_fresh_dirs(&[data_dir])
        }
        (Some(data_ver), Some(backup_ver)) => {
            if data_ver != backup_ver {
                Err(mismatched(&data_ver, &backup_ver))
            } else if compatible.matches(&data_ver) {
                Ok(())
            } else {
                Err(unsupported(&data_ver))
            }
        }
    }
}

/// Creates the fresh directories `dirs` and gives each a `VERSION` naming
/// `DATABASE_FORMAT_VERSION`, or, if any step fails, undoes what the call did.
///
/// Every directory in `dirs` was read as fresh, so none holds a `VERSION`, and
/// a `VERSION` found in one after a failed step was written by this call. A
/// leftover `VERSION.tmp` is not touched while the markers are written: each
/// marker goes through a temporary of its own, `VERSION.tmp` where there is no
/// leftover and [`VERSION_BESIDE_LEFTOVER_FILE_NAME`] beside one, and the
/// leftovers are removed only once every marker is in place. A leftover is
/// therefore never read, so one that cannot be read does not stop the
/// initialization, and a failed one finds it with the directory entry, inode,
/// links, bytes and mode it had.
///
/// On failure each directory a write was attempted in loses that `VERSION`
/// and the temporary the write went through, and then the directories created
/// here are removed, deepest first. A directory that is read-only, or a disk
/// that is full, therefore stops the initialization without leaving one side
/// marked and the other not, or a missing directory created.
///
/// # Errors
///
/// Returns an error if a directory cannot be created or inspected, if two
/// directories overlap, if a marker cannot be written, or if what was written
/// cannot be undone, in which case the error names both failures. Returns an
/// error as well if a leftover cannot be removed once every marker is
/// written; the markers are kept then, since they are complete, and the pair
/// opens on the next start.
fn initialize_fresh_dirs(dirs: &[&Path]) -> Result<()> {
    let mut created = Vec::new();
    let mut temporaries = Vec::with_capacity(dirs.len());
    for dir in dirs {
        created.extend(missing_ancestors(dir)?);
        temporaries.push(if has_leftover(dir)? {
            VERSION_BESIDE_LEFTOVER_FILE_NAME
        } else {
            VERSION_TMP_FILE_NAME
        });
    }

    let mut attempted = 0;
    let result = create_fresh_dirs(dirs, &temporaries).and_then(|()| {
        for (dir, temporary) in dirs.iter().zip(&temporaries) {
            attempted += 1;
            write_version_marker(dir, DATABASE_FORMAT_VERSION, Temporary::Create(temporary))
                .context("failed to create VERSION")?;
        }
        Ok(())
    });
    let Err(e) = result else {
        for (dir, temporary) in dirs.iter().zip(&temporaries) {
            if *temporary == VERSION_BESIDE_LEFTOVER_FILE_NAME {
                let tmp = dir.join(VERSION_TMP_FILE_NAME);
                remove_if_present(&tmp).with_context(|| {
                    format!(
                        "the data dirs are initialized, but {} cannot be removed",
                        tmp.display()
                    )
                })?;
            }
        }
        return Ok(());
    };

    let undo_failed = |path: &Path, undo_err: anyhow::Error| {
        undo_err.context(format!(
            "cannot restore {} after the data dirs could not be initialized: {e:#}",
            path.display()
        ))
    };
    // Only the directories a write was attempted in are touched: before the
    // first write, the overlap check may have failed because a name the
    // markers are written under in one directory is another directory.
    for (dir, temporary) in dirs.iter().zip(&temporaries).take(attempted) {
        for name in [VERSION_FILE_NAME, *temporary] {
            let path = dir.join(name);
            remove_if_present(&path).map_err(|undo_err| undo_failed(&path, undo_err))?;
        }
    }
    for path in &removal_order(created) {
        match remove_dir(path) {
            Ok(()) => {}
            Err(remove_err) if remove_err.kind() == ErrorKind::NotFound => {}
            Err(remove_err) => {
                return Err(undo_failed(path, remove_err.into()));
            }
        }
    }
    Err(e)
}

/// Removes the file at `path` if there is one.
///
/// # Errors
///
/// Returns an error if a file is there and cannot be removed.
fn remove_if_present(path: &Path) -> Result<()> {
    match remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).context("cannot remove the file"),
    }
}

/// Tells whether the fresh directory `dir` holds a leftover `VERSION.tmp`.
///
/// Only the directory entry is inspected: the leftover is never opened, so
/// one whose mode forbids reading it is found all the same.
///
/// # Errors
///
/// Returns an error if the leftover cannot be inspected.
fn has_leftover(dir: &Path) -> Result<bool> {
    let tmp = dir.join(VERSION_TMP_FILE_NAME);
    match symlink_metadata(&tmp) {
        Ok(_) => Ok(true),
        Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => Ok(false),
        Err(e) => Err(e).with_context(|| format!("cannot inspect {}", tmp.display())),
    }
}

/// Creates the fresh directories `dirs`, then checks that no creation stopped
/// another directory's marker from being written.
///
/// Each read sees its directory as it is before anything is written, yet the
/// writes run in turn. A directory at or below another's `VERSION`, or the
/// temporary its marker is written through, such as `store` beside
/// `store/VERSION`, is fresh while both are missing, but the first write puts
/// a file or a directory where the second needs the other, so the second
/// would fail with the first marker already in place. `temporaries` holds
/// that name for each directory of `dirs`.
///
/// Whether two paths name the same directory depends on the file system that
/// holds them: one that folds case, or Unicode normalization, makes `État`
/// and `état/VERSION` overlap, while a case-sensitive one keeps `store` and
/// `store/version` apart. No comparison of names can follow every such rule,
/// so the file system is asked instead. The directories are created, and two
/// of them overlap exactly when that puts something at either one's
/// `VERSION` or [`VERSION_BESIDE_LEFTOVER_FILE_NAME`], or anything but the
/// leftover regular file at its `VERSION.tmp`: before the creation, each
/// fresh directory had none of them. The caller,
/// [`initialize_fresh_dirs`], removes the directories created here again,
/// deepest first, before an overlapping pair is refused, so its contents are
/// left as they were found and no marker is written. The directory the
/// outermost of them was created in keeps its entries, but its modification
/// and status change times record the creation and the removal: no write to a
/// directory leaves them as they were, and the status change time cannot be
/// set back.
///
/// # Errors
///
/// Returns an error if two directories overlap, or if one cannot be created or
/// inspected.
fn create_fresh_dirs(dirs: &[&Path], temporaries: &[&str]) -> Result<()> {
    for dir in dirs {
        create_dir_all(dir).context("cannot create data dir")?;
    }
    for (i, (dir, temporary)) in dirs.iter().zip(temporaries).enumerate() {
        for (j, other) in dirs.iter().enumerate() {
            if i != j {
                check_marker_names_are_free(dir, temporary, other)?;
            }
        }
    }
    Ok(())
}

/// Returns the directories in `created` in an order that removes each one
/// before the directory holding it.
///
/// The paths as given cannot be ordered by their depth: a symbolic link can
/// make a directory's path longer than that of a directory inside it, as with
/// `a/b/c/alias/store` beside `store/VERSION` where `a/b/c/alias` links to
/// the directory holding `store`. Each path is therefore resolved, now that
/// the directories exist, and the resolved paths are ordered deepest first; a
/// directory inside another always resolves to a longer path than it. The
/// two lists `created` was built from can name one directory twice, through
/// a link or an alias the file system folds, and it is then named once. A
/// path that no longer resolves names nothing to remove, since nothing was
/// created there, and a path that cannot be resolved otherwise is kept as
/// given, so that its removal reports the failure.
fn removal_order(created: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut resolved: Vec<PathBuf> = created
        .into_iter()
        .filter_map(|path| match canonicalize(&path) {
            Ok(resolved) => Some(resolved),
            Err(e) if e.kind() == ErrorKind::NotFound => None,
            Err(_) => Some(path),
        })
        .collect();
    resolved.sort_unstable_by(|a, b| {
        b.components()
            .count()
            .cmp(&a.components().count())
            .then_with(|| a.cmp(b))
    });
    resolved.dedup();
    resolved
}

/// Returns the missing ancestors of `dir`, `dir` itself included, from the
/// deepest up.
///
/// # Errors
///
/// Returns an error if an ancestor cannot be inspected.
fn missing_ancestors(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut missing = Vec::new();
    for path in dir.ancestors() {
        let path: PathBuf = path.components().collect();
        if path.as_os_str().is_empty() {
            break;
        }
        match symlink_metadata(&path) {
            Ok(_) => break,
            Err(e) if e.kind() == ErrorKind::NotFound => missing.push(path),
            Err(e) => {
                return Err(e).with_context(|| format!("cannot inspect {}", path.display()));
            }
        }
    }
    Ok(missing)
}

/// Checks that nothing stands at the `VERSION` of `dir`, a fresh directory
/// that now exists, or at the temporary `temporary` its marker is written
/// through, and nothing but a regular file at its `VERSION.tmp`.
///
/// `other` is the directory whose creation would have put it there.
///
/// # Errors
///
/// Returns an error if a name is taken, or if it cannot be inspected.
fn check_marker_names_are_free(dir: &Path, temporary: &str, other: &Path) -> Result<()> {
    for name in [VERSION_FILE_NAME, temporary, VERSION_TMP_FILE_NAME] {
        let path = dir.join(name);
        let taken = match symlink_metadata(&path) {
            Ok(found) => name != VERSION_TMP_FILE_NAME || !found.is_file(),
            Err(e) if e.kind() == ErrorKind::NotFound => false,
            Err(e) => {
                return Err(e).with_context(|| format!("cannot inspect {}", path.display()));
            }
        };
        if taken {
            return Err(anyhow!(
                "cannot create data dir: {} is inside the {name} of {}",
                other.display(),
                dir.display()
            ));
        }
    }
    Ok(())
}

/// Checks that the `VERSION.tmp` of `fresh`, which is removed once `fresh` is
/// initialized, is not the file `marked` holds its marker in.
///
/// A `VERSION` of `marked` that is a symbolic link to that `VERSION.tmp`
/// would be left dangling once the leftover is removed, and one that is a
/// hard link to it shares its inode. Either way the file is not a leftover of
/// an interrupted write but the marker the pair was accepted on, so the pair
/// is refused while nothing has been written.
///
/// # Errors
///
/// Returns an error if the two are the same file, or if either cannot be
/// inspected.
fn check_leftover_is_not_the_marker(fresh: &Path, marked: &Path) -> Result<()> {
    let tmp = fresh.join(VERSION_TMP_FILE_NAME);
    let leftover = match symlink_metadata(&tmp) {
        Ok(leftover) => leftover,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("cannot inspect {}", tmp.display())),
    };
    let version = marked.join(VERSION_FILE_NAME);
    let held =
        metadata(&version).with_context(|| format!("cannot inspect {}", version.display()))?;
    if (leftover.dev(), leftover.ino()) == (held.dev(), held.ino()) {
        return Err(anyhow!(
            "cannot create data dir: {} is the VERSION of {}",
            tmp.display(),
            marked.display()
        ));
    }
    Ok(())
}

/// Checks `marker`, held by one directory whose counterpart is fresh.
///
/// The fresh counterpart would be given the current format, so the pair is
/// compared as if it held `current`. `marker_on_data` tells whether `marker`
/// is the data directory's.
///
/// # Errors
///
/// Returns the mismatch error if `marker` is within `compatible` but is not
/// `current`, and the unsupported-format error if it is outside `compatible`.
fn check_marker_beside_fresh(
    marker: &Version,
    current: &Version,
    compatible: &VersionReq,
    marker_on_data: bool,
) -> Result<()> {
    if marker == current {
        return Ok(());
    }
    if !compatible.matches(marker) {
        return Err(unsupported(marker));
    }
    let (data, backup) = if marker_on_data {
        (marker, current)
    } else {
        (current, marker)
    };
    Err(mismatched(data, backup))
}

/// Returns the error for a data and a backup directory holding different
/// markers.
fn mismatched(data: &Version, backup: &Version) -> anyhow::Error {
    anyhow!("mismatched database version {data} and backup version {backup}")
}

/// Returns the error for a marker naming a format this build cannot open.
fn unsupported(version: &Version) -> anyhow::Error {
    anyhow!("database format {version} is not supported")
}

/// Returns the format marker `dir` holds, or `None` if `dir` is fresh.
///
/// A fresh directory is missing, empty, or holds nothing but a
/// `VERSION.tmp` that is a regular file. Nothing is created or changed either
/// way.
///
/// # Errors
///
/// Returns an error if `dir` is empty, if it cannot be listed, if it is missing
/// and could not be created, or if it is not fresh and its `VERSION` cannot be
/// read or parsed.
fn read_marker(dir: &Path) -> Result<Option<Version>> {
    // Listing an empty path fails as not found, yet joining a file name to it
    // names that file in the working directory, so calling it missing would
    // let the working directory's `VERSION` be replaced. It names no
    // directory, so it is refused before anything is written.
    if dir.as_os_str().is_empty() {
        return Err(anyhow!("cannot read data dir: the path is empty"));
    }
    let entries = match dir.read_dir() {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            check_missing_dir_can_be_created(dir)?;
            return Ok(None);
        }
        Err(e) => return Err(e).context("cannot read data dir"),
    };

    // A temporary left behind by an interrupted write must not make an
    // otherwise empty directory look populated, or a fresh data directory
    // would never be given a VERSION. Only that one name is forgiven, and only
    // as a regular file, which is all `create_version_file` can leave: a
    // directory holding anything else but no VERSION stays an error, since
    // stamping the current version onto an existing tree would let it open in
    // a format it is not in. A subdirectory or a symbolic link of that name is
    // no leftover of ours, and calling it fresh would let one side be written
    // before the write over that name fails on the other.
    let tmp = dir.join(VERSION_TMP_FILE_NAME);
    let populated = entries.into_iter().any(|entry| match entry {
        Ok(entry) => entry.path() != tmp || !entry.file_type().is_ok_and(|kind| kind.is_file()),
        Err(_) => true,
    });
    if !populated {
        return Ok(None);
    }

    read_version_file(&dir.join(VERSION_FILE_NAME)).map(Some)
}

/// Checks that `dir`, which cannot be listed because it is not found, is
/// really missing and can be created by `create_dir_all`.
///
/// A dangling symbolic link at `dir`, or at one of its ancestors, also makes
/// listing `dir` fail as not found, yet `create_dir_all` cannot create a
/// directory through it. Calling such a side fresh would let the other side be
/// written before the write on this one fails, so it is refused here, while
/// nothing has been written yet. The nearest ancestor that exists must
/// therefore resolve to a directory.
///
/// Each path is inspected without a trailing separator or `.`, which `Path`
/// does not count as a component: `link/` and `link/.` resolve `link` before
/// they are looked up, so a dangling `link` would make them fail as not found
/// where `link` itself is found as a link.
///
/// The part of `dir` below its nearest existing ancestor must not hold a `..`
/// either. `missing/../old` cannot be listed while `missing` is missing, yet
/// once `create_dir_all` has created `missing` it names `old`, which may
/// already hold a `VERSION` of an earlier format; calling it fresh would let
/// that marker be replaced. Only the components that are missing are checked:
/// a `..` within the existing ancestor resolves the same before and after.
///
/// # Errors
///
/// Returns an error if a dangling symbolic link stands at `dir` or at one of
/// its ancestors, if the nearest existing ancestor is not a directory, if a
/// `..` follows a missing component of `dir`, or if the ancestors cannot be
/// inspected.
fn check_missing_dir_can_be_created(dir: &Path) -> Result<()> {
    for path in dir.ancestors() {
        let path: PathBuf = path.components().collect();
        let existing_components = path.components().count();
        // An empty path is the current directory of a relative `dir`.
        let path = if path.as_os_str().is_empty() {
            Path::new(".")
        } else {
            path.as_path()
        };
        match symlink_metadata(path) {
            Ok(_) => {
                if dir
                    .components()
                    .skip(existing_components)
                    .any(|component| component == Component::ParentDir)
                {
                    return Err(anyhow!(
                        "cannot create data dir: {} has a `..` after a missing component",
                        dir.display()
                    ));
                }
                return match metadata(path) {
                    Ok(resolved) if resolved.is_dir() => Ok(()),
                    Ok(_) => Err(anyhow!(
                        "cannot create data dir: {} is not a directory",
                        path.display()
                    )),
                    Err(e) => Err(e).with_context(|| {
                        format!(
                            "cannot create data dir: {} does not resolve to a directory",
                            path.display()
                        )
                    }),
                };
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e).with_context(|| format!("cannot inspect {}", path.display()));
            }
        }
    }
    Ok(())
}

/// The temporary [`create_version_file`] writes the marker to before renaming
/// it over VERSION.
#[derive(Clone, Copy, Debug)]
enum Temporary {
    /// A new file is created under this name, which nothing may hold, so the
    /// bytes go to an inode of its own and the marker gets the mode
    /// `OpenOptions` and the umask give a new file.
    ///
    /// `migrate_data_dir` initializes fresh directories this way, under
    /// `VERSION.tmp` where there is no leftover and under
    /// [`VERSION_BESIDE_LEFTOVER_FILE_NAME`] beside one, which it never
    /// writes to: a leftover that is a hard link to some other file shares
    /// that file's inode, and writing through it would rewrite that file too.
    Create(&'static str),
    /// `VERSION.tmp` is created, or truncated and written in place if it is
    /// already there, so a leftover keeps its inode and its mode, and the
    /// marker it is renamed to has them.
    ///
    /// [`write_version_markers`] writes this way, as it always has: the
    /// rollback it serves is outside the format change, and so is the mode
    /// of the markers it leaves.
    Reuse,
}

/// Writes `version` to the VERSION file at `path`, creating it if it does not
/// exist.
///
/// The file is replaced rather than rewritten: the version goes to a
/// temporary in the same directory and is renamed over VERSION, so an
/// interrupted write cannot leave VERSION empty or partial.
///
/// `version` is written verbatim, so every caller passes a string it has
/// already validated: `DATABASE_FORMAT_VERSION` from `migrate_data_dir`, and the
/// canonical form of a parsed [`Version`] from [`write_version_markers`].
/// `temporary` says which file the version goes to first.
///
/// # Errors
///
/// Returns an error if the temporary file cannot be created, written, or
/// flushed, if it cannot be renamed over the VERSION file, or if the
/// containing directory cannot be flushed.
fn create_version_file(path: &Path, version: &str, temporary: Temporary) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));

    // No mode is requested here. `rename` installs this inode at the
    // destination, so the temporary's mode becomes VERSION's, and
    // `OpenOptions` asks for `0o666` and lets the umask narrow it — which is
    // what VERSION has had all along. It records a format version, not a
    // secret, so there is nothing to tighten.
    let (tmp, opened) = match temporary {
        Temporary::Create(name) => {
            let tmp = dir.join(name);
            let opened = OpenOptions::new().write(true).create_new(true).open(&tmp);
            (tmp, opened)
        }
        Temporary::Reuse => {
            let tmp = dir.join(VERSION_TMP_FILE_NAME);
            let opened = File::create(&tmp);
            (tmp, opened)
        }
    };
    let mut f = opened.context("cannot create temporary VERSION")?;
    f.write_all(version.as_bytes())
        .context("cannot write temporary VERSION")?;

    // Flush before the rename. The next start reads VERSION back to decide
    // whether the directories can be opened, so a rename reaching disk ahead
    // of these bytes would leave a version that cannot be parsed and a
    // database that will not open.
    f.sync_all().context("cannot flush temporary VERSION")?;
    drop(f);

    if let Err(rename_err) = rename(&tmp, path) {
        // Leave nothing behind but what `read_marker` already forgives in an
        // empty data directory.
        return match remove_file(&tmp) {
            Ok(()) => Err(rename_err).context("cannot replace VERSION"),
            Err(remove_err) => {
                Err(remove_err).context("cannot remove temporary VERSION after a failed rename")
            }
        };
    }

    // Flush the directory as well: the rename is what makes the new version
    // visible, and until that directory entry is on disk a power loss can
    // still lose it, leaving a directory recorded as the version it held
    // before the write, or as fresh.
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
/// This is the metadata companion to restoring a rollback snapshot. The
/// snapshot covers `data_dir/states.db` only, while the format version lives
/// beside it in the two `VERSION` files, so restoring the snapshot taken
/// before an update puts the older database back under markers that may still
/// name the newer format, which the earlier binary does not know. After restoring the snapshot, the caller
/// passes the format version it recorded before the update — the
/// `pre_update_version` of the operation attempt — and both markers again
/// describe the restored contents.
///
/// `version` is parsed as a [`semver::Version`] before anything is written,
/// and it is the parsed value's canonical `to_string()` form that reaches each
/// file, with no trailing bytes. Validation is syntactic only: this function
/// does not read `states.db`, does not read the markers it replaces, and does
/// not judge whether any binary can migrate from `version`. Choosing a version
/// the rollback binary supports remains the caller's responsibility.
///
/// A missing directory, and any missing component of its path, is created.
/// Each marker is replaced through the same write-to-a-temporary, sync,
/// rename, and directory-sync path `migrate_data_dir` uses, so an interruption cannot
/// leave a marker empty or partially written. A `VERSION.tmp` already in a
/// directory is truncated and reused rather than replaced, as it always has
/// been, so the marker renamed from it keeps that file's mode. The two files can live on
/// different filesystems, so there is no cross-directory atomic commit: a
/// failure on the second leaves the first already updated. The operation is
/// idempotent — correct the filesystem failure and call it again with the same
/// paths and version, and both markers end up canonical and equal.
///
/// `VERSION.tmp`, the temporary each replacement goes through, is a fixed name,
/// so the caller must serialize this call against `migrate_data_dir` and any
/// other marker write for each directory involved.
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

    write_version_marker(data_dir, &canonical, Temporary::Reuse).with_context(|| {
        format!(
            "cannot write the data directory VERSION in {}",
            data_dir.display()
        )
    })?;
    write_version_marker(backup_dir, &canonical, Temporary::Reuse).with_context(|| {
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
fn write_version_marker(dir: &Path, version: &str, temporary: Temporary) -> Result<()> {
    create_dir_all(dir).context("cannot create the directory")?;
    create_version_file(&dir.join(VERSION_FILE_NAME), version, temporary)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        io::Write,
        path::{Path, PathBuf},
    };

    use semver::{Version, VersionReq};

    use super::{
        COMPATIBLE_VERSION_REQ, DATABASE_FORMAT_VERSION, Temporary,
        VERSION_BESIDE_LEFTOVER_FILE_NAME, VERSION_FILE_NAME, VERSION_TMP_FILE_NAME,
        create_version_file, migrate_data_dir, read_version_file, write_version_markers,
    };

    /// The bytes a `VERSION.tmp` left behind by an interrupted write holds in
    /// these tests.
    const STALE_TMP: &[u8] = b"0.6";

    /// Helper to write a specific version to a VERSION file.
    fn write_version(path: &Path, version: &str) {
        let version_file = path.join(VERSION_FILE_NAME);
        let mut f = std::fs::File::create(&version_file).unwrap();
        f.write_all(version.as_bytes()).unwrap();
    }

    /// The ways a directory is fresh.
    #[derive(Clone, Copy, Debug)]
    enum Fresh {
        Empty,
        Missing,
        TmpOnly,
    }

    const FRESH: [Fresh; 3] = [Fresh::Empty, Fresh::Missing, Fresh::TmpOnly];

    /// What a test puts in one of the two directories.
    #[derive(Clone, Copy, Debug)]
    enum Side<'a> {
        Fresh(Fresh),
        /// A `VERSION` holding these bytes, beside a database.
        Marked(&'a str),
        /// A database and no `VERSION`.
        Unmarked,
        /// Nothing but a subdirectory named `VERSION.tmp`.
        TmpDirectory,
        /// Nothing but a symbolic link named `VERSION.tmp` to a regular file
        /// outside the directory.
        TmpSymlink,
    }

    /// Creates `name` under `root` holding what `side` describes, and returns
    /// its path.
    fn make_side(root: &Path, name: &str, side: Side<'_>) -> PathBuf {
        let dir = root.join(name);
        match side {
            Side::Fresh(Fresh::Missing) => {}
            Side::Fresh(Fresh::Empty) => std::fs::create_dir(&dir).unwrap(),
            Side::Fresh(Fresh::TmpOnly) => {
                std::fs::create_dir(&dir).unwrap();
                std::fs::write(dir.join(VERSION_TMP_FILE_NAME), STALE_TMP).unwrap();
            }
            Side::Marked(version) => {
                std::fs::create_dir(&dir).unwrap();
                std::fs::write(dir.join("states.db"), b"synthetic database").unwrap();
                write_version(&dir, version);
            }
            Side::Unmarked => {
                std::fs::create_dir(&dir).unwrap();
                std::fs::write(dir.join("states.db"), b"synthetic database").unwrap();
            }
            Side::TmpDirectory => {
                std::fs::create_dir(&dir).unwrap();
                std::fs::create_dir(dir.join(VERSION_TMP_FILE_NAME)).unwrap();
            }
            Side::TmpSymlink => {
                std::fs::create_dir(&dir).unwrap();
                let target = root.join(format!("{name}-link-target"));
                std::fs::write(&target, STALE_TMP).unwrap();
                std::os::unix::fs::symlink(&target, dir.join(VERSION_TMP_FILE_NAME)).unwrap();
            }
        }
        dir
    }

    /// Every file under `dir` with its contents, or `None` if `dir` is
    /// missing.
    fn dir_state(dir: &Path) -> Option<BTreeMap<PathBuf, Vec<u8>>> {
        fn walk(dir: &Path, base: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                let relative = path.strip_prefix(base).unwrap().to_path_buf();
                if path.is_dir() {
                    files.insert(relative, Vec::new());
                    walk(&path, base, files);
                } else {
                    files.insert(relative, std::fs::read(&path).unwrap());
                }
            }
        }

        if !dir.exists() {
            return None;
        }
        let mut files = BTreeMap::new();
        walk(dir, dir, &mut files);
        Some(files)
    }

    /// The device, inode and modification time of the `VERSION` in `dir`.
    ///
    /// A marker that is replaced through a rename gets a new inode, and one
    /// rewritten in place gets a new modification time, so a marker that is
    /// written again with the same bytes still changes this.
    fn marker_identity(dir: &Path) -> (u64, u64, std::time::SystemTime) {
        use std::os::unix::fs::MetadataExt;

        let metadata = std::fs::metadata(dir.join(VERSION_FILE_NAME)).unwrap();
        (metadata.dev(), metadata.ino(), metadata.modified().unwrap())
    }

    /// Runs `migrate_data_dir` over `data` and `backup`, and returns the two
    /// directories and the outcome.
    fn run(
        root: &Path,
        data: Side<'_>,
        backup: Side<'_>,
    ) -> (PathBuf, PathBuf, anyhow::Result<()>) {
        let data_dir = make_side(root, "data", data);
        let backup_dir = make_side(root, "backup", backup);
        let result = migrate_data_dir(&data_dir, &backup_dir, None);
        (data_dir, backup_dir, result)
    }

    /// Asserts that `dir` holds a `VERSION` of exactly the current format and
    /// no `VERSION.tmp`.
    fn assert_initialized(dir: &Path) {
        assert_eq!(
            std::fs::read(dir.join(VERSION_FILE_NAME)).unwrap(),
            DATABASE_FORMAT_VERSION.as_bytes(),
            "{} must hold the current format",
            dir.display()
        );
        assert!(!dir.join(VERSION_TMP_FILE_NAME).exists());
    }

    /// Asserts that the pair is refused with an error whose message is
    /// `expected`, and that neither directory changed.
    fn assert_refused(data: Side<'_>, backup: Side<'_>, expected: &str) {
        let root = tempfile::tempdir().unwrap();
        let data_dir = make_side(root.path(), "data", data);
        let backup_dir = make_side(root.path(), "backup", backup);
        let data_before = dir_state(&data_dir);
        let backup_before = dir_state(&backup_dir);

        let err = migrate_data_dir(&data_dir, &backup_dir, None)
            .expect_err(&format!("{data:?} and {backup:?} must be refused"));

        assert_eq!(err.to_string(), expected, "for {data:?} and {backup:?}");
        assert_eq!(
            dir_state(&data_dir),
            data_before,
            "{data:?} beside {backup:?}"
        );
        assert_eq!(
            dir_state(&backup_dir),
            backup_before,
            "{backup:?} beside {data:?}"
        );
    }

    #[test]
    fn format_marker_is_raised_to_0_63_once() {
        assert_eq!(DATABASE_FORMAT_VERSION, "0.63.0");
        assert_eq!(COMPATIBLE_VERSION_REQ, ">=0.63.0,<0.64.0");
        let compatible = VersionReq::parse(COMPATIBLE_VERSION_REQ).unwrap();
        assert!(compatible.matches(&Version::parse(DATABASE_FORMAT_VERSION).unwrap()));
    }

    /// Two fresh directories, in every combination of the ways a directory is
    /// fresh, are both given the current format and then open unchanged.
    #[test]
    fn fresh_directories_are_initialized_and_reopen() {
        for data in FRESH {
            for backup in FRESH {
                let root = tempfile::tempdir().unwrap();
                let (data_dir, backup_dir, result) =
                    run(root.path(), Side::Fresh(data), Side::Fresh(backup));
                result.unwrap();
                assert_initialized(&data_dir);
                assert_initialized(&backup_dir);

                let data_before = dir_state(&data_dir);
                let backup_before = dir_state(&backup_dir);
                let data_marker = marker_identity(&data_dir);
                let backup_marker = marker_identity(&backup_dir);
                migrate_data_dir(&data_dir, &backup_dir, None).unwrap();
                assert_eq!(dir_state(&data_dir), data_before);
                assert_eq!(dir_state(&backup_dir), backup_before);
                assert_eq!(marker_identity(&data_dir), data_marker);
                assert_eq!(marker_identity(&backup_dir), backup_marker);
            }
        }
    }

    /// Both directories holding the same marker in the compatible range open,
    /// and nothing is written: neither marker is replaced, even with the same
    /// bytes.
    #[test]
    fn matching_compatible_markers_open_unchanged() {
        for marker in [DATABASE_FORMAT_VERSION, "0.63.1"] {
            let root = tempfile::tempdir().unwrap();
            let data_dir = make_side(root.path(), "data", Side::Marked(marker));
            let backup_dir = make_side(root.path(), "backup", Side::Marked(marker));
            let data_before = dir_state(&data_dir);
            let backup_before = dir_state(&backup_dir);
            let data_marker = marker_identity(&data_dir);
            let backup_marker = marker_identity(&backup_dir);

            migrate_data_dir(&data_dir, &backup_dir, None)
                .unwrap_or_else(|e| panic!("two {marker} markers must open: {e:#}"));

            assert_eq!(dir_state(&data_dir), data_before, "{marker}");
            assert_eq!(dir_state(&backup_dir), backup_before, "{marker}");
            assert_eq!(marker_identity(&data_dir), data_marker, "{marker}");
            assert_eq!(marker_identity(&backup_dir), backup_marker, "{marker}");
        }
    }

    /// The current format on one side and a fresh directory on the other, on
    /// each side in turn: the fresh one is given the current format, and the
    /// marked one is left as it is.
    #[test]
    fn a_fresh_counterpart_of_the_current_format_is_initialized() {
        let marked = Side::Marked(DATABASE_FORMAT_VERSION);
        for fresh in FRESH {
            for marked_on_data in [true, false] {
                let root = tempfile::tempdir().unwrap();
                let marked_dir = make_side(
                    root.path(),
                    if marked_on_data { "data" } else { "backup" },
                    marked,
                );
                let marked_before = dir_state(&marked_dir);
                let marked_marker = marker_identity(&marked_dir);
                let fresh_dir = make_side(
                    root.path(),
                    if marked_on_data { "backup" } else { "data" },
                    Side::Fresh(fresh),
                );
                let (data_dir, backup_dir) = if marked_on_data {
                    (&marked_dir, &fresh_dir)
                } else {
                    (&fresh_dir, &marked_dir)
                };

                migrate_data_dir(data_dir, backup_dir, None).unwrap();

                assert_initialized(&fresh_dir);
                assert_eq!(
                    dir_state(&fresh_dir).unwrap().len(),
                    1,
                    "{fresh:?} must hold VERSION alone"
                );
                assert_eq!(dir_state(&marked_dir), marked_before);
                assert_eq!(marker_identity(&marked_dir), marked_marker);
            }
        }
    }

    /// A marker outside the compatible range on both sides alike is refused,
    /// naming the marker, and nothing is written.
    #[test]
    fn markers_of_an_earlier_format_are_refused() {
        for marker in [
            "0.30.0",
            "0.61.0",
            "0.62.0",
            "0.62.1",
            "0.64.0",
            "0.62.0-alpha.1",
            "0.63.0-alpha.1",
            "0.63.1-alpha.1",
        ] {
            assert_refused(
                Side::Marked(marker),
                Side::Marked(marker),
                &format!("database format {marker} is not supported"),
            );
        }
    }

    /// A marker outside the compatible range on one side, with the other
    /// fresh in every way and on each side in turn, is refused, naming the
    /// marker. The fresh side gets no `VERSION`, a `VERSION.tmp` stays as it
    /// is, and a missing directory is not created.
    #[test]
    fn a_marker_of_an_earlier_format_beside_a_fresh_directory_is_refused() {
        for marker in ["0.62.0", "0.61.0", "0.63.0-alpha.1"] {
            let expected = format!("database format {marker} is not supported");
            for fresh in FRESH {
                assert_refused(Side::Marked(marker), Side::Fresh(fresh), &expected);
                assert_refused(Side::Fresh(fresh), Side::Marked(marker), &expected);
            }
        }
    }

    /// Two different markers are refused as mismatched, whether either is in
    /// the compatible range or not.
    #[test]
    fn different_markers_are_refused_as_mismatched() {
        for (data, backup) in [
            ("0.63.0", "0.63.1"),
            ("0.63.1", "0.63.0"),
            ("0.62.0", "0.63.0"),
            ("0.63.0", "0.62.0"),
            ("0.61.0", "0.62.0"),
            ("0.63.0", "0.63.0-alpha.1"),
        ] {
            assert_refused(
                Side::Marked(data),
                Side::Marked(backup),
                &format!("mismatched database version {data} and backup version {backup}"),
            );
        }
    }

    /// A marker in the compatible range other than the current format, beside
    /// a fresh directory, is refused as mismatched against the current format
    /// the fresh side would be given.
    #[test]
    fn a_later_compatible_marker_beside_a_fresh_directory_is_refused() {
        const MARKER: &str = "0.63.1";
        for fresh in FRESH {
            assert_refused(
                Side::Marked(MARKER),
                Side::Fresh(fresh),
                &format!(
                    "mismatched database version {MARKER} and backup version \
                     {DATABASE_FORMAT_VERSION}"
                ),
            );
            assert_refused(
                Side::Fresh(fresh),
                Side::Marked(MARKER),
                &format!(
                    "mismatched database version {DATABASE_FORMAT_VERSION} and backup version \
                     {MARKER}"
                ),
            );
        }
    }

    /// A populated directory without a `VERSION` is refused rather than
    /// stamped with the current format, on each side in turn, and its fresh
    /// counterpart gets no `VERSION` either.
    #[test]
    fn a_populated_directory_without_version_is_refused() {
        for fresh in FRESH {
            assert_refused(Side::Unmarked, Side::Fresh(fresh), "cannot open VERSION");
            assert_refused(Side::Fresh(fresh), Side::Unmarked, "cannot open VERSION");
        }
        assert_refused(
            Side::Unmarked,
            Side::Marked(DATABASE_FORMAT_VERSION),
            "cannot open VERSION",
        );
        assert_refused(
            Side::Marked(DATABASE_FORMAT_VERSION),
            Side::Unmarked,
            "cannot open VERSION",
        );
    }

    /// A `VERSION.tmp` that is not a regular file makes its directory
    /// populated rather than fresh. Beside a fresh directory, on each side in
    /// turn, the pair is refused for the missing `VERSION`, and neither side is
    /// written: the fresh one gets no `VERSION`, and the `VERSION.tmp` is left
    /// as it is.
    #[test]
    fn a_version_tmp_that_is_not_a_regular_file_is_refused() {
        for odd in [Side::TmpDirectory, Side::TmpSymlink] {
            for fresh in FRESH {
                assert_refused(odd, Side::Fresh(fresh), "cannot open VERSION");
                assert_refused(Side::Fresh(fresh), odd, "cannot open VERSION");
            }
            assert_refused(odd, odd, "cannot open VERSION");
        }
    }

    /// A side whose path cannot be listed because a dangling symbolic link
    /// stands at it, or at one of its ancestors, is not missing: no directory
    /// can be created through the link. Beside a fresh directory, on each side
    /// in turn, the pair is refused before anything is written, so the fresh
    /// side gets no `VERSION`, and the link is left dangling. The path is
    /// refused alike when it ends in a separator or in `/.`, which resolve the
    /// link before the path is looked up.
    #[test]
    fn a_dangling_directory_symlink_is_refused() {
        const NOT_A_DIRECTORY: &str = "does not resolve to a directory";

        for (at_ancestor, suffix) in [false, true]
            .into_iter()
            .flat_map(|at_ancestor| ["", "/", "/."].map(|suffix| (at_ancestor, suffix)))
        {
            for fresh in FRESH {
                for link_on_data in [true, false] {
                    let root = tempfile::tempdir().unwrap();
                    let link = root.path().join("link");
                    let target = root.path().join("nowhere");
                    std::os::unix::fs::symlink(&target, &link).unwrap();
                    let mut linked = if at_ancestor {
                        link.join("sub")
                    } else {
                        link.clone()
                    }
                    .into_os_string();
                    linked.push(suffix);
                    let linked = PathBuf::from(linked);
                    let fresh_dir = make_side(root.path(), "fresh", Side::Fresh(fresh));
                    let fresh_before = dir_state(&fresh_dir);

                    let (data_dir, backup_dir) = if link_on_data {
                        (&linked, &fresh_dir)
                    } else {
                        (&fresh_dir, &linked)
                    };
                    let err = migrate_data_dir(data_dir, backup_dir, None).expect_err(&format!(
                        "{} beside {fresh:?} must be refused",
                        linked.display()
                    ));

                    let message = err.to_string();
                    assert!(
                        message.contains(NOT_A_DIRECTORY),
                        "unexpected error for {} beside {fresh:?}: {message}",
                        linked.display()
                    );
                    assert_eq!(
                        dir_state(&fresh_dir),
                        fresh_before,
                        "{fresh:?} beside {}",
                        linked.display()
                    );
                    assert_eq!(std::fs::read_link(&link).unwrap(), target);
                    assert!(std::fs::symlink_metadata(&target).is_err());
                }
            }
        }
    }

    /// A path with a `..` after a missing component, such as `missing/../old`,
    /// cannot be listed while `missing` is missing, yet would name `old` once
    /// `missing` was created. Beside a fresh directory, on each side in turn,
    /// the pair is refused before anything is written: the `VERSION` of an
    /// earlier format in `old` is kept, `missing` is not created, and the
    /// fresh side gets no `VERSION`.
    #[test]
    fn a_parent_dir_after_a_missing_component_is_refused() {
        const PARENT_AFTER_MISSING: &str = "has a `..` after a missing component";

        for fresh in FRESH {
            for dotdot_on_data in [true, false] {
                let root = tempfile::tempdir().unwrap();
                let old = make_side(root.path(), "old", Side::Marked("0.62.0"));
                let missing = root.path().join("missing");
                let through_missing = missing.join("..").join("old");
                let fresh_dir = make_side(root.path(), "fresh", Side::Fresh(fresh));
                let old_before = dir_state(&old);
                let fresh_before = dir_state(&fresh_dir);

                let (data_dir, backup_dir) = if dotdot_on_data {
                    (&through_missing, &fresh_dir)
                } else {
                    (&fresh_dir, &through_missing)
                };
                let err = migrate_data_dir(data_dir, backup_dir, None).expect_err(&format!(
                    "`missing/../old` beside {fresh:?} must be refused"
                ));

                let message = err.to_string();
                assert!(
                    message.contains(PARENT_AFTER_MISSING),
                    "unexpected error beside {fresh:?}: {message}"
                );
                assert_eq!(dir_state(&old), old_before, "beside {fresh:?}");
                assert_eq!(
                    std::fs::read(old.join(VERSION_FILE_NAME)).unwrap(),
                    b"0.62.0"
                );
                assert!(
                    std::fs::symlink_metadata(&missing).is_err(),
                    "`missing` must not be created beside {fresh:?}"
                );
                assert_eq!(dir_state(&fresh_dir), fresh_before, "{fresh:?}");
            }
        }
    }

    /// A `..` within the existing part of a missing directory's path resolves
    /// the same before and after the directory is created, so the directory is
    /// initialized as any other missing one.
    #[test]
    fn a_parent_dir_within_the_existing_ancestor_is_accepted() {
        let root = tempfile::tempdir().unwrap();
        let existing = make_side(root.path(), "existing", Side::Fresh(Fresh::Empty));
        let data_dir = existing.join("..").join("data");
        let backup_dir = root.path().join("backup");

        migrate_data_dir(&data_dir, &backup_dir, None).unwrap();

        assert_initialized(&root.path().join("data"));
        assert_initialized(&backup_dir);
    }

    /// Pairs of paths, relative to one directory, of which the second may lie
    /// at or below the `VERSION` or `VERSION.tmp` of the first.
    ///
    /// The first three overlap on every file system. The rest overlap only on
    /// one that folds case (`version`, `Version.TMP`), Unicode case (`ſ`
    /// folds to `s`, `É` to `é`) or Unicode normalization (a precomposed `É`
    /// against `E` and a combining acute accent), as macOS does by default.
    const OVERLAP_CANDIDATES: [(&str, &str); 8] = [
        ("store", "store/VERSION"),
        ("store", "store/VERSION.tmp"),
        ("store", "store/VERSION/sub"),
        ("store", "store/version"),
        ("store", "store/Version.TMP"),
        ("store", "store/VER\u{17f}ION"),
        ("\u{c9}tat", "\u{e9}tat/VERSION"),
        ("\u{c9}tat", "E\u{301}tat/VERSION"),
    ];

    /// Whether creating `inner` puts anything at the `VERSION` or
    /// `VERSION.tmp` of `outer`, both relative to a scratch directory, on the
    /// file system the tests' temporary directories live on.
    fn overlaps_here(outer: &str, inner: &str) -> bool {
        let probe = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(probe.path().join(inner)).unwrap();
        let outer = probe.path().join(outer);
        [VERSION_FILE_NAME, VERSION_TMP_FILE_NAME]
            .iter()
            .any(|name| std::fs::symlink_metadata(outer.join(name)).is_ok())
    }

    /// Two fresh directories where one is at or below the other's `VERSION` or
    /// `VERSION.tmp` as the file system resolves names, such as `store` beside
    /// `store/VERSION`, are refused, on each side in turn: writing one marker
    /// would put a file or a directory where the other needs to be. The outer
    /// directory is missing or empty, and the inner path may reach the outer
    /// one through a symbolic link. Nothing is left behind: no marker is
    /// written, and a missing directory is missing again.
    ///
    /// The same pairs whose names the file system keeps apart, such as `store`
    /// beside `store/version` on a case-sensitive one, hold two independent
    /// directories, and both are initialized.
    #[test]
    fn overlapping_fresh_directories_are_refused() {
        const OVERLAP: &str = "is inside the";

        for (outer_name, inner_name) in OVERLAP_CANDIDATES {
            let overlaps = overlaps_here(outer_name, inner_name);
            if inner_name.starts_with("store/VERSION") {
                assert!(overlaps, "{inner_name} must overlap {outer_name} anywhere");
            }
            for outer_state in [Fresh::Missing, Fresh::Empty] {
                for through_link in [false, true] {
                    for outer_on_data in [true, false] {
                        let root = tempfile::tempdir().unwrap();
                        let real = make_side(root.path(), "real", Side::Fresh(Fresh::Empty));
                        let alias = root.path().join("alias");
                        std::os::unix::fs::symlink(&real, &alias).unwrap();
                        let outer = make_side(&real, outer_name, Side::Fresh(outer_state));
                        let inner_dir = if through_link { &alias } else { &real }.join(inner_name);
                        let before = dir_state(&real);

                        let (data_dir, backup_dir) = if outer_on_data {
                            (&outer, &inner_dir)
                        } else {
                            (&inner_dir, &outer)
                        };
                        let case = format!(
                            "{} beside {} ({outer_state:?})",
                            data_dir.display(),
                            backup_dir.display()
                        );
                        let result = migrate_data_dir(data_dir, backup_dir, None);

                        if !overlaps {
                            result.unwrap_or_else(|e| panic!("{case} must be accepted: {e:#}"));
                            assert_initialized(&outer);
                            assert_initialized(&inner_dir);
                            continue;
                        }
                        let message = result
                            .expect_err(&format!("{case} must be refused"))
                            .to_string();
                        assert!(
                            message.contains(OVERLAP),
                            "unexpected error for {case}: {message}"
                        );
                        assert_eq!(dir_state(&real), before, "{case}");
                        assert!(
                            std::fs::symlink_metadata(&inner_dir).is_err(),
                            "{case}: the inner directory must stay missing"
                        );
                        if matches!(outer_state, Fresh::Missing) {
                            assert!(
                                std::fs::symlink_metadata(&outer).is_err(),
                                "{case}: the outer directory must stay missing"
                            );
                        }
                    }
                }
            }
        }
    }

    /// Two missing fresh directories that overlap through a symbolic link that
    /// makes the outer one's path the longer, `a/b/c/alias/store` beside
    /// `store/VERSION` with `a/b/c/alias` linking to the directory holding
    /// `store`, are refused, on each side in turn, and both are missing again:
    /// the directories created for the check are removed in the order their
    /// resolved paths nest, not by the length of the paths as given.
    #[test]
    fn overlap_through_a_longer_alias_is_cleaned_up() {
        const OVERLAP: &str = "is inside the";

        for outer_on_data in [true, false] {
            let root = tempfile::tempdir().unwrap();
            let real = make_side(root.path(), "real", Side::Fresh(Fresh::Empty));
            let link_parent = root.path().join("a").join("b").join("c");
            std::fs::create_dir_all(&link_parent).unwrap();
            std::os::unix::fs::symlink(&real, link_parent.join("alias")).unwrap();
            let outer = link_parent.join("alias").join("store");
            let inner = real.join("store").join(VERSION_FILE_NAME);
            let before = dir_state(&real);

            let (data_dir, backup_dir) = if outer_on_data {
                (&outer, &inner)
            } else {
                (&inner, &outer)
            };
            let case = format!("outer on data: {outer_on_data}");
            let message = migrate_data_dir(data_dir, backup_dir, None)
                .expect_err(&format!("{case} must be refused"))
                .to_string();

            assert!(
                message.contains(OVERLAP),
                "unexpected error for {case}: {message}"
            );
            assert!(
                std::fs::symlink_metadata(real.join("store")).is_err(),
                "{case}: store must stay missing"
            );
            assert_eq!(dir_state(&real), before, "{case}");
        }
    }

    /// A `VERSION` that is a symbolic or a hard link to the leftover
    /// `VERSION.tmp` of a fresh counterpart is refused, on each side in turn:
    /// initializing the counterpart would remove that file, leaving the
    /// marker dangling, or a link of the marker the pair was accepted on. Neither
    /// directory changes, the fresh side gets no `VERSION`, and the marker
    /// still reads the current format.
    #[test]
    fn a_marker_linked_to_the_counterparts_leftover_is_refused() {
        const SAME_FILE: &str = "is the VERSION of";

        for hard in [false, true] {
            for marked_on_data in [true, false] {
                let root = tempfile::tempdir().unwrap();
                let marked = make_side(root.path(), "marked", Side::Unmarked);
                let fresh = make_side(root.path(), "fresh", Side::Fresh(Fresh::Empty));
                let leftover = fresh.join(VERSION_TMP_FILE_NAME);
                std::fs::write(&leftover, DATABASE_FORMAT_VERSION).unwrap();
                let version = marked.join(VERSION_FILE_NAME);
                if hard {
                    std::fs::hard_link(&leftover, &version).unwrap();
                } else {
                    std::os::unix::fs::symlink(&leftover, &version).unwrap();
                }
                let marked_before = dir_state(&marked);
                let fresh_before = dir_state(&fresh);

                let (data_dir, backup_dir) = if marked_on_data {
                    (&marked, &fresh)
                } else {
                    (&fresh, &marked)
                };
                let case = format!("hard: {hard}, marked on data: {marked_on_data}");
                let message = migrate_data_dir(data_dir, backup_dir, None)
                    .expect_err(&format!("{case} must be refused"))
                    .to_string();

                assert!(
                    message.contains(SAME_FILE),
                    "unexpected error for {case}: {message}"
                );
                assert_eq!(dir_state(&marked), marked_before, "{case}");
                assert_eq!(dir_state(&fresh), fresh_before, "{case}");
                assert!(!fresh.join(VERSION_FILE_NAME).exists(), "{case}");
                assert_eq!(
                    std::fs::read(&version).unwrap(),
                    DATABASE_FORMAT_VERSION.as_bytes(),
                    "{case}"
                );
            }
        }
    }

    /// A leftover `VERSION.tmp` that is a hard link to a file outside both
    /// directories is removed without writing through it, beside a marker of
    /// the current format and beside a fresh directory whose leftover is a
    /// hard link to the same file, on each side in turn. Both directories end
    /// up with a readable `VERSION` of their own, the outside file keeps its
    /// bytes, and a marker that was there keeps its inode and modification
    /// time.
    #[test]
    fn a_hard_linked_leftover_is_removed_without_writing_through_it() {
        const OUTSIDE: &[u8] = b"synthetic bytes outside both directories";

        for counterpart in [
            Side::Marked(DATABASE_FORMAT_VERSION),
            Side::Fresh(Fresh::Empty),
        ] {
            for leftover_on_data in [true, false] {
                let root = tempfile::tempdir().unwrap();
                let outside = root.path().join("outside");
                std::fs::write(&outside, OUTSIDE).unwrap();
                let fresh = make_side(root.path(), "fresh", Side::Fresh(Fresh::Empty));
                std::fs::hard_link(&outside, fresh.join(VERSION_TMP_FILE_NAME)).unwrap();
                let other = make_side(root.path(), "other", counterpart);
                let marker_before = if matches!(counterpart, Side::Marked(_)) {
                    Some(marker_identity(&other))
                } else {
                    std::fs::hard_link(&outside, other.join(VERSION_TMP_FILE_NAME)).unwrap();
                    None
                };

                let (data_dir, backup_dir) = if leftover_on_data {
                    (&fresh, &other)
                } else {
                    (&other, &fresh)
                };
                let case = format!("{counterpart:?}, leftover on data: {leftover_on_data}");
                migrate_data_dir(data_dir, backup_dir, None)
                    .unwrap_or_else(|e| panic!("{case} must be accepted: {e:#}"));

                assert_initialized(&fresh);
                assert_initialized(&other);
                assert_eq!(std::fs::read(&outside).unwrap(), OUTSIDE, "{case}");
                if let Some(identity) = marker_before {
                    assert_eq!(marker_identity(&other), identity, "{case}");
                }
                let outside_identity = {
                    use std::os::unix::fs::MetadataExt;
                    let metadata = std::fs::metadata(&outside).unwrap();
                    (metadata.dev(), metadata.ino())
                };
                for dir in [&fresh, &other] {
                    let (dev, ino, _) = marker_identity(dir);
                    assert_ne!((dev, ino), outside_identity, "{case}: {}", dir.display());
                }
            }
        }
    }

    /// A fresh directory whose `VERSION` cannot be written, because it is
    /// read-only, stops the initialization of a fresh pair, on each side in
    /// turn and beside each way the counterpart is fresh, and the pair is left
    /// as it was found: the counterpart gets no `VERSION`, keeps its leftover
    /// `VERSION.tmp` as the same file with the same mode, and stays missing if
    /// it was missing.
    #[test]
    fn a_marker_write_failure_leaves_the_fresh_pair_unchanged() {
        use std::os::unix::fs::PermissionsExt;

        const READ_ONLY: u32 = 0o555;
        const WRITABLE: u32 = 0o755;
        const LEFTOVER_MODE: u32 = 0o604;

        for read_only_state in [Fresh::Empty, Fresh::TmpOnly] {
            for counterpart in FRESH {
                for read_only_on_data in [true, false] {
                    let root = tempfile::tempdir().unwrap();
                    let read_only =
                        make_side(root.path(), "read-only", Side::Fresh(read_only_state));
                    let other = make_side(root.path(), "other", Side::Fresh(counterpart));
                    std::fs::set_permissions(
                        &read_only,
                        std::fs::Permissions::from_mode(READ_ONLY),
                    )
                    .unwrap();
                    // A process that ignores file modes, such as one run as
                    // root, cannot be made to fail this way.
                    let probe = read_only.join("probe");
                    if std::fs::write(&probe, b"").is_ok() {
                        std::fs::remove_file(&probe).unwrap();
                        return;
                    }
                    // A mode no new file gets, so that a leftover put back
                    // with the mode a new file gets is caught.
                    let other_tmp = other.join(VERSION_TMP_FILE_NAME);
                    if matches!(counterpart, Fresh::TmpOnly) {
                        std::fs::set_permissions(
                            &other_tmp,
                            std::fs::Permissions::from_mode(LEFTOVER_MODE),
                        )
                        .unwrap();
                    }
                    let tmp_mode = |tmp: &Path| {
                        use std::os::unix::fs::MetadataExt;

                        std::fs::symlink_metadata(tmp).ok().map(|found| {
                            (
                                found.dev(),
                                found.ino(),
                                found.permissions().mode() & 0o7777,
                            )
                        })
                    };
                    let read_only_tmp = read_only.join(VERSION_TMP_FILE_NAME);
                    let read_only_tmp_mode_before = tmp_mode(&read_only_tmp);
                    let read_only_before = dir_state(&read_only);
                    let other_before = dir_state(&other);
                    let other_tmp_mode_before = tmp_mode(&other_tmp);

                    let (data_dir, backup_dir) = if read_only_on_data {
                        (&read_only, &other)
                    } else {
                        (&other, &read_only)
                    };
                    let case = format!(
                        "read-only {read_only_state:?} beside {counterpart:?}, on data: \
                         {read_only_on_data}"
                    );
                    let message = format!(
                        "{:#}",
                        migrate_data_dir(data_dir, backup_dir, None)
                            .expect_err(&format!("{case} must fail"))
                    );
                    std::fs::set_permissions(&read_only, std::fs::Permissions::from_mode(WRITABLE))
                        .unwrap();

                    assert!(
                        message.contains("failed to create VERSION"),
                        "unexpected error for {case}: {message}"
                    );
                    assert_eq!(dir_state(&read_only), read_only_before, "{case}");
                    assert_eq!(dir_state(&other), other_before, "{case}");
                    assert_eq!(tmp_mode(&other_tmp), other_tmp_mode_before, "{case}");
                    assert_eq!(
                        tmp_mode(&read_only_tmp),
                        read_only_tmp_mode_before,
                        "{case}"
                    );
                }
            }
        }
    }

    /// A leftover `VERSION.tmp` that is a hard link to a file outside both
    /// directories is still that link after an initialization that fails on
    /// the counterpart, which is read-only, on each side in turn: the outside
    /// file keeps its bytes and both of its links, and the fresh side gets no
    /// `VERSION`.
    #[test]
    fn a_failed_initialization_keeps_a_hard_linked_leftover() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        const OUTSIDE: &[u8] = b"synthetic bytes outside both directories";
        const READ_ONLY: u32 = 0o555;
        const WRITABLE: u32 = 0o755;

        for leftover_on_data in [true, false] {
            let root = tempfile::tempdir().unwrap();
            let outside = root.path().join("outside");
            std::fs::write(&outside, OUTSIDE).unwrap();
            let fresh = make_side(root.path(), "fresh", Side::Fresh(Fresh::Empty));
            let leftover = fresh.join(VERSION_TMP_FILE_NAME);
            std::fs::hard_link(&outside, &leftover).unwrap();
            let read_only = make_side(root.path(), "read-only", Side::Fresh(Fresh::Empty));
            std::fs::set_permissions(&read_only, std::fs::Permissions::from_mode(READ_ONLY))
                .unwrap();
            // A process that ignores file modes, such as one run as root,
            // cannot be made to fail this way.
            let probe = read_only.join("probe");
            if std::fs::write(&probe, b"").is_ok() {
                std::fs::remove_file(&probe).unwrap();
                return;
            }

            let (data_dir, backup_dir) = if leftover_on_data {
                (&fresh, &read_only)
            } else {
                (&read_only, &fresh)
            };
            let case = format!("leftover on data: {leftover_on_data}");
            let result = migrate_data_dir(data_dir, backup_dir, None);
            std::fs::set_permissions(&read_only, std::fs::Permissions::from_mode(WRITABLE))
                .unwrap();
            result.expect_err(&format!("{case} must fail"));

            let outside_metadata = std::fs::metadata(&outside).unwrap();
            let leftover_metadata = std::fs::symlink_metadata(&leftover).unwrap();
            assert_eq!(
                (leftover_metadata.dev(), leftover_metadata.ino()),
                (outside_metadata.dev(), outside_metadata.ino()),
                "{case}: the leftover must still be the outside file"
            );
            assert_eq!(outside_metadata.nlink(), 2, "{case}");
            assert_eq!(std::fs::read(&outside).unwrap(), OUTSIDE, "{case}");
            assert_eq!(
                dir_state(&fresh),
                Some(BTreeMap::from([(
                    PathBuf::from(VERSION_TMP_FILE_NAME),
                    OUTSIDE.to_vec()
                )])),
                "{case}"
            );
            assert_eq!(dir_state(&read_only), Some(BTreeMap::new()), "{case}");
        }
    }

    /// A leftover `VERSION.tmp` that cannot be read, because its mode allows
    /// writing only, does not stop a fresh directory from being initialized,
    /// beside a missing directory, beside a marker of the current format, and
    /// beside another such leftover, on each side in turn: the leftover is
    /// never opened, and it is removed once the markers are written.
    #[test]
    fn an_unreadable_leftover_does_not_stop_the_initialization() {
        use std::os::unix::fs::PermissionsExt;

        const WRITE_ONLY: u32 = 0o200;

        for counterpart in [
            Side::Fresh(Fresh::Missing),
            Side::Marked(DATABASE_FORMAT_VERSION),
            Side::Fresh(Fresh::TmpOnly),
        ] {
            for leftover_on_data in [true, false] {
                let root = tempfile::tempdir().unwrap();
                let fresh = make_side(root.path(), "fresh", Side::Fresh(Fresh::TmpOnly));
                let other = make_side(root.path(), "other", counterpart);
                let mut leftovers = vec![fresh.join(VERSION_TMP_FILE_NAME)];
                if matches!(counterpart, Side::Fresh(Fresh::TmpOnly)) {
                    leftovers.push(other.join(VERSION_TMP_FILE_NAME));
                }
                for leftover in &leftovers {
                    std::fs::set_permissions(leftover, std::fs::Permissions::from_mode(WRITE_ONLY))
                        .unwrap();
                }
                // A process that ignores file modes, such as one run as root,
                // reads the leftover all the same.
                if std::fs::read(&leftovers[0]).is_ok() {
                    return;
                }
                let marker_before =
                    matches!(counterpart, Side::Marked(_)).then(|| marker_identity(&other));

                let (data_dir, backup_dir) = if leftover_on_data {
                    (&fresh, &other)
                } else {
                    (&other, &fresh)
                };
                let case = format!("{counterpart:?}, leftover on data: {leftover_on_data}");
                migrate_data_dir(data_dir, backup_dir, None)
                    .unwrap_or_else(|e| panic!("{case} must be accepted: {e:#}"));

                assert_initialized(&fresh);
                assert_initialized(&other);
                for dir in [&fresh, &other] {
                    assert!(
                        !dir.join(VERSION_BESIDE_LEFTOVER_FILE_NAME).exists(),
                        "{case}: {}",
                        dir.display()
                    );
                }
                if let Some(identity) = marker_before {
                    assert_eq!(marker_identity(&other), identity, "{case}");
                }
            }
        }
    }

    /// A fresh directory at the name the marker of a fresh directory holding a
    /// leftover is written through, such as `store/VERSION.new` beside a
    /// `store` holding `VERSION.tmp`, is refused, on each side in turn, and
    /// stays missing, while beside a `store` without a leftover it is just a
    /// nested directory and both are initialized.
    #[test]
    fn a_directory_at_the_marker_beside_a_leftover_is_refused() {
        const OVERLAP: &str = "is inside the";

        for outer_state in [Fresh::TmpOnly, Fresh::Empty] {
            for outer_on_data in [true, false] {
                let root = tempfile::tempdir().unwrap();
                let outer = make_side(root.path(), "store", Side::Fresh(outer_state));
                let inner = outer.join(VERSION_BESIDE_LEFTOVER_FILE_NAME);
                let before = dir_state(&outer);

                let (data_dir, backup_dir) = if outer_on_data {
                    (&outer, &inner)
                } else {
                    (&inner, &outer)
                };
                let case = format!("{outer_state:?}, outer on data: {outer_on_data}");
                let result = migrate_data_dir(data_dir, backup_dir, None);

                if matches!(outer_state, Fresh::Empty) {
                    result.unwrap_or_else(|e| panic!("{case} must be accepted: {e:#}"));
                    assert_initialized(&outer);
                    assert_initialized(&inner);
                    continue;
                }
                let message = result
                    .expect_err(&format!("{case} must be refused"))
                    .to_string();
                assert!(
                    message.contains(OVERLAP),
                    "unexpected error for {case}: {message}"
                );
                assert_eq!(dir_state(&outer), before, "{case}");
                assert!(
                    std::fs::symlink_metadata(&inner).is_err(),
                    "{case}: the inner directory must stay missing"
                );
            }
        }
    }

    /// A fresh directory nested inside the other, which holds no leftover,
    /// under any name but `VERSION` and `VERSION.tmp` does not stop either
    /// marker from being written, so both are initialized, on each side in
    /// turn.
    #[test]
    fn nested_fresh_directories_are_initialized() {
        for outer_on_data in [true, false] {
            let root = tempfile::tempdir().unwrap();
            let outer = root.path().join("store");
            let inner = outer.join("backup");

            let (data_dir, backup_dir) = if outer_on_data {
                (&outer, &inner)
            } else {
                (&inner, &outer)
            };
            migrate_data_dir(data_dir, backup_dir, None).unwrap();

            assert_initialized(&outer);
            assert_initialized(&inner);
        }
    }

    /// Marks the child process [`an_empty_path_is_refused`] starts, and names
    /// the fresh directory it passes beside the empty path.
    const EMPTY_PATH_FRESH_DIR_ENV: &str = "REVIEW_DATABASE_EMPTY_PATH_FRESH_DIR";

    /// Tells the child process [`an_empty_path_is_refused`] starts whether the
    /// empty path is the data directory (`data`) or the backup (`backup`).
    const EMPTY_PATH_SIDE_ENV: &str = "REVIEW_DATABASE_EMPTY_PATH_SIDE";

    /// An empty path, which joins to names in the working directory, is
    /// refused before anything is written, on each side in turn and beside
    /// each kind of fresh directory: the working directory's `VERSION` of an
    /// earlier format is kept, and the fresh side gets no `VERSION`.
    ///
    /// The empty path resolves against the working directory, which a test
    /// must not change, so the call runs in a child test process started in a
    /// directory of its own.
    #[test]
    fn an_empty_path_is_refused() {
        const CHILD: &str = "migration::tests::refuse_an_empty_path_in_a_child";

        for fresh in FRESH {
            for empty_on_data in [true, false] {
                let root = tempfile::tempdir().unwrap();
                let cwd = make_side(root.path(), "cwd", Side::Marked("0.62.0"));
                let fresh_dir = make_side(root.path(), "fresh", Side::Fresh(fresh));
                let cwd_before = dir_state(&cwd);
                let fresh_before = dir_state(&fresh_dir);

                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", CHILD, "--ignored", "--test-threads=1"])
                    .current_dir(&cwd)
                    .env(EMPTY_PATH_FRESH_DIR_ENV, &fresh_dir)
                    .env(
                        EMPTY_PATH_SIDE_ENV,
                        if empty_on_data { "data" } else { "backup" },
                    )
                    .output()
                    .unwrap();

                let stdout = String::from_utf8_lossy(&output.stdout);
                assert!(
                    output.status.success(),
                    "the child failed beside {fresh:?}: {stdout}{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(
                    stdout.contains("test result: ok. 1 passed"),
                    "the child must run exactly one test: {stdout}"
                );
                assert_eq!(dir_state(&cwd), cwd_before, "beside {fresh:?}");
                assert_eq!(
                    std::fs::read(cwd.join(VERSION_FILE_NAME)).unwrap(),
                    b"0.62.0"
                );
                assert_eq!(dir_state(&fresh_dir), fresh_before, "{fresh:?}");
            }
        }
    }

    /// The body [`an_empty_path_is_refused`] runs in a child process, in the
    /// working directory it chose.
    #[test]
    #[ignore = "run only as the child process of an_empty_path_is_refused"]
    fn refuse_an_empty_path_in_a_child() {
        let fresh_dir = PathBuf::from(std::env::var_os(EMPTY_PATH_FRESH_DIR_ENV).unwrap());
        let empty = PathBuf::new();
        let side = std::env::var(EMPTY_PATH_SIDE_ENV).unwrap();
        let (data_dir, backup_dir) = match side.as_str() {
            "data" => (&empty, &fresh_dir),
            "backup" => (&fresh_dir, &empty),
            other => panic!("unexpected side {other}"),
        };

        let err = migrate_data_dir(data_dir, backup_dir, None)
            .expect_err("an empty path must be refused");

        assert_eq!(err.to_string(), "cannot read data dir: the path is empty");
    }

    /// A `VERSION` that does not parse is refused, on each side in turn and
    /// whatever the other side holds.
    #[test]
    fn an_unparsable_version_is_refused() {
        const INVALID: &str = "not-a-valid-version";
        for other in [
            Side::Fresh(Fresh::Empty),
            Side::Fresh(Fresh::Missing),
            Side::Fresh(Fresh::TmpOnly),
            Side::Marked(DATABASE_FORMAT_VERSION),
        ] {
            assert_refused(Side::Marked(INVALID), other, "cannot parse VERSION");
            assert_refused(other, Side::Marked(INVALID), "cannot parse VERSION");
        }
    }

    /// Test `read_version_file` and `create_version_file` helper functions.
    #[test]
    fn version_file_helpers() {
        let temp = tempfile::tempdir().unwrap();
        let version_path = temp.path().join("VERSION");

        // Create a version file
        create_version_file(
            &version_path,
            env!("CARGO_PKG_VERSION"),
            Temporary::Create(VERSION_TMP_FILE_NAME),
        )
        .unwrap();

        // Read it back
        let version = read_version_file(&version_path).unwrap();
        assert_eq!(version, Version::parse(env!("CARGO_PKG_VERSION")).unwrap());
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
        write_version(temp.path(), "0.45.0");
        let version_path = temp.path().join(VERSION_FILE_NAME);

        create_version_file(
            &version_path,
            DATABASE_FORMAT_VERSION,
            Temporary::Create(VERSION_TMP_FILE_NAME),
        )
        .unwrap();

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
        const REQUESTED: &str = "0.46.0";

        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        write_version_markers(data_dir.path(), backup_dir.path(), REQUESTED).unwrap();

        let expected = Version::parse(REQUESTED).unwrap().to_string();
        for dir in [data_dir.path(), backup_dir.path()] {
            let marker = std::fs::read_to_string(dir.join(VERSION_FILE_NAME)).unwrap();
            assert_eq!(marker, expected);
        }
    }

    /// Test that missing marker directories, including intermediate
    /// components, are created and receive their markers.
    #[test]
    fn write_version_markers_creates_missing_directories() {
        let root = tempfile::tempdir().unwrap();
        let data_dir = root.path().join("restored").join("data");
        let backup_dir = root.path().join("restored").join("backup");

        write_version_markers(&data_dir, &backup_dir, "0.46.0").unwrap();

        for dir in [&data_dir, &backup_dir] {
            assert!(dir.is_dir());
            assert_eq!(
                std::fs::read_to_string(dir.join(VERSION_FILE_NAME)).unwrap(),
                "0.46.0"
            );
        }
    }

    /// Test that an unparsable version is rejected before any filesystem
    /// change: no directory appears, and an existing marker keeps its
    /// contents.
    #[test]
    fn write_version_markers_rejects_invalid_versions() {
        for invalid in ["", "0.46", "not a version", "0.46.0 ", "0.46.0extra"] {
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
            write_version(existing_data.path(), "0.45.0");
            write_version(existing_backup.path(), "0.45.0");

            assert!(
                write_version_markers(existing_data.path(), existing_backup.path(), invalid)
                    .is_err(),
                "{invalid:?} must be rejected"
            );
            for dir in [existing_data.path(), existing_backup.path()] {
                assert_eq!(
                    std::fs::read_to_string(dir.join(VERSION_FILE_NAME)).unwrap(),
                    "0.45.0",
                    "{invalid:?} must leave the existing marker alone"
                );
                assert!(!dir.join(VERSION_TMP_FILE_NAME).exists());
            }
        }
    }

    /// Test that an existing marker is replaced rather than appended to, even
    /// when it names a newer format or was not stored canonically. This is the
    /// rollback case: the update left both markers at the version being rolled
    /// back from.
    #[test]
    fn write_version_markers_replaces_existing_markers() {
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        write_version(data_dir.path(), DATABASE_FORMAT_VERSION);
        write_version(backup_dir.path(), "0.47.0\n");

        write_version_markers(data_dir.path(), backup_dir.path(), "0.46.0").unwrap();

        for dir in [data_dir.path(), backup_dir.path()] {
            assert_eq!(
                std::fs::read_to_string(dir.join(VERSION_FILE_NAME)).unwrap(),
                "0.46.0"
            );
            assert!(!dir.join(VERSION_TMP_FILE_NAME).exists());
        }
    }

    /// Test that a leftover `VERSION.tmp` is reused by the rollback writer, as
    /// it always has been: the marker renamed from it keeps the leftover's
    /// inode and mode rather than taking the mode the umask gives a new file.
    #[test]
    fn write_version_markers_reuses_a_leftover_temporary() {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        const LEFTOVER_MODE: u32 = 0o600;

        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let mut leftovers = Vec::new();
        for dir in [data_dir.path(), backup_dir.path()] {
            let tmp = dir.join(VERSION_TMP_FILE_NAME);
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(LEFTOVER_MODE)
                .open(&tmp)
                .unwrap()
                .write_all(STALE_TMP)
                .unwrap();
            leftovers.push(std::fs::metadata(&tmp).unwrap().ino());
        }

        write_version_markers(data_dir.path(), backup_dir.path(), "0.46.0").unwrap();

        for (dir, leftover) in [data_dir.path(), backup_dir.path()]
            .into_iter()
            .zip(leftovers)
        {
            let marker = dir.join(VERSION_FILE_NAME);
            assert_eq!(std::fs::read_to_string(&marker).unwrap(), "0.46.0");
            let metadata = std::fs::metadata(&marker).unwrap();
            assert_eq!(metadata.ino(), leftover);
            assert_eq!(metadata.mode() & 0o777, LEFTOVER_MODE);
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

        let err = write_version_markers(&data_dir, &backup_dir, "0.46.0")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("backup directory VERSION"),
            "the error must name the backup directory, got {err}"
        );

        std::fs::remove_file(&backup_dir).unwrap();
        write_version_markers(&data_dir, &backup_dir, "0.46.0").unwrap();

        let data_marker = std::fs::read_to_string(data_dir.join(VERSION_FILE_NAME)).unwrap();
        let backup_marker = std::fs::read_to_string(backup_dir.join(VERSION_FILE_NAME)).unwrap();
        assert_eq!(data_marker, Version::parse("0.46.0").unwrap().to_string());
        assert_eq!(data_marker, backup_marker);
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
        write_version(backup_dir.path(), "0.45.0");

        let err = write_version_markers(&data_dir, backup_dir.path(), "0.46.0")
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("data directory VERSION"),
            "the error must name the data directory, got {err}"
        );
        assert_eq!(
            std::fs::read_to_string(backup_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            "0.45.0",
            "the backup marker must be left alone"
        );
        assert!(!backup_dir.path().join(VERSION_TMP_FILE_NAME).exists());
    }
}
