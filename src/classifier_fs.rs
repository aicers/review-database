use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

pub type Result<T> = std::result::Result<T, ClassifierFsError>;

/// The directory under the data directory that holds every classifier file.
pub(crate) const CLASSIFIERS_DIR: &str = "classifiers";

/// Manages classifier file storage in the file system using computed paths.
///
/// Stores classifier binary data in a hierarchical directory structure:
/// `base_dir/classifiers/model_{id}/classifier_{generation}.bin`
///
/// A model's classifier files are named by its id and a generation number,
/// never by its name: a name may be up to 255 bytes long, which would push
/// `classifier_{name}.bin` past the file system's limit on a file name.
#[derive(Clone, Debug)]
pub(crate) struct ClassifierFileManager {
    base_dir: PathBuf,
}

impl ClassifierFileManager {
    /// Creates a new `ClassifierFileManager` with the specified base directory.
    /// The base directory will be created if it doesn't exist.
    ///
    /// # Errors
    ///
    /// If directory creation fails due to insufficient permissions,
    /// invalid path, I/O errors, etc. during directory creation.
    pub(crate) fn new<P: AsRef<Path>>(base_dir: P) -> Result<Self> {
        let base_dir = base_dir.as_ref().to_path_buf();

        // Validate base directory is not a file
        if base_dir.exists() && !base_dir.is_dir() {
            return Err(ClassifierFsError::NotADirectory(base_dir));
        }

        fs::create_dir_all(&base_dir)
            .map_err(|err| ClassifierFsError::DirectoryCreation(err, base_dir.clone()))?;
        Ok(Self { base_dir })
    }

    /// Returns the `classifiers` directory under the base directory.
    fn classifiers_dir(&self) -> PathBuf {
        self.base_dir.join(CLASSIFIERS_DIR)
    }

    /// Returns the directory holding every classifier file of `model_id`.
    pub(crate) fn model_dir(&self, model_id: u32) -> PathBuf {
        self.classifiers_dir().join(format!("model_{model_id}"))
    }

    /// Creates the file system path for the classifier of `model_id` in
    /// `generation`.
    ///
    /// This is a pure function that generates deterministic paths without checking
    /// if the file actually exists. The path structure is:
    /// `{base_dir}/classifiers/model_{model_id}/classifier_{generation}.bin`
    pub(crate) fn create_classifier_path(&self, model_id: u32, generation: u64) -> PathBuf {
        self.model_dir(model_id)
            .join(format!("classifier_{generation}.bin"))
    }

    /// Stores the classifier of `model_id` in `generation`.
    ///
    /// Data is first written to a temporary file with a unique timestamp
    /// extension, flushed, then renamed to the final location, and the model
    /// directory is flushed after the rename. Callers write each generation's
    /// file before the transaction that makes the database refer to it, so
    /// both flushes are what lets that record survive a crash with its file:
    /// the first keeps the rename from reaching disk ahead of the data, the
    /// second keeps the rename itself. The `classifiers` and `model_{id}`
    /// directories are made durable in their parents the same way, so the
    /// first classifier of a new model survives a crash as well; each parent
    /// is flushed even when the directory already exists, since an earlier
    /// call may have created it and stopped before flushing the parent.
    ///
    /// Callers serialize writes of one model under the store's model-files
    /// lock, so no two writers race for one destination.
    ///
    /// # Errors
    ///
    /// If storage fails due to insufficient disk space, permission denied, I/O
    /// errors during directory creation, file write, rename or flush, etc.
    pub(crate) fn store_classifier(
        &self,
        model_id: u32,
        generation: u64,
        data: &[u8],
    ) -> Result<()> {
        let classifiers_dir = self.classifiers_dir();
        let model_dir = self.model_dir(model_id);
        create_dir_durably(&classifiers_dir, &self.base_dir)?;
        create_dir_durably(&model_dir, &classifiers_dir)?;

        let file_path = self.create_classifier_path(model_id, generation);
        let timestamp = chrono::Utc::now().timestamp_millis();
        let temp_path = file_path.with_extension(timestamp.to_string());

        // Write to temporary file first. The mode is requested here because
        // `rename` installs this inode at the destination, so the finished file
        // ends up with whatever mode the temporary was created with. `0o600`
        // records that the destination holds model data this service writes and
        // reads back under a single account, so nothing else has a reason to
        // open it; a umask may narrow it further. `create_new` is required for
        // the mode to take effect, since it is applied only when `open` creates
        // the file: reopening an existing temporary would keep its old mode.
        let mut temp_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp_path)
            .map_err(|err| ClassifierFsError::FileWrite(err, temp_path.clone()))?;
        temp_file
            .write_all(data)
            .map_err(|err| ClassifierFsError::FileWrite(err, temp_path.clone()))?;

        // Flush before the rename, so that a rename reaching disk ahead of the
        // data cannot leave the record that is about to refer to this file
        // pointing at an empty or truncated classifier.
        temp_file
            .sync_all()
            .map_err(|err| ClassifierFsError::FileWrite(err, temp_path.clone()))?;
        drop(temp_file);

        // Rename to final location
        if let Err(rename_err) = fs::rename(&temp_path, &file_path) {
            // Clean up temp file on failure
            return match fs::remove_file(&temp_path) {
                Ok(()) => Err(ClassifierFsError::FileRename(
                    rename_err, temp_path, file_path,
                )),
                Err(remove_err) => Err(ClassifierFsError::TempFileCleanup(remove_err, temp_path)),
            };
        }

        // Flush the directory entry the rename wrote, so that the file is
        // still there after a crash once the record that refers to it commits.
        sync_dir(&model_dir)
    }

    /// Loads the classifier of `model_id` in `generation`.
    ///
    /// # Errors
    ///
    /// Returns `FileNotFound` if the classifier file does not exist.
    /// If loading fails due to permission denied, I/O errors, corrupted file, etc.
    pub(crate) fn load_classifier(&self, model_id: u32, generation: u64) -> Result<Vec<u8>> {
        let file_path = self.create_classifier_path(model_id, generation);

        // Return error if file doesn't exist
        if !file_path.exists() {
            return Err(ClassifierFsError::FileNotFound(model_id, generation));
        }

        fs::read(&file_path).map_err(|err| ClassifierFsError::FileRead(err, file_path))
    }

    /// Checks if a classifier file exists without loading it.
    ///
    /// This is a synchronous operation that only checks file existence,
    /// not readability or integrity. The file might exist but be unreadable
    /// due to permission issues.
    #[must_use]
    pub(crate) fn classifier_exists(&self, model_id: u32, generation: u64) -> bool {
        self.create_classifier_path(model_id, generation).exists()
    }

    /// Deletes the classifier file of `model_id` in `generation`.
    ///
    /// If the file doesn't exist, this operation succeeds silently.
    ///
    /// # Errors
    ///
    /// If deletion fails due to permission denied, I/O errors, etc.
    pub(crate) fn delete_classifier(&self, model_id: u32, generation: u64) -> Result<()> {
        let file_path = self.create_classifier_path(model_id, generation);
        match fs::remove_file(&file_path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(ClassifierFsError::FileRemoval(err, file_path)),
        }
    }

    /// Deletes the directory of `model_id` with every classifier file in it.
    ///
    /// If the directory doesn't exist, this operation succeeds silently.
    ///
    /// # Errors
    ///
    /// If deletion fails due to permission denied, I/O errors, etc.
    pub(crate) fn delete_model_dir(&self, model_id: u32) -> Result<()> {
        let dir = self.model_dir(model_id);
        match fs::remove_dir_all(&dir) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(ClassifierFsError::FileRemoval(err, dir)),
        }
    }
}

/// Creates `dir` if it is missing, then flushes `parent`, which holds its
/// entry.
///
/// `parent` is flushed even if `dir` already exists: whoever created it may
/// have failed or stopped before flushing, and an entry found in the page
/// cache is not necessarily on disk.
fn create_dir_durably(dir: &Path, parent: &Path) -> Result<()> {
    match fs::create_dir(dir) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
        Err(err) => {
            return Err(ClassifierFsError::ParentDirectoryCreation(
                err,
                dir.to_path_buf(),
            ));
        }
    }
    sync_dir(parent)
}

/// A test's stand-in for a directory flush, called with the directory.
#[cfg(test)]
type SyncDirHook = Box<dyn FnMut(&Path) -> io::Result<()>>;

#[cfg(test)]
thread_local! {
    /// Called with every directory `sync_dir` is about to flush on this
    /// thread; an error it returns is the flush's.
    static SYNC_DIR_HOOK: std::cell::RefCell<Option<SyncDirHook>> =
        const { std::cell::RefCell::new(None) };
}

/// Flushes the entries of the directory at `dir` to disk.
fn sync_dir(dir: &Path) -> Result<()> {
    #[cfg(test)]
    SYNC_DIR_HOOK
        .with_borrow_mut(|hook| hook.as_mut().map_or(Ok(()), |hook| hook(dir)))
        .map_err(|err| ClassifierFsError::DirectorySync(err, dir.to_path_buf()))?;
    fs::File::open(dir)
        .and_then(|dir| dir.sync_all())
        .map_err(|err| ClassifierFsError::DirectorySync(err, dir.to_path_buf()))
}

/// Validates a model name: 1 to 255 bytes, with no path separator, no `..`,
/// no control character and none of `:<>|*?"`.
///
/// # Errors
///
/// Returns `InvalidName` naming the rule `name` breaks.
pub(crate) fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 255 {
        return Err(ClassifierFsError::InvalidName(
            "must be 1-255 bytes".to_string(),
        ));
    }

    if name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err(ClassifierFsError::InvalidName(
            "contains path separators or traversal sequences".to_string(),
        ));
    }

    if name
        .chars()
        .any(|c| c.is_control() || ":<>|*?\"".contains(c))
    {
        return Err(ClassifierFsError::InvalidName(
            "contains forbidden characters".to_string(),
        ));
    }

    Ok(())
}

#[derive(thiserror::Error, Debug)]
pub enum ClassifierFsError {
    #[error("Base path exists but is not a directory: {0}")]
    NotADirectory(PathBuf),

    #[error("Failed to create directories: {1}: {0}")]
    DirectoryCreation(std::io::Error, PathBuf),

    #[error("Invalid name: {0}")]
    InvalidName(String),

    #[error("Failed to create parent directories: {1}: {0}")]
    ParentDirectoryCreation(std::io::Error, PathBuf),

    #[error("Failed to load classifier file: {1}: {0}")]
    FileRead(std::io::Error, PathBuf),

    #[error("Failed to write classifier file: {1}: {0}")]
    FileWrite(std::io::Error, PathBuf),

    #[error("Failed to remove classifier file: {1}: {0}")]
    FileRemoval(std::io::Error, PathBuf),

    #[error("Failed to rename classifier file from {1} to {2}: {0}")]
    FileRename(std::io::Error, PathBuf, PathBuf),

    #[error("classifier file does not exist for model_id: {0}, generation: {1}")]
    FileNotFound(u32, u64),

    #[error("Failed to flush directory: {1}: {0}")]
    DirectorySync(std::io::Error, PathBuf),

    #[error("Failed to remove temp classifier file: {1}: {0}")]
    TempFileCleanup(std::io::Error, PathBuf),
}

#[cfg(test)]
mod tests {
    use std::{os::unix::fs::PermissionsExt, sync::Arc};

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn test_new_creates_directory() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join("test_base");

        assert!(!base_path.exists());

        let manager = ClassifierFileManager::new(&base_path).unwrap();

        assert!(base_path.exists());
        assert_eq!(manager.base_dir, base_path);
    }

    #[test]
    fn test_new_with_existing_directory() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        assert!(base_path.exists());

        let manager = ClassifierFileManager::new(base_path).unwrap();

        assert_eq!(manager.base_dir, base_path);
    }

    #[test]
    fn test_create_classifier_path() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ClassifierFileManager::new(temp_dir.path()).unwrap();

        let path = manager.create_classifier_path(123, 4);
        let expected = temp_dir
            .path()
            .join("classifiers")
            .join("model_123")
            .join("classifier_4.bin");

        assert_eq!(path, expected);
    }

    #[test]
    fn test_store_and_load_classifier() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ClassifierFileManager::new(temp_dir.path()).unwrap();

        let test_data = b"test classifier data";
        let model_id = 456;

        manager.store_classifier(model_id, 1, test_data).unwrap();

        let loaded_data = manager.load_classifier(model_id, 1).unwrap();
        assert_eq!(loaded_data, test_data);
    }

    #[test]
    fn test_generations_are_separate_files() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ClassifierFileManager::new(temp_dir.path()).unwrap();

        manager.store_classifier(3, 1, b"first").unwrap();
        manager.store_classifier(3, 2, b"second").unwrap();

        assert_eq!(manager.load_classifier(3, 1).unwrap(), b"first");
        assert_eq!(manager.load_classifier(3, 2).unwrap(), b"second");
    }

    #[test]
    fn test_store_grants_no_group_or_other_access() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ClassifierFileManager::new(temp_dir.path()).unwrap();

        let model_id = 457;

        manager
            .store_classifier(model_id, 1, b"test classifier data")
            .unwrap();

        let path = manager.create_classifier_path(model_id, 1);
        let mode = fs::metadata(&path).unwrap().permissions().mode();

        // Only the absence of group and other bits is asserted: a umask can
        // clear bits but never add them, so this holds whatever the umask is,
        // while the exact mode does not.
        assert_eq!(mode & 0o077, 0, "unexpected mode {mode:o} for {path:?}");
    }

    #[test]
    fn test_store_replaces_a_group_readable_file() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ClassifierFileManager::new(temp_dir.path()).unwrap();

        let model_id = 458;

        // Stand in for a leftover of an earlier model under the same id,
        // written group- and other-readable.
        let path = manager.create_classifier_path(model_id, 1);
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        fs::write(&path, b"stale data").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        manager
            .store_classifier(model_id, 1, b"fresh data")
            .unwrap();

        // The rename installs the temporary's inode, so the destination takes
        // the temporary's mode rather than keeping the one it had.
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "unexpected mode {mode:o} for {path:?}");
        assert_eq!(manager.load_classifier(model_id, 1).unwrap(), b"fresh data");

        // The rename consumed the temporary, so the classifier is the only
        // file left in the model directory.
        let leftovers: Vec<_> = fs::read_dir(parent)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(leftovers, vec![path]);
    }

    #[test]
    fn test_load_nonexistent_classifier() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ClassifierFileManager::new(temp_dir.path()).unwrap();

        let result = manager.load_classifier(999, 7);
        assert!(matches!(
            result,
            Err(ClassifierFsError::FileNotFound(999, 7))
        ));
    }

    #[test]
    fn test_classifier_exists() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ClassifierFileManager::new(temp_dir.path()).unwrap();

        assert!(!manager.classifier_exists(123, 1));

        let path = manager.create_classifier_path(123, 1);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"test data").unwrap();

        assert!(manager.classifier_exists(123, 1));
        assert!(!manager.classifier_exists(123, 2));
    }

    #[test]
    fn test_delete_classifier() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ClassifierFileManager::new(temp_dir.path()).unwrap();

        let model_id = 789;
        let test_data = b"data to delete";

        manager.store_classifier(model_id, 1, test_data).unwrap();
        manager.store_classifier(model_id, 2, test_data).unwrap();
        assert!(manager.classifier_exists(model_id, 1));

        manager.delete_classifier(model_id, 1).unwrap();
        assert!(!manager.classifier_exists(model_id, 1));
        assert!(manager.classifier_exists(model_id, 2));
    }

    #[test]
    fn test_delete_nonexistent_classifier() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ClassifierFileManager::new(temp_dir.path()).unwrap();

        let result = manager.delete_classifier(999, 1);
        assert!(result.is_ok());
    }

    #[test]
    fn test_delete_model_dir() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ClassifierFileManager::new(temp_dir.path()).unwrap();

        manager.store_classifier(5, 1, b"one").unwrap();
        manager.store_classifier(5, 2, b"two").unwrap();
        manager.store_classifier(6, 1, b"other").unwrap();

        manager.delete_model_dir(5).unwrap();
        assert!(!manager.model_dir(5).exists());
        assert_eq!(manager.load_classifier(6, 1).unwrap(), b"other");

        // A missing directory is not an error.
        manager.delete_model_dir(5).unwrap();
    }

    #[test]
    fn test_store_creates_parent_directories() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ClassifierFileManager::new(temp_dir.path()).unwrap();

        let model_id = 111;
        let test_data = b"nested data";

        manager.store_classifier(model_id, 1, test_data).unwrap();

        let expected_parent = temp_dir.path().join("classifiers").join("model_111");
        assert!(expected_parent.exists());

        let loaded_data = manager.load_classifier(model_id, 1).unwrap();
        assert_eq!(loaded_data, test_data);
    }

    #[test]
    fn test_store_flushes_parents_left_unflushed() {
        use std::{cell::RefCell, rc::Rc};

        let temp_dir = TempDir::new().unwrap();
        let manager = ClassifierFileManager::new(temp_dir.path()).unwrap();
        let classifiers_dir = temp_dir.path().join("classifiers");
        let model_dir = classifiers_dir.join("model_7");

        // The first store creates `classifiers/model_7`, then fails flushing
        // `classifiers`, which gained its entry.
        let failing = classifiers_dir.clone();
        SYNC_DIR_HOOK.set(Some(Box::new(move |dir| {
            if dir == failing {
                Err(io::Error::other("injected"))
            } else {
                Ok(())
            }
        })));
        let failed = manager.store_classifier(7, 1, b"first");
        assert!(matches!(
            failed,
            Err(ClassifierFsError::DirectorySync(_, ref dir)) if *dir == classifiers_dir
        ));
        assert!(model_dir.is_dir());
        assert!(!manager.classifier_exists(7, 1));

        // The retry finds both directories and still flushes their parents
        // before the file's own directory.
        let synced = Rc::new(RefCell::new(Vec::new()));
        let record = Rc::clone(&synced);
        SYNC_DIR_HOOK.set(Some(Box::new(move |dir| {
            record.borrow_mut().push(dir.to_path_buf());
            Ok(())
        })));
        manager.store_classifier(7, 1, b"first").unwrap();
        SYNC_DIR_HOOK.set(None);
        assert_eq!(
            *synced.borrow(),
            [
                temp_dir.path().to_path_buf(),
                classifiers_dir.clone(),
                model_dir.clone(),
            ]
        );
        assert_eq!(manager.load_classifier(7, 1).unwrap(), b"first");
    }

    #[test]
    fn test_invalid_names() {
        assert!(validate_name("").is_err());
        assert!(validate_name(&"a".repeat(256)).is_err());
        assert!(validate_name("../../../test/path").is_err());
        assert!(validate_name("test/path").is_err());
        assert!(validate_name("test\\path").is_err());
        assert!(validate_name("test:name").is_err());
        assert!(validate_name("test*name").is_err());
        assert!(validate_name("test<name").is_err());
        assert!(validate_name("test>name").is_err());
        assert!(validate_name("test|name").is_err());
        assert!(validate_name("test?name").is_err());
        assert!(validate_name("test\"name").is_err());
        assert!(validate_name("test\nname").is_err());

        assert!(validate_name("valid_name").is_ok());
        assert!(validate_name("valid-name").is_ok());
        assert!(validate_name("valid.name").is_ok());
        assert!(validate_name("valid_name_123").is_ok());
        assert!(validate_name(&"a".repeat(255)).is_ok());
    }

    #[test]
    fn test_concurrent_stores() {
        use std::thread;

        let temp_dir = TempDir::new().unwrap();
        let manager = Arc::new(ClassifierFileManager::new(temp_dir.path()).unwrap());

        let handles: Vec<_> = (0..10_u32)
            .map(|i| {
                let manager = Arc::clone(&manager);
                let data = format!("data_{i}").into_bytes();
                thread::spawn(move || manager.store_classifier(i, 1, &data))
            })
            .collect();

        for handle in handles {
            handle.join().unwrap().unwrap();
        }

        for i in 0..10 {
            assert_eq!(
                manager.load_classifier(i, 1).unwrap(),
                format!("data_{i}").into_bytes()
            );
        }
    }

    #[test]
    fn test_new_with_file_as_base_dir() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("not_a_directory");
        std::fs::write(&file_path, b"test").unwrap();

        let result = ClassifierFileManager::new(&file_path);
        assert!(result.is_err());
    }
}
