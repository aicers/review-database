use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

pub type Result<T> = std::result::Result<T, ClassifierFsError>;

/// Manages classifier file storage in the file system using computed paths.
///
/// Stores classifier binary data in a hierarchical directory structure:
/// `base_dir/classifiers/model_{id}/classifier_{name}.bin`
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

    /// Creates the file system path for a classifier based on model id and name.
    ///
    /// This is a pure function that generates deterministic paths without checking
    /// if the file actually exists. The path structure is:
    /// `{base_dir}/classifiers/model_{model_id}/classifier_{name}.bin`
    ///
    /// # Errors
    ///
    /// If the name contains invalid characters.
    pub(crate) fn create_classifier_path(&self, model_id: u32, name: &str) -> Result<PathBuf> {
        validate_name(name)?;

        Ok(self
            .base_dir
            .join("classifiers")
            .join(format!("model_{model_id}"))
            .join(format!("classifier_{name}.bin")))
    }

    /// Stores classifier data to the file system.
    ///
    /// Data is first written to a temporary file with a unique timestamp
    /// extension, then renamed to the final location.
    ///
    /// Note that since `REview` only supports a single `REconverge`, it is
    /// highly unlikely that `review-database` receives multiple write requests
    /// for the same classifier simultaneously.
    ///
    /// # Errors
    ///
    /// If storage fails due to insufficient disk space, permission denied, I/O
    /// errors during directory creation, file write, or rename, or concurrent
    /// access conflicts (rare with timestamp-based temp files), etc.
    pub(crate) fn store_classifier(&self, model_id: u32, name: &str, data: &[u8]) -> Result<()> {
        let file_path = self.create_classifier_path(model_id, name)?;

        // Create parent directories if they don't exist
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                ClassifierFsError::ParentDirectoryCreation(err, file_path.clone())
            })?;
        }

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

        // Flush before the rename. `upsert_model` has already committed the
        // model row to RocksDB, and `load_model_by_name` reads this file back
        // for that row, so a rename reaching disk ahead of the data would leave
        // the model pointing at an empty or truncated classifier.
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

        Ok(())
    }

    /// Loads classifier data from the file system.
    ///
    /// # Errors
    ///
    /// Returns `FileNotFound` if the classifier file does not exist.
    /// If loading fails due to permission denied, I/O errors, corrupted file, etc.
    pub(crate) fn load_classifier(&self, model_id: u32, name: &str) -> Result<Vec<u8>> {
        let file_path = self.create_classifier_path(model_id, name)?;

        // Return error if file doesn't exist
        if !file_path.exists() {
            return Err(ClassifierFsError::FileNotFound(model_id, name.to_string()));
        }

        fs::read(&file_path).map_err(|err| ClassifierFsError::FileRead(err, file_path))
    }

    /// Checks if a classifier file exists without loading it.
    ///
    /// This is a synchronous operation that only checks file existence,
    /// not readability or integrity. The file might exist but be unreadable
    /// due to permission issues.
    #[must_use]
    pub(crate) fn classifier_exists(&self, model_id: u32, name: &str) -> bool {
        let Ok(file_path) = self.create_classifier_path(model_id, name) else {
            return false;
        };
        file_path.exists()
    }

    /// Deletes a classifier file from the file system.
    ///
    /// If the file doesn't exist, this operation succeeds silently.
    ///
    /// # Errors
    ///
    /// If deletion fails due to permission denied, I/O errors, etc.
    pub(crate) fn delete_classifier(&self, model_id: u32, name: &str) -> Result<()> {
        let file_path = self.create_classifier_path(model_id, name)?;

        // Only attempt deletion if file exists
        if file_path.exists() {
            fs::remove_file(&file_path)
                .map_err(|err| ClassifierFsError::FileRemoval(err, file_path))?;
        }

        Ok(())
    }
}

/// Validates classifier name to prevent characters that could cause issues.
fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 255 {
        return Err(ClassifierFsError::InvalidName(
            "must be 1-255 characters".to_string(),
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

    #[error("classifier file does not exist for model_id: {0}, name = '{1}'")]
    FileNotFound(u32, String),

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

        let path = manager
            .create_classifier_path(123, "test_classifier")
            .unwrap();
        let expected = temp_dir
            .path()
            .join("classifiers")
            .join("model_123")
            .join("classifier_test_classifier.bin");

        assert_eq!(path, expected);
    }

    #[test]
    fn test_store_and_load_classifier() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ClassifierFileManager::new(temp_dir.path()).unwrap();

        let test_data = b"test classifier data";
        let model_id = 456;
        let name = "test_model";

        manager.store_classifier(model_id, name, test_data).unwrap();

        let loaded_data = manager.load_classifier(model_id, name).unwrap();
        assert_eq!(loaded_data, test_data);
    }

    #[test]
    fn test_store_grants_no_group_or_other_access() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ClassifierFileManager::new(temp_dir.path()).unwrap();

        let model_id = 457;
        let name = "permission_test";

        manager
            .store_classifier(model_id, name, b"test classifier data")
            .unwrap();

        let path = manager.create_classifier_path(model_id, name).unwrap();
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
        let name = "replacement_test";

        // Stand in for a classifier left by an earlier release, which wrote
        // through `fs::write` and so ended up group- and other-readable.
        let path = manager.create_classifier_path(model_id, name).unwrap();
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        fs::write(&path, b"stale data").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        manager
            .store_classifier(model_id, name, b"fresh data")
            .unwrap();

        // The rename installs the temporary's inode, so the destination takes
        // the temporary's mode rather than keeping the one it had.
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "unexpected mode {mode:o} for {path:?}");
        assert_eq!(
            manager.load_classifier(model_id, name).unwrap(),
            b"fresh data"
        );

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

        let result = manager.load_classifier(999, "nonexistent");
        assert!(matches!(
            result,
            Err(ClassifierFsError::FileNotFound(999, name)) if name == "nonexistent"
        ));
    }

    #[test]
    fn test_classifier_exists() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ClassifierFileManager::new(temp_dir.path()).unwrap();

        assert!(!manager.classifier_exists(123, "test"));

        let path = manager.create_classifier_path(123, "test").unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"test data").unwrap();

        assert!(manager.classifier_exists(123, "test"));
    }

    #[test]
    fn test_delete_classifier() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ClassifierFileManager::new(temp_dir.path()).unwrap();

        let model_id = 789;
        let name = "delete_test";
        let test_data = b"data to delete";

        manager.store_classifier(model_id, name, test_data).unwrap();
        assert!(manager.classifier_exists(model_id, name));

        manager.delete_classifier(model_id, name).unwrap();
        assert!(!manager.classifier_exists(model_id, name));
    }

    #[test]
    fn test_delete_nonexistent_classifier() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ClassifierFileManager::new(temp_dir.path()).unwrap();

        let result = manager.delete_classifier(999, "nonexistent");
        assert!(result.is_ok());
    }

    #[test]
    fn test_store_creates_parent_directories() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ClassifierFileManager::new(temp_dir.path()).unwrap();

        let model_id = 111;
        let name = "nested_test";
        let test_data = b"nested data";

        manager.store_classifier(model_id, name, test_data).unwrap();

        let expected_parent = temp_dir.path().join("classifiers").join("model_111");
        assert!(expected_parent.exists());

        let loaded_data = manager.load_classifier(model_id, name).unwrap();
        assert_eq!(loaded_data, test_data);
    }

    #[test]
    fn test_invalid_names() {
        assert!(validate_name("").is_err());
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

        assert!(validate_name("valid_name").is_ok());
        assert!(validate_name("valid-name").is_ok());
        assert!(validate_name("valid.name").is_ok());
        assert!(validate_name("valid_name_123").is_ok());
    }

    #[test]
    fn test_concurrent_stores() {
        use std::thread;

        let temp_dir = TempDir::new().unwrap();
        let manager = Arc::new(ClassifierFileManager::new(temp_dir.path()).unwrap());

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let manager = Arc::clone(&manager);
                let data = format!("data_{i}").into_bytes();
                thread::spawn(move || manager.store_classifier(1, &format!("test_{i}"), &data))
            })
            .collect();

        for handle in handles {
            handle.join().unwrap().unwrap();
        }

        for i in 0..10 {
            assert!(manager.classifier_exists(1, &format!("test_{i}")));
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
