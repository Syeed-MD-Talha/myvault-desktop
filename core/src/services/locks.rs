//! Cross-process "vault is already open" guard.
//!
//! SQLite's own locking protects the database file, but two connections in the
//! same process (or two windows of the same application) would not be
//! prevented from writing. The guard below is an operating-system file lock on
//! a small marker file derived from the vault path:
//!
//! * on Windows the marker is opened with `share_mode(0)`, so any second
//!   opener fails with a sharing violation,
//! * the lock disappears with the process, so a crash never leaves a stale
//!   lock that blocks the user,
//! * markers live in `%LOCALAPPDATA%\MyVault\locks`, never next to the user's
//!   vault file.

use std::fs::File;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::errors::{VaultError, VaultResult};

/// Holds the open marker file for as long as the vault is open.
#[derive(Debug)]
pub struct VaultLock {
    _file: File,
    pub marker: PathBuf,
}

fn lock_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("MyVault")
        .join("locks")
}

/// Canonical identity of a vault file, even before it has been created.
fn canonical_identity(vault_path: &Path) -> PathBuf {
    if let Ok(p) = vault_path.canonicalize() {
        return p;
    }
    let parent = vault_path
        .parent()
        .and_then(|p| p.canonicalize().ok())
        .unwrap_or_default();
    match vault_path.file_name() {
        Some(name) => parent.join(name),
        None => parent,
    }
}

fn marker_path(vault_path: &Path) -> PathBuf {
    let identity = canonical_identity(vault_path);
    let mut hasher = Sha256::new();
    hasher.update(identity.to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in digest {
        hex.push_str(&format!("{b:02x}"));
    }
    lock_dir().join(format!("{hex}.lock"))
}

impl VaultLock {
    pub fn acquire(vault_path: &Path) -> VaultResult<Self> {
        let dir = lock_dir();
        std::fs::create_dir_all(&dir).map_err(|e| {
            VaultError::Io(format!("cannot prepare the MyVault lock directory: {e}"))
        })?;
        let marker = marker_path(vault_path);
        let file = open_marker(&marker)?;
        Ok(VaultLock {
            _file: file,
            marker,
        })
    }
}

#[cfg(windows)]
fn open_marker(marker: &Path) -> VaultResult<File> {
    use std::os::windows::fs::OpenOptionsExt;

    // ERROR_SHARING_VIOLATION
    const SHARING_VIOLATION: i32 = 32;
    // ERROR_LOCK_VIOLATION
    const LOCK_VIOLATION: i32 = 33;

    let result = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .share_mode(0)
        .open(marker);
    match result {
        Ok(file) => Ok(file),
        Err(e) => {
            let code = e.raw_os_error().unwrap_or(0);
            if code == SHARING_VIOLATION || code == LOCK_VIOLATION {
                Err(VaultError::VaultInUse)
            } else {
                Err(VaultError::Io(format!(
                    "cannot create the vault lock marker: {e}"
                )))
            }
        }
    }
}

#[cfg(not(windows))]
fn open_marker(marker: &Path) -> VaultResult<File> {
    // Best effort on other platforms: create_new fails when another MyVault
    // instance holds the marker.
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(marker)
    {
        Ok(file) => Ok(file),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(VaultError::VaultInUse),
        Err(e) => Err(VaultError::Io(format!(
            "cannot create the vault lock marker: {e}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_acquire_for_the_same_vault_fails() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("sample.vault");
        std::fs::write(&vault, b"x").unwrap();
        let first = VaultLock::acquire(&vault).unwrap();
        match VaultLock::acquire(&vault) {
            Err(VaultError::VaultInUse) => {}
            other => panic!("expected VaultInUse, got {other:?}"),
        }
        drop(first);
        // The operating system releases the lock when the handle closes.
        VaultLock::acquire(&vault).unwrap();
    }

    #[test]
    fn different_vaults_get_different_markers() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.vault");
        let b = dir.path().join("b.vault");
        std::fs::write(&a, b"a").unwrap();
        std::fs::write(&b, b"b").unwrap();
        let la = VaultLock::acquire(&a).unwrap();
        let lb = VaultLock::acquire(&b).unwrap();
        assert_ne!(la.marker, lb.marker);
    }
}
