//! Short-lived decrypted copies used to open a file in its default Windows
//! application.
//!
//! Windows applications need a real plaintext file, so "opening" an encrypted
//! file necessarily creates one. The rules enforced here are:
//!
//! * copies live only under `%LOCALAPPDATA%\MyVault\open`, never next to the
//!   user's documents and never inside the vault folder,
//! * the area is marked as MyVault-owned and is never used if the marker is
//!   missing (so a misconfigured path cannot cause files to be deleted),
//! * leftovers from a crashed process are removed on the next unlock,
//! * every copy is removed when the vault is locked and when the application
//!   exits.
//!
//! Residual risk is documented in `SECURITY.md`: a hard kill of the process, a
//! system crash or a copy made by another program while the file is open can
//! outlive the deletion window.

use std::path::{Path, PathBuf};

use crate::errors::{VaultError, VaultResult};
use crate::services::paths;
use crate::services::progress::NoopContext;
use crate::services::transfer;
use crate::services::vault::Vault;
use crate::storage::manifest::Entry;

/// Marker that proves the directory belongs to MyVault.
pub const OWNER_MARKER: &str = ".myvault-open";

/// A decrypted copy that is about to be handed to an external application.
#[derive(Debug, Clone)]
pub struct TempOpenFile {
    pub path: PathBuf,
    pub name: String,
    /// Human-readable warnings to show before opening.
    pub warnings: Vec<String>,
}

/// The area where short-lived decrypted copies are written.
#[derive(Debug, Clone)]
pub struct TempOpenArea {
    root: PathBuf,
}

impl TempOpenArea {
    pub fn new(root: PathBuf) -> Self {
        TempOpenArea { root }
    }

    /// `%LOCALAPPDATA%\MyVault\open`, or a temporary directory when the
    /// environment variable is unavailable.
    pub fn default_area() -> Self {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        TempOpenArea {
            root: base.join("MyVault").join("open"),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Prepare the area and sweep leftovers from a previous run.
    ///
    /// Returns the number of entries removed.
    pub fn prepare(&self) -> VaultResult<usize> {
        if self.root.exists() && !self.root.join(OWNER_MARKER).is_file() {
            return Err(VaultError::IllegalState(
                "the MyVault temporary folder exists but is not owned by MyVault".into(),
            ));
        }
        std::fs::create_dir_all(&self.root).map_err(|e| {
            VaultError::Io(format!("cannot create the temporary folder: {e}"))
        })?;
        let marker = self.root.join(OWNER_MARKER);
        if !marker.is_file() {
            std::fs::write(
                &marker,
                b"MyVault temporary decrypted files.\nThese files are deleted when the vault is locked or MyVault exits.\n",
            )
            .map_err(|e| VaultError::Io(format!("cannot mark the temporary folder: {e}")))?;
        }
        Ok(self.remove_contents())
    }

    /// Remove every child of the area, keeping the marker. Returns the number
    /// of removed entries.
    pub fn remove_contents(&self) -> usize {
        let mut removed = 0usize;
        let read = match std::fs::read_dir(&self.root) {
            Ok(read) => read,
            Err(_) => return 0,
        };
        for item in read.flatten() {
            if item.file_name() == OWNER_MARKER {
                continue;
            }
            let path = item.path();
            let result = if path.is_dir() {
                std::fs::remove_dir_all(&path)
            } else {
                std::fs::remove_file(&path)
            };
            if result.is_ok() {
                removed += 1;
            }
        }
        removed
    }

    /// Delete all decrypted copies. Safe to call repeatedly and from a
    /// shutdown handler.
    pub fn remove_all(&self) -> usize {
        self.remove_contents()
    }

    fn session_dir(&self, vault_id_hex: &str) -> PathBuf {
        let short = &vault_id_hex[..vault_id_hex.len().min(16)];
        self.root.join(short)
    }

    /// Decrypt one file into the temporary area and return its path.
    ///
    /// The caller is responsible for opening the file and for eventually
    /// calling [`TempOpenArea::remove_all`] (done on lock and on exit).
    pub fn open_entry(&self, vault: &Vault, entry: &Entry) -> VaultResult<TempOpenFile> {
        if entry.is_dir() {
            return Err(VaultError::WrongEntryKind);
        }
        let vault_id: String = vault
            .header
            .vault_id
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let session = self.session_dir(&vault_id);

        if !session.exists() {
            // First open in this session: clear leftovers from earlier runs.
            self.prepare()?;
        }
        std::fs::create_dir_all(&session)?;

        transfer::export_entries(vault, &[entry.id], &session, true, &NoopContext)?;

        let name = paths::sanitize_export_name(&entry.name)?;
        let path = paths::safe_join(&session, &name)?;
        if !path.is_file() {
            return Err(VaultError::Internal(
                "the decrypted copy was not written".into(),
            ));
        }

        let mut warnings = Vec::new();
        warnings.push(
            "Other programs can read this decrypted copy while it exists.".to_string(),
        );
        if entry.size > 0 && entry.size < 4096 {
            warnings.push(
                "The file is very small; Windows may store its final bytes in a file-system record that persists after deletion."
                    .to_string(),
            );
        }
        if crate::services::paths::hibernation_or_compression_enabled() {
            warnings.push(
                "Windows paging, hibernation or memory compression is enabled, so copies of the plaintext may remain in system-managed files."
                    .to_string(),
            );
        }

        Ok(TempOpenFile {
            path,
            name,
            warnings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::vault::{Vault, VaultOptions};
    use crate::storage::manifest::ROOT_ID;
    use crate::{KdfParams, NoopContext as Noop};

    fn fast_options() -> VaultOptions {
        VaultOptions {
            kdf_params: KdfParams {
                m_cost_kib: 8 * 1024,
                t_cost: 1,
                p_cost: 1,
                key_len: 32,
            },
            chunk_size: 64 * 1024,
        }
    }

    const PASSWORD: &str = "correct horse battery staple";

    fn setup() -> (tempfile::TempDir, Vault, TempOpenArea) {
        let dir = tempfile::tempdir().unwrap();
        let area_dir = tempfile::tempdir().unwrap();
        let vault = Vault::create_with_options(
            dir.path().join("t.vault"),
            PASSWORD,
            fast_options(),
        )
        .unwrap();
        let area = TempOpenArea::new(area_dir.path().join("open"));
        // Leak the temp dirs so the paths stay valid for the test body.
        (dir, vault, area)
    }

    #[test]
    fn area_is_marked_and_created() {
        let (_dir, _vault, area) = setup();
        assert_eq!(area.prepare().unwrap(), 0);
        assert!(area.root().join(OWNER_MARKER).is_file());
        assert_eq!(area.remove_contents(), 0);
    }

    #[test]
    fn refuses_to_use_a_foreign_directory() {
        let (_dir, _vault, area) = setup();
        std::fs::create_dir_all(area.root()).unwrap();
        let foreign = area.root().join("important.txt");
        std::fs::write(&foreign, b"do not delete me").unwrap();

        let error = area.prepare().unwrap_err();
        assert!(matches!(error, VaultError::IllegalState(_)));
        assert!(foreign.is_file(), "a foreign file must never be deleted");
        assert_eq!(std::fs::read(&foreign).unwrap(), b"do not delete me");
    }

    #[test]
    fn opening_a_file_writes_the_exact_plaintext() {
        let (dir, mut vault, area) = setup();
        let src = tempfile::tempdir().unwrap();
        let payload: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
        let source = src.path().join("report.pdf");
        std::fs::write(&source, &payload).unwrap();
        vault.import_paths(&[source], &ROOT_ID, false, &Noop).unwrap();

        let id =
            crate::services::vault::parse_id(&vault.list_directory(None).unwrap()[0].id).unwrap();
        let entry = vault.manifest.get(&id).unwrap().clone();

        let opened = area.open_entry(&vault, &entry).unwrap();
        assert_eq!(opened.name, "report.pdf");
        assert!(opened.path.starts_with(area.root()));
        assert_eq!(std::fs::read(&opened.path).unwrap(), payload);
        assert!(!opened.warnings.is_empty());

        assert_eq!(area.remove_all(), 1);
        assert!(!opened.path.exists());
        assert!(area.root().join(OWNER_MARKER).is_file());
        drop(dir);
    }

    #[test]
    fn empty_files_open_as_empty_copies() {
        let (dir, mut vault, area) = setup();
        let src = tempfile::tempdir().unwrap();
        let source = src.path().join("empty.txt");
        std::fs::write(&source, b"").unwrap();
        vault
            .import_paths(&[source], &ROOT_ID, false, &Noop)
            .unwrap();
        let id =
            crate::services::vault::parse_id(&vault.list_directory(None).unwrap()[0].id).unwrap();
        let entry = vault.manifest.get(&id).unwrap().clone();
        let opened = area.open_entry(&vault, &entry).unwrap();
        assert_eq!(std::fs::read(&opened.path).unwrap(), Vec::<u8>::new());
        drop(dir);
    }

    #[test]
    fn directories_cannot_be_opened() {
        let (dir, mut vault, area) = setup();
        let created = vault.create_directory(&ROOT_ID, "Docs").unwrap();
        let id = crate::services::vault::parse_id(&created.id).unwrap();
        let entry = vault.manifest.get(&id).unwrap().clone();
        assert_eq!(
            area.open_entry(&vault, &entry).unwrap_err(),
            VaultError::WrongEntryKind
        );
        drop(dir);
    }

    #[test]
    fn leftover_copies_are_removed_on_the_next_prepare() {
        let (_dir, _vault, area) = setup();
        area.prepare().unwrap();
        let leftover = area.root().join("old-session").join("secret.txt");
        std::fs::create_dir_all(leftover.parent().unwrap()).unwrap();
        std::fs::write(&leftover, b"leftover").unwrap();

        assert_eq!(area.prepare().unwrap(), 1);
        assert!(!leftover.exists());
    }
}
