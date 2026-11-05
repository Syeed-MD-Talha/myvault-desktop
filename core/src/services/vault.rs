//! High-level vault lifecycle: create, open, unlock, lock, and the virtual
//! file-system operations that do not move bulk data.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use subtle::ConstantTimeEq;

use crate::crypto::{cipher, derive_kek, random_bytes, validate_password_strength, KdfParams, SALT_LEN};
use crate::errors::{VaultError, VaultResult};
use crate::services::paths;
use crate::services::progress::{NoopContext, OpContext};
use crate::services::transfer;
use crate::storage::chunks;
use crate::storage::db;
use crate::storage::header::{self, VaultHeader, FORMAT_VERSION};
use crate::storage::manifest::{
    self, validate_name, Entry, EntryKind, Id, Manifest, MANIFEST_VERSION, ROOT_ID,
};

/// Tunables applied when creating a vault. Tests use cheap KDF parameters.
#[derive(Debug, Clone)]
pub struct VaultOptions {
    pub kdf_params: KdfParams,
    pub chunk_size: usize,
}

impl Default for VaultOptions {
    fn default() -> Self {
        VaultOptions {
            kdf_params: KdfParams::default(),
            chunk_size: chunks::DEFAULT_CHUNK_SIZE,
        }
    }
}

/// A vault whose header has been read but which is still locked.
pub struct OpenedVault {
    pub(crate) conn: Connection,
    pub(crate) path: PathBuf,
    pub(crate) header: VaultHeader,
    pub(crate) _lock: crate::services::locks::VaultLock,
}

impl std::fmt::Debug for OpenedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedVault")
            .field("path", &self.path)
            .field("format_version", &self.header.format_version)
            .finish_non_exhaustive()
    }
}

/// A serializable directory entry for the UI. Contains no key material.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryView {
    pub id: String,
    pub parent_id: String,
    pub name: String,
    /// `"directory"` or `"file"`.
    pub kind: String,
    pub size: u64,
    pub created_ms: u64,
    pub modified_ms: u64,
    pub chunk_count: usize,
    /// Virtual path relative to the vault root, e.g. `Documents/report.pdf`.
    pub path: String,
}

impl EntryView {
    fn from_entry(manifest: &Manifest, index: &HashMap<Id, usize>, e: &Entry) -> Self {
        let path = manifest
            .path_of_with(index, &e.id)
            .unwrap_or_default()
            .join("/");
        EntryView {
            id: id_hex(&e.id),
            parent_id: id_hex(&e.parent),
            name: e.name.clone(),
            kind: if e.is_dir() { "directory" } else { "file" }.into(),
            size: e.size,
            created_ms: e.created_ms,
            modified_ms: e.modified_ms,
            chunk_count: e.chunks.len(),
            path,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Crumb {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultInfo {
    pub path: String,
    pub name: String,
    pub vault_id: String,
    pub root_id: String,
    pub format_version: u16,
    pub created_ms: u64,
    pub entries: u64,
    pub files: u64,
    pub directories: u64,
    pub chunks: u64,
    pub stored_bytes: u64,
    pub plaintext_bytes: u64,
    pub chunk_size: usize,
    pub kdf: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockResult {
    pub unlock_ms: u64,
    pub info: VaultInfo,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteReport {
    pub deleted_entries: u64,
    pub deleted_chunks: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IntegrityReport {
    pub ok: bool,
    pub entries_checked: u64,
    pub chunks_checked: u64,
    pub bytes_checked: u64,
    pub orphan_chunks: u64,
    pub issues: Vec<String>,
}

fn id_hex(id: &Id) -> String {
    let mut s = String::with_capacity(32);
    for b in id {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Parse a 32-character hex entry id. Any other input is rejected instead of
/// being silently coerced.
pub fn parse_id(value: &str) -> VaultResult<Id> {
    let value = value.trim();
    if value.len() != 32 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(VaultError::InvalidPath("malformed item id".into()));
    }
    let mut id = [0u8; 16];
    for (i, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
            .map_err(|_| VaultError::InvalidPath("malformed item id".into()))?;
    }
    Ok(id)
}

fn read_sealed_manifest(conn: &Connection) -> VaultResult<manifest::SealedManifest> {
    let row: Option<(Vec<u8>, Vec<u8>)> = conn
        .query_row(
            "SELECT nonce, ciphertext FROM encrypted_manifest WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (nonce, ciphertext) = row.ok_or(VaultError::CorruptManifest)?;
    if nonce.len() != cipher::NONCE_LEN {
        return Err(VaultError::CorruptManifest);
    }
    let mut n = [0u8; cipher::NONCE_LEN];
    n.copy_from_slice(&nonce);
    Ok(manifest::SealedManifest {
        nonce: n,
        ciphertext,
    })
}

/// Write (or replace) the single encrypted manifest row.
pub(crate) fn write_manifest(
    conn: &Connection,
    manifest_key: &[u8; cipher::KEY_LEN],
    vault_id: &Id,
    manifest: &Manifest,
) -> VaultResult<()> {
    let sealed = manifest::seal_manifest(manifest_key, vault_id, manifest)?;
    conn.execute(
        "INSERT INTO encrypted_manifest (id, nonce, ciphertext, updated_ms) VALUES (1, ?1, ?2, ?3) \
         ON CONFLICT(id) DO UPDATE SET nonce = excluded.nonce, \
         ciphertext = excluded.ciphertext, updated_ms = excluded.updated_ms",
        params![&sealed.nonce[..], sealed.ciphertext, crate::now_ms() as i64],
    )?;
    Ok(())
}

impl OpenedVault {
    /// Open an existing container without decrypting anything secret.
    pub fn open(path: impl AsRef<Path>) -> VaultResult<Self> {
        let path = path.as_ref();
        if !path.is_file() {
            return Err(VaultError::NotAVault);
        }
        let lock = crate::services::locks::VaultLock::acquire(path)?;
        let conn = db::open_exclusive(path)?;
        if !db::is_initialized(&conn)? {
            return Err(VaultError::NotAVault);
        }
        db::check_schema(&conn)?;
        let header = VaultHeader::read(&conn)?;
        if header.format_version != FORMAT_VERSION {
            return Err(VaultError::UnsupportedVersion(header.format_version));
        }
        Ok(OpenedVault {
            conn,
            path: path.to_path_buf(),
            header,
            _lock: lock,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn vault_id(&self) -> Id {
        self.header.vault_id
    }

    pub fn format_version(&self) -> u16 {
        self.header.format_version
    }

    /// Cheap public information available before unlocking (nothing sensitive).
    pub fn name_hint(&self) -> String {
        self.path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "Vault".into())
    }

    /// Derive the KEK and try to unwrap the vault master key. Only a
    /// successful authenticated decryption proves the password is correct.
    pub fn unlock(self, password: &str) -> VaultResult<Vault> {
        let started = Instant::now();
        let kek = derive_kek(password.as_bytes(), &self.header.kdf_salt, &self.header.kdf_params)?;
        let master = header::unwrap_master_key(&kek, &self.header)?;
        let sealed = read_sealed_manifest(&self.conn)?;
        let manifest = manifest::open_manifest(master.manifest_key(), &self.header.vault_id, &sealed)?;
        manifest.validate()?;
        let vault = Vault {
            conn: self.conn,
            path: self.path,
            header: self.header,
            master,
            manifest,
            chunk_size: chunks::DEFAULT_CHUNK_SIZE,
            unlock_ms: started.elapsed().as_millis() as u64,
            _lock: self._lock,
        };
        // Reclaim any chunks left behind by a crash between chunk commit and
        // manifest commit.
        let referenced = vault.manifest.referenced_chunk_ids();
        chunks::delete_orphans(&vault.conn, &referenced)?;
        Ok(vault)
    }
}

/// An unlocked vault. Dropping it zeroizes the key material.
pub struct Vault {
    pub(crate) conn: Connection,
    pub(crate) path: PathBuf,
    pub(crate) header: VaultHeader,
    pub(crate) master: crate::crypto::VaultMasterKey,
    pub(crate) manifest: Manifest,
    pub(crate) chunk_size: usize,
    unlock_ms: u64,
    pub(crate) _lock: crate::services::locks::VaultLock,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("entries", &self.manifest.entries.len())
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Create a new encrypted vault. Never overwrites an existing file.
    pub fn create(path: impl AsRef<Path>, password: &str) -> VaultResult<Self> {
        Self::create_with_options(path, password, VaultOptions::default())
    }

    pub fn create_with_options(
        path: impl AsRef<Path>,
        password: &str,
        options: VaultOptions,
    ) -> VaultResult<Self> {
        validate_password_strength(password)?;
        chunks::validate_chunk_size(options.chunk_size)?;
        options.kdf_params.validate()?;

        let path = path.as_ref();
        if path.exists() {
            return Err(VaultError::IllegalState(
                "a file already exists at that location; choose another name".into(),
            ));
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.is_dir() {
                return Err(VaultError::InvalidPath(
                    "the destination folder does not exist".into(),
                ));
            }
        }

        let lock = crate::services::locks::VaultLock::acquire(path)?;
        let result = Self::create_inner(path, password, options, lock);
        if result.is_err() {
            // Do not leave a half-written container behind.
            let _ = std::fs::remove_file(path);
        }
        result
    }

    fn create_inner(
        path: &Path,
        password: &str,
        options: VaultOptions,
        lock: crate::services::locks::VaultLock,
    ) -> VaultResult<Self> {
        let conn = db::open(path)?;
        db::initialize(&conn)?;

        let master = crate::crypto::VaultMasterKey::generate();
        let salt = random_bytes::<SALT_LEN>();
        let kek = derive_kek(password.as_bytes(), &salt, &options.kdf_params)?;
        let vault_id = random_bytes::<16>();
        let (key_nonce, wrapped) = header::wrap_master_key(&kek, &vault_id, &master)?;
        let header = VaultHeader {
            format_version: FORMAT_VERSION,
            vault_id,
            kdf_algorithm: crate::crypto::kdf::KDF_ALGORITHM.to_string(),
            kdf_salt: salt.to_vec(),
            kdf_params: options.kdf_params,
            key_nonce,
            wrapped_master_key: wrapped,
            created_ms: crate::now_ms(),
        };

        let manifest = Manifest::new();
        let tx = conn.unchecked_transaction()?;
        header.insert(&tx)?;
        write_manifest(&tx, master.manifest_key(), &vault_id, &manifest)?;
        tx.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('created_by', 'MyVault 1.0')",
            [],
        )?;
        tx.commit()?;

        // Re-open through the exclusive path so the running application holds
        // the write lock exactly like an unlock does.
        drop(conn);
        let conn = db::open_exclusive(path)?;
        Ok(Vault {
            conn,
            path: path.to_path_buf(),
            header,
            master,
            manifest,
            chunk_size: options.chunk_size,
            unlock_ms: 0,
            _lock: lock,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn vault_id(&self) -> Id {
        self.header.vault_id
    }

    pub fn unlock_ms(&self) -> u64 {
        self.unlock_ms
    }

    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Explicitly lock: consume the vault, zeroizing keys and clearing the
    /// in-memory manifest.
    pub fn lock(self) {
        drop(self);
    }

    pub fn info(&self) -> VaultResult<VaultInfo> {
        let files = self
            .manifest
            .entries
            .iter()
            .filter(|e| !e.is_dir())
            .count() as u64;
        let directories = self.manifest.entries.len() as u64 - files;
        let plaintext_bytes: u64 = self
            .manifest
            .entries
            .iter()
            .filter(|e| !e.is_dir())
            .map(|e| e.size)
            .sum();
        Ok(VaultInfo {
            path: self.path.to_string_lossy().to_string(),
            name: self
                .path
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "Vault".into()),
            vault_id: id_hex(&self.header.vault_id),
            root_id: id_hex(&ROOT_ID),
            format_version: self.header.format_version,
            created_ms: self.header.created_ms,
            entries: self.manifest.entries.len() as u64,
            files,
            directories,
            chunks: chunks::chunk_count(&self.conn)?,
            stored_bytes: chunks::stored_bytes(&self.conn)?,
            plaintext_bytes,
            chunk_size: self.chunk_size,
            kdf: self.header.kdf_params.describe(),
        })
    }

    fn resolve_dir(&self, id: Option<&Id>) -> VaultResult<Id> {
        match id {
            None => Ok(ROOT_ID),
            Some(id) => {
                let e = self.manifest.get(id)?;
                if !e.is_dir() {
                    return Err(VaultError::WrongEntryKind);
                }
                Ok(*id)
            }
        }
    }

    pub fn list_directory(&self, dir: Option<&Id>) -> VaultResult<Vec<EntryView>> {
        let id = self.resolve_dir(dir)?;
        let index = self.manifest.index();
        Ok(self
            .manifest
            .children(&id)
            .into_iter()
            .map(|e| EntryView::from_entry(&self.manifest, &index, e))
            .collect())
    }

    pub fn entry(&self, id: &Id) -> VaultResult<EntryView> {
        let index = self.manifest.index();
        let e = self.manifest.get_indexed(&index, id)?;
        Ok(EntryView::from_entry(&self.manifest, &index, e))
    }

    pub fn breadcrumbs(&self, id: &Id) -> VaultResult<Vec<Crumb>> {
        let mut out = Vec::new();
        let mut cur = self.manifest.get(id)?;
        let mut guard = 0;
        loop {
            out.push(Crumb {
                id: id_hex(&cur.id),
                name: cur.name.clone(),
            });
            if cur.id == ROOT_ID {
                break;
            }
            cur = self.manifest.get(&cur.parent)?;
            guard += 1;
            if guard > self.manifest.entries.len() + 1 {
                return Err(VaultError::CorruptManifest);
            }
        }
        out.reverse();
        Ok(out)
    }

    fn save(&mut self) -> VaultResult<()> {
        let tx = self.conn.unchecked_transaction()?;
        write_manifest(&tx, self.master.manifest_key(), &self.header.vault_id, &self.manifest)?;
        tx.commit()?;
        Ok(())
    }

    pub fn create_directory(&mut self, parent: &Id, name: &str) -> VaultResult<EntryView> {
        validate_name(name)?;
        let parent_id = self.resolve_dir(Some(parent))?;
        if self.manifest.child_named(&parent_id, name).is_some() {
            return Err(VaultError::NameConflict(name.to_string()));
        }
        let now = crate::now_ms();
        let entry = Entry {
            id: random_bytes::<16>(),
            parent: parent_id,
            name: name.to_string(),
            kind: EntryKind::Directory,
            created_ms: now,
            modified_ms: now,
            size: 0,
            chunks: Vec::new(),
        };
        self.manifest.entries.push(entry.clone());
        self.manifest.touch();
        if let Err(e) = self.save() {
            self.manifest.wipe_entry(&entry.id);
            return Err(e);
        }
        self.entry(&entry.id)
    }

    pub fn rename_entry(&mut self, id: &Id, new_name: &str) -> VaultResult<EntryView> {
        if id == &ROOT_ID {
            return Err(VaultError::IllegalState(
                "the vault root cannot be renamed".into(),
            ));
        }
        validate_name(new_name)?;
        let parent = self.manifest.get(id)?.parent;
        if let Some(existing) = self.manifest.child_named(&parent, new_name) {
            if &existing.id != id {
                return Err(VaultError::NameConflict(new_name.to_string()));
            }
        }
        let previous = self.manifest.get(id)?.clone();
        {
            let entry = self.manifest.get_mut(id)?;
            entry.name = new_name.to_string();
            entry.modified_ms = crate::now_ms();
        }
        self.manifest.touch();
        if let Err(e) = self.save() {
            *self.manifest.get_mut(id)? = previous;
            return Err(e);
        }
        self.entry(id)
    }

    pub fn delete_entry(&mut self, id: &Id) -> VaultResult<DeleteReport> {
        if id == &ROOT_ID {
            return Err(VaultError::IllegalState(
                "the vault root cannot be deleted".into(),
            ));
        }
        self.manifest.get(id)?;
        let ids = self.manifest.subtree_ids(id)?;
        let snapshot = self.manifest.clone();
        let index = self.manifest.index();

        let mut chunk_ids: Vec<Id> = Vec::new();
        for entry_id in &ids {
            if let Some(position) = index.get(entry_id) {
                if let Some(entry) = self.manifest.entries.get(*position) {
                    chunk_ids.extend(entry.chunks.iter().map(|c| c.id));
                }
            }
        }

        let removing: std::collections::HashSet<Id> = ids.iter().copied().collect();
        self.manifest.entries.retain(|e| !removing.contains(&e.id));
        self.manifest.touch();

        let tx = self.conn.unchecked_transaction()?;
        if let Err(e) = chunks::delete_chunks(&tx, &chunk_ids).and_then(|_| {
            write_manifest(&tx, self.master.manifest_key(), &self.header.vault_id, &self.manifest)
        }) {
            self.manifest = snapshot;
            return Err(e);
        }
        if let Err(e) = tx.commit() {
            self.manifest = snapshot;
            return Err(VaultError::from(e));
        }
        Ok(DeleteReport {
            deleted_entries: ids.len() as u64,
            deleted_chunks: chunk_ids.len() as u64,
        })
    }

    pub fn move_entry(&mut self, id: &Id, destination: &Id) -> VaultResult<EntryView> {
        if id == &ROOT_ID {
            return Err(VaultError::IllegalState("the vault root cannot be moved".into()));
        }
        let dest = self.resolve_dir(Some(destination))?;
        if &dest == id {
            return Err(VaultError::InvalidMove(
                "an item cannot be moved into itself".into(),
            ));
        }
        if self.manifest.subtree_ids(id)?.contains(&dest) {
            return Err(VaultError::InvalidMove(
                "an item cannot be moved inside its own subtree".into(),
            ));
        }
        let entry = self.manifest.get(id)?.clone();
        if entry.parent == dest {
            let index = self.manifest.index();
            return Ok(EntryView::from_entry(&self.manifest, &index, &entry));
        }
        if let Some(existing) = self.manifest.child_named(&dest, &entry.name) {
            if &existing.id != id {
                return Err(VaultError::NameConflict(entry.name.clone()));
            }
        }
        {
            let m = self.manifest.get_mut(id)?;
            m.parent = dest;
            m.modified_ms = crate::now_ms();
        }
        self.manifest.touch();
        if let Err(e) = self.save() {
            *self.manifest.get_mut(id)? = entry;
            return Err(e);
        }
        self.entry(id)
    }

    /// Filename search inside the unlocked vault only.
    pub fn search(&self, query: &str) -> VaultResult<Vec<EntryView>> {
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            return Ok(Vec::new());
        }
        let index = self.manifest.index();
        let mut out: Vec<EntryView> = self
            .manifest
            .entries
            .iter()
            .filter(|e| e.id != ROOT_ID && e.name.to_lowercase().contains(&q))
            .map(|e| EntryView::from_entry(&self.manifest, &index, e))
            .collect();
        out.sort_by(|a, b| a.path.to_lowercase().cmp(&b.path.to_lowercase()));
        Ok(out)
    }

    /// All directories, ordered by virtual path. Used by the "move to folder"
    /// picker so the UI does not have to walk the tree entry by entry.
    pub fn directories(&self) -> Vec<EntryView> {
        let index = self.manifest.index();
        let mut out: Vec<EntryView> = self
            .manifest
            .entries
            .iter()
            .filter(|e| e.is_dir())
            .map(|e| EntryView::from_entry(&self.manifest, &index, e))
            .collect();
        out.sort_by(|a, b| a.path.to_lowercase().cmp(&b.path.to_lowercase()));
        out
    }

    /// Re-wrap the same vault master key under a new password. No file data is
    /// re-encrypted and the key envelope update is atomic.
    pub fn change_password(&mut self, current: &str, new: &str) -> VaultResult<()> {
        validate_password_strength(new)?;
        let current_kek = derive_kek(
            current.as_bytes(),
            &self.header.kdf_salt,
            &self.header.kdf_params,
        )?;
        let unwrapped = header::unwrap_master_key(&current_kek, &self.header)?;
        let matches: bool = unwrapped
            .expose_master()
            .ct_eq(self.master.expose_master())
            .into();
        if !matches {
            return Err(VaultError::InvalidPassword);
        }

        let salt = random_bytes::<SALT_LEN>();
        let params = self.header.kdf_params;
        let new_kek = derive_kek(new.as_bytes(), &salt, &params)?;
        let (nonce, wrapped) = header::wrap_master_key(&new_kek, &self.header.vault_id, &self.master)?;

        let tx = self.conn.unchecked_transaction()?;
        VaultHeader::update_envelope(&tx, &nonce, &wrapped, &salt, &params)?;
        tx.commit()?;

        self.header.kdf_salt = salt.to_vec();
        self.header.kdf_params = params;
        self.header.key_nonce = nonce;
        self.header.wrapped_master_key = wrapped;
        Ok(())
    }

    /// Create a consistent copy of the container while it is unlocked.
    ///
    /// `VACUUM INTO` writes a transactionally consistent snapshot, so the
    /// backup never captures a half-committed state even while the vault is
    /// open.
    pub fn backup_to(&self, destination: &Path) -> VaultResult<()> {
        if destination.exists() {
            return Err(VaultError::IllegalState(
                "a file already exists at the backup location".into(),
            ));
        }
        if let Some(parent) = destination.parent() {
            if !parent.as_os_str().is_empty() && !parent.is_dir() {
                return Err(VaultError::InvalidPath(
                    "the backup folder does not exist".into(),
                ));
            }
        }
        let target = destination
            .to_str()
            .ok_or_else(|| VaultError::InvalidPath("the backup path is not valid Unicode".into()))?;
        self.conn
            .execute("VACUUM INTO ?1", params![target])
            .map_err(|e| VaultError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Full verification: SQLite structure, header, manifest and every chunk's
    /// authentication tag.
    pub fn verify_integrity(&self, ctx: &dyn OpContext) -> VaultResult<IntegrityReport> {
        let mut issues = Vec::new();
        if let Err(e) = db::quick_check(&self.conn) {
            issues.push(format!("database structure: {e}"));
        }
        match VaultHeader::read(&self.conn) {
            Ok(h) => {
                if h.vault_id != self.header.vault_id {
                    issues.push("the vault identifier does not match the header".into());
                }
            }
            Err(e) => issues.push(format!("header: {e}")),
        }
        let manifest = match read_sealed_manifest(&self.conn)
            .and_then(|sealed| manifest::open_manifest(self.master.manifest_key(), &self.header.vault_id, &sealed))
        {
            Ok(m) => m,
            Err(e) => {
                issues.push(format!("manifest: {e}"));
                Manifest::new()
            }
        };
        if manifest.version != MANIFEST_VERSION {
            issues.push("manifest version mismatch".into());
        }

        let files: Vec<&Entry> = manifest.entries.iter().filter(|e| !e.is_dir()).collect();
        let total: u64 = files.iter().map(|e| e.size).sum();
        let mut checked_chunks = 0u64;
        let mut checked_bytes = 0u64;
        let mut done = 0u64;

        for file in &files {
            if ctx.is_cancelled() {
                return Err(VaultError::Cancelled);
            }
            let mut offset = 0u64;
            for (index, chunk) in file.chunks.iter().enumerate() {
                match chunks::read_decrypted_chunk(
                    &self.conn,
                    self.master.file_key(),
                    &self.header.vault_id,
                    &file.id,
                    index as u64,
                    &chunk.id,
                ) {
                    Ok(plain) => {
                        if plain.len() != chunk.len as usize {
                            issues.push(format!("chunk length mismatch in entry {}", id_hex(&file.id)));
                        }
                        offset += plain.len() as u64;
                    }
                    Err(e) => issues.push(format!(
                        "entry {} chunk {index}: {e}",
                        id_hex(&file.id)
                    )),
                }
                checked_chunks += 1;
                checked_bytes += chunk.len as u64;
            }
            if offset != file.size {
                issues.push(format!("entry {} size mismatch", id_hex(&file.id)));
            }
            done += file.size;
            ctx.progress(crate::services::progress::Progress {
                phase: "verify",
                current: done,
                total,
                item: file.name.clone(),
            });
        }

        let referenced = manifest.referenced_chunk_ids();
        let stored = chunks::chunk_count(&self.conn)?;
        let orphan_chunks = stored.saturating_sub(referenced.len() as u64);
        if orphan_chunks > 0 {
            issues.push(format!("{orphan_chunks} unreferenced chunk(s) found"));
        }

        Ok(IntegrityReport {
            ok: issues.is_empty(),
            entries_checked: manifest.entries.len() as u64,
            chunks_checked: checked_chunks,
            bytes_checked: checked_bytes,
            orphan_chunks,
            issues,
        })
    }

    /// Decrypt one file into the short-lived area used for opening it in its
    /// default Windows application. See [`crate::services::temp_open`].
    pub fn prepare_open(
        &self,
        area: &crate::services::temp_open::TempOpenArea,
        id: &Id,
    ) -> VaultResult<crate::services::temp_open::TempOpenFile> {
        let entry = self.manifest.get(id)?.clone();
        area.open_entry(self, &entry)
    }

    /// Import files and/or directory trees into a virtual directory.
    pub fn import_paths(
        &mut self,
        sources: &[PathBuf],
        destination: &Id,
        rename_on_conflict: bool,
        ctx: &dyn OpContext,
    ) -> VaultResult<transfer::ImportReport> {
        transfer::import_paths(self, sources, destination, rename_on_conflict, ctx)
    }

    /// Export entries into a physical directory.
    pub fn export_entries(
        &self,
        ids: &[Id],
        destination: &Path,
        overwrite: bool,
        ctx: &dyn OpContext,
    ) -> VaultResult<transfer::ExportReport> {
        transfer::export_entries(self, ids, destination, overwrite, ctx)
    }

    /// Convenience wrapper used by the tests and the CLI-style flows.
    pub fn verify(&self) -> VaultResult<IntegrityReport> {
        self.verify_integrity(&NoopContext)
    }

    /// Internal helper for `transfer`: snapshot the manifest so a failed
    /// import can restore the previous valid state.
    pub(crate) fn manifest_snapshot(&self) -> Manifest {
        self.manifest.clone()
    }

    /// Sanitized physical name for an entry (used by export).
    pub(crate) fn export_name(&self, entry: &Entry) -> VaultResult<String> {
        paths::sanitize_export_name(&entry.name)
    }
}

/// Read the vault header of a container without holding it open.
pub fn peek(path: impl AsRef<Path>) -> VaultResult<(String, u16)> {
    let conn = db::open(path.as_ref())?;
    if !db::is_initialized(&conn)? {
        return Err(VaultError::NotAVault);
    }
    let header = VaultHeader::read(&conn)?;
    Ok((
        path.as_ref()
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default(),
        header.format_version,
    ))
}

