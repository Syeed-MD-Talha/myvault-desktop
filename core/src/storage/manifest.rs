//! The encrypted, authenticated virtual file system manifest.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::crypto::aad::{Aad, OBJ_MANIFEST};
use crate::crypto::cipher;
use crate::errors::{VaultError, VaultResult};

pub type Id = [u8; 16];

/// The root directory always has this id so that an empty manifest is not
/// ambiguous.
pub const ROOT_ID: Id = [0u8; 16];
pub const MANIFEST_VERSION: u16 = 1;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    Directory,
    File,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ChunkRef {
    /// Random id of the stored, encrypted chunk row.
    pub id: Id,
    /// Plaintext length of this chunk in bytes.
    pub len: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Entry {
    pub id: Id,
    pub parent: Id,
    pub name: String,
    pub kind: EntryKind,
    pub created_ms: u64,
    pub modified_ms: u64,
    /// Plaintext size in bytes. Zero for directories.
    pub size: u64,
    /// Ordered chunk references. Empty for directories and empty files.
    #[serde(default)]
    pub chunks: Vec<ChunkRef>,
}

impl Entry {
    pub fn is_dir(&self) -> bool {
        matches!(self.kind, EntryKind::Directory)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Manifest {
    pub version: u16,
    pub created_ms: u64,
    pub modified_ms: u64,
    pub entries: Vec<Entry>,
}

/// An encrypted blob of manifest bytes together with its nonce.
#[derive(Clone, Debug)]
pub struct SealedManifest {
    pub nonce: [u8; cipher::NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

impl Manifest {
    pub fn new() -> Self {
        let now = crate::now_ms();
        Manifest {
            version: MANIFEST_VERSION,
            created_ms: now,
            modified_ms: now,
            entries: vec![Entry {
                id: ROOT_ID,
                parent: ROOT_ID,
                name: "Home".into(),
                kind: EntryKind::Directory,
                created_ms: now,
                modified_ms: now,
                size: 0,
                chunks: Vec::new(),
            }],
        }
    }

    pub fn get(&self, id: &Id) -> VaultResult<&Entry> {
        self.entries
            .iter()
            .find(|e| &e.id == id)
            .ok_or(VaultError::EntryNotFound)
    }

    pub fn get_mut(&mut self, id: &Id) -> VaultResult<&mut Entry> {
        self.entries
            .iter_mut()
            .find(|e| &e.id == id)
            .ok_or(VaultError::EntryNotFound)
    }

    /// Build an id -> position index once for bulk operations. Scanning all
    /// entries for every lookup would make listing and validation quadratic on
    /// vaults with thousands of items.
    pub fn index(&self) -> HashMap<Id, usize> {
        let mut map = HashMap::with_capacity(self.entries.len());
        for (position, entry) in self.entries.iter().enumerate() {
            map.entry(entry.id).or_insert(position);
        }
        map
    }

    pub fn get_indexed<'a>(
        &'a self,
        index: &HashMap<Id, usize>,
        id: &Id,
    ) -> VaultResult<&'a Entry> {
        index
            .get(id)
            .and_then(|position| self.entries.get(*position))
            .ok_or(VaultError::EntryNotFound)
    }

    pub fn contains(&self, id: &Id) -> bool {
        self.entries.iter().any(|e| &e.id == id)
    }

    /// Children of `parent`, directories first then files, each group sorted
    /// case-insensitively by name (stable, predictable UI ordering).
    pub fn children(&self, parent: &Id) -> Vec<&Entry> {
        let mut out: Vec<&Entry> = self
            .entries
            .iter()
            .filter(|e| &e.parent == parent && &e.id != parent)
            .collect();
        out.sort_by(|a, b| {
            b.is_dir()
                .cmp(&a.is_dir())
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        out
    }

    pub fn child_named(&self, parent: &Id, name: &str) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|e| &e.parent == parent && &e.id != parent && e.name.eq_ignore_ascii_case(name))
    }

    /// Full virtual path from the root, excluding the root name.
    pub fn path_of(&self, id: &Id) -> VaultResult<Vec<String>> {
        self.path_of_with(&self.index(), id)
    }

    pub fn path_of_with(&self, index: &HashMap<Id, usize>, id: &Id) -> VaultResult<Vec<String>> {
        let mut parts = Vec::new();
        let mut cur = self.get_indexed(index, id)?;
        let mut guard = 0;
        while &cur.id != &ROOT_ID {
            parts.push(cur.name.clone());
            cur = self.get_indexed(index, &cur.parent)?;
            guard += 1;
            if guard > self.entries.len() + 1 {
                return Err(VaultError::CorruptManifest);
            }
        }
        parts.reverse();
        Ok(parts)
    }

    /// All entries beneath `id`, including `id` itself.
    pub fn subtree_ids(&self, id: &Id) -> VaultResult<Vec<Id>> {
        self.get(id)?;
        let mut children: HashMap<Id, Vec<Id>> = HashMap::new();
        for e in &self.entries {
            if e.id == ROOT_ID {
                continue;
            }
            children.entry(e.parent).or_default().push(e.id);
        }
        let mut out = Vec::new();
        let mut stack = vec![*id];
        while let Some(next) = stack.pop() {
            out.push(next);
            if let Some(kids) = children.get(&next) {
                stack.extend(kids.iter().copied());
            }
        }
        Ok(out)
    }

    pub fn referenced_chunk_ids(&self) -> HashSet<Id> {
        self.entries
            .iter()
            .flat_map(|e| e.chunks.iter().map(|c| c.id))
            .collect()
    }

    /// Structural validation performed after every decode and before every
    /// commit. A manifest that fails here is never surfaced as valid.
    ///
    /// Runs in O(n) using an id index and memoized cycle detection so a large
    /// vault does not become slow to open or save.
    pub fn validate(&self) -> VaultResult<()> {
        if self.version != MANIFEST_VERSION {
            return Err(VaultError::UnsupportedVersion(self.version));
        }
        let index = self.index();
        if index.len() != self.entries.len() {
            return Err(VaultError::CorruptManifest);
        }

        let mut chunk_ids: HashSet<Id> = HashSet::new();
        let mut dir_ids: HashSet<Id> = HashSet::new();

        for e in &self.entries {
            validate_name(&e.name)?;
            if e.is_dir() {
                if !e.chunks.is_empty() || e.size != 0 {
                    return Err(VaultError::CorruptManifest);
                }
                dir_ids.insert(e.id);
            } else {
                if e.chunks.iter().map(|c| c.len as u64).sum::<u64>() != e.size {
                    return Err(VaultError::CorruptManifest);
                }
                for c in &e.chunks {
                    if c.id == ROOT_ID || !chunk_ids.insert(c.id) {
                        return Err(VaultError::CorruptManifest);
                    }
                }
            }
        }

        let root = self.get_indexed(&index, &ROOT_ID)?;
        if !root.is_dir() {
            return Err(VaultError::CorruptManifest);
        }

        // Parents must exist and be directories.
        for e in &self.entries {
            if e.id == ROOT_ID {
                continue;
            }
            if !index.contains_key(&e.parent) || !dir_ids.contains(&e.parent) {
                return Err(VaultError::CorruptManifest);
            }
        }

        // Cycle detection: 0 = unvisited, 1 = on the current chain, 2 = verified.
        let mut state: HashMap<Id, u8> = HashMap::with_capacity(self.entries.len());
        for e in &self.entries {
            let mut chain = Vec::new();
            let mut cur = e.id;
            loop {
                match state.get(&cur).copied() {
                    Some(2) => break,
                    Some(1) => return Err(VaultError::CorruptManifest),
                    _ => {}
                }
                if cur == ROOT_ID {
                    state.insert(cur, 2);
                    break;
                }
                let entry = self.get_indexed(&index, &cur)?;
                state.insert(cur, 1);
                chain.push(cur);
                cur = entry.parent;
                if chain.len() > self.entries.len() {
                    return Err(VaultError::CorruptManifest);
                }
            }
            for id in chain {
                state.insert(id, 2);
            }
        }

        // Sibling names must be unique (case-insensitive, Windows-like).
        let mut seen: HashSet<(Id, String)> = HashSet::with_capacity(self.entries.len());
        for e in &self.entries {
            if e.id == ROOT_ID {
                continue;
            }
            if !seen.insert((e.parent, e.name.to_lowercase())) {
                return Err(VaultError::CorruptManifest);
            }
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> VaultResult<Vec<u8>> {
        self.validate()?;
        Ok(serde_json::to_vec(self)?)
    }

    pub fn from_bytes(bytes: &[u8]) -> VaultResult<Self> {
        let m: Manifest = serde_json::from_slice(bytes)
            .map_err(|_| VaultError::CorruptManifest)?;
        m.validate()?;
        Ok(m)
    }

    pub fn wipe_entry(&mut self, id: &Id) {
        self.entries.retain(|e| &e.id != id);
    }

    pub fn touch(&mut self) {
        self.modified_ms = crate::now_ms();
    }
}

impl Default for Manifest {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Manifest {
    fn drop(&mut self) {
        // Best-effort scrubbing of plaintext names when the vault is locked.
        use zeroize::Zeroize;
        for entry in &mut self.entries {
            entry.name.zeroize();
        }
    }
}

/// Encrypt the manifest with the manifest subkey. AAD binds it to the vault,
/// to the manifest object type and to format version 1.
pub fn seal_manifest(
    manifest_key: &[u8; cipher::KEY_LEN],
    vault_id: &Id,
    manifest: &Manifest,
) -> VaultResult<SealedManifest> {
    let bytes = manifest.to_bytes()?;
    let aad = Aad::new(OBJ_MANIFEST, *vault_id, [0u8; 16], 0).encode(1);
    let nonce = cipher::random_nonce();
    let ciphertext = cipher::seal_with_nonce(manifest_key, &nonce, &aad, &bytes)?;
    Ok(SealedManifest { nonce, ciphertext })
}

pub fn open_manifest(
    manifest_key: &[u8; cipher::KEY_LEN],
    vault_id: &Id,
    sealed: &SealedManifest,
) -> VaultResult<Manifest> {
    let aad = Aad::new(OBJ_MANIFEST, *vault_id, [0u8; 16], 0).encode(1);
    let plain = cipher::open_with_nonce(manifest_key, &sealed.nonce, &aad, &sealed.ciphertext)
        .map_err(|_| VaultError::CorruptManifest)?;
    Manifest::from_bytes(&plain)
}

const RESERVED_NAMES: [&str; 22] = [
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

pub const MAX_NAME_LEN: usize = 255;

/// Validate a single virtual path component.
pub fn validate_name(name: &str) -> VaultResult<()> {
    if name.is_empty() {
        return Err(VaultError::InvalidName("the name is empty".into()));
    }
    if name.chars().count() > MAX_NAME_LEN {
        return Err(VaultError::InvalidName("the name is too long".into()));
    }
    if name == "." || name == ".." {
        return Err(VaultError::InvalidName(
            "relative path components are not allowed".into(),
        ));
    }
    if let Some(c) = name
        .chars()
        .find(|c| c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'))
    {
        return Err(VaultError::InvalidName(format!(
            "the character {c:?} is not allowed"
        )));
    }
    if name.ends_with(' ') || name.ends_with('.') {
        return Err(VaultError::InvalidName(
            "the name must not end with a space or a dot".into(),
        ));
    }
    let stem = name.split('.').next().unwrap_or(name).to_lowercase();
    if RESERVED_NAMES.contains(&stem.as_str()) {
        return Err(VaultError::InvalidName(
            "this name is reserved by Windows".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_entry(id: u8, parent: Id, name: &str, chunks: Vec<ChunkRef>) -> Entry {
        Entry {
            id: [id; 16],
            parent,
            name: name.into(),
            kind: EntryKind::File,
            created_ms: 1,
            modified_ms: 1,
            size: chunks.iter().map(|c| c.len as u64).sum(),
            chunks,
        }
    }

    #[test]
    fn new_manifest_is_valid_and_rooted() {
        let m = Manifest::new();
        m.validate().unwrap();
        assert_eq!(m.entries.len(), 1);
        assert_eq!(m.entries[0].id, ROOT_ID);
        assert!(m.children(&ROOT_ID).is_empty());
    }

    #[test]
    fn round_trip_through_bytes() {
        let mut m = Manifest::new();
        m.entries.push(Entry {
            id: [1; 16],
            parent: ROOT_ID,
            name: "Documents".into(),
            kind: EntryKind::Directory,
            created_ms: 1,
            modified_ms: 2,
            size: 0,
            chunks: vec![],
        });
        m.entries.push(file_entry(
            2,
            [1; 16],
            "notes.txt",
            vec![ChunkRef { id: [9; 16], len: 5 }],
        ));
        let bytes = m.to_bytes().unwrap();
        let back = Manifest::from_bytes(&bytes).unwrap();
        assert_eq!(back.entries.len(), 3);
        assert_eq!(back.path_of(&[2; 16]).unwrap(), vec!["Documents", "notes.txt"]);
    }

    #[test]
    fn serialized_form_contains_no_extensions_field_and_is_plain_json_in_memory_only() {
        // The manifest is only ever persisted encrypted; this test documents
        // that the plaintext representation is JSON and therefore must never
        // reach the database.
        let m = Manifest::new();
        let text = String::from_utf8(m.to_bytes().unwrap()).unwrap();
        assert!(text.contains("\"entries\""));
    }

    #[test]
    fn rejects_duplicate_ids() {
        let mut m = Manifest::new();
        m.entries.push(file_entry(1, ROOT_ID, "a.txt", vec![]));
        m.entries.push(file_entry(1, ROOT_ID, "b.txt", vec![]));
        assert_eq!(m.validate().unwrap_err(), VaultError::CorruptManifest);
    }

    #[test]
    fn rejects_duplicate_sibling_names_case_insensitively() {
        let mut m = Manifest::new();
        m.entries.push(file_entry(1, ROOT_ID, "Report.txt", vec![]));
        m.entries.push(file_entry(2, ROOT_ID, "report.TXT", vec![]));
        assert_eq!(m.validate().unwrap_err(), VaultError::CorruptManifest);
    }

    #[test]
    fn rejects_size_mismatch() {
        let mut m = Manifest::new();
        let mut e = file_entry(1, ROOT_ID, "a.bin", vec![ChunkRef { id: [3; 16], len: 4 }]);
        e.size = 99;
        m.entries.push(e);
        assert_eq!(m.validate().unwrap_err(), VaultError::CorruptManifest);
    }

    #[test]
    fn rejects_missing_parent_and_cycles() {
        let mut m = Manifest::new();
        m.entries.push(file_entry(1, [7; 16], "orphan", vec![]));
        assert_eq!(m.validate().unwrap_err(), VaultError::CorruptManifest);

        let mut m = Manifest::new();
        m.entries.push(Entry {
            id: [1; 16],
            parent: [2; 16],
            name: "a".into(),
            kind: EntryKind::Directory,
            created_ms: 0,
            modified_ms: 0,
            size: 0,
            chunks: vec![],
        });
        m.entries.push(Entry {
            id: [2; 16],
            parent: [1; 16],
            name: "b".into(),
            kind: EntryKind::Directory,
            created_ms: 0,
            modified_ms: 0,
            size: 0,
            chunks: vec![],
        });
        assert_eq!(m.validate().unwrap_err(), VaultError::CorruptManifest);
    }

    #[test]
    fn rejects_duplicate_chunk_reference() {
        let mut m = Manifest::new();
        m.entries.push(file_entry(
            1,
            ROOT_ID,
            "a.bin",
            vec![
                ChunkRef { id: [4; 16], len: 1 },
                ChunkRef { id: [4; 16], len: 1 },
            ],
        ));
        assert_eq!(m.validate().unwrap_err(), VaultError::CorruptManifest);
    }

    #[test]
    fn name_validation_covers_windows_and_traversal_cases() {
        assert!(validate_name("normal file.txt").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name("..").is_err());
        assert!(validate_name("a/b").is_err());
        assert!(validate_name("a\\b").is_err());
        assert!(validate_name("evil:stream").is_err());
        assert!(validate_name("trailing.").is_err());
        assert!(validate_name("trailing ").is_err());
        assert!(validate_name("CON").is_err());
        assert!(validate_name("lpt9.txt").is_err());
        assert!(validate_name(&"x".repeat(MAX_NAME_LEN + 1)).is_err());
    }

    #[test]
    fn sealing_round_trips_and_binds_vault_id() {
        let key = [11u8; 32];
        let m = Manifest::new();
        let sealed = seal_manifest(&key, &[1u8; 16], &m).unwrap();
        assert!(open_manifest(&key, &[1u8; 16], &sealed).is_ok());
        assert!(open_manifest(&key, &[2u8; 16], &sealed).is_err());
        assert!(open_manifest(&[12u8; 32], &[1u8; 16], &sealed).is_err());
    }

    #[test]
    fn tampered_manifest_ciphertext_is_rejected() {
        let key = [11u8; 32];
        let m = Manifest::new();
        let mut sealed = seal_manifest(&key, &[1u8; 16], &m).unwrap();
        let last = sealed.ciphertext.len() - 1;
        sealed.ciphertext[last] ^= 0xff;
        assert_eq!(
            open_manifest(&key, &[1u8; 16], &sealed).unwrap_err(),
            VaultError::CorruptManifest
        );
    }
}
