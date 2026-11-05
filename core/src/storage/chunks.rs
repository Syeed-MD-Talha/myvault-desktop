//! Encrypted chunk storage.
//!
//! Every chunk is stored under a random id with its own random nonce and its
//! own authenticated context (vault id, file id, chunk index). A chunk copied
//! from another file, replayed at another index, or from another vault fails
//! authentication.

use rusqlite::{params, Connection, OptionalExtension};

use crate::crypto::aad::{Aad, OBJ_CHUNK};
use crate::crypto::cipher;
use crate::errors::{VaultError, VaultResult};
use crate::storage::manifest::Id;

/// Default plaintext chunk size: 1 MiB.
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;
/// Smallest and largest accepted chunk sizes (defensive bounds).
pub const MIN_CHUNK_SIZE: usize = 4096;
pub const MAX_CHUNK_SIZE: usize = 8 * 1024 * 1024;

pub fn validate_chunk_size(size: usize) -> VaultResult<()> {
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&size) {
        return Err(VaultError::Validation(format!(
            "chunk size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE} bytes"
        )));
    }
    Ok(())
}

pub fn new_chunk_id() -> Id {
    cipher::random_bytes::<16>()
}

/// Encrypt `plaintext` as chunk number `index` of file `file_id` and store it.
/// Returns the chunk reference needed by the manifest.
pub fn insert_encrypted_chunk(
    conn: &Connection,
    file_key: &[u8; cipher::KEY_LEN],
    vault_id: &Id,
    file_id: &Id,
    index: u64,
    plaintext: &[u8],
) -> VaultResult<crate::storage::manifest::ChunkRef> {
    let chunk_id: Id = new_chunk_id();
    insert_encrypted_chunk_with_id(conn, file_key, vault_id, file_id, index, plaintext, chunk_id)
}

/// Same as [`insert_encrypted_chunk`] but with a caller-supplied chunk id,
/// used when staging into a transaction.
pub fn insert_encrypted_chunk_with_id(
    conn: &Connection,
    file_key: &[u8; cipher::KEY_LEN],
    vault_id: &Id,
    file_id: &Id,
    index: u64,
    plaintext: &[u8],
    chunk_id: Id,
) -> VaultResult<crate::storage::manifest::ChunkRef> {
    let aad = Aad::new(OBJ_CHUNK, *vault_id, *file_id, index).encode(1);
    let nonce = cipher::random_nonce();
    let ciphertext = cipher::seal_with_nonce(file_key, &nonce, &aad, plaintext)?;
    conn.execute(
        "INSERT INTO encrypted_chunks (chunk_id, nonce, ciphertext) VALUES (?1, ?2, ?3)",
        params![&chunk_id[..], &nonce[..], ciphertext],
    )?;
    Ok(crate::storage::manifest::ChunkRef {
        id: chunk_id,
        len: plaintext.len() as u32,
    })
}

/// Decrypt chunk `index` of file `file_id`.
pub fn read_decrypted_chunk(
    conn: &Connection,
    file_key: &[u8; cipher::KEY_LEN],
    vault_id: &Id,
    file_id: &Id,
    index: u64,
    chunk_id: &Id,
) -> VaultResult<zeroize::Zeroizing<Vec<u8>>> {
    let row: Option<(Vec<u8>, Vec<u8>)> = conn
        .query_row(
            "SELECT nonce, ciphertext FROM encrypted_chunks WHERE chunk_id = ?1",
            params![&chunk_id[..]],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (nonce, ciphertext) = row.ok_or(VaultError::CorruptManifest)?;
    if nonce.len() != cipher::NONCE_LEN {
        return Err(VaultError::AuthenticationFailed);
    }
    let mut nonce_arr = [0u8; cipher::NONCE_LEN];
    nonce_arr.copy_from_slice(&nonce);
    let aad = Aad::new(OBJ_CHUNK, *vault_id, *file_id, index).encode(1);
    cipher::open_with_nonce(file_key, &nonce_arr, &aad, &ciphertext)
}

pub fn delete_chunks(conn: &Connection, ids: &[Id]) -> VaultResult<()> {
    let mut stmt = conn.prepare("DELETE FROM encrypted_chunks WHERE chunk_id = ?1")?;
    for id in ids {
        stmt.execute(params![&id[..]])?;
    }
    Ok(())
}

/// Delete chunk rows that the manifest no longer references. Called after a
/// successful manifest commit; failures here are non-fatal for correctness
/// because orphaned rows are invisible and are reclaimed on the next sweep.
pub fn delete_orphans(conn: &Connection, referenced: &std::collections::HashSet<Id>) -> VaultResult<u64> {
    let mut stmt = conn.prepare("SELECT chunk_id FROM encrypted_chunks")?;
    let existing: Vec<Id> = stmt
        .query_map([], |r| {
            let raw: Vec<u8> = r.get(0)?;
            let mut id = [0u8; 16];
            if raw.len() == 16 {
                id.copy_from_slice(&raw);
            }
            Ok(id)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut removed = 0u64;
    for id in existing {
        if !referenced.contains(&id) {
            conn.execute(
                "DELETE FROM encrypted_chunks WHERE chunk_id = ?1",
                params![&id[..]],
            )?;
            removed += 1;
        }
    }
    Ok(removed)
}

pub fn chunk_count(conn: &Connection) -> VaultResult<u64> {
    let n: i64 = conn.query_row("SELECT COUNT(*) FROM encrypted_chunks", [], |r| r.get(0))?;
    Ok(n as u64)
}

/// Total ciphertext bytes currently stored (a storage-usage figure that does
/// not reveal plaintext sizes beyond the inherent padding of the AEAD tag).
pub fn stored_bytes(conn: &Connection) -> VaultResult<u64> {
    let n: i64 = conn.query_row(
        "SELECT COALESCE(SUM(LENGTH(ciphertext) + LENGTH(nonce)), 0) FROM encrypted_chunks",
        [],
        |r| r.get(0),
    )?;
    Ok(n as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn setup() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::storage::db::configure(&conn).unwrap();
        crate::storage::db::initialize(&conn).unwrap();
        conn
    }

    #[test]
    fn chunk_round_trip() {
        let conn = setup();
        let key = [4u8; 32];
        let vault = [1u8; 16];
        let file = [2u8; 16];
        let r = insert_encrypted_chunk(&conn, &key, &vault, &file, 0, b"hello chunk").unwrap();
        assert_eq!(r.len, 11);
        let plain = read_decrypted_chunk(&conn, &key, &vault, &file, 0, &r.id).unwrap();
        assert_eq!(&plain[..], b"hello chunk");
    }

    #[test]
    fn chunk_cannot_be_replayed_at_another_index() {
        let conn = setup();
        let key = [4u8; 32];
        let vault = [1u8; 16];
        let file = [2u8; 16];
        let r = insert_encrypted_chunk(&conn, &key, &vault, &file, 0, b"first").unwrap();
        assert_eq!(
            read_decrypted_chunk(&conn, &key, &vault, &file, 1, &r.id).unwrap_err(),
            VaultError::AuthenticationFailed
        );
    }

    #[test]
    fn chunk_cannot_be_moved_between_files() {
        let conn = setup();
        let key = [4u8; 32];
        let vault = [1u8; 16];
        let a = insert_encrypted_chunk(&conn, &key, &vault, &[2u8; 16], 0, b"a").unwrap();
        assert_eq!(
            read_decrypted_chunk(&conn, &key, &vault, &[3u8; 16], 0, &a.id).unwrap_err(),
            VaultError::AuthenticationFailed
        );
    }

    #[test]
    fn chunk_cannot_be_moved_between_vaults() {
        let conn = setup();
        let key = [4u8; 32];
        let a = insert_encrypted_chunk(&conn, &key, &[1u8; 16], &[2u8; 16], 0, b"a").unwrap();
        assert_eq!(
            read_decrypted_chunk(&conn, &key, &[9u8; 16], &[2u8; 16], 0, &a.id).unwrap_err(),
            VaultError::AuthenticationFailed
        );
    }

    #[test]
    fn tampered_chunk_bytes_are_rejected() {
        let conn = setup();
        let key = [4u8; 32];
        let vault = [1u8; 16];
        let file = [2u8; 16];
        let r = insert_encrypted_chunk(&conn, &key, &vault, &file, 0, b"abc").unwrap();
        conn.execute(
            "UPDATE encrypted_chunks SET ciphertext = x'00010203' WHERE chunk_id = ?1",
            params![&r.id[..]],
        )
        .unwrap();
        assert_eq!(
            read_decrypted_chunk(&conn, &key, &vault, &file, 0, &r.id).unwrap_err(),
            VaultError::AuthenticationFailed
        );
    }

    #[test]
    fn missing_chunk_is_reported_not_panicked() {
        let conn = setup();
        assert_eq!(
            read_decrypted_chunk(&conn, &[4u8; 32], &[1u8; 16], &[2u8; 16], 0, &[9u8; 16])
                .unwrap_err(),
            VaultError::CorruptManifest
        );
    }

    #[test]
    fn orphan_sweep_removes_unreferenced_rows() {
        let conn = setup();
        let key = [4u8; 32];
        let vault = [1u8; 16];
        let file = [2u8; 16];
        let keep = insert_encrypted_chunk(&conn, &key, &vault, &file, 0, b"keep").unwrap();
        let drop = insert_encrypted_chunk(&conn, &key, &vault, &file, 1, b"drop").unwrap();
        let referenced: HashSet<Id> = [keep.id].into_iter().collect();
        assert_eq!(delete_orphans(&conn, &referenced).unwrap(), 1);
        assert_eq!(chunk_count(&conn).unwrap(), 1);
        assert!(read_decrypted_chunk(&conn, &key, &vault, &file, 1, &drop.id).is_err());
    }

    #[test]
    fn chunk_size_bounds() {
        assert!(validate_chunk_size(DEFAULT_CHUNK_SIZE).is_ok());
        assert!(validate_chunk_size(0).is_err());
        assert!(validate_chunk_size(MAX_CHUNK_SIZE + 1).is_err());
    }
}
