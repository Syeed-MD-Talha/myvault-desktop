//! Security tests for the vault container (SRS section 14.3).

mod common;

use std::path::{Path, PathBuf};

use common::*;
use myvault_core::{NoopContext, OpenedVault, Vault, VaultError, ROOT_ID};

fn vault_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.vault"))
}

fn create_with_file(dir: &Path, name: &str, file_name: &str, content: &[u8]) -> (PathBuf, Vault) {
    let path = vault_path(dir, name);
    let src = tempfile::tempdir().unwrap();
    let source = write_source(src.path(), file_name, content);
    // Keep the source directory alive for the duration of the call.
    std::mem::forget(src);
    let mut vault = Vault::create_with_options(&path, PASSWORD, fast_options()).unwrap();
    vault
        .import_paths(&[source], &ROOT_ID, false, &NoopContext)
        .unwrap();
    (path, vault)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn container_contains_no_plaintext_names_content_or_extensions() {
    let dir = tempfile::tempdir().unwrap();
    let secret_name = "VerySecretReport_Q3_financials.pdf";
    let secret_content = b"CONFIDENTIAL-MARKER-9f3a1b: salary figures and merger plans";
    let (path, vault) = create_with_file(dir.path(), "privacy", secret_name, secret_content);
    vault.lock();

    let raw = std::fs::read(&path).unwrap();
    assert!(!raw.is_empty());
    // Filenames, extensions, and content must not be recoverable while locked.
    assert!(
        !contains(&raw, secret_name.as_bytes()),
        "the plaintext file name leaked into the container"
    );
    assert!(
        !contains(&raw, b"VerySecretReport"),
        "a plaintext name fragment leaked into the container"
    );
    assert!(
        !contains(&raw, b".pdf"),
        "the plaintext extension leaked into the container"
    );
    assert!(
        !contains(&raw, secret_content),
        "plaintext file content leaked into the container"
    );
    assert!(!contains(&raw, PASSWORD.as_bytes()));

    // The unlocked API still works, proving the data is really there.
    let vault = OpenedVault::open(&path).unwrap().unlock(PASSWORD).unwrap();
    assert_eq!(vault.list_directory(None).unwrap()[0].name, secret_name);
}

#[test]
fn tampered_chunk_is_rejected_and_leaves_no_partial_export() {
    let dir = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let payload = pattern_bytes(128 * 1024, 5);
    let (path, vault) = create_with_file(dir.path(), "tamper", "data.bin", &payload);
    let id = myvault_core::parse_id(&vault.list_directory(None).unwrap()[0].id).unwrap();
    vault.lock();

    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        let rows: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = {
            let mut stmt = conn
                .prepare("SELECT chunk_id, nonce, ciphertext FROM encrypted_chunks ORDER BY rowid")
                .unwrap();
            let iter = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .unwrap();
            iter.map(|r| r.unwrap()).collect()
        };
        assert!(rows.len() >= 2);
        // Swap the ciphertext of chunk 0 and chunk 1: the tag no longer matches
        // the (vault, file, index) associated data.
        conn.execute(
            "UPDATE encrypted_chunks SET ciphertext = ?1 WHERE chunk_id = ?2",
            rusqlite::params![rows[1].2, rows[0].0],
        )
        .unwrap();
    }

    let vault = OpenedVault::open(&path).unwrap().unlock(PASSWORD).unwrap();
    let err = vault
        .export_entries(&[id], out_dir.path(), false, &NoopContext)
        .unwrap_err();
    assert_eq!(err, VaultError::AuthenticationFailed);

    let leftovers: Vec<String> = std::fs::read_dir(out_dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert!(
        leftovers.is_empty(),
        "a failed export left files behind: {leftovers:?}"
    );
}

#[test]
fn reordered_chunks_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let payload = pattern_bytes(200 * 1024, 21);
    let (path, vault) = create_with_file(dir.path(), "reorder", "data.bin", &payload);
    let id = myvault_core::parse_id(&vault.list_directory(None).unwrap()[0].id).unwrap();
    vault.lock();

    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        let rows: Vec<(Vec<u8>, Vec<u8>)> = {
            let mut stmt = conn
                .prepare("SELECT chunk_id, ciphertext FROM encrypted_chunks ORDER BY rowid")
                .unwrap();
            let iter = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            iter.map(|r| r.unwrap()).collect()
        };
        conn.execute(
            "UPDATE encrypted_chunks SET ciphertext = ?1 WHERE chunk_id = ?2",
            rusqlite::params![rows[2].1, rows[0].0],
        )
        .unwrap();
    }

    let vault = OpenedVault::open(&path).unwrap().unlock(PASSWORD).unwrap();
    assert_eq!(
        vault
            .export_entries(&[id], out_dir.path(), false, &NoopContext)
            .unwrap_err(),
        VaultError::AuthenticationFailed
    );
    assert!(!out_dir.path().join("data.bin").exists());
}

#[test]
fn chunk_from_another_file_cannot_be_substituted() {
    let dir = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let path = vault_path(dir.path(), "substitute");

    let a = write_source(src.path(), "a.bin", &pattern_bytes(100 * 1024, 1));
    let b = write_source(src.path(), "b.bin", &pattern_bytes(100 * 1024, 2));
    let mut vault = Vault::create_with_options(&path, PASSWORD, fast_options()).unwrap();
    vault
        .import_paths(&[a, b], &ROOT_ID, false, &NoopContext)
        .unwrap();
    let entries = vault.list_directory(None).unwrap();
    assert_eq!(entries.len(), 2);
    let id_a = myvault_core::parse_id(&entries[0].id).unwrap();
    vault.lock();

    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        let chunk_of_b: Vec<u8> = conn
            .query_row(
                "SELECT ciphertext FROM encrypted_chunks ORDER BY rowid DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let first_chunk_of_a: Vec<u8> = conn
            .query_row(
                "SELECT chunk_id FROM encrypted_chunks ORDER BY rowid ASC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        conn.execute(
            "UPDATE encrypted_chunks SET ciphertext = ?1 WHERE chunk_id = ?2",
            rusqlite::params![chunk_of_b, first_chunk_of_a],
        )
        .unwrap();
    }

    let vault = OpenedVault::open(&path).unwrap().unlock(PASSWORD).unwrap();
    assert_eq!(
        vault
            .export_entries(&[id_a], out_dir.path(), false, &NoopContext)
            .unwrap_err(),
        VaultError::AuthenticationFailed
    );
}

#[test]
fn corrupted_manifest_fails_safely_without_modifying_the_vault() {
    let dir = tempfile::tempdir().unwrap();
    let (path, vault) = create_with_file(dir.path(), "manifest", "a.txt", b"hello");
    vault.lock();
    let before = std::fs::read(&path).unwrap();

    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        let mut ct: Vec<u8> = conn
            .query_row("SELECT ciphertext FROM encrypted_manifest WHERE id = 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x7f;
        conn.execute(
            "UPDATE encrypted_manifest SET ciphertext = ?1 WHERE id = 1",
            rusqlite::params![ct],
        )
        .unwrap();
    }

    let err = OpenedVault::open(&path).unwrap().unlock(PASSWORD).unwrap_err();
    assert_eq!(err, VaultError::CorruptManifest);

    // Opening for write must not "repair" or overwrite the damaged data.
    let after = std::fs::read(&path).unwrap();
    assert_eq!(before.len(), after.len());
    assert_ne!(before, after, "the tampering should be visible in the file");
    assert!(OpenedVault::open(&path).unwrap().unlock(PASSWORD).is_err());
}

#[test]
fn corrupted_header_is_reported_as_a_generic_unlock_failure() {
    let dir = tempfile::tempdir().unwrap();
    let (path, vault) = create_with_file(dir.path(), "header", "a.txt", b"hello");
    vault.lock();

    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        let mut wrapped: Vec<u8> = conn
            .query_row("SELECT wrapped_master_key FROM vault_header WHERE id = 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        wrapped[3] ^= 0xff;
        conn.execute(
            "UPDATE vault_header SET wrapped_master_key = ?1 WHERE id = 1",
            rusqlite::params![wrapped],
        )
        .unwrap();
    }

    // A damaged key envelope must be indistinguishable from a wrong password.
    assert_eq!(
        OpenedVault::open(&path).unwrap().unlock(PASSWORD).unwrap_err(),
        VaultError::InvalidPassword
    );
}

#[test]
fn rebinding_a_vault_header_to_another_vault_id_is_rejected() {
    // The vault id is bound into both the key envelope AAD and the manifest
    // AAD, so rebinding the header makes the vault unusable rather than
    // silently readable.
    let dir = tempfile::tempdir().unwrap();
    let (path, vault) = create_with_file(dir.path(), "binding", "a.txt", b"hello");
    vault.lock();
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        let other = [0xABu8; 16];
        conn.execute(
            "UPDATE vault_header SET vault_id = ?1 WHERE id = 1",
            rusqlite::params![&other[..]],
        )
        .unwrap();
    }
    let err = OpenedVault::open(&path).unwrap().unlock(PASSWORD).unwrap_err();
    // Fails at the key envelope first: indistinguishable from a wrong password.
    assert_eq!(err, VaultError::InvalidPassword);
}

#[test]
fn import_rejects_relative_and_missing_sources() {
    let dir = tempfile::tempdir().unwrap();
    let path = vault_path(dir.path(), "sources");
    let mut vault = Vault::create_with_options(&path, PASSWORD, fast_options()).unwrap();
    assert!(vault
        .import_paths(&[PathBuf::from("relative.txt")], &ROOT_ID, false, &NoopContext)
        .is_err());
    assert!(vault
        .import_paths(
            &[PathBuf::from(r"C:\definitely-not-here\missing.bin")],
            &ROOT_ID,
            false,
            &NoopContext
        )
        .is_err());
    assert!(vault.list_directory(None).unwrap().is_empty());
}

#[test]
fn export_rejects_a_missing_destination() {
    let dir = tempfile::tempdir().unwrap();
    let (path, vault) = create_with_file(dir.path(), "dest", "a.txt", b"hello");
    let id = myvault_core::parse_id(&vault.list_directory(None).unwrap()[0].id).unwrap();
    let err = vault
        .export_entries(&[id], Path::new(r"C:\no-such-folder-myvault"), false, &NoopContext)
        .unwrap_err();
    assert!(matches!(err, VaultError::Io(_) | VaultError::InvalidPath(_)));
    drop(path);
}

#[test]
fn locked_vault_exposes_no_entries_until_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let (path, vault) = create_with_file(dir.path(), "locked-api", "secret.txt", b"secret");
    vault.lock();

    // The locked handle exposes only the format version and a name hint.
    let opened = OpenedVault::open(&path).unwrap();
    assert_eq!(opened.format_version(), 1);
    assert_eq!(opened.name_hint(), "locked-api");
    // There is no API on the locked handle that returns entry metadata.
    let unlocked = opened.unlock(PASSWORD).unwrap();
    assert_eq!(unlocked.list_directory(None).unwrap().len(), 1);
}
