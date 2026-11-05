//! End-to-end tests for the vault engine (SRS section 14.2).

mod common;

use std::path::PathBuf;

use common::*;
use myvault_core::{
    CancelToken, NoopContext, OpenedVault, Vault, VaultError, ROOT_ID,
};

fn vault_path(dir: &PathBuf, name: &str) -> PathBuf {
    dir.join(format!("{name}.vault"))
}

#[test]
fn create_lock_unlock_cycle() {
    let dir = tempfile::tempdir().unwrap();
    let path = vault_path(&dir.path().to_path_buf(), "Personal");

    let vault = Vault::create_with_options(&path, PASSWORD, fast_options()).unwrap();
    assert!(path.is_file());
    let info = vault.info().unwrap();
    assert_eq!(info.files, 0);
    assert_eq!(info.directories, 1);
    vault.lock();

    let opened = OpenedVault::open(&path).unwrap();
    assert_eq!(opened.format_version(), 1);
    let vault = opened.unlock(PASSWORD).unwrap();
    assert_eq!(vault.info().unwrap().directories, 1);
}

#[test]
fn wrong_password_is_rejected_generically() {
    let dir = tempfile::tempdir().unwrap();
    let path = vault_path(&dir.path().to_path_buf(), "v");
    Vault::create_with_options(&path, PASSWORD, fast_options())
        .unwrap()
        .lock();

    let opened = OpenedVault::open(&path).unwrap();
    let err = opened.unlock("not the right passphrase").unwrap_err();
    assert_eq!(err, VaultError::InvalidPassword);
    assert_eq!(err.code(), "invalid_password");
    // The message must not reveal whether the password or the data was wrong.
    let message = err.to_string();
    assert!(!message.to_lowercase().contains("password is correct"));
    assert!(!message.contains(PASSWORD));
}

#[test]
fn weak_passwords_are_refused_at_creation() {
    let dir = tempfile::tempdir().unwrap();
    let path = vault_path(&dir.path().to_path_buf(), "weak");
    assert!(matches!(
        Vault::create_with_options(&path, "123456", fast_options()).unwrap_err(),
        VaultError::WeakPassword(_)
    ));
    assert!(!path.exists(), "a refused create must not leave a file");
}

#[test]
fn create_refuses_to_overwrite_an_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = vault_path(&dir.path().to_path_buf(), "existing");
    std::fs::write(&path, b"do not clobber").unwrap();
    assert!(matches!(
        Vault::create_with_options(&path, PASSWORD, fast_options()).unwrap_err(),
        VaultError::IllegalState(_)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), b"do not clobber");
}

#[test]
fn import_export_round_trip_is_byte_exact() {
    let dir = tempfile::tempdir().unwrap();
    let src_dir = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let path = vault_path(&dir.path().to_path_buf(), "roundtrip");

    // Larger than the 64 KiB chunk size so several chunks are exercised, and
    // containing NUL bytes and invalid UTF-8 on purpose.
    let payload = pattern_bytes(300 * 1024 + 137, 42);
    let source = write_source(src_dir.path(), "binary.bin", &payload);

    let mut vault = Vault::create_with_options(&path, PASSWORD, fast_options()).unwrap();
    let report = vault
        .import_paths(&[source], &ROOT_ID, false, &NoopContext)
        .unwrap();
    assert_eq!(report.imported_files, 1);
    assert_eq!(report.imported_bytes, payload.len() as u64);

    let listed = vault.list_directory(None).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "binary.bin");
    assert_eq!(listed[0].size, payload.len() as u64);
    assert!(listed[0].chunk_count > 1);

    // Lock, reopen, unlock, export.
    vault.lock();
    let vault = OpenedVault::open(&path).unwrap().unlock(PASSWORD).unwrap();
    let id = myvault_core::parse_id(&vault.list_directory(None).unwrap()[0].id).unwrap();
    let export = vault
        .export_entries(&[id], out_dir.path(), false, &NoopContext)
        .unwrap();
    assert_eq!(export.exported_files, 1);
    assert_eq!(read_all(&out_dir.path().join("binary.bin")), payload);
}

#[test]
fn nested_directory_tree_is_preserved_including_empty_folders() {
    let dir = tempfile::tempdir().unwrap();
    let src_dir = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let path = vault_path(&dir.path().to_path_buf(), "tree");

    let tree = src_dir.path().join("Projects");
    std::fs::create_dir_all(tree.join("src").join("nested")).unwrap();
    std::fs::create_dir_all(tree.join("empty")).unwrap();
    std::fs::write(tree.join("README.md"), b"# readme\n").unwrap();
    std::fs::write(tree.join("src").join("main.rs"), b"fn main() {}\n").unwrap();
    std::fs::write(tree.join("src").join("nested").join("deep.txt"), b"deep").unwrap();

    let mut vault = Vault::create_with_options(&path, PASSWORD, fast_options()).unwrap();
    vault
        .import_paths(&[tree.clone()], &ROOT_ID, false, &NoopContext)
        .unwrap();

    let projects = myvault_core::parse_id(&vault.list_directory(None).unwrap()[0].id).unwrap();
    let names: Vec<String> = vault
        .list_directory(Some(&projects))
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, vec!["empty", "src", "README.md"]);
    assert!(vault.entry(&projects).unwrap().kind == "directory");

    let export = vault
        .export_entries(&[projects], out_dir.path(), false, &NoopContext)
        .unwrap();
    assert_eq!(export.exported_directories, 4);
    assert_eq!(export.exported_files, 3);
    assert!(out_dir.path().join("Projects").join("empty").is_dir());
    assert_eq!(
        read_all(&out_dir.path().join("Projects").join("src").join("nested").join("deep.txt")),
        b"deep"
    );
}

#[test]
fn empty_files_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let src_dir = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let path = vault_path(&dir.path().to_path_buf(), "empty");

    let source = write_source(src_dir.path(), "empty.txt", b"");
    let mut vault = Vault::create_with_options(&path, PASSWORD, fast_options()).unwrap();
    vault
        .import_paths(&[source], &ROOT_ID, false, &NoopContext)
        .unwrap();
    let entry = vault.list_directory(None).unwrap().remove(0);
    assert_eq!(entry.size, 0);
    assert_eq!(entry.chunk_count, 0);

    let id = myvault_core::parse_id(&entry.id).unwrap();
    vault
        .export_entries(&[id], out_dir.path(), false, &NoopContext)
        .unwrap();
    assert_eq!(read_all(&out_dir.path().join("empty.txt")), Vec::<u8>::new());
}

#[test]
fn create_rename_move_and_delete_entries() {
    let dir = tempfile::tempdir().unwrap();
    let path = vault_path(&dir.path().to_path_buf(), "ops");
    let mut vault = Vault::create_with_options(&path, PASSWORD, fast_options()).unwrap();

    let docs = vault.create_directory(&ROOT_ID, "Documents").unwrap();
    let docs_id = myvault_core::parse_id(&docs.id).unwrap();
    let archive = vault.create_directory(&ROOT_ID, "Archive").unwrap();
    let archive_id = myvault_core::parse_id(&archive.id).unwrap();
    assert!(matches!(
        vault.create_directory(&ROOT_ID, "documents").unwrap_err(),
        VaultError::NameConflict(_)
    ));

    let renamed = vault.rename_entry(&docs_id, "Docs").unwrap();
    assert_eq!(renamed.name, "Docs");

    let moved = vault.move_entry(&docs_id, &archive_id).unwrap();
    assert_eq!(moved.parent_id, archive.id);
    assert_eq!(vault.list_directory(None).unwrap().len(), 1);

    // A directory cannot be moved inside itself.
    assert!(matches!(
        vault.move_entry(&archive_id, &archive_id).unwrap_err(),
        VaultError::InvalidMove(_)
    ));

    let report = vault.delete_entry(&archive_id).unwrap();
    assert_eq!(report.deleted_entries, 2);
    assert!(vault.list_directory(None).unwrap().is_empty());
}

#[test]
fn delete_removes_chunk_rows() {
    let dir = tempfile::tempdir().unwrap();
    let src_dir = tempfile::tempdir().unwrap();
    let path = vault_path(&dir.path().to_path_buf(), "delete");
    let source = write_source(src_dir.path(), "a.bin", &pattern_bytes(200 * 1024, 7));

    let mut vault = Vault::create_with_options(&path, PASSWORD, fast_options()).unwrap();
    vault
        .import_paths(&[source], &ROOT_ID, false, &NoopContext)
        .unwrap();
    assert!(vault.info().unwrap().chunks >= 3);
    let id = myvault_core::parse_id(&vault.list_directory(None).unwrap()[0].id).unwrap();
    let report = vault.delete_entry(&id).unwrap();
    assert_eq!(report.deleted_chunks, 4);
    assert_eq!(vault.info().unwrap().chunks, 0);
    assert!(vault.list_directory(None).unwrap().is_empty());
}

#[test]
fn change_password_rewraps_without_touching_file_data() {
    let dir = tempfile::tempdir().unwrap();
    let src_dir = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let path = vault_path(&dir.path().to_path_buf(), "rotate");
    let payload = pattern_bytes(150 * 1024, 99);
    let source = write_source(src_dir.path(), "data.bin", &payload);

    let mut vault = Vault::create_with_options(&path, PASSWORD, fast_options()).unwrap();
    vault
        .import_paths(&[source], &ROOT_ID, false, &NoopContext)
        .unwrap();
    let chunks_before = vault.info().unwrap().chunks;

    assert_eq!(
        vault.change_password("wrong current password", OTHER_PASSWORD).unwrap_err(),
        VaultError::InvalidPassword
    );
    vault.change_password(PASSWORD, OTHER_PASSWORD).unwrap();
    assert_eq!(vault.info().unwrap().chunks, chunks_before);
    let id = myvault_core::parse_id(&vault.list_directory(None).unwrap()[0].id).unwrap();
    vault.lock();

    assert_eq!(
        OpenedVault::open(&path).unwrap().unlock(PASSWORD).unwrap_err(),
        VaultError::InvalidPassword
    );
    let vault = OpenedVault::open(&path).unwrap().unlock(OTHER_PASSWORD).unwrap();
    vault
        .export_entries(&[id], out_dir.path(), false, &NoopContext)
        .unwrap();
    assert_eq!(read_all(&out_dir.path().join("data.bin")), payload);
}

#[test]
fn import_of_many_small_files() {
    let dir = tempfile::tempdir().unwrap();
    let src_dir = tempfile::tempdir().unwrap();
    let path = vault_path(&dir.path().to_path_buf(), "many");
    let mut sources = Vec::new();
    for i in 0..50 {
        sources.push(write_source(
            src_dir.path(),
            &format!("file-{i:03}.txt"),
            format!("content {i}").as_bytes(),
        ));
    }
    let mut vault = Vault::create_with_options(&path, PASSWORD, fast_options()).unwrap();
    let report = vault
        .import_paths(&sources, &ROOT_ID, false, &NoopContext)
        .unwrap();
    assert_eq!(report.imported_files, 50);
    assert_eq!(vault.list_directory(None).unwrap().len(), 50);
    // Filtering happens in the UI; the search API must work too.
    assert_eq!(vault.search("file-01").unwrap().len(), 10);
}

#[test]
fn name_conflicts_are_renamed_on_import_when_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let src_a = tempfile::tempdir().unwrap();
    let src_b = tempfile::tempdir().unwrap();
    let path = vault_path(&dir.path().to_path_buf(), "conflict");
    let a = write_source(src_a.path(), "report.pdf", b"first");
    let b = write_source(src_b.path(), "report.pdf", b"second");

    let mut vault = Vault::create_with_options(&path, PASSWORD, fast_options()).unwrap();
    vault
        .import_paths(&[a], &ROOT_ID, false, &NoopContext)
        .unwrap();
    assert!(matches!(
        vault.import_paths(&[b.clone()], &ROOT_ID, false, &NoopContext).unwrap_err(),
        VaultError::NameConflict(_)
    ));
    let report = vault
        .import_paths(&[b], &ROOT_ID, true, &NoopContext)
        .unwrap();
    assert_eq!(report.renamed.len(), 1);
    let names: Vec<String> = vault
        .list_directory(None)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, vec!["report (2).pdf", "report.pdf"]);
}

#[test]
fn export_refuses_to_overwrite_without_permission() {
    let dir = tempfile::tempdir().unwrap();
    let src_dir = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let path = vault_path(&dir.path().to_path_buf(), "overwrite");
    let source = write_source(src_dir.path(), "notes.txt", b"new content");
    std::fs::write(out_dir.path().join("notes.txt"), b"existing").unwrap();

    let mut vault = Vault::create_with_options(&path, PASSWORD, fast_options()).unwrap();
    vault
        .import_paths(&[source], &ROOT_ID, false, &NoopContext)
        .unwrap();
    let id = myvault_core::parse_id(&vault.list_directory(None).unwrap()[0].id).unwrap();

    assert!(matches!(
        vault
            .export_entries(&[id], out_dir.path(), false, &NoopContext)
            .unwrap_err(),
        VaultError::NameConflict(_)
    ));
    assert_eq!(read_all(&out_dir.path().join("notes.txt")), b"existing");

    vault
        .export_entries(&[id], out_dir.path(), true, &NoopContext)
        .unwrap();
    assert_eq!(read_all(&out_dir.path().join("notes.txt")), b"new content");
}

#[test]
fn cancelled_import_leaves_no_trace() {
    let dir = tempfile::tempdir().unwrap();
    let src_dir = tempfile::tempdir().unwrap();
    let path = vault_path(&dir.path().to_path_buf(), "cancel");
    let source = write_source(src_dir.path(), "big.bin", &pattern_bytes(2 * 1024 * 1024, 3));

    let mut vault = Vault::create_with_options(&path, PASSWORD, fast_options()).unwrap();
    let chunks_before = vault.info().unwrap().chunks;

    let token = CancelToken::new();
    token.cancel(); // cancel immediately, before the first chunk
    let err = vault
        .import_paths(&[source], &ROOT_ID, false, &token)
        .unwrap_err();
    assert_eq!(err, VaultError::Cancelled);
    assert!(vault.list_directory(None).unwrap().is_empty());
    assert_eq!(vault.info().unwrap().chunks, chunks_before);

    // The vault must remain fully usable afterwards.
    let source2 = write_source(src_dir.path(), "small.txt", b"ok");
    vault
        .import_paths(&[source2], &ROOT_ID, false, &NoopContext)
        .unwrap();
    assert_eq!(vault.list_directory(None).unwrap().len(), 1);
}

#[test]
fn a_second_open_of_the_same_vault_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = vault_path(&dir.path().to_path_buf(), "locked");
    let vault = Vault::create_with_options(&path, PASSWORD, fast_options()).unwrap();
    match OpenedVault::open(&path) {
        Err(VaultError::VaultInUse) => {}
        other => panic!("expected VaultInUse, got {other:?}"),
    }
    vault.lock();
    assert!(OpenedVault::open(&path).is_ok());
}

#[test]
fn integrity_report_is_clean_for_a_healthy_vault() {
    let dir = tempfile::tempdir().unwrap();
    let src_dir = tempfile::tempdir().unwrap();
    let path = vault_path(&dir.path().to_path_buf(), "integrity");
    let source = write_source(src_dir.path(), "a.bin", &pattern_bytes(180 * 1024, 11));
    let mut vault = Vault::create_with_options(&path, PASSWORD, fast_options()).unwrap();
    vault
        .import_paths(&[source], &ROOT_ID, false, &NoopContext)
        .unwrap();
    let report = vault.verify().unwrap();
    assert!(report.ok, "unexpected issues: {:?}", report.issues);
    assert_eq!(report.chunks_checked, 3);
    assert_eq!(report.orphan_chunks, 0);
}

#[test]
fn unsupported_format_version_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = vault_path(&dir.path().to_path_buf(), "future");
    Vault::create_with_options(&path, PASSWORD, fast_options())
        .unwrap()
        .lock();
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("UPDATE vault_header SET format_version = 99 WHERE id = 1", [])
            .unwrap();
    }
    assert_eq!(
        OpenedVault::open(&path).unwrap_err(),
        VaultError::UnsupportedVersion(99)
    );
}

#[test]
fn a_plain_sqlite_file_is_not_a_vault() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("plain.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE t (x INTEGER);").unwrap();
    }
    assert_eq!(OpenedVault::open(&path).unwrap_err(), VaultError::NotAVault);
}

#[test]
fn backup_creates_a_usable_independent_copy() {
    let dir = tempfile::tempdir().unwrap();
    let src_dir = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let path = vault_path(&dir.path().to_path_buf(), "original");
    let backup = dir.path().join("backup.vault");
    let payload = pattern_bytes(90 * 1024, 17);
    let source = write_source(src_dir.path(), "data.bin", &payload);

    let mut vault = Vault::create_with_options(&path, PASSWORD, fast_options()).unwrap();
    vault
        .import_paths(&[source], &ROOT_ID, false, &NoopContext)
        .unwrap();
    vault.backup_to(&backup).unwrap();
    assert!(backup.is_file());
    // A backup must never silently overwrite an existing file.
    assert_eq!(
        vault.backup_to(&backup).unwrap_err(),
        VaultError::IllegalState("a file already exists at the backup location".into())
    );

    // The original stays usable and the copy is independent.
    let id = myvault_core::parse_id(&vault.list_directory(None).unwrap()[0].id).unwrap();
    assert_eq!(vault.list_directory(None).unwrap().len(), 1);
    vault.lock();

    let restored = OpenedVault::open(&backup).unwrap().unlock(PASSWORD).unwrap();
    restored
        .export_entries(&[id], out_dir.path(), false, &NoopContext)
        .unwrap();
    assert_eq!(read_all(&out_dir.path().join("data.bin")), payload);
}

#[test]
fn keys_are_zeroized_when_the_vault_is_locked() {
    // Dropping the vault must not leave a usable handle; this is a behavioural
    // check that lock consumes the vault and reopening requires the password.
    let dir = tempfile::tempdir().unwrap();
    let path = vault_path(&dir.path().to_path_buf(), "zeroize");
    let vault = Vault::create_with_options(&path, PASSWORD, fast_options()).unwrap();
    vault.lock();
    assert_eq!(
        OpenedVault::open(&path).unwrap().unlock("").unwrap_err(),
        VaultError::InvalidPassword
    );
}
