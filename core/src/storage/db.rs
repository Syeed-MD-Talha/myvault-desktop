//! SQLite connection handling and the on-disk schema.
//!
//! SQLite is a storage engine only: it never receives plaintext file content,
//! plaintext names, paths, or the master password.

use std::path::Path;

use rusqlite::Connection;

use crate::errors::{VaultError, VaultResult};

/// Bumped only when the on-disk schema changes. The cryptographic container
/// format version lives in the vault header and is independent.
pub const SCHEMA_VERSION: i64 = 1;

pub const MAGIC_APPLICATION_ID: i64 = 0x4D59_564C; // "MYVL"

pub const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS vault_header (
    id               INTEGER PRIMARY KEY CHECK (id = 1),
    format_version   INTEGER NOT NULL,
    vault_id         BLOB    NOT NULL,
    kdf_algorithm    TEXT    NOT NULL,
    kdf_salt         BLOB    NOT NULL,
    kdf_params       TEXT    NOT NULL,
    key_nonce        BLOB    NOT NULL,
    wrapped_master_key BLOB  NOT NULL,
    created_ms       INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS encrypted_manifest (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    nonce      BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    updated_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS encrypted_chunks (
    chunk_id   BLOB PRIMARY KEY,
    nonce      BLOB NOT NULL,
    ciphertext BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS vault_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#;

/// Open (creating if necessary) a vault database and apply pragmas.
///
/// Durability pragmas:
/// * `journal_mode=DELETE` keeps the container a single file outside of active
///   transactions and provides rollback on crash.
/// * `synchronous=FULL` makes commits durable across power loss, which the SRS
///   requires for interrupted imports.
pub fn open(path: &Path) -> VaultResult<Connection> {
    let conn = Connection::open(path).map_err(|e| VaultError::Storage(e.to_string()))?;
    configure(&conn)?;
    Ok(conn)
}

/// Open a vault database for exclusive use by this process.
///
/// SQLite's exclusive locking mode holds an operating-system file lock for the
/// lifetime of the connection, so a second MyVault process (or window) cannot
/// open the same vault and produce conflicting writers. The lock is released
/// automatically by the OS if the process dies.
pub fn open_exclusive(path: &Path) -> VaultResult<Connection> {
    use std::time::Duration;

    let conn = Connection::open(path).map_err(|e| VaultError::Storage(e.to_string()))?;
    configure(&conn)?;
    conn.busy_timeout(Duration::from_millis(250))?;
    conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?;
    // The first read acquires and retains the lock.
    let probe = conn.query_row("SELECT COUNT(*) FROM sqlite_master", [], |r| {
        r.get::<_, i64>(0)
    });
    if let Err(rusqlite::Error::SqliteFailure(err, _)) = &probe {
        if err.code == rusqlite::ErrorCode::DatabaseBusy {
            return Err(VaultError::VaultInUse);
        }
    }
    probe.map_err(VaultError::from)?;
    conn.busy_timeout(Duration::from_secs(10))?;
    Ok(conn)
}

pub fn configure(conn: &Connection) -> VaultResult<()> {
    conn.pragma_update(None, "journal_mode", "DELETE")?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "secure_delete", "ON")?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    Ok(())
}

/// Create the schema in a brand new database file.
pub fn initialize(conn: &Connection) -> VaultResult<()> {
    conn.execute_batch(SCHEMA_SQL)?;
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    conn.pragma_update(None, "application_id", MAGIC_APPLICATION_ID)?;
    Ok(())
}

/// True when the file exists and already carries the MyVault application id.
pub fn is_initialized(conn: &Connection) -> VaultResult<bool> {
    let app_id: i64 = conn.pragma_query_value(None, "application_id", |r| r.get(0))?;
    Ok(app_id == MAGIC_APPLICATION_ID)
}

pub fn schema_version(conn: &Connection) -> VaultResult<i64> {
    Ok(conn.pragma_query_value(None, "user_version", |r| r.get(0))?)
}

/// Lightweight structural check used before a vault is opened.
pub fn check_schema(conn: &Connection) -> VaultResult<()> {
    if !is_initialized(conn)? {
        return Err(VaultError::NotAVault);
    }
    let v = schema_version(conn)?;
    if v != SCHEMA_VERSION {
        return Err(VaultError::UnsupportedVersion(v as u16));
    }
    // Force SQLite to parse the schema.
    conn.execute_batch(
        "SELECT id, format_version, vault_id, kdf_algorithm, kdf_salt, kdf_params, key_nonce, \
         wrapped_master_key, created_ms FROM vault_header LIMIT 1;",
    )
    .map_err(|_| VaultError::CorruptHeader)?;
    Ok(())
}

/// Run SQLite's own structural integrity check (`PRAGMA quick_check`).
pub fn quick_check(conn: &Connection) -> VaultResult<()> {
    let result: String = conn
        .query_row("PRAGMA quick_check(1)", [], |r| r.get(0))
        .map_err(|e| VaultError::Integrity(e.to_string()))?;
    if result != "ok" {
        return Err(VaultError::Integrity(result));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_database_is_initialized_and_checked() {
        let conn = Connection::open_in_memory().unwrap();
        configure(&conn).unwrap();
        assert!(!is_initialized(&conn).unwrap());
        initialize(&conn).unwrap();
        assert!(is_initialized(&conn).unwrap());
        check_schema(&conn).unwrap();
        assert_eq!(schema_version(&conn).unwrap(), SCHEMA_VERSION);
        quick_check(&conn).unwrap();
    }

    #[test]
    fn plain_sqlite_file_is_not_a_vault() {
        let conn = Connection::open_in_memory().unwrap();
        assert_eq!(check_schema(&conn).unwrap_err(), VaultError::NotAVault);
    }

    #[test]
    fn schema_version_mismatch_is_refused() {
        let conn = Connection::open_in_memory().unwrap();
        initialize(&conn).unwrap();
        conn.pragma_update(None, "user_version", 99i64).unwrap();
        assert_eq!(
            check_schema(&conn).unwrap_err(),
            VaultError::UnsupportedVersion(99)
        );
    }
}
