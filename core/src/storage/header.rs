//! Persistence of the authenticated vault header.

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::crypto::aad::{Aad, OBJ_VAULT_KEY};
use crate::crypto::cipher::{self, NONCE_LEN};
use crate::crypto::kdf::{KdfParams, KDF_ALGORITHM};
use crate::crypto::keys::VaultMasterKey;
use crate::errors::{VaultError, VaultResult};
use crate::storage::manifest::Id;

/// Container format version. This value is bound into every AAD, so a
/// ciphertext produced by another format version can never be accepted.
pub const FORMAT_VERSION: u16 = 1;
pub const ENCRYPTION_ALGORITHM: &str = "xchacha20poly1305";
pub const WRAPPED_KEY_LEN: usize = cipher::KEY_LEN + cipher::TAG_LEN;

#[derive(Clone, Debug)]
pub struct VaultHeader {
    pub format_version: u16,
    pub vault_id: Id,
    pub kdf_algorithm: String,
    pub kdf_salt: Vec<u8>,
    pub kdf_params: KdfParams,
    pub key_nonce: [u8; NONCE_LEN],
    pub wrapped_master_key: Vec<u8>,
    pub created_ms: u64,
}

/// Serialized KDF parameters stored in the header (versioned JSON so future
/// parameters can be added without a schema change).
#[derive(Serialize, Deserialize)]
struct StoredKdfParams {
    algorithm: String,
    params: KdfParams,
    encryption: String,
}

impl VaultHeader {
    pub fn read(conn: &Connection) -> VaultResult<Self> {
        let row = conn
            .query_row(
                "SELECT format_version, vault_id, kdf_algorithm, kdf_salt, kdf_params, key_nonce, \
                 wrapped_master_key, created_ms FROM vault_header WHERE id = 1",
                [],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, Vec<u8>>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, Vec<u8>>(5)?,
                        r.get::<_, Vec<u8>>(6)?,
                        r.get::<_, i64>(7)?,
                    ))
                },
            )
            .optional()?
            .ok_or(VaultError::CorruptHeader)?;

        let (format_version, vault_id_raw, kdf_algorithm, kdf_salt, kdf_params_raw, nonce_raw, wrapped, created_ms) = row;

        if vault_id_raw.len() != 16 || nonce_raw.len() != NONCE_LEN {
            return Err(VaultError::CorruptHeader);
        }
        if !(0..=u16::MAX as i64).contains(&format_version) {
            return Err(VaultError::CorruptHeader);
        }
        let mut vault_id = [0u8; 16];
        vault_id.copy_from_slice(&vault_id_raw);
        let mut key_nonce = [0u8; NONCE_LEN];
        key_nonce.copy_from_slice(&nonce_raw);

        let stored: StoredKdfParams = serde_json::from_str(&kdf_params_raw)
            .map_err(|_| VaultError::CorruptHeader)?;
        if stored.algorithm != KDF_ALGORITHM || stored.encryption != ENCRYPTION_ALGORITHM {
            return Err(VaultError::CorruptHeader);
        }
        if kdf_algorithm != stored.algorithm {
            return Err(VaultError::CorruptHeader);
        }
        if wrapped.len() != WRAPPED_KEY_LEN || kdf_salt.len() != crate::crypto::SALT_LEN {
            return Err(VaultError::CorruptHeader);
        }
        stored.params.validate()?;

        Ok(VaultHeader {
            format_version: format_version as u16,
            vault_id,
            kdf_algorithm,
            kdf_salt,
            kdf_params: stored.params,
            key_nonce,
            wrapped_master_key: wrapped,
            created_ms: created_ms as u64,
        })
    }

    pub fn insert(&self, conn: &Connection) -> VaultResult<()> {
        let stored = StoredKdfParams {
            algorithm: self.kdf_algorithm.clone(),
            params: self.kdf_params,
            encryption: ENCRYPTION_ALGORITHM.into(),
        };
        let params_json = serde_json::to_string(&stored)?;
        conn.execute(
            "INSERT INTO vault_header (id, format_version, vault_id, kdf_algorithm, kdf_salt, \
             kdf_params, key_nonce, wrapped_master_key, created_ms) \
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                self.format_version as i64,
                &self.vault_id[..],
                self.kdf_algorithm,
                self.kdf_salt,
                params_json,
                &self.key_nonce[..],
                self.wrapped_master_key,
                self.created_ms as i64
            ],
        )?;
        Ok(())
    }

    /// Atomically replace the key envelope (used by change-password).
    pub fn update_envelope(
        conn: &Connection,
        nonce: &[u8; NONCE_LEN],
        wrapped: &[u8],
        salt: &[u8],
        params: &KdfParams,
    ) -> VaultResult<()> {
        let stored = StoredKdfParams {
            algorithm: KDF_ALGORITHM.into(),
            params: *params,
            encryption: ENCRYPTION_ALGORITHM.into(),
        };
        let params_json = serde_json::to_string(&stored)?;
        let changed = conn.execute(
            "UPDATE vault_header SET key_nonce = ?1, wrapped_master_key = ?2, kdf_salt = ?3, \
             kdf_params = ?4 WHERE id = 1",
            params![&nonce[..], wrapped, salt, params_json],
        )?;
        if changed != 1 {
            return Err(VaultError::CorruptHeader);
        }
        Ok(())
    }
}

/// Domains for the wrapped-key envelope.
pub fn key_aad(vault_id: &Id) -> Vec<u8> {
    Aad::new(OBJ_VAULT_KEY, *vault_id, *vault_id, 0).encode(FORMAT_VERSION)
}

/// Wrap the vault master key under the password-derived KEK.
pub fn wrap_master_key(
    kek: &[u8; cipher::KEY_LEN],
    vault_id: &Id,
    master: &VaultMasterKey,
) -> VaultResult<([u8; NONCE_LEN], Vec<u8>)> {
    let nonce = cipher::random_nonce();
    let ciphertext = cipher::seal_with_nonce(kek, &nonce, &key_aad(vault_id), master.expose_master())?;
    Ok((nonce, ciphertext))
}

/// Unwrap the vault master key. Any authentication failure is reported as a
/// generic invalid-password error so an attacker learns nothing from the
/// difference between a wrong password and a damaged envelope.
pub fn unwrap_master_key(
    kek: &[u8; cipher::KEY_LEN],
    header: &VaultHeader,
) -> VaultResult<VaultMasterKey> {
    let plain = cipher::open_with_nonce(
        kek,
        &header.key_nonce,
        &key_aad(&header.vault_id),
        &header.wrapped_master_key,
    )
    .map_err(|_| VaultError::InvalidPassword)?;
    if plain.len() != cipher::KEY_LEN {
        return Err(VaultError::CorruptHeader);
    }
    let mut bytes = [0u8; cipher::KEY_LEN];
    bytes.copy_from_slice(&plain);
    Ok(VaultMasterKey::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db;

    const PW: &[u8] = b"a sufficiently long test passphrase";

    fn setup() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        db::configure(&conn).unwrap();
        db::initialize(&conn).unwrap();
        conn
    }

    fn fast_params() -> KdfParams {
        KdfParams {
            m_cost_kib: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
            key_len: 32,
        }
    }

    fn make_header(conn: &Connection, master: &VaultMasterKey) -> VaultHeader {
        let vault_id = [3u8; 16];
        let salt = vec![7u8; crate::crypto::SALT_LEN];
        let params = fast_params();
        let kek = crate::crypto::derive_kek(PW, &salt, &params).unwrap();
        let (nonce, wrapped) = wrap_master_key(&kek, &vault_id, master).unwrap();
        let header = VaultHeader {
            format_version: FORMAT_VERSION,
            vault_id,
            kdf_algorithm: KDF_ALGORITHM.into(),
            kdf_salt: salt,
            kdf_params: params,
            key_nonce: nonce,
            wrapped_master_key: wrapped,
            created_ms: 1,
        };
        header.insert(conn).unwrap();
        header
    }

    #[test]
    fn header_round_trips() {
        let conn = setup();
        let master = VaultMasterKey::generate();
        let header = make_header(&conn, &master);
        let read = VaultHeader::read(&conn).unwrap();
        assert_eq!(read.format_version, FORMAT_VERSION);
        assert_eq!(read.vault_id, header.vault_id);
        assert_eq!(read.kdf_salt, header.kdf_salt);
    }

    #[test]
    fn correct_password_unwraps_same_master_key() {
        let conn = setup();
        let master = VaultMasterKey::generate();
        let header = make_header(&conn, &master);
        let kek = crate::crypto::derive_kek(PW, &header.kdf_salt, &header.kdf_params).unwrap();
        let unwrapped = unwrap_master_key(&kek, &header).unwrap();
        assert_eq!(unwrapped.expose_master(), master.expose_master());
        assert_eq!(unwrapped.file_key(), master.file_key());
    }

    #[test]
    fn wrong_password_reports_generic_error() {
        let conn = setup();
        let master = VaultMasterKey::generate();
        let header = make_header(&conn, &master);
        let kek =
            crate::crypto::derive_kek(b"another passphrase entirely", &header.kdf_salt, &header.kdf_params)
                .unwrap();
        assert_eq!(
            unwrap_master_key(&kek, &header).unwrap_err(),
            VaultError::InvalidPassword
        );
    }

    #[test]
    fn damaged_envelope_reports_generic_error() {
        let conn = setup();
        let master = VaultMasterKey::generate();
        let mut header = make_header(&conn, &master);
        header.wrapped_master_key[0] ^= 0xff;
        let kek = crate::crypto::derive_kek(PW, &header.kdf_salt, &header.kdf_params).unwrap();
        assert_eq!(
            unwrap_master_key(&kek, &header).unwrap_err(),
            VaultError::InvalidPassword
        );
    }

    #[test]
    fn truncated_or_malformed_header_is_rejected() {
        let conn = setup();
        conn.execute(
            "INSERT INTO vault_header VALUES (1, 1, x'00', 'argon2id', x'00', '{}', x'00', x'00', 0)",
            [],
        )
        .unwrap();
        assert_eq!(VaultHeader::read(&conn).unwrap_err(), VaultError::CorruptHeader);
    }

    #[test]
    fn unknown_algorithm_is_rejected() {
        let conn = setup();
        let master = VaultMasterKey::generate();
        make_header(&conn, &master);
        conn.execute(
            "UPDATE vault_header SET kdf_algorithm = 'pbkdf2' WHERE id = 1",
            [],
        )
        .unwrap();
        assert_eq!(VaultHeader::read(&conn).unwrap_err(), VaultError::CorruptHeader);
    }
}
