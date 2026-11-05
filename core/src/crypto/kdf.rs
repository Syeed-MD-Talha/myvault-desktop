//! Password-based key derivation (Argon2id).
//!
//! The derived key is a Key Encryption Key (KEK). It is used only to wrap and
//! unwrap the random vault master key; it never encrypts file or manifest data
//! directly.

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::errors::{VaultError, VaultResult};

pub const KDF_ALGORITHM: &str = "argon2id";
pub const SALT_LEN: usize = 16;
pub const KEK_LEN: usize = 32;

/// Bounds that protect against a hostile header demanding absurd resources.
const MIN_M_COST_KIB: u32 = 8 * 1024;
const MAX_M_COST_KIB: u32 = 1024 * 1024;
const MIN_T_COST: u32 = 1;
const MAX_T_COST: u32 = 10;
const MIN_P_COST: u32 = 1;
const MAX_P_COST: u32 = 8;

/// Argon2id parameters. Stored in the vault header so that the format remains
/// upgradeable: raising the cost in a future version does not break old vaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Number of passes.
    pub t_cost: u32,
    /// Degree of parallelism.
    pub p_cost: u32,
    /// Length of the derived key in bytes.
    pub key_len: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams {
            m_cost_kib: 64 * 1024, // 64 MiB
            t_cost: 3,
            p_cost: 1,
            key_len: KEK_LEN as u32,
        }
    }
}

impl KdfParams {
    pub fn validate(&self) -> VaultResult<()> {
        if !(MIN_M_COST_KIB..=MAX_M_COST_KIB).contains(&self.m_cost_kib) {
            return Err(VaultError::CorruptHeader);
        }
        if !(MIN_T_COST..=MAX_T_COST).contains(&self.t_cost) {
            return Err(VaultError::CorruptHeader);
        }
        if !(MIN_P_COST..=MAX_P_COST).contains(&self.p_cost) {
            return Err(VaultError::CorruptHeader);
        }
        if self.key_len != KEK_LEN as u32 {
            return Err(VaultError::CorruptHeader);
        }
        Ok(())
    }

    /// Human readable cost summary for the vault info panel.
    pub fn describe(&self) -> String {
        format!(
            "argon2id, {} MiB, {} iterations, {} lanes",
            self.m_cost_kib / 1024,
            self.t_cost,
            self.p_cost
        )
    }
}

/// Derive the key encryption key from the master password.
///
/// The password bytes are wiped by the caller; the returned key is zeroized on
/// drop.
pub fn derive_kek(
    password: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> VaultResult<Zeroizing<[u8; KEK_LEN]>> {
    params.validate()?;
    if salt.len() != SALT_LEN {
        return Err(VaultError::CorruptHeader);
    }
    let argon_params = Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(KEK_LEN))
        .map_err(VaultError::from)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = Zeroizing::new([0u8; KEK_LEN]);
    argon
        .hash_password_into(password, salt, out.as_mut())
        .map_err(VaultError::from)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cheap parameters so the test suite stays fast; production defaults are
    /// exercised once in `kdf_default_params_are_usable`.
    fn fast() -> KdfParams {
        KdfParams {
            m_cost_kib: MIN_M_COST_KIB,
            t_cost: 1,
            p_cost: 1,
            key_len: KEK_LEN as u32,
        }
    }

    #[test]
    fn derivation_is_deterministic_for_same_inputs() {
        let salt = [3u8; SALT_LEN];
        let a = derive_kek(b"correct horse battery staple", &salt, &fast()).unwrap();
        let b = derive_kek(b"correct horse battery staple", &salt, &fast()).unwrap();
        assert_eq!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn different_password_changes_key() {
        let salt = [3u8; SALT_LEN];
        let a = derive_kek(b"password-a", &salt, &fast()).unwrap();
        let b = derive_kek(b"password-b", &salt, &fast()).unwrap();
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn different_salt_changes_key() {
        let a = derive_kek(b"same password", &[1u8; SALT_LEN], &fast()).unwrap();
        let b = derive_kek(b"same password", &[2u8; SALT_LEN], &fast()).unwrap();
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn hostile_parameters_are_rejected() {
        let salt = [3u8; SALT_LEN];
        let huge = KdfParams {
            m_cost_kib: u32::MAX,
            ..fast()
        };
        assert_eq!(
            derive_kek(b"p", &salt, &huge).unwrap_err(),
            VaultError::CorruptHeader
        );
        let zero_iters = KdfParams {
            t_cost: 0,
            ..fast()
        };
        assert_eq!(
            derive_kek(b"p", &salt, &zero_iters).unwrap_err(),
            VaultError::CorruptHeader
        );
        let bad_salt_len = derive_kek(b"p", &[0u8; 5], &fast());
        assert_eq!(bad_salt_len.unwrap_err(), VaultError::CorruptHeader);
    }

    #[test]
    fn default_parameters_are_usable() {
        let salt = [9u8; SALT_LEN];
        let p = KdfParams::default();
        p.validate().unwrap();
        let k = derive_kek(b"a reasonably long master passphrase", &salt, &p).unwrap();
        assert_eq!(k.as_ref().len(), KEK_LEN);
    }
}
