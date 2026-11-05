//! Key hierarchy: the random vault master key (VMK) and its purpose-bound
//! subkeys, plus the password-key envelope.
//!
//! ```text
//! Master Password --Argon2id(salt, params)--> KEK
//! KEK --XChaCha20-Poly1305 unlock--> wrapped VMK
//! VMK --HKDF-SHA256("file")--> file key
//! VMK --HKDF-SHA256("manifest")--> manifest key
//! ```
//!
//! Subkeys mean a file chunk and the manifest never share a raw key, so a
//! ciphertext cannot be moved between purposes even if the AAD were absent.

use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::cipher::{random_bytes, KEY_LEN};
use crate::errors::{VaultError, VaultResult};

const INFO_FILE: &[u8] = b"myvault/subkey/file/v1";
const INFO_MANIFEST: &[u8] = b"myvault/subkey/manifest/v1";

/// A purpose-bound 256-bit subkey, zeroized when dropped.
#[derive(Clone)]
pub struct SubKey(Zeroizing<[u8; KEY_LEN]>);

impl SubKey {
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for SubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SubKey(<redacted>)")
    }
}

/// The random vault master key. Only ever held in the Rust backend.
pub struct VaultMasterKey {
    master: SecretBox<[u8; KEY_LEN]>,
    file: SubKey,
    manifest: SubKey,
}

impl std::fmt::Debug for VaultMasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultMasterKey(<redacted>)")
    }
}

impl VaultMasterKey {
    /// Generate a new random 256-bit vault master key.
    pub fn generate() -> Self {
        Self::from_bytes(random_bytes::<KEY_LEN>())
    }

    /// Rebuild the key object (and its subkeys) from raw bytes.
    /// The input array is zeroized before returning.
    pub fn from_bytes(mut bytes: [u8; KEY_LEN]) -> Self {
        let file = derive_subkey(&bytes, INFO_FILE);
        let manifest = derive_subkey(&bytes, INFO_MANIFEST);
        let key = VaultMasterKey {
            master: SecretBox::new(Box::new(bytes)),
            file,
            manifest,
        };
        bytes.zeroize();
        key
    }

    /// Only for the key-wrapping operation during create/unlock/change-password.
    pub fn expose_master(&self) -> &[u8; KEY_LEN] {
        self.master.expose_secret()
    }

    pub fn file_key(&self) -> &[u8; KEY_LEN] {
        self.file.as_bytes()
    }

    pub fn manifest_key(&self) -> &[u8; KEY_LEN] {
        self.manifest.as_bytes()
    }
}

fn derive_subkey(master: &[u8; KEY_LEN], info: &[u8]) -> SubKey {
    let hk = Hkdf::<Sha256>::new(None, master);
    let mut okm = Zeroizing::new([0u8; KEY_LEN]);
    // expand() only fails for output lengths above 8160 bytes.
    hk.expand(info, okm.as_mut())
        .expect("HKDF output length is fixed and valid");
    SubKey(okm)
}

/// A wrapped (encrypted) vault master key.
#[derive(Clone)]
pub struct WrappedKey {
    pub nonce: [u8; crate::crypto::cipher::NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

impl std::fmt::Debug for WrappedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WrappedKey(<redacted>)")
    }
}

impl WrappedKey {
    pub fn total_len(&self) -> usize {
        self.nonce.len() + self.ciphertext.len()
    }
}

/// Validate that a password is long enough to be a meaningful master secret.
///
/// The SRS forbids relying on a short numeric PIN; a minimum length plus a
/// reject-list of trivially weak patterns is enforced instead of a numeric
/// policy that would push users toward predictable strings.
pub fn validate_password_strength(password: &str) -> VaultResult<()> {
    const MIN_LEN: usize = 10;
    const MAX_LEN: usize = 1024;
    if password.chars().count() < MIN_LEN {
        return Err(VaultError::WeakPassword(format!(
            "use at least {MIN_LEN} characters (a passphrase of several words works well)"
        )));
    }
    if password.chars().count() > MAX_LEN {
        return Err(VaultError::WeakPassword("the password is too long".into()));
    }
    let lower = password.to_lowercase();
    const BANNED: [&str; 8] = [
        "password",
        "12345",
        "qwerty",
        "letmein",
        "admin",
        "iloveyou",
        "welcome",
        "myvault",
    ];
    if BANNED.iter().any(|b| lower.contains(b)) {
        return Err(VaultError::WeakPassword(
            "this password contains a very commonly used word".into(),
        ));
    }
    if lower.chars().all(|c| c.is_ascii_digit()) {
        return Err(VaultError::WeakPassword(
            "a numeric PIN alone is not accepted; add words or symbols".into(),
        ));
    }
    if lower.chars().all(|c| c == lower.chars().next().unwrap()) {
        return Err(VaultError::WeakPassword(
            "the password must not be a single repeated character".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subkeys_are_derived_and_distinct() {
        let k = VaultMasterKey::from_bytes([5u8; KEY_LEN]);
        assert_ne!(k.expose_master(), k.file_key());
        assert_ne!(k.expose_master(), k.manifest_key());
        assert_ne!(k.file_key(), k.manifest_key());
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = VaultMasterKey::from_bytes([7u8; KEY_LEN]);
        let b = VaultMasterKey::from_bytes([7u8; KEY_LEN]);
        assert_eq!(a.file_key(), b.file_key());
        assert_eq!(a.manifest_key(), b.manifest_key());
    }

    #[test]
    fn generated_keys_differ() {
        let a = VaultMasterKey::generate();
        let b = VaultMasterKey::generate();
        assert_ne!(a.expose_master(), b.expose_master());
    }

    #[test]
    fn debug_output_does_not_leak_key_material() {
        let k = VaultMasterKey::generate();
        let rendered = format!("{k:?} {:?}", k.file_key());
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("SubKey(["));
    }

    #[test]
    fn password_strength_policy() {
        assert!(validate_password_strength("correct horse battery staple").is_ok());
        assert!(validate_password_strength("short").is_err());
        assert!(validate_password_strength("1234567890").is_err());
        assert!(validate_password_strength("Password1234!").is_err());
        assert!(validate_password_strength("aaaaaaaaaaaaaa").is_err());
    }
}
