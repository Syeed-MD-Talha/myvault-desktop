//! Cryptographic building blocks. No Tauri, no UI, no storage dependencies.

pub mod aad;
pub mod cipher;
pub mod kdf;
pub mod keys;

pub use aad::{Aad, OBJ_CHUNK, OBJ_MANIFEST, OBJ_VAULT_KEY};
pub use cipher::{open, open_with_nonce, random_bytes, random_nonce, seal, seal_with_nonce};
pub use kdf::{derive_kek, KdfParams, KEK_LEN, SALT_LEN};
pub use keys::{validate_password_strength, VaultMasterKey, WrappedKey};
