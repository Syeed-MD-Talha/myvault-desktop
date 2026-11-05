//! MyVault core engine.
//!
//! Contains every cryptographic and storage operation. It has no GUI or Tauri
//! dependency so that it can be tested without launching the application.
//!
//! Security model in one paragraph: a random 256-bit vault master key encrypts
//! file chunks and the manifest with XChaCha20-Poly1305; the master key is
//! wrapped by a key derived from the master password with Argon2id; the
//! wrapped key, the encrypted manifest and the encrypted chunks are the only
//! things SQLite ever sees.

pub mod crypto;
pub mod errors;
pub mod services;
pub mod storage;

pub use crypto::{KdfParams, VaultMasterKey};
pub use errors::{VaultError, VaultErrorPayload, VaultResult};
pub use services::progress::{CancelToken, NoopContext, OpContext, Progress};
pub use services::transfer::{ExportReport, ImportReport};
pub use services::{TempOpenArea, TempOpenFile};
pub use services::vault::{
    parse_id, Crumb, DeleteReport, EntryView, IntegrityReport, OpenedVault, UnlockResult, Vault,
    VaultInfo, VaultOptions,
};
pub use storage::manifest::{Entry, EntryKind, Id, ROOT_ID};

/// Milliseconds since the Unix epoch, used for manifest timestamps.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The container format version implemented by this build.
pub const FORMAT_VERSION: u16 = storage::header::FORMAT_VERSION;
/// The application version shown in the UI.
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
