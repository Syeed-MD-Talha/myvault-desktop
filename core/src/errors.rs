//! Typed, structured errors. No variant ever carries secret material.

use std::fmt;

/// Result alias used across the engine.
pub type VaultResult<T> = Result<T, VaultError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    /// Wrong password. Deliberately indistinguishable from a corrupted key
    /// envelope so that unlock failures never leak information.
    InvalidPassword,
    /// The supplied password does not meet the minimum strength policy.
    WeakPassword(String),
    /// The file is not a MyVault container.
    NotAVault,
    /// Container format version is not supported by this build.
    UnsupportedVersion(u16),
    /// Authenticated decryption failed: the data was tampered with or corrupt.
    AuthenticationFailed,
    /// The vault header is malformed or corrupted.
    CorruptHeader,
    /// The encrypted manifest could not be decoded.
    CorruptManifest,
    /// The vault is locked; an unlock is required first.
    VaultLocked,
    /// A vault is already open in this process.
    VaultAlreadyOpen,
    /// The same vault file is already open by another MyVault process.
    VaultInUse,
    /// The requested entry does not exist.
    EntryNotFound,
    /// The requested entry id already exists.
    EntryExists,
    /// An operation was attempted on a wrong entry kind.
    WrongEntryKind,
    /// A name is empty, too long, or contains forbidden characters.
    InvalidName(String),
    /// The operation would create a cycle in the virtual directory tree.
    InvalidMove(String),
    /// A path (physical or virtual) failed validation.
    InvalidPath(String),
    /// Path traversal or an absolute path was attempted.
    PathTraversal(String),
    /// Reparse points (symlinks, junctions) are rejected by default.
    ReparsePointRejected(String),
    /// An entry with that name already exists at the destination.
    NameConflict(String),
    /// Validation of an imported file failed.
    Validation(String),
    /// The source file disappeared or changed while importing/exporting.
    SourceChanged(String),
    /// Not enough disk space to complete the operation.
    InsufficientSpace(String),
    /// The requested vault operation is not possible in the current state.
    IllegalState(String),
    /// File system I/O failure.
    Io(String),
    /// SQLite / storage failure.
    Storage(String),
    /// Manifest serialization or encoding failure.
    Serialization(String),
    /// The database failed an integrity check.
    Integrity(String),
    /// The operation was cancelled by the user.
    Cancelled,
    /// Internal invariant violation. Never contains user data.
    Internal(String),
}

impl VaultError {
    /// Stable machine-readable code used by the frontend.
    pub fn code(&self) -> &'static str {
        match self {
            VaultError::InvalidPassword => "invalid_password",
            VaultError::WeakPassword(_) => "weak_password",
            VaultError::NotAVault => "not_a_vault",
            VaultError::UnsupportedVersion(_) => "unsupported_version",
            VaultError::AuthenticationFailed => "authentication_failed",
            VaultError::CorruptHeader => "corrupt_header",
            VaultError::CorruptManifest => "corrupt_manifest",
            VaultError::VaultLocked => "vault_locked",
            VaultError::VaultAlreadyOpen => "vault_already_open",
            VaultError::VaultInUse => "vault_in_use",
            VaultError::EntryNotFound => "entry_not_found",
            VaultError::EntryExists => "entry_exists",
            VaultError::WrongEntryKind => "wrong_entry_kind",
            VaultError::InvalidName(_) => "invalid_name",
            VaultError::InvalidMove(_) => "invalid_move",
            VaultError::InvalidPath(_) => "invalid_path",
            VaultError::PathTraversal(_) => "path_traversal",
            VaultError::ReparsePointRejected(_) => "reparse_point_rejected",
            VaultError::NameConflict(_) => "name_conflict",
            VaultError::Validation(_) => "validation_failed",
            VaultError::SourceChanged(_) => "source_changed",
            VaultError::InsufficientSpace(_) => "insufficient_space",
            VaultError::IllegalState(_) => "illegal_state",
            VaultError::Io(_) => "io_error",
            VaultError::Storage(_) => "storage_error",
            VaultError::Serialization(_) => "serialization_error",
            VaultError::Integrity(_) => "integrity_error",
            VaultError::Cancelled => "cancelled",
            VaultError::Internal(_) => "internal_error",
        }
    }
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::InvalidPassword => {
                write!(f, "The master password is incorrect, or the vault key envelope is damaged.")
            }
            VaultError::WeakPassword(m) => write!(f, "The password is too weak: {m}"),
            VaultError::NotAVault => write!(f, "The selected file is not a MyVault container."),
            VaultError::UnsupportedVersion(v) => {
                write!(f, "Vault format version {v} is not supported by this build.")
            }
            VaultError::AuthenticationFailed => {
                write!(f, "Integrity check failed. The encrypted data was modified or corrupted.")
            }
            VaultError::CorruptHeader => write!(f, "The vault header is corrupted."),
            VaultError::CorruptManifest => write!(f, "The encrypted manifest is corrupted."),
            VaultError::VaultLocked => write!(f, "The vault is locked."),
            VaultError::VaultAlreadyOpen => write!(f, "A vault is already open."),
            VaultError::VaultInUse => {
                write!(f, "This vault is currently open by another MyVault window.")
            }
            VaultError::EntryNotFound => write!(f, "The requested item no longer exists."),
            VaultError::EntryExists => write!(f, "That item id already exists."),
            VaultError::WrongEntryKind => write!(f, "The item is not the expected type."),
            VaultError::InvalidName(m) => write!(f, "Invalid name: {m}"),
            VaultError::InvalidMove(m) => write!(f, "Cannot move the item: {m}"),
            VaultError::InvalidPath(m) => write!(f, "Invalid path: {m}"),
            VaultError::PathTraversal(m) => write!(f, "Refused unsafe path: {m}"),
            VaultError::ReparsePointRejected(m) => {
                write!(f, "Symbolic links and junctions are not imported: {m}")
            }
            VaultError::NameConflict(m) => write!(f, "An item named \"{m}\" already exists here."),
            VaultError::Validation(m) => write!(f, "Validation failed: {m}"),
            VaultError::SourceChanged(m) => write!(f, "The source changed during the operation: {m}"),
            VaultError::InsufficientSpace(m) => write!(f, "Not enough disk space: {m}"),
            VaultError::IllegalState(m) => write!(f, "Operation not allowed: {m}"),
            VaultError::Io(m) => write!(f, "File system error: {m}"),
            VaultError::Storage(m) => write!(f, "Storage error: {m}"),
            VaultError::Serialization(m) => write!(f, "Encoding error: {m}"),
            VaultError::Integrity(m) => write!(f, "Integrity error: {m}"),
            VaultError::Cancelled => write!(f, "The operation was cancelled."),
            VaultError::Internal(m) => write!(f, "Internal error: {m}"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        // Map the two error kinds the SRS explicitly calls out.
        match e.kind() {
            std::io::ErrorKind::PermissionDenied => VaultError::Io("permission denied".into()),
            std::io::ErrorKind::StorageFull => VaultError::InsufficientSpace("device is full".into()),
            _ => VaultError::Io(e.to_string()),
        }
    }
}

impl From<rusqlite::Error> for VaultError {
    fn from(e: rusqlite::Error) -> Self {
        VaultError::Storage(e.to_string())
    }
}

impl From<serde_json::Error> for VaultError {
    fn from(e: serde_json::Error) -> Self {
        VaultError::Serialization(e.to_string())
    }
}

impl From<argon2::Error> for VaultError {
    fn from(e: argon2::Error) -> Self {
        VaultError::Internal(format!("argon2: {e}"))
    }
}

/// Convert a core error into a serializable payload for the UI boundary.
#[derive(Debug, serde::Serialize)]
pub struct VaultErrorPayload {
    pub code: &'static str,
    pub message: String,
}

impl From<VaultError> for VaultErrorPayload {
    fn from(e: VaultError) -> Self {
        VaultErrorPayload {
            code: e.code(),
            message: e.to_string(),
        }
    }
}
