//! Tauri commands, grouped by area.

pub mod files;
pub mod settings;
pub mod vault;

use myvault_core::{VaultError, VaultErrorPayload};

pub type CommandResult<T> = Result<T, VaultErrorPayload>;

pub fn to_payload(error: VaultError) -> VaultErrorPayload {
    error.into()
}
