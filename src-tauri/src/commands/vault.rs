//! Vault lifecycle commands: create, open, unlock, lock, info, password
//! change and integrity verification.

use serde::Serialize;
use tauri::{AppHandle, State};
use zeroize::Zeroizing;

use myvault_core::{IntegrityReport, OpenedVault, UnlockResult, Vault, VaultError, VaultInfo};

use crate::commands::{to_payload, CommandResult};
use crate::state::{AppState, UiContext};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenedSummary {
    pub path: String,
    pub name: String,
    pub format_version: u16,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub version: &'static str,
    pub format_version: u16,
    pub platform: &'static str,
    pub chunk_size: usize,
    pub kdf: String,
}

#[tauri::command]
pub fn app_info() -> AppInfo {
    AppInfo {
        version: myvault_core::APP_VERSION,
        format_version: myvault_core::FORMAT_VERSION,
        platform: std::env::consts::OS,
        chunk_size: 1024 * 1024,
        kdf: myvault_core::KdfParams::default().describe(),
    }
}

#[tauri::command]
pub async fn create_vault(
    state: State<'_, AppState>,
    path: String,
    password: String,
) -> CommandResult<OpenedSummary> {
    if state.vault.lock().map_err(lock_error)?.is_some() {
        return Err(to_payload(VaultError::VaultAlreadyOpen));
    }
    // Drop any previously selected container so its lock is released.
    let previous = state.opened.lock().map_err(lock_error)?.take();
    drop(previous);
    let secret = Zeroizing::new(password);
    let created = tauri::async_runtime::spawn_blocking(move || {
        Vault::create(&path, secret.as_str()).map_err(to_payload)
    })
    .await
    .map_err(join_error)??;

    let info = created.info().map_err(to_payload)?;
    let summary = OpenedSummary {
        path: info.path,
        name: info.name,
        format_version: info.format_version,
    };
    *state.vault.lock().map_err(lock_error)? = Some(created);
    Ok(summary)
}

#[tauri::command]
pub async fn open_vault(state: State<'_, AppState>, path: String) -> CommandResult<OpenedSummary> {
    if state.vault.lock().map_err(lock_error)?.is_some() {
        return Err(to_payload(VaultError::VaultAlreadyOpen));
    }
    let opened =
        tauri::async_runtime::spawn_blocking(move || OpenedVault::open(&path).map_err(to_payload))
            .await
            .map_err(join_error)??;

    let summary = OpenedSummary {
        path: opened.path().to_string_lossy().to_string(),
        name: opened.name_hint(),
        format_version: opened.format_version(),
    };
    *state.opened.lock().map_err(lock_error)? = Some(opened);
    Ok(summary)
}

#[tauri::command]
pub async fn unlock_vault(
    state: State<'_, AppState>,
    password: String,
) -> CommandResult<UnlockResult> {
    let opened = state
        .opened
        .lock()
        .map_err(lock_error)?
        .take()
        .ok_or_else(|| to_payload(VaultError::IllegalState("no vault is selected".into())))?;
    let path = opened.path().to_path_buf();
    let secret = Zeroizing::new(password);

    let outcome = tauri::async_runtime::spawn_blocking(move || -> Result<_, VaultError> {
        let vault = opened.unlock(secret.as_str())?;
        let info = vault.info()?;
        let unlock_ms = vault.unlock_ms();
        Ok((vault, UnlockResult { unlock_ms, info }))
    })
    .await
    .map_err(join_error)?;

    match outcome {
        Ok((vault, unlocked)) => {
            *state.vault.lock().map_err(lock_error)? = Some(vault);
            Ok(unlocked)
        }
        Err(e) => {
            // Keep the container selected so the user can retry the password.
            if let Ok(reopened) = OpenedVault::open(&path) {
                *state.opened.lock().map_err(lock_error)? = Some(reopened);
            }
            Err(to_payload(e))
        }
    }
}

#[tauri::command]
pub fn lock_vault(state: State<'_, AppState>) -> CommandResult<()> {
    // Bump the epoch first so any operation that finishes later discards its
    // vault instead of resurrecting the unlocked state.
    state.bump_epoch();
    state.cancel.cancel();
    let vault = state.vault.lock().map_err(lock_error)?.take();
    drop(vault);
    let opened = state.opened.lock().map_err(lock_error)?.take();
    drop(opened);
    // Remove every decrypted copy created for "open in default application".
    let removed = myvault_core::TempOpenArea::default_area().remove_all();
    let _ = removed;
    Ok(())
}

#[tauri::command]
pub fn vault_info(state: State<'_, AppState>) -> CommandResult<VaultInfo> {
    let guard = state.vault.lock().map_err(lock_error)?;
    let vault = guard
        .as_ref()
        .ok_or_else(|| to_payload(VaultError::VaultLocked))?;
    vault.info().map_err(to_payload)
}

#[tauri::command]
pub async fn change_password(
    state: State<'_, AppState>,
    current_password: String,
    new_password: String,
) -> CommandResult<()> {
    let current = Zeroizing::new(current_password);
    let new = Zeroizing::new(new_password);
    let vault = state
        .vault
        .lock()
        .map_err(lock_error)?
        .take()
        .ok_or_else(|| to_payload(VaultError::VaultLocked))?;
    let epoch = state.current_epoch();

    // Key derivation is intentionally slow; keep it off the UI thread and own
    // the vault for the duration so no other command can interleave.
    let (vault, outcome) = tauri::async_runtime::spawn_blocking(move || {
        let mut vault = vault;
        let result = vault
            .change_password(current.as_str(), new.as_str())
            .map_err(to_payload);
        (vault, result)
    })
    .await
    .map_err(join_error)?;

    if state.current_epoch() == epoch {
        *state.vault.lock().map_err(lock_error)? = Some(vault);
        outcome
    } else {
        drop(vault);
        Err(to_payload(VaultError::VaultLocked))
    }
}

#[tauri::command]
pub async fn verify_vault_integrity(
    state: State<'_, AppState>,
    app: AppHandle,
) -> CommandResult<IntegrityReport> {
    let vault = state
        .vault
        .lock()
        .map_err(lock_error)?
        .take()
        .ok_or_else(|| to_payload(VaultError::VaultLocked))?;
    state.cancel.reset();
    let epoch = state.current_epoch();
    let ctx = UiContext {
        app,
        cancel: state.cancel.clone(),
    };

    let (vault, outcome) = tauri::async_runtime::spawn_blocking(move || {
        let report = vault.verify_integrity(&ctx).map_err(to_payload);
        (vault, report)
    })
    .await
    .map_err(join_error)?;

    if state.current_epoch() == epoch {
        *state.vault.lock().map_err(lock_error)? = Some(vault);
        outcome
    } else {
        drop(vault);
        Err(to_payload(VaultError::VaultLocked))
    }
}

#[tauri::command]
pub async fn backup_vault(
    state: State<'_, AppState>,
    destination_path: String,
) -> CommandResult<String> {
    let vault = state
        .vault
        .lock()
        .map_err(lock_error)?
        .take()
        .ok_or_else(|| to_payload(VaultError::VaultLocked))?;
    let epoch = state.current_epoch();
    let path = std::path::PathBuf::from(destination_path);
    let backup_path = path.clone();

    let (vault, outcome) = tauri::async_runtime::spawn_blocking(move || {
        let result = vault.backup_to(&backup_path).map_err(to_payload);
        (vault, result)
    })
    .await
    .map_err(join_error)?;

    if state.current_epoch() == epoch {
        *state.vault.lock().map_err(lock_error)? = Some(vault);
        outcome.map(|_| path.to_string_lossy().to_string())
    } else {
        drop(vault);
        Err(to_payload(VaultError::VaultLocked))
    }
}

fn lock_error<T>(_: T) -> myvault_core::VaultErrorPayload {
    to_payload(VaultError::Internal(
        "the application state is unavailable".into(),
    ))
}

fn join_error(e: tauri::Error) -> myvault_core::VaultErrorPayload {
    to_payload(VaultError::Internal(format!(
        "background task failed: {e}"
    )))
}
