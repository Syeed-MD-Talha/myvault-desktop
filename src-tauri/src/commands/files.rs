//! Virtual file-system commands: navigation, mutations, import and export.

use tauri::{AppHandle, State};

use myvault_core::{
    parse_id, Crumb, DeleteReport, EntryView, ExportReport, ImportReport, TempOpenArea, Vault,
    VaultError,
};

use crate::commands::{to_payload, CommandResult};
use crate::state::{AppState, UiContext};

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenEntryResult {
    pub path: String,
    pub name: String,
    pub temporary_root: String,
    pub warnings: Vec<String>,
}

fn locked() -> myvault_core::VaultErrorPayload {
    to_payload(VaultError::VaultLocked)
}

#[tauri::command]
pub fn list_directory(
    state: State<'_, AppState>,
    directory_id: Option<String>,
) -> CommandResult<Vec<EntryView>> {
    let guard = state
        .vault
        .lock()
        .map_err(|_| to_payload(VaultError::Internal("state unavailable".into())))?;
    let vault = guard.as_ref().ok_or_else(locked)?;
    let dir = match directory_id {
        Some(id) => Some(parse_id(&id).map_err(to_payload)?),
        None => None,
    };
    vault.list_directory(dir.as_ref()).map_err(to_payload)
}

#[tauri::command]
pub fn breadcrumbs(state: State<'_, AppState>, id: String) -> CommandResult<Vec<Crumb>> {
    let guard = state
        .vault
        .lock()
        .map_err(|_| to_payload(VaultError::Internal("state unavailable".into())))?;
    let vault = guard.as_ref().ok_or_else(locked)?;
    let id = parse_id(&id).map_err(to_payload)?;
    vault.breadcrumbs(&id).map_err(to_payload)
}

#[tauri::command]
pub fn search_entries(state: State<'_, AppState>, query: String) -> CommandResult<Vec<EntryView>> {
    let guard = state
        .vault
        .lock()
        .map_err(|_| to_payload(VaultError::Internal("state unavailable".into())))?;
    let vault = guard.as_ref().ok_or_else(locked)?;
    vault.search(&query).map_err(to_payload)
}

#[tauri::command]
pub fn list_directories(state: State<'_, AppState>) -> CommandResult<Vec<EntryView>> {
    let guard = state
        .vault
        .lock()
        .map_err(|_| to_payload(VaultError::Internal("state unavailable".into())))?;
    let vault = guard.as_ref().ok_or_else(locked)?;
    Ok(vault.directories())
}

#[tauri::command]
pub fn create_directory(
    state: State<'_, AppState>,
    parent_id: String,
    name: String,
) -> CommandResult<EntryView> {
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| to_payload(VaultError::Internal("state unavailable".into())))?;
    let vault = guard.as_mut().ok_or_else(locked)?;
    let parent = parse_id(&parent_id).map_err(to_payload)?;
    vault.create_directory(&parent, &name).map_err(to_payload)
}

#[tauri::command]
pub fn rename_entry(
    state: State<'_, AppState>,
    id: String,
    new_name: String,
) -> CommandResult<EntryView> {
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| to_payload(VaultError::Internal("state unavailable".into())))?;
    let vault = guard.as_mut().ok_or_else(locked)?;
    let id = parse_id(&id).map_err(to_payload)?;
    vault.rename_entry(&id, &new_name).map_err(to_payload)
}

#[tauri::command]
pub fn delete_entry(state: State<'_, AppState>, id: String) -> CommandResult<DeleteReport> {
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| to_payload(VaultError::Internal("state unavailable".into())))?;
    let vault = guard.as_mut().ok_or_else(locked)?;
    let id = parse_id(&id).map_err(to_payload)?;
    vault.delete_entry(&id).map_err(to_payload)
}

#[tauri::command]
pub fn move_entry(
    state: State<'_, AppState>,
    id: String,
    destination_id: String,
) -> CommandResult<EntryView> {
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| to_payload(VaultError::Internal("state unavailable".into())))?;
    let vault = guard.as_mut().ok_or_else(locked)?;
    let id = parse_id(&id).map_err(to_payload)?;
    let destination = parse_id(&destination_id).map_err(to_payload)?;
    vault.move_entry(&id, &destination).map_err(to_payload)
}

#[tauri::command]
pub async fn import_files(
    state: State<'_, AppState>,
    app: AppHandle,
    paths: Vec<String>,
    destination_id: String,
    rename_on_conflict: bool,
) -> CommandResult<ImportReport> {
    let vault = state
        .vault
        .lock()
        .map_err(|_| to_payload(VaultError::Internal("state unavailable".into())))?
        .take()
        .ok_or_else(locked)?;
    state.cancel.reset();
    let epoch = state.current_epoch();
    let ctx = UiContext {
        app,
        cancel: state.cancel.clone(),
    };

    let (vault, outcome) = tauri::async_runtime::spawn_blocking(move || {
        let mut vault = vault;
        let result = import_blocking(&mut vault, paths, destination_id, rename_on_conflict, &ctx);
        (vault, result)
    })
    .await
    .map_err(|e| to_payload(VaultError::Internal(format!("background task failed: {e}"))))?;

    // If the vault was locked while this task ran, discard the keys instead of
    // resurrecting the unlocked state.
    if state.current_epoch() == epoch {
        *state
            .vault
            .lock()
            .map_err(|_| to_payload(VaultError::Internal("state unavailable".into())))? = Some(vault);
        outcome
    } else {
        drop(vault);
        Err(to_payload(VaultError::VaultLocked))
    }
}

fn import_blocking(
    vault: &mut Vault,
    paths: Vec<String>,
    destination_id: String,
    rename_on_conflict: bool,
    ctx: &dyn myvault_core::OpContext,
) -> CommandResult<ImportReport> {
    let destination = parse_id(&destination_id).map_err(to_payload)?;
    let sources: Vec<std::path::PathBuf> = paths.into_iter().map(std::path::PathBuf::from).collect();
    vault
        .import_paths(&sources, &destination, rename_on_conflict, ctx)
        .map_err(to_payload)
}

#[tauri::command]
pub async fn export_entries(
    state: State<'_, AppState>,
    app: AppHandle,
    ids: Vec<String>,
    destination_path: String,
    overwrite: bool,
) -> CommandResult<ExportReport> {
    let vault = state
        .vault
        .lock()
        .map_err(|_| to_payload(VaultError::Internal("state unavailable".into())))?
        .take()
        .ok_or_else(locked)?;
    state.cancel.reset();
    let epoch = state.current_epoch();
    let ctx = UiContext {
        app,
        cancel: state.cancel.clone(),
    };

    let (vault, outcome) = tauri::async_runtime::spawn_blocking(move || {
        let result = export_blocking(&vault, ids, destination_path, overwrite, &ctx);
        (vault, result)
    })
    .await
    .map_err(|e| to_payload(VaultError::Internal(format!("background task failed: {e}"))))?;

    if state.current_epoch() == epoch {
        *state
            .vault
            .lock()
            .map_err(|_| to_payload(VaultError::Internal("state unavailable".into())))? = Some(vault);
        outcome
    } else {
        drop(vault);
        Err(to_payload(VaultError::VaultLocked))
    }
}

fn export_blocking(
    vault: &Vault,
    ids: Vec<String>,
    destination_path: String,
    overwrite: bool,
    ctx: &dyn myvault_core::OpContext,
) -> CommandResult<ExportReport> {
    let mut parsed = Vec::with_capacity(ids.len());
    for id in ids {
        parsed.push(parse_id(&id).map_err(to_payload)?);
    }
    vault
        .export_entries(
            &parsed,
            std::path::Path::new(&destination_path),
            overwrite,
            ctx,
        )
        .map_err(to_payload)
}

#[tauri::command]
pub fn cancel_operation(state: State<'_, AppState>) -> CommandResult<()> {
    state.cancel.cancel();
    Ok(())
}

/// Decrypt one file into the short-lived area and hand it to Windows so the
/// default application can open it.
#[tauri::command]
pub async fn open_entry(
    state: State<'_, AppState>,
    id: String,
) -> CommandResult<OpenEntryResult> {
    let vault = state
        .vault
        .lock()
        .map_err(|_| to_payload(VaultError::Internal("state unavailable".into())))?
        .take()
        .ok_or_else(locked)?;
    let epoch = state.current_epoch();
    let parsed = parse_id(&id).map_err(to_payload)?;

    let (vault, outcome) = tauri::async_runtime::spawn_blocking(move || {
        let area = TempOpenArea::default_area();
        let result = vault.prepare_open(&area, &parsed).map_err(to_payload);
        (vault, result)
    })
    .await
    .map_err(|e| to_payload(VaultError::Internal(format!("background task failed: {e}"))))?;

    if state.current_epoch() != epoch {
        drop(vault);
        return Err(to_payload(VaultError::VaultLocked));
    }
    *state
        .vault
        .lock()
        .map_err(|_| to_payload(VaultError::Internal("state unavailable".into())))? = Some(vault);

    let opened = outcome?;
    tauri_plugin_opener::open_path(&opened.path, None::<String>).map_err(|e| {
        to_payload(VaultError::Io(format!(
            "Windows could not open this file with its default application: {e}"
        )))
    })?;

    Ok(OpenEntryResult {
        path: opened.path.to_string_lossy().to_string(),
        name: opened.name,
        temporary_root: TempOpenArea::default_area()
            .root()
            .to_string_lossy()
            .to_string(),
        warnings: opened.warnings,
    })
}
