//! Non-sensitive application preferences (theme, auto-lock timeout).
//!
//! These are stored as plain JSON because they contain no vault data; the
//! vault path itself is deliberately not persisted.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::commands::{to_payload, CommandResult};
use myvault_core::VaultError;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    /// `system`, `light` or `dark`.
    pub theme: String,
    /// Idle minutes before the vault locks itself; 0 disables auto-lock.
    pub auto_lock_minutes: u32,
    /// Ask before deleting entries.
    pub confirm_delete: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            theme: "system".into(),
            auto_lock_minutes: 5,
            confirm_delete: true,
        }
    }
}

fn settings_path() -> PathBuf {
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join("MyVault").join("settings.json")
}

fn load() -> Settings {
    match std::fs::read_to_string(settings_path()) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
        Err(_) => Settings::default(),
    }
}

fn store(settings: &Settings) -> CommandResult<()> {
    let path = settings_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| to_payload(VaultError::Io(e.to_string())))?;
    }
    let text = serde_json::to_string_pretty(settings)
        .map_err(|e| to_payload(VaultError::Serialization(e.to_string())))?;
    std::fs::write(&path, text).map_err(|e| to_payload(VaultError::Io(e.to_string())))?;
    Ok(())
}

#[tauri::command]
pub fn get_settings() -> Settings {
    load()
}

#[tauri::command]
pub fn save_settings(settings: Settings) -> CommandResult<Settings> {
    // Reject values the UI does not offer, rather than persisting nonsense.
    let allowed = [0u32, 1, 5, 10, 15, 30];
    let mut settings = settings;
    if !allowed.contains(&settings.auto_lock_minutes) {
        settings.auto_lock_minutes = 5;
    }
    if !["system", "light", "dark"].contains(&settings.theme.as_str()) {
        settings.theme = "system".into();
    }
    store(&settings)?;
    Ok(settings)
}
