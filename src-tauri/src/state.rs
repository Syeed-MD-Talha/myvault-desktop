//! Shared application state for the Tauri layer.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use myvault_core::{CancelToken, OpenedVault, Progress, Vault};
use tauri::{AppHandle, Emitter};

/// Progress event name consumed by the React frontend.
pub const PROGRESS_EVENT: &str = "vault://progress";

/// Application state. Every sensitive field lives only in Rust memory.
#[derive(Clone)]
pub struct AppState {
    pub vault: Arc<Mutex<Option<Vault>>>,
    pub opened: Arc<Mutex<Option<OpenedVault>>>,
    pub cancel: CancelToken,
    /// Incremented on every lock so a long-running operation that finishes
    /// afterwards knows not to put a freshly unlocked vault back into memory.
    pub epoch: Arc<AtomicU64>,
    pub app: AppHandle,
}

impl AppState {
    pub fn new(app: AppHandle) -> Self {
        AppState {
            vault: Arc::new(Mutex::new(None)),
            opened: Arc::new(Mutex::new(None)),
            cancel: CancelToken::new(),
            epoch: Arc::new(AtomicU64::new(0)),
            app,
        }
    }

    pub fn current_epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    pub fn bump_epoch(&self) -> u64 {
        self.epoch.fetch_add(1, Ordering::SeqCst) + 1
    }
}

/// Bridges core progress/cancellation into Tauri events.
pub struct UiContext {
    pub app: AppHandle,
    pub cancel: CancelToken,
}

impl myvault_core::OpContext for UiContext {
    fn progress(&self, progress: Progress) {
        // Progress carries only a virtual item name, never plaintext data.
        let _ = self.app.emit(PROGRESS_EVENT, &progress);
    }

    fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }
}
