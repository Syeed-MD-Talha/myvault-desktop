//! Progress reporting and cooperative cancellation, decoupled from the UI.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::errors::{VaultError, VaultResult};

#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    /// One of: `import`, `export`, `verify`.
    pub phase: &'static str,
    /// Completed work units (bytes for transfers, entries for verification).
    pub current: u64,
    pub total: u64,
    /// Name of the item currently being processed (virtual name only).
    pub item: String,
}

impl Progress {
    pub fn percent(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.current as f64 / self.total as f64) * 100.0
        }
    }
}

/// Sink for progress plus a cancellation flag. Implementations must be
/// cheap and must never block on the UI.
pub trait OpContext: Send + Sync {
    fn progress(&self, progress: Progress);
    fn is_cancelled(&self) -> bool;

    fn check(&self) -> VaultResult<()> {
        if self.is_cancelled() {
            Err(VaultError::Cancelled)
        } else {
            Ok(())
        }
    }
}

/// Default context: no reporting, never cancelled.
pub struct NoopContext;

impl OpContext for NoopContext {
    fn progress(&self, _progress: Progress) {}
    fn is_cancelled(&self) -> bool {
        false
    }
}

/// A cancellation flag that can be flipped from another thread (the UI).
#[derive(Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    pub fn reset(&self) {
        self.0.store(false, Ordering::SeqCst);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

impl OpContext for CancelToken {
    fn progress(&self, _progress: Progress) {}
    fn is_cancelled(&self) -> bool {
        self.is_cancelled()
    }
}

/// Combines a cancellation token with a user-provided progress callback.
pub struct CallbackContext<F> {
    pub cancel: CancelToken,
    pub callback: F,
}

impl<F> OpContext for CallbackContext<F>
where
    F: Fn(Progress) + Send + Sync,
{
    fn progress(&self, progress: Progress) {
        (self.callback)(progress);
    }
    fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_token_flips_and_resets() {
        let token = CancelToken::new();
        assert!(!token.is_cancelled());
        assert!(token.check().is_ok());
        token.cancel();
        assert!(token.is_cancelled());
        assert_eq!(token.check().unwrap_err(), VaultError::Cancelled);
        token.reset();
        assert!(token.check().is_ok());
    }

    #[test]
    fn callback_context_reports() {
        use std::sync::Mutex;
        let seen = Mutex::new(Vec::new());
        let ctx = CallbackContext {
            cancel: CancelToken::new(),
            callback: |p: Progress| seen.lock().unwrap().push(p.current),
        };
        ctx.progress(Progress {
            phase: "import",
            current: 5,
            total: 10,
            item: "a.txt".into(),
        });
        assert_eq!(*seen.lock().unwrap(), vec![5]);
    }

    #[test]
    fn percent_handles_zero_total() {
        let p = Progress::default();
        assert_eq!(p.percent(), 0.0);
    }
}
