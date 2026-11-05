//! Application services: vault lifecycle, transfers, path validation.

pub mod locks;
pub mod paths;
pub mod progress;
pub mod temp_open;
pub mod transfer;
pub mod vault;

pub use progress::{CallbackContext, CancelToken, NoopContext, OpContext, Progress};
pub use temp_open::{TempOpenArea, TempOpenFile};
pub use vault::{
    parse_id, Crumb, DeleteReport, EntryView, IntegrityReport, OpenedVault, UnlockResult, Vault,
    VaultInfo, VaultOptions,
};
