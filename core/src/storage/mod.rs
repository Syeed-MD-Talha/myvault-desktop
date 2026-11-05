//! Storage layer: SQLite container, header, manifest and chunks.

pub mod chunks;
pub mod db;
pub mod header;
pub mod manifest;

pub use header::{VaultHeader, FORMAT_VERSION};
pub use manifest::{Entry, EntryKind, Id, Manifest, ROOT_ID};
