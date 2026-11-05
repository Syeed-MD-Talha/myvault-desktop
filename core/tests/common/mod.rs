//! Shared helpers for the integration and security test suites.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use myvault_core::{KdfParams, VaultOptions};

/// Argon2id at the minimum accepted cost so the suite runs quickly. Production
/// defaults (64 MiB / 3 passes) are covered by the unit tests and by the
/// benchmark test.
pub fn fast_options() -> VaultOptions {
    VaultOptions {
        kdf_params: KdfParams {
            m_cost_kib: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
            key_len: 32,
        },
        chunk_size: 64 * 1024,
    }
}

pub const PASSWORD: &str = "correct horse battery staple";
pub const OTHER_PASSWORD: &str = "a completely different passphrase";

pub fn write_source(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&path, bytes).unwrap();
    path
}

/// Deterministic pseudo-random bytes so failures are reproducible.
pub fn pattern_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 8);
    let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    while out.len() < len {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

pub fn read_all(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap()
}
