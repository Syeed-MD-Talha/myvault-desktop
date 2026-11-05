//! Performance checks from SRS section 13. Run with `cargo test -- --ignored`.
//!
//! These are engineering measurements on the current machine, not guarantees.

mod common;

use std::time::Instant;

use common::*;
use myvault_core::{KdfParams, NoopContext, OpenedVault, Vault, VaultOptions, ROOT_ID};

fn default_options() -> VaultOptions {
    VaultOptions {
        kdf_params: KdfParams::default(),
        chunk_size: 1024 * 1024,
    }
}

#[test]
#[ignore = "benchmark: prints timing information"]
fn benchmark_unlock_latency_with_production_kdf_parameters() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bench.vault");

    let create_start = Instant::now();
    let vault = Vault::create_with_options(&path, PASSWORD, default_options()).unwrap();
    println!(
        "create (Argon2id 64 MiB / 3 passes): {:?}",
        create_start.elapsed()
    );
    vault.lock();

    let mut samples = Vec::new();
    for _ in 0..5 {
        let opened = OpenedVault::open(&path).unwrap();
        let start = Instant::now();
        let vault = opened.unlock(PASSWORD).unwrap();
        samples.push(start.elapsed());
        drop(vault);
    }
    let total: std::time::Duration = samples.iter().sum();
    println!(
        "unlock: min {:?}, mean {:?}, max {:?}",
        samples.iter().min().unwrap(),
        total / samples.len() as u32,
        samples.iter().max().unwrap()
    );
}

#[test]
#[ignore = "benchmark: prints throughput information"]
fn benchmark_import_export_throughput_64_mib() {
    let dir = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    let path = dir.path().join("throughput.vault");

    let size = 64 * 1024 * 1024;
    let payload = pattern_bytes(size, 1234);
    let source = write_source(src.path(), "big.bin", &payload);

    let mut vault = Vault::create_with_options(&path, PASSWORD, fast_options()).unwrap();
    let start = Instant::now();
    let report = vault
        .import_paths(&[source], &ROOT_ID, false, &NoopContext)
        .unwrap();
    let import_elapsed = start.elapsed();
    assert_eq!(report.imported_bytes, size as u64);
    println!(
        "import 64 MiB: {:?} ({:.1} MiB/s), {} chunks",
        import_elapsed,
        size as f64 / 1024.0 / 1024.0 / import_elapsed.as_secs_f64(),
        vault.info().unwrap().chunks
    );

    let id = myvault_core::parse_id(&vault.list_directory(None).unwrap()[0].id).unwrap();
    let start = Instant::now();
    vault
        .export_entries(&[id], out.path(), false, &NoopContext)
        .unwrap();
    let export_elapsed = start.elapsed();
    println!(
        "export 64 MiB: {:?} ({:.1} MiB/s)",
        export_elapsed,
        size as f64 / 1024.0 / 1024.0 / export_elapsed.as_secs_f64()
    );
    assert_eq!(read_all(&out.path().join("big.bin")), payload);
}

#[test]
#[ignore = "benchmark: prints timing information"]
fn benchmark_ten_thousand_entries() {
    let dir = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    let path = dir.path().join("many.vault");

    // 10,000 empty files in one folder, imported in a single transaction.
    let bulk = src.path().join("bulk");
    std::fs::create_dir_all(&bulk).unwrap();
    for index in 0..10_000 {
        std::fs::write(bulk.join(format!("file-{index:05}.txt")), b"").unwrap();
    }

    let mut vault = Vault::create_with_options(&path, PASSWORD, fast_options()).unwrap();
    let start = Instant::now();
    let report = vault
        .import_paths(&[bulk], &ROOT_ID, false, &NoopContext)
        .unwrap();
    let import_elapsed = start.elapsed();
    assert_eq!(report.imported_files, 10_000);

    let bulk_id = myvault_core::parse_id(&vault.list_directory(None).unwrap()[0].id).unwrap();
    let start = Instant::now();
    let entries = vault.list_directory(Some(&bulk_id)).unwrap();
    let list_elapsed = start.elapsed();
    assert_eq!(entries.len(), 10_000);
    assert_eq!(entries[0].path, "bulk/file-00000.txt");

    let start = Instant::now();
    let found = vault.search("file-0999").unwrap();
    let search_elapsed = start.elapsed();
    assert_eq!(found.len(), 10);

    let start = Instant::now();
    let report = vault.verify().unwrap();
    let verify_elapsed = start.elapsed();
    assert!(report.ok);

    println!(
        "10k entries: import {:?}, list {:?}, search {:?}, verify {:?}",
        import_elapsed, list_elapsed, search_elapsed, verify_elapsed
    );
}
