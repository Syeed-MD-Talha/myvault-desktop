# MyVault Test Report

Version 1.0.0 - container format v1
Environment: Windows 11 (build 26300), AMD64, Rust 1.95.0 stable (MSVC),
Node.js 24.21.0.

## 1. Summary

| Suite | Tests | Result |
| --- | --- | --- |
| Unit tests (`core/src/**`) | 63 | **pass** |
| Integration tests (`core/tests/vault_tests.rs`) | 20 | **pass** |
| Security tests (`core/tests/security_tests.rs`) | 10 | **pass** |
| Performance benchmarks (`core/tests/benchmark.rs`) | 3 | **pass** (ignored by default) |
| **Total** | **96** | **all passing** |

Run:

```powershell
cargo test                                  # 93 tests, benchmarks skipped
cargo test --release -- --ignored --nocapture --test-threads=1   # 3 benchmarks
```

## 2. Unit tests (63)

| Area | Coverage |
| --- | --- |
| AAD encoding | Stable encoding; chunk index, object id, context and format version all produce distinct AAD; no ambiguity from concatenation |
| AEAD | Round trip; empty plaintext; fresh nonce per operation; tampered ciphertext, tampered AAD, wrong key and truncated input rejected without panic |
| Argon2id | Deterministic derivation; password and salt sensitivity; hostile parameters rejected; production defaults usable |
| Key hierarchy | Subkeys distinct and deterministic; generated keys differ; debug output redacted; password policy |
| Manifest | Root invariants; JSON round trip; duplicate ids, duplicate sibling names, size mismatch, orphan parents, cycles and duplicate chunk references rejected; name validation; seal/open binding to vault id; tamper rejection |
| Vault header | Round trip; correct password unwraps the same VMK; wrong password and damaged envelope produce the same generic error; malformed header and unknown algorithm rejected |
| Encrypted chunks | Round trip; replay at another index, file or vault rejected; tampered bytes rejected; missing chunk reported; orphan sweep; chunk-size bounds |
| SQLite layer | Fresh database initialized and checked; plain SQLite file rejected; schema version mismatch refused |
| Paths and export names | Traversal, absolute paths, reserved names; destination containment; unique temporary names |
| Progress/cancellation | Token flips and resets; callback context; zero-total percentage |
| Process lock | Second acquisition fails; different vaults get different markers |
| Temporary open area | Area is created and marked; a foreign directory is never used or deleted; exact plaintext is written and removed again; empty files; directories refused; leftovers swept |

## 3. Integration tests (20)

| Test | SRS requirement |
| --- | --- |
| `create_lock_unlock_cycle` | FR-01, FR-02 |
| `wrong_password_is_rejected_generically` | FR-02, SEC-03 |
| `weak_passwords_are_refused_at_creation` | Section 2.2 |
| `create_refuses_to_overwrite_an_existing_file` | Section 12 |
| `import_export_round_trip_is_byte_exact` | FR-03, FR-07, acceptance 3 |
| `nested_directory_tree_is_preserved_including_empty_folders` | FR-04, section 6.4 |
| `empty_files_round_trip` | Section 14.1 |
| `create_rename_move_and_delete_entries` | FR-06, FR-05 |
| `delete_removes_chunk_rows` | FR-06 |
| `change_password_rewraps_without_touching_file_data` | FR-10, SEC-14 |
| `import_of_many_small_files` | FR-03, FR-11 |
| `name_conflicts_are_renamed_on_import_when_allowed` | Section 12 |
| `export_refuses_to_overwrite_without_permission` | Section 7.1 |
| `cancelled_import_leaves_no_trace` | Section 6.3, 6.4 |
| `a_second_open_of_the_same_vault_is_refused` | Section 12 |
| `integrity_report_is_clean_for_a_healthy_vault` | FR-13 |
| `unsupported_format_version_is_refused` | SEC-15 |
| `a_plain_sqlite_file_is_not_a_vault` | Section 12 |
| `backup_creates_a_usable_independent_copy` | FR-14 |
| `keys_are_zeroized_when_the_vault_is_locked` | SEC-07 |

## 4. Security tests (10)

| Test | Attack simulated | Result |
| --- | --- | --- |
| `container_contains_no_plaintext_names_content_or_extensions` | Inspecting the locked container for names, extensions, content or password | No plaintext found |
| `tampered_chunk_is_rejected_and_leaves_no_partial_export` | Single chunk substitution | Rejected; no output file left |
| `reordered_chunks_are_rejected` | Chunk reordering | Rejected |
| `chunk_from_another_file_cannot_be_substituted` | Cross-file chunk swap | Rejected |
| `corrupted_manifest_fails_safely_without_modifying_the_vault` | Manifest bit flip | Safe failure; container not rewritten |
| `corrupted_header_is_reported_as_a_generic_unlock_failure` | Key envelope tampering | Generic invalid-password error |
| `rebinding_a_vault_header_to_another_vault_id_is_rejected` | Header rebinding | Rejected |
| `import_rejects_relative_and_missing_sources` | Relative / non-existent source paths | Rejected before any write |
| `export_rejects_a_missing_destination` | Invalid destination | Rejected |
| `locked_vault_exposes_no_entries_until_unlock` | Locked-state API surface | Only format version and name hint |

Not covered by automated tests (documented manual procedures):

- Forced process termination during an import (the transaction design is
  verified by the cancellation and rollback tests, and by SQLite's documented
  durability with `synchronous=FULL`).
- Low-disk-space behaviour (mapped to a typed `insufficient_space` error).
- Windows junction/reparse-point traversal on real junctions (the reparse check
  is unit-tested at the attribute level).

## 5. Performance measurements

Measured with `cargo test --release -- --ignored --nocapture` on the reference
machine. These are observations, not guarantees.

| Metric | SRS target | Measured |
| --- | --- | --- |
| Vault creation (Argon2id 64 MiB / 3 passes) | - | 243 ms |
| Unlock latency | 0.5-2 s | min 179 ms, mean 209 ms, max 238 ms |
| Import throughput (64 MiB, 1024 chunks) | streamed, bounded memory | 343 ms - **186 MiB/s** |
| Export throughput (64 MiB) | streamed, bounded memory | 225 ms - **284 MiB/s** |
| Import 10,000 entries (single transaction) | section 13 | 2.08 s |
| List a 10,000-entry folder | responsive UI | 75 ms |
| Search across 10,000 entries | FR-11 | 3 ms |
| Verify 10,000 entries | FR-13 | 38 ms |

Memory use is bounded by one 1 MiB chunk plus the manifest; a 1 GiB file never
loads into RAM as a whole.

## 6. Packaging smoke test

- `cargo build --release -p myvault --features custom-protocol` produces a
  single 10.8 MB `myvault.exe` with the React bundle embedded (no dev server).
- The executable was launched on the reference machine; the process stays
  resident and creates a window titled `MyVault`.
- A `PrintWindow` capture of the window confirmed that the WebView2 control
  renders the application UI (welcome/create-unlock flow) rather than a
  connection error, proving the embedded assets are served from the custom
  protocol.
- No console window is created in release builds
  (`windows_subsystem = "windows"`), and devtools are not compiled in.
- **End-to-end GUI check:** a vault was created through the running application
  (`C:\My__Drive\Personal.vault`, 28 KB). The container was copied and inspected
  with `cargo run -p myvault-core --example peek`, which reported
  `format_version=1` and a valid 16-byte vault id, proving the packaged
  executable writes a well-formed container through the real command layer.

## 7. Acceptance criteria (SRS 14.4)

| # | Criterion | Evidence |
| --- | --- | --- |
| 1 | A vault can be created and reopened | `create_lock_unlock_cycle`, `backup_creates_a_usable_independent_copy` |
| 2 | Files and nested folders can be imported | `nested_directory_tree_is_preserved_including_empty_folders` |
| 3 | Contents recoverable byte-for-byte | `import_export_round_trip_is_byte_exact` (binary data with NUL and invalid UTF-8) |
| 4 | A wrong password cannot unlock | `wrong_password_is_rejected_generically` |
| 5 | Corrupted ciphertext is never silently accepted | four security tests above |
| 6 | Metadata stays encrypted while locked | `container_contains_no_plaintext_names_content_or_extensions` |
| 7 | Interrupted imports leave no partial entries | `cancelled_import_leaves_no_trace` |
| 8 | Executable runs without Python, Node.js or Rust | single self-contained `MyVault.exe` (WebView2 runtime is part of Windows 11) |
| 9 | Runs without internet access | no network code; CSP forbids remote resources |
| 10 | Automated tests pass on Windows 11 | 93 tests passing on the reference machine |

## 8. Known gaps and next steps

- No automated test performs a hard process kill mid-import; a helper process
  harness is recommended for CI.
- The "open in default application" flow is covered at the engine level
  (decrypt, exact bytes, cleanup, foreign-directory refusal), but the hand-off
  to Windows and the shutdown cleanup hook are exercised manually only.
- The temporary open area inherits the ACL of `%LOCALAPPDATA%` (user-only on a
  default Windows profile) rather than applying an explicit DACL; a future
  version should set one and verify it.
- NSIS installer generation is environment-dependent (requires the Tauri CLI
  and network access for tooling).
- Concurrency is limited to one vault per process by design; multi-window
  support would need an explicit session model.
