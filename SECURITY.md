# MyVault Security Model

Version 1.0 - container format v1

## 1. What MyVault protects

MyVault protects **data at rest**. When the vault is locked, the `.vault`
container contains only:

- a small plaintext header (format version, random vault id, Argon2id salt and
  parameters, the wrapped vault master key),
- one encrypted manifest,
- encrypted file chunks with random identifiers.

A locked container does not reveal file names, folder names, extensions,
timestamps, file contents or the master password. It does reveal the total
size, the number of chunk records, approximate file sizes and write activity.

## 2. What MyVault cannot protect against

Documented in the application (About screen) and repeated here:

- Malware running with the user's permissions while the vault is unlocked.
- An administrator who can inspect the application's process memory, page file
  contents, or crash dumps.
- Keyloggers or screen capture capturing the master password.
- AI agents or other software reading files after the user exports them.
- Destruction or corruption of the container by any process with write access.
- Remanence after deletion: SSD wear levelling, snapshots, filesystem journals
  and backups can keep copies. **Ordinary deletion is not secure erasure.**

## 3. Algorithms

| Purpose | Algorithm | Parameters |
| --- | --- | --- |
| Password-based key derivation | Argon2id (RustCrypto `argon2`) | 64 MiB, 3 passes, 1 lane, 16-byte random salt, 32-byte output |
| Key wrapping | XChaCha20-Poly1305 | 24-byte random nonce per wrap |
| File encryption | XChaCha20-Poly1305 | 24-byte random nonce per 1 MiB chunk |
| Manifest encryption | XChaCha20-Poly1305 | 24-byte random nonce per save |
| Subkey derivation | HKDF-SHA256 | distinct `info` per purpose |
| Randomness | OS CSPRNG (`BCryptGenRandom`) | 16/24/32-byte draws |
| Key lifetime | `secrecy` + `zeroize` | keys wiped on drop |

No cipher is implemented by hand; only the RustCrypto and `hkdf` crates are
used.

Argon2id parameters are stored in the header, so they can be raised in a later
version without breaking existing containers. Parameters read from a header are
validated (`m_cost` 8 MiB-1 GiB, `t_cost` 1-10, `p_cost` 1-8) so a hostile
container cannot request absurd resources.

## 4. Key hierarchy

```
master password
      |
      | Argon2id(salt, params)
      v
     KEK  (never used to encrypt file data)
      |
      | XChaCha20-Poly1305 open/seal (AAD = key envelope context)
      v
   VMK: 256-bit random vault master key
      |
      +-- HKDF-SHA256("myvault/subkey/file/v1")     -> file key
      +-- HKDF-SHA256("myvault/subkey/manifest/v1") -> manifest key
```

Consequences:

- The password protects only the 32-byte VMK, so changing the password rewraps
  one small blob instead of re-encrypting the vault.
- File data and manifest data never share a key, so a chunk cannot be replayed
  as manifest ciphertext even if associated data were ignored.
- The VMK never leaves Rust memory and is never sent over the IPC boundary.

## 5. Password verification

There is no password hash, no verifier column and no recovery secret. Unlocking
derives the KEK and attempts authenticated decryption of the wrapped VMK. A
failed authentication produces the **same generic error** whether the password
was wrong or the envelope was damaged, so no information is leaked.

## 6. Associated data (AAD)

Every encryption binds the ciphertext to its logical context with a canonical
binary encoding. Ambiguous string concatenation is never used.

```
domain (8 bytes, "MYVAAD\\0\\x01")
format_version (u16 LE)
context (u8: 1 = vault key envelope, 2 = manifest, 3 = chunk)
vault_id (16 bytes)
object_id (16 bytes)
chunk_index (u64 LE)
```

Because `vault_id`, `object_id`, `chunk_index` and `format_version` are all
authenticated, the following are rejected at decryption time:

- a chunk copied into a different file (`object_id` mismatch),
- a chunk replayed at a different position (`chunk_index` mismatch),
- a chunk or manifest moved into another vault (`vault_id` mismatch),
- a ciphertext produced by a different container format version,
- any single-bit modification of nonce, ciphertext or AAD.

## 7. Nonces

Every encryption operation draws a fresh 24-byte nonce from the OS CSPRNG. No
nonce is derived from content, counters or time. With 192-bit random nonces,
collision probability is negligible even for millions of chunks.

## 8. Atomicity and crash safety

- Each mutation runs in a single SQLite transaction: encrypted chunks and the
  encrypted manifest commit together.
- `synchronous=FULL` is set, and the rollback journal (`journal_mode=DELETE`)
  keeps the container a single file outside active transactions.
- A failed or cancelled import rolls back completely; the previous manifest is
  restored in memory and the previous container state is preserved.
- Chunks written by a process that died before the manifest commit are invisible
  and are reclaimed on the next unlock.
- The manifest is fully re-validated after every decryption: unique ids,
  parent existence, absence of cycles, size consistency, unique sibling names.

## 9. Opening files in external applications

Windows applications need a real plaintext file, so opening an encrypted file
necessarily creates one. MyVault makes that explicit:

- A confirmation dialog states that a decrypted copy will be created.
- The copy is written to `%LOCALAPPDATA%\MyVault\open\<vault-id>\<name>`.
- The area is marked with `.myvault-open`; MyVault refuses to use (and will not
  delete files inside) a directory that lacks the marker.
- Copies are deleted when the vault is locked, when MyVault exits, and any
  leftovers from a crash are removed the next time a file is opened.
- The UI reports the exact temporary path and warns that other programs can
  read the file while it exists.
- Small files (under 4 KiB) additionally produce a warning that NTFS may keep
  their final bytes in a file-system record after deletion.

Residual risk, which the UI states: a hard process kill (`TerminateProcess`),
a system crash, a power loss, or another program's own temporary/autosave files
can outlive the deletion window. Windows paging or hibernation can also copy
plaintext into system-managed files. This is inherent to handing files to
external applications and is why the feature is opt-in per file.

## 10. Input and path validation

- Import sources must be absolute existing paths; relative paths are rejected.
- Windows reparse points (symlinks, junctions) are rejected and reported as
  skipped rather than followed.
- Recursion depth is capped at 64 levels, so directory loops cannot occur.
- Virtual names reject `.`, `..`, separators, control characters, Windows
  reserved device names and trailing dots/spaces.
- Export resolves names through a single-component sanitizer and then proves the
  resulting path is still inside the chosen destination directory.
- Existing files are never overwritten without an explicit confirmation.

## 11. Process and UI hardening

- Only the Rust backend handles keys or file content. The UI receives metadata
  and progress events.
- The Tauri capability set is minimal: `core:default` and `dialog:default` only.
  No filesystem, shell, HTTP or process plugin is available to the webview.
- A Content Security Policy blocks remote scripts and inline scripts.
- No decrypted content is written to `localStorage` or `sessionStorage`.
- Passwords are cleared from React state immediately after the command
  completes, and are wrapped in `Zeroizing` in Rust.
- Diagnostic output never includes passwords, keys or plaintext file content.

## 12. Concurrency

A vault can be opened by only one MyVault instance at a time. Two mechanisms
apply:

1. SQLite's exclusive locking mode holds an OS file lock for the connection's
   lifetime.
2. A marker file in `%LOCALAPPDATA%\MyVault\locks` is opened with Windows
   `share_mode(0)`, so a second opener (even in the same process) fails with a
   sharing violation.

Both are released automatically by the operating system if the process crashes,
so no stale lock can permanently block a vault.

## 13. Reporting a vulnerability

This is a reference implementation. If you find a flaw, do not publish it
before the maintainer has had a chance to respond. Include a minimal
reproduction and the affected version.
