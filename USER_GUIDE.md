# MyVault User Guide

## 1. First run

Launch `MyVault.exe`. The welcome screen offers four actions:

- **Create New Vault** - choose a location, a name and a master password.
- **Open Existing Vault** - select a `.vault` file, then enter its password.
- **Settings** - theme, automatic locking, password change, integrity checks.
- **About** - version, algorithms and security boundaries.

## 2. Creating a vault

1. Choose a **vault name** (for example `Personal`).
2. Choose the **storage location** with *Browse*. The file must not already
   exist. Example: `D:\Private\Personal.vault`.
3. Enter a **master password**. Use a passphrase of several words with at least
   10 characters. A numeric PIN is rejected.
4. Confirm the password and tick the acknowledgement box.
5. Select **Create Vault**.

The vault is created and unlocked immediately. Encryption of the key envelope
uses Argon2id; creation takes roughly one second on a typical PC.

> **Write your password down and store it somewhere safe.** MyVault has no
> password recovery, no hint and no backdoor. Losing the password means losing
> the files.

## 3. Importing files and folders

With the vault unlocked:

- **Import Files** - select one or more files.
- **Import Folder** - select a folder; its nested structure and empty folders
  are preserved.
- **Drag and drop** - drop files or folders anywhere on the window.

Imports **copy** the data into the container. The originals are left untouched
and unencrypted, so delete them yourself if you no longer need plaintext copies
(and remember that ordinary deletion is not secure erasure on an SSD).

If an item with the same name already exists, the new item is imported as
`name (2).ext` and the rename is reported.

Symbolic links and junctions are skipped and listed in the result message.

## 4. Browsing and organising

- Double-click a folder to open it.
- Use the breadcrumbs to jump to any parent folder.
- **New Folder**, **Rename**, **Move**, **Delete** work on the selected items.
- Click a row to select it; use the checkboxes for multi-selection.
- Keyboard: `F2` rename, `Delete` delete, `Enter` open the selected folder.
- The search box filters file and folder names across the whole vault. Search
  only works while the vault is unlocked.

Deleting removes the encrypted chunks from the container. Anything you already
exported to disk is not affected.

## 5. Exporting

Select one or more items and choose **Export**, then pick a destination folder.

- Content is decrypted in 1 MiB chunks and written to a temporary file.
- The file is only renamed into place after every chunk authenticates, so a
  failure never leaves a truncated file.
- If a file with the same name exists you are asked before it is replaced.
- **Exported files are plaintext** and are no longer protected by MyVault.

Direct opening in Word, Adobe Reader and similar applications is intentionally
not supported in version 1.0: export the file first, and delete the exported
copy when you are done.

## 6. Locking

- **Lock** in the header locks immediately: keys are dropped, the file list is
  cleared and you return to the welcome screen. Any decrypted copies created by
  "Open" are deleted at the same time.
- **Automatic locking** is configured in Settings: Off, 1, 5, 10, 15 or 30
  minutes. Inactivity means no interaction with MyVault, not with Windows.

While a long import or export runs, cancel the operation first: locking waits
for in-progress work to finish so that the database is never left in an
intermediate state.

## 7. Opening a file

Double-click a file (or select it and choose **Open**) to view it in the
application Windows associates with that extension - Word, Adobe Reader, the
Photos app, your editor, and so on.

Because those applications cannot read an encrypted container, MyVault:

1. asks for confirmation that a decrypted copy will be created,
2. decrypts the file to `%LOCALAPPDATA%\MyVault\open\<vault-id>\`,
3. starts the default application for the file,
4. shows the exact temporary path and a warning that other programs can read
   the copy while it exists.

The copies are removed when you lock the vault or close MyVault. Leftovers from
a crash are removed the next time a file is opened. "Save" in the external
application writes to that temporary copy only; to keep changes, export the
file to a real location from MyVault (the vault copy is not updated
automatically).

If a file has no associated application, Windows shows its "How do you want to
open this file?" dialog.

## 8. Changing the master password

1. Unlock the vault.
2. Open **Settings -> Master password**.
3. Enter the current password, the new password and the confirmation.
4. Select **Change password**.

Only the key envelope is rewritten with a fresh salt; the files are not
re-encrypted, so the operation is quick and atomic. The old password stops
working immediately.

## 9. Verifying a vault

**Settings -> Integrity verification** checks:

- the SQLite structure,
- the header and its parameters,
- the encrypted manifest (decrypts and validates the tree),
- every chunk's authentication tag and recorded length,
- unreferenced (orphaned) chunk rows.

Verification never repairs or rewrites data. If problems are reported, stop
using the container and restore a backup.

## 10. Backups

The vault is one file. Copy it while it is **locked** (or simply with MyVault
closed). Keep several copies on separate media, and remember that the backup is
only as safe as the master password.

Restoring is equally simple: put the `.vault` file back and open it with
MyVault. There is no export/import metadata step.

## 11. Troubleshooting

| Symptom | Explanation |
| --- | --- |
| "The master password is incorrect" | Wrong password, or the key envelope was damaged. MyVault cannot distinguish the two, by design. |
| "This vault is currently open by another MyVault window" | Another instance holds the vault. Close it; locks are released automatically when a process exits. |
| "The encrypted manifest is corrupted" | The manifest failed authentication. Do not modify the file; restore a backup. |
| "An item named ... already exists" | Virtual folders behave like Windows folders. Rename or move the existing item. |
| Import skipped files | Symbolic links and junctions are not imported. |
| Export reports a name conflict | Confirm the replacement, or choose another destination. |
| Application is slow on first launch | The window creates its WebView2 profile; subsequent launches are faster. |

## 12. Command line

MyVault is a GUI application. There is no CLI mode in version 1.0; build the
`myvault-core` crate if you want to embed the engine programmatically.
