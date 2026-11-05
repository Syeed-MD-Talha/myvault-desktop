//! Streaming import and export of file content.
//!
//! Imports are staged inside a single SQLite transaction: chunks and the
//! manifest commit together, so a crash or a cancellation can never expose a
//! partially imported file. Exports write to a temporary file in the target
//! directory and only rename it into place after every chunk has been
//! authenticated.

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::crypto::random_bytes;
use crate::errors::{VaultError, VaultResult};
use crate::services::paths;
use crate::services::progress::{OpContext, Progress};
use crate::services::vault::{write_manifest, EntryView, Vault};
use crate::storage::chunks;
use crate::storage::manifest::{validate_name, Entry, EntryKind, Id, Manifest, ROOT_ID};

/// Hard limit on directory nesting so recursive loops are impossible.
const MAX_DEPTH: usize = 64;

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportReport {
    pub imported_files: u64,
    pub imported_directories: u64,
    pub imported_bytes: u64,
    /// Items that were refused (for example reparse points).
    pub skipped: Vec<String>,
    /// Items renamed because the destination already had that name.
    pub renamed: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportReport {
    pub exported_files: u64,
    pub exported_directories: u64,
    pub exported_bytes: u64,
    pub destination: String,
}

enum PlanNode {
    Dir {
        name: String,
        mtime_ms: u64,
        children: Vec<PlanNode>,
    },
    File {
        name: String,
        source: PathBuf,
        size: u64,
        mtime_ms: u64,
    },
}

impl PlanNode {
    fn name(&self) -> &str {
        match self {
            PlanNode::Dir { name, .. } => name,
            PlanNode::File { name, .. } => name,
        }
    }

    fn size(&self) -> u64 {
        match self {
            PlanNode::Dir { children, .. } => children.iter().map(|c| c.size()).sum(),
            PlanNode::File { size, .. } => *size,
        }
    }
}

fn metadata_mtime_ms(metadata: &std::fs::Metadata) -> u64 {
    metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or_else(crate::now_ms)
}

/// Walk a physical source path into an immutable import plan. All validation
/// happens here, before any ciphertext is written, so an invalid selection
/// fails without leaving anything behind.
fn plan_source(
    path: &Path,
    ctx: &dyn OpContext,
    skipped: &mut Vec<String>,
    depth: usize,
) -> VaultResult<Option<PlanNode>> {
    if depth > MAX_DEPTH {
        skipped.push(format!("{}: nesting limit reached", path.display()));
        return Ok(None);
    }
    ctx.check()?;
    let metadata = match paths::validate_source(path) {
        Ok(m) => m,
        Err(VaultError::ReparsePointRejected(name)) => {
            skipped.push(format!("{name}: symbolic link or junction"));
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .ok_or_else(|| VaultError::InvalidPath("the source has no file name".into()))?;
    validate_name(&name)?;

    if metadata.is_file() {
        Ok(Some(PlanNode::File {
            name,
            source: path.to_path_buf(),
            size: metadata.len(),
            mtime_ms: metadata_mtime_ms(&metadata),
        }))
    } else {
        let mut entries: Vec<PathBuf> = Vec::new();
        for item in std::fs::read_dir(path)
            .map_err(|e| VaultError::Io(format!("cannot read a source folder: {e}")))?
        {
            let item = item.map_err(|e| VaultError::Io(e.to_string()))?;
            entries.push(item.path());
        }
        entries.sort();
        let mut children = Vec::new();
        for child in entries {
            if let Some(node) = plan_source(&child, ctx, skipped, depth + 1)? {
                children.push(node);
            }
        }
        Ok(Some(PlanNode::Dir {
            name,
            mtime_ms: metadata_mtime_ms(&metadata),
            children,
        }))
    }
}

/// Find a free sibling name, appending ` (2)`, ` (3)`, ... before the
/// extension.
fn free_name(existing: &dyn Fn(&str) -> bool, desired: &str) -> Option<String> {
    if !existing(desired) {
        return Some(desired.to_string());
    }
    let (stem, ext) = match desired.rfind('.') {
        Some(i) if i > 0 => (&desired[..i], &desired[i..]),
        _ => (desired, ""),
    };
    for n in 2..10_000u32 {
        let candidate = format!("{stem} ({n}){ext}");
        if !existing(&candidate) {
            return Some(candidate);
        }
    }
    None
}

pub fn import_paths(
    vault: &mut Vault,
    sources: &[PathBuf],
    destination: &Id,
    rename_on_conflict: bool,
    ctx: &dyn OpContext,
) -> VaultResult<ImportReport> {
    if sources.is_empty() {
        return Err(VaultError::Validation("no source was selected".into()));
    }
    match vault.manifest.get(destination) {
        Ok(e) if e.is_dir() => {}
        Ok(_) => return Err(VaultError::WrongEntryKind),
        Err(_) if destination == &ROOT_ID => {}
        Err(e) => return Err(e),
    }

    let mut report = ImportReport::default();
    let mut plans = Vec::new();
    for source in sources {
        if !source.is_absolute() {
            return Err(VaultError::InvalidPath(
                "import sources must be absolute paths".into(),
            ));
        }
        if let Some(node) = plan_source(source, ctx, &mut report.skipped, 0)? {
            plans.push(node);
        }
    }
    if plans.is_empty() {
        return Ok(report);
    }
    let total_bytes: u64 = plans.iter().map(|p| p.size()).sum();

    let snapshot = vault.manifest_snapshot();
    let Vault {
        conn,
        manifest,
        master,
        header,
        chunk_size,
        ..
    } = vault;

    let tx = conn.unchecked_transaction()?;
    let mut used: HashSet<(Id, String)> = HashSet::new();
    let mut done = 0u64;

    for plan in &plans {
        let staged = stage_node(
            &tx,
            manifest,
            master,
            &header.vault_id,
            *chunk_size,
            plan,
            destination,
            rename_on_conflict,
            &mut used,
            &mut done,
            total_bytes,
            &mut report,
            ctx,
        );
        if let Err(e) = staged {
            // Dropping the transaction rolls back every staged chunk.
            drop(tx);
            *manifest = snapshot;
            return Err(e);
        }
    }

    let committed = (|| -> VaultResult<()> {
        write_manifest(&tx, master.manifest_key(), &header.vault_id, manifest)?;
        tx.commit()?;
        Ok(())
    })();
    if let Err(e) = committed {
        *manifest = snapshot;
        return Err(e);
    }

    // Safe point: the manifest is durable. Unreferenced staging rows can be
    // reclaimed.
    let referenced = manifest.referenced_chunk_ids();
    let _ = chunks::delete_orphans(conn, &referenced);
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
fn stage_node(
    tx: &rusqlite::Connection,
    manifest: &mut Manifest,
    master: &crate::crypto::VaultMasterKey,
    vault_id: &Id,
    chunk_size: usize,
    node: &PlanNode,
    parent: &Id,
    rename_on_conflict: bool,
    used: &mut HashSet<(Id, String)>,
    done: &mut u64,
    total: u64,
    report: &mut ImportReport,
    ctx: &dyn OpContext,
) -> VaultResult<()> {
    ctx.check()?;
    let parent_key = *parent;
    let taken = |name: &str| -> bool {
        used.contains(&(parent_key, name.to_lowercase()))
            || manifest.child_named(&parent_key, name).is_some()
    };

    let chosen = if taken(node.name()) {
        if !rename_on_conflict {
            return Err(VaultError::NameConflict(node.name().to_string()));
        }
        let chosen = free_name(&taken, node.name())
            .ok_or_else(|| VaultError::NameConflict(node.name().to_string()))?;
        report.renamed.push(format!("{} -> {chosen}", node.name()));
        chosen
    } else {
        node.name().to_string()
    };
    used.insert((parent_key, chosen.to_lowercase()));

    match node {
        PlanNode::Dir {
            mtime_ms, children, ..
        } => {
            let id: Id = random_bytes::<16>();
            manifest.entries.push(Entry {
                id,
                parent: parent_key,
                name: chosen.clone(),
                kind: EntryKind::Directory,
                created_ms: *mtime_ms,
                modified_ms: *mtime_ms,
                size: 0,
                chunks: Vec::new(),
            });
            report.imported_directories += 1;
            ctx.progress(Progress {
                phase: "import",
                current: *done,
                total,
                item: chosen,
            });
            for child in children {
                stage_node(
                    tx,
                    manifest,
                    master,
                    vault_id,
                    chunk_size,
                    child,
                    &id,
                    rename_on_conflict,
                    used,
                    done,
                    total,
                    report,
                    ctx,
                )?;
            }
            Ok(())
        }
        PlanNode::File {
            source,
            size,
            mtime_ms,
            ..
        } => {
            let file_id: Id = random_bytes::<16>();
            let mut file = File::open(source)?;
            let mut buffer = vec![0u8; chunk_size];
            let mut chunk_refs = Vec::new();
            let mut index = 0u64;
            let mut read_total = 0u64;
            loop {
                ctx.check()?;
                let mut filled = 0usize;
                while filled < chunk_size {
                    match file.read(&mut buffer[filled..]) {
                        Ok(0) => break,
                        Ok(n) => filled += n,
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(VaultError::Io(e.to_string())),
                    }
                }
                if filled == 0 {
                    break;
                }
                let chunk_ref = chunks::insert_encrypted_chunk_with_id(
                    tx,
                    master.file_key(),
                    vault_id,
                    &file_id,
                    index,
                    &buffer[..filled],
                    random_bytes::<16>(),
                )?;
                chunk_refs.push(chunk_ref);
                index += 1;
                read_total += filled as u64;
                *done += filled as u64;
                ctx.progress(Progress {
                    phase: "import",
                    current: *done,
                    total,
                    item: chosen.clone(),
                });
                if filled < chunk_size {
                    break;
                }
            }
            if read_total != *size {
                return Err(VaultError::SourceChanged(format!(
                    "{} changed size while it was being imported",
                    chosen
                )));
            }
            let now = crate::now_ms();
            manifest.entries.push(Entry {
                id: file_id,
                parent: parent_key,
                name: chosen,
                kind: EntryKind::File,
                created_ms: *mtime_ms,
                modified_ms: now.max(*mtime_ms),
                size: *size,
                chunks: chunk_refs,
            });
            report.imported_files += 1;
            report.imported_bytes += *size;
            Ok(())
        }
    }
}

pub fn export_entries(
    vault: &Vault,
    ids: &[Id],
    destination: &Path,
    overwrite: bool,
    ctx: &dyn OpContext,
) -> VaultResult<ExportReport> {
    paths::validate_destination_dir(destination)?;
    if ids.is_empty() {
        return Err(VaultError::Validation("no item was selected".into()));
    }
    let mut report = ExportReport {
        destination: destination.to_string_lossy().to_string(),
        ..Default::default()
    };

    let mut total = 0u64;
    for id in ids {
        total += subtree_plaintext_bytes(vault, id)?;
    }
    for id in ids {
        let entry = vault.manifest.get(id)?.clone();
        export_node(vault, &entry, destination, overwrite, total, &mut report, ctx)?;
    }
    Ok(report)
}

fn subtree_plaintext_bytes(vault: &Vault, id: &Id) -> VaultResult<u64> {
    let ids = vault.manifest.subtree_ids(id)?;
    Ok(ids
        .iter()
        .filter_map(|i| vault.manifest.get(i).ok())
        .filter(|e| !e.is_dir())
        .map(|e| e.size)
        .sum())
}

fn export_node(
    vault: &Vault,
    entry: &Entry,
    parent_dir: &Path,
    overwrite: bool,
    total: u64,
    report: &mut ExportReport,
    ctx: &dyn OpContext,
) -> VaultResult<()> {
    ctx.check()?;
    let name = vault.export_name(entry)?;
    let target = paths::safe_join(parent_dir, &name)?;

    if entry.is_dir() {
        if target.exists() {
            if !target.is_dir() {
                return Err(VaultError::NameConflict(name));
            }
            if !overwrite {
                return Err(VaultError::NameConflict(name));
            }
        } else {
            std::fs::create_dir(&target)?;
            report.exported_directories += 1;
        }
        let children: Vec<Entry> = vault
            .manifest
            .children(&entry.id)
            .into_iter()
            .cloned()
            .collect();
        for child in &children {
            export_node(vault, child, &target, overwrite, total, report, ctx)?;
        }
        return Ok(());
    }

    if target.exists() && !overwrite {
        return Err(VaultError::NameConflict(name));
    }

    let temp = paths::temp_output_path(parent_dir);
    if let Err(e) = write_file_out(vault, entry, &temp, total, report, ctx) {
        let _ = std::fs::remove_file(&temp);
        return Err(e);
    }
    if target.exists() {
        std::fs::remove_file(&target)?;
    }
    if let Err(e) = std::fs::rename(&temp, &target) {
        let _ = std::fs::remove_file(&temp);
        return Err(VaultError::Io(e.to_string()));
    }
    report.exported_files += 1;
    Ok(())
}

fn write_file_out(
    vault: &Vault,
    entry: &Entry,
    temp: &Path,
    total: u64,
    report: &mut ExportReport,
    ctx: &dyn OpContext,
) -> VaultResult<()> {
    let file = File::create(temp)?;
    let mut writer = BufWriter::with_capacity(1024 * 1024, file);
    let mut written = 0u64;
    for (index, chunk) in entry.chunks.iter().enumerate() {
        ctx.check()?;
        let plain = chunks::read_decrypted_chunk(
            &vault.conn,
            vault.master.file_key(),
            &vault.header.vault_id,
            &entry.id,
            index as u64,
            &chunk.id,
        )?;
        if plain.len() != chunk.len as usize {
            return Err(VaultError::CorruptManifest);
        }
        writer.write_all(&plain)?;
        written += plain.len() as u64;
        ctx.progress(Progress {
            phase: "export",
            current: written,
            total: total.max(entry.size),
            item: entry.name.clone(),
        });
    }
    writer.flush()?;
    let file = writer.into_inner().map_err(|e| VaultError::Io(e.to_string()))?;
    file.sync_all()?;
    if written != entry.size {
        return Err(VaultError::CorruptManifest);
    }
    report.exported_bytes += written;
    Ok(())
}

/// Describe entries for the UI without exposing keys.
pub fn describe_entries(vault: &Vault, ids: &[Id]) -> VaultResult<Vec<EntryView>> {
    ids.iter().map(|id| vault.entry(id)).collect()
}
