//! Validation of physical paths used for import and export, plus safe
//! filename sanitization for export.

use std::path::{Component, Path, PathBuf};

use crate::errors::{VaultError, VaultResult};
use crate::storage::manifest::validate_name;

#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

/// Symlinks and Windows junctions/reparse points are rejected by default.
pub fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

/// Validate a source path that the user asked to import.
pub fn validate_source(path: &Path) -> VaultResult<std::fs::Metadata> {
    if !path.is_absolute() {
        return Err(VaultError::InvalidPath(
            "the source path must be absolute".into(),
        ));
    }
    let metadata = std::fs::metadata(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => {
            VaultError::InvalidPath("the source no longer exists".into())
        }
        std::io::ErrorKind::PermissionDenied => {
            VaultError::Io("permission denied while reading the source".into())
        }
        _ => VaultError::Io(e.to_string()),
    })?;
    if is_reparse_point(&metadata) {
        return Err(VaultError::ReparsePointRejected(
            path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".into()),
        ));
    }
    if !metadata.is_file() && !metadata.is_dir() {
        return Err(VaultError::Validation(
            "only regular files and directories can be imported".into(),
        ));
    }
    Ok(metadata)
}

/// Validate an export destination directory.
pub fn validate_destination_dir(path: &Path) -> VaultResult<()> {
    if !path.is_absolute() {
        return Err(VaultError::InvalidPath(
            "the destination path must be absolute".into(),
        ));
    }
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_dir() {
        return Err(VaultError::InvalidPath(
            "the destination must be a directory".into(),
        ));
    }
    if is_reparse_point(&metadata) {
        return Err(VaultError::ReparsePointRejected(
            "the destination is a reparse point".into(),
        ));
    }
    Ok(())
}

/// Turn a virtual entry name into a safe single path component for export.
///
/// The name was already validated on the way in, but re-validating on the way
/// out defends against a manifest produced by a different (possibly hostile)
/// writer.
pub fn sanitize_export_name(name: &str) -> VaultResult<String> {
    validate_name(name)?;
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(VaultError::PathTraversal(name.into()));
    }
    if Path::new(name).components().count() != 1 {
        return Err(VaultError::PathTraversal(name.into()));
    }
    Ok(name.to_string())
}

/// Join a validated name onto a directory and prove the result stays inside.
pub fn safe_join(base: &Path, name: &str) -> VaultResult<PathBuf> {
    let clean = sanitize_export_name(name)?;
    let joined = base.join(&clean);
    let base_canon = base
        .canonicalize()
        .map_err(|_| VaultError::InvalidPath("the destination is not accessible".into()))?;
    // canonicalize the parent (the joined path may not exist yet)
    let parent = joined
        .parent()
        .ok_or_else(|| VaultError::PathTraversal(clean.clone()))?
        .canonicalize()
        .map_err(|_| VaultError::InvalidPath("the destination is not accessible".into()))?;
    if !parent.starts_with(&base_canon) {
        return Err(VaultError::PathTraversal(clean));
    }
    let normalized: Vec<Component> = Path::new(&clean).components().collect();
    if normalized.len() != 1 {
        return Err(VaultError::PathTraversal(clean));
    }
    Ok(joined)
}

/// Create a unique temporary file path in the destination directory.
pub fn temp_output_path(dir: &Path) -> PathBuf {
    let n: [u8; 8] = crate::crypto::random_bytes();
    let hex: String = n.iter().map(|b| format!("{b:02x}")).collect();
    dir.join(format!(".myvault-tmp-{hex}.part"))
}

/// True when Windows paging or hibernation is active, in which case plaintext
/// may be copied into system-managed files outside MyVault's control.
pub fn hibernation_or_compression_enabled() -> bool {
    #[cfg(windows)]
    {
        Path::new(r"C:\hiberfil.sys").exists() || Path::new(r"C:\pagefile.sys").exists()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_relative_sources() {
        assert!(validate_source(Path::new("relative.txt")).is_err());
    }

    #[test]
    fn missing_source_reports_invalid_path() {
        let missing = std::env::temp_dir().join("myvault-does-not-exist-12345.bin");
        assert!(matches!(
            validate_source(&missing).unwrap_err(),
            VaultError::InvalidPath(_)
        ));
    }

    #[test]
    fn export_name_sanitization_blocks_traversal() {
        assert!(sanitize_export_name("normal.txt").is_ok());
        assert!(sanitize_export_name("..").is_err());
        assert!(sanitize_export_name("../escape").is_err());
        assert!(sanitize_export_name("a/b").is_err());
        assert!(sanitize_export_name("..\\escape").is_err());
        assert!(sanitize_export_name("C:\\absolute").is_err());
        assert!(sanitize_export_name("").is_err());
    }

    #[test]
    fn safe_join_stays_inside_base() {
        let dir = tempfile::tempdir().unwrap();
        let joined = safe_join(dir.path(), "file.txt").unwrap();
        assert!(joined.starts_with(dir.path()));
        assert!(safe_join(dir.path(), "..\\evil.txt").is_err());
    }

    #[test]
    fn temp_paths_are_unique_and_hidden() {
        let dir = tempfile::tempdir().unwrap();
        let a = temp_output_path(dir.path());
        let b = temp_output_path(dir.path());
        assert_ne!(a, b);
        assert!(a.file_name().unwrap().to_string_lossy().starts_with(".myvault-tmp-"));
    }
}
