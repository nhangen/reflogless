use crate::error::{Error, Result};
use crate::manifest::{Manifest, ManifestEntry};
use crate::repo::Repo;
use crate::select::{self, Selection};
use crate::store::{atomic_write, Store};
use chrono::Utc;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct SnapshotResult {
    pub manifest_id: String,
    pub manifest_path: PathBuf,
    pub files_written: usize,
    pub bytes_written: u64,
    pub skipped: usize,
}

pub fn snap(
    repo: &Repo,
    store: &Store,
    event: &str,
    message: Option<String>,
) -> Result<SnapshotResult> {
    if event == "latest" {
        return Err(Error::Config(
            "event name 'latest' would collide with the restore-latest alias".into(),
        ));
    }
    // Defensively exclude the store itself — prevents recursive snapshotting
    // when the user puts $GITSAFE_DATA_DIR inside the repo (tests, sandboxes).
    let exclude = vec![store.root.clone()];
    let Selection { files, skipped } =
        select::collect_with_cap(repo, select::PER_FILE_CAP_BYTES, &exclude)?;
    let id = make_id(event);
    let mut manifest = Manifest::new(
        id.clone(),
        event.to_string(),
        message,
        repo.root.to_string_lossy().into_owned(),
    );
    let mut bytes = 0u64;
    for f in &files {
        let data = fs::read(&f.abs).map_err(|e| Error::io(&f.abs, e))?;
        let digest = store.write_blob(&data)?;
        bytes += f.size;
        manifest.entries.push(ManifestEntry {
            path: f.rel.clone(),
            blob: digest,
            size: f.size,
            mode: f.mode,
        });
    }
    let manifest_path = store.write_manifest(&manifest)?;
    Ok(SnapshotResult {
        manifest_id: id,
        manifest_path,
        files_written: files.len(),
        bytes_written: bytes,
        skipped: skipped.len(),
    })
}

pub fn restore(
    repo: &Repo,
    store: &Store,
    snap_id: &str,
    only: &[PathBuf],
    force: bool,
) -> Result<RestoreResult> {
    let m = store.load_manifest(snap_id)?;

    // Resolve which entries to restore and which user-supplied paths matched.
    let (selected, missing) = select_entries(&m, only);
    if !missing.is_empty() {
        return Err(Error::NotInSnapshot {
            snap_id: m.id,
            missing,
        });
    }

    // Phase 1: stage all blobs in memory (10 MB per-file cap bounds memory).
    // A read failure here aborts before any byte lands in the user's tree.
    let mut staged: Vec<(&ManifestEntry, Vec<u8>)> = Vec::with_capacity(selected.len());
    let mut refused = Vec::new();
    for e in selected {
        let target = repo.root.join(&e.path);
        if target.exists() && !force {
            refused.push(e.path.clone());
            continue;
        }
        let data = store.read_blob(&e.blob)?;
        staged.push((e, data));
    }

    // Phase 2: atomic-write each staged entry. Each write is tmp+rename, so
    // an individual failure leaves the target file either at its prior state
    // or fully replaced — no truncated hybrids.
    let mut restored = 0usize;
    for (e, data) in staged {
        let target = repo.root.join(&e.path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|err| Error::io(parent, err))?;
        }
        atomic_write(&target, &data)?;
        set_mode(&target, e.mode)?;
        restored += 1;
    }
    Ok(RestoreResult {
        snap_id: m.id,
        restored,
        refused,
    })
}

fn select_entries<'a>(
    m: &'a Manifest,
    only: &[PathBuf],
) -> (Vec<&'a ManifestEntry>, Vec<PathBuf>) {
    if only.is_empty() {
        return (m.entries.iter().collect(), Vec::new());
    }
    let mut selected = Vec::new();
    let mut matched = vec![false; only.len()];
    for e in &m.entries {
        for (i, p) in only.iter().enumerate() {
            if p == &e.path {
                selected.push(e);
                matched[i] = true;
                break;
            }
        }
    }
    let missing: Vec<PathBuf> = only
        .iter()
        .zip(matched.iter())
        .filter_map(|(p, m)| if *m { None } else { Some(p.clone()) })
        .collect();
    (selected, missing)
}

#[derive(Debug)]
pub struct RestoreResult {
    pub snap_id: String,
    pub restored: usize,
    pub refused: Vec<PathBuf>,
}

fn make_id(event: &str) -> String {
    format!("{}-{}", Utc::now().format("%Y%m%dT%H%M%S%3fZ"), event)
}

#[cfg(unix)]
fn set_mode(target: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(mode);
    fs::set_permissions(target, perms).map_err(|e| Error::io(target, e))
}

#[cfg(not(unix))]
fn set_mode(_target: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    fn make_repo(td: &Path) -> Repo {
        Command::new("git").arg("init").arg("-q").arg(td).status().unwrap();
        Command::new("git")
            .args(["-C", td.to_str().unwrap(), "config", "user.email", "t@example.com"])
            .status()
            .unwrap();
        Command::new("git")
            .args(["-C", td.to_str().unwrap(), "config", "user.name", "t"])
            .status()
            .unwrap();
        Repo::discover(td).unwrap()
    }

    #[test]
    fn snap_then_restore_roundtrip() {
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let store = Store::for_repo_with_base(&repo, data_dir.path().to_path_buf()).unwrap();

        fs::write(repo.root.join("hello.txt"), b"hello world\n").unwrap();
        fs::write(repo.root.join("note.md"), b"a note\n").unwrap();

        let snap_res = snap(&repo, &store, "manual", None).unwrap();
        assert_eq!(snap_res.files_written, 2);

        fs::remove_file(repo.root.join("hello.txt")).unwrap();
        assert!(!repo.root.join("hello.txt").exists());

        let r = restore(&repo, &store, &snap_res.manifest_id, &[], false).unwrap();
        assert_eq!(r.restored, 1);
        assert_eq!(fs::read(repo.root.join("hello.txt")).unwrap(), b"hello world\n");
    }

    #[test]
    fn restore_refuses_overwrite_without_force() {
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let store = Store::for_repo_with_base(&repo, data_dir.path().to_path_buf()).unwrap();
        fs::write(repo.root.join("a.txt"), b"v1").unwrap();
        let s = snap(&repo, &store, "manual", None).unwrap();

        fs::write(repo.root.join("a.txt"), b"v2-current").unwrap();
        let r = restore(&repo, &store, &s.manifest_id, &[], false).unwrap();
        assert_eq!(r.restored, 0);
        assert_eq!(r.refused, vec![PathBuf::from("a.txt")]);
        assert_eq!(fs::read(repo.root.join("a.txt")).unwrap(), b"v2-current");
    }

    #[test]
    fn force_overwrites() {
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let store = Store::for_repo_with_base(&repo, data_dir.path().to_path_buf()).unwrap();
        fs::write(repo.root.join("a.txt"), b"v1").unwrap();
        let s = snap(&repo, &store, "manual", None).unwrap();
        fs::write(repo.root.join("a.txt"), b"v2").unwrap();
        let r = restore(&repo, &store, &s.manifest_id, &[], true).unwrap();
        assert_eq!(r.restored, 1);
        assert_eq!(fs::read(repo.root.join("a.txt")).unwrap(), b"v1");
    }

    #[test]
    fn default_deny_skips_log_files() {
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let store = Store::for_repo_with_base(&repo, data_dir.path().to_path_buf()).unwrap();
        fs::write(repo.root.join("keep.txt"), b"keep").unwrap();
        fs::write(repo.root.join("noisy.log"), b"NOISE").unwrap();
        let s = snap(&repo, &store, "manual", None).unwrap();
        assert_eq!(s.files_written, 1);
    }

    #[test]
    fn snap_rejects_event_named_latest() {
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let store = Store::for_repo_with_base(&repo, data_dir.path().to_path_buf()).unwrap();
        fs::write(repo.root.join("a.txt"), b"x").unwrap();
        match snap(&repo, &store, "latest", None) {
            Err(Error::Config(msg)) => assert!(msg.contains("latest")),
            other => panic!("expected Config error, got {other:?}"),
        }
    }

    #[test]
    fn restore_with_typo_path_returns_not_in_snapshot() {
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let store = Store::for_repo_with_base(&repo, data_dir.path().to_path_buf()).unwrap();
        fs::write(repo.root.join("real.txt"), b"x").unwrap();
        let s = snap(&repo, &store, "manual", None).unwrap();
        match restore(&repo, &store, &s.manifest_id, &[PathBuf::from("typo.txt")], false) {
            Err(Error::NotInSnapshot { missing, .. }) => {
                assert_eq!(missing, vec![PathBuf::from("typo.txt")])
            }
            other => panic!("expected NotInSnapshot, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn restore_preserves_executable_mode() {
        use std::os::unix::fs::PermissionsExt;
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let store = Store::for_repo_with_base(&repo, data_dir.path().to_path_buf()).unwrap();
        let target = repo.root.join("script.sh");
        fs::write(&target, b"#!/bin/sh\necho hi\n").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        let s = snap(&repo, &store, "manual", None).unwrap();
        fs::remove_file(&target).unwrap();
        restore(&repo, &store, &s.manifest_id, &[], false).unwrap();
        let mode = fs::metadata(&target).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755, "mode={:o}", mode);
    }

    #[test]
    fn restore_aborts_with_no_writes_on_missing_blob() {
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let store = Store::for_repo_with_base(&repo, data_dir.path().to_path_buf()).unwrap();
        fs::write(repo.root.join("a.txt"), b"alpha").unwrap();
        fs::write(repo.root.join("b.txt"), b"beta").unwrap();
        let s = snap(&repo, &store, "manual", None).unwrap();
        fs::remove_file(repo.root.join("a.txt")).unwrap();
        fs::remove_file(repo.root.join("b.txt")).unwrap();
        // Sabotage one blob to force a phase-1 read error.
        let m = store.load_manifest(&s.manifest_id).unwrap();
        let blob = &m.entries[0].blob;
        let (a, b) = blob.split_at(2);
        fs::remove_file(store.objects_dir().join(a).join(b)).unwrap();
        let err = restore(&repo, &store, &s.manifest_id, &[], false).unwrap_err();
        assert!(matches!(err, Error::Io { .. }));
        // Neither file should have been written — phase-1 prefetch aborted.
        assert!(!repo.root.join("a.txt").exists());
        assert!(!repo.root.join("b.txt").exists());
    }

    #[test]
    fn snap_roundtrip_preserves_size_in_manifest() {
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let store = Store::for_repo_with_base(&repo, data_dir.path().to_path_buf()).unwrap();
        fs::write(repo.root.join("a.txt"), b"twelve bytes").unwrap();
        let s = snap(&repo, &store, "manual", None).unwrap();
        let m = store.load_manifest(&s.manifest_id).unwrap();
        assert_eq!(m.entries[0].size, 12);
    }

    #[test]
    fn snap_excludes_store_dir_inside_repo() {
        let workdir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        // Store base lives INSIDE the repo (pathological config; defend
        // against recursive snapshotting).
        let store_base = repo.root.join(".gitsafe-data");
        let store = Store::for_repo_with_base(&repo, store_base.clone()).unwrap();
        fs::write(repo.root.join("keep.txt"), b"keep").unwrap();
        // First snap creates store files; second snap should NOT see them.
        let s1 = snap(&repo, &store, "manual", None).unwrap();
        assert_eq!(s1.files_written, 1);
        let s2 = snap(&repo, &store, "manual", None).unwrap();
        assert_eq!(s2.files_written, 1, "store files leaked into second snap");
    }

    #[test]
    fn snap_roundtrips_zero_byte_file() {
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let store = Store::for_repo_with_base(&repo, data_dir.path().to_path_buf()).unwrap();
        fs::write(repo.root.join("empty"), b"").unwrap();
        let s = snap(&repo, &store, "manual", None).unwrap();
        assert_eq!(s.files_written, 1);
        fs::remove_file(repo.root.join("empty")).unwrap();
        restore(&repo, &store, &s.manifest_id, &[], false).unwrap();
        assert_eq!(fs::read(repo.root.join("empty")).unwrap(), b"");
    }
}
