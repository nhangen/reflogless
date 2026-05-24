use crate::config::{should_encrypt, EncryptPolicy};
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
    snap_with_policy(repo, store, event, message, EncryptPolicy::Secrets)
}

/// Take a snapshot using an explicit encryption policy. Per-entry decision is:
/// secret-shaped paths are always encrypted; the policy controls everything
/// else. Encryption is only applied when the store has a crypto context.
pub fn snap_with_policy(
    repo: &Repo,
    store: &Store,
    event: &str,
    message: Option<String>,
    policy: EncryptPolicy,
) -> Result<SnapshotResult> {
    if event == "latest" {
        return Err(Error::Config(
            "event name 'latest' would collide with the restore-latest alias".into(),
        ));
    }
    repo.assert_safe_ownership()?;
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
        let encrypt_this = match store.crypto() {
            Some(_) => should_encrypt(&f.rel, policy),
            None => false,
        };
        let (digest, encrypted) = if encrypt_this {
            let ctx = store.crypto().expect("encrypt_this implies crypto present");
            (store.write_blob_encrypted(&data, &ctx.recipient)?, true)
        } else {
            (store.write_blob(&data)?, false)
        };
        bytes += f.size;
        manifest.entries.push(ManifestEntry {
            path: f.rel.clone(),
            blob: digest,
            size: f.size,
            mode: f.mode,
            encrypted,
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

    repo.assert_safe_ownership()?;
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
        let data = store.read_entry(e)?;
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

    fn encrypted_store(repo: &Repo, base: &Path) -> (Store, age::x25519::Identity) {
        use crate::crypto;
        let store = Store::for_repo_with_base(repo, base.to_path_buf()).unwrap();
        let id = crypto::generate_identity();
        let recipient = crypto::recipient_of(&id);
        store.save_recipient(&recipient).unwrap();
        let store = store.with_crypto(crate::store::CryptoCtx::from_identity(id.clone()));
        (store, id)
    }

    #[test]
    fn encrypted_snap_writes_age_manifest_and_roundtrips() {
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let (store, _id) = encrypted_store(&repo, data_dir.path());

        fs::write(repo.root.join(".env.production"), b"DATABASE_URL=postgres://prod").unwrap();
        fs::write(repo.root.join("notes.md"), b"safe").unwrap();

        let r = snap_with_policy(&repo, &store, "manual", None, EncryptPolicy::Secrets).unwrap();
        assert_eq!(r.files_written, 2);
        // Manifest landed at .json.age path.
        let snap_dir = store.snapshots_dir();
        let names: Vec<_> = fs::read_dir(&snap_dir)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name().into_string().unwrap()))
            .collect();
        assert!(
            names.iter().any(|n| n.ends_with(".json.age")),
            "no encrypted manifest found in {names:?}"
        );
        assert!(
            !names.iter().any(|n| n.ends_with(".json") && !n.ends_with(".json.age")),
            "plaintext manifest leaked: {names:?}"
        );

        // Manifest contents are unreadable as JSON.
        let enc_path = snap_dir
            .read_dir()
            .unwrap()
            .filter_map(|e| e.ok())
            .find(|e| e.file_name().to_string_lossy().ends_with(".json.age"))
            .unwrap()
            .path();
        let raw = fs::read(&enc_path).unwrap();
        assert!(
            serde_json::from_slice::<serde_json::Value>(&raw).is_err(),
            "encrypted manifest still parses as JSON"
        );

        // Restore via the identity-attached store works.
        fs::remove_file(repo.root.join(".env.production")).unwrap();
        fs::remove_file(repo.root.join("notes.md")).unwrap();
        let rr = restore(&repo, &store, &r.manifest_id, &[], false).unwrap();
        assert_eq!(rr.restored, 2);
        assert_eq!(
            fs::read(repo.root.join(".env.production")).unwrap(),
            b"DATABASE_URL=postgres://prod"
        );
    }

    #[test]
    fn secrets_policy_encrypts_only_secret_shaped_blobs() {
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let (store, _id) = encrypted_store(&repo, data_dir.path());

        fs::write(repo.root.join("safe.txt"), b"plaintext-fine").unwrap();
        fs::write(repo.root.join(".env"), b"DB=prod").unwrap();

        let r = snap_with_policy(&repo, &store, "manual", None, EncryptPolicy::Secrets).unwrap();
        let m = store.load_manifest(&r.manifest_id).unwrap();
        let env_entry = m.entries.iter().find(|e| e.path == PathBuf::from(".env")).unwrap();
        let safe_entry = m.entries.iter().find(|e| e.path == PathBuf::from("safe.txt")).unwrap();
        assert!(env_entry.encrypted, ".env should be encrypted");
        assert!(!safe_entry.encrypted, "safe.txt should be plain");

        // The plain blob is byte-equal to plaintext on disk.
        let plain = store.read_blob(&safe_entry.blob).unwrap();
        assert_eq!(plain, b"plaintext-fine");
    }

    #[test]
    fn all_policy_encrypts_every_blob() {
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let (store, _id) = encrypted_store(&repo, data_dir.path());

        fs::write(repo.root.join("safe.txt"), b"plain").unwrap();
        let r = snap_with_policy(&repo, &store, "manual", None, EncryptPolicy::All).unwrap();
        let m = store.load_manifest(&r.manifest_id).unwrap();
        assert!(m.entries.iter().all(|e| e.encrypted));
    }

    #[test]
    fn none_policy_still_encrypts_secret_shaped_paths() {
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let (store, _id) = encrypted_store(&repo, data_dir.path());

        fs::write(repo.root.join("plain.md"), b"plain").unwrap();
        fs::write(repo.root.join("id_rsa_prod"), b"-----BEGIN KEY-----").unwrap();
        let r = snap_with_policy(&repo, &store, "manual", None, EncryptPolicy::Off).unwrap();
        let m = store.load_manifest(&r.manifest_id).unwrap();
        let key = m.entries.iter().find(|e| e.path == PathBuf::from("id_rsa_prod")).unwrap();
        let plain = m.entries.iter().find(|e| e.path == PathBuf::from("plain.md")).unwrap();
        assert!(key.encrypted, "id_rsa_prod must always be encrypted");
        assert!(!plain.encrypted, "plain.md under 'none' policy stays plain");
    }

    #[test]
    fn gitsafe_toml_policy_applies_end_to_end() {
        // Pins the wiring `Config::load_or_default(repo_root).encrypt →
        // snap_with_policy(..., cfg.encrypt)` exercised by main.rs::run.
        use crate::config::Config;
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let (store, _id) = encrypted_store(&repo, data_dir.path());

        // .gitsafe.toml requests `encrypt = "all"`.
        fs::write(repo.root.join(".gitsafe.toml"), "encrypt = \"all\"\n").unwrap();
        fs::write(repo.root.join("README.md"), b"docs").unwrap();
        let cfg = Config::load_or_default(&repo.root).unwrap();
        let r = snap_with_policy(&repo, &store, "manual", None, cfg.encrypt).unwrap();
        let m = store.load_manifest(&r.manifest_id).unwrap();
        let readme = m
            .entries
            .iter()
            .find(|e| e.path == PathBuf::from("README.md"))
            .unwrap();
        assert!(
            readme.encrypted,
            "encrypt = \"all\" in .gitsafe.toml must encrypt non-secret blobs"
        );
    }

    #[test]
    fn read_entry_returns_plaintext_for_encrypted_entry() {
        // Regression for the diff_snapshot bug: any code path that reads a
        // manifest entry must go through Store::read_entry, which decrypts
        // when `entry.encrypted`. Pre-fix, `gitsafe diff <id> .env.production`
        // returned ciphertext bytes for a text-diff pass.
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let (store, _id) = encrypted_store(&repo, data_dir.path());

        fs::write(repo.root.join(".env"), b"SECRET=prod\n").unwrap();
        let r = snap_with_policy(&repo, &store, "manual", None, EncryptPolicy::Secrets).unwrap();
        let m = store.load_manifest(&r.manifest_id).unwrap();
        let entry = m.entries.iter().find(|e| e.path == PathBuf::from(".env")).unwrap();
        assert!(entry.encrypted);
        // Raw read_blob returns ciphertext.
        let raw = store.read_blob(&entry.blob).unwrap();
        assert_ne!(raw, b"SECRET=prod\n", "raw blob must be ciphertext");
        // read_entry must return plaintext for downstream consumers (restore, diff).
        let decoded = store.read_entry(entry).unwrap();
        assert_eq!(decoded, b"SECRET=prod\n");
    }

    #[test]
    fn read_entry_errors_loudly_on_encrypted_without_identity() {
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let (store_with_id, _id) = encrypted_store(&repo, data_dir.path());
        fs::write(repo.root.join(".env"), b"x").unwrap();
        let r = snap_with_policy(&repo, &store_with_id, "manual", None, EncryptPolicy::Secrets).unwrap();
        let m = store_with_id.load_manifest(&r.manifest_id).unwrap();
        let entry = m.entries.iter().find(|e| e.path == PathBuf::from(".env")).unwrap().clone();

        let bare = Store::for_repo_with_base(&repo, data_dir.path().to_path_buf()).unwrap();
        match bare.read_entry(&entry) {
            Err(Error::Decryption(_)) => {}
            other => panic!("expected Decryption error, got {other:?}"),
        }
    }

    #[test]
    fn restore_fails_loudly_when_identity_missing() {
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let (store_with_id, _id) = encrypted_store(&repo, data_dir.path());

        fs::write(repo.root.join(".env"), b"x").unwrap();
        let r = snap_with_policy(&repo, &store_with_id, "manual", None, EncryptPolicy::Secrets).unwrap();
        fs::remove_file(repo.root.join(".env")).unwrap();

        // Reattach a store WITHOUT identity and verify restore errors cleanly.
        let bare = Store::for_repo_with_base(&repo, data_dir.path().to_path_buf()).unwrap();
        match restore(&repo, &bare, &r.manifest_id, &[], false) {
            Err(Error::Decryption(_)) => {}
            other => panic!("expected Decryption error, got {other:?}"),
        }
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
