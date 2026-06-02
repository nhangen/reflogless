use crate::config::{is_secret_shaped, should_encrypt, Config, EncryptPolicy};
use crate::error::{Error, Result};
use crate::manifest::{Manifest, ManifestEntry};
use crate::repo::Repo;
use crate::select::{self, Selection, Skipped};
use crate::store::{atomic_write, SnapLockMode, Store};
use chrono::Utc;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct SnapshotResult {
    pub manifest_id: String,
    pub manifest_path: PathBuf,
    pub files_written: usize,
    pub bytes_written: u64,
    pub skipped: Vec<Skipped>,
    /// `Some(reason)` when snap was skipped because git was mid-operation
    /// (rebase, merge, cherry-pick, etc.). `files_written` is 0 and
    /// `manifest_id`/`manifest_path` are empty in this case. See #40.
    pub skipped_git_busy: Option<String>,
    /// True when snap was skipped because the per-store `.snap.lock` was held
    /// by another process and the caller asked for `SnapLockMode::TryOnce`
    /// (i.e. the future watcher daemon #30, which must never block git).
    pub skipped_lock_held: bool,
}

pub fn snap(
    repo: &Repo,
    store: &Store,
    event: &str,
    message: Option<String>,
) -> Result<SnapshotResult> {
    snap_with_policy(repo, store, event, message, EncryptPolicy::Secrets)
}

/// Convenience wrapper that builds a Config carrying just the encryption
/// policy (no track allowlist). Retained for tests that only need to pass
/// an encryption policy without loading `.reflogless.toml`.
pub fn snap_with_policy(
    repo: &Repo,
    store: &Store,
    event: &str,
    message: Option<String>,
    policy: EncryptPolicy,
) -> Result<SnapshotResult> {
    let cfg = Config {
        encrypt: policy,
        ..Config::default()
    };
    snap_with_config(repo, store, event, message, &cfg)
}

/// Take a snapshot using full repo config (encryption policy + track
/// allowlist). Per-entry encryption decision: secret-shaped paths are always
/// encrypted; the policy controls everything else. Encryption is only applied
/// when the store has a crypto context.
pub fn snap_with_config(
    repo: &Repo,
    store: &Store,
    event: &str,
    message: Option<String>,
    cfg: &Config,
) -> Result<SnapshotResult> {
    snap_with_config_lock_mode(repo, store, event, message, cfg, SnapLockMode::Block)
}

/// Same as `snap_with_config` but with explicit lock acquisition mode. The
/// watcher daemon (#30) calls this with `SnapLockMode::TryOnce` so it skips
/// the snap window instead of blocking git when hooks/shim are mid-snap.
/// On skip the result carries `skipped_lock_held: true`; manifest_id is empty.
pub fn snap_with_config_lock_mode(
    repo: &Repo,
    store: &Store,
    event: &str,
    message: Option<String>,
    cfg: &Config,
    lock_mode: SnapLockMode,
) -> Result<SnapshotResult> {
    if event == "latest" {
        return Err(Error::Config(
            "event name 'latest' would collide with the restore-latest alias".into(),
        ));
    }
    repo.assert_safe_ownership()?;
    // Skip snap when git is mid-rebase/merge/cherry-pick/bisect or holds
    // index.lock — snapshotting half-applied state captures conflict markers
    // as if they were user content. See issue #40.
    if let Some(reason) = repo.git_busy() {
        log_gate_skip(store, event, &reason);
        return Ok(SnapshotResult {
            manifest_id: String::new(),
            manifest_path: PathBuf::new(),
            files_written: 0,
            bytes_written: 0,
            skipped: Vec::new(),
            skipped_git_busy: Some(reason),
            skipped_lock_held: false,
        });
    }
    // Serialize concurrent snaps against this store. Hooks/shim Block; the
    // watcher daemon (#30) passes TryOnce so it skips this window instead of
    // blocking git when hooks/shim are mid-snap. See issue #39.
    let _lock = match store.acquire_snap_lock(lock_mode)? {
        Some(g) => g,
        None => {
            return Ok(SnapshotResult {
                manifest_id: String::new(),
                manifest_path: PathBuf::new(),
                files_written: 0,
                bytes_written: 0,
                skipped: Vec::new(),
                skipped_git_busy: None,
                skipped_lock_held: true,
            });
        }
    };
    // Defensively exclude the store itself — prevents recursive snapshotting
    // when the user puts $REFLOGLESS_DATA_DIR inside the repo (tests, sandboxes).
    let exclude = vec![store.root.clone()];
    let Selection { files, skipped } =
        select::collect_with_cap(repo, select::PER_FILE_CAP_BYTES, &exclude, &cfg.track)?;
    // Invariant: secret-shaped paths are never written plaintext. Pre-flight
    // BEFORE any blob write so refusal is atomic — covers both `cfg.track`
    // opt-ins and any git-status path resolving a secret-shaped name on a
    // store with no provisioned identity. Per
    // ~/.claude/rules/safety-invariant-scope.md (gate at the function, not
    // each caller).
    if store.crypto().is_none() {
        if let Some(secret) = files.iter().find(|f| is_secret_shaped(&f.rel)) {
            return Err(Error::Config(format!(
                "{} is secret-shaped; provision an encryption identity \
                 with `reflogless init` before snapshotting (refusing to write plaintext secret)",
                secret.rel.display()
            )));
        }
    }
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
            Some(_) => should_encrypt(&f.rel, cfg.encrypt),
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
        skipped,
        skipped_git_busy: None,
        skipped_lock_held: false,
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

fn select_entries<'a>(m: &'a Manifest, only: &[PathBuf]) -> (Vec<&'a ManifestEntry>, Vec<PathBuf>) {
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

const GATE_SKIP_LOG_FILENAME: &str = "skipped_git_busy.jsonl";
const GATE_SKIP_LOG_DIR: &str = "events";
const GATE_SKIP_LOG_MAX_BYTES: u64 = 1_048_576;

/// Append one JSONL line per gate firing to `<store>/events/skipped_git_busy.jsonl`.
/// Best-effort: failures here never propagate (gate already returned a valid skip
/// result to the caller). Size-capped via head-truncation: when the file exceeds
/// GATE_SKIP_LOG_MAX_BYTES, drop the oldest 50%.
fn log_gate_skip(store: &Store, event: &str, reason: &str) {
    let dir = store.root.join(GATE_SKIP_LOG_DIR);
    if fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join(GATE_SKIP_LOG_FILENAME);
    let ts = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let line = format!(
        "{{\"ts\":\"{}\",\"event\":\"{}\",\"reason\":\"{}\"}}\n",
        ts,
        json_escape(event),
        json_escape(reason),
    );
    use std::io::Write;
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = f.write_all(line.as_bytes());
    }
    if let Ok(meta) = fs::metadata(&path) {
        if meta.len() > GATE_SKIP_LOG_MAX_BYTES {
            let _ = truncate_head(&path);
        }
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn truncate_head(path: &Path) -> Result<()> {
    let body = fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
    let lines: Vec<&str> = body.lines().collect();
    let keep_from = lines.len() / 2;
    let trimmed = lines[keep_from..].join("\n") + "\n";
    atomic_write(path, trimmed.as_bytes())
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
        Command::new("git")
            .arg("init")
            .arg("-q")
            .arg(td)
            .status()
            .unwrap();
        Command::new("git")
            .args([
                "-C",
                td.to_str().unwrap(),
                "config",
                "user.email",
                "t@example.com",
            ])
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
        assert_eq!(
            fs::read(repo.root.join("hello.txt")).unwrap(),
            b"hello world\n"
        );
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
        match restore(
            &repo,
            &store,
            &s.manifest_id,
            &[PathBuf::from("typo.txt")],
            false,
        ) {
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
        let store_base = repo.root.join(".reflogless-data");
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

        fs::write(
            repo.root.join(".env.production"),
            b"DATABASE_URL=postgres://prod",
        )
        .unwrap();
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
            !names
                .iter()
                .any(|n| n.ends_with(".json") && !n.ends_with(".json.age")),
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
        let env_entry = m
            .entries
            .iter()
            .find(|e| e.path == Path::new(".env"))
            .unwrap();
        let safe_entry = m
            .entries
            .iter()
            .find(|e| e.path == Path::new("safe.txt"))
            .unwrap();
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
        let key = m
            .entries
            .iter()
            .find(|e| e.path == Path::new("id_rsa_prod"))
            .unwrap();
        let plain = m
            .entries
            .iter()
            .find(|e| e.path == Path::new("plain.md"))
            .unwrap();
        assert!(key.encrypted, "id_rsa_prod must always be encrypted");
        assert!(!plain.encrypted, "plain.md under 'none' policy stays plain");
    }

    #[test]
    fn reflogless_toml_policy_applies_end_to_end() {
        // Pins the wiring `Config::load_or_default(repo_root).encrypt →
        // snap_with_policy(..., cfg.encrypt)` exercised by main.rs::run.
        use crate::config::Config;
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let (store, _id) = encrypted_store(&repo, data_dir.path());

        // .reflogless.toml requests `encrypt = "all"`.
        fs::write(repo.root.join(".reflogless.toml"), "encrypt = \"all\"\n").unwrap();
        fs::write(repo.root.join("README.md"), b"docs").unwrap();
        let cfg = Config::load_or_default(&repo.root).unwrap();
        let r = snap_with_policy(&repo, &store, "manual", None, cfg.encrypt).unwrap();
        let m = store.load_manifest(&r.manifest_id).unwrap();
        let readme = m
            .entries
            .iter()
            .find(|e| e.path == Path::new("README.md"))
            .unwrap();
        assert!(
            readme.encrypted,
            "encrypt = \"all\" in .reflogless.toml must encrypt non-secret blobs"
        );
    }

    #[test]
    fn read_entry_returns_plaintext_for_encrypted_entry() {
        // Regression for the diff_snapshot bug: any code path that reads a
        // manifest entry must go through Store::read_entry, which decrypts
        // when `entry.encrypted`. Pre-fix, `reflogless diff <id> .env.production`
        // returned ciphertext bytes for a text-diff pass.
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let (store, _id) = encrypted_store(&repo, data_dir.path());

        fs::write(repo.root.join(".env"), b"SECRET=prod\n").unwrap();
        let r = snap_with_policy(&repo, &store, "manual", None, EncryptPolicy::Secrets).unwrap();
        let m = store.load_manifest(&r.manifest_id).unwrap();
        let entry = m
            .entries
            .iter()
            .find(|e| e.path == Path::new(".env"))
            .unwrap();
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
        let r = snap_with_policy(
            &repo,
            &store_with_id,
            "manual",
            None,
            EncryptPolicy::Secrets,
        )
        .unwrap();
        let m = store_with_id.load_manifest(&r.manifest_id).unwrap();
        let entry = m
            .entries
            .iter()
            .find(|e| e.path == Path::new(".env"))
            .unwrap()
            .clone();

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
        let r = snap_with_policy(
            &repo,
            &store_with_id,
            "manual",
            None,
            EncryptPolicy::Secrets,
        )
        .unwrap();
        fs::remove_file(repo.root.join(".env")).unwrap();

        // Reattach a store WITHOUT identity and verify restore errors cleanly.
        let bare = Store::for_repo_with_base(&repo, data_dir.path().to_path_buf()).unwrap();
        match restore(&repo, &bare, &r.manifest_id, &[], false) {
            Err(Error::Decryption(_)) => {}
            other => panic!("expected Decryption error, got {other:?}"),
        }
    }

    #[test]
    fn snap_refuses_secret_shaped_track_entry_without_crypto() {
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let store = Store::for_repo_with_base(&repo, data_dir.path().to_path_buf()).unwrap();
        assert!(store.crypto().is_none());
        fs::write(repo.root.join(".gitignore"), b".env\n").unwrap();
        fs::write(repo.root.join(".env"), b"SECRET=1\n").unwrap();
        let cfg = Config {
            track: vec![".env".to_string()],
            ..Config::default()
        };
        let err = snap_with_config(&repo, &store, "manual", None, &cfg).unwrap_err();
        match err {
            Error::Config(msg) => assert!(
                msg.contains("secret-shaped") && msg.contains(".env"),
                "msg={msg}"
            ),
            other => panic!("expected Config error, got {other:?}"),
        }
        // Crucially: nothing landed in the store.
        let manifests = store.list_manifests_lenient().unwrap().0;
        assert!(
            manifests.is_empty(),
            "no manifest should be written when secret refusal fires"
        );
    }

    #[test]
    fn snap_refuses_git_status_secret_shaped_without_crypto() {
        // Broader scope: even a non-tracked, git-status-reported secret-shaped
        // path must not land plaintext. This is the invariant-scope expansion
        // (per safety-invariant-scope.md): gate at the write site, not just
        // cfg.track callers.
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let store = Store::for_repo_with_base(&repo, data_dir.path().to_path_buf()).unwrap();
        assert!(store.crypto().is_none());
        // No .gitignore, no `track` — git status will report .env as untracked.
        fs::write(repo.root.join(".env"), b"SECRET=2\n").unwrap();
        let err = snap(&repo, &store, "manual", None).unwrap_err();
        match err {
            Error::Config(msg) => assert!(
                msg.contains("secret-shaped") && msg.contains(".env"),
                "msg={msg}"
            ),
            other => panic!("expected Config error, got {other:?}"),
        }
        let manifests = store.list_manifests_lenient().unwrap().0;
        assert!(manifests.is_empty(), "no manifest should land on refusal");
    }

    #[test]
    fn snap_with_config_captures_and_encrypts_tracked_env() {
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let (store, _id) = encrypted_store(&repo, data_dir.path());
        fs::write(repo.root.join(".gitignore"), b".env\n").unwrap();
        fs::write(repo.root.join(".env"), b"SECRET=1\n").unwrap();
        let cfg = Config {
            track: vec![".env".to_string()],
            ..Config::default()
        };
        let r = snap_with_config(&repo, &store, "manual", None, &cfg).unwrap();
        let manifest = store.load_manifest(&r.manifest_id).unwrap();
        let env_entry = manifest
            .entries
            .iter()
            .find(|e| e.path == Path::new(".env"))
            .expect("manifest must contain .env entry");
        assert!(
            env_entry.encrypted,
            ".env must be encrypted (secret-shaped)"
        );
    }

    #[test]
    fn snap_with_config_restores_tracked_env() {
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let (store, _id) = encrypted_store(&repo, data_dir.path());
        fs::write(repo.root.join(".gitignore"), b".env\n").unwrap();
        fs::write(repo.root.join(".env"), b"SECRET=1\n").unwrap();
        let cfg = Config {
            track: vec![".env".to_string()],
            ..Config::default()
        };
        let r = snap_with_config(&repo, &store, "manual", None, &cfg).unwrap();
        fs::remove_file(repo.root.join(".env")).unwrap();
        restore(&repo, &store, &r.manifest_id, &[], false).unwrap();
        assert_eq!(fs::read(repo.root.join(".env")).unwrap(), b"SECRET=1\n");
    }

    #[test]
    fn snap_result_surfaces_per_path_skipped() {
        // Reach into select via collect_with_cap directly, then verify
        // SnapshotResult.skipped carries those entries by name (not a count).
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let store = Store::for_repo_with_base(&repo, data_dir.path().to_path_buf()).unwrap();
        // Create a `.log` file (default-denied by *.log rule).
        fs::write(repo.root.join("big.log"), b"noise\n").unwrap();
        let r = snap(&repo, &store, "manual", None).unwrap();
        assert!(
            r.skipped.iter().any(
                |s| matches!(s, select::Skipped::DenyMatch { rel } if rel.ends_with("big.log"))
            ),
            "expected DenyMatch for big.log in SnapshotResult.skipped, got {:?}",
            r.skipped
        );
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

    #[test]
    fn snap_skips_when_git_is_rebasing() {
        // Pins the git-busy gate wiring inside snap_with_config (#40).
        // Removing the gate makes snap proceed and capture a manifest with
        // the rebase-merge artifacts visible.
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let store = Store::for_repo_with_base(&repo, data_dir.path().to_path_buf()).unwrap();
        fs::write(repo.root.join("file"), b"hi").unwrap();
        fs::create_dir_all(repo.root.join(".git").join("rebase-merge")).unwrap();
        let r = snap(&repo, &store, "manual", None).unwrap();
        assert!(r.skipped_git_busy.is_some(), "should have skipped");
        assert!(
            r.skipped_git_busy.as_deref().unwrap().contains("rebase"),
            "reason should mention rebase, got {:?}",
            r.skipped_git_busy
        );
        assert_eq!(r.files_written, 0);
        assert!(r.manifest_id.is_empty());
        assert!(store.list_manifests_lenient().unwrap().0.is_empty());
    }

    #[test]
    fn snap_skips_when_index_lock_is_held() {
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let store = Store::for_repo_with_base(&repo, data_dir.path().to_path_buf()).unwrap();
        fs::write(repo.root.join("file"), b"hi").unwrap();
        fs::write(repo.root.join(".git").join("index.lock"), b"").unwrap();
        let r = snap(&repo, &store, "manual", None).unwrap();
        assert!(r.skipped_git_busy.is_some());
        assert_eq!(r.files_written, 0);
    }

    #[test]
    fn snap_proceeds_when_git_is_idle() {
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let store = Store::for_repo_with_base(&repo, data_dir.path().to_path_buf()).unwrap();
        fs::write(repo.root.join("file"), b"hi").unwrap();
        let r = snap(&repo, &store, "manual", None).unwrap();
        assert!(r.skipped_git_busy.is_none());
        assert_eq!(r.files_written, 1);
    }

    #[test]
    fn gate_skip_appends_event_log() {
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let store = Store::for_repo_with_base(&repo, data_dir.path().to_path_buf()).unwrap();
        fs::create_dir_all(repo.root.join(".git").join("rebase-merge")).unwrap();
        let r = snap(&repo, &store, "post-commit", None).unwrap();
        assert!(r.skipped_git_busy.is_some());
        let log = store.root.join("events").join("skipped_git_busy.jsonl");
        assert!(log.exists(), "gate skip should write event log");
        let body = fs::read_to_string(&log).unwrap();
        assert_eq!(body.lines().count(), 1, "one line per skip; got {body:?}");
        assert!(body.contains("\"event\":\"post-commit\""));
        assert!(body.contains("\"reason\":\"interactive rebase in progress\""));
        assert!(body.contains("\"ts\":\""));
        // Second skip appends, doesn't overwrite.
        let _ = snap(&repo, &store, "manual", None).unwrap();
        let body2 = fs::read_to_string(&log).unwrap();
        assert_eq!(body2.lines().count(), 2);
    }

    #[test]
    fn gate_skip_log_escapes_special_chars_in_reason() {
        // Crafted reason via custom repo: index.lock with a quote in event name.
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let store = Store::for_repo_with_base(&repo, data_dir.path().to_path_buf()).unwrap();
        fs::write(repo.root.join(".git").join("index.lock"), b"").unwrap();
        let r = snap(&repo, &store, "weird\"event\nname", None).unwrap();
        assert!(r.skipped_git_busy.is_some());
        let body =
            fs::read_to_string(store.root.join("events").join("skipped_git_busy.jsonl")).unwrap();
        assert!(
            body.contains("weird\\\"event\\nname"),
            "event escaped: {body:?}"
        );
    }

    #[test]
    fn gate_skip_log_truncates_head_when_oversized() {
        use super::{GATE_SKIP_LOG_DIR, GATE_SKIP_LOG_FILENAME};
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let store = Store::for_repo_with_base(&repo, data_dir.path().to_path_buf()).unwrap();
        fs::create_dir_all(repo.root.join(".git").join("rebase-merge")).unwrap();
        let log_dir = store.root.join(GATE_SKIP_LOG_DIR);
        fs::create_dir_all(&log_dir).unwrap();
        let log_path = log_dir.join(GATE_SKIP_LOG_FILENAME);
        // Seed an oversized log with 1.5 MB of lines.
        let line = "{\"ts\":\"2026-01-01T00:00:00Z\",\"event\":\"x\",\"reason\":\"old\"}\n";
        let copies = (1_500_000 / line.len()) + 1;
        fs::write(&log_path, line.repeat(copies)).unwrap();
        let before = fs::metadata(&log_path).unwrap().len();
        assert!(before > 1_048_576);
        let _ = snap(&repo, &store, "post-commit", None).unwrap();
        let after = fs::metadata(&log_path).unwrap().len();
        assert!(
            after < before / 2 + 200,
            "truncated; before={before} after={after}"
        );
        // The newest line (just-written post-commit) must still be there.
        let body = fs::read_to_string(&log_path).unwrap();
        assert!(body.contains("post-commit"));
    }

    #[test]
    fn snap_blocks_while_external_lock_is_held() {
        // Pins the lock-acquisition wiring inside snap_with_config (#39).
        // External flock holder releases after ~500ms; assert snap waited
        // at least 300ms before completing. With the lock acquisition
        // removed, snap returns near-instantly and the assert fails.
        use crate::store::SNAP_LOCK_FILENAME;
        use std::process::{Command as Cmd, Stdio};
        let workdir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let repo = make_repo(workdir.path());
        let store = Store::for_repo_with_base(&repo, data_dir.path().to_path_buf()).unwrap();
        fs::write(repo.root.join("a.txt"), b"hello").unwrap();
        let lockpath = store.root.join(SNAP_LOCK_FILENAME);
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lockpath)
            .unwrap();
        let marker = data_dir.path().join("child-ready");
        let helper = r#"
import fcntl, os, sys, time
f = open(sys.argv[1], 'r+')
fcntl.flock(f, fcntl.LOCK_EX)
open(sys.argv[2], 'w').close()
time.sleep(0.5)
"#;
        let mut child = Cmd::new("python3")
            .arg("-c")
            .arg(helper)
            .arg(&lockpath)
            .arg(&marker)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let start = std::time::Instant::now();
        while !marker.exists() && start.elapsed().as_secs() < 2 {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(marker.exists(), "child failed to acquire lock");
        let t0 = std::time::Instant::now();
        let r = snap(&repo, &store, "manual", None).unwrap();
        let elapsed = t0.elapsed();
        assert!(
            elapsed.as_millis() >= 300,
            "snap returned in {elapsed:?}; expected >= 300ms because external lock held"
        );
        assert_eq!(r.files_written, 1);
        let _ = child.wait();
    }
}
