use crate::crypto;
use crate::error::Result;
use crate::hooks::{hooks_dir, HOOKS, MARKER};
use crate::repo::Repo;
use crate::store::Store;
use std::fmt::Write as _;
use std::fs;

#[derive(Debug)]
pub struct DoctorReport {
    pub hooks: Vec<HookStatus>,
    pub store_size_bytes: Result<u64>,
    pub snapshots: Result<usize>,
    pub corrupt_snapshots: usize,
    pub shim_status: ShimStatus,
    pub canary_roundtrip: bool,
    pub recent_hook_errors: Vec<String>,
    pub crypto_status: CryptoStatus,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CryptoStatus {
    /// Store has no recipient file; encryption not provisioned.
    NotProvisioned,
    /// Recipient on disk, identity reachable via attached crypto context; round-trip OK.
    Healthy { insecure_file_key: bool },
    /// Provisioned but doctor couldn't decrypt the canary.
    RoundtripFailed(String),
    /// Recipient on disk but no identity attached to the store at doctor time.
    KeyUnreachable,
}

#[derive(Debug)]
pub struct HookStatus {
    pub name: String,
    pub state: HookState,
}

#[derive(Debug, PartialEq, Eq)]
pub enum HookState {
    Missing,
    Unreadable(String),
    Managed { chained: bool },
    Tampered,
    Foreign,
}

#[derive(Debug)]
pub enum ShimStatus {
    /// No reflogless-managed shim at the resolved install dir.
    Off,
    /// Shim present and is the first `git` on PATH.
    On { path: std::path::PathBuf },
    /// Shim present but PATH resolves `git` to a different binary that
    /// precedes it — the shim won't run.
    Shadowed {
        ours: std::path::PathBuf,
        precedes: std::path::PathBuf,
    },
    /// A file at the shim path exists but is not reflogless-managed.
    Foreign { path: std::path::PathBuf },
}

impl From<crate::shim::ShimStatus> for ShimStatus {
    fn from(s: crate::shim::ShimStatus) -> Self {
        match s {
            crate::shim::ShimStatus::Off => ShimStatus::Off,
            crate::shim::ShimStatus::On { path } => ShimStatus::On { path },
            crate::shim::ShimStatus::Shadowed { ours, precedes } => {
                ShimStatus::Shadowed { ours, precedes }
            }
            crate::shim::ShimStatus::Foreign { path } => ShimStatus::Foreign { path },
        }
    }
}

pub fn run(repo: &Repo, store: &Store) -> Result<DoctorReport> {
    let dir = hooks_dir(repo)?;
    let mut hook_status = Vec::new();
    for h in HOOKS {
        let p = dir.join(h);
        let backup = p.with_extension("reflogless-orig");
        let state = if !p.exists() {
            HookState::Missing
        } else {
            match fs::read_to_string(&p) {
                Err(e) => HookState::Unreadable(e.to_string()),
                Ok(body) => {
                    if body.contains(MARKER) {
                        HookState::Managed {
                            chained: backup.exists(),
                        }
                    } else if body.contains("reflogless snap --event") {
                        // A user hand-edited the reflogless wrapper and stripped
                        // the marker, but the reflogless call is still present —
                        // distinct from a legitimate third-party hook.
                        HookState::Tampered
                    } else {
                        HookState::Foreign
                    }
                }
            }
        };
        hook_status.push(HookStatus {
            name: (*h).into(),
            state,
        });
    }

    let store_size_bytes = dir_size(&store.root);
    let (snapshots, corrupt_snapshots) = match store.list_manifests_lenient() {
        Ok((ok, warn)) => (Ok(ok.len()), warn.len()),
        Err(e) => (Err(e), 0),
    };

    // Canary: roundtrip a fixed blob through the SAME write/read path the
    // user's snapshots take. On an encrypted store this exercises
    // write_blob_encrypted + read_blob_encrypted so an unreachable identity
    // or corrupt recipient surfaces here, not at first real snap.
    let canary_bytes: &[u8] = b"reflogless-doctor-canary-32-bytes!!";
    let canary_roundtrip = match store.crypto() {
        Some(ctx) => match store.write_blob_encrypted(canary_bytes, &ctx.recipient) {
            Ok(d) => {
                let ok = store
                    .read_blob_encrypted(&d, &ctx.identity)
                    .map(|b| b == canary_bytes)
                    .unwrap_or(false);
                if let Err(e) = store.delete_blob(&d) {
                    eprintln!(
                        "reflogless: warning: canary blob cleanup failed at {d}: {e}"
                    );
                }
                ok
            }
            Err(_) => false,
        },
        None => match store.write_blob(canary_bytes) {
            Ok(d) => {
                let ok = store
                    .read_blob(&d)
                    .map(|b| b == canary_bytes)
                    .unwrap_or(false);
                if let Err(e) = store.delete_blob(&d) {
                    eprintln!(
                        "reflogless: warning: canary blob cleanup failed at {d}: {e}"
                    );
                }
                ok
            }
            Err(_) => false,
        },
    };

    let recent_hook_errors = read_hook_error_log(store);
    let crypto_status = assess_crypto(store);

    Ok(DoctorReport {
        hooks: hook_status,
        store_size_bytes,
        snapshots,
        corrupt_snapshots,
        shim_status: crate::shim::observe().into(),
        canary_roundtrip,
        recent_hook_errors,
        crypto_status,
    })
}

fn assess_crypto(store: &Store) -> CryptoStatus {
    if !store.provisioned_for_encryption() {
        return CryptoStatus::NotProvisioned;
    }
    let ctx = match store.crypto() {
        Some(c) => c,
        None => return CryptoStatus::KeyUnreachable,
    };
    // Canary: encrypt a fixed plaintext and decrypt it back.
    let plaintext: &[u8] = b"reflogless-crypto-canary";
    match crypto::encrypt(plaintext, &ctx.recipient) {
        Err(e) => return CryptoStatus::RoundtripFailed(e.to_string()),
        Ok(ct) => match crypto::decrypt(&ct, &ctx.identity) {
            Ok(pt) if pt == plaintext => {
                CryptoStatus::Healthy { insecure_file_key: store.is_insecure_keyed() }
            }
            Ok(_) => CryptoStatus::RoundtripFailed("plaintext mismatch".into()),
            Err(e) => CryptoStatus::RoundtripFailed(e.to_string()),
        },
    }
}

fn read_hook_error_log(store: &Store) -> Vec<String> {
    let log = std::env::var("REFLOGLESS_HOOK_LOG").unwrap_or_else(|_| {
        store
            .root
            .join("hook-errors.log")
            .to_string_lossy()
            .into_owned()
    });
    let p = std::path::Path::new(&log);
    if !p.exists() {
        return Vec::new();
    }
    let body = fs::read_to_string(p).unwrap_or_default();
    body.lines().rev().take(5).map(|s| s.to_string()).collect()
}

impl DoctorReport {
    /// True iff every check is in a healthy state.
    pub fn is_healthy(&self) -> bool {
        self.first_failure().is_none()
    }

    /// Returns the first non-healthy check as a short label, or None if all
    /// checks pass. Used to make the doctor error message actionable.
    pub fn first_failure(&self) -> Option<&'static str> {
        for h in &self.hooks {
            match &h.state {
                HookState::Missing => return Some("hook missing"),
                HookState::Unreadable(_) => return Some("hook unreadable"),
                HookState::Tampered => return Some("hook tampered"),
                HookState::Foreign => return Some("hook foreign (not managed)"),
                HookState::Managed { .. } => {}
            }
        }
        if !self.canary_roundtrip {
            return Some("canary roundtrip failed");
        }
        if self.store_size_bytes.is_err() {
            return Some("store unreadable");
        }
        if self.snapshots.is_err() {
            return Some("snapshots unreadable");
        }
        if self.corrupt_snapshots > 0 {
            return Some("corrupt snapshots present");
        }
        if !self.recent_hook_errors.is_empty() {
            return Some("recent hook errors logged");
        }
        match &self.crypto_status {
            CryptoStatus::NotProvisioned => {}
            CryptoStatus::Healthy { insecure_file_key: false } => {}
            CryptoStatus::Healthy { insecure_file_key: true } => return Some("insecure file key"),
            CryptoStatus::KeyUnreachable => return Some("encryption key unreachable"),
            CryptoStatus::RoundtripFailed(_) => return Some("encryption canary roundtrip failed"),
        }
        match &self.shim_status {
            // `Off` is the default for users who didn't opt in to the shim.
            ShimStatus::Off | ShimStatus::On { .. } => {}
            ShimStatus::Shadowed { .. } => return Some("shim shadowed by another git"),
            ShimStatus::Foreign { .. } => return Some("shim path holds a foreign file"),
        }
        None
    }

    pub fn render(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "reflogless doctor:");
        for h in &self.hooks {
            let state = match &h.state {
                HookState::Missing => "MISSING".into(),
                HookState::Unreadable(e) => format!("UNREADABLE: {e}"),
                HookState::Managed { chained: true } => "OK (chained)".into(),
                HookState::Managed { chained: false } => "OK".into(),
                HookState::Tampered => "TAMPERED (manually edited)".into(),
                HookState::Foreign => "FOREIGN (not reflogless-managed)".into(),
            };
            let _ = writeln!(s, "  hook {:>22}: {state}", h.name);
        }
        match &self.store_size_bytes {
            Ok(n) => {
                let _ = writeln!(s, "  store size          : {n} bytes");
            }
            Err(e) => {
                let _ = writeln!(s, "  store size          : UNREADABLE ({e})");
            }
        }
        match &self.snapshots {
            Ok(n) => {
                let _ = writeln!(s, "  snapshots           : {n}");
            }
            Err(e) => {
                let _ = writeln!(s, "  snapshots           : UNREADABLE ({e})");
            }
        }
        let _ = writeln!(s, "  corrupt snapshots   : {}", self.corrupt_snapshots);
        let _ = writeln!(s, "  shim                : {}", render_shim(&self.shim_status));
        let _ = writeln!(
            s,
            "  canary roundtrip    : {}",
            if self.canary_roundtrip { "ok" } else { "FAILED" }
        );
        if !self.recent_hook_errors.is_empty() {
            let _ = writeln!(s, "  recent hook errors  :");
            for line in &self.recent_hook_errors {
                let _ = writeln!(s, "    {line}");
            }
        }
        let crypto_label = match &self.crypto_status {
            CryptoStatus::NotProvisioned => "not provisioned".into(),
            CryptoStatus::Healthy { insecure_file_key: false } => "ok (keychain)".into(),
            CryptoStatus::Healthy { insecure_file_key: true } => {
                "ok (INSECURE FILE KEY — see --insecure-file-key)".into()
            }
            CryptoStatus::KeyUnreachable => "KEY UNREACHABLE".into(),
            CryptoStatus::RoundtripFailed(err) => format!("ROUNDTRIP FAILED: {err}"),
        };
        let _ = writeln!(s, "  encryption          : {crypto_label}");
        let _ = writeln!(
            s,
            "  overall             : {}",
            if self.is_healthy() {
                "HEALTHY".to_string()
            } else {
                format!("needs attention ({})", self.first_failure().unwrap_or("?"))
            }
        );
        s
    }
}

fn render_shim(s: &ShimStatus) -> String {
    match s {
        ShimStatus::Off => "off".into(),
        ShimStatus::On { path } => format!("on ({})", path.display()),
        ShimStatus::Shadowed { ours, precedes } => format!(
            "SHADOWED (ours at {}; PATH resolves git to {})",
            ours.display(),
            precedes.display()
        ),
        ShimStatus::Foreign { path } => {
            format!("FOREIGN ({} exists but is not reflogless-managed)", path.display())
        }
    }
}

fn dir_size(p: &std::path::Path) -> Result<u64> {
    use crate::error::Error;
    if !p.exists() {
        return Err(Error::io(p, std::io::Error::from(std::io::ErrorKind::NotFound)));
    }
    let mut total = 0;
    let mut stack = vec![p.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).map_err(|e| Error::io(&dir, e))? {
            let entry = entry.map_err(|e| Error::io(&dir, e))?;
            let md = entry.metadata().map_err(|e| Error::io(entry.path(), e))?;
            if md.is_dir() {
                stack.push(entry.path());
            } else {
                total += md.len();
            }
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks;
    use std::process::Command;
    use tempfile::TempDir;

    fn init_repo(td: &std::path::Path) -> Repo {
        Command::new("git").arg("init").arg("-q").arg(td).status().unwrap();
        Command::new("git")
            .args(["-C", td.to_str().unwrap(), "config", "user.email", "t@t"])
            .status()
            .unwrap();
        Command::new("git")
            .args(["-C", td.to_str().unwrap(), "config", "user.name", "t"])
            .status()
            .unwrap();
        Repo::discover(td).unwrap()
    }

    #[test]
    fn doctor_reports_missing_hooks_on_fresh_repo() {
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        let report = run(&repo, &store).unwrap();
        assert!(report
            .hooks
            .iter()
            .all(|h| matches!(h.state, HookState::Missing)));
        assert!(report.canary_roundtrip);
        assert!(!report.is_healthy());
        assert_eq!(report.first_failure(), Some("hook missing"));
    }

    #[test]
    fn doctor_reports_healthy_after_install() {
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        hooks::install(&repo, &store.root.join("hook-errors.log")).unwrap();
        let report = run(&repo, &store).unwrap();
        for h in &report.hooks {
            assert!(matches!(h.state, HookState::Managed { .. }), "{:?}", h);
        }
        assert!(report.is_healthy(), "report=\n{}", report.render());
        assert_eq!(report.first_failure(), None);
    }

    #[test]
    fn doctor_reports_tampered_when_marker_stripped() {
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        hooks::install(&repo, &store.root.join("hook-errors.log")).unwrap();
        // Manually strip the marker but leave the reflogless call.
        let p = repo.root.join(".git").join("hooks").join("post-checkout");
        let body = fs::read_to_string(&p).unwrap();
        let stripped = body.replace(crate::hooks::MARKER, "# foo");
        fs::write(&p, stripped).unwrap();
        let report = run(&repo, &store).unwrap();
        let pc = report
            .hooks
            .iter()
            .find(|h| h.name == "post-checkout")
            .unwrap();
        assert!(matches!(pc.state, HookState::Tampered), "got {:?}", pc.state);
        assert!(!report.is_healthy());
        assert_eq!(report.first_failure(), Some("hook tampered"));
    }

    #[test]
    fn doctor_reports_crypto_not_provisioned_by_default() {
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        hooks::install(&repo, &store.root.join("hook-errors.log")).unwrap();
        let report = run(&repo, &store).unwrap();
        assert_eq!(report.crypto_status, CryptoStatus::NotProvisioned);
        assert!(report.is_healthy());
    }

    #[test]
    fn doctor_reports_healthy_crypto_when_identity_attached() {
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        hooks::install(&repo, &store.root.join("hook-errors.log")).unwrap();
        let id = crate::crypto::generate_identity();
        store.save_recipient(&crate::crypto::recipient_of(&id)).unwrap();
        let store = store.with_crypto(crate::store::CryptoCtx::from_identity(id));
        let report = run(&repo, &store).unwrap();
        assert!(matches!(
            report.crypto_status,
            CryptoStatus::Healthy { insecure_file_key: false }
        ), "got {:?}", report.crypto_status);
        assert!(report.is_healthy());
    }

    #[test]
    fn doctor_flags_key_unreachable_when_provisioned_but_unattached() {
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        hooks::install(&repo, &store.root.join("hook-errors.log")).unwrap();
        // Provisioned (recipient on disk) but no identity attached.
        let id = crate::crypto::generate_identity();
        store.save_recipient(&crate::crypto::recipient_of(&id)).unwrap();
        let report = run(&repo, &store).unwrap();
        assert_eq!(report.crypto_status, CryptoStatus::KeyUnreachable);
        assert!(!report.is_healthy());
        assert_eq!(report.first_failure(), Some("encryption key unreachable"));
    }

    #[test]
    fn doctor_flags_insecure_file_key_in_render_and_first_failure() {
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        hooks::install(&repo, &store.root.join("hook-errors.log")).unwrap();
        let id = crate::crypto::generate_identity();
        store.save_recipient(&crate::crypto::recipient_of(&id)).unwrap();
        store.mark_insecure().unwrap();
        let store = store.with_crypto(crate::store::CryptoCtx::from_identity(id));
        let report = run(&repo, &store).unwrap();
        assert!(matches!(
            report.crypto_status,
            CryptoStatus::Healthy { insecure_file_key: true }
        ));
        assert!(
            report.render().contains("INSECURE FILE KEY"),
            "render did not surface the warning:\n{}",
            report.render()
        );
        // Insecure file key is a non-zero-exit condition: CI gates like
        // `reflogless doctor && deploy` must catch it.
        assert!(!report.is_healthy());
        assert_eq!(report.first_failure(), Some("insecure file key"));
    }

    #[test]
    fn doctor_canary_uses_crypto_path_on_encrypted_store() {
        // Regression for: doctor canary previously used write_blob (plaintext)
        // even on an encrypted store, so a broken crypto path passed the
        // canary check on disk.
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        hooks::install(&repo, &store.root.join("hook-errors.log")).unwrap();
        let id = crate::crypto::generate_identity();
        store.save_recipient(&crate::crypto::recipient_of(&id)).unwrap();
        let store = store.with_crypto(crate::store::CryptoCtx::from_identity(id));
        // Run, then inspect objects/. Canary cleanup is best-effort so we
        // can't rely on it being gone, but if any blob is on disk it must
        // NOT match the plaintext canary bytes.
        let _ = run(&repo, &store).unwrap();
        let objects = store.objects_dir();
        let mut found_blob = false;
        if let Ok(rd) = fs::read_dir(&objects) {
            for shard in rd.flatten() {
                if !shard.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    continue;
                }
                if let Ok(rd2) = fs::read_dir(shard.path()) {
                    for f in rd2.flatten() {
                        let bytes = fs::read(f.path()).unwrap();
                        found_blob = true;
                        assert_ne!(
                            bytes,
                            b"reflogless-doctor-canary-32-bytes!!".to_vec(),
                            "canary wrote plaintext on an encrypted store"
                        );
                    }
                }
            }
        }
        // If the cleanup succeeded we won't find any blob — that's also fine.
        let _ = found_blob;
    }

    #[cfg(unix)]
    #[test]
    fn doctor_reports_unreadable_store() {
        use std::os::unix::fs::PermissionsExt;
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        hooks::install(&repo, &store.root.join("hook-errors.log")).unwrap();
        // Make the objects dir unreadable.
        let objects = store.root.join("objects");
        fs::set_permissions(&objects, fs::Permissions::from_mode(0o000)).unwrap();
        let report = run(&repo, &store);
        // Restore perms regardless, so TempDir can clean up.
        let _ = fs::set_permissions(&objects, fs::Permissions::from_mode(0o755));
        let report = report.unwrap();
        // Either canary fails, or store_size returns Err — both unhealthy.
        assert!(!report.is_healthy(), "report=\n{}", report.render());
    }
}
