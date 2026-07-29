use crate::crypto;
use crate::error::Result;
use crate::hooks::{
    body_chains_to, body_is_current_version, extract_hook_binary, read_entry, resolve_hooks_target,
    Entry, HooksTarget, HOOKS, INVOKE_PROBE, MARKER,
};
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
    pub recent_shim_errors: Vec<String>,
    pub recent_gate_skips: Vec<String>,
    pub watcher: crate::watch::WatcherLiveness,
    pub crypto_status: CryptoStatus,
    pub remote: RemoteStatus,
    /// `core.hooksPath` pointed outside the repo, so hooks live in the repo's own
    /// hooks dir instead. Git invokes only the configured path, so these run only
    /// if that dispatcher chains to the repo's hook.
    pub declined_hooks_path: Option<std::path::PathBuf>,
    /// Hooks git provably cannot invoke: `core.hooksPath` was declined and that
    /// directory has no entry to forward from. A failure, not a note — the same
    /// call reflogless makes for a shadowed shim.
    pub shadowed_hooks: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RemoteStatus {
    /// No `<store>/remote.toml` — backend is disabled.
    Disabled,
    /// Remote configured + log readable. Health derived from oldest pending
    /// age vs thresholds. `oldest_age_days = None` means backlog is empty.
    Enabled {
        s3_url: String,
        backlog: usize,
        oldest_age_days: Option<i64>,
        health: RemoteHealth,
    },
    /// Remote configured but the pending log or remote.toml couldn't be read.
    Unreadable(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum RemoteHealth {
    Ok,
    Warn,
    Unhealthy,
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
    Managed {
        chained: bool,
        /// Set when the hook is ours but will not deliver protection as installed.
        /// Not cosmetic — see `HookStale`.
        stale: Option<HookStale>,
    },
    Tampered,
    Foreign,
}

/// Why a managed hook won't do its job until `reflogless init` is re-run.
#[derive(Debug, PartialEq, Eq)]
pub enum HookStale {
    /// Body predates the current `build_hook_body` format. A v2 body invokes bare
    /// `reflogless`, so it silently skips the snapshot under a PATH that lacks the
    /// install dir (#74).
    Version,
    /// The absolute binary the body bakes in is no longer executable — reinstall
    /// to a new prefix, a moved or upgraded binary. The hook falls back to a PATH
    /// lookup, which is the pre-#74 behavior.
    Binary(std::path::PathBuf),
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
    /// A file at the shim path exists but can't be read (permissions,
    /// I/O error, dangling symlink). Distinct from `Foreign`.
    Unreadable {
        path: std::path::PathBuf,
        error: String,
    },
    /// Shim is reflogless-managed but its baked-in reflogless binary
    /// path is stale. Fix with `reflogless init --shim`.
    Stale {
        path: std::path::PathBuf,
        script_points_at: std::path::PathBuf,
        current_binary_at: Option<std::path::PathBuf>,
    },
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
            crate::shim::ShimStatus::Unreadable { path, error } => {
                ShimStatus::Unreadable { path, error }
            }
            crate::shim::ShimStatus::Stale {
                path,
                script_points_at,
                current_binary_at,
            } => ShimStatus::Stale {
                path,
                script_points_at,
                current_binary_at,
            },
        }
    }
}

/// Why a managed hook body won't deliver protection as installed, if it won't.
///
/// Mirrors what `shim.rs` already does for the PATH shim (`ShimStatus::Stale`):
/// that code bakes a reflogless path into a generated script, then reads it back
/// and compares against the current binary so a relocated install is reported
/// rather than silently degrading. Hooks bake the same kind of path and had none
/// of that detection, so an install that had stopped protecting the repo still
/// read as four `OK` lines and `overall: HEALTHY`.
///
/// Version is checked before the binary: an old body may not bake a path at all,
/// and "re-run init" is the same remedy either way.
fn hook_staleness(body: &str) -> Option<HookStale> {
    if !body_is_current_version(body) {
        return Some(HookStale::Version);
    }
    match extract_hook_binary(body) {
        // Deliberately an executability test rather than a comparison against
        // `current_exe()`: a hook pointing at a *different but working* reflogless
        // is a supported setup (a pinned build, a wrapper), and `doctor` may be
        // running from a different binary than the hooks were installed with.
        Some(p) if !is_executable_file(&p) => Some(HookStale::Binary(p)),
        _ => None,
    }
}

#[cfg(unix)]
fn is_executable_file(p: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable_file(p: &std::path::Path) -> bool {
    p.is_file()
}

pub fn run(repo: &Repo, store: &Store) -> Result<DoctorReport> {
    // Inspect the directory `install` writes to, not whatever `core.hooksPath`
    // names — with a global `core.hooksPath` those differ, and reading the shared
    // dispatcher classifies a healthy install as Foreign (#76). Resolving through
    // the same function as `install` is what keeps the two from disagreeing.
    let HooksTarget { dir, declined } = resolve_hooks_target(repo)?;
    let mut hook_status = Vec::new();
    for h in HOOKS {
        let p = dir.join(h);
        let backup = p.with_extension("reflogless-orig");
        // Classified through the same `read_entry` as `install`, so the two cannot
        // disagree about a given entry.
        let state = match read_entry(&p) {
            Entry::Missing => HookState::Missing,
            // Ownership unknown, and saying `FOREIGN` here would assert something
            // false about a file that may well be ours.
            Entry::Unreadable(e) => HookState::Unreadable(e),
            Entry::Symlink { .. } => HookState::Foreign,
            Entry::Body(body) => {
                if body.contains(MARKER) {
                    HookState::Managed {
                        // From the body, not `backup.exists()` — see
                        // `hooks::body_chains_to`.
                        chained: body_chains_to(&body, &backup),
                        stale: hook_staleness(&body),
                    }
                } else if body.contains(INVOKE_PROBE) {
                    // A user hand-edited the reflogless wrapper and stripped
                    // the marker, but the reflogless call is still present —
                    // distinct from a legitimate third-party hook.
                    HookState::Tampered
                } else {
                    HookState::Foreign
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
                    eprintln!("reflogless: warning: canary blob cleanup failed at {d}: {e}");
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
                    eprintln!("reflogless: warning: canary blob cleanup failed at {d}: {e}");
                }
                ok
            }
            Err(_) => false,
        },
    };

    let recent_hook_errors = read_hook_error_log(store);
    let recent_shim_errors = read_shim_error_log(store);
    let recent_gate_skips = read_gate_skip_log(store);
    let watcher = crate::watch::liveness(store);
    let crypto_status = assess_crypto(store);

    let thresholds = crate::config::Config::load_or_default(&repo.root)
        .map(|c| c.remote)
        .unwrap_or_default();
    let remote = assess_remote(store, thresholds);

    Ok(DoctorReport {
        hooks: hook_status,
        store_size_bytes,
        snapshots,
        corrupt_snapshots,
        shim_status: crate::shim::observe().into(),
        canary_roundtrip,
        recent_hook_errors,
        recent_shim_errors,
        recent_gate_skips,
        watcher,
        crypto_status,
        remote,
        shadowed_hooks: declined
            .as_deref()
            .map(crate::hooks::shadowed_hooks)
            .unwrap_or_default(),
        declined_hooks_path: declined,
    })
}

fn assess_remote(store: &Store, thresholds: crate::config::RemoteThresholds) -> RemoteStatus {
    let cfg = match crate::remote_config::RemoteConfig::load(store) {
        Ok(Some(c)) => c,
        Ok(None) => return RemoteStatus::Disabled,
        Err(e) => return RemoteStatus::Unreadable(format!("remote.toml: {e}")),
    };
    let pending = match crate::remote::read_pending(store) {
        Ok(p) => p,
        Err(e) => return RemoteStatus::Unreadable(format!("remote-pending.jsonl: {e}")),
    };
    let now = chrono::Utc::now();
    let oldest = pending.iter().map(|e| e.created_at).min();
    let oldest_age_days = oldest.map(|t| now.signed_duration_since(t).num_days().max(0));
    let health = match oldest_age_days {
        None => RemoteHealth::Ok,
        Some(d) if d >= thresholds.unhealthy_days => RemoteHealth::Unhealthy,
        Some(d) if d >= thresholds.warn_days => RemoteHealth::Warn,
        Some(_) => RemoteHealth::Ok,
    };
    RemoteStatus::Enabled {
        s3_url: cfg.s3_url(),
        backlog: pending.len(),
        oldest_age_days,
        health,
    }
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
        Err(e) => CryptoStatus::RoundtripFailed(e.to_string()),
        Ok(ct) => match crypto::decrypt(&ct, &ctx.identity) {
            Ok(pt) if pt == plaintext => CryptoStatus::Healthy {
                insecure_file_key: store.is_insecure_keyed(),
            },
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
    read_recent_lines(std::path::Path::new(&log))
}

fn read_shim_error_log(store: &Store) -> Vec<String> {
    read_recent_lines(&store.root.join("shim-errors.log"))
}

fn read_gate_skip_log(store: &Store) -> Vec<String> {
    let path = store.root.join("events").join("skipped_git_busy.jsonl");
    if !path.exists() {
        return Vec::new();
    }
    let body = fs::read_to_string(&path).unwrap_or_default();
    body.lines()
        .rev()
        .take(5)
        .map(format_gate_skip_line)
        .collect()
}

/// Best-effort render of a JSONL gate-skip line. Pulls ts + event + reason
/// without a json dep — tolerant of malformed lines (returns the raw line).
fn format_gate_skip_line(line: &str) -> String {
    let extract = |key: &str| -> Option<String> {
        let needle = format!("\"{}\":\"", key);
        let start = line.find(&needle)? + needle.len();
        let rest = &line[start..];
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    };
    match (extract("ts"), extract("event"), extract("reason")) {
        (Some(ts), Some(event), Some(reason)) => format!("{ts}  {event:<16}  {reason}"),
        _ => line.to_string(),
    }
}

fn read_recent_lines(p: &std::path::Path) -> Vec<String> {
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
                // A stale hook is installed but not protecting: a pre-#74 body
                // resolves the binary off PATH, and a dead baked path falls back
                // to that same PATH lookup. Nothing rewrites hooks on its own, so
                // reporting this as a note would leave the user holding an
                // unprotected repo and a green doctor.
                HookState::Managed {
                    stale: Some(HookStale::Version),
                    ..
                } => return Some("hooks predate this reflogless version (run `reflogless init`)"),
                HookState::Managed {
                    stale: Some(HookStale::Binary(_)),
                    ..
                } => {
                    return Some(
                        "hook points at a reflogless binary that is gone (run `reflogless init`)",
                    )
                }
                HookState::Managed { stale: None, .. } => {}
            }
        }
        // A hook git will never call is as broken as a shadowed shim, which this
        // same function already fails on. Reporting it as a note let `doctor`
        // exit 0 on a repo with no protection at all.
        if !self.shadowed_hooks.is_empty() {
            return Some("hooks shadowed by core.hooksPath (git will not invoke them)");
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
        if !self.recent_shim_errors.is_empty() {
            return Some("recent shim errors logged");
        }
        match &self.watcher {
            // pid reuse across reboot — state file claims a running daemon
            // but it's actually gone. This is the whole reason boot_id
            // liveness exists; failing the doctor check is the point.
            crate::watch::WatcherLiveness::Stale { .. } => {
                return Some("watcher stale (pid reused after reboot)");
            }
            crate::watch::WatcherLiveness::StateUnreadable => {
                return Some("watcher state file unreadable");
            }
            crate::watch::WatcherLiveness::NeverInstalled
            | crate::watch::WatcherLiveness::Running { .. }
            | crate::watch::WatcherLiveness::Stopped { .. } => {}
        }
        match &self.crypto_status {
            CryptoStatus::NotProvisioned => {}
            CryptoStatus::Healthy {
                insecure_file_key: false,
            } => {}
            CryptoStatus::Healthy {
                insecure_file_key: true,
            } => return Some("insecure file key"),
            CryptoStatus::KeyUnreachable => return Some("encryption key unreachable"),
            CryptoStatus::RoundtripFailed(_) => return Some("encryption canary roundtrip failed"),
        }
        match &self.shim_status {
            // `Off` is the default for users who didn't opt in to the shim.
            ShimStatus::Off | ShimStatus::On { .. } => {}
            ShimStatus::Shadowed { .. } => return Some("shim shadowed by another git"),
            ShimStatus::Foreign { .. } => return Some("shim path holds a foreign file"),
            ShimStatus::Unreadable { .. } => return Some("shim file is unreadable"),
            ShimStatus::Stale { .. } => return Some("shim points at stale reflogless binary"),
        }
        match &self.remote {
            RemoteStatus::Disabled => {}
            RemoteStatus::Enabled {
                health: RemoteHealth::Unhealthy,
                ..
            } => return Some("remote backlog past unhealthy threshold"),
            RemoteStatus::Enabled { .. } => {}
            RemoteStatus::Unreadable(_) => return Some("remote state unreadable"),
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
                HookState::Managed {
                    stale: Some(HookStale::Version),
                    ..
                } => "STALE (older hook format — run `reflogless init`)".into(),
                HookState::Managed {
                    stale: Some(HookStale::Binary(p)),
                    ..
                } => format!("STALE (baked binary missing: {})", p.display()),
                HookState::Managed {
                    chained: true,
                    stale: None,
                } => "OK (chained)".into(),
                HookState::Managed {
                    chained: false,
                    stale: None,
                } => "OK".into(),
                HookState::Tampered => "TAMPERED (manually edited)".into(),
                HookState::Foreign => "FOREIGN (not reflogless-managed)".into(),
            };
            let _ = writeln!(s, "  hook {:>22}: {state}", h.name);
        }
        if let Some(p) = &self.declined_hooks_path {
            if self.shadowed_hooks.is_empty() {
                let _ = writeln!(s, "  core.hooksPath      : {} (outside repo)", p.display());
                let _ = writeln!(
                    s,
                    "                        hooks installed in the repo's own dir; they run \
                     only if that dispatcher chains to them"
                );
            } else {
                let _ = writeln!(
                    s,
                    "  core.hooksPath      : SHADOWED by {} (outside repo)",
                    p.display()
                );
                let _ = writeln!(
                    s,
                    "                        git looks only there, and it has no entry for: {}",
                    self.shadowed_hooks.join(", ")
                );
                let _ = writeln!(
                    s,
                    "                        those hooks will never run — reflogless is not \
                     protecting this repo"
                );
            }
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
        let _ = writeln!(
            s,
            "  shim                : {}",
            render_shim(&self.shim_status)
        );
        let _ = writeln!(
            s,
            "  canary roundtrip    : {}",
            if self.canary_roundtrip {
                "ok"
            } else {
                "FAILED"
            }
        );
        if !self.recent_hook_errors.is_empty() {
            let _ = writeln!(s, "  recent hook errors  :");
            for line in &self.recent_hook_errors {
                let _ = writeln!(s, "    {line}");
            }
        }
        if !self.recent_shim_errors.is_empty() {
            let _ = writeln!(s, "  recent shim errors  :");
            for line in &self.recent_shim_errors {
                let _ = writeln!(s, "    {line}");
            }
        }
        if !self.recent_gate_skips.is_empty() {
            let _ = writeln!(s, "  recent gate skips   :");
            for line in &self.recent_gate_skips {
                let _ = writeln!(s, "    {line}");
            }
        }
        let watcher_label = match &self.watcher {
            crate::watch::WatcherLiveness::NeverInstalled => "never installed".to_string(),
            crate::watch::WatcherLiveness::StateUnreadable => "STATE UNREADABLE".to_string(),
            crate::watch::WatcherLiveness::Running { pid } => format!("running (pid {pid})"),
            crate::watch::WatcherLiveness::Stale { pid } => {
                format!("STALE (pid {pid} from earlier boot; daemon not restarted)")
            }
            crate::watch::WatcherLiveness::Stopped { pid } => {
                format!("stopped (last pid {pid} no longer alive)")
            }
        };
        let _ = writeln!(s, "  watcher             : {watcher_label}");
        let crypto_label = match &self.crypto_status {
            CryptoStatus::NotProvisioned => "not provisioned".into(),
            CryptoStatus::Healthy {
                insecure_file_key: false,
            } => "ok (keychain)".into(),
            CryptoStatus::Healthy {
                insecure_file_key: true,
            } => "ok (INSECURE FILE KEY — see --insecure-file-key)".into(),
            CryptoStatus::KeyUnreachable => "KEY UNREACHABLE".into(),
            CryptoStatus::RoundtripFailed(err) => format!("ROUNDTRIP FAILED: {err}"),
        };
        let _ = writeln!(s, "  encryption          : {crypto_label}");
        match &self.remote {
            RemoteStatus::Disabled => {
                let _ = writeln!(s, "  remote              : disabled");
            }
            RemoteStatus::Enabled {
                s3_url,
                backlog,
                oldest_age_days,
                health,
            } => {
                let _ = writeln!(s, "  remote              : enabled ({s3_url})");
                let oldest_label = match oldest_age_days {
                    None => "no backlog".to_string(),
                    Some(0) => "oldest <1d".to_string(),
                    Some(d) => format!("oldest {d}d"),
                };
                let health_label = match health {
                    RemoteHealth::Ok => "ok",
                    RemoteHealth::Warn => "WARN",
                    RemoteHealth::Unhealthy => "UNHEALTHY",
                };
                let _ = writeln!(
                    s,
                    "  remote.backlog      : {backlog} pending uploads, {oldest_label} ({health_label})"
                );
            }
            RemoteStatus::Unreadable(err) => {
                let _ = writeln!(s, "  remote              : UNREADABLE ({err})");
            }
        }
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
            format!(
                "FOREIGN ({} exists but is not reflogless-managed)",
                path.display()
            )
        }
        ShimStatus::Unreadable { path, error } => {
            format!("UNREADABLE ({}: {error})", path.display())
        }
        ShimStatus::Stale {
            path,
            script_points_at,
            current_binary_at,
        } => {
            let current = match current_binary_at {
                Some(p) => p.display().to_string(),
                None => "<current_exe unavailable>".into(),
            };
            format!(
                "STALE ({} points at {} but reflogless is at {}; run `reflogless init --shim` to refresh)",
                path.display(),
                script_points_at.display(),
                current,
            )
        }
    }
}

fn dir_size(p: &std::path::Path) -> Result<u64> {
    use crate::error::Error;
    if !p.exists() {
        return Err(Error::io(
            p,
            std::io::Error::from(std::io::ErrorKind::NotFound),
        ));
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

    use crate::testutil::init_repo;

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

    #[cfg(unix)]
    #[test]
    fn doctor_surfaces_hook_snapshot_config_failure() {
        use std::os::unix::fs::PermissionsExt;

        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        // Install-time hook_log_path lives in a separate tempdir from the
        // runtime store root. If the hook ever falls back to the baked
        // install-time path, errors land in `install_only` and doctor (which
        // reads from `data`) sees nothing — pinning the runtime-resolution
        // fix per `~/.claude/rules/test-the-fix-not-the-investigation.md`.
        let install_only = TempDir::new().unwrap();
        let bin = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        hooks::install(&repo, &install_only.path().join("install-time.log")).unwrap();

        let fake = bin.path().join("reflogless");
        fs::write(
            &fake,
            "#!/bin/sh\necho 'reflogless: .reflogless.toml: track entry \"../escape\" must be a repo-relative path without `..`' >&2\nexit 1\n",
        )
        .unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();

        let hook = repo.root.join(".git").join("hooks").join("post-checkout");
        let path = format!(
            "{}:{}",
            bin.path().display(),
            std::env::var("PATH").unwrap_or_default()
        );
        // `REFLOGLESS_BIN` rather than PATH: since #74 the hook addresses an
        // absolute baked-in binary, so a PATH-injected stub is (correctly) not
        // consulted.
        let status = Command::new(&hook)
            .env("PATH", path)
            .env("REFLOGLESS_BIN", &fake)
            .env("REFLOGLESS_DATA_DIR", data.path())
            .status()
            .unwrap();
        assert!(status.success(), "hook must remain best-effort");

        let runtime_log = store.root.join("hook-errors.log");
        assert!(
            runtime_log.exists(),
            "hook must write to runtime-resolved REFLOGLESS_DATA_DIR path, not install-time fallback"
        );
        assert!(
            !install_only.path().join("install-time.log").exists(),
            "hook must NOT write to install-time path when REFLOGLESS_DATA_DIR is set"
        );

        let report = run(&repo, &store).unwrap();
        assert_eq!(report.first_failure(), Some("recent hook errors logged"));
        assert!(
            report
                .recent_hook_errors
                .iter()
                .any(|line| line.contains("track entry") && line.contains("repo-relative")),
            "report={report:#?}"
        );
        assert!(report.render().contains("recent hook errors"));
    }

    #[test]
    fn doctor_reports_remote_disabled_by_default() {
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        let report = run(&repo, &store).unwrap();
        assert_eq!(report.remote, RemoteStatus::Disabled);
        assert!(report.render().contains("remote              : disabled"));
    }

    #[test]
    fn doctor_reports_remote_enabled_empty_backlog_is_healthy() {
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        let rc = crate::remote_config::RemoteConfig {
            bucket: "mb".to_string(),
            region: "us-east-1".to_string(),
            endpoint: None,
            path_style: false,
            key_prefix: "host/".to_string(),
        };
        rc.save(&store).unwrap();
        let report = run(&repo, &store).unwrap();
        match &report.remote {
            RemoteStatus::Enabled {
                backlog: 0,
                oldest_age_days: None,
                health: RemoteHealth::Ok,
                ..
            } => {}
            other => panic!("expected enabled+empty+ok, got {other:?}"),
        }
        assert!(report.render().contains("remote              : enabled"));
        assert!(report
            .render()
            .contains("0 pending uploads, no backlog (ok)"));
    }

    #[test]
    fn doctor_flags_remote_backlog_past_unhealthy_threshold() {
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        hooks::install(&repo, &store.root.join("hook-errors.log")).unwrap();
        let rc = crate::remote_config::RemoteConfig {
            bucket: "mb".to_string(),
            region: "us-east-1".to_string(),
            endpoint: None,
            path_style: false,
            key_prefix: "host/".to_string(),
        };
        rc.save(&store).unwrap();
        // Seed a pending entry whose created_at is 100 days ago — past the
        // 60-day unhealthy default. We bypass append_pending so we can pin
        // the timestamp; this still exercises the on-disk JSONL parser.
        let stale = crate::remote::PendingEntry {
            manifest_id: "stale".to_string(),
            blob_digests: vec!["sha:x".to_string()],
            created_at: chrono::Utc::now() - chrono::Duration::days(100),
        };
        let path = store.remote_pending_path();
        fs::write(
            &path,
            format!("{}\n", serde_json::to_string(&stale).unwrap()),
        )
        .unwrap();

        let report = run(&repo, &store).unwrap();
        match &report.remote {
            RemoteStatus::Enabled {
                backlog: 1,
                oldest_age_days: Some(d),
                health: RemoteHealth::Unhealthy,
                ..
            } if *d >= 60 => {}
            other => panic!("expected enabled+unhealthy, got {other:?}"),
        }
        assert_eq!(
            report.first_failure(),
            Some("remote backlog past unhealthy threshold")
        );
        assert!(report.render().contains("UNHEALTHY"));
    }

    #[test]
    fn doctor_warns_remote_backlog_past_warn_threshold_but_stays_healthy_overall() {
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        hooks::install(&repo, &store.root.join("hook-errors.log")).unwrap();
        let rc = crate::remote_config::RemoteConfig {
            bucket: "mb".to_string(),
            region: "us-east-1".to_string(),
            endpoint: None,
            path_style: false,
            key_prefix: "host/".to_string(),
        };
        rc.save(&store).unwrap();
        let warn = crate::remote::PendingEntry {
            manifest_id: "warn".to_string(),
            blob_digests: vec!["sha:y".to_string()],
            created_at: chrono::Utc::now() - chrono::Duration::days(20),
        };
        let path = store.remote_pending_path();
        fs::write(
            &path,
            format!("{}\n", serde_json::to_string(&warn).unwrap()),
        )
        .unwrap();

        let report = run(&repo, &store).unwrap();
        match &report.remote {
            RemoteStatus::Enabled {
                health: RemoteHealth::Warn,
                ..
            } => {}
            other => panic!("expected enabled+warn, got {other:?}"),
        }
        // Warn is informational; overall stays healthy modulo other checks.
        assert_ne!(
            report.first_failure(),
            Some("remote backlog past unhealthy threshold")
        );
        assert!(report.render().contains("WARN"));
    }

    /// A v2 hook resolves the binary off PATH, so it silently skips the snapshot
    /// from a GUI editor or launchd — the #74 bug. Nothing rewrites hooks on its
    /// own, so `doctor` failing is the only way the user learns to run `init`.
    /// Before this, a v2 body reported four `OK` lines and `overall: HEALTHY`.
    #[test]
    fn doctor_fails_on_a_hook_body_from_an_older_reflogless() {
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        hooks::install(&repo, &store.root.join("hook-errors.log")).unwrap();
        let p = repo.root.join(".git").join("hooks").join("post-checkout");
        let body = fs::read_to_string(&p).unwrap();
        // Roll the version line back one, leaving the marker intact — exactly what
        // an install predating this release looks like.
        fs::write(
            &p,
            body.replace(crate::hooks::MARKER_VERSION, "# reflogless-hook-version: 2"),
        )
        .unwrap();

        let report = run(&repo, &store).unwrap();
        let pc = report
            .hooks
            .iter()
            .find(|h| h.name == "post-checkout")
            .unwrap();
        assert_eq!(
            pc.state,
            HookState::Managed {
                chained: false,
                stale: Some(HookStale::Version)
            },
            "stale body classified as {:?}",
            pc.state
        );
        assert!(!report.is_healthy(), "stale hooks reported healthy");
        assert_eq!(
            report.first_failure(),
            Some("hooks predate this reflogless version (run `reflogless init`)")
        );
        assert!(report.render().contains("STALE"), "{}", report.render());
    }

    /// Upgrade to a new prefix, move the binary, or let a package manager delete
    /// a versioned path, and the baked path dies. The hook then falls back to a
    /// PATH lookup — the pre-#74 behavior — and used to report `OK`.
    #[cfg(unix)]
    #[test]
    fn doctor_fails_when_the_baked_binary_is_gone() {
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        hooks::install(&repo, &store.root.join("hook-errors.log")).unwrap();
        let p = repo.root.join(".git").join("hooks").join("post-checkout");
        let body = fs::read_to_string(&p).unwrap();
        let live = crate::hooks::extract_hook_binary(&body).expect("install bakes a path");
        let dead = td.path().join("removed-by-an-upgrade");
        fs::write(
            &p,
            body.replace(live.to_str().unwrap(), dead.to_str().unwrap()),
        )
        .unwrap();

        let report = run(&repo, &store).unwrap();
        let pc = report
            .hooks
            .iter()
            .find(|h| h.name == "post-checkout")
            .unwrap();
        assert_eq!(
            pc.state,
            HookState::Managed {
                chained: false,
                stale: Some(HookStale::Binary(dead.clone()))
            },
            "dead baked path classified as {:?}",
            pc.state
        );
        assert!(!report.is_healthy());
        assert_eq!(
            report.first_failure(),
            Some("hook points at a reflogless binary that is gone (run `reflogless init`)")
        );
        assert!(
            report.render().contains("removed-by-an-upgrade"),
            "render does not name the dead path: {}",
            report.render()
        );
    }

    /// The complement: a freshly installed hook points at a live binary and must
    /// not be called stale, or the new failure fires on every healthy repo.
    #[test]
    fn doctor_does_not_call_a_fresh_install_stale() {
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        hooks::install(&repo, &store.root.join("hook-errors.log")).unwrap();

        let report = run(&repo, &store).unwrap();
        for h in &report.hooks {
            assert_eq!(
                h.state,
                HookState::Managed {
                    chained: false,
                    stale: None
                },
                "{} reported stale right after install",
                h.name
            );
        }
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
        assert!(
            matches!(pc.state, HookState::Tampered),
            "got {:?}",
            pc.state
        );
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
        store
            .save_recipient(&crate::crypto::recipient_of(&id))
            .unwrap();
        let store = store.with_crypto(crate::store::CryptoCtx::from_identity(id));
        let report = run(&repo, &store).unwrap();
        assert!(
            matches!(
                report.crypto_status,
                CryptoStatus::Healthy {
                    insecure_file_key: false
                }
            ),
            "got {:?}",
            report.crypto_status
        );
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
        store
            .save_recipient(&crate::crypto::recipient_of(&id))
            .unwrap();
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
        store
            .save_recipient(&crate::crypto::recipient_of(&id))
            .unwrap();
        store.mark_insecure().unwrap();
        let store = store.with_crypto(crate::store::CryptoCtx::from_identity(id));
        let report = run(&repo, &store).unwrap();
        assert!(matches!(
            report.crypto_status,
            CryptoStatus::Healthy {
                insecure_file_key: true
            }
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
        store
            .save_recipient(&crate::crypto::recipient_of(&id))
            .unwrap();
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

    #[test]
    fn doctor_surfaces_recent_gate_skips() {
        use crate::snapshot::snap;
        let td = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        Command::new("git")
            .arg("init")
            .arg("-q")
            .arg(td.path())
            .status()
            .unwrap();
        let repo = Repo::discover(td.path()).unwrap();
        let store = Store::for_repo_with_base(&repo, data_dir.path().to_path_buf()).unwrap();
        fs::create_dir_all(repo.root.join(".git").join("rebase-merge")).unwrap();
        let _ = snap(&repo, &store, "post-commit", None).unwrap();
        let _ = snap(&repo, &store, "manual", None).unwrap();
        let report = run(&repo, &store).unwrap();
        assert_eq!(report.recent_gate_skips.len(), 2);
        let rendered = report.render();
        assert!(
            rendered.contains("recent gate skips"),
            "expected gate skips header, got:\n{rendered}"
        );
        assert!(rendered.contains("post-commit"));
        assert!(rendered.contains("interactive rebase in progress"));
    }

    #[test]
    fn doctor_reports_watcher_never_installed_by_default() {
        let td = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        Command::new("git")
            .arg("init")
            .arg("-q")
            .arg(td.path())
            .status()
            .unwrap();
        let repo = Repo::discover(td.path()).unwrap();
        let store = Store::for_repo_with_base(&repo, data_dir.path().to_path_buf()).unwrap();
        let report = run(&repo, &store).unwrap();
        assert_eq!(
            report.watcher,
            crate::watch::WatcherLiveness::NeverInstalled
        );
        let rendered = report.render();
        assert!(rendered.contains("watcher             : never installed"));
    }

    #[test]
    fn doctor_reports_watcher_running_for_self_pid() {
        let td = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        Command::new("git")
            .arg("init")
            .arg("-q")
            .arg(td.path())
            .status()
            .unwrap();
        let repo = Repo::discover(td.path()).unwrap();
        let store = Store::for_repo_with_base(&repo, data_dir.path().to_path_buf()).unwrap();
        // Plant a state file pointing at this process.
        let mut s = crate::watch::WatchState::new();
        s.pid = std::process::id();
        crate::watch::write_state(&store, &s).unwrap();
        let report = run(&repo, &store).unwrap();
        match report.watcher {
            crate::watch::WatcherLiveness::Running { pid } => {
                assert_eq!(pid, std::process::id())
            }
            other => panic!("expected Running, got {other:?}"),
        }
        let rendered = report.render();
        assert!(rendered.contains(&format!(
            "watcher             : running (pid {}",
            std::process::id()
        )));
    }

    #[test]
    fn doctor_reports_stale_watcher_as_unhealthy() {
        let td = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        Command::new("git")
            .arg("init")
            .arg("-q")
            .arg(td.path())
            .status()
            .unwrap();
        let repo = Repo::discover(td.path()).unwrap();
        let store = Store::for_repo_with_base(&repo, data_dir.path().to_path_buf()).unwrap();
        // Synthetic stale state: our pid is alive but boot_id is forged.
        let mut s = crate::watch::WatchState::new();
        s.pid = std::process::id();
        s.boot_id = "synthetic-prior-boot".to_string();
        crate::watch::write_state(&store, &s).unwrap();
        let report = run(&repo, &store).unwrap();
        assert!(
            matches!(report.watcher, crate::watch::WatcherLiveness::Stale { .. }),
            "expected Stale, got {:?}",
            report.watcher
        );
        assert!(
            !report.is_healthy(),
            "Stale watcher must fail doctor — pid reuse after reboot is the whole point of boot_id"
        );
        // The fixture doesn't install hooks so the first failure is "hook
        // missing"; what we're asserting is that Stale is *somewhere* in the
        // unhealthy set — exercise via direct DoctorReport construction.
        let isolated = DoctorReport {
            hooks: vec![],
            store_size_bytes: Ok(0),
            snapshots: Ok(0),
            corrupt_snapshots: 0,
            shim_status: ShimStatus::Off,
            canary_roundtrip: true,
            recent_hook_errors: vec![],
            recent_shim_errors: vec![],
            recent_gate_skips: vec![],
            watcher: crate::watch::WatcherLiveness::Stale {
                pid: std::process::id(),
            },
            crypto_status: CryptoStatus::NotProvisioned,
            remote: RemoteStatus::Disabled,
            declined_hooks_path: None,
            shadowed_hooks: vec![],
        };
        assert_eq!(
            isolated.first_failure(),
            Some("watcher stale (pid reused after reboot)")
        );
    }

    /// Point `core.hooksPath` at `value` for this repo only, under the suite's
    /// isolated git config.
    fn set_hooks_path(repo: &Repo, value: &str) {
        crate::testutil::git_in(&[
            "-C",
            repo.root.to_str().unwrap(),
            "config",
            "--local",
            "core.hooksPath",
            value,
        ]);
    }

    /// #76: with `core.hooksPath` outside the repo, doctor used to inspect that
    /// shared directory and call a perfectly good install FOREIGN on every repo of
    /// the machine. It must inspect what `install` wrote.
    #[test]
    fn doctor_reports_managed_when_hookspath_points_outside_the_repo() {
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        set_hooks_path(&repo, outside.path().to_str().unwrap());
        // The dispatcher forwards, so nothing is shadowed — the healthy shape.
        for h in HOOKS {
            let p = outside.path().join(h);
            fs::write(
                &p,
                "#!/bin/sh\nexec \"$(git rev-parse --git-path hooks)/$0\"\n",
            )
            .unwrap();
        }

        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        crate::hooks::install(&repo, &repo.root.join("hook-errors.log")).unwrap();
        let report = run(&repo, &store).unwrap();

        for h in &report.hooks {
            assert_eq!(
                h.state,
                HookState::Managed {
                    chained: false,
                    stale: None,
                },
                "{} should be Managed, not {:?}",
                h.name,
                h.state
            );
        }
        assert_eq!(report.declined_hooks_path.as_deref(), Some(outside.path()));
        assert!(
            report.shadowed_hooks.is_empty(),
            "dispatcher has an entry for every hook, so none are shadowed"
        );
    }

    /// The other half: when the declined directory has *no* entry for a hook, git
    /// can never reach ours. That is a failure, not a note — reporting healthy here
    /// told the user they were protected when they were not.
    #[test]
    fn doctor_fails_when_hooks_are_shadowed_by_hookspath() {
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        set_hooks_path(&repo, outside.path().to_str().unwrap());

        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        crate::hooks::install(&repo, &repo.root.join("hook-errors.log")).unwrap();
        let report = run(&repo, &store).unwrap();

        assert_eq!(
            report.shadowed_hooks.len(),
            HOOKS.len(),
            "the declined dir is empty, so every hook is unreachable"
        );
        assert_eq!(
            report.first_failure(),
            Some("hooks shadowed by core.hooksPath (git will not invoke them)"),
            "a dead install must not report healthy"
        );
        assert!(!report.is_healthy());
        let rendered = report.render();
        assert!(rendered.contains("SHADOWED"), "render: {rendered}");
        assert!(rendered.contains("will never run"), "render: {rendered}");
    }

    /// Install and doctor must classify one entry the same way. Doctor used to
    /// follow the symlink and call it Managed while install saw a foreign entry and
    /// chained it.
    #[cfg(unix)]
    #[test]
    fn doctor_and_install_agree_on_a_symlinked_entry() {
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        let hooks = repo.git_common_dir().join("hooks");
        fs::create_dir_all(&hooks).unwrap();
        let shared = repo.root.join("dispatcher.sh");
        fs::write(&shared, format!("{MARKER}\n")).unwrap();
        std::os::unix::fs::symlink(&shared, hooks.join("post-checkout")).unwrap();

        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        let report = run(&repo, &store).unwrap();

        let pc = report
            .hooks
            .iter()
            .find(|h| h.name == "post-checkout")
            .unwrap();
        assert_eq!(
            pc.state,
            HookState::Foreign,
            "a symlink is foreign to doctor exactly as it is to install"
        );
    }

    /// `chained` must be read from the wrapper body, not from the backup file's
    /// existence. An orphaned `.reflogless-orig` beside a wrapper that no longer
    /// execs it is exactly the state that reported `OK (chained)` for a
    /// third-party hook that had silently stopped running.
    #[test]
    fn doctor_reports_unchained_when_a_backup_is_orphaned() {
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        crate::hooks::install(&repo, &repo.root.join("hook-errors.log")).unwrap();
        let hooks = repo.git_common_dir().join("hooks");
        // A backup with no corresponding `exec` in the installed wrapper.
        fs::write(
            hooks.join("post-checkout.reflogless-orig"),
            "#!/bin/sh\n# orphaned\n",
        )
        .unwrap();

        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        let report = run(&repo, &store).unwrap();
        let pc = report
            .hooks
            .iter()
            .find(|h| h.name == "post-checkout")
            .unwrap();

        assert_eq!(
            pc.state,
            HookState::Managed {
                chained: false,
                stale: None,
            },
            "a backup that nothing execs is not a chain"
        );
        assert!(report.render().contains("post-checkout: OK\n"));
    }

    /// An unreadable hook is not evidence that someone else owns it. Reporting
    /// FOREIGN there is a wrong answer, not a vague one, and it points the user at
    /// the wrong fix.
    #[cfg(unix)]
    #[test]
    fn doctor_reports_unreadable_hook_distinctly_from_foreign() {
        use std::os::unix::fs::PermissionsExt;
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        crate::hooks::install(&repo, &repo.root.join("hook-errors.log")).unwrap();
        let p = repo.git_common_dir().join("hooks").join("post-checkout");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o000)).unwrap();

        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        let report = run(&repo, &store).unwrap();
        let pc = report
            .hooks
            .iter()
            .find(|h| h.name == "post-checkout")
            .unwrap();

        // Restore before asserting so a failure doesn't leave an unreadable temp file.
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();

        match &pc.state {
            HookState::Unreadable(e) => assert!(!e.is_empty(), "must carry the reason"),
            other => panic!("expected Unreadable, got {other:?}"),
        }
        assert!(report.render().contains("UNREADABLE"));
    }

    #[test]
    fn doctor_omits_gate_skips_when_log_absent() {
        let td = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        Command::new("git")
            .arg("init")
            .arg("-q")
            .arg(td.path())
            .status()
            .unwrap();
        let repo = Repo::discover(td.path()).unwrap();
        let store = Store::for_repo_with_base(&repo, data_dir.path().to_path_buf()).unwrap();
        let report = run(&repo, &store).unwrap();
        assert!(report.recent_gate_skips.is_empty());
        assert!(!report.render().contains("recent gate skips"));
    }
}
