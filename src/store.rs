use crate::crypto;
use crate::error::{Error, Result};
use crate::manifest::Manifest;
use crate::repo::Repo;
use age::x25519::{Identity, Recipient};
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const RECIPIENT_FILENAME: &str = "recipient.txt";
pub const INSECURE_KEY_MARKER: &str = "insecure-file-key";
pub const REPO_ORIGIN_FILENAME: &str = "repo_origin.txt";
pub const SNAP_LOCK_FILENAME: &str = ".snap.lock";
pub const REMOTE_LOCK_FILENAME: &str = ".remote.lock";
pub const REMOTE_PENDING_FILENAME: &str = "remote-pending.jsonl";

/// Acquisition mode for the per-store snap lock.
///
/// Hooks and shim use `Block` — they're already serialized with whatever git
/// operation invoked them, and waiting briefly is correct. A future watcher
/// daemon (#30) uses `TryOnce` — never block git, just skip this debounce
/// window if hooks/shim are currently snapping.
#[derive(Debug, Clone, Copy)]
pub enum SnapLockMode {
    Block,
    TryOnce,
}

/// RAII guard around an `flock`-acquired lock at `<store-root>/.snap.lock`.
/// Releases when dropped (file close releases the OS-level lock). The path
/// stays on disk between acquisitions — only the lock state is process-scoped.
pub struct SnapLock {
    _file: fs::File,
}

/// RAII guard around `<store-root>/.remote.lock`. Serializes appends to the
/// remote-pending log against the pusher's read-and-rewrite cycle so
/// concurrent snap-time appends don't write into a stale offset of a file
/// the pusher is rewriting (issue #31 audit HIGH-2).
pub struct RemoteLock {
    _file: fs::File,
}

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub const DEFAULT_MAX_STORE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const DEFAULT_MAX_AGE_DAYS: i64 = 30;

/// (successfully-parsed manifests, per-path read errors for the rest).
pub type LenientManifestList = (Vec<Manifest>, Vec<(PathBuf, Error)>);

pub struct Store {
    pub root: PathBuf,
    crypto: Option<CryptoCtx>,
}

/// Bundle of materials needed to encrypt blobs (`recipient`) and decrypt them
/// (`identity`). Stored on `Store` so all manifest/blob read paths can pick up
/// encryption transparently without leaking it into every signature.
#[derive(Clone)]
pub struct CryptoCtx {
    pub identity: Identity,
    pub recipient: Recipient,
}

impl CryptoCtx {
    pub fn from_identity(identity: Identity) -> Self {
        let recipient = crypto::recipient_of(&identity);
        Self {
            identity,
            recipient,
        }
    }
}

impl Store {
    pub fn for_repo(repo: &Repo) -> Result<Self> {
        Self::for_repo_with_base(repo, base_data_dir()?)
    }

    pub fn for_repo_with_base(repo: &Repo, base: PathBuf) -> Result<Self> {
        let root = base.join("reflogless").join(repo.id());
        let objects = root.join("objects");
        let snapshots = root.join("snapshots");
        fs::create_dir_all(&objects).map_err(|e| Error::io(&root, e))?;
        fs::create_dir_all(&snapshots).map_err(|e| Error::io(&root, e))?;
        set_dir_perms(&root)?;
        set_dir_perms(&objects)?;
        set_dir_perms(&snapshots)?;
        let s = Self { root, crypto: None };
        // Origin recording is cosmetic-metadata for `list --all`; a failure here
        // must not abort `reflogless snap` — the store itself is still valid.
        if let Err(e) = s.save_repo_origin(&repo.root) {
            eprintln!(
                "reflogless: warning: could not record origin path ({e}); \
                 store will show as legacy in `list --all` until next write succeeds"
            );
        }
        Ok(s)
    }

    /// Acquire the per-store snap lock. Serializes `snap_with_config` across
    /// hooks, shim, and (future) the watcher daemon (#30). The lockfile lives
    /// at `<root>/.snap.lock`; it is created lazily on first acquisition and
    /// stays on disk between acquisitions — only the OS-level lock state is
    /// process-scoped.
    ///
    /// Returns `Ok(Some(SnapLock))` on success, `Ok(None)` for `TryOnce` mode
    /// when another process already holds the lock (caller skips this snap),
    /// `Err` only on genuine IO failure opening or locking the file.
    pub fn acquire_snap_lock(&self, mode: SnapLockMode) -> Result<Option<SnapLock>> {
        use fs4::fs_std::FileExt;
        let p = self.root.join(SNAP_LOCK_FILENAME);
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&p)
            .map_err(|e| Error::io(&p, e))?;
        set_file_perms(&p)?;
        match mode {
            SnapLockMode::Block => {
                file.lock_exclusive().map_err(|e| Error::io(&p, e))?;
                Ok(Some(SnapLock { _file: file }))
            }
            SnapLockMode::TryOnce => match file.try_lock_exclusive() {
                Ok(true) => Ok(Some(SnapLock { _file: file })),
                Ok(false) => Ok(None),
                Err(e) => Err(Error::io(&p, e)),
            },
        }
    }

    /// Acquire the per-store remote-pending log lock. Mirrors `acquire_snap_lock`
    /// but at `<root>/.remote.lock`. Snap-time appends use `TryOnce` — if the
    /// pusher is currently draining the log, skip the append; the entry will
    /// be re-derived from the manifest on the next push (deduped via
    /// `head_blob`). The pusher itself uses `Block`.
    pub fn acquire_remote_lock(&self, mode: SnapLockMode) -> Result<Option<RemoteLock>> {
        use fs4::fs_std::FileExt;
        let p = self.root.join(REMOTE_LOCK_FILENAME);
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&p)
            .map_err(|e| Error::io(&p, e))?;
        set_file_perms(&p)?;
        match mode {
            SnapLockMode::Block => {
                file.lock_exclusive().map_err(|e| Error::io(&p, e))?;
                Ok(Some(RemoteLock { _file: file }))
            }
            SnapLockMode::TryOnce => match file.try_lock_exclusive() {
                Ok(true) => Ok(Some(RemoteLock { _file: file })),
                Ok(false) => Ok(None),
                Err(e) => Err(Error::io(&p, e)),
            },
        }
    }

    pub fn remote_pending_path(&self) -> PathBuf {
        self.root.join(REMOTE_PENDING_FILENAME)
    }

    /// Persist the origin repo path so `list --all` can show it. Idempotent —
    /// skips the rewrite if the on-disk content already matches.
    pub fn save_repo_origin(&self, path: &Path) -> Result<()> {
        let p = self.root.join(REPO_ORIGIN_FILENAME);
        let target = path.to_string_lossy();
        if let Ok(existing) = fs::read_to_string(&p) {
            if existing == target {
                return Ok(());
            }
        }
        atomic_write(&p, target.as_bytes())?;
        set_file_perms(&p)
    }

    /// Read the persisted origin path. Returns `None` for legacy stores that
    /// predate `save_repo_origin`, or on any read error.
    pub fn read_repo_origin(&self) -> Option<PathBuf> {
        let p = self.root.join(REPO_ORIGIN_FILENAME);
        let s = fs::read_to_string(&p).ok()?;
        let trimmed = s.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(PathBuf::from(trimmed))
        }
    }

    /// Attach a crypto context. Subsequent manifest writes/reads will encrypt
    /// the manifest body, and `write_blob_via_policy` / `read_entry` will route
    /// through encryption when the policy says so.
    pub fn with_crypto(mut self, ctx: CryptoCtx) -> Self {
        self.crypto = Some(ctx);
        self
    }

    pub fn crypto(&self) -> Option<&CryptoCtx> {
        self.crypto.as_ref()
    }

    /// Path to the on-disk recipient (public key) file. Presence indicates the
    /// store was provisioned for encryption.
    pub fn recipient_path(&self) -> PathBuf {
        self.root.join(RECIPIENT_FILENAME)
    }

    /// Path to the insecure-file-key marker. Presence indicates the identity
    /// lives in a local file rather than the OS keychain. Doctor surfaces this.
    pub fn insecure_marker_path(&self) -> PathBuf {
        self.root.join(INSECURE_KEY_MARKER)
    }

    pub fn provisioned_for_encryption(&self) -> bool {
        self.recipient_path().exists()
    }

    pub fn save_recipient(&self, recipient: &Recipient) -> Result<()> {
        let p = self.recipient_path();
        atomic_write(&p, recipient.to_string().as_bytes())?;
        set_file_perms(&p)?;
        Ok(())
    }

    pub fn load_recipient(&self) -> Result<Recipient> {
        let p = self.recipient_path();
        let s = fs::read_to_string(&p).map_err(|e| Error::io(&p, e))?;
        crypto::parse_recipient(&s)
    }

    pub fn mark_insecure(&self) -> Result<()> {
        let p = self.insecure_marker_path();
        atomic_write(&p, b"")?;
        set_file_perms(&p)
    }

    pub fn is_insecure_keyed(&self) -> bool {
        self.insecure_marker_path().exists()
    }

    pub fn objects_dir(&self) -> PathBuf {
        self.root.join("objects")
    }

    pub fn snapshots_dir(&self) -> PathBuf {
        self.root.join("snapshots")
    }

    /// Write plaintext bytes to a CAS blob keyed by sha256 of plaintext.
    /// Returns the plaintext digest. Used when no encryption is desired.
    pub fn write_blob(&self, bytes: &[u8]) -> Result<String> {
        self.write_blob_inner(bytes, bytes)
    }

    /// Write a blob whose disk-content is encrypted with `recipient`. CAS key
    /// stays the *plaintext* digest so dedup works across snapshots regardless
    /// of nonce churn. Caller records `encrypted: true` in the manifest entry.
    pub fn write_blob_encrypted(&self, plaintext: &[u8], recipient: &Recipient) -> Result<String> {
        let ciphertext = crypto::encrypt(plaintext, recipient)?;
        self.write_blob_inner(plaintext, &ciphertext)
    }

    fn write_blob_inner(&self, plaintext_for_digest: &[u8], on_disk: &[u8]) -> Result<String> {
        let mut h = Sha256::new();
        h.update(plaintext_for_digest);
        let digest = format!("{:x}", h.finalize());
        let (a, b) = digest.split_at(2);
        let dir = self.objects_dir().join(a);
        let dir_existed = dir.exists();
        fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
        if !dir_existed {
            // 0700 on new shards too, not just the root, so blob existence
            // can't be enumerated by world-readable directory traversal.
            set_dir_perms(&dir)?;
        }
        let p = dir.join(b);
        let rewrite = match fs::metadata(&p) {
            Ok(md) => md.len() != on_disk.len() as u64,
            Err(_) => true,
        };
        if rewrite {
            atomic_write(&p, on_disk)?;
            set_file_perms(&p)?;
        }
        Ok(digest)
    }

    pub fn read_blob(&self, digest: &str) -> Result<Vec<u8>> {
        let (a, b) = digest.split_at(2);
        let p = self.objects_dir().join(a).join(b);
        let mut f = fs::File::open(&p).map_err(|e| Error::io(&p, e))?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).map_err(|e| Error::io(&p, e))?;
        Ok(buf)
    }

    /// Read an age-encrypted blob and return decrypted plaintext.
    pub fn read_blob_encrypted(&self, digest: &str, identity: &Identity) -> Result<Vec<u8>> {
        let ct = self.read_blob(digest)?;
        crypto::decrypt(&ct, identity)
    }

    /// Read a manifest entry's bytes, branching on `entry.encrypted` so callers
    /// can't accidentally feed ciphertext into a text-diff or restore path.
    /// Errors loudly when an encrypted entry is read against a store with no
    /// crypto context attached.
    pub fn read_entry(&self, entry: &crate::manifest::ManifestEntry) -> Result<Vec<u8>> {
        if entry.encrypted {
            let ctx = self.crypto.as_ref().ok_or_else(|| {
                Error::Decryption(format!(
                    "entry {} is encrypted but no identity attached to store",
                    entry.path.display()
                ))
            })?;
            self.read_blob_encrypted(&entry.blob, &ctx.identity)
        } else {
            self.read_blob(&entry.blob)
        }
    }

    pub fn delete_blob(&self, digest: &str) -> Result<()> {
        let (a, b) = digest.split_at(2);
        let p = self.objects_dir().join(a).join(b);
        if p.exists() {
            fs::remove_file(&p).map_err(|e| Error::io(&p, e))?;
        }
        Ok(())
    }

    /// Write the manifest. When the store has a crypto context attached, the
    /// body is age-encrypted and written as `<id>.json.age`. Otherwise plain
    /// JSON at `<id>.json`.
    pub fn write_manifest(&self, m: &Manifest) -> Result<PathBuf> {
        let json = serde_json::to_vec_pretty(m)?;
        let p = match &self.crypto {
            Some(ctx) => {
                let body = crypto::encrypt(&json, &ctx.recipient)?;
                let p = self.snapshots_dir().join(format!("{}.json.age", m.id));
                atomic_write(&p, &body)?;
                set_file_perms(&p)?;
                p
            }
            None => {
                let p = self.snapshots_dir().join(format!("{}.json", m.id));
                atomic_write(&p, &json)?;
                set_file_perms(&p)?;
                p
            }
        };
        Ok(p)
    }

    pub fn load_manifest(&self, id: &str) -> Result<Manifest> {
        if id.is_empty() {
            return Err(Error::SnapshotNotFound("(empty)".into()));
        }
        // exact match: try encrypted first, then plain, so an encrypted store
        // can still surface a pre-encryption manifest if one lingers.
        let enc = self.snapshots_dir().join(format!("{}.json.age", id));
        if enc.exists() {
            return self.read_manifest_file(&enc);
        }
        let exact = self.snapshots_dir().join(format!("{}.json", id));
        if exact.exists() {
            return self.read_manifest_file(&exact);
        }
        // "latest" alias
        if id == "latest" {
            let (mut all, _warnings) = self.list_manifests_lenient()?;
            all.sort_by_key(|m| m.created_at);
            return all
                .pop()
                .ok_or_else(|| Error::SnapshotNotFound("latest".into()));
        }
        // prefix match
        let matches: Vec<_> = self
            .list_manifest_paths()?
            .into_iter()
            .filter(|p| {
                manifest_id_from_path(p.as_path())
                    .map(|s| s.starts_with(id))
                    .unwrap_or(false)
            })
            .collect();
        match matches.len() {
            0 => Err(Error::SnapshotNotFound(id.into())),
            1 => self.read_manifest_file(&matches[0]),
            _ => {
                let ids: Vec<String> = matches
                    .iter()
                    .filter_map(|p| manifest_id_from_path(p))
                    .collect();
                Err(Error::AmbiguousSnapshot {
                    id: id.into(),
                    matches: ids,
                })
            }
        }
    }

    /// Strict list — errors on the first malformed manifest. Prefer
    /// `list_manifests_lenient` for any user-facing path that needs to survive
    /// partial corruption.
    pub fn list_manifests(&self) -> Result<Vec<Manifest>> {
        let mut out = Vec::new();
        for p in self.list_manifest_paths()? {
            out.push(self.read_manifest_file(&p)?);
        }
        Ok(out)
    }

    /// Returns successfully-parsed manifests plus per-path errors for the rest.
    /// One bad manifest never blinds the user to the N-1 good ones.
    pub fn list_manifests_lenient(&self) -> Result<LenientManifestList> {
        let mut ok = Vec::new();
        let mut warnings = Vec::new();
        for p in self.list_manifest_paths()? {
            match self.read_manifest_file(&p) {
                Ok(m) => ok.push(m),
                Err(e) => warnings.push((p, e)),
            }
        }
        Ok((ok, warnings))
    }

    fn list_manifest_paths(&self) -> Result<Vec<PathBuf>> {
        let dir = self.snapshots_dir();
        let mut paths = Vec::new();
        let rd = fs::read_dir(&dir).map_err(|e| Error::io(&dir, e))?;
        for entry in rd {
            let entry = entry.map_err(|e| Error::io(&dir, e))?;
            let p = entry.path();
            let name = match p.file_name().and_then(|s| s.to_str()) {
                Some(s) => s,
                None => continue,
            };
            if name.ends_with(".json") || name.ends_with(".json.age") {
                paths.push(p);
            }
        }
        Ok(paths)
    }

    fn read_manifest_file(&self, p: &Path) -> Result<Manifest> {
        let mut f = fs::File::open(p).map_err(|e| Error::io(p, e))?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).map_err(|e| Error::io(p, e))?;
        let plaintext = if is_encrypted_manifest_path(p) {
            let ctx = self.crypto.as_ref().ok_or_else(|| {
                Error::Decryption(format!(
                    "encrypted manifest {} but no identity attached",
                    p.display()
                ))
            })?;
            crypto::decrypt(&buf, &ctx.identity)?
        } else {
            buf
        };
        Ok(serde_json::from_slice(&plaintext)?)
    }

    /// Evict snapshots older than `max_age_days`, then enforce `max_bytes` by LRU
    /// (oldest snapshots dropped first), then drop unreferenced blobs.
    ///
    /// Manifests that fail to parse are treated as eviction candidates rather
    /// than aborting the whole GC pass.
    pub fn gc(&self, max_age_days: i64, max_bytes: u64) -> Result<GcReport> {
        let mut report = GcReport::default();
        let cutoff = Utc::now() - Duration::days(max_age_days);

        let mut retained: Vec<(PathBuf, Manifest)> = Vec::new();
        for p in self.list_manifest_paths()? {
            match self.read_manifest_file(&p) {
                Ok(m) => {
                    if m.created_at < cutoff {
                        fs::remove_file(&p).map_err(|e| Error::io(&p, e))?;
                        report.snapshots_age_evicted += 1;
                    } else {
                        retained.push((p, m));
                    }
                }
                Err(_) => {
                    // Unreadable manifest is itself store rot — drop it.
                    fs::remove_file(&p).map_err(|e| Error::io(&p, e))?;
                    report.snapshots_corrupt_evicted += 1;
                }
            }
        }

        // Oldest first by manifest-declared time, not filesystem mtime.
        retained.sort_by_key(|(_, m)| m.created_at);

        let mut total = self.total_blob_bytes()?;
        let mut idx = 0;
        while total > max_bytes && idx < retained.len() {
            let (p, _) = &retained[idx];
            fs::remove_file(p).map_err(|e| Error::io(p, e))?;
            report.snapshots_size_evicted += 1;
            idx += 1;
            let keep: HashSet<String> = retained
                .iter()
                .skip(idx)
                .flat_map(|(_, m)| m.entries.iter().map(|e| e.blob.clone()))
                .collect();
            total = self.objects_size_filtered(&keep)?;
        }

        let kept: HashSet<String> = retained
            .iter()
            .skip(idx)
            .flat_map(|(_, m)| m.entries.iter().map(|e| e.blob.clone()))
            .collect();
        report.blobs_evicted = self.drop_unreferenced_blobs(&kept)?;
        Ok(report)
    }

    fn total_blob_bytes(&self) -> Result<u64> {
        let mut total = 0;
        let dir = self.objects_dir();
        for d in fs::read_dir(&dir).map_err(|e| Error::io(&dir, e))? {
            let d = d.map_err(|e| Error::io(&dir, e))?;
            if !d.path().is_dir() {
                continue;
            }
            for f in fs::read_dir(d.path()).map_err(|e| Error::io(d.path(), e))? {
                let f = f.map_err(|e| Error::io(d.path(), e))?;
                let m = f.metadata().map_err(|e| Error::io(f.path(), e))?;
                total += m.len();
            }
        }
        Ok(total)
    }

    fn objects_size_filtered(&self, keep: &HashSet<String>) -> Result<u64> {
        let mut total = 0;
        for digest in keep {
            let (a, b) = digest.split_at(2);
            let p = self.objects_dir().join(a).join(b);
            if let Ok(m) = fs::metadata(&p) {
                total += m.len();
            }
        }
        Ok(total)
    }

    fn drop_unreferenced_blobs(&self, keep: &HashSet<String>) -> Result<usize> {
        let mut dropped = 0;
        let dir = self.objects_dir();
        for d in fs::read_dir(&dir).map_err(|e| Error::io(&dir, e))? {
            let d = d.map_err(|e| Error::io(&dir, e))?;
            if !d.path().is_dir() {
                continue;
            }
            let a = d.file_name();
            for f in fs::read_dir(d.path()).map_err(|e| Error::io(d.path(), e))? {
                let f = f.map_err(|e| Error::io(d.path(), e))?;
                let b = f.file_name();
                let digest = format!("{}{}", a.to_string_lossy(), b.to_string_lossy());
                if !keep.contains(&digest) {
                    fs::remove_file(f.path()).map_err(|e| Error::io(f.path(), e))?;
                    dropped += 1;
                }
            }
        }
        Ok(dropped)
    }
}

#[derive(Debug, Default)]
pub struct GcReport {
    pub snapshots_age_evicted: usize,
    pub snapshots_size_evicted: usize,
    pub snapshots_corrupt_evicted: usize,
    pub blobs_evicted: usize,
}

/// Strip `.json` or `.json.age` extension and return the manifest id portion of
/// a snapshot filename. Returns None when the filename has neither suffix.
fn manifest_id_from_path(p: &Path) -> Option<String> {
    let name = p.file_name()?.to_str()?;
    if let Some(stem) = name.strip_suffix(".json.age") {
        return Some(stem.to_string());
    }
    if let Some(stem) = name.strip_suffix(".json") {
        return Some(stem.to_string());
    }
    None
}

fn is_encrypted_manifest_path(p: &Path) -> bool {
    p.file_name()
        .and_then(|s| s.to_str())
        .map(|n| n.ends_with(".json.age"))
        .unwrap_or(false)
}

/// State a store can be in when discovered via cross-repo listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreOriginState {
    /// `repo_origin.txt` present and the path still exists on disk.
    Active(PathBuf),
    /// `repo_origin.txt` present but the path is gone.
    Stale(PathBuf),
    /// No `repo_origin.txt` — store predates the feature or was hand-created.
    Legacy,
}

/// Per-store summary surfaced by `list_all_stores`. Metadata is plaintext-only;
/// per-manifest detail (event/message/files) requires the originating repo's
/// identity and stays in single-repo `reflogless list`.
#[derive(Debug, Clone)]
pub struct StoreSummary {
    pub store_id: String,
    pub state: StoreOriginState,
    pub snapshot_count: usize,
    pub snapshot_ids: Vec<String>,
    /// True when the snapshots/ dir couldn't be read at scan time. The count
    /// is 0 in that case; the printer should distinguish "no snapshots" from
    /// "snapshots unreadable" so a user doesn't act on a false negative.
    pub snapshots_unreadable: bool,
}

/// Walk `<base>/reflogless/<16-hex>/` and summarize each store. Skips entries
/// whose directory name isn't a 16-hex `Repo::id()` value (avoids confusion
/// with hand-placed files/dirs). Stale/legacy stores are surfaced, not skipped.
pub fn list_all_stores(base: &Path) -> Result<Vec<StoreSummary>> {
    let root = base.join("reflogless");
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut out: Vec<StoreSummary> = Vec::new();
    let entries = match fs::read_dir(&root) {
        Ok(it) => it,
        Err(e) => return Err(Error::io(&root, e)),
    };
    for ent in entries {
        let ent = match ent {
            Ok(e) => e,
            Err(e) => {
                eprintln!(
                    "reflogless: warning: skipping unreadable entry under {}: {e}",
                    root.display()
                );
                continue;
            }
        };
        let path = ent.path();
        if !path.is_dir() {
            continue;
        }
        let name = match path.file_name().and_then(|s| s.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if !is_repo_id_dirname(&name) {
            continue;
        }

        let origin_path = fs::read_to_string(path.join(REPO_ORIGIN_FILENAME))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);

        let state = match origin_path {
            Some(p) if p.exists() => StoreOriginState::Active(p),
            Some(p) => StoreOriginState::Stale(p),
            None => StoreOriginState::Legacy,
        };

        let snapshots_dir = path.join("snapshots");
        let (ids, snapshots_unreadable) = match fs::read_dir(&snapshots_dir) {
            Ok(dirit) => {
                let mut v: Vec<String> = Vec::new();
                for f in dirit.flatten() {
                    if let Some(id) = manifest_id_from_path(&f.path()) {
                        v.push(id);
                    }
                }
                v.sort();
                (v, false)
            }
            Err(e) => {
                eprintln!(
                    "reflogless: warning: cannot read {}: {e}",
                    snapshots_dir.display()
                );
                (Vec::new(), true)
            }
        };

        out.push(StoreSummary {
            store_id: name,
            state,
            snapshot_count: ids.len(),
            snapshot_ids: ids,
            snapshots_unreadable,
        });
    }

    out.sort_by(|a, b| match (&a.state, &b.state) {
        (StoreOriginState::Active(pa), StoreOriginState::Active(pb)) => pa.cmp(pb),
        (StoreOriginState::Active(_), _) => std::cmp::Ordering::Less,
        (_, StoreOriginState::Active(_)) => std::cmp::Ordering::Greater,
        (StoreOriginState::Stale(pa), StoreOriginState::Stale(pb)) => pa.cmp(pb),
        (StoreOriginState::Stale(_), _) => std::cmp::Ordering::Less,
        (_, StoreOriginState::Stale(_)) => std::cmp::Ordering::Greater,
        (StoreOriginState::Legacy, StoreOriginState::Legacy) => a.store_id.cmp(&b.store_id),
    });

    Ok(out)
}

fn is_repo_id_dirname(name: &str) -> bool {
    name.len() == 16 && name.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn base_data_dir() -> Result<PathBuf> {
    // Explicit override beats platform default.
    if let Ok(p) = std::env::var("REFLOGLESS_DATA_DIR") {
        if !p.is_empty() {
            return Ok(PathBuf::from(p));
        }
    }
    if let Ok(p) = std::env::var("XDG_DATA_HOME") {
        if !p.is_empty() {
            return Ok(PathBuf::from(p));
        }
    }
    dirs::data_dir().ok_or_else(|| Error::Config("could not resolve data dir".into()))
}

pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or(Path::new("."));
    let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = parent.join(format!(".reflogless-tmp-{}-{}", std::process::id(), n));
    let write_result = (|| -> Result<()> {
        let mut f = fs::File::create(&tmp).map_err(|e| Error::io(&tmp, e))?;
        f.write_all(bytes).map_err(|e| Error::io(&tmp, e))?;
        f.sync_all().map_err(|e| Error::io(&tmp, e))?;
        Ok(())
    })();
    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(Error::io(path, e));
    }
    Ok(())
}

#[cfg(unix)]
fn set_dir_perms(p: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o700);
    fs::set_permissions(p, perms).map_err(|e| Error::io(p, e))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_perms(_p: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_file_perms(p: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o600);
    fs::set_permissions(p, perms).map_err(|e| Error::io(p, e))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_perms(_p: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::ManifestEntry;
    use chrono::DateTime;
    use tempfile::TempDir;

    fn ephemeral_store() -> (TempDir, Store) {
        let td = TempDir::new().unwrap();
        let root = td.path().join("reflogless").join("test");
        fs::create_dir_all(root.join("objects")).unwrap();
        fs::create_dir_all(root.join("snapshots")).unwrap();
        (td, Store { root, crypto: None })
    }

    #[test]
    fn write_and_read_blob_roundtrips() {
        let (_td, store) = ephemeral_store();
        let bytes = b"hello world";
        let digest = store.write_blob(bytes).unwrap();
        let got = store.read_blob(&digest).unwrap();
        assert_eq!(got, bytes);
    }

    #[test]
    fn dedup_writes_one_file_on_disk() {
        let (_td, store) = ephemeral_store();
        let d1 = store.write_blob(b"same").unwrap();
        let d2 = store.write_blob(b"same").unwrap();
        assert_eq!(d1, d2);
        let (a, b) = d1.split_at(2);
        let p = store.objects_dir().join(a).join(b);
        assert!(p.exists());
        // No tmp file should be lying around.
        let leftovers: Vec<_> = fs::read_dir(p.parent().unwrap())
            .unwrap()
            .filter_map(|d| d.ok())
            .filter(|d| {
                d.file_name()
                    .to_string_lossy()
                    .starts_with(".reflogless-tmp-")
            })
            .collect();
        assert!(leftovers.is_empty(), "tmp leftover: {leftovers:?}");
    }

    #[test]
    fn load_manifest_prefers_encrypted_when_both_exist() {
        // Pre-Phase-3 manifests may linger next to their re-encrypted siblings
        // during migration. The encrypted file is canonical for a crypto-attached
        // store and must win.
        use crate::crypto;
        let (_td, store) = ephemeral_store();
        let id_str = "20260523T000000000Z-manual";
        // Write plaintext directly.
        let m = make_manifest(id_str, Utc::now(), vec![]);
        let plain_json = serde_json::to_vec_pretty(&m).unwrap();
        atomic_write(
            &store.snapshots_dir().join(format!("{id_str}.json")),
            &plain_json,
        )
        .unwrap();
        // Write encrypted with a different message under same id.
        let id = crypto::generate_identity();
        let recipient = crypto::recipient_of(&id);
        let store = store.with_crypto(CryptoCtx::from_identity(id));
        let mut m2 = make_manifest(id_str, Utc::now(), vec![]);
        m2.message = Some("from-encrypted".into());
        let body = serde_json::to_vec_pretty(&m2).unwrap();
        let ct = crypto::encrypt(&body, &recipient).unwrap();
        atomic_write(
            &store.snapshots_dir().join(format!("{id_str}.json.age")),
            &ct,
        )
        .unwrap();

        let loaded = store.load_manifest(id_str).unwrap();
        assert_eq!(loaded.message.as_deref(), Some("from-encrypted"));
    }

    #[test]
    fn gc_evicts_corrupt_encrypted_manifest() {
        use crate::crypto;
        let (_td, store) = ephemeral_store();
        let id = crypto::generate_identity();
        let store = store.with_crypto(CryptoCtx::from_identity(id));
        // Sabotage an encrypted manifest path with non-ciphertext bytes.
        fs::write(
            store
                .snapshots_dir()
                .join("20260523T000000000Z-manual.json.age"),
            b"not-age-encrypted",
        )
        .unwrap();
        let report = store.gc(365, u64::MAX).unwrap();
        assert_eq!(report.snapshots_corrupt_evicted, 1);
    }

    #[test]
    fn write_blob_repairs_truncated_existing_object() {
        let (_td, store) = ephemeral_store();
        let digest = store.write_blob(b"hello").unwrap();
        let (a, b) = digest.split_at(2);
        let p = store.objects_dir().join(a).join(b);
        fs::write(&p, b"").unwrap();
        // Re-writing the same bytes should restore the truncated blob.
        store.write_blob(b"hello").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"hello");
    }

    fn make_manifest(id: &str, created: DateTime<Utc>, entries: Vec<ManifestEntry>) -> Manifest {
        Manifest {
            version: crate::manifest::MANIFEST_VERSION,
            id: id.into(),
            created_at: created,
            event: "manual".into(),
            message: None,
            repo_root: "/".into(),
            entries,
        }
    }

    #[test]
    fn load_manifest_rejects_empty_id() {
        let (_td, store) = ephemeral_store();
        let m = make_manifest("only", Utc::now(), vec![]);
        store.write_manifest(&m).unwrap();
        assert!(matches!(
            store.load_manifest(""),
            Err(Error::SnapshotNotFound(_))
        ));
    }

    #[test]
    fn load_manifest_latest_returns_newest_by_created_at() {
        let (_td, store) = ephemeral_store();
        let older = make_manifest("a", Utc::now() - Duration::hours(2), vec![]);
        let newer = make_manifest("b", Utc::now(), vec![]);
        store.write_manifest(&older).unwrap();
        store.write_manifest(&newer).unwrap();
        let m = store.load_manifest("latest").unwrap();
        assert_eq!(m.id, "b");
    }

    #[test]
    fn load_manifest_prefix_match_returns_unique() {
        let (_td, store) = ephemeral_store();
        store
            .write_manifest(&make_manifest(
                "20260520T000000000Z-manual",
                Utc::now(),
                vec![],
            ))
            .unwrap();
        store
            .write_manifest(&make_manifest(
                "20260521T000000000Z-manual",
                Utc::now(),
                vec![],
            ))
            .unwrap();
        let m = store.load_manifest("20260520").unwrap();
        assert_eq!(m.id, "20260520T000000000Z-manual");
    }

    #[test]
    fn load_manifest_ambiguous_prefix_errors() {
        let (_td, store) = ephemeral_store();
        store
            .write_manifest(&make_manifest(
                "20260520T000000000Z-manual",
                Utc::now(),
                vec![],
            ))
            .unwrap();
        store
            .write_manifest(&make_manifest(
                "20260520T000000001Z-manual",
                Utc::now(),
                vec![],
            ))
            .unwrap();
        match store.load_manifest("20260520") {
            Err(Error::AmbiguousSnapshot { matches, .. }) => assert_eq!(matches.len(), 2),
            other => panic!("expected AmbiguousSnapshot, got {other:?}"),
        }
    }

    #[test]
    fn list_manifests_lenient_skips_corrupt_files() {
        let (_td, store) = ephemeral_store();
        store
            .write_manifest(&make_manifest("good", Utc::now(), vec![]))
            .unwrap();
        fs::write(store.snapshots_dir().join("bad.json"), b"{not json").unwrap();
        let (ok, warnings) = store.list_manifests_lenient().unwrap();
        assert_eq!(ok.len(), 1);
        assert_eq!(warnings.len(), 1);
        assert_eq!(ok[0].id, "good");
    }

    #[test]
    fn gc_evicts_snapshots_older_than_cutoff() {
        let (_td, store) = ephemeral_store();
        let digest = store.write_blob(b"payload").unwrap();
        let entries = vec![ManifestEntry {
            path: PathBuf::from("a.txt"),
            blob: digest.clone(),
            size: 7,
            mode: 0o644,
            encrypted: false,
        }];
        store
            .write_manifest(&make_manifest(
                "old",
                Utc::now() - Duration::days(60),
                entries,
            ))
            .unwrap();
        let report = store.gc(30, u64::MAX).unwrap();
        assert_eq!(report.snapshots_age_evicted, 1);
        assert_eq!(report.blobs_evicted, 1);
        let (a, b) = digest.split_at(2);
        assert!(!store.objects_dir().join(a).join(b).exists());
    }

    #[test]
    fn gc_size_cap_evicts_oldest_first() {
        let (_td, store) = ephemeral_store();
        let d1 = store.write_blob(&vec![1u8; 1000]).unwrap();
        let d2 = store.write_blob(&vec![2u8; 1000]).unwrap();
        let d3 = store.write_blob(&vec![3u8; 1000]).unwrap();
        let mk = |id, secs: i64, digest: &str| {
            make_manifest(
                id,
                Utc::now() - Duration::seconds(secs),
                vec![ManifestEntry {
                    path: PathBuf::from(format!("{id}.bin")),
                    blob: digest.into(),
                    size: 1000,
                    mode: 0o644,
                    encrypted: false,
                }],
            )
        };
        store.write_manifest(&mk("A", 30, &d1)).unwrap();
        store.write_manifest(&mk("B", 20, &d2)).unwrap();
        store.write_manifest(&mk("C", 10, &d3)).unwrap();
        // Cap at 2050 bytes — must evict A.
        let report = store.gc(365, 2050).unwrap();
        assert_eq!(report.snapshots_size_evicted, 1);
        assert!(store.load_manifest("A").is_err());
        assert!(store.load_manifest("B").is_ok());
        assert!(store.load_manifest("C").is_ok());
    }

    #[test]
    fn gc_drops_unreferenced_blobs() {
        let (_td, store) = ephemeral_store();
        store.write_blob(b"orphan").unwrap();
        let report = store.gc(365, u64::MAX).unwrap();
        assert_eq!(report.blobs_evicted, 1);
    }

    #[test]
    fn gc_empty_store_is_noop() {
        let (_td, store) = ephemeral_store();
        let report = store.gc(30, u64::MAX).unwrap();
        assert_eq!(report.snapshots_age_evicted, 0);
        assert_eq!(report.snapshots_size_evicted, 0);
        assert_eq!(report.snapshots_corrupt_evicted, 0);
        assert_eq!(report.blobs_evicted, 0);
    }

    #[test]
    fn gc_drops_corrupt_manifests_instead_of_aborting() {
        let (_td, store) = ephemeral_store();
        let digest = store.write_blob(b"x").unwrap();
        store
            .write_manifest(&make_manifest(
                "good",
                Utc::now(),
                vec![ManifestEntry {
                    path: PathBuf::from("x"),
                    blob: digest.clone(),
                    size: 1,
                    mode: 0o644,
                    encrypted: false,
                }],
            ))
            .unwrap();
        fs::write(store.snapshots_dir().join("bad.json"), b"not json").unwrap();
        let report = store.gc(365, u64::MAX).unwrap();
        assert_eq!(report.snapshots_corrupt_evicted, 1);
        assert!(store.load_manifest("good").is_ok());
    }

    /// Construct a minimal store dir on disk under a custom base, optionally
    /// writing a `repo_origin.txt` and seeding N snapshot files. Avoids the
    /// `Repo::discover` path so we don't need a real git repo.
    fn seed_store(
        base: &Path,
        store_id: &str,
        origin: Option<&Path>,
        manifest_ids: &[&str],
        encrypted: bool,
    ) {
        let root = base.join("reflogless").join(store_id);
        fs::create_dir_all(root.join("objects")).unwrap();
        fs::create_dir_all(root.join("snapshots")).unwrap();
        if let Some(o) = origin {
            atomic_write(
                &root.join(REPO_ORIGIN_FILENAME),
                o.to_string_lossy().as_bytes(),
            )
            .unwrap();
        }
        for id in manifest_ids {
            let ext = if encrypted { ".json.age" } else { ".json" };
            fs::write(root.join("snapshots").join(format!("{id}{ext}")), b"x").unwrap();
        }
    }

    #[test]
    fn list_all_stores_returns_multiple_active_stores() {
        let td = TempDir::new().unwrap();
        let repo_a = td.path().join("repo-a");
        let repo_b = td.path().join("repo-b");
        fs::create_dir_all(&repo_a).unwrap();
        fs::create_dir_all(&repo_b).unwrap();
        seed_store(
            td.path(),
            "aaaaaaaaaaaaaaaa",
            Some(&repo_a),
            &["s1", "s2"],
            false,
        );
        seed_store(td.path(), "bbbbbbbbbbbbbbbb", Some(&repo_b), &["s3"], true);

        let stores = list_all_stores(td.path()).unwrap();
        assert_eq!(stores.len(), 2);
        let by_id: std::collections::HashMap<_, _> =
            stores.iter().map(|s| (s.store_id.as_str(), s)).collect();
        let a = by_id.get("aaaaaaaaaaaaaaaa").unwrap();
        assert!(matches!(&a.state, StoreOriginState::Active(p) if p == &repo_a));
        assert_eq!(a.snapshot_count, 2);
        assert_eq!(a.snapshot_ids, vec!["s1".to_string(), "s2".to_string()]);
        let b = by_id.get("bbbbbbbbbbbbbbbb").unwrap();
        assert!(matches!(&b.state, StoreOriginState::Active(p) if p == &repo_b));
        assert_eq!(b.snapshot_count, 1);
    }

    #[test]
    fn list_all_stores_handles_stale_origin() {
        let td = TempDir::new().unwrap();
        let bogus = td.path().join("repo-never-existed");
        seed_store(td.path(), "cccccccccccccccc", Some(&bogus), &["x"], false);
        let stores = list_all_stores(td.path()).unwrap();
        assert_eq!(stores.len(), 1);
        match &stores[0].state {
            StoreOriginState::Stale(p) => assert_eq!(p, &bogus),
            other => panic!("expected Stale, got {other:?}"),
        }
        assert_eq!(stores[0].snapshot_count, 1);
    }

    #[test]
    fn list_all_stores_handles_legacy_store_without_origin_file() {
        let td = TempDir::new().unwrap();
        seed_store(td.path(), "dddddddddddddddd", None, &["y"], false);
        let stores = list_all_stores(td.path()).unwrap();
        assert_eq!(stores.len(), 1);
        assert!(matches!(stores[0].state, StoreOriginState::Legacy));
        assert_eq!(stores[0].snapshot_count, 1);
    }

    #[test]
    fn list_all_stores_skips_non_repo_id_directory_names() {
        let td = TempDir::new().unwrap();
        // non-hex
        fs::create_dir_all(td.path().join("reflogless").join("not-a-hex")).unwrap();
        fs::create_dir_all(td.path().join("reflogless").join("ZZZZZZZZZZZZZZZZ")).unwrap();
        // boundary: hex but wrong length
        fs::create_dir_all(td.path().join("reflogless").join("deadbeef")).unwrap();
        fs::create_dir_all(td.path().join("reflogless").join("deadbeefdeadbeefdead")).unwrap();
        seed_store(td.path(), "eeeeeeeeeeeeeeee", None, &[], false);
        let stores = list_all_stores(td.path()).unwrap();
        assert_eq!(stores.len(), 1);
        assert_eq!(stores[0].store_id, "eeeeeeeeeeeeeeee");
    }

    #[test]
    fn list_all_stores_returns_empty_when_root_missing() {
        let td = TempDir::new().unwrap();
        let stores = list_all_stores(td.path()).unwrap();
        assert!(stores.is_empty());
    }

    #[test]
    fn list_all_stores_sort_active_before_stale_before_legacy() {
        let td = TempDir::new().unwrap();
        let active = td.path().join("active-repo");
        fs::create_dir_all(&active).unwrap();
        let stale_path = td.path().join("missing-repo");
        seed_store(td.path(), "1111111111111111", None, &[], false);
        seed_store(td.path(), "2222222222222222", Some(&stale_path), &[], false);
        seed_store(td.path(), "3333333333333333", Some(&active), &[], false);
        let stores = list_all_stores(td.path()).unwrap();
        let states: Vec<&str> = stores
            .iter()
            .map(|s| match &s.state {
                StoreOriginState::Active(_) => "active",
                StoreOriginState::Stale(_) => "stale",
                StoreOriginState::Legacy => "legacy",
            })
            .collect();
        assert_eq!(states, vec!["active", "stale", "legacy"]);
    }

    #[test]
    fn save_repo_origin_is_idempotent_when_path_matches() {
        let (td, store) = ephemeral_store();
        let path = td.path().join("some-repo");
        store.save_repo_origin(&path).unwrap();
        let p = store.root.join(REPO_ORIGIN_FILENAME);
        let mtime1 = fs::metadata(&p).unwrap().modified().unwrap();
        // sleep just a hair so a rewrite would show different mtime
        std::thread::sleep(std::time::Duration::from_millis(10));
        store.save_repo_origin(&path).unwrap();
        let mtime2 = fs::metadata(&p).unwrap().modified().unwrap();
        assert_eq!(mtime1, mtime2, "idempotent write should not touch mtime");
        assert_eq!(store.read_repo_origin().unwrap(), path);
    }

    #[test]
    fn save_repo_origin_rewrites_when_path_changes() {
        let (td, store) = ephemeral_store();
        store.save_repo_origin(&td.path().join("a")).unwrap();
        store.save_repo_origin(&td.path().join("b")).unwrap();
        assert_eq!(store.read_repo_origin().unwrap(), td.path().join("b"));
    }

    #[test]
    fn for_repo_with_base_records_origin_path() {
        let td = TempDir::new().unwrap();
        let repo_root = td.path().join("a-repo");
        fs::create_dir_all(repo_root.join(".git")).unwrap();
        let repo = Repo::discover(&repo_root).unwrap();
        let base = td.path().join("data");
        let store = Store::for_repo_with_base(&repo, base).unwrap();
        assert_eq!(store.read_repo_origin(), Some(repo.root.clone()));
    }

    #[test]
    fn snap_lock_block_releases_on_drop() {
        let (_td, store) = ephemeral_store();
        {
            let g = store.acquire_snap_lock(SnapLockMode::Block).unwrap();
            assert!(g.is_some());
        }
        // After drop, second acquisition must succeed.
        let g2 = store.acquire_snap_lock(SnapLockMode::Block).unwrap();
        assert!(g2.is_some());
    }

    #[test]
    fn snap_lock_try_once_returns_none_when_held_by_another_process() {
        // Inter-process semantics: spawn a child that holds the lock and
        // sleeps; assert TryOnce in the parent returns Ok(None).
        use std::process::{Command, Stdio};
        let (td, store) = ephemeral_store();
        let lockpath = store.root.join(SNAP_LOCK_FILENAME);
        // Pre-create with right perms; child just locks it.
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lockpath)
            .unwrap();
        let marker = td.path().join("child-ready");
        let helper = r#"
import fcntl, os, sys, time
f = open(sys.argv[1], 'r+')
fcntl.flock(f, fcntl.LOCK_EX)
open(sys.argv[2], 'w').close()
time.sleep(5)
"#;
        let mut child = Command::new("python3")
            .arg("-c")
            .arg(helper)
            .arg(&lockpath)
            .arg(&marker)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        // Wait for child to acquire (up to 2s).
        let start = std::time::Instant::now();
        while !marker.exists() && start.elapsed().as_secs() < 2 {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(marker.exists(), "child failed to acquire lock");
        let result = store.acquire_snap_lock(SnapLockMode::TryOnce).unwrap();
        assert!(result.is_none(), "TryOnce should not block; got a guard");
        // Kill child + wait so the lock releases before the temp dir vanishes.
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn snap_lock_try_once_succeeds_when_free() {
        let (_td, store) = ephemeral_store();
        let g = store.acquire_snap_lock(SnapLockMode::TryOnce).unwrap();
        assert!(g.is_some());
    }

    #[test]
    fn snap_lock_file_has_secure_perms() {
        let (_td, store) = ephemeral_store();
        let _g = store.acquire_snap_lock(SnapLockMode::Block).unwrap();
        let lockpath = store.root.join(SNAP_LOCK_FILENAME);
        assert!(lockpath.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&lockpath).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "snap lockfile should be 0600");
        }
    }
}
