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
///
/// `Drop` calls `flock(LOCK_UN)` explicitly before closing the file. On macOS,
/// relying on close-to-release leaves the kernel lock state in flight long
/// enough that sequential same-process re-acquisitions intermittently see
/// `WouldBlock` (the symptom: `TryOnce` returning false with no other holder).
pub struct RemoteLock {
    file: Option<fs::File>,
}

impl Drop for RemoteLock {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let _ = file.unlock();
        }
    }
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
        // Not cosmetic, despite what this comment used to say: since #78 the
        // origin file is the only evidence `gc --stale-stores` has that a store
        // is dead. A failure here still must not abort `reflogless snap` — the
        // store is usable without it — but the consequence is that the store
        // becomes unreclaimable, so it is warned about rather than ignored, and
        // `remove_stale_store` verifies the recorded path against the store id
        // rather than trusting whatever ends up on disk.
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
                Ok(Some(RemoteLock { file: Some(file) }))
            }
            SnapLockMode::TryOnce => match file.try_lock_exclusive() {
                Ok(true) => Ok(Some(RemoteLock { file: Some(file) })),
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
    /// `repo_origin.txt` present, and the origin path is confirmed *absent* —
    /// the check returned "not found", not merely "could not tell". Only this
    /// state is reclaimable.
    Stale(PathBuf),
    /// No `repo_origin.txt` — store predates the feature or was hand-created.
    Legacy,
    /// The origin could not be resolved: `repo_origin.txt` was unreadable, or
    /// probing the path failed for some reason other than "not found" — an
    /// unmounted volume, an offline network share, a permission change on a
    /// parent directory, a path over the OS length limit.
    ///
    /// Never reclaimable. `Path::exists()` collapses every one of those causes
    /// into `false`, which would classify a fully intact repo as dead and delete
    /// its snapshots. Destroying data requires positive confirmation that the
    /// origin is gone, never absence of evidence that it is there.
    Unknown {
        origin: Option<PathBuf>,
        reason: String,
    },
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

/// Decide a store's origin state from its `repo_origin.txt`.
///
/// The only path to `Stale` — the only reclaimable state — is a *confirmed*
/// absent origin. `try_exists` is what makes that distinction available:
/// `Path::exists()` returns `false` for a permission error on a parent, an
/// unmounted volume, an offline share, or a too-long path, all of which would
/// otherwise present a live repo's store as reclaimable garbage.
fn classify_origin(origin_file: &Path) -> StoreOriginState {
    let recorded = match fs::read_to_string(origin_file) {
        Ok(s) => s.trim().to_string(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return StoreOriginState::Legacy,
        Err(e) => {
            return StoreOriginState::Unknown {
                origin: None,
                reason: format!("cannot read {}: {e}", origin_file.display()),
            }
        }
    };
    // An empty file is not an absent one. `Legacy` means "predates the origin
    // file", i.e. install age; an empty file means a truncated write, a full
    // disk, or an interrupted delete — a damaged store, which must not be
    // filed under a design decision and reported as "kept" forever.
    if recorded.is_empty() {
        return StoreOriginState::Unknown {
            origin: None,
            reason: format!("{} is empty", origin_file.display()),
        };
    }
    let p = PathBuf::from(recorded);
    // A relative origin is resolved against the *caller's* cwd, and
    // `gc --stale-stores` dispatches before repo discovery so its cwd is
    // arbitrary — the same store would classify Active or Stale depending on
    // where the command was run. That is not a confirmed anything.
    if !p.is_absolute() {
        return StoreOriginState::Unknown {
            reason: format!("recorded origin {} is not an absolute path", p.display()),
            origin: Some(p),
        };
    }
    match p.try_exists() {
        Ok(true) => StoreOriginState::Active(p),
        Ok(false) => StoreOriginState::Stale(p),
        Err(e) => StoreOriginState::Unknown {
            reason: format!("cannot determine whether {} exists: {e}", p.display()),
            origin: Some(p),
        },
    }
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

        let state = classify_origin(&path.join(REPO_ORIGIN_FILENAME));

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

    // Active first, then stale, then unknown, then legacy; ties by origin path
    // (or store id where there is none) so output is stable across runs.
    fn rank(s: &StoreOriginState) -> u8 {
        match s {
            StoreOriginState::Active(_) => 0,
            StoreOriginState::Stale(_) => 1,
            StoreOriginState::Unknown { .. } => 2,
            StoreOriginState::Legacy => 3,
        }
    }
    fn origin_of(s: &StoreOriginState) -> Option<&PathBuf> {
        match s {
            StoreOriginState::Active(p) | StoreOriginState::Stale(p) => Some(p),
            StoreOriginState::Unknown { origin, .. } => origin.as_ref(),
            StoreOriginState::Legacy => None,
        }
    }
    out.sort_by(|a, b| {
        rank(&a.state)
            .cmp(&rank(&b.state))
            .then_with(|| origin_of(&a.state).cmp(&origin_of(&b.state)))
            .then_with(|| a.store_id.cmp(&b.store_id))
    });

    Ok(out)
}

/// Hex-only, fixed-length. That is also the path-traversal guard for every
/// caller that joins this name onto the store root: a name passing this check
/// cannot contain `/`, `.`, or `..`.
fn is_repo_id_dirname(name: &str) -> bool {
    name.len() == 16 && name.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Recursive byte total under `p`.
///
/// Symlinks are counted at their own (tiny) link size and never traversed: a
/// store holding a link to a large tree elsewhere must not report that tree as
/// its own bytes, because the number is presented to the user as reclaimable
/// space. That holds because `DirEntry::metadata` does *not* follow symlinks —
/// unlike `fs::metadata`, which would.
/// Errors rather than reporting a partial figure: the total is shown to the user
/// as reclaimable space and as the size of something about to be deleted, so an
/// undercount reads as "this store is nearly empty" when it may be gigabytes.
pub(crate) fn dir_size(p: &Path) -> Result<u64> {
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

/// Machine-wide store accounting, for the visibility half of #78: `snap` never
/// prunes, so without a reported total the data dir grows unobserved until a
/// user notices the disk.
///
/// Walks every store directory, so this is one full stat pass over the data dir
/// — a diagnostic, not something to call from a hook.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StoreUsage {
    pub store_count: usize,
    pub total_bytes: u64,
    /// Stores whose recorded origin repo is gone. The reclaimable ones.
    pub stale_count: usize,
    pub stale_bytes: u64,
    /// Stores with no `repo_origin.txt`. Reported for visibility only: absence
    /// of that file tracks install age, not deadness — stores in active use
    /// today predate the file — so these are never reclaimable.
    pub legacy_count: usize,
    pub legacy_bytes: u64,
    /// Stores whose origin could not be resolved (see
    /// `StoreOriginState::Unknown`). Reported separately from stale because
    /// these are *not* reclaimable — they may well be live.
    pub unknown_count: usize,
    pub unknown_bytes: u64,
    /// Store ids whose size could not be read. Their bytes are missing from
    /// the totals, so a caller must not present the totals as exact.
    pub unreadable: Vec<String>,
}

pub fn store_usage(base: &Path) -> Result<StoreUsage> {
    let root = base.join("reflogless");
    let mut usage = StoreUsage::default();
    for s in list_all_stores(base)? {
        usage.store_count += 1;
        let bytes = match dir_size(&root.join(&s.store_id)) {
            Ok(b) => b,
            Err(_) => {
                usage.unreadable.push(s.store_id.clone());
                continue;
            }
        };
        usage.total_bytes += bytes;
        match s.state {
            StoreOriginState::Active(_) => {}
            StoreOriginState::Stale(_) => {
                usage.stale_count += 1;
                usage.stale_bytes += bytes;
            }
            StoreOriginState::Legacy => {
                usage.legacy_count += 1;
                usage.legacy_bytes += bytes;
            }
            StoreOriginState::Unknown { .. } => {
                usage.unknown_count += 1;
                usage.unknown_bytes += bytes;
            }
        }
    }
    Ok(usage)
}

/// One store eligible for reclamation: its recorded origin repo was absent when
/// the pass scanned it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReclaimCandidate {
    pub store_id: String,
    pub origin: PathBuf,
    /// `None` when the store's size could not be measured. The printer must say
    /// so rather than render it as `0 bytes`: this is the consent screen for an
    /// irreversible delete, and "0 bytes" invites a yes on what may be
    /// gigabytes of snapshots.
    pub bytes: Option<u64>,
    pub snapshot_count: usize,
    /// True when `snapshots/` was unreadable at scan time, making
    /// `snapshot_count` a floor rather than a count — same reasoning as `bytes`.
    pub snapshots_unreadable: bool,
}

/// Why a candidate was not reclaimed, and — the part that matters — what that
/// implies about the store's contents. The three kinds need three different
/// pieces of advice, and conflating any two of them tells the user something
/// false about their own data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReclaimFailureKind {
    /// Nothing was removed: either a precondition refused before the delete, or
    /// the delete ran and the store measured the same size afterwards. Safe to
    /// retry once the cause is fixed.
    Intact,
    /// The store measured smaller after the failure, so content was removed.
    /// `snapshots_left` is counted directly rather than inferred, because "you
    /// have lost snapshots" is the one claim here worth being sure of.
    PartlyDeleted {
        bytes_removed: u64,
        snapshots_left: usize,
    },
    /// The store's size could not be read on one or both sides of the failed
    /// delete, so whether anything was removed is genuinely unknown. Reported as
    /// unknown — not guessed in either direction.
    Unverified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReclaimFailure {
    pub store_id: String,
    pub reason: String,
    pub kind: ReclaimFailureKind,
}

#[derive(Debug, Default)]
pub struct ReclaimReport {
    /// Every stale store found, whether or not it was removed. Populated in
    /// both modes — this is what a dry run reports.
    pub candidates: Vec<ReclaimCandidate>,
    /// True when nothing was deleted because `apply` was not set.
    pub dry_run: bool,
    pub removed: Vec<String>,
    /// Bytes freed by stores this pass removed *completely*. Kept separate from
    /// `bytes_destroyed` so the "reclaimed N store(s), X bytes" line can never
    /// pair a count of zero with a non-zero total.
    pub bytes_freed: u64,
    /// Bytes removed from stores whose delete then failed. Not a success figure.
    pub bytes_destroyed: u64,
    /// Candidates skipped because the origin repo reappeared between the scan
    /// and the delete. Not an error — the store is live again.
    pub revived: Vec<String>,
    /// Candidates that could not be reclaimed. Non-empty means the pass partly
    /// failed; a caller must not report clean success.
    pub failures: Vec<ReclaimFailure>,
    /// Stores skipped because their origin could not be resolved, with the
    /// reason. These are not candidates and were not touched, but they are
    /// reported so a store that is silently never reclaimed is still visible —
    /// an unmounted volume looks exactly like a leak otherwise.
    pub skipped_unknown: Vec<(String, String)>,
}

/// Reclaim whole stores whose origin repo no longer exists (#78).
///
/// This operates on `base` rather than on a `Store`, because a `Store` is
/// constructed from an existing repo path — so `Store::gc` structurally cannot
/// reach the one class of store guaranteed to be dead.
///
/// With `apply` false nothing is deleted; the report lists what would be. One
/// store failing does not abort the pass: the remaining stores are still
/// reclaimed and the failure is recorded in `failed`.
pub fn reclaim_stale_stores(base: &Path, apply: bool) -> Result<ReclaimReport> {
    let root = base.join("reflogless");
    let mut report = ReclaimReport {
        dry_run: !apply,
        ..Default::default()
    };
    for s in list_all_stores(base)? {
        let origin = match &s.state {
            StoreOriginState::Stale(p) => p.clone(),
            // Not proof of death, so not reclaimable. Active is in use. Legacy
            // has no recorded origin at all. Unknown means the probe failed, and
            // a failed probe is not an absent repo (#78).
            StoreOriginState::Unknown { reason, .. } => {
                report
                    .skipped_unknown
                    .push((s.store_id.clone(), reason.clone()));
                continue;
            }
            StoreOriginState::Active(_) | StoreOriginState::Legacy => continue,
        };
        let dir = root.join(&s.store_id);
        let bytes = dir_size(&dir).ok();
        report.candidates.push(ReclaimCandidate {
            store_id: s.store_id.clone(),
            origin: origin.clone(),
            bytes,
            snapshot_count: s.snapshot_count,
            snapshots_unreadable: s.snapshots_unreadable,
        });
        if !apply {
            continue;
        }
        match remove_stale_store(base, &s.store_id, &origin, current_euid()) {
            RemoveOutcome::Removed => {
                report.removed.push(s.store_id.clone());
                report.bytes_freed += bytes.unwrap_or(0);
            }
            RemoveOutcome::Revived => report.revived.push(s.store_id.clone()),
            // Nothing was touched, by construction — the refusal happened before
            // the delete.
            RemoveOutcome::Refused(reason) => report.failures.push(ReclaimFailure {
                store_id: s.store_id.clone(),
                reason,
                kind: ReclaimFailureKind::Intact,
            }),
            RemoveOutcome::DeleteFailed(reason) => {
                // The delete ran, so part of the tree may already be unlinked.
                // Which of the three cases this is has to be established, not
                // assumed: "your snapshots are gone" and "nothing happened, retry"
                // are both damaging when wrong, and the third case — we cannot
                // tell — is a real outcome that must not be rounded to either.
                let residual = dir_size(&dir).ok();
                let kind = match bytes.zip(residual) {
                    Some((before, after)) if after < before => ReclaimFailureKind::PartlyDeleted {
                        bytes_removed: before - after,
                        snapshots_left: count_snapshots(&dir),
                    },
                    Some(_) => ReclaimFailureKind::Intact,
                    // Unmeasurable on one or both sides. Not provably intact and
                    // not provably damaged.
                    None => ReclaimFailureKind::Unverified,
                };
                if let ReclaimFailureKind::PartlyDeleted { bytes_removed, .. } = kind {
                    report.bytes_destroyed += bytes_removed;
                }
                report.failures.push(ReclaimFailure {
                    store_id: s.store_id.clone(),
                    reason,
                    kind,
                });
            }
        }
    }
    Ok(report)
}

/// The shallowest file still present under `dir`, breadth-first — the best
/// available pointer at what blocked a delete. Breadth-first because the
/// remaining entry closest to the root is the most useful thing to name.
fn first_remaining_entry(dir: &Path) -> Option<PathBuf> {
    let mut queue = vec![dir.to_path_buf()];
    let mut subdirs = Vec::new();
    while let Some(d) = queue.pop() {
        let Ok(entries) = fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            match e.metadata() {
                Ok(md) if md.is_dir() => subdirs.push(e.path()),
                Ok(_) => return Some(e.path()),
                Err(_) => return Some(e.path()),
            }
        }
        if queue.is_empty() {
            queue.append(&mut subdirs);
        }
    }
    None
}

/// Manifests still present under `<store>/snapshots`. Counted on the failure
/// path so the report can say how many survived instead of asserting loss it
/// has not checked.
fn count_snapshots(store_dir: &Path) -> usize {
    match fs::read_dir(store_dir.join("snapshots")) {
        Ok(it) => it
            .flatten()
            .filter(|e| manifest_id_from_path(&e.path()).is_some())
            .count(),
        Err(_) => 0,
    }
}

/// What happened to one store in a reclaim pass. `Refused` and `DeleteFailed`
/// are separate because only the latter can have destroyed anything: a refusal
/// is decided before `remove_dir_all` is called.
enum RemoveOutcome {
    Removed,
    /// The origin reappeared before the delete; the store was left alone.
    Revived,
    /// A precondition failed. Nothing was touched.
    Refused(String),
    /// `remove_dir_all` ran and returned an error.
    DeleteFailed(String),
}

/// Delete one store directory. Every precondition is enforced here rather than
/// at the call site so no caller can opt out.
///
/// Invariant: a store directory is removed only when it is a real directory
/// named by a 16-hex store id under `<base>/reflogless`, owned by the current
/// user, and its recorded origin repo is *confirmed absent* at the moment of
/// removal.
///
/// "Confirmed absent" is the load-bearing word. Every precondition here fails
/// closed: anything that cannot be established — the origin probe erroring, the
/// store's metadata being unreadable — refuses the delete rather than proceeding.
///
/// Returns `Revived` when the origin reappeared since the scan: a repo can be
/// restored, re-cloned, or a volume remounted while the pass runs, and the store
/// is then live again.
/// `euid` is passed in rather than read here so the ownership refusal is
/// reachable from a test — the same reason `repo::is_uid_safe` takes both uids
/// instead of calling `geteuid` itself. Production callers pass
/// `repo::current_euid()`.
fn remove_stale_store(base: &Path, store_id: &str, origin: &Path, euid: u32) -> RemoveOutcome {
    if !is_repo_id_dirname(store_id) {
        return RemoveOutcome::Refused(format!("refusing to reclaim {store_id}: not a store id"));
    }
    // The recorded origin is the sole evidence that this store is dead, and it
    // arrives from a file on disk. Re-derive the store id from it: a store id is
    // `sha256(abs repo root)[..8]`, so a faithful origin necessarily hashes back
    // to the directory holding it. Anything else — a hand-edited file, a write
    // truncated mid-flight, or a path mangled by `to_string_lossy` on a
    // non-UTF-8 repo root — is a path this store's repo never had, and a
    // nonexistent path is exactly what looks like proof of death.
    let derived = crate::repo::id_for_root(origin);
    if derived != store_id {
        return RemoveOutcome::Refused(format!(
            "refusing to reclaim {store_id}: recorded origin {} hashes to store id \
             {derived}, so it is not a faithful record of this store's repo",
            origin.display()
        ));
    }
    match origin.try_exists() {
        Ok(false) => {}
        Ok(true) => return RemoveOutcome::Revived,
        // Same reasoning as `classify_origin`: a probe that errors is not a
        // repo that is gone. Without this, the re-check is the identical
        // predicate that classified the store, and so protects against nothing
        // whose cause persists for the length of the pass.
        Err(e) => {
            return RemoveOutcome::Refused(format!(
                "refusing to reclaim {store_id}: cannot determine whether {} exists: {e}",
                origin.display()
            ))
        }
    }
    let dir = base.join("reflogless").join(store_id);
    let md = match fs::symlink_metadata(&dir) {
        Ok(md) => md,
        Err(e) => {
            return RemoveOutcome::Refused(format!(
                "refusing to reclaim {store_id}: cannot stat {}: {e}",
                dir.display()
            ))
        }
    };
    if md.is_symlink() {
        return RemoveOutcome::Refused(format!(
            "refusing to reclaim {store_id}: {} is a symlink, and deleting through it \
             would remove data outside the store directory",
            dir.display()
        ));
    }
    if !md.is_dir() {
        return RemoveOutcome::Refused(format!(
            "refusing to reclaim {store_id}: {} is not a directory",
            dir.display()
        ));
    }
    if let Err(e) = assert_dir_owned_by(&dir, &md, euid) {
        return RemoveOutcome::Refused(format!("refusing to reclaim {store_id}: {e}"));
    }
    match fs::remove_dir_all(&dir) {
        Ok(()) => RemoveOutcome::Removed,
        // `remove_dir_all` returns a bare error with no path, and the blocker is
        // usually a nested entry, not the store root — attributing it to the root
        // sends the user to a directory that is typically fine. Name the entry
        // that is actually still there.
        Err(e) => RemoveOutcome::DeleteFailed(match first_remaining_entry(&dir) {
            Some(blocker) => format!("{e} (still present: {})", blocker.display()),
            None => e.to_string(),
        }),
    }
}

#[cfg(unix)]
fn current_euid() -> u32 {
    crate::repo::current_euid()
}

/// Windows ownership semantics differ; `Repo::assert_safe_ownership` is likewise
/// a no-op there.
#[cfg(not(unix))]
fn current_euid() -> u32 {
    0
}

/// Every other mutating entry point gates on `Repo::assert_safe_ownership`. This
/// is the one destructive path with no repo to ask, so it checks the store
/// directory itself.
#[cfg(unix)]
fn assert_dir_owned_by(dir: &Path, md: &fs::Metadata, euid: u32) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    crate::repo::is_uid_safe(md.uid(), euid, dir)
}

#[cfg(not(unix))]
fn assert_dir_owned_by(_dir: &Path, _md: &fs::Metadata, _euid: u32) -> Result<()> {
    Ok(())
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

    /// `seed_store` with the store id **derived from the origin**, as production
    /// guarantees: a store's directory name is `sha256(abs repo root)[..8]` of the
    /// very path its `repo_origin.txt` records. Any fixture that exercises the
    /// delete path must satisfy that, because `remove_stale_store` now re-derives
    /// the id and refuses a mismatch. Returns the derived id.
    fn seed_store_for(base: &Path, origin: &Path, manifest_ids: &[&str]) -> String {
        let id = crate::repo::id_for_root(origin);
        seed_store(base, &id, Some(origin), manifest_ids, false);
        id
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
        // A relative origin classifies Unknown, so rank 2 gets a fixture too.
        seed_store(
            td.path(),
            "4444444444444444",
            Some(Path::new("rel/repo")),
            &[],
            false,
        );
        let stores = list_all_stores(td.path()).unwrap();
        let states: Vec<&str> = stores
            .iter()
            .map(|s| match &s.state {
                StoreOriginState::Active(_) => "active",
                StoreOriginState::Stale(_) => "stale",
                StoreOriginState::Legacy => "legacy",
                StoreOriginState::Unknown { .. } => "unknown",
            })
            .collect();
        assert_eq!(states, vec!["active", "stale", "unknown", "legacy"]);
    }

    /// The core #78 invariant: a store whose origin repo is gone gets reclaimed,
    /// and neither an active store nor a legacy one is touched. Legacy is the
    /// dangerous case — absence of `repo_origin.txt` tracks install age, not
    /// deadness, so stores in daily use look identical to dead ones.
    #[test]
    fn reclaim_removes_stale_stores_and_never_active_or_legacy() {
        let td = TempDir::new().unwrap();
        let live = td.path().join("live-repo");
        fs::create_dir_all(&live).unwrap();
        let dead = td.path().join("deleted-repo");
        let active_id = seed_store_for(td.path(), &live, &["a"]);
        let stale_id = seed_store_for(td.path(), &dead, &["b"]);
        seed_store(td.path(), "3333333333333333", None, &["c"], false);

        let report = reclaim_stale_stores(td.path(), true).unwrap();
        assert!(!report.dry_run);
        assert_eq!(report.removed, vec![stale_id.clone()]);
        assert!(
            report.failures.is_empty(),
            "unexpected failures: {report:?}"
        );
        assert!(report.revived.is_empty());

        let root = td.path().join("reflogless");
        assert!(root.join(&active_id).exists(), "active was removed");
        assert!(!root.join(&stale_id).exists(), "stale survived");
        assert!(root.join("3333333333333333").exists(), "legacy was removed");
    }

    #[test]
    fn reclaim_dry_run_reports_candidates_without_deleting() {
        let td = TempDir::new().unwrap();
        let dead = td.path().join("deleted-repo");
        seed_store(
            td.path(),
            "4444444444444444",
            Some(&dead),
            &["a", "b"],
            false,
        );

        let report = reclaim_stale_stores(td.path(), false).unwrap();
        assert!(report.dry_run);
        assert_eq!(report.candidates.len(), 1);
        assert_eq!(report.candidates[0].store_id, "4444444444444444");
        assert_eq!(report.candidates[0].origin, dead);
        assert_eq!(report.candidates[0].snapshot_count, 2);
        assert!(
            report.candidates[0].bytes.unwrap_or(0) > 0,
            "size not measured"
        );
        assert!(!report.candidates[0].snapshots_unreadable);
        assert!(report.removed.is_empty());
        assert_eq!(report.bytes_freed, 0);
        assert!(
            td.path()
                .join("reflogless")
                .join("4444444444444444")
                .exists(),
            "dry run deleted the store"
        );
    }

    /// TOCTOU: the origin repo can come back between the scan and the delete
    /// (restored from backup, re-cloned, volume remounted). The re-check lives
    /// inside `remove_stale_store`, so this is what keeps a revived repo's
    /// snapshots from being destroyed by a pass that started moments earlier.
    #[test]
    fn reclaim_skips_a_store_whose_origin_reappeared_before_the_delete() {
        let td = TempDir::new().unwrap();
        let revived = td.path().join("came-back");
        let id = seed_store_for(td.path(), &revived, &["a"]);
        // Scan-time state is Stale; recreate the repo before the delete runs.
        let scanned = list_all_stores(td.path()).unwrap();
        assert!(matches!(scanned[0].state, StoreOriginState::Stale(_)));
        fs::create_dir_all(&revived).unwrap();

        assert!(
            matches!(
                remove_stale_store(td.path(), &id, &revived, current_euid()),
                RemoveOutcome::Revived
            ),
            "removed a store whose repo had come back"
        );
        assert!(td.path().join("reflogless").join(&id).exists());
    }

    #[test]
    fn reclaim_refuses_a_store_id_that_is_not_a_store_id() {
        let td = TempDir::new().unwrap();
        let gone = td.path().join("nope");
        // Traversal shape: hex-only/len-16 is the guard that makes joining the
        // name onto the store root safe.
        match remove_stale_store(td.path(), "../../../etc", &gone, current_euid()) {
            RemoveOutcome::Refused(msg) => assert!(msg.contains("not a store id"), "{msg}"),
            other => panic!("expected a refusal, got {}", outcome_name(&other)),
        }
    }

    fn outcome_name(o: &RemoveOutcome) -> &'static str {
        match o {
            RemoveOutcome::Removed => "Removed",
            RemoveOutcome::Revived => "Revived",
            RemoveOutcome::Refused(_) => "Refused",
            RemoveOutcome::DeleteFailed(_) => "DeleteFailed",
        }
    }

    #[cfg(unix)]
    #[test]
    fn reclaim_refuses_to_delete_through_a_symlinked_store_dir() {
        let td = TempDir::new().unwrap();
        let outside = td.path().join("someone-elses-data");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("precious.txt"), b"keep me").unwrap();
        let root = td.path().join("reflogless");
        fs::create_dir_all(&root).unwrap();
        let gone = td.path().join("deleted-repo");
        let id = crate::repo::id_for_root(&gone);
        std::os::unix::fs::symlink(&outside, root.join(&id)).unwrap();

        match remove_stale_store(td.path(), &id, &gone, current_euid()) {
            // The diagnosis must name the symlink. Falling through to the generic
            // "not a directory" refusal would also be safe but would point the
            // user at the wrong problem.
            RemoveOutcome::Refused(msg) => assert!(
                msg.contains("symlink"),
                "refusal does not identify the symlink: {msg}"
            ),
            other => panic!("expected a refusal, got {}", outcome_name(&other)),
        }
        assert!(
            outside.join("precious.txt").exists(),
            "deleted data outside the store directory"
        );
    }

    /// One unremovable store must not abort the pass — the rest still get
    /// reclaimed, and the failure is reported rather than swallowed.
    #[cfg(unix)]
    #[test]
    fn reclaim_reports_a_failure_without_abandoning_the_remaining_stores() {
        use std::os::unix::fs::PermissionsExt;
        let td = TempDir::new().unwrap();
        let root = td.path().join("reflogless");
        let gone_a = td.path().join("dead-a");
        let gone_b = td.path().join("dead-b");
        let blocked_id = seed_store_for(td.path(), &gone_a, &["a"]);
        let ok_id = seed_store_for(td.path(), &gone_b, &["b"]);
        // Read+execute but not write, at *every* level: each directory is still
        // traversable (so the store scans normally) but nothing inside it can be
        // unlinked, so `remove_dir_all` fails having removed nothing. Locking
        // only the store root is not enough — the walk would descend into a
        // writable `snapshots/` and empty it first, which is the partial case
        // covered by `reclaim_reports_a_partly_deleted_store_as_partly_deleted`.
        let blocked = root.join(&blocked_id);
        fs::set_permissions(blocked.join("snapshots"), fs::Permissions::from_mode(0o500)).unwrap();
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o500)).unwrap();

        let report = reclaim_stale_stores(td.path(), true).unwrap();

        // Restore before any assertion can unwind, or TempDir cleanup fails.
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(blocked.join("snapshots"), fs::Permissions::from_mode(0o700)).unwrap();

        assert_eq!(report.failures.len(), 1, "failure not reported: {report:?}");
        assert_eq!(report.failures[0].store_id, blocked_id);
        assert_eq!(
            report.failures[0].kind,
            ReclaimFailureKind::Intact,
            "nothing was deleted, so this must not claim damage: {report:?}"
        );
        assert_eq!(
            report.removed,
            vec![ok_id],
            "one failure abandoned the remaining stores"
        );
    }

    /// The blocker this PR shipped with: `Path::exists()` returns `false` for
    /// *any* metadata error, so a fully intact repo behind an unreadable parent
    /// directory — an unmounted volume, an offline share, a `chmod` on a parent —
    /// classified as dead and had its snapshots deleted, reporting success.
    ///
    /// The repo here is entirely present. Only its parent is unreadable.
    #[cfg(unix)]
    #[test]
    fn a_live_repo_behind_an_unreadable_parent_is_never_reclaimed() {
        use std::os::unix::fs::PermissionsExt;
        let td = TempDir::new().unwrap();
        let vault = td.path().join("vault");
        let live = vault.join("live-repo");
        fs::create_dir_all(&live).unwrap();
        fs::write(live.join("f.txt"), b"precious").unwrap();
        seed_store(td.path(), "9999999999999999", Some(&live), &["a"], false);

        // Traversal denied on the parent: the repo exists, but no process can
        // confirm it. `exists()` says false; `try_exists()` says "cannot tell".
        fs::set_permissions(&vault, fs::Permissions::from_mode(0o000)).unwrap();
        let scanned = list_all_stores(td.path()).unwrap();
        let report = reclaim_stale_stores(td.path(), true).unwrap();
        fs::set_permissions(&vault, fs::Permissions::from_mode(0o700)).unwrap();

        assert!(
            matches!(scanned[0].state, StoreOriginState::Unknown { .. }),
            "an unreadable parent was read as proof the repo is gone: {:?}",
            scanned[0].state
        );
        assert!(
            report.candidates.is_empty() && report.removed.is_empty(),
            "deleted a live repo's snapshots because its parent was unreadable: {report:?}"
        );
        assert_eq!(
            report.skipped_unknown.len(),
            1,
            "skipped the store without saying so: {report:?}"
        );
        assert!(
            live.join("f.txt").exists(),
            "the repo was there the whole time"
        );
        assert!(td
            .path()
            .join("reflogless")
            .join("9999999999999999")
            .join("snapshots")
            .exists());
    }

    /// The pre-delete re-check must fail closed for the same reason: if it uses
    /// the same predicate that classified the store, it protects only against
    /// causes that vanish mid-pass, which is the rarest case and not the one that
    /// loses data.
    #[cfg(unix)]
    #[test]
    fn the_pre_delete_recheck_refuses_when_the_origin_cannot_be_probed() {
        use std::os::unix::fs::PermissionsExt;
        let td = TempDir::new().unwrap();
        let vault = td.path().join("vault");
        let live = vault.join("live-repo");
        fs::create_dir_all(&live).unwrap();
        let id = seed_store_for(td.path(), &live, &["a"]);

        fs::set_permissions(&vault, fs::Permissions::from_mode(0o000)).unwrap();
        let outcome = remove_stale_store(td.path(), &id, &live, current_euid());
        fs::set_permissions(&vault, fs::Permissions::from_mode(0o700)).unwrap();

        match outcome {
            RemoveOutcome::Refused(msg) => assert!(
                msg.contains("cannot determine whether"),
                "wrong refusal: {msg}"
            ),
            other => panic!(
                "deleted or accepted a store whose origin could not be probed: {}",
                outcome_name(&other)
            ),
        }
        assert!(td
            .path()
            .join("reflogless")
            .join(&id)
            .join("snapshots")
            .exists());
    }

    /// Every other mutating entry point gates on `Repo::assert_safe_ownership`.
    /// This is the only destructive path with no repo to ask, so it must gate on
    /// the store directory itself — a store under someone else's uid is not ours
    /// to delete, however dead its origin looks.
    #[cfg(unix)]
    #[test]
    fn reclaim_refuses_a_store_directory_owned_by_another_user() {
        let td = TempDir::new().unwrap();
        let gone = td.path().join("dead-repo");
        let id = seed_store_for(td.path(), &gone, &["a"]);

        // The fixture is ours; the *check* is what's under test, so pass a uid
        // that is not the owner rather than chowning (which needs root).
        let not_us = 0xdead_beef;
        match remove_stale_store(td.path(), &id, &gone, not_us) {
            RemoveOutcome::Refused(msg) => {
                assert!(msg.contains("owned by uid"), "wrong refusal: {msg}")
            }
            other => panic!("deleted another user's store: {}", outcome_name(&other)),
        }
        assert!(td
            .path()
            .join("reflogless")
            .join(&id)
            .join("snapshots")
            .exists());
    }

    /// `remove_dir_all` can unlink part of a store and then fail. That must be
    /// reported as damage — the original defect called it a no-op ("could not
    /// reclaim", zero bytes), i.e. "fix the cause and retry" when snapshots were
    /// already gone.
    ///
    /// An unwritable `objects/<shard>/` is the production shape: `write_blob`
    /// creates exactly that nesting, and the walk unlinks what it can reach
    /// before hitting the entry it cannot.
    #[cfg(unix)]
    #[test]
    fn reclaim_reports_a_partly_deleted_store_as_damaged_with_a_counted_remainder() {
        use std::os::unix::fs::PermissionsExt;
        let td = TempDir::new().unwrap();
        let gone = td.path().join("dead-repo");
        let id = seed_store_for(td.path(), &gone, &["a", "b"]);
        let dir = td.path().join("reflogless").join(&id);
        let shard = dir.join("objects").join("ab");
        fs::create_dir_all(&shard).unwrap();
        fs::write(shard.join("blob"), vec![0u8; 4096]).unwrap();
        fs::set_permissions(&shard, fs::Permissions::from_mode(0o500)).unwrap();

        let report = reclaim_stale_stores(td.path(), true).unwrap();
        fs::set_permissions(&shard, fs::Permissions::from_mode(0o700)).unwrap();

        assert!(
            report.removed.is_empty(),
            "claimed a successful delete: {report:?}"
        );
        assert_eq!(report.failures.len(), 1, "{report:?}");
        assert_eq!(report.failures[0].store_id, id);
        match report.failures[0].kind {
            ReclaimFailureKind::PartlyDeleted {
                bytes_removed,
                snapshots_left,
            } => {
                assert!(bytes_removed > 0, "damage reported as zero bytes");
                // How many manifests survive is readdir-order dependent, because
                // `remove_dir_all` bails on its first error: reach `snapshots/`
                // before the locked shard and they are gone, reach the shard first
                // and all of them remain. macOS gave 0 here and Linux gave 2, so a
                // hard-coded expectation pins the platform, not the product.
                //
                // The invariant that holds either way is the one the original
                // defect broke: the number the report gives a user must match what
                // they would find if they looked. Counted inline rather than with
                // `count_snapshots` so this cannot pass by the two agreeing while
                // both are wrong; that primitive is pinned directly in
                // `count_snapshots_counts_manifests_on_disk`.
                let on_disk = fs::read_dir(dir.join("snapshots"))
                    .map(|rd| {
                        rd.flatten()
                            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
                            .count()
                    })
                    .unwrap_or(0);
                assert_eq!(
                    snapshots_left, on_disk,
                    "reported remainder disagrees with the filesystem"
                );
                assert_eq!(report.bytes_destroyed, bytes_removed);
            }
            ref other => panic!("a partly-deleted store was not reported as damaged: {other:?}"),
        }
        assert_eq!(
            report.bytes_freed, 0,
            "damage counted as successfully freed space: {report:?}"
        );
    }

    /// `count_snapshots` is what stops the damage report inventing a remainder,
    /// so it has to actually read the directory. A non-zero count is the case the
    /// partial-delete fixture above cannot produce: `remove_dir_all` bails on its
    /// first error, so whether the manifests survive a partial delete depends on
    /// readdir order — which is why the count is pinned here instead.
    #[test]
    fn count_snapshots_counts_manifests_on_disk() {
        let td = TempDir::new().unwrap();
        let dir = td.path().join("store");
        fs::create_dir_all(dir.join("snapshots")).unwrap();
        assert_eq!(count_snapshots(&dir), 0);
        fs::write(dir.join("snapshots").join("a.json"), b"{}").unwrap();
        fs::write(dir.join("snapshots").join("b.json.age"), b"x").unwrap();
        // Not a manifest — must not inflate the count a user reads as "recoverable".
        fs::write(dir.join("snapshots").join("README"), b"x").unwrap();
        assert_eq!(count_snapshots(&dir), 2);
    }

    /// The regression the fix for the above introduced: when the same permission
    /// fault blocks `dir_size` *and* the delete, nothing is removed, but the store
    /// was reported as "partly deleted, snapshots cannot be restored — remove by
    /// hand". Following that advice destroys snapshots the tool merely failed to
    /// read. Unmeasurable is its own answer, not a guess in either direction.
    #[cfg(unix)]
    #[test]
    fn reclaim_reports_an_unmeasurable_failure_as_unverified_not_as_damage() {
        use std::os::unix::fs::PermissionsExt;
        let td = TempDir::new().unwrap();
        let gone = td.path().join("dead-repo");
        let id = seed_store_for(td.path(), &gone, &["a"]);
        let dir = td.path().join("reflogless").join(&id);
        // Write+execute, no read: `dir_size` cannot enumerate it and
        // `remove_dir_all` cannot either, so nothing is deleted and nothing is
        // measurable.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o300)).unwrap();

        let report = reclaim_stale_stores(td.path(), true).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();

        assert_eq!(report.failures.len(), 1, "{report:?}");
        assert_eq!(
            report.failures[0].kind,
            ReclaimFailureKind::Unverified,
            "an unreadable store was reported as damaged: {report:?}"
        );
        assert_eq!(
            report.bytes_destroyed, 0,
            "claimed bytes were destroyed without being able to measure: {report:?}"
        );
        // Nothing was actually touched.
        assert_eq!(count_snapshots(&dir), 1, "a snapshot was lost");
    }

    /// The origin file is the sole evidence a store is dead, and it comes off
    /// disk. A store id is `sha256(abs repo root)[..8]`, so a faithful origin
    /// hashes back to the directory holding it. One that doesn't — hand-edited, a
    /// truncated write, or a path mangled by `to_string_lossy` on a non-UTF-8 repo
    /// root — names a path this repo never had, and a nonexistent path is exactly
    /// what reads as proof of death.
    #[test]
    fn reclaim_refuses_a_store_whose_origin_does_not_hash_to_its_store_id() {
        let td = TempDir::new().unwrap();
        let live = td.path().join("very-much-alive");
        fs::create_dir_all(&live).unwrap();
        // A real store for a live repo, but its origin file has been rewritten to
        // a path that does not exist. Classification says Stale; the store id says
        // this is not that repo's store.
        let id = crate::repo::id_for_root(&live);
        seed_store(
            td.path(),
            &id,
            Some(Path::new("/nonexistent/mangled")),
            &["a"],
            false,
        );

        let report = reclaim_stale_stores(td.path(), true).unwrap();

        assert!(
            report.removed.is_empty(),
            "deleted a store on the word of an unverifiable origin file: {report:?}"
        );
        assert_eq!(report.failures.len(), 1, "{report:?}");
        assert_eq!(report.failures[0].kind, ReclaimFailureKind::Intact);
        assert!(
            report.failures[0].reason.contains("hashes to store id"),
            "wrong refusal: {}",
            report.failures[0].reason
        );
        assert!(td
            .path()
            .join("reflogless")
            .join(&id)
            .join("snapshots")
            .exists());
    }

    /// An empty origin file means a truncated write or an interrupted delete — a
    /// damaged store. Filing it as `Legacy` reports it as a design decision
    /// ("no recorded origin, kept") and hides it forever.
    #[test]
    fn an_empty_origin_file_is_unknown_not_legacy() {
        let td = TempDir::new().unwrap();
        seed_store(
            td.path(),
            "1234123412341234",
            Some(Path::new("   \n\t ")),
            &["a"],
            false,
        );
        let stores = list_all_stores(td.path()).unwrap();
        assert!(
            matches!(
                stores[0].state,
                StoreOriginState::Unknown { origin: None, .. }
            ),
            "wrong state: {:?}",
            stores[0].state
        );
    }

    /// A relative origin resolves against the caller's cwd, and
    /// `gc --stale-stores` dispatches before repo discovery so its cwd is
    /// arbitrary — the same store would read Active or Stale depending on where
    /// the command ran. That is not confirmation of anything.
    #[test]
    fn a_relative_origin_is_unknown_and_never_a_candidate() {
        let td = TempDir::new().unwrap();
        seed_store(
            td.path(),
            "5678567856785678",
            Some(Path::new("some/relative/repo")),
            &["a"],
            false,
        );

        let stores = list_all_stores(td.path()).unwrap();
        let report = reclaim_stale_stores(td.path(), true).unwrap();

        assert!(
            matches!(stores[0].state, StoreOriginState::Unknown { .. }),
            "a cwd-relative origin was treated as authoritative: {:?}",
            stores[0].state
        );
        assert!(report.candidates.is_empty(), "{report:?}");
        assert_eq!(report.skipped_unknown.len(), 1);
    }

    /// A store whose size cannot be measured must not be offered for deletion as
    /// `0 bytes`. This is the consent screen for an irreversible delete, and the
    /// 1.9 GB orphan that motivated #78 is exactly the case that matters.
    #[cfg(unix)]
    #[test]
    fn an_unmeasurable_candidate_reports_no_size_rather_than_zero() {
        use std::os::unix::fs::PermissionsExt;
        let td = TempDir::new().unwrap();
        let gone = td.path().join("dead-repo");
        seed_store(td.path(), "cafecafecafecafe", Some(&gone), &["a"], false);
        let snaps = td
            .path()
            .join("reflogless")
            .join("cafecafecafecafe")
            .join("snapshots");
        fs::set_permissions(&snaps, fs::Permissions::from_mode(0o000)).unwrap();

        let report = reclaim_stale_stores(td.path(), false).unwrap();
        fs::set_permissions(&snaps, fs::Permissions::from_mode(0o700)).unwrap();

        assert_eq!(report.candidates.len(), 1);
        assert!(
            report.candidates[0].bytes.is_none(),
            "an unreadable store reported a concrete size: {report:?}"
        );
        assert!(
            report.candidates[0].snapshots_unreadable,
            "snapshot count is a floor here and must say so: {report:?}"
        );
    }

    /// An unreadable `repo_origin.txt` is not an absent one. Reading it as
    /// `Legacy` would be safe today but silently wrong, and the distinction is
    /// what keeps `store_usage` honest about which stores it cannot classify.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_origin_file_is_unknown_not_legacy() {
        use std::os::unix::fs::PermissionsExt;
        let td = TempDir::new().unwrap();
        let gone = td.path().join("dead-repo");
        seed_store(td.path(), "d00dd00dd00dd00d", Some(&gone), &["a"], false);
        let origin_file = td
            .path()
            .join("reflogless")
            .join("d00dd00dd00dd00d")
            .join(REPO_ORIGIN_FILENAME);
        fs::set_permissions(&origin_file, fs::Permissions::from_mode(0o000)).unwrap();

        let stores = list_all_stores(td.path()).unwrap();
        let usage = store_usage(td.path()).unwrap();
        fs::set_permissions(&origin_file, fs::Permissions::from_mode(0o600)).unwrap();

        assert!(
            matches!(
                stores[0].state,
                StoreOriginState::Unknown { origin: None, .. }
            ),
            "wrong state: {:?}",
            stores[0].state
        );
        assert_eq!(usage.unknown_count, 1);
        assert_eq!(usage.legacy_count, 0, "counted as legacy");
        assert!(usage.unknown_bytes > 0);
    }

    #[test]
    fn store_usage_separates_total_stale_and_legacy_bytes() {
        let td = TempDir::new().unwrap();
        let live = td.path().join("live-repo");
        fs::create_dir_all(&live).unwrap();
        let dead = td.path().join("dead-repo");
        seed_store(td.path(), "aaaaaaaaaaaaaaa1", Some(&live), &["a"], false);
        seed_store(td.path(), "aaaaaaaaaaaaaaa2", Some(&dead), &["b"], false);
        seed_store(td.path(), "aaaaaaaaaaaaaaa3", None, &["c"], false);

        let u = store_usage(td.path()).unwrap();
        assert_eq!(u.store_count, 3);
        assert_eq!(u.stale_count, 1);
        assert_eq!(u.legacy_count, 1);
        assert!(u.unreadable.is_empty());
        assert!(u.stale_bytes > 0 && u.legacy_bytes > 0);
        // Totals include active stores, so the total must exceed either class.
        assert!(u.total_bytes > u.stale_bytes + u.legacy_bytes);
    }

    #[test]
    fn store_usage_is_empty_when_no_stores_exist() {
        let td = TempDir::new().unwrap();
        assert_eq!(store_usage(td.path()).unwrap(), StoreUsage::default());
    }

    /// A store containing a symlink to a big tree elsewhere must not report that
    /// tree's bytes as its own — the figure is presented to the user as
    /// reclaimable space.
    #[cfg(unix)]
    #[test]
    fn dir_size_does_not_follow_symlinks_out_of_the_tree() {
        let td = TempDir::new().unwrap();
        let outside = td.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("big"), vec![0u8; 4096]).unwrap();
        let inside = td.path().join("inside");
        fs::create_dir_all(&inside).unwrap();
        fs::write(inside.join("small"), b"xy").unwrap();
        std::os::unix::fs::symlink(&outside, inside.join("link")).unwrap();

        let n = dir_size(&inside).unwrap();
        assert!(
            n < 4096,
            "counted the symlink target's bytes ({n}) as store bytes"
        );
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
