use crate::error::{Error, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct Repo {
    pub root: PathBuf,
}

impl Repo {
    pub fn discover(start: &Path) -> Result<Self> {
        let mut cur = start.canonicalize().map_err(|e| Error::io(start, e))?;
        loop {
            if cur.join(".git").exists() {
                return Ok(Repo { root: cur });
            }
            match cur.parent() {
                Some(p) => cur = p.to_path_buf(),
                None => return Err(Error::NotARepo(start.to_path_buf())),
            }
        }
    }

    pub fn id(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.root.to_string_lossy().as_bytes());
        let digest = h.finalize();
        hex::encode_short(&digest[..8])
    }

    /// Refuse to operate on a repo owned by another user.
    ///
    /// On unix, compares `repo.root`'s owner uid against the current effective
    /// uid. Returns `Error::UnsafeOwnership` if they differ. No-op on non-unix
    /// (Windows ownership semantics differ; future work).
    #[cfg(unix)]
    pub fn assert_safe_ownership(&self) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let md = std::fs::metadata(&self.root).map_err(|e| Error::io(&self.root, e))?;
        is_uid_safe(md.uid(), unsafe { libc_geteuid() }, &self.root)
    }

    #[cfg(not(unix))]
    pub fn assert_safe_ownership(&self) -> Result<()> {
        Ok(())
    }

    /// Resolve the actual `.git` directory, honoring worktree gitfiles.
    ///
    /// For a primary worktree, `repo.root/.git` is a directory. For a linked
    /// worktree (`git worktree add`), it is a file containing `gitdir: <path>`
    /// pointing at `main-clone/.git/worktrees/<name>/`. We need the resolved
    /// path so `is_git_busy` checks fire against the correct rebase/merge state.
    pub fn git_dir(&self) -> PathBuf {
        let g = self.root.join(".git");
        if let Ok(meta) = std::fs::metadata(&g) {
            if meta.is_file() {
                if let Ok(content) = std::fs::read_to_string(&g) {
                    for line in content.lines() {
                        if let Some(rest) = line.strip_prefix("gitdir:") {
                            let p = PathBuf::from(rest.trim());
                            if p.is_absolute() {
                                return p;
                            }
                            return self.root.join(p);
                        }
                    }
                }
            }
        }
        g
    }

    /// Resolve the git **common** directory — the one shared by every worktree of
    /// a clone.
    ///
    /// This is not the same as [`Self::git_dir`], and the difference decides where
    /// hooks live. Git splits its admin state in two: per-worktree state (rebase
    /// and merge progress, `index.lock`, `HEAD`) lives in the *git dir*, while
    /// `hooks`, `config`, and `refs` live in the *common* dir. `hooks` is on git's
    /// common list, so a linked worktree runs the **main clone's** hooks —
    /// `main/.git/hooks`, never `main/.git/worktrees/<name>/hooks`.
    ///
    /// Verified: with a hook planted in both directories, two checkouts inside a
    /// linked worktree fired the common-dir copy twice and the per-worktree copy
    /// zero times.
    ///
    /// Falls back to [`Self::git_dir`] when git can't be asked, which is correct
    /// for a primary worktree (there the two are the same directory).
    pub fn git_common_dir(&self) -> PathBuf {
        let out = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(["rev-parse", "--git-common-dir"])
            .output();
        if let Ok(o) = out {
            if o.status.success() {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if !s.is_empty() {
                    let p = PathBuf::from(&s);
                    // git may answer relatively (plain `.git`) depending on cwd.
                    return if p.is_absolute() {
                        p
                    } else {
                        self.root.join(p)
                    };
                }
            }
        }
        self.git_dir()
    }

    /// Returns `Some(reason)` if git is mid-operation and a snap right now
    /// would capture transient half-applied state (conflict markers, rebase
    /// scratch). Hooks/shim/watcher all skip snap when this fires. See #40.
    pub fn git_busy(&self) -> Option<String> {
        let g = self.git_dir();
        const SIGNALS: &[(&str, &str)] = &[
            ("rebase-merge", "interactive rebase in progress"),
            ("rebase-apply", "non-interactive rebase in progress"),
            ("MERGE_HEAD", "merge in progress"),
            ("CHERRY_PICK_HEAD", "cherry-pick in progress"),
            ("REVERT_HEAD", "revert in progress"),
            ("BISECT_LOG", "bisect in progress"),
            ("index.lock", "another git process holds index.lock"),
        ];
        for (path, reason) in SIGNALS {
            if g.join(path).exists() {
                return Some((*reason).to_string());
            }
        }
        None
    }

    pub fn status_porcelain(&self) -> Result<Vec<StatusEntry>> {
        let out = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(["status", "--porcelain=v1", "-uall", "-z"])
            .output()
            .map_err(|e| Error::Git(format!("invoking git status: {e}")))?;
        if !out.status.success() {
            return Err(Error::Git(
                String::from_utf8_lossy(&out.stderr).into_owned(),
            ));
        }
        Ok(parse_porcelain_z(&out.stdout))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusEntry {
    pub xy: [u8; 2],
    pub path: PathBuf,
}

impl StatusEntry {
    pub fn is_untracked(&self) -> bool {
        self.xy == *b"??"
    }

    pub fn is_modified_unstaged(&self) -> bool {
        self.xy[1] == b'M'
    }

    pub fn snapshottable(&self) -> bool {
        self.is_untracked() || self.is_modified_unstaged()
    }
}

fn parse_porcelain_z(buf: &[u8]) -> Vec<StatusEntry> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        if buf.len() - i < 3 {
            break;
        }
        let xy = [buf[i], buf[i + 1]];
        // buf[i + 2] is ' '
        let mut end = i + 3;
        while end < buf.len() && buf[end] != 0 {
            end += 1;
        }
        let path = PathBuf::from(std::str::from_utf8(&buf[i + 3..end]).unwrap_or(""));
        // Renames and copies have an extra NUL-terminated origin path; skip
        // both for v1 — only untracked + modified-unstaged contribute to snaps.
        if matches!(xy[0], b'R' | b'C') || matches!(xy[1], b'R' | b'C') {
            let mut end2 = end + 1;
            while end2 < buf.len() && buf[end2] != 0 {
                end2 += 1;
            }
            i = end2 + 1;
            continue;
        }
        out.push(StatusEntry { xy, path });
        i = end + 1;
    }
    out
}

#[cfg(unix)]
extern "C" {
    fn geteuid() -> u32;
}

#[cfg(unix)]
unsafe fn libc_geteuid() -> u32 {
    geteuid()
}

/// Pure helper extracted from `assert_safe_ownership` so the safety invariant
/// is exercised without needing a real chown'd fixture in tests.
#[cfg(unix)]
fn is_uid_safe(owner: u32, me: u32, root: &Path) -> Result<()> {
    if owner != me {
        return Err(Error::UnsafeOwnership(format!(
            "repo {} is owned by uid {owner}, but current uid is {me}",
            root.display()
        )));
    }
    Ok(())
}

mod hex {
    pub fn encode_short(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_untracked_only() {
        let buf = b"?? foo.txt\x00 M bar.txt\x00";
        let entries = parse_porcelain_z(buf);
        assert_eq!(entries.len(), 2);
        assert!(entries[0].is_untracked());
        assert!(entries[1].is_modified_unstaged());
        assert_eq!(entries[0].path, PathBuf::from("foo.txt"));
    }

    #[test]
    fn skips_renames() {
        let buf = b"R  new.txt\x00old.txt\x00?? other.txt\x00";
        let entries = parse_porcelain_z(buf);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, PathBuf::from("other.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn is_uid_safe_accepts_matching_owner() {
        let p = PathBuf::from("/tmp/x");
        assert!(is_uid_safe(501, 501, &p).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn is_uid_safe_rejects_uid_mismatch() {
        let p = PathBuf::from("/tmp/foreign");
        match is_uid_safe(0, 501, &p) {
            Err(Error::UnsafeOwnership(msg)) => {
                assert!(msg.contains("/tmp/foreign"));
                assert!(msg.contains("uid 0"));
                assert!(msg.contains("uid is 501"));
            }
            other => panic!("expected UnsafeOwnership, got {other:?}"),
        }
    }

    #[test]
    fn skips_copies() {
        let buf = b"C  copy.txt\x00src.txt\x00?? after.txt\x00";
        let entries = parse_porcelain_z(buf);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, PathBuf::from("after.txt"));
    }

    #[test]
    fn git_busy_returns_none_on_clean_repo() {
        let td = tempfile::TempDir::new().unwrap();
        std::process::Command::new("git")
            .arg("init")
            .arg("-q")
            .arg(td.path())
            .status()
            .unwrap();
        let repo = Repo::discover(td.path()).unwrap();
        assert!(repo.git_busy().is_none());
    }

    #[test]
    fn git_busy_detects_each_signal() {
        for (file, expected) in [
            ("rebase-merge", "interactive rebase"),
            ("rebase-apply", "non-interactive rebase"),
            ("MERGE_HEAD", "merge"),
            ("CHERRY_PICK_HEAD", "cherry-pick"),
            ("REVERT_HEAD", "revert"),
            ("BISECT_LOG", "bisect"),
            ("index.lock", "index.lock"),
        ] {
            let td = tempfile::TempDir::new().unwrap();
            std::process::Command::new("git")
                .arg("init")
                .arg("-q")
                .arg(td.path())
                .status()
                .unwrap();
            let repo = Repo::discover(td.path()).unwrap();
            // rebase-merge/rebase-apply are directories; the rest are files.
            let target = repo.git_dir().join(file);
            if file.starts_with("rebase-") {
                std::fs::create_dir_all(&target).unwrap();
            } else {
                std::fs::write(&target, b"").unwrap();
            }
            let reason = repo.git_busy().expect("expected git_busy to fire");
            assert!(
                reason.contains(expected),
                "for {file}, expected reason to mention {expected:?}, got {reason:?}"
            );
        }
    }

    #[test]
    fn git_dir_resolves_worktree_gitfile() {
        let td = tempfile::TempDir::new().unwrap();
        let wt = td.path().join("wt");
        let real_gitdir = td.path().join("main/.git/worktrees/wt");
        std::fs::create_dir_all(&wt).unwrap();
        std::fs::create_dir_all(&real_gitdir).unwrap();
        std::fs::write(
            wt.join(".git"),
            format!("gitdir: {}\n", real_gitdir.display()),
        )
        .unwrap();
        let repo = Repo::discover(&wt).unwrap();
        assert_eq!(repo.git_dir(), real_gitdir);
    }
}
