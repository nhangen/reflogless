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

    pub fn status_porcelain(&self) -> Result<Vec<StatusEntry>> {
        let out = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(["status", "--porcelain=v1", "-uall", "-z"])
            .output()
            .map_err(|e| Error::Git(format!("invoking git status: {e}")))?;
        if !out.status.success() {
            return Err(Error::Git(String::from_utf8_lossy(&out.stderr).into_owned()));
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
        self.xy == [b'?', b'?']
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
}
