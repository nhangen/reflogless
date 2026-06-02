//! Per-store remote backend configuration. Lives at `<store-root>/remote.toml`
//! so the user's `.reflogless.toml` stays a hand-edited file and the CLI owns
//! a separate machine-edited file.

use crate::store::Store;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub const REMOTE_CONFIG_FILENAME: &str = "remote.toml";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteConfig {
    pub bucket: String,
    pub region: String,
    /// Custom endpoint URL — set this for MinIO / LocalStack / non-AWS S3
    /// servers. `None` means use AWS S3 public endpoints for the given region.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Path-style addressing (`<host>/<bucket>/<key>`). Required for most
    /// non-AWS endpoints since virtual-hosted style needs wildcard DNS.
    #[serde(default)]
    pub path_style: bool,
    /// Object-key prefix under the bucket — typically `<hostname>/` so two
    /// machines backing up to the same bucket don't collide in the manifest
    /// listing (blobs dedupe automatically via content-addressing; manifests
    /// don't).
    pub key_prefix: String,
}

impl RemoteConfig {
    pub fn path(store: &Store) -> PathBuf {
        store.root.join(REMOTE_CONFIG_FILENAME)
    }

    pub fn load(store: &Store) -> Result<Option<Self>> {
        let p = Self::path(store);
        let body = match fs::read_to_string(&p) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error::io(&p, e)),
        };
        let cfg: Self =
            toml::from_str(&body).map_err(|e| Error::Config(format!("{}: {e}", p.display())))?;
        Ok(Some(cfg))
    }

    pub fn save(&self, store: &Store) -> Result<()> {
        let p = Self::path(store);
        let body = toml::to_string_pretty(self)
            .map_err(|e| Error::Config(format!("serialize remote config: {e}")))?;
        crate::store::atomic_write(&p, body.as_bytes())
    }

    pub fn remove(store: &Store) -> Result<bool> {
        let p = Self::path(store);
        match fs::remove_file(&p) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Error::io(&p, e)),
        }
    }

    pub fn s3_url(&self) -> String {
        if self.key_prefix.is_empty() {
            format!("s3://{}", self.bucket)
        } else {
            let trimmed = self.key_prefix.trim_end_matches('/');
            format!("s3://{}/{}", self.bucket, trimmed)
        }
    }
}

/// Parse an `s3://bucket[/path]` URL into a (bucket, base_prefix) pair.
/// `base_prefix` is the portion AFTER the bucket name, normalized without
/// leading/trailing slashes (the caller appends the per-host segment).
///
/// Rejects: missing scheme, empty bucket, embedded `..` segments.
pub fn parse_s3_url(url: &str) -> Result<(String, String)> {
    let rest = url.strip_prefix("s3://").ok_or_else(|| {
        Error::Config(format!(
            "remote url {url:?} must start with s3:// (e.g. s3://my-bucket/optional/prefix)"
        ))
    })?;
    let mut parts = rest.splitn(2, '/');
    let bucket = parts.next().unwrap_or("");
    let prefix = parts.next().unwrap_or("");
    if bucket.is_empty() {
        return Err(Error::Config(format!("remote url {url:?} has no bucket")));
    }
    let prefix = prefix.trim_matches('/');
    for segment in prefix.split('/') {
        if segment == ".." {
            return Err(Error::Config(format!(
                "remote url {url:?} contains a `..` segment"
            )));
        }
    }
    Ok((bucket.to_string(), prefix.to_string()))
}

/// Resolve the per-host portion of the key prefix. Uses the system hostname
/// when available; falls back to `unknown-host`. Sanitized to safe S3 chars.
pub fn hostname_segment() -> String {
    let raw = hostname().unwrap_or_else(|| "unknown-host".to_string());
    sanitize_segment(&raw)
}

fn hostname() -> Option<String> {
    if let Ok(h) = std::env::var("HOSTNAME") {
        if !h.is_empty() {
            return Some(h);
        }
    }
    let out = std::process::Command::new("hostname").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let raw = String::from_utf8(out.stdout).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Make a string safe to drop into an S3 key prefix. S3 itself permits most
/// characters, but `/`, leading dots, and shell-special chars cause friction
/// in URLs and logs. Conservative whitelist: ASCII alphanumerics, `-`, `_`.
fn sanitize_segment(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('-');
    if trimmed.is_empty() {
        "host".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Compose the final key prefix for a remote config: `<base>/<host>/` (or
/// just `<host>/` when no base). Trailing slash is enforced.
pub fn compose_key_prefix(base: &str, host: &str) -> String {
    let base = base.trim_matches('/');
    if base.is_empty() {
        format!("{host}/")
    } else {
        format!("{base}/{host}/")
    }
}

/// Render a tiny user-facing string for `remote status` and friends.
pub fn render_status_line(cfg: Option<&RemoteConfig>) -> String {
    match cfg {
        Some(c) => format!(
            "enabled ({}, region={}{})",
            c.s3_url(),
            c.region,
            if let Some(ep) = &c.endpoint {
                format!(", endpoint={ep}")
            } else {
                String::new()
            }
        ),
        None => "disabled".to_string(),
    }
}

/// True iff a remote config file exists at the conventional path. Used by
/// snap-time wiring to skip the `append_pending` call cheaply when no remote
/// is configured (avoids reading + parsing TOML on the hot path).
pub fn is_configured(store_root: &Path) -> bool {
    store_root.join(REMOTE_CONFIG_FILENAME).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bucket_only() {
        let (b, p) = parse_s3_url("s3://my-bucket").unwrap();
        assert_eq!(b, "my-bucket");
        assert_eq!(p, "");
    }

    #[test]
    fn parse_bucket_plus_prefix() {
        let (b, p) = parse_s3_url("s3://my-bucket/some/prefix").unwrap();
        assert_eq!(b, "my-bucket");
        assert_eq!(p, "some/prefix");
    }

    #[test]
    fn parse_trims_slashes() {
        let (_b, p) = parse_s3_url("s3://my-bucket/some/prefix/").unwrap();
        assert_eq!(p, "some/prefix");
    }

    #[test]
    fn parse_rejects_non_s3_scheme() {
        assert!(parse_s3_url("https://my-bucket").is_err());
        assert!(parse_s3_url("my-bucket").is_err());
    }

    #[test]
    fn parse_rejects_empty_bucket() {
        assert!(parse_s3_url("s3:///just-prefix").is_err());
    }

    #[test]
    fn parse_rejects_parent_dir_segments() {
        assert!(parse_s3_url("s3://b/foo/../bar").is_err());
    }

    #[test]
    fn sanitize_replaces_unsafe_chars() {
        assert_eq!(sanitize_segment("alice.local"), "alice-local");
        assert_eq!(sanitize_segment("Some Host"), "Some-Host");
        assert_eq!(sanitize_segment("host/with/slash"), "host-with-slash");
        assert_eq!(sanitize_segment(""), "host");
        assert_eq!(sanitize_segment("...."), "host");
        assert_eq!(sanitize_segment("-leading-trailing-"), "leading-trailing");
    }

    #[test]
    fn compose_with_base() {
        assert_eq!(compose_key_prefix("env/prod", "alice"), "env/prod/alice/");
    }

    #[test]
    fn compose_without_base() {
        assert_eq!(compose_key_prefix("", "alice"), "alice/");
        assert_eq!(compose_key_prefix("/", "alice"), "alice/");
    }

    #[test]
    fn config_roundtrip_with_endpoint() {
        let cfg = RemoteConfig {
            bucket: "mb".to_string(),
            region: "us-east-1".to_string(),
            endpoint: Some("http://localhost:9000".to_string()),
            path_style: true,
            key_prefix: "alice/".to_string(),
        };
        let body = toml::to_string_pretty(&cfg).unwrap();
        let parsed: RemoteConfig = toml::from_str(&body).unwrap();
        assert_eq!(cfg, parsed);
    }

    #[test]
    fn config_roundtrip_without_endpoint() {
        let cfg = RemoteConfig {
            bucket: "mb".to_string(),
            region: "us-east-1".to_string(),
            endpoint: None,
            path_style: false,
            key_prefix: "alice/".to_string(),
        };
        let body = toml::to_string_pretty(&cfg).unwrap();
        let parsed: RemoteConfig = toml::from_str(&body).unwrap();
        assert_eq!(cfg, parsed);
    }

    #[test]
    fn s3_url_renders() {
        let cfg = RemoteConfig {
            bucket: "mb".to_string(),
            region: "us-east-1".to_string(),
            endpoint: None,
            path_style: false,
            key_prefix: "alice/".to_string(),
        };
        assert_eq!(cfg.s3_url(), "s3://mb/alice");
    }

    #[test]
    fn s3_url_renders_no_prefix() {
        let cfg = RemoteConfig {
            bucket: "mb".to_string(),
            region: "us-east-1".to_string(),
            endpoint: None,
            path_style: false,
            key_prefix: "".to_string(),
        };
        assert_eq!(cfg.s3_url(), "s3://mb");
    }

    #[test]
    fn status_line_enabled_and_disabled() {
        let cfg = RemoteConfig {
            bucket: "mb".to_string(),
            region: "us-east-1".to_string(),
            endpoint: None,
            path_style: false,
            key_prefix: "alice/".to_string(),
        };
        assert!(render_status_line(Some(&cfg)).contains("enabled"));
        assert_eq!(render_status_line(None), "disabled");
    }
}
