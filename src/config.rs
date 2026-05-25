use crate::error::{Error, Result};
use serde::Deserialize;
use std::fs;
use std::path::Path;

pub const CONFIG_FILENAME: &str = ".reflogless.toml";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum EncryptPolicy {
    /// Encrypt files matching secret-shaped patterns. Default.
    #[serde(rename = "secrets")]
    Secrets,
    /// Encrypt every blob and the manifest.
    #[serde(rename = "all")]
    All,
    /// Skip encryption for non-secret blobs. Secret-shaped paths are still
    /// encrypted. Renamed from `None` so it doesn't shadow `Option::None`
    /// in pattern matches across the crate.
    #[serde(rename = "none")]
    Off,
}

impl Default for EncryptPolicy {
    fn default() -> Self {
        EncryptPolicy::Secrets
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub encrypt: EncryptPolicy,
}

impl Config {
    /// Load `.reflogless.toml` from the repo root. Missing file returns defaults.
    /// Parse errors propagate as `Error::Config`.
    pub fn load_or_default(repo_root: &Path) -> Result<Self> {
        let path = repo_root.join(CONFIG_FILENAME);
        if !path.exists() {
            return Ok(Self::default());
        }
        let body = fs::read_to_string(&path).map_err(|e| Error::io(&path, e))?;
        toml::from_str(&body).map_err(|e| Error::Config(format!("{}: {e}", path.display())))
    }
}

/// Filename patterns that are always encrypted regardless of `encrypt` setting.
/// Matched case-insensitively against the path's filename only.
const SECRET_PATTERNS: &[&str] = &[
    ".env",        // matches .env, .env.production, .env.local, etc. (prefix)
    "id_rsa",      // matches id_rsa, id_rsa_prod, id_rsa.pub
    "id_ecdsa",    // matches id_ecdsa*
    "id_ed25519",  // matches id_ed25519*
    "id_dsa",      // matches id_dsa*
];

const SECRET_EXTENSIONS: &[&str] = &["pem", "key", "p12", "pfx", "jks", "asc", "gpg"];

/// True iff the path's basename matches any secret-shaped pattern.
pub fn is_secret_shaped(path: &Path) -> bool {
    let name = match path.file_name().and_then(|s| s.to_str()) {
        Some(n) => n.to_ascii_lowercase(),
        None => return false,
    };
    // Public-key files (id_rsa.pub, id_ed25519.pub) share the SSH prefix but
    // are not secrets — skip the prefix check for them so we don't burn
    // encryption overhead on data that's already in `gh ssh-key list`.
    let is_pub_key = name.ends_with(".pub");
    if !is_pub_key {
        for pat in SECRET_PATTERNS {
            if name.starts_with(pat) {
                return true;
            }
        }
    }
    if let Some(ext) = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
    {
        if SECRET_EXTENSIONS.iter().any(|e| *e == ext) {
            return true;
        }
    }
    false
}

/// Resolve whether a given path should be encrypted given the configured policy.
/// Secret-shaped paths are always encrypted (overriding `none`).
pub fn should_encrypt(path: &Path, policy: EncryptPolicy) -> bool {
    if is_secret_shaped(path) {
        return true;
    }
    matches!(policy, EncryptPolicy::All)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn default_policy_is_secrets() {
        assert_eq!(EncryptPolicy::default(), EncryptPolicy::Secrets);
    }

    #[test]
    fn load_missing_returns_default() {
        let td = TempDir::new().unwrap();
        let cfg = Config::load_or_default(td.path()).unwrap();
        assert_eq!(cfg.encrypt, EncryptPolicy::Secrets);
    }

    #[test]
    fn load_parses_all() {
        let td = TempDir::new().unwrap();
        fs::write(td.path().join(CONFIG_FILENAME), "encrypt = \"all\"\n").unwrap();
        let cfg = Config::load_or_default(td.path()).unwrap();
        assert_eq!(cfg.encrypt, EncryptPolicy::All);
    }

    #[test]
    fn load_parses_none() {
        let td = TempDir::new().unwrap();
        fs::write(td.path().join(CONFIG_FILENAME), "encrypt = \"none\"\n").unwrap();
        let cfg = Config::load_or_default(td.path()).unwrap();
        assert_eq!(cfg.encrypt, EncryptPolicy::Off);
    }

    #[test]
    fn load_rejects_unknown_policy() {
        let td = TempDir::new().unwrap();
        fs::write(td.path().join(CONFIG_FILENAME), "encrypt = \"sometimes\"\n").unwrap();
        assert!(matches!(
            Config::load_or_default(td.path()),
            Err(Error::Config(_))
        ));
    }

    #[test]
    fn secret_shaped_paths_detected() {
        for p in &[
            ".env",
            ".env.production",
            ".env.local",
            ".ENV",
            "ID_RSA",
            "id_rsa",
            "id_rsa_prod",
            "id_ed25519",
            "key.pem",
            "cert.PEM",
            "deploy.key",
            "secrets.GPG",
            "client-cert.p12",
            "windows-cert.pfx",
            "android.jks",
            "signature.asc",
        ] {
            assert!(is_secret_shaped(Path::new(p)), "expected secret-shaped: {p}");
        }
    }

    #[test]
    fn non_secret_paths_not_detected() {
        for p in &[
            "README.md",
            "src/main.rs",
            "config.yaml",
            "notes.txt",
            "customers.sql",
            // Public keys share the id_* prefix but are not secrets.
            "id_rsa.pub",
            "id_ed25519.pub",
        ] {
            assert!(
                !is_secret_shaped(Path::new(p)),
                "expected NOT secret-shaped: {p}"
            );
        }
    }

    #[test]
    fn should_encrypt_secret_paths_under_none_policy() {
        assert!(should_encrypt(Path::new(".env.production"), EncryptPolicy::Off));
        assert!(should_encrypt(Path::new("id_rsa"), EncryptPolicy::Off));
    }

    #[test]
    fn should_encrypt_all_policy_encrypts_everything() {
        assert!(should_encrypt(Path::new("README.md"), EncryptPolicy::All));
    }

    #[test]
    fn should_encrypt_secrets_policy_only_encrypts_secrets() {
        assert!(!should_encrypt(Path::new("README.md"), EncryptPolicy::Secrets));
        assert!(should_encrypt(Path::new(".env"), EncryptPolicy::Secrets));
    }
}
