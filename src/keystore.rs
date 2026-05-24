use crate::crypto::{identity_to_string, parse_identity};
use crate::error::{Error, Result};
use age::x25519::Identity;
use std::fs;
use std::path::{Path, PathBuf};

pub const KEYCHAIN_SERVICE: &str = "gitsafe";

pub trait KeyStore {
    fn save(&self, repo_id: &str, identity: &Identity) -> Result<()>;
    fn load(&self, repo_id: &str) -> Result<Identity>;
    fn delete(&self, repo_id: &str) -> Result<()>;
    fn kind(&self) -> &'static str;
}

pub struct KeychainStore;

impl KeyStore for KeychainStore {
    fn save(&self, repo_id: &str, identity: &Identity) -> Result<()> {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, repo_id)
            .map_err(|e| Error::Keychain(format!("opening entry: {e}")))?;
        entry
            .set_password(&identity_to_string(identity))
            .map_err(|e| Error::Keychain(format!("setting password: {e}")))?;
        Ok(())
    }

    fn load(&self, repo_id: &str) -> Result<Identity> {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, repo_id)
            .map_err(|e| Error::Keychain(format!("opening entry: {e}")))?;
        let s = entry
            .get_password()
            .map_err(|e| Error::Keychain(format!("reading password: {e}")))?;
        parse_identity(&s)
    }

    fn delete(&self, repo_id: &str) -> Result<()> {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, repo_id)
            .map_err(|e| Error::Keychain(format!("opening entry: {e}")))?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(Error::Keychain(format!("deleting: {e}"))),
        }
    }

    fn kind(&self) -> &'static str {
        "keychain"
    }
}

pub struct FileStore {
    pub path: PathBuf,
}

impl FileStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl KeyStore for FileStore {
    fn save(&self, _repo_id: &str, identity: &Identity) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
        }
        fs::write(&self.path, identity_to_string(identity))
            .map_err(|e| Error::io(&self.path, e))?;
        set_file_perms(&self.path)?;
        Ok(())
    }

    fn load(&self, _repo_id: &str) -> Result<Identity> {
        let s = fs::read_to_string(&self.path).map_err(|e| Error::io(&self.path, e))?;
        parse_identity(&s)
    }

    fn delete(&self, _repo_id: &str) -> Result<()> {
        if self.path.exists() {
            fs::remove_file(&self.path).map_err(|e| Error::io(&self.path, e))?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "file (insecure)"
    }
}

#[cfg(unix)]
fn set_file_perms(p: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(0o600))
        .map_err(|e| Error::io(p, e))
}

#[cfg(not(unix))]
fn set_file_perms(_p: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_identity;
    use tempfile::TempDir;

    #[test]
    fn file_store_roundtrip() {
        let td = TempDir::new().unwrap();
        let store = FileStore::new(td.path().join("identity.key"));
        let id = generate_identity();
        store.save("repo-id", &id).unwrap();
        let loaded = store.load("repo-id").unwrap();
        assert_eq!(identity_to_string(&loaded), identity_to_string(&id));
    }

    #[cfg(unix)]
    #[test]
    fn file_store_permissions_are_0600() {
        use std::os::unix::fs::PermissionsExt;
        let td = TempDir::new().unwrap();
        let path = td.path().join("identity.key");
        let store = FileStore::new(&path);
        store.save("repo-id", &generate_identity()).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode={:o}", mode);
    }

    #[test]
    fn file_store_delete_is_idempotent() {
        let td = TempDir::new().unwrap();
        let store = FileStore::new(td.path().join("identity.key"));
        store.save("repo-id", &generate_identity()).unwrap();
        store.delete("repo-id").unwrap();
        store.delete("repo-id").unwrap();
    }
}
