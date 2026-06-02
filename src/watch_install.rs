//! Filesystem-watcher daemon installer (slices 5 + 6 of #30).
//!
//! Wires the `reflogless watch run` daemon into a per-user supervisor so it
//! starts on login and restarts on failure. macOS uses `launchd` via a
//! LaunchAgent plist (slice 5); Linux uses `systemd --user` via a unit file
//! at `~/.config/systemd/user/` (slice 6).
//!
//! User-facing CLI:
//!
//! - `reflogless watch install` — write the unit/plist + load with the
//!   supervisor. Daemon starts immediately and persists across reboots.
//! - `reflogless watch uninstall` — unload from the supervisor + remove the
//!   unit/plist file. Daemon stops permanently until re-installed.
//!
//! Both `install` + `uninstall` only. launchd and systemd both conflate
//! "stop running" with "remove registration"; a separate `start`/`stop`
//! UX (toggle without re-bootstrapping) is a deferred enhancement.

use crate::error::{Error, Result};
use crate::repo::Repo;
use crate::store::Store;
use std::path::PathBuf;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::process::Command;

/// Outcome of an install or uninstall operation. Both fields populated so the
/// caller can print a useful next-step message.
#[derive(Debug)]
pub struct InstallReport {
    pub unit_path: PathBuf,
    pub label: String,
}

#[cfg(target_os = "macos")]
pub fn install(repo: &Repo, store: &Store) -> Result<InstallReport> {
    macos::install(repo, store)
}

#[cfg(target_os = "macos")]
pub fn uninstall(repo: &Repo, store: &Store) -> Result<InstallReport> {
    macos::uninstall(repo, store)
}

#[cfg(target_os = "linux")]
pub fn install(repo: &Repo, store: &Store) -> Result<InstallReport> {
    linux::install(repo, store)
}

#[cfg(target_os = "linux")]
pub fn uninstall(repo: &Repo, store: &Store) -> Result<InstallReport> {
    linux::uninstall(repo, store)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn install(_repo: &Repo, _store: &Store) -> Result<InstallReport> {
    Err(Error::Config(
        "watch install: only macOS launchd is implemented; Linux systemd is #30 \
         slice 6; Windows is out of scope."
            .into(),
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn uninstall(_repo: &Repo, _store: &Store) -> Result<InstallReport> {
    Err(Error::Config(
        "watch uninstall: only macOS launchd is implemented.".into(),
    ))
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::fs;
    use std::io::Write;

    /// Stable label per repo: `com.nhangen.reflogless.<repo_id>` where repo_id
    /// is the 16-hex-char store id (same as `Store::for_repo`'s store dir name).
    pub fn label_for(repo: &Repo) -> String {
        format!("com.nhangen.reflogless.{}", repo.id())
    }

    /// Path to the per-user LaunchAgent plist for this repo's watcher.
    pub fn plist_path_for(label: &str) -> Result<PathBuf> {
        let home = std::env::var("HOME")
            .map_err(|_| Error::Config("watch install: HOME not set".into()))?;
        Ok(PathBuf::from(home)
            .join("Library")
            .join("LaunchAgents")
            .join(format!("{label}.plist")))
    }

    /// Build the plist body. Pulled out so tests can exercise the generated
    /// shape without writing to `~/Library/LaunchAgents`.
    pub fn render_plist(
        label: &str,
        exe: &std::path::Path,
        repo_root: &std::path::Path,
        log_path: &std::path::Path,
    ) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>watch</string>
        <string>run</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{repo_root}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>30</integer>
    <key>ExitTimeOut</key>
    <integer>30</integer>
    <key>StandardOutPath</key>
    <string>{log}</string>
    <key>StandardErrorPath</key>
    <string>{log}</string>
</dict>
</plist>
"#,
            label = xml_escape(label),
            exe = xml_escape(&exe.to_string_lossy()),
            repo_root = xml_escape(&repo_root.to_string_lossy()),
            log = xml_escape(&log_path.to_string_lossy()),
        )
    }

    fn xml_escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    }

    /// Current effective user's GUI domain target for `launchctl`.
    fn gui_target(label: &str) -> Result<String> {
        extern "C" {
            fn geteuid() -> u32;
        }
        let uid = unsafe { geteuid() };
        Ok(format!("gui/{uid}/{label}"))
    }

    fn gui_domain() -> Result<String> {
        extern "C" {
            fn geteuid() -> u32;
        }
        let uid = unsafe { geteuid() };
        Ok(format!("gui/{uid}"))
    }

    /// Resolve the current `reflogless` binary path so the plist points at
    /// the right exe even when the user has multiple installs on PATH.
    fn current_exe() -> Result<PathBuf> {
        std::env::current_exe().map_err(|e| Error::Config(format!("current_exe: {e}")))
    }

    pub fn install(repo: &Repo, store: &Store) -> Result<InstallReport> {
        let label = label_for(repo);
        let path = plist_path_for(&label)?;
        let exe = current_exe()?;
        let log = store.root.join("watch.log");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
        }
        let body = render_plist(&label, &exe, &repo.root, &log);
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .map_err(|e| Error::io(&path, e))?;
        f.write_all(body.as_bytes())
            .map_err(|e| Error::io(&path, e))?;
        // Best-effort: if a prior instance is loaded, bootout first so
        // bootstrap doesn't fail with "service already loaded". Ignore errors —
        // a clean install where no prior load exists will hit "no such service"
        // here, which is fine.
        let target = gui_target(&label)?;
        let _ = Command::new("launchctl")
            .args(["bootout", &target])
            .output();
        let domain = gui_domain()?;
        let out = Command::new("launchctl")
            .args(["bootstrap", &domain, &path.to_string_lossy()])
            .output()
            .map_err(|e| Error::Config(format!("launchctl bootstrap: {e}")))?;
        if !out.status.success() {
            return Err(Error::Config(format!(
                "launchctl bootstrap {domain} {} failed: {}",
                path.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(InstallReport {
            unit_path: path,
            label,
        })
    }

    pub fn uninstall(repo: &Repo, _store: &Store) -> Result<InstallReport> {
        let label = label_for(repo);
        let path = plist_path_for(&label)?;
        let target = gui_target(&label)?;
        // bootout is non-fatal if the service isn't loaded — we still want to
        // remove the plist file. Capture and report only if BOTH steps failed.
        let bootout = Command::new("launchctl")
            .args(["bootout", &target])
            .output();
        let plist_existed = path.exists();
        if plist_existed {
            fs::remove_file(&path).map_err(|e| Error::io(&path, e))?;
        }
        match bootout {
            Ok(out) if !out.status.success() && !plist_existed => {
                return Err(Error::Config(format!(
                    "launchctl bootout {target} failed and no plist at {} to remove: {}",
                    path.display(),
                    String::from_utf8_lossy(&out.stderr).trim(),
                )));
            }
            _ => {}
        }
        Ok(InstallReport {
            unit_path: path,
            label,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn label_includes_repo_id() {
            let td = tempfile::TempDir::new().unwrap();
            std::process::Command::new("git")
                .arg("init")
                .arg("-q")
                .arg(td.path())
                .status()
                .unwrap();
            let repo = Repo::discover(td.path()).unwrap();
            let label = label_for(&repo);
            assert!(label.starts_with("com.nhangen.reflogless."));
            assert!(label.ends_with(&repo.id()));
        }

        #[test]
        fn render_plist_includes_required_keys() {
            let plist = render_plist(
                "com.nhangen.reflogless.deadbeef00000000",
                std::path::Path::new("/usr/local/bin/reflogless"),
                std::path::Path::new("/Users/me/projects/myrepo"),
                std::path::Path::new("/Users/me/.local/share/reflogless/abc/watch.log"),
            );
            // Required launchd keys
            assert!(plist.contains("<key>Label</key>"));
            assert!(plist.contains("<key>ProgramArguments</key>"));
            assert!(plist.contains("<key>WorkingDirectory</key>"));
            assert!(plist.contains("<key>RunAtLoad</key>"));
            assert!(plist.contains("<key>KeepAlive</key>"));
            assert!(plist.contains("<key>ThrottleInterval</key>"));
            assert!(plist.contains("<key>ExitTimeOut</key>"));
            // Args are watch run, in order
            assert!(plist.contains("<string>/usr/local/bin/reflogless</string>"));
            assert!(plist.contains("<string>watch</string>"));
            assert!(plist.contains("<string>run</string>"));
            // KeepAlive on non-zero exit
            assert!(plist.contains("<key>SuccessfulExit</key>"));
            assert!(plist.contains("<false/>"));
            // Throttle / timeout are explicit per audit MEDIUMs from #45/#47
            assert!(plist.contains("<integer>30</integer>"));
        }

        #[test]
        fn render_plist_xml_escapes_special_chars_in_repo_path() {
            let plist = render_plist(
                "com.nhangen.reflogless.test",
                std::path::Path::new("/usr/local/bin/reflogless"),
                std::path::Path::new("/Users/me/repo with <angle> & \"quote\""),
                std::path::Path::new("/tmp/watch.log"),
            );
            assert!(plist.contains("repo with &lt;angle&gt; &amp; &quot;quote&quot;"));
            assert!(!plist.contains("<angle>")); // not raw
        }

        #[test]
        fn plist_path_for_uses_launchagents_dir() {
            std::env::set_var("HOME", "/tmp/fake-home-for-test");
            let p = plist_path_for("com.nhangen.reflogless.deadbeef").unwrap();
            assert_eq!(
                p,
                PathBuf::from("/tmp/fake-home-for-test/Library/LaunchAgents/com.nhangen.reflogless.deadbeef.plist")
            );
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs;
    use std::io::Write;

    /// Stable unit name per repo: `reflogless-<repo_id>.service`.
    pub fn unit_name_for(repo: &Repo) -> String {
        format!("reflogless-{}.service", repo.id())
    }

    /// Path to the per-user systemd unit for this repo's watcher. systemd
    /// `--user` reads from `~/.config/systemd/user/` per the XDG spec.
    pub fn unit_path_for(unit_name: &str) -> Result<PathBuf> {
        let home = std::env::var("HOME")
            .map_err(|_| Error::Config("watch install: HOME not set".into()))?;
        Ok(PathBuf::from(home)
            .join(".config")
            .join("systemd")
            .join("user")
            .join(unit_name))
    }

    /// Render the systemd unit file body. Hoisted so tests exercise the
    /// generated shape without writing to `~/.config/systemd/user/`.
    pub fn render_unit(
        exe: &std::path::Path,
        repo_root: &std::path::Path,
        log_path: &std::path::Path,
    ) -> String {
        format!(
            "[Unit]\n\
             Description=reflogless watcher for {repo}\n\
             After=default.target\n\
             \n\
             [Service]\n\
             Type=simple\n\
             ExecStart={exe} watch run\n\
             WorkingDirectory={repo}\n\
             Restart=on-failure\n\
             RestartSec=30s\n\
             StartLimitBurst=5\n\
             StartLimitIntervalSec=300s\n\
             TimeoutStopSec=30s\n\
             StandardOutput=append:{log}\n\
             StandardError=append:{log}\n\
             \n\
             [Install]\n\
             WantedBy=default.target\n",
            exe = exe.display(),
            repo = repo_root.display(),
            log = log_path.display(),
        )
    }

    /// Resolve the running `reflogless` binary path so the unit points at
    /// the right exe even with multiple installs on PATH.
    fn current_exe() -> Result<PathBuf> {
        std::env::current_exe().map_err(|e| Error::Config(format!("current_exe: {e}")))
    }

    pub fn install(repo: &Repo, store: &Store) -> Result<InstallReport> {
        let unit_name = unit_name_for(repo);
        let path = unit_path_for(&unit_name)?;
        let exe = current_exe()?;
        let log = store.root.join("watch.log");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
        }
        let body = render_unit(&exe, &repo.root, &log);
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .map_err(|e| Error::io(&path, e))?;
        f.write_all(body.as_bytes())
            .map_err(|e| Error::io(&path, e))?;
        // daemon-reload picks up the new unit file. Skip-if-not-systemd
        // (containers, minimal environments) makes daemon-reload errors
        // non-fatal — the file still exists for manual reload, and the
        // user-facing error from the next step (`enable --now`) is clearer.
        let _ = Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .output();
        // enable --now both enables for next login AND starts now.
        let out = Command::new("systemctl")
            .args(["--user", "enable", "--now", &unit_name])
            .output()
            .map_err(|e| Error::Config(format!("systemctl --user enable: {e}")))?;
        if !out.status.success() {
            return Err(Error::Config(format!(
                "systemctl --user enable --now {unit_name} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(InstallReport {
            unit_path: path,
            label: unit_name,
        })
    }

    pub fn uninstall(repo: &Repo, _store: &Store) -> Result<InstallReport> {
        let unit_name = unit_name_for(repo);
        let path = unit_path_for(&unit_name)?;
        // disable --now both stops the running instance AND removes the
        // wants/ symlink. Non-fatal: if not active, the call may exit
        // non-zero but the file removal below is the user-visible result.
        let disable = Command::new("systemctl")
            .args(["--user", "disable", "--now", &unit_name])
            .output();
        let unit_existed = path.exists();
        if unit_existed {
            fs::remove_file(&path).map_err(|e| Error::io(&path, e))?;
        }
        // daemon-reload so systemd forgets the file we just removed.
        let _ = Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .output();
        match disable {
            Ok(out) if !out.status.success() && !unit_existed => {
                return Err(Error::Config(format!(
                    "systemctl --user disable {unit_name} failed and no unit at {} to remove: {}",
                    path.display(),
                    String::from_utf8_lossy(&out.stderr).trim(),
                )));
            }
            _ => {}
        }
        Ok(InstallReport {
            unit_path: path,
            label: unit_name,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn unit_name_includes_repo_id() {
            let td = tempfile::TempDir::new().unwrap();
            std::process::Command::new("git")
                .arg("init")
                .arg("-q")
                .arg(td.path())
                .status()
                .unwrap();
            let repo = Repo::discover(td.path()).unwrap();
            let name = unit_name_for(&repo);
            assert!(name.starts_with("reflogless-"));
            assert!(name.ends_with(".service"));
            assert!(name.contains(&repo.id()));
        }

        #[test]
        fn render_unit_includes_required_directives() {
            let unit = render_unit(
                std::path::Path::new("/usr/local/bin/reflogless"),
                std::path::Path::new("/home/me/projects/myrepo"),
                std::path::Path::new("/home/me/.local/share/reflogless/abc/watch.log"),
            );
            // Sections
            assert!(unit.contains("[Unit]"));
            assert!(unit.contains("[Service]"));
            assert!(unit.contains("[Install]"));
            // Required directives
            assert!(unit.contains("ExecStart=/usr/local/bin/reflogless watch run"));
            assert!(unit.contains("WorkingDirectory=/home/me/projects/myrepo"));
            assert!(unit.contains("Restart=on-failure"));
            // Per design audit MEDIUMs from #45/#47 — throttle + timeout explicit
            assert!(unit.contains("RestartSec=30s"));
            assert!(unit.contains("StartLimitBurst=5"));
            assert!(unit.contains("StartLimitIntervalSec=300s"));
            assert!(unit.contains("TimeoutStopSec=30s"));
            // Install target — default.target so the unit fires on user-session
            // start (not boot — systemd --user is per-user, not per-system).
            assert!(unit.contains("WantedBy=default.target"));
        }

        #[test]
        fn unit_path_for_uses_xdg_systemd_user_dir() {
            std::env::set_var("HOME", "/tmp/fake-home-for-test");
            let p = unit_path_for("reflogless-deadbeef.service").unwrap();
            assert_eq!(
                p,
                PathBuf::from(
                    "/tmp/fake-home-for-test/.config/systemd/user/reflogless-deadbeef.service"
                )
            );
        }
    }
}
