//! Does the *shipped* hook reach the binary? (#74)
//!
//! The unit tests cover `build_hook_body` and `normalize_bin` directly, but they
//! cannot exercise the one input that matters here: what `current_exe()` actually
//! returns when a user invokes reflogless. In-process, `current_exe()` is already
//! absolute and canonical, so the normalization at the `install` call site is
//! invisible to a unit test — removing it breaks nothing.
//!
//! These tests run the real binary the way a user would and inspect the hook it
//! writes, which is the artifact that has to work.
//!
//! Isolated with `REFLOGLESS_DATA_DIR` and a neutralized git config so neither
//! the developer's store nor their global `core.hooksPath` is touched.

#![cfg(unix)]

use std::fs;
use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_reflogless");

fn git_repo(p: &Path) {
    fs::create_dir_all(p).unwrap();
    for args in [
        vec!["init", "-q", p.to_str().unwrap()],
        vec!["-C", p.to_str().unwrap(), "config", "user.email", "t@x"],
        vec!["-C", p.to_str().unwrap(), "config", "user.name", "t"],
    ] {
        assert!(Command::new("git")
            .args(&args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .status()
            .unwrap()
            .success());
    }
    fs::write(p.join("f.txt"), b"x").unwrap();
    for args in [
        vec!["-C", p.to_str().unwrap(), "add", "f.txt"],
        vec!["-C", p.to_str().unwrap(), "commit", "-qm", "init"],
    ] {
        assert!(Command::new("git")
            .args(&args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .status()
            .unwrap()
            .success());
    }
}

/// Read the `__REFLOGLESS_BIN='...'` value out of an installed hook.
fn baked_path(hook: &Path) -> String {
    let body = fs::read_to_string(hook).unwrap();
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("__REFLOGLESS_BIN='") {
            if let Some(end) = rest.rfind('\'') {
                return rest[..end].to_string();
            }
        }
    }
    panic!("no baked binary in {}:\n{body}", hook.display());
}

/// Invoking reflogless by a relative path must not bake the install-time working
/// directory into the hook. `current_exe()` returns `/cwd/../rl` for `../rl`, and
/// baking that verbatim means renaming the parent kills every hook even though
/// the binary never moved.
#[test]
fn a_relative_invocation_does_not_bake_the_install_time_cwd() {
    let td = TempDir::new().unwrap();
    let data = td.path().join("data");
    let bin = td.path().join("rl");
    fs::copy(BIN, &bin).unwrap();
    let repo = td.path().join("repo");
    git_repo(&repo);

    // `../rl init`, run from inside the repo — exactly how someone tries a build
    // out of a sibling directory.
    let status = Command::new("../rl")
        .arg("init")
        // Headless CI has no Secret Service, so keychain provisioning fails
        // there. Where the key lives is irrelevant to binary resolution, which
        // is what these tests are about.
        .arg("--insecure-file-key")
        .current_dir(&repo)
        .env("HOME", td.path())
        .env("REFLOGLESS_DATA_DIR", &data)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .status()
        .unwrap();
    assert!(status.success(), "init failed");

    let baked = baked_path(&repo.join(".git").join("hooks").join("post-checkout"));
    assert!(
        !baked.contains(".."),
        "hook bakes a `..` path, so it depends on the install-time cwd: {baked}"
    );
    assert!(
        Path::new(&baked).is_absolute() && Path::new(&baked).exists(),
        "baked path does not resolve: {baked}"
    );
}

/// The end-to-end property #74 is about: a hook installed by the real binary must
/// invoke it under a PATH that cannot resolve `reflogless`. Every unit test hands
/// `build_hook_body` a stub path directly, so none of them would notice if
/// `install` stopped baking one.
#[test]
fn an_installed_hook_snapshots_with_reflogless_absent_from_path() {
    let td = TempDir::new().unwrap();
    let data = td.path().join("data");
    let repo = td.path().join("repo");
    git_repo(&repo);

    assert!(Command::new(BIN)
        .arg("init")
        .arg("--insecure-file-key")
        .current_dir(&repo)
        .env("HOME", td.path())
        .env("REFLOGLESS_DATA_DIR", &data)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .status()
        .unwrap()
        .success());

    // An untracked file is what reflogless exists to protect.
    fs::write(repo.join("untracked.txt"), b"precious").unwrap();

    let hook = repo.join(".git").join("hooks").join("post-checkout");
    let status = Command::new(&hook)
        // Only the minimum needed to run a shell script — deliberately no
        // directory that could resolve a bare `reflogless`. This is the GUI
        // editor / launchd / sandboxed-runner environment from #74.
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", td.path())
        .env("REFLOGLESS_DATA_DIR", &data)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .current_dir(&repo)
        .status()
        .unwrap();
    assert!(status.success(), "hook must stay best-effort");

    // The hook ran the binary if and only if a snapshot manifest appeared beyond
    // the baseline `init` took.
    let store = fs::read_dir(data.join("reflogless"))
        .expect("no store dir — the hook never reached the binary")
        .next()
        .expect("no store")
        .unwrap()
        .path();
    let snaps: Vec<_> = fs::read_dir(store.join("snapshots"))
        .expect("no snapshots dir")
        .flatten()
        .collect();
    assert!(
        snaps.len() >= 2,
        "expected the hook's snapshot on top of init's baseline, found {}",
        snaps.len()
    );

    let log = store.join("hook-errors.log");
    let logged = fs::read_to_string(&log).unwrap_or_default();
    assert!(
        !logged.contains("command not found"),
        "hook fell back to a PATH lookup and failed — #74 regressed: {logged}"
    );
}
