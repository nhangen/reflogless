//! Shared test fixtures.

use crate::repo::Repo;
use std::path::Path;
use std::process::Command;

/// Initialize a throwaway git repo for tests, isolated from the developer's
/// ambient git configuration.
///
/// The `core.hooksPath` pin is the load-bearing part. A temp repo still inherits
/// *global* git config, so on any machine with a global `core.hooksPath` (husky,
/// lefthook, an identity-gate dispatcher) `hooks::hooks_dir` resolves to that
/// shared directory and every test touching `install`/`uninstall` operates on
/// the developer's real hooks instead of this repo. Pinning locally makes the
/// resolution deterministic without weakening the production path, which still
/// honors `core.hooksPath` as git does.
///
/// Every test that installs hooks must build its repo through here rather than
/// calling `git init` inline — that is what keeps the isolation from rotting.
/// See #73.
pub(crate) fn init_repo(td: &Path) -> Repo {
    let path = td.to_str().expect("temp path is valid utf-8");
    run_git(["init", "-q", path]);
    run_git(["-C", path, "config", "user.email", "t@t"]);
    run_git(["-C", path, "config", "user.name", "t"]);
    run_git([
        "-C",
        path,
        "config",
        "--local",
        "core.hooksPath",
        ".git/hooks",
    ]);
    Repo::discover(td).expect("temp dir is a git repo")
}

fn run_git<const N: usize>(args: [&str; N]) {
    let status = Command::new("git")
        .args(args)
        .status()
        .expect("git is on PATH");
    assert!(status.success(), "git {args:?} failed");
}
