//! Shared test fixtures.

use crate::repo::Repo;
use std::path::Path;
use std::process::Command;

/// Initialize a throwaway git repo for tests, isolated from the developer's
/// ambient git configuration.
///
/// The `core.hooksPath` pin keeps a temp repo from inheriting the *global* value.
/// Without it, git commands run here execute the developer's real hooks — on a
/// machine with an identity-gate dispatcher a test commit gets rejected outright —
/// and `install` would resolve against that shared directory.
///
/// The pin must **not** be mistaken for coverage of the global-`core.hooksPath`
/// case. Pinning it and stopping there is what let #73 ship green while `install`
/// was in fact broken on every repo of a machine that sets it. That condition is
/// covered by pointing `core.hooksPath` at a directory *outside* the repo
/// explicitly (`install_declines_hooks_dir_outside_repo_and_falls_back` and its
/// uninstall twin), which is deterministic on every machine rather than depending
/// on whatever the developer happens to have configured.
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
