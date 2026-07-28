//! Shared test fixtures.

use crate::repo::Repo;
use std::path::Path;
use std::process::Command;

/// Initialize a throwaway git repo for tests, isolated from the developer's
/// ambient git configuration.
///
/// Isolation is by **neutralizing global and system config**
/// (`GIT_CONFIG_GLOBAL=/dev/null`), not by pinning `core.hooksPath` to a value the
/// production code then honors. That distinction is load-bearing twice over:
///
/// - A pin makes the *configured* branch of `resolve_hooks_target` the default in
///   tests, so the unset branch — the majority production configuration — goes
///   untested. Pinning and stopping there is what let this branch's first attempt
///   ship 244 green tests while `install` was broken on every repo of a machine
///   with a global `core.hooksPath`.
/// - A pin does not actually isolate. Any test that clears it, or any change that
///   stops honoring it, lets the suite resolve the developer's real hooks
///   directory — which is how a mutation-testing run wrote reflogless hooks into
///   `~/.config/git/hooks` and clobbered four symlinks of a shared dispatcher.
///   Neutralized config cannot do that: there is no global value to inherit.
///
/// The global-`core.hooksPath` condition is instead covered explicitly, by tests
/// that point the setting at a directory outside the repo — deterministic on any
/// machine rather than dependent on the developer's config.
///
/// Every test that touches hooks must build its repo through here, and every git
/// invocation in a test must go through [`git_in`], or the isolation is void.
/// See #73.
pub(crate) fn init_repo(td: &Path) -> Repo {
    isolate_git_config();
    let path = td.to_str().expect("temp path is valid utf-8");
    git_in(&["init", "-q", path]);
    git_in(&["-C", path, "config", "user.email", "t@t"]);
    git_in(&["-C", path, "config", "user.name", "t"]);
    Repo::discover(td).expect("temp dir is a git repo")
}

/// Neutralize global/system git config for the whole test **process**.
///
/// Setting these on our own `Command`s is not enough: the code under test spawns
/// its own `git` (`configured_hooks_path`, `git_common_dir`), and a child only
/// inherits what is in the process environment. Exported once here, every git
/// process in the suite — ours and production's — sees an empty global config.
/// `/dev/null` parses as a valid empty config file.
fn isolate_git_config() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        std::env::set_var("GIT_CONFIG_GLOBAL", "/dev/null");
        std::env::set_var("GIT_CONFIG_SYSTEM", "/dev/null");
        std::env::set_var("GIT_CONFIG_NOSYSTEM", "1");
    });
}

/// Run a git command under the suite's isolated config and assert it succeeded.
pub(crate) fn git_in(args: &[&str]) {
    isolate_git_config();
    let status = Command::new("git")
        .args(args)
        .status()
        .expect("git is on PATH");
    assert!(status.success(), "git {args:?} failed");
}
