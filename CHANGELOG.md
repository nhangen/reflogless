# Changelog

All notable changes to this project are documented here. Format roughly
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions
follow [SemVer](https://semver.org/).

## [Unreleased]

### Added
- Optional remote snapshot backend (#31): push the blob and manifest content
  of an encrypted store to S3-compatible object storage so snapshots survive
  laptop loss. Opt-in via `cargo install reflogless --features remote`; the
  default build is unchanged. New CLI surface:
  `reflogless remote enable --s3-url s3://<bucket>/<prefix> --region <r>`
  (refuses unless the store has `encrypt = "all"` and an attached identity;
  reads credentials from `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` /
  optional `AWS_SESSION_TOKEN`), `reflogless remote push` (drains the
  per-store pending log, dedupes via `head_blob`, uploads new manifests),
  `reflogless remote status`, `reflogless remote disable`. Per-machine
  layout: a `<hostname>` segment is appended to the user's key prefix so
  multiple laptops can share one bucket safely. `reflogless doctor` now
  reports `remote :` and `remote.backlog :` with WARN/UNHEALTHY tiers
  (defaults: 14 days warn, 60 days unhealthy; tunable under `[remote]` in
  `.reflogless.toml`). Snapshots are never blocked on network — each snap
  appends a tiny entry to `<store>/remote-pending.jsonl` (a local "waiting
  room") via a try-once lock that yields immediately on contention, and
  uploads happen out-of-band when `remote push` runs.
- `reflogless gc --stale-stores` (#78): reclaim whole stores whose origin repo
  has been deleted. Orphaned stores were previously detected by
  `list --all` and then never acted on — and because a `Store` is constructed
  from an existing repo path, `Store::gc` structurally could not reach the one
  class of store guaranteed to be dead. One such store held 1.9 GB for 52 days
  and had to be removed by hand. The reclaim path is a free function over the
  data directory rather than a `Store` method, so it can act on stores whose
  repo is gone. Reports only unless `--yes` is also passed; prints each
  candidate's size, snapshot count, and dead origin path first. A store whose
  origin repo reappears between the scan and the delete is kept, and one
  unremovable store no longer aborts the pass (it is reported, and the command
  exits non-zero). Stores with no recorded origin are never evicted — that
  file's absence tracks install age, not deadness.
- `reflogless doctor` now reports machine-wide store totals and reclaimable
  orphans (#78): `all stores` (bytes + count) and, when any exist,
  `orphaned stores` with reclaimable bytes and the command to review them.
  `snap` deliberately does not prune — running a GC pass from a git hook would
  mean silently deleting user data on the hot path — so this is what makes
  unbounded growth visible. Orphans are informational and do not fail doctor:
  another repo's dead store is not a failure of this repo's protection.
- `reflogless list --all` (#29): cross-repo listing enumerates every store
  under the configured data directory, surfacing each store's origin path
  (active / stale / legacy), snapshot count, and snapshot IDs. Plaintext-only
  — per-manifest detail (event/message/files) stays in the single-repo
  `list` since it requires the identity. Stores now persist their origin
  path in `repo_origin.txt` at construction; pre-existing stores show as
  `legacy` until next touched.

### Fixed
- Installed hooks resolved the binary off `PATH`, so snapshots were silently
  skipped wherever `PATH` lacked the install dir (#74). Hooks invoked bare
  `reflogless`, and a GUI editor, launchd/cron job, or sandboxed runner
  typically has neither `~/.cargo/bin` nor `/opt/homebrew/bin` — the lookup
  failed, the trailing `|| true` swallowed it, and nothing at the call site
  showed a snapshot had been missed. Measured on one real store: 118
  `reflogless: command not found` lines in `hook-errors.log`. Coverage was
  intermittent rather than absent, since the same repo snapshots fine when git
  is driven from an interactive shell, which is what made it easy to miss.
  `install` now bakes the absolute path of the running binary into each hook
  (normalized so the install-time working directory can't leak in via `..`,
  and without resolving the final symlink, so an install reached through a
  version manager's stable link survives an upgrade). Resolution order in the
  generated hook is: the baked path, overridden by `$REFLOGLESS_BIN` when that
  names something executable, then bare `reflogless` as a last resort. Every
  step down that chain writes a line to `hook-errors.log` naming itself, and
  `MARKER_VERSION` is bumped to 3 so older hooks are detected (see below).
- `reflogless doctor` reported hooks as healthy when they had stopped
  protecting the repo (#74 follow-on). A hook body predating the current format
  still resolves the binary off `PATH`, and a baked path that a reinstall or
  upgrade deleted falls back to the same lookup — both printed `OK` and
  `overall: HEALTHY`. Nothing rewrites hooks automatically, so a user had no way
  to learn they should re-run `reflogless init`. `doctor` now reads the version
  and the baked path back out of each managed hook and reports `STALE (...)`,
  naming the dead path, and fails the run with `run reflogless init` as the
  remedy — matching what it already did for a stale PATH shim.
- A hook run with a minimal `PATH` discarded its own error log (regression from
  #68). The log's parent directory was derived with `$(dirname ...)`, an external
  command, so under a PATH without coreutils the substitution returned empty, the
  directory check failed, and the entire log was redirected to `/dev/null`. The
  hook then failed *and* destroyed the only record of it, in exactly the
  environment class where that is most likely. Now uses the `${VAR%/*}` builtin,
  so an existing log directory keeps logging with no `PATH` at all. `%/*` is not
  `dirname`: a log path with no directory component would otherwise have `mkdir`'d
  a *directory* of that name into the working tree, so that shape is normalized to
  `.`, and a root-level path yields an empty parent, so `mkdir` is skipped rather
  than run on `""`. The log is then tested for *appendability* rather than its
  directory for existence — a directory can exist and still not accept the append,
  and a failed redirect means `sh` never runs the snapshot at all, so probing the
  wrong thing silently skipped the very snapshot the hook exists to take. That
  probe runs in a subshell: POSIX makes a redirection error on a special builtin
  exit a non-interactive shell, which dash obeys and bash does not, so on Debian
  and Ubuntu (`/bin/sh` is dash) a brace-grouped probe aborted the hook with
  exit 2 instead of falling back — trading a missed snapshot for a broken `git`.
- Hook installation destroyed a shared `core.hooksPath` directory (#73).
  `core.hooksPath` is frequently set *globally*, naming one directory of
  symlinks that every repo on the machine shares. `install` wrote straight
  into it, and because `fs::write` and `set_permissions` follow symlinks it
  rewrote the link *target* — overwriting the shared dispatcher those links
  point at. `uninstall` then deleted entries reflogless never created.
  Observed damage: a dispatcher truncated from 71 lines to 24, 4 of 19 hook
  symlinks turned into regular files, and a git-tracked file in an unrelated
  repo modified. Now: an out-of-repo `core.hooksPath` is declined and hooks
  go to the repo's own hooks directory, reported by `install`, `uninstall`,
  and `doctor`; entries are unlinked before writing so a symlink is replaced
  rather than followed; and every existence check uses `symlink_metadata`, so
  a dangling link no longer reads as absent.
- Hooks were installed where git does not read them, in a linked worktree.
  Resolution used the per-worktree git dir, but `hooks` is a *common*-dir
  path — git runs `<main-clone>/.git/hooks`. Hooks landed in
  `.git/worktrees/<name>/hooks`, `install` reported success, and `doctor`
  reported healthy while nothing was ever invoked. Resolution now goes
  through `git rev-parse --git-common-dir`.
- `doctor` reported a healthy install as FOREIGN on any machine with a global
  `core.hooksPath` (#76), because it inspected whatever the setting named
  rather than where `install` writes. It now shares one resolver and one
  entry classifier with `install`, so the two cannot disagree.
- `doctor` reported healthy for hooks git can never invoke. When
  `core.hooksPath` is declined and that directory has no entry for a hook,
  nothing can forward to ours — the hook is provably dead. That is now a
  doctor failure (`hooks shadowed by core.hooksPath`) and a warning at
  install time, not a footnote.
- A second `reflogless init` silently stopped running a preserved
  third-party hook: the already-managed branch rewrote the wrapper without
  its `exec`, while `doctor` kept reporting `OK (chained)` because it read
  the backup file's existence rather than the wrapper body. Both fixed.
- An unreadable hook (permissions, non-UTF-8, a directory) was reported as
  `FOREIGN (not reflogless-managed)` — a wrong answer that points at the
  wrong fix. `doctor` now reports `UNREADABLE` with the reason, and
  `uninstall` warns instead of silently skipping a hook that may be ours and
  still firing.
- A dangling symlink at a hook entry aborted `install` part-way through,
  leaving some hooks installed and others not. It is now replaced outright,
  since a link with nothing behind it has no body worth preserving.
- macOS lock release race in `RemoteLock` (#62): on macOS, closing a file
  that holds a `flock` does not release the kernel-level lock fast enough
  for a same-process re-acquire — back-to-back `TryOnce` attempts failed
  ~45% of the time under the full test suite. Fixed by explicitly calling
  `file.unlock()` in `Drop` before the `File` closes. Lockdown test does
  50 sequential acquire/release cycles; removing the `Drop` impl fails it.

## [1.0.0] — 2026-05-25

### Added
- Homebrew publishing via `nhangen/homebrew-tap`, so macOS and Linux users
  can install with `brew install nhangen/tap/reflogless` (#3).
- Scoop bucket publishing via `nhangen/scoop-bucket`, so Windows users can
  install with `scoop bucket add nhangen https://github.com/nhangen/scoop-bucket`
  followed by `scoop install reflogless` (#3).
- Windows shim support (#8): `reflogless init --shim` now installs a managed
  `git.cmd` wrapper next to `reflogless.exe`, `reflogless uninstall` removes it,
  and `doctor` accounts for Windows `PATHEXT` resolution.
- Per-repo shim opt-out (#12): set `shim = false` in `.reflogless.toml` to
  bypass global shim snapshotting for that repo.
- Expanded shim allowlist (#9): `git restore`, `git switch -f` /
  `--discard-changes`, `git checkout -f` / `--force`, and `git checkout
  <ref> -- <pathspec>` now snapshot before exec.
- Shim short-circuits on `git clean --dry-run` / `-n` (including short
  clusters like `-nd`, `-ndx`) — dry-run is touch-free, no snapshot
  needed (#10).
- `ShimStatus::Stale` variant: doctor detects when the shim's
  hardcoded `reflogless` path no longer matches the current binary
  (e.g. after reinstall to a different toolchain) and prints the fix
  (#11).
- `ShimStatus::Unreadable` variant: doctor now reports unreadable shim files
  distinctly from foreign third-party files.
- Doctor now surfaces recent `<store>/shim-errors.log` entries alongside hook
  errors.
- PR-time CI gate: `cargo fmt --check` + `cargo clippy --all-targets
  -- -D warnings` + `cargo test --all-targets` on Linux + macOS.

### Changed
- Lint cleanup: 13 → 0 clippy warnings across the crate (cmp_owned,
  manual_contains, type_complexity, derivable_impls, needless_return).
- Bulk `cargo fmt` across the crate; rustfmt is now enforced.

### Fixed
- Windows shim wrapper quotes `--shim-dir=%~dp0.` safely so the trailing
  backslash in `%~dp0` cannot escape the closing quote.

## [0.1.2] — 2026-05-25

### Added
- Optional PATH shim (`reflogless init --shim`) that snapshots before
  `git clean` and `git reset --hard` — the two destructive git
  subcommands with no native hook coverage (#2 / PR #7).
- Conservative, line-anchored MARKER refusal: the shim installer
  won't overwrite or remove a non-reflogless file at the install path.

### Fixed
- Shim must never abort the user's `git`: process-replacement failure
  now falls through to `Command::status()` instead of returning Err.
- `log_shim_error` now uses an XDG state-dir fallback when the
  per-repo store is unreachable, instead of leaking errors to git's
  stderr.
- macOS shim install: `dirs::executable_dir()` returns `None` on
  macOS, so the installer now defaults to `~/.local/bin` instead of
  next to the reflogless binary (which would target a Homebrew system
  dir).

## [0.1.1] — 2026-05-25

### Fixed
- Restored prebuilt `aarch64-unknown-linux-gnu` release artifact via
  cargo-dist's `[dist.dependencies.apt]` for the keyring stack (#1).

## [0.1.0] — 2026-05-25

### Added
- Initial public release after extraction from the `llm-tools`
  monorepo. Covers Phases 1–4 of the original design:
  - `reflogless init` provisions per-repo age x25519 identity, writes
    git hooks, and creates the snapshot store.
  - `reflogless snap` / `restore` / `list` / `diff` operate over a
    SHA-256 content-addressed store with per-entry encryption policy
    driven by `.reflogless.toml`.
  - `reflogless doctor` reports hook state, store size, snapshot
    count, encryption roundtrip canary, and recent hook errors.
  - OS keychain backing for the secret key (`apple-native`,
    `windows-native`, `sync-secret-service`); `--insecure-file-key`
    fallback for headless / CI cases.
- Tag-driven multi-OS release via cargo-dist: macOS arm64 + x86,
  Linux x86, Windows x86 prebuilt binaries.

[Unreleased]: https://github.com/nhangen/reflogless/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/nhangen/reflogless/compare/v0.1.2...v1.0.0
[0.1.2]: https://github.com/nhangen/reflogless/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/nhangen/reflogless/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/nhangen/reflogless/releases/tag/v0.1.0
