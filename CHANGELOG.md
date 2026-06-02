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
- `reflogless list --all` (#29): cross-repo listing enumerates every store
  under the configured data directory, surfacing each store's origin path
  (active / stale / legacy), snapshot count, and snapshot IDs. Plaintext-only
  — per-manifest detail (event/message/files) stays in the single-repo
  `list` since it requires the identity. Stores now persist their origin
  path in `repo_origin.txt` at construction; pre-existing stores show as
  `legacy` until next touched.

### Fixed
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
