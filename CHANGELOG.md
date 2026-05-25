# Changelog

All notable changes to this project are documented here. Format roughly
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions
follow [SemVer](https://semver.org/).

## [Unreleased]

### Added
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
- PR-time CI gate: `cargo fmt --check` + `cargo clippy --all-targets
  -- -D warnings` + `cargo test --all-targets` on Linux + macOS.

### Changed
- Lint cleanup: 13 → 0 clippy warnings across the crate (cmp_owned,
  manual_contains, type_complexity, derivable_impls, needless_return).
- Bulk `cargo fmt` across the crate; rustfmt is now enforced.

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

[Unreleased]: https://github.com/nhangen/reflogless/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/nhangen/reflogless/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/nhangen/reflogless/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/nhangen/reflogless/releases/tag/v0.1.0
