# reflogless

> `git reflog` saves you from a botched rebase. `reflogless` saves you from everything reflog can't reach.

Local safety net for the working-tree state git refuses to track. Snapshots untracked + dirty files into a content-addressed store so `git clean -fdx`, `git reset --hard`, and bad rebases don't destroy work that was never committed.

Blobs and snapshot manifests are encrypted at rest with [age](https://github.com/FiloSottile/age), keyed to the OS keychain (macOS Keychain / Linux Secret Service / Windows DPAPI via the [`keyring`](https://crates.io/crates/keyring) crate). Hooks run automatically around `post-checkout`, `pre-rebase`, `post-rewrite`, and `reference-transaction`. No cloud, no network, no telemetry.

> **Status:** v0.1.0 — first public release. Homebrew tap, Scoop manifest, and the optional `--shim` (for `git clean` / `git reset --hard` coverage) are tracked in [open issues](https://github.com/nhangen/reflogless/issues).

## Wedge

- Monorepo developers with untracked generated config (`.env.local`, build artifacts).
- ML / data folks with untracked datasets and notebooks.
- Anyone burned by `git clean -fdx` who wants a passive safety net.

Not a `git stash` replacement. Tracked-file workflows stay with stash + reflog.

## Quickstart

```sh
# install (macOS / Linux)
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/nhangen/reflogless/releases/latest/download/reflogless-installer.sh | sh

# in any git repo
cd my-repo
reflogless init           # installs hooks + provisions encryption identity
reflogless doctor         # confirms everything is healthy

# work normally; hooks auto-snap around branch switches and rebases.
# manual snapshot whenever you want:
reflogless snap -m "before risky cleanup"

# list, restore, diff:
reflogless list
reflogless restore latest
```

Full install paths (Windows, source builds, headless Linux) below.

## Install

### Prebuilt binaries

**macOS / Linux:**

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/nhangen/reflogless/releases/latest/download/reflogless-installer.sh | sh
```

**Windows (PowerShell):**

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://github.com/nhangen/reflogless/releases/latest/download/reflogless-installer.ps1 | iex"
```

Or download a per-platform archive from the [releases page](https://github.com/nhangen/reflogless/releases):

| Platform | Archive |
|---|---|
| Apple Silicon macOS | `reflogless-aarch64-apple-darwin.tar.xz` |
| Intel macOS | `reflogless-x86_64-apple-darwin.tar.xz` |
| x86_64 Linux | `reflogless-x86_64-unknown-linux-gnu.tar.xz` |
| x86_64 Windows | `reflogless-x86_64-pc-windows-msvc.zip` |

aarch64-linux (Graviton, Raspberry Pi, Ampere) is not in v0.1.0 — see [#1](https://github.com/nhangen/reflogless/issues/1). Build from source on those hosts.

> **Windows users:** v0.1.0 binaries are unsigned. SmartScreen will warn on first run ("Windows protected your PC") — choose *More info* → *Run anyway*. On enterprise machines with Smart App Control or AppLocker in enforcement mode the binary may be blocked silently with no warning dialog — use `cargo install` from source or wait for signed builds. Authenticode EV signing is deferred to v2 (cert is $300–600/year + HSM).

### From source

Requires a Rust toolchain (install via [rustup.rs](https://rustup.rs)). Transitive deps (`keyring 3`, `age 0.11`) currently pull in a recent compiler — if `cargo install` complains about an MSRV, `rustup update stable` fixes it.

```sh
cargo install --git https://github.com/nhangen/reflogless --tag v0.1.0
```

Or clone and build:

```sh
git clone https://github.com/nhangen/reflogless
cd reflogless
cargo install --path .
```

### Linux prerequisite for encryption

`reflogless init` provisions an age identity into the OS keychain via the [`keyring`](https://crates.io/crates/keyring) crate. On Linux that requires a running Secret Service provider (gnome-keyring or KWallet) and an active D-Bus session — headless servers, Docker containers, CI runners, and ssh-only boxes have none.

On those hosts:

```sh
reflogless init --insecure-file-key
```

Stores the identity in a `0600` file at `<store>/identity.key`. `reflogless doctor` will surface this as `INSECURE FILE KEY`. Acceptable for ephemeral CI; for a persistent host, prefer to set up a real keychain.

### Verify the install

```sh
reflogless --version
reflogless doctor    # checks hooks, store, encryption canary roundtrip
```

Open a new shell first if `reflogless` isn't found — the installer writes to `~/.cargo/bin` (or `~/.local/bin`) which existing shells may not have on PATH yet.

## Usage

```
reflogless init                      install hooks + provision encryption identity
reflogless init --insecure-file-key  same, but store key on disk (loud warning)
reflogless doctor                    verify install + store + canary + encryption
reflogless snap -m MSG               manual snapshot
reflogless list                      all snapshots for this repo
reflogless show ID                   files in a snapshot
reflogless restore ID                restore (refuses overwrite without --force)
reflogless restore latest            restore most recent
reflogless restore ID PATH ...       restore specific paths only
reflogless diff ID [PATH]            unified diff snap vs work
reflogless gc                        LRU + age eviction
reflogless uninstall                 remove hooks; restore prior chained hooks
reflogless uninstall --purge --yes   also delete the store (--yes required)
```

Snapshot IDs accept a unique prefix — `reflogless restore 20260524T193` works if it disambiguates. `latest` is always valid.

## Recovery example

The whole point of the tool. A realistic flow on a fresh install.

```sh
$ cd my-monorepo
$ reflogless init
installed into /Users/me/my-monorepo/.git/hooks
  + post-checkout
  + pre-rebase
  + post-rewrite
  + reference-transaction
provisioned identity (keychain service=reflogless account=8f3a9b2c)

$ echo "STRIPE_KEY=sk_test_abcdefghij" > .env.local
$ echo "trained_weights = ..." > data/model.bin
$ reflogless snap -m "before nuke"
20260524T193045123Z-manual
files: 2  bytes: 2147  skipped: 0
```

Now disaster:

```sh
$ git clean -fdx
Removing .env.local
Removing data/model.bin
```

Recovery:

```sh
$ reflogless list
20260524T192201040Z-post-checkout  post-checkout  2 files
20260524T193045123Z-manual         manual         2 files  before nuke

$ reflogless show latest
id: 20260524T193045123Z-manual
created: 2026-05-24T19:30:45.123Z
event: manual
message: before nuke
entries: 2
  .env.local (1024 bytes, mode 600) blob 3a7f2e9c1d8b
  data/model.bin (1123 bytes, mode 644) blob 9e4c8f3a1b27

$ reflogless restore latest
restored 2 from 20260524T193045123Z-manual (refused 0)

$ cat .env.local
STRIPE_KEY=sk_test_abcdefghij
```

The hooks would have snapshotted before any branch-switch or rebase too — the manual `snap` above is only required because `git clean` has no hook (until the optional `--shim`, [#2](https://github.com/nhangen/reflogless/issues/2)).

Restore one path at a time:

```sh
$ reflogless restore latest .env.local
restored 1 from 20260524T193045123Z-manual (refused 0)
```

If a file already exists in the working tree, restore refuses unless you pass `--force`:

```sh
$ reflogless restore latest
restored 0 from 20260524T193045123Z-manual (refused 2)
  refused: .env.local (use --force)
  refused: data/model.bin (use --force)
```

## Storage

- `$REFLOGLESS_DATA_DIR` if set (explicit override; primarily for tests), else `$XDG_DATA_HOME/reflogless/<repo-hash>/`, else `dirs::data_dir()`.
- `objects/<a>/<b>` — SHA-256 content-addressed blobs (auto-dedup across snapshots).
- `snapshots/<ts>-<event>.json` — manifests referencing blob digests + relpaths + mode bits.
- Unix: store dirs are mode `0700`, files `0600`. Restored files preserve their original mode. On Windows, mode bits and `0700`/`0600` are not enforced.

## File selection

- Includes: untracked + modified-unstaged (`git status --porcelain=v1 -uall`).
- Honors `.gitignore` (via git status) and `.refloglessignore` at repo root.
- Default-deny: `node_modules/`, `vendor/`, `.venv/`, `target/`, `dist/`, `*.log`.
- Per-file cap: 10 MB. Larger files are skipped with a note on stderr.

## Hook coverage

After `reflogless init`:

| Hook | Triggers when | Catches |
|---|---|---|
| `post-checkout` | branch switch | dirty files about to be obscured |
| `pre-rebase` | rebase start | pre-rebase working tree |
| `post-rewrite` | after rebase / commit --amend | rewritten state |
| `reference-transaction` | any ref update (git ≥ 2.28) | belt-and-suspenders |

Hooks are best-effort: a snap failure never blocks the underlying git op. **`git` exposes no hooks on `clean` or `reset --hard`** — those land via the opt-in `--shim` ([#2](https://github.com/nhangen/reflogless/issues/2)).

If a third-party hook is already installed (husky, lefthook, hand-written), reflogless preserves it: the prior file is renamed to `<hook>.reflogless-orig` and reflogless's wrapper `exec`s it after taking the snapshot. `reflogless uninstall` restores the prior hook from `.reflogless-orig`.

## Encryption

`reflogless init` provisions an [age](https://github.com/FiloSottile/age) x25519 identity:

- Secret key lives in the OS keychain (service `reflogless`, account = repo hash).
- Public recipient is written to `<store>/recipient.txt` (not secret).
- `--insecure-file-key` falls back to a `0600` file at `<store>/identity.key`. `reflogless doctor` surfaces this as `INSECURE FILE KEY`.

Encryption policy is set in `.reflogless.toml` at the repo root (optional; defaults work without it):

```toml
encrypt = "secrets"  # default — encrypt secret-shaped paths only
# encrypt = "all"    # encrypt every blob
# encrypt = "none"   # only secret-shaped paths get encrypted; everything else stays plain
```

Secret-shaped paths (always encrypted regardless of policy):

- `.env*`, `id_rsa*`, `id_ecdsa*`, `id_ed25519*`, `id_dsa*`
- Extensions: `.pem`, `.key`, `.p12`, `.pfx`, `.jks`, `.asc`, `.gpg`

When an identity is provisioned, **the manifest itself is always encrypted** (`<id>.json.age`) so filenames in entries (e.g. `.env.production`, `customers.sql`) don't leak.

`reflogless doctor` runs an encrypt/decrypt canary on every invocation. It fails fast with `encryption canary roundtrip failed` if the keychain denies access or the identity is corrupt.

## Multi-user safety

`reflogless` refuses to operate when the repo root is owned by a different unix uid than the current process. This blocks accidental cross-user access (e.g. running as your shell user against a repo under another user's home directory). Windows ownership semantics differ — no-op there for now.

## Troubleshooting

### `reflogless: command not found`

Open a new shell. The installer writes to `~/.cargo/bin` or `~/.local/bin`; existing shells need their PATH refreshed. If that doesn't work, run `ls ~/.cargo/bin/reflogless ~/.local/bin/reflogless` to confirm the binary landed and add whichever directory it's in to your PATH.

### `reflogless doctor` reports `canary roundtrip failed`

The keychain refused access or the identity is corrupt. Most common causes:

- **macOS:** Keychain Access denied the lookup. Open Keychain Access.app, search for `reflogless`, delete the entry, and `reflogless init` again (you'll lose decryption ability for prior snapshots).
- **Linux:** D-Bus session dropped or Secret Service provider was killed. Check `systemctl --user status gnome-keyring-daemon` (or `kwalletd`). Restart the session.
- **All platforms:** The keychain entry was deleted out from under reflogless. Same recovery: `reflogless init` again, prior snapshots become unreadable.

### `reflogless doctor` reports `INSECURE FILE KEY`

You installed with `--insecure-file-key`. The identity is a `0600` file at `<store>/identity.key`. Anyone with read access to that file (or a backup of it) can decrypt every snapshot. Migrate to keychain-backed identity by deleting the store + identity file and running `reflogless init` without the flag — prior snapshots become unreadable, the new identity goes into the keychain.

### Hook reports `FOREIGN (not reflogless-managed)`

Another tool installed the same hook file after reflogless. `reflogless init` won't overwrite a foreign hook. Either:

- Configure that tool to chain through `reflogless` (most third-party hook managers like husky and lefthook do this automatically — install reflogless first, then re-run the third-party tool's installer).
- Manually merge: read the foreign hook, prepend `reflogless snap --event <hook-name>` to its first non-shebang line.

### Hook errors logged

`reflogless` writes hook errors to `<store>/hook-errors.log`. The doctor surfaces recent entries. Common cause: encryption canary failed mid-hook (see above). Hook errors never block the underlying git op — the work continues, the snapshot just didn't land.

### Recovering from a corrupted store

`reflogless gc` evicts corrupt snapshots automatically (`snapshots_corrupt_evicted` count in the gc summary). If `reflogless list` is producing UNREADABLE warnings, run `reflogless gc` and they'll drop. If the store itself is unreadable (permissions, disk corruption), the nuclear option is `reflogless uninstall --purge --yes` followed by `reflogless init` — you'll lose snapshot history but the install will be clean.

### Headless Linux / CI / Docker

No D-Bus session → no Secret Service → no keychain. Use `reflogless init --insecure-file-key`. For CI specifically, snapshots are usually pointless (the runner is ephemeral) — consider skipping reflogless entirely on CI and only running it on developer workstations.

## FAQ

**Q: Why not just use `git stash --include-untracked`?**
Stash works for one save-restore cycle and is manual. It also pops on top of your current tree, which is exactly the wrong thing when you've already done destructive cleanup. reflogless writes to a separate store, snapshots automatically around dangerous operations, and lets you restore by ID after the fact — including a week later.

**Q: Why not restic / borg / a generic backup tool?**
Those run on a schedule and don't know what "before this risky git operation" means. reflogless is git-aware — it snapshots at the specific moments work is about to be erased, dedupes via content-addressed storage (so most snapshots cost ~zero bytes), and encrypts only what should be encrypted. Generic backup tools also tend to snapshot the entire filesystem; reflogless only captures untracked + dirty paths and applies sensible default-deny rules.

**Q: How does it compare to autosave plugins (VS Code, JetBrains, etc.)?**
Autosave plugins save your *open buffers*. reflogless captures *the working tree on disk*, including files you've never opened in the editor (build artifacts, generated configs, downloaded fixtures). It also persists across editor restarts, machine reboots, and editor switches.

**Q: Does this protect committed work?**
No. Committed work is already in git — `git reflog` covers that. reflogless covers exactly the gap reflog leaves: untracked and modified-but-unstaged files.

**Q: Performance impact?**
The git hooks fire after the git command completes. Snapshot work happens off the critical path. Content-addressed storage means a snapshot that's mostly unchanged from the prior one writes ~zero new bytes. The per-file 10 MB cap prevents big binaries from causing surprise slowdowns.

**Q: Can I share snapshots between machines?**
Not in v0.1.0. The encryption key is bound to the machine's keychain. v2 may add an optional remote backend ([#4](https://github.com/nhangen/reflogless/issues/4)).

**Q: What happens if I switch machines mid-project?**
Snapshots stay on the old machine. New machine starts fresh. The encryption key doesn't roam.

**Q: Does it work with worktrees?**
Yes — each worktree is treated as its own repo (different `<repo-hash>`). Snapshots from worktree A can't be restored into worktree B even if they share the same `.git`.

## Contributing

Bug reports and PRs welcome. Open an [issue](https://github.com/nhangen/reflogless/issues) first if the change is non-trivial.

```sh
git clone https://github.com/nhangen/reflogless
cd reflogless
cargo test
```

83 tests; should be quick (< 2s).

Conventions:

- One concern per commit. Commit message explains the *why*, not just the *what*.
- TDD where the change has observable behavior. A failing test before the fix; verify the test fails when the fix is reverted.
- PR description includes a Test plan section a reviewer can follow.
- New CLI subcommands need a corresponding doctor check and a README usage line.

## Roadmap

Phases: Core (`snap` / `restore` / CAS store) → Hooks + `init` + `doctor` → Encryption → Packaging → optional `--shim` (covers `git clean -fdx` / `git reset --hard`) → v1.0 → v2.

v0.1.0 ships the first four phases. Open follow-ups:

- [#1](https://github.com/nhangen/reflogless/issues/1) — Restore aarch64-unknown-linux-gnu in the release matrix.
- [#2](https://github.com/nhangen/reflogless/issues/2) — Phase 5: optional `--shim` for `git clean` / `git reset --hard` coverage.
- [#3](https://github.com/nhangen/reflogless/issues/3) — v1.0 release criteria.
- [#4](https://github.com/nhangen/reflogless/issues/4) — v2 backlog (filesystem-watcher daemon, remote backend, multi-repo `list --all`, Authenticode signing).

## History

Originally developed in the [`nhangen/llm-tools`](https://github.com/nhangen/llm-tools) monorepo under the working name `gitsafe` (PRs [#24](https://github.com/nhangen/llm-tools/pull/24), [#25](https://github.com/nhangen/llm-tools/pull/25), [#27](https://github.com/nhangen/llm-tools/pull/27), [#28](https://github.com/nhangen/llm-tools/pull/28), [#29](https://github.com/nhangen/llm-tools/pull/29), [#30](https://github.com/nhangen/llm-tools/pull/30), [#31](https://github.com/nhangen/llm-tools/pull/31)). Extracted on 2026-05-24 and renamed because (a) `gitsafe` is taken on npm and PyPI by adjacent projects, and (b) `nhangen/llm-tools` is private, which blocked the `curl | sh` install UX. Commit history is preserved via `git filter-repo`.

## License

MIT.
