# gitsafe

Local untracked-file safety net for git. Snapshots untracked + dirty files into a content-addressed store so `git clean -fdx`, `git reset --hard`, and bad rebases don't destroy work.

> **Status:** Phase 4 (Packaging) in progress. Manual snap + hook-driven snaps with at-rest encryption: age-based blob/manifest encryption with the identity stored in the OS keychain (macOS Keychain / Linux Secret Service / Windows DPAPI via the `keyring` crate). Tag-driven multi-OS releases via cargo-dist are wired up; the first `gitsafe-v0.1.0` tag will publish shell + PowerShell installers and per-target archives. Homebrew tap, Scoop manifest, and the optional `--shim` (Phase 5) are still ahead.

## Wedge

- Monorepo developers with untracked generated config (`.env.local`, build artifacts).
- ML / data folks with untracked datasets and notebooks.
- Anyone burned by `git clean -fdx` who wants a passive safety net.

Not a `git stash` replacement. Tracked-file workflows stay with stash + reflog.

## Install

### From source (works today)

Requires a Rust toolchain (install via [rustup.rs](https://rustup.rs)). From the repo root:

```sh
cd gitsafe
cargo install --path .
```

### Prebuilt binaries (after `gitsafe-v0.1.0` is tagged)

The installer URLs below 404 until the first release is published — running the snippets before then will print a `curl: (56) The requested URL returned error: 404` and install nothing.

**macOS / Linux:**

```sh
# Available after gitsafe-v0.1.0 is tagged
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/nhangen/llm-tools/releases/latest/download/gitsafe-installer.sh | sh
```

**Windows (PowerShell):**

```powershell
# Available after gitsafe-v0.1.0 is tagged
powershell -ExecutionPolicy ByPass -c "irm https://github.com/nhangen/llm-tools/releases/latest/download/gitsafe-installer.ps1 | iex"
```

Or download a per-platform archive directly from the [releases page](https://github.com/nhangen/llm-tools/releases): `gitsafe-aarch64-apple-darwin.tar.xz` (Apple Silicon), `gitsafe-x86_64-apple-darwin.tar.xz` (Intel Mac), `gitsafe-x86_64-unknown-linux-gnu.tar.xz`, `gitsafe-x86_64-pc-windows-msvc.zip`. aarch64-linux (Graviton, RPi, Ampere) needs to build from source for v0.1.0 — prebuilt arm64-linux is a follow-up.

> **Windows users:** v0.1.0 binaries are unsigned. SmartScreen will warn on first run ("Windows protected your PC") — choose *More info* → *Run anyway*. On enterprise machines with Smart App Control or AppLocker in enforcement mode the binary may be blocked silently with no warning dialog — use `cargo install --path .` from source or wait for v2 signed builds. Authenticode EV signing is deferred to v2 (cert is $300–600/year + HSM).

### Linux prerequisite for encryption

`gitsafe init` provisions an age identity into the OS keychain via the [`keyring` crate](https://crates.io/crates/keyring). On Linux that requires a running Secret Service provider (gnome-keyring or KWallet) and an active D-Bus session — headless servers, Docker containers, CI runners, and ssh-only boxes have none. On those hosts use `gitsafe init --insecure-file-key` to store the identity in a `0600` file at `<store>/identity.key`; `gitsafe doctor` will surface this as `INSECURE FILE KEY`.

### Verify

```sh
gitsafe --version
gitsafe doctor   # checks hooks, store, encryption canary roundtrip
```

Open a new shell first if `gitsafe` isn't found — the cargo-dist installer writes to `~/.cargo/bin` (or `~/.local/bin`) which existing shells may not have on PATH yet.

Homebrew tap + Scoop manifest are next; tracked in the Phase 4 plan.

## Usage

```sh
gitsafe init                      # install hooks + provision encryption identity in OS keychain
gitsafe init --insecure-file-key  # store key on disk (loud warning; doctor surfaces it)
gitsafe doctor                    # verify install + store + canary + encryption roundtrip
gitsafe snap -m "before rebase"   # manual snapshot (honors .gitsafe.toml policy)
gitsafe list                      # all snapshots for this repo
gitsafe show <id>                 # files in a snapshot
gitsafe restore <id>              # restore (refuses overwrite without --force)
gitsafe restore latest            # restore most recent
gitsafe restore <id> path/to/file # restore one path
gitsafe diff <id> [path]          # unified diff snap vs work
gitsafe gc                        # LRU + age eviction
gitsafe uninstall                 # remove hooks; restore prior chained hooks
gitsafe uninstall --purge --yes   # also delete the store (--yes required)
```

Snapshot IDs accept a unique prefix (`gitsafe restore 20260519T13` works if it disambiguates).

## Storage

- `$GITSAFE_DATA_DIR` if set (explicit override; primarily for tests), else `$XDG_DATA_HOME/gitsafe/<repo-hash>/`, else `dirs::data_dir()`.
- `objects/<a>/<b>` — SHA-256 content-addressed blobs (auto-dedup).
- `snapshots/<ts>-<event>.json` — manifests referencing blob digests + relpaths + mode bits.
- Unix: store dirs are mode `0700`, files `0600`, and restored files preserve their original mode. On Windows, mode bits and `0700/0600` are not enforced (Phase 1 — revisit in Phase 4 packaging).

## File selection

- Includes: untracked + modified-unstaged (`git status --porcelain=v1 -uall`).
- Honors `.gitignore` (via git status) and `.gitsafeignore` at repo root.
- Default-deny: `node_modules/`, `vendor/`, `.venv/`, `target/`, `dist/`, `*.log`.
- Per-file cap: 10 MB. Larger files are skipped with a note.

## Hook coverage

After `gitsafe init`:

- `post-checkout` — auto-snap on branch switch.
- `pre-rebase`, `post-rewrite` — bracket rebase operations.
- `reference-transaction` (git ≥ 2.28) — belt-and-suspenders for ref updates.

Hooks are best-effort: a snap failure never blocks the underlying git op. **`git` exposes no hooks on `clean` or `reset --hard`** — those land in Phase 5 via the opt-in `--shim`.

If a third-party hook is already installed (husky, lefthook, hand-written), gitsafe preserves it: the prior file is renamed to `<hook>.gitsafe-orig` and gitsafe's wrapper `exec`s it after taking the snapshot. `gitsafe uninstall` restores the prior hook from `.gitsafe-orig`.

`gitsafe doctor` reports each hook's state (`OK`, `OK (chained)`, `FOREIGN`, `MISSING`), store size + snapshot count, canary roundtrip, and shim status (currently always `off`).

## Encryption

`gitsafe init` provisions an [age](https://github.com/FiloSottile/age) x25519 identity:

- Secret key lives in the OS keychain (service `gitsafe`, account = repo hash).
- Public recipient is written to `<store>/recipient.txt` (not secret).
- `--insecure-file-key` falls back to a 0600 file at `<store>/identity.key`. Doctor surfaces this as `INSECURE FILE KEY`.

Encryption policy is set in `.gitsafe.toml` at the repo root:

```toml
encrypt = "secrets"  # default — encrypt secret-shaped paths only
# encrypt = "all"    # encrypt every blob
# encrypt = "none"   # only secret-shaped paths get encrypted; everything else stays plain
```

Secret-shaped paths (always encrypted regardless of policy):

- `.env*`, `id_rsa*`, `id_ecdsa*`, `id_ed25519*`, `id_dsa*`
- Extensions: `.pem`, `.key`, `.p12`, `.pfx`, `.jks`, `.asc`, `.gpg`

When an identity is provisioned, **the manifest itself is always encrypted** (`<id>.json.age`) so filenames in entries (e.g. `.env.production`, `customers.sql`) don't leak.

`gitsafe doctor` runs an encrypt/decrypt canary on every invocation. It fails fast with `encryption canary roundtrip failed` if the keychain denies access or the identity is corrupt.

## Multi-user safety

`gitsafe` refuses to operate when the repo root is owned by a different unix uid than the current process. This blocks accidental cross-user access (e.g. running as your shell user against a repo under another user's home directory). Windows ownership semantics differ — no-op there for now.

## Roadmap

See issues [#17](https://github.com/nhangen/llm-tools/issues/17)–[#23](https://github.com/nhangen/llm-tools/issues/23). Phases: Core → Hooks/init/doctor → Encryption → Packaging → Shim → v1.0 → v2.

## License

MIT.
