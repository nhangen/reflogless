# gitsafe

Local untracked-file safety net for git. Snapshots untracked + dirty files into a content-addressed store so `git clean -fdx`, `git reset --hard`, and bad rebases don't destroy work.

> **Status:** Phase 2 (Hooks + init + doctor). Manual snap, plus auto-snap on `post-checkout` / `pre-rebase` / `post-rewrite` / `reference-transaction` after `gitsafe init`. Encryption (Phase 3), packaging (Phase 4), and the optional `--shim` (Phase 5) are still ahead.

## Wedge

- Monorepo developers with untracked generated config (`.env.local`, build artifacts).
- ML / data folks with untracked datasets and notebooks.
- Anyone burned by `git clean -fdx` who wants a passive safety net.

Not a `git stash` replacement. Tracked-file workflows stay with stash + reflog.

## Install (Phase 1, source-build)

```sh
cd gitsafe
cargo install --path .
```

Homebrew / Scoop / cargo-dist arrive in Phase 4.

## Usage

```sh
gitsafe init                      # install hooks (honors core.hooksPath)
gitsafe doctor                    # verify install + store + canary
gitsafe snap -m "before rebase"   # manual snapshot
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

## Roadmap

See issues [#17](https://github.com/nhangen/llm-tools/issues/17)–[#23](https://github.com/nhangen/llm-tools/issues/23). Phases: Core → Hooks/init/doctor → Encryption → Packaging → Shim → v1.0 → v2.

## License

MIT.
