# Development Plan — gpg-keysmith

`gpg-keysmith` is a Go CLI that automates the full path from "no GPG key" to "signed commits flowing on GitHub". This document is the canonical 10-milestone roadmap. Each milestone is independently shippable and reviewable.

## Goals

- **End-to-end automation.** A developer runs `keysmith wizard` once and ends up with: a fresh GPG key, the public key uploaded to GitHub, `git config user.signingkey` set, the private key stored as a repository secret for CI, and the public key published to a keyserver.
- **Reproducible.** No "click around the GitHub UI" steps. Every step is a CLI invocation the wizard orchestrates.
- **Safe.** Private key material never touches disk in plaintext beyond the standard `~/.gnupg` storage; never printed to stdout; never committed to a repo.
- **Inspectable.** `keysmith status` shows exactly what is and is not configured, so a partial setup can be resumed.

## Non-goals

- We do **not** replace `gpg` itself — we drive it via `gpg --full-generate-key` and friends.
- We do **not** manage SSH keys, age keys, or any non-OpenPGP signing scheme.
- We do **not** implement a custom keyserver — we publish to existing ones (`keys.openpgp.org`, `keyserver.ubuntu.com`).

## Milestones

### Milestone 1 — Scaffold ✅

Create the project skeleton: `cmd/keysmith/main.go` (cobra root), `internal/` packages (`gpg`, `github`, `git`, `keyserver`, `config`, `wizard`), `go.mod`, `Makefile`, `README.md`, `LICENSE` (MIT, 2026, Leonid Golikhin), `.gitignore`, this `DEVELOPMENT.md`. All `internal/` files are stubs with function signatures and `TODO` comments. `go build ./...` must pass.

**Done when:** `go build ./...` compiles; `go run ./cmd/keysmith` shows help with all subcommands.

### Milestone 2 — `detect` command ✅

Implement `internal/gpg/detect.go`: parse `gpg --list-secret-keys --keyid-format=long --with-colons` into a `[]GpgKey` and render a table from the `detect` subcommand. Also export `DetectKeyForEmail(email string) (*GpgKey, error)` for use by later milestones.

**Done when:** `go run ./cmd/keysmith detect` lists the user's real GPG keys; `DetectKeyForEmail` returns the right key for an email that exists.

### Milestone 3 — `generate` command

Implement `internal/gpg/generate.go`: drive `gpg --full-generate-key` with a batch parameter file (`%no-protection` is forbidden — we always require a passphrase; the wizard collects it once and pipes it via `gpg --pinentry-mode loopback`). Key parameters: RSA 4096, no expiry by default (configurable), user name + email + comment collected via `survey`.

**Done when:** running `keysmith generate` in a clean `gpg` keystore produces a new secret key visible via `keysmith detect`.

### Milestone 4 — `export` command

Implement `internal/gpg/export.go`: export the public key (`gpg --armor --export <keyid>`) and the private key (`gpg --armor --export-secret-keys <keyid>`, with `--pinentry-mode loopback` and the passphrase). Public key is written to `gpg-public-key.asc`; private key is held in memory only and piped to the GitHub secrets step (Milestone 6). Never write the private key to disk.

**Done when:** `keysmith export --keyid <id> --pubkey gpg-public-key.asc` produces a valid ASCII-armored public key file; the private key is captured in memory and never logged.

### Milestone 5 — `git-config` command

Implement `internal/git/config.go`: set `user.name`, `user.email`, `user.signingkey`, `commit.gpgsign=true`, `gpg.format=openpgp`, `tag.gpgsign=true` in the local repo config (with `--global` opt-in via a flag). Reads the keyid from `detect` if not given.

**Done when:** after `keysmith git-config`, `git config --local --list` shows the signing settings and `git commit -S --allow-empty -m test` produces a signed commit verifiable with `git verify-commit HEAD`.

### Milestone 6 — `github` command group

Implement `internal/github/`:

- `pubkey.go` — upload the public key to GitHub via the `users/gpg_keys` REST API (requires a PAT with `admin:gpg_key` scope). Detect existing keys by fingerprint; do not re-upload.
- `secrets.go` — store the private key as a repository secret `GPG_PRIVATE_KEY` and the passphrase as `GPG_PASSPHRASE` via the `repos/{owner}/{repo}/actions/secrets` API (requires `repo` + `admin:repo_hook` scopes). Uses libsodium-sealed secrets — implement via the `github.com/bradleyfalzon/ghinstallation/v2`-style sealed-box approach or shell out to `gh` CLI when available.
- `repo.go` — commit `gpg-public-key.asc` to the target repo on a `chore/add-gpg-public-key` branch and open a PR. Uses `go-git` or shells out to `git`.

**Done when:** `keysmith github --repo owner/name` uploads the public key, sets the two repo secrets, and opens a PR adding `gpg-public-key.asc`.

### Milestone 7 — `publish` command

Implement `internal/keyserver/publish.go`: publish the public key to `keys.openpgp.org` (preferred, no email-verification needed for the key itself, but a verification email is sent for the UID) and `keyserver.ubuntu.com` (fallback). Use HTTPS submit endpoints, not the legacy HKP `hkp://` protocol.

**Done when:** `keysmith publish` uploads the public key and the returned URL (`https://keys.openpgp.org/vks/vby/<fingerprint>`) is fetchable.

### Milestone 8 — `wizard` command

Implement `internal/wizard/wizard.go`: orchestrate milestones 2–7 in order, with per-step confirmation, retry-on-failure, and a resume capability keyed off `~/.config/gpg-keysmith/state.json`. Each step writes its completion to the state file so a failed run can be resumed from the last successful step.

**Done when:** a clean user (no GPG key, no GitHub PAT) can run `keysmith wizard` once and end up fully set up; re-running on a partially-set-up machine resumes from the last incomplete step.

### Milestone 9 — `status` command

Implement `status` as a read-only inspector: shows existing keys (via `detect`), checks `git config` for signing settings, queries GitHub for the user's uploaded GPG keys, checks the target repo for the `GPG_PRIVATE_KEY` / `GPG_PASSPHRASE` secrets, and checks keyserver presence by fingerprint. Emits a single table with a per-step ✅ / ❌ / ⚠️ indicator.

**Done when:** `keysmith status` on a fully-set-up machine shows all-green; on a fresh machine shows all-red with one-line remediation hints per step.

### Milestone 10 — Config, polish, release

Implement `internal/config/config.go` (~/.config/gpg-keysmith/config.yaml): persistent defaults for key type, length, expiry, keyserver choice, GitHub PAT storage reference (env var name, never the value), default repo. Add `--config` flag, `keysmith config init` to write a template, `keysmith config show`. Polish: man page, shell completion (`keysmith completion bash/zsh/fish`), Homebrew formula, Arch AUR, GitHub Release with `goreleaser`, signed release binaries (dogfooded — the release is signed with a key produced by `keysmith` itself).

**Done when:** v1.0.0 tag is cut, release binaries are published and signed, and the Homebrew formula installs cleanly on a fresh macOS machine.

## Architecture

```
cmd/keysmith/main.go        — cobra root + subcommand wiring
internal/
  gpg/        — gpg CLI wrapper (detect, generate, export)
  github/     — GitHub REST API client (pubkey, secrets, repo)
  git/        — local git config wrapper
  keyserver/  — keyserver publish client
  config/     — YAML config loader/writer
  wizard/     — orchestration of the full flow
```

No package in `internal/` imports `cmd/`. `internal/wizard` may import any other `internal/` package. `internal/github` does not import `internal/git` and vice versa. The `gpg` package is the only one allowed to shell out to the `gpg` binary.

## Testing strategy

- **Unit tests** for parsers (`detect` colon output, config YAML).
- **Integration tests** that shell out to a real `gpg` against a temp `GNUPGHOME` — these are tagged `//go:build integration` and skipped in CI by default.
- **No network tests** in the default suite; GitHub and keyserver calls are behind interfaces with mock implementations in tests.

## Release policy

Semantic versioning. `main` is always green. Releases cut from `release/vX.Y.Z` branches; hotfixes from `hotfix/vX.Y.Z`. See `git-workflow` policy.