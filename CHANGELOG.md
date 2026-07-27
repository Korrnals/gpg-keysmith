# Changelog

All notable changes to gpg-keysmith are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `.goreleaser.yaml`: goreleaser config with 5 cross-compilation targets (linux/darwin × amd64/arm64, windows/amd64), UPX compression on non-darwin binaries, sha256 checksums, and source archive — replicating the artifact set from the old `scripts/build-artifacts.sh` (#28)
- `.github/workflows/release.yml`: GitHub Actions workflow that runs `goreleaser release` on tag push (`v*`), replacing the manual `scripts/release.sh` build + `gh release create` flow (#28)
- `.goreleaser.yaml`: commented-out publisher sections for Homebrew (`brews:`), AUR (`aurs:`), and cosign signing (`signs:`) — activate when owner-only infra exists (#26, #27, #29)

### Changed
- `scripts/release.sh`: reduced to a thin wrapper — bumps `VERSION`, commits, tags, and pushes; no longer builds or uploads artifacts (goreleaser in CI does that on tag push) (#28)
- `CONTRIBUTING.md`, `docs/ru/CONTRIBUTING.md`: release process section rewritten to describe the two-part flow (local `release.sh` + CI goreleaser) (#28)

### Fixed
- `docs/{en,ru}/installation.md`: corrected checksum filename from `checksums.txt` to `checksums-sha256.txt` (matches the actual artifact name produced by the release pipeline) (#28)

### Removed
- `scripts/build-artifacts.sh`: superseded by goreleaser (the script was gitignored/local-only; the goreleaser config is the new source of truth) (#28)

## [1.4.0] — 2026-07-27

### Added
- `CONTRIBUTING.md`: documented the `PRESET_PASSPHRASE` recipe for signed commits after the wizard (#31, closes #23)
- `docs/{en,ru}/commands/wizard.md`: new "After the wizard" section explaining post-wizard signed commits (#34, closes #24)
- `docs/{en,ru}/security.md`: note on `state.json` concurrency (single wizard instance at a time) (#34, closes #25)
- `internal/gpg`: test coverage raised from 47.8% to 80.9% (#35, closes #30)

### Changed
- `internal/wizard`: `SaveState` now writes to a temp file then renames atomically, preventing partial `state.json` on crash (#32, closes #21)

### Fixed
- `internal/wizard`: `GithubKeyID` is now re-validated against the current GitHub token on wizard re-run, catching stale or revoked keys (#33, closes #22)

## [1.3.2] — 2026-07-27

## [1.3.1] — 2026-07-22

## [1.3.0] — 2026-07-22

## [1.2.0] — 2026-07-21

### Added
- M17: one-line-install — in progress
- make install: one-command install (build + deps check/auto-install + PATH setup), OS/shell auto-detection
- M16: `--version` / `-v` flag on the root command (cobra `Version` field); prints `keysmith <version>` and exits 0 — fixes `make install` verification step which called `keysmith --version` on a binary with no such flag

## [1.1.2] — 2026-07-21

### Added
- M15: polish — `CONTRIBUTING.md` contributor guide + `keysmith.1` man page; fixed README contributing link to point to `CONTRIBUTING.md`

## [1.1.1] — 2026-07-21

### Added
- M14: coverage — `cmd/keysmith` run* happy-path tests via exec mocking (QA1), internal `wizard` (QA3) and `git` coverage backfills

## [1.1.0] — 2026-07-21

### Added
- `--passphrase-file` flag for `generate`/`export`/`wizard` (non-interactive CI/script usage; reads passphrase from file to avoid TTY/survey block; file perms warn if looser than 0600)

## [1.0.1] — 2026-07-20

## [1.0.0] — 2026-07-20

### Added
- M12: readme-sync — in progress
- M11: docs — in progress
- M10: `config` command — persistent defaults (`~/.config/gpg-keysmith/config.yaml`), `config init`/`show`/`path`, `--config` flag, shell completion (`completion bash`/`zsh`/`fish`)

## [0.7.0] — 2026-07-20

### Added
- M9: `status` command — read-only inspector with ✅/❌/⚠️ per-step indicators + remediation hints
- M8: `wizard` command — orchestrates detect→generate→export→git-config→github→publish with per-step confirmation, retry, and resume via state.json

## [0.6.0] — 2026-07-20

### Added
- M7: `publish` command — upload public key to keys.openpgp.org + keyserver.ubuntu.com

## [0.5.0] — 2026-07-20

### Added
- M6: `github` command group — upload pubkey, set repo secrets, commit pubkey file + PR

## [0.4.0] — 2026-07-20

### Added
- M5: `git-config` command — sets `user.name`, `user.email`, `user.signingkey`, `commit.gpgsign=true`, `gpg.format=openpgp`, `tag.gpgsign=true` in local repo config (or `--global`); reads keyid from `detect` if not given; resolves empty name/email from existing config

## [0.3.0] — 2026-07-20

### Added
- M4: `export` command — exports ASCII-armored public key to file (0644), captures private key in memory (never on disk); passphrase via `--passphrase-fd 0` stdin, never CLI arg; keyID hex-validated

## [0.2.0] — 2026-07-20

### Added
- M3: generate command
- M1: project scaffold — cobra CLI with 8 subcommands, `internal/` package layout
- M2: `detect` command — parses `gpg --with-colons`, lists existing GPG keys

## [0.1.0] — 2026-07-19

### Added
- Initial baseline: scaffold (M1) + `detect` command (M2)
- `detect` lists real GPG secret keys with keyid, created/expires, user id
- `DetectKeyForEmail(email)` exported for downstream milestones
