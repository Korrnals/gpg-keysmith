# Changelog

All notable changes to gpg-keysmith are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
