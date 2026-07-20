# Changelog

All notable changes to gpg-keysmith are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] — 2026-07-20

### Added
- M3: generate — in progress
- M1: project scaffold — cobra CLI with 8 subcommands, `internal/` package layout
- M2: `detect` command — parses `gpg --with-colons`, lists existing GPG keys

## [0.1.0] — 2026-07-19

### Added
- Initial baseline: scaffold (M1) + `detect` command (M2)
- `detect` lists real GPG secret keys with keyid, created/expires, user id
- `DetectKeyForEmail(email)` exported for downstream milestones
