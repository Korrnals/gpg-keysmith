# gpg-keysmith

<p align="center">
  <img src="../assets/banner.svg" alt="gpg-keysmith banner" width="100%"/>
</p>

[![English](https://img.shields.io/badge/lang-English-blue.svg)](./README.md) [![Русский](https://img.shields.io/badge/lang-Русский-red.svg)](../ru/README.md)

[![Version](https://img.shields.io/badge/version-1.0.0-0f766e.svg)](../../VERSION) [![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](../../LICENSE) [![Go](https://img.shields.io/badge/Go-1.22%2B-00add8.svg)](https://go.dev) [![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)](./installation.md)

`gpg-keysmith` is a Go CLI that automates the full path from "no GPG key" to "signed commits flowing on GitHub". A single `keysmith wizard` invocation walks a developer through every step: generate a GPG key, export the public key, configure `git` to sign commits and tags, upload the public key to GitHub, store the private key as a repository Action secret for CI signing, and publish the public key to a keyserver.

This is the full English documentation. The condensed root [README](../../README.md) links here.

## Highlights

- **End-to-end automation.** `keysmith wizard` orchestrates six milestones in order: detect → generate → export → git-config → github → publish. Each step prompts for confirmation, offers retry/skip/abort on failure, and writes completion to a state file so a failed run resumes from the last successful step.
- **Safe by design.** Passphrase via stdin, private key in memory only, GitHub PAT from an env var — see [Security](./security.md).
- **Drives battle-tested tools.** Shells out to `gpg`, `git`, and `gh` rather than reimplementing cryptography. Only validated hex key IDs and owner/repo names ever reach a subprocess.
- **Inspectable.** `keysmith status` reports per-step ✅ / ❌ / ⚠️ with one-line remediation hints, so a partial setup can be diagnosed and resumed.

## Quick start

```bash
go install github.com/Korrnals/gpg-keysmith/cmd/keysmith@latest
export GITHUB_TOKEN=ghp_your_pat_with_repo_admin_gpg_key
keysmith wizard
```

The wizard prompts for confirmation at each step. Pass any flag (`--name`, `--email`, `--repo owner/name`, etc.) to pre-fill the prompts and run partially non-interactively.

## Documentation index

| Topic | Document |
|---|---|
| Installation, prerequisites, shell completion | [installation.md](./installation.md) |
| Architecture, package layout, integration model | [architecture.md](./architecture.md) |
| Security model, threat model, controls | [security.md](./security.md) |
| Command reference (9 commands) | [commands/](./commands/) |

## Command overview

| Command | What it does |
|---|---|
| [`wizard`](./commands/wizard.md) | Run the full interactive setup flow (default entry point) |
| [`detect`](./commands/detect.md) | List existing GPG secret keys for the current user |
| [`generate`](./commands/generate.md) | Generate a new GPG key via `gpg --gen-key` |
| [`export`](./commands/export.md) | Export the public key to a file; capture the private key in memory |
| [`git-config`](./commands/git-config.md) | Set `user.signingkey`, `commit.gpgsign`, `gpg.format`, `tag.gpgsign` |
| [`github`](./commands/github.md) | Upload public key to GitHub, set repo secrets, open a PR |
| [`publish`](./commands/publish.md) | Publish the public key to a keyserver |
| [`status`](./commands/status.md) | Show current setup state with per-step indicators |
| [`config`](./commands/config.md) | Manage the persistent config file (`init` / `show` / `path`) |

Each command accepts `--help`:

```bash
keysmith <command> --help
```

## Architecture at a glance

`gpg-keysmith` is a Go CLI built on [cobra](https://github.com/spf13/cobra) and [survey](https://github.com/AlecAivazis/survey). It is **not** a Go GPG library binding — only `internal/gpg` shells out to the system `gpg` binary, with hex-validated key IDs. `internal/git` shells out to `git config`. `internal/github` uses the GitHub REST API (`net/http`) for public-key upload, file commit, and PR, and shells out to `gh secret set` for repository secrets so libsodium sealing stays in the `gh` CLI. `internal/keyserver` publishes via HTTPS POST.

Full details: [Architecture](./architecture.md).

## Security at a glance

Three protected assets — **passphrase**, **private key**, **GitHub PAT** — never cross a leak surface. Passphrase is piped to `gpg` via `--passphrase-fd 0` stdin (never a CLI arg, never a batch file). The private key is exported into memory only and held in-process for the `github` step. The PAT is read from an env var named by `config.github.token_env`; the `--token` flag was removed because it leaked via `ps` and `/proc/cmdline`.

Full threat model, controls, and non-goals: [Security](./security.md).

## Contributing

Pull requests welcome. Before submitting, run the local CI pipeline:

```bash
make ci     # mod verify + fmt + vet + build + test — must be green
```

Follow [Conventional Commits](https://www.conventionalcommits.org/) for commit messages. See [DEVELOPMENT.md](../../DEVELOPMENT.md) for the original 10-milestone roadmap.

## License

MIT — see [LICENSE](../../LICENSE). Copyright © 2026 Leonid Golikhin.