# `github`

Upload the GPG public key to GitHub, set repo Action secrets, and open a PR with the pubkey file.

## Synopsis

```
keysmith github [flags]
```

`github` performs three actions:

1. Upload the public key to the authenticated user's GitHub GPG keys (`users/gpg_keys` REST API).
2. Store the private key and passphrase as repository Action secrets `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE` (via `gh secret set`).
3. Commit the public key file to the target repo on a `chore/add-gpg-public-key` branch and open a pull request.

Requires a GitHub PAT with `admin:gpg_key` (for the public key upload) and `repo` + `admin:repo_hook` scopes (for the repo secrets). The `gh` CLI must be installed for the secrets step — `gpg-keysmith` shells out to `gh secret set` to avoid a libsodium native binding dependency.

## Token resolution

The token is resolved from env vars only, never a flag:

1. Env var named by `config.github.token_env` (default `GITHUB_TOKEN`)
2. `GH_TOKEN` env var as fallback

The `--token` flag would leak via `ps` and `/proc/cmdline` — it was removed in security hardening. Passphrase uses stdin for the same reason; the two stay symmetric.

## Flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `--keyid` | string | `""` | GPG key id to export (if empty, pick interactively from `detect`) |
| `--pubkey-file` | string | `""` | Read armored public key from this file instead of calling `gpg --export` |
| `--repo` | string | `""` (required) | Target repo as `owner/name` |
| `-h`, `--help` | bool | `false` | Print help for `github` |
| `--config` | string | `~/.config/gpg-keysmith/config.yaml` | Path to the config file (global flag) |

`--repo` is required. If `--keyid` is empty, the key is picked interactively from `gpg --list-secret-keys`. If `--pubkey-file` is set, the armored public key is read from that file instead of calling `gpg --export`.

## Examples

### Upload to a repo (interactive key pick)

```bash
export GITHUB_TOKEN=ghp_your_pat_with_repo_admin_gpg_key
keysmith github --repo owner/name
```

### Upload a specific key non-interactively

```bash
keysmith github --repo owner/name --keyid F49BE957CD553B1C
```

### Use a pre-exported pubkey file (skip `gpg --export`)

```bash
keysmith export --keyid F49BE957CD553B1C --pubkey ./gpg-public-key.asc
keysmith github --repo owner/name --pubkey-file ./gpg-public-key.asc
```

### Use a different env var for the token

```bash
# In ~/.config/gpg-keysmith/config.yaml:
#   github:
#     token_env: MY_GH_TOKEN
export MY_GH_TOKEN=ghp_...
keysmith github --repo owner/name
```

## Required PAT scopes

| Scope | Why |
|---|---|
| `admin:gpg_key` | Upload the public key to the user's GitHub GPG keys |
| `repo` | Set repo secrets, commit the pubkey file, open a PR |
| `admin:repo_hook` | Required alongside `repo` for repo-secret writes |

## Notes

- **Public key de-dup.** `github` detects existing GPG keys by fingerprint and does not re-upload.
- **Secrets via `gh`.** Repository secrets use libsodium sealed-secret encryption, which `gh secret set` handles natively. Reimplementing it in Go would pull in a libsodium native binding; shelling out to `gh` keeps the dependency surface small and the sealing logic in a battle-tested tool.
- **PR branch.** The pubkey file is committed to a `chore/add-gpg-public-key` branch and a PR is opened against the default branch.
- **owner/repo validation.** `ValidateOwnerRepo` rejects anything outside `^[A-Za-z0-9._-]+$` before the repo name reaches a URL path; `url.PathEscape` is applied as defense-in-depth. See [Security](../security.md).
- **Runtime dependencies.** Requires `gh` (GitHub CLI) for the secrets step, and `gpg` if `--pubkey-file` is not given.
- **Passphrase handling.** The passphrase is piped to `gpg --export-secret-keys` via stdin when the private key is captured (only when `--pubkey-file` is not given). It is never a CLI arg.

## See also

- [`export`](./export.md) — produce the `--pubkey-file` ahead of time
- [`status`](./status.md) — check the public key and repo secrets are in place
- [`wizard`](./wizard.md) — run `github` as the fifth step of the full flow
- [`config`](./config.md) — set `github.token_env` to use a non-default env var