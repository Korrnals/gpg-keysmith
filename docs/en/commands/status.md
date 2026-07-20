# `status`

Show the current state of your GPG + GitHub setup with per-step ✅ / ❌ / ⚠️ indicators.

## Synopsis

```
keysmith status [flags]
```

`status` is a read-only inspector. It performs five checks and emits a single table with a per-step indicator. Each non-green check emits a one-line remediation hint.

## The five checks

| # | Check | What it inspects | Source |
|---|---|---|---|
| 1 | GPG keys | Local gpg keyring | `gpg --list-secret-keys` |
| 2 | Git config | `user.signingkey` + `commit.gpgsign` in the local repo | `git config --local --get` |
| 3 | GitHub pubkey | GPG keys uploaded to your GitHub account | `users/gpg_keys` REST API |
| 4 | Repo secrets | `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE` on the target repo | `gh secret list` |
| 5 | Keyserver | Public key published to the keyserver (by fingerprint) | HTTPS GET to the keyserver |

If `--repo` is omitted, the repo-secrets check degrades to ⚠️ (skipped, not failed).

## Token resolution

The token is resolved from env vars only, never a flag:

1. Env var named by `config.github.token_env` (default `GITHUB_TOKEN`)
2. `GH_TOKEN` env var as fallback

## Flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `--fingerprint` | string | `""` (derived from first key) | GPG key fingerprint (optional — derived from first key if empty) |
| `--keyserver` | string | `"keys.openpgp.org"` | Keyserver to check for key publication |
| `--repo` | string | `""` | Target repo as `owner/name` (optional — secrets check degrades to ⚠️ if omitted) |
| `-h`, `--help` | bool | `false` | Print help for `status` |
| `--config` | string | `~/.config/gpg-keysmith/config.yaml` | Path to the config file (global flag) |

## Examples

### Full status (all five checks)

```bash
export GITHUB_TOKEN=ghp_...
keysmith status --repo owner/name
```

### Skip the repo-secrets check

```bash
keysmith status
```

The repo-secrets check shows ⚠️ (skipped, not failed) when `--repo` is omitted.

### Check a specific fingerprint on a different keyserver

```bash
keysmith status --repo owner/name \
  --fingerprint F49BE957CD553B1C1234567890ABCDEF12345678 \
  --keyserver keyserver.ubuntu.com
```

### Sample output (fully set up)

```
Status:

  1. GPG keys        ✅  1 key found (F49BE957CD553B1C)
  2. Git config      ✅  user.signingkey set, commit.gpgsign=true
  3. GitHub pubkey   ✅  1 GPG key uploaded
  4. Repo secrets    ✅  GPG_PRIVATE_KEY + GPG_PASSPHRASE set on owner/name
  5. Keyserver       ✅  key published to keys.openpgp.org
```

### Sample output (fresh machine)

```
Status:

  1. GPG keys        ❌  no keys found — run 'keysmith generate'
  2. Git config      ❌  user.signingkey not set — run 'keysmith git-config'
  3. GitHub pubkey   ❌  no GPG keys uploaded — run 'keysmith github'
  4. Repo secrets    ⚠️  --repo not given, skipping
  5. Keyserver       ❌  key not found on keyserver — run 'keysmith publish'
```

## Notes

- **Read-only.** `status` does not modify anything — it only inspects and reports.
- **One-line remediation.** Every non-green check emits a single-line hint pointing at the command to fix it.
- **Keyserver check.** The fingerprint is hex-validated before being used in the keyserver lookup URL.
- **Token for GitHub checks.** Checks 3 and 4 require the GitHub PAT. If the token is missing, those checks degrade to ⚠️ (cannot authenticate).
- **Runtime dependencies.** Requires `gpg` (checks 1, 5), `git` (check 2), `gh` (check 4), and the GitHub PAT (checks 3, 4).

## See also

- [`detect`](./detect.md) — the GPG-key check `status` runs
- [`git-config`](./git-config.md) — fix the git config check
- [`github`](./github.md) — fix the GitHub pubkey + repo secrets checks
- [`publish`](./publish.md) — fix the keyserver check
- [`wizard`](./wizard.md) — run the full flow to get all-green