# `wizard`

Run the full `gpg-keysmith` setup flow end-to-end.

## Synopsis

```
keysmith wizard [flags]
```

The wizard orchestrates the six milestones in order:

```mermaid
flowchart LR
  D[detect] --> G[generate]
  G --> E[export]
  E --> GC[git-config]
  GC --> GH[github]
  GH --> P[publish]
```

Each step prompts for confirmation, offers retry / skip / abort on failure, and writes its completion to `~/.config/gpg-keysmith/state.json` so a failed run can be resumed from the last successful step. On full completion the state file is cleared.

Flags pre-fill the survey prompts; any flag left empty is collected interactively. `--reset` clears the state file and starts fresh.

## Flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `--comment` | string | `""` | Optional comment for the key user id (prompted if empty) |
| `--email` | string | `""` | Email for the key + git `user.email` (prompted if empty) |
| `--expiry` | string | `"0"` | Expiry date spec (`0` = never, `2y` = 2 years) |
| `--key-length` | int | `4096` | RSA key length in bits |
| `--keyserver` | string | `"all"` | Keyserver target: `all` (default), `openpgp`, or `ubuntu` |
| `--name` | string | `""` | Real name for the key + git `user.name` (prompted if empty) |
| `--repo` | string | `""` | Target GitHub repo as `owner/name` (prompted if empty) |
| `--reset` | bool | `false` | Clear the state file and start fresh (ignore prior progress) |
| `--state-path` | string | `~/.config/gpg-keysmith/state.json` | Override state file location |
| `-h`, `--help` | bool | `false` | Print help for `wizard` |
| `--config` | string | `~/.config/gpg-keysmith/config.yaml` | Path to the config file (global flag) |

## Examples

### Fully interactive (prompt for everything)

```bash
export GITHUB_TOKEN=ghp_your_pat_with_repo_admin_gpg_key
keysmith wizard
```

The wizard walks every step, prompting for name, email, comment, expiry, key length, repo, and passphrase as needed.

### Pre-fill name, email, repo (rest prompted)

```bash
keysmith wizard --name "Jane Doe" --email jane@example.com --repo owner/name
```

### Generate a 2-year key with a comment

```bash
keysmith wizard --name "Jane Doe" --email jane@example.com --repo owner/name \
  --comment "acme-corp signing" --expiry 2y
```

### Publish only to keys.openpgp.org

```bash
keysmith wizard --name "Jane Doe" --email jane@example.com --repo owner/name \
  --keyserver openpgp
```

### Resume after a failure

```bash
# Previous run failed at the github step
keysmith wizard   # resumes from the github step; detect/generate/export/git-config are skipped
```

### Start over and ignore prior progress

```bash
keysmith wizard --reset
```

## Security notes

- **Passphrase is always a masked prompt.** The passphrase is collected via `survey.Password` and piped to `gpg` via stdin. It is never read from a flag (which would leak via shell history / `ps`).
- **State file never contains secrets.** The state file records only step names, key id, email, and repo. The `Passphrase`, `PrivateKey`, and `PubKeyArmor` fields on `WizardState` carry the `json:"-"` tag — they are held in memory between steps and discarded at the end of the run. The invariant is verified by `TestSaveStateOmitsSecrets`. See [Security](../security.md).
- **Runtime dependencies.** Requires `gpg`, `git`, and `gh` (for the github step), plus the GitHub PAT env var.

## Per-step behaviour

| Step | What it does | On failure |
|---|---|---|
| `detect` | List existing GPG keys | If keys exist, the wizard offers to use one; if none, it proceeds to `generate` |
| `generate` | Create a new key (or reuse an existing one) | Retry / skip / abort |
| `export` | Export the public key to `gpg-public-key.asc`, capture private key in memory | Retry / skip / abort |
| `git-config` | Set the six git signing keys in the local repo | Retry / skip / abort |
| `github` | Upload public key, set repo secrets, open a PR | Retry / skip / abort |
| `publish` | Publish the public key to the keyserver(s) | Retry / skip / abort |

Skipping a step records it as completed in the state file, so the wizard resumes from the next step on a re-run.

## See also

- [`detect`](./detect.md) — step 1
- [`generate`](./generate.md) — step 2
- [`export`](./export.md) — step 3
- [`git-config`](./git-config.md) — step 4
- [`github`](./github.md) — step 5
- [`publish`](./publish.md) — step 6
- [`status`](./status.md) — inspect what the wizard produced
- [`config`](./config.md) — set persistent defaults the wizard reads