# `git-config`

Configure the local git repository (or `--global` user config) to sign commits and tags with a GPG key.

## Synopsis

```
keysmith git-config [flags]
```

`git-config` sets six git config keys:

| Config key | Value |
|---|---|
| `user.name` | real name for the commit author |
| `user.email` | email for the commit author |
| `user.signingkey` | the GPG key id to sign with |
| `commit.gpgsign` | `true` (sign every commit) |
| `gpg.format` | `openpgp` (this tool only supports OpenPGP) |
| `tag.gpgsign` | `true` (sign every tag) |

If `--name` or `--email` are not given, the existing `user.name` / `user.email` are read from git config and preserved. If they are not set anywhere, an error is returned telling you to pass `--name` / `--email` or set them first.

If `--keyid` is not given, the existing `user.signingkey` is read from git config; if that is also unset, `gpg --list-secret-keys` is scanned and you are prompted to pick a key. If no GPG keys exist, the command errors with a hint to run `keysmith generate` first.

## Flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `--email` | string | `""` | Email to set as `user.email` (if empty, keep existing) |
| `--global` | bool | `false` | Write to the global user config instead of the local repo config |
| `--keyid` | string | `""` | GPG key id to set as `user.signingkey` (if empty, read from existing config or pick interactively) |
| `--name` | string | `""` | Real name to set as `user.name` (if empty, keep existing) |
| `-h`, `--help` | bool | `false` | Print help for `git-config` |
| `--config` | string | `~/.config/gpg-keysmith/config.yaml` | Path to the config file (global flag) |

## Examples

### Fully interactive (pick key from `detect`)

```bash
keysmith git-config
```

If `user.signingkey` is unset, the command scans `gpg --list-secret-keys` and prompts you to pick a key. If `user.name` / `user.email` are unset, it errors with a hint.

### Set name and email explicitly

```bash
keysmith git-config --name "Jane Doe" --email jane@example.com
```

### Set a specific signing key non-interactively

```bash
keysmith git-config --name "Jane Doe" --email jane@example.com --keyid F49BE957CD553B1C
```

### Configure global git config (across all repos)

```bash
keysmith git-config --global --name "Jane Doe" --email jane@example.com --keyid F49BE957CD553B1C
```

### Preserve existing name/email, only set the signing key

```bash
keysmith git-config --keyid F49BE957CD553B1C
```

If `user.name` and `user.email` are already set in git config, they are preserved; only `user.signingkey`, `commit.gpgsign`, `gpg.format`, and `tag.gpgsign` are written.

### Verify after running

```bash
git config --local --list | grep -E 'user\.|gpg\.|commit\.gpgsign|tag\.gpgsign'
git commit -S --allow-empty -m "test: signed commit" && git verify-commit HEAD
```

## Notes

- **Shells out to `git config`.** `internal/git` uses `exec.Command("git", "config", ...)`, not [go-git](https://github.com/go-git/go-git). The behaviour matches what you would get from running `git config` yourself.
- **No passphrase needed.** `git-config` only sets config keys; it does not sign anything. The passphrase is used by `git` itself when you next run `git commit -S`.
- **`gpg.format=openpgp` is the only value.** This tool does not support `gpg.format=ssh` or `gpg.format=x509`.
- **Runtime dependency.** Requires the `git` binary on `PATH`. If `--keyid` is empty and `user.signingkey` is unset, it also requires `gpg` to scan for keys.

## See also

- [`detect`](./detect.md) — list keys to pick a signing key
- [`generate`](./generate.md) — create a key if none exist
- [`status`](./status.md) — verify `git config` is set
- [`wizard`](./wizard.md) — run `git-config` as the fourth step of the full flow