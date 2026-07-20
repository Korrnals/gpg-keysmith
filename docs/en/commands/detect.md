# `detect`

List existing GPG secret keys for the current user.

## Synopsis

```
keysmith detect [flags]
```

`detect` parses the output of `gpg --list-secret-keys --keyid-format=long --with-colons` and renders a table of found keys. If no keys exist, it prints a hint to run `keysmith generate`.

## Flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `-h`, `--help` | bool | `false` | Print help for `detect` |
| `--config` | string | `~/.config/gpg-keysmith/config.yaml` | Path to the config file (global flag) |

`detect` has no command-specific flags — it takes no parameters.

## Examples

### List all GPG keys

```bash
keysmith detect
```

Example output:

```
Found 1 GPG key(s):

  KEY ID              TYPE  CREATED             EXPIRES             USER ID
  F49BE957CD553B1C    sec   2026-07-17 12:25     2028-07-17 12:25    Leonid Golikhin (signing) <korrnals@gmail.com>
```

### When no keys exist

```bash
keysmith detect
```

```
No GPG keys found. Run 'gpg-keysmith generate' to create one.
```

### Check a specific config file

```bash
keysmith detect --config ~/.config/gpg-keysmith/config.yaml
```

## Notes

- `detect` shells out to `gpg --list-secret-keys --keyid-format=long --with-colons`. It does not need a passphrase and does not modify the keyring.
- The parsed key list is the input for `git-config` and `wizard`, which auto-prompt the user to pick a key if one is not given explicitly.
- The exported helper `DetectKeyForEmail(email)` (used internally by later milestones) returns the key whose user id matches a given email.

## See also

- [`generate`](./generate.md) — create a new GPG key when `detect` finds none
- [`git-config`](./git-config.md) — set the signing key from the `detect` list
- [`status`](./status.md) — combine `detect` with the other setup checks
- [`wizard`](./wizard.md) — run `detect` as the first step of the full flow