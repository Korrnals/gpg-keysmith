# `publish`

Publish the GPG public key to a public keyserver via HTTPS submit endpoints.

## Synopsis

```
keysmith publish [flags]
```

`publish` uploads the ASCII-armored public key to one or both of:

- `keys.openpgp.org` — `https://keys.openpgp.org/vks/v1/upload` (preferred)
- `keyserver.ubuntu.com` — `https://keyserver.ubuntu.com/pks/submit` (fallback)

The default keyserver is `all` (publishes to both). Use `--keyserver=openpgp` for just the first, or `--keyserver=ubuntu` for just the second.

If `--keyid` is empty, the key is picked interactively from `gpg --list-secret-keys`. If `--pubkey-file` is set, the armored public key is read from that file instead of calling `gpg --export`.

On success, `publish` prints the verification URL for each keyserver.

## Flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `--keyid` | string | `""` | GPG key id to export (if empty, pick interactively from `detect`) |
| `--keyserver` | string | `"all"` | Keyserver target: `all`, `openpgp`, or `ubuntu` |
| `--pubkey-file` | string | `""` | Read armored public key from this file instead of calling `gpg --export` |
| `-h`, `--help` | bool | `false` | Print help for `publish` |
| `--config` | string | `~/.config/gpg-keysmith/config.yaml` | Path to the config file (global flag) |

## Examples

### Publish to both keyservers (default)

```bash
keysmith publish
```

Picks the key interactively from `gpg --list-secret-keys` and publishes to `keys.openpgp.org` + `keyserver.ubuntu.com`.

### Publish a specific key

```bash
keysmith publish --keyid F49BE957CD553B1C
```

### Publish only to keys.openpgp.org

```bash
keysmith publish --keyid F49BE957CD553B1C --keyserver openpgp
```

### Publish only to keyserver.ubuntu.com

```bash
keysmith publish --keyid F49BE957CD553B1C --keyserver ubuntu
```

### Publish a pre-exported pubkey file

```bash
keysmith export --keyid F49BE957CD553B1C --pubkey ./gpg-public-key.asc
keysmith publish --pubkey-file ./gpg-public-key.asc
```

### Sample success output

```
Published to keys.openpgp.org
  Verification URL: https://keys.openpgp.org/vks/vby/F49BE957CD553B1C1234567890ABCDEF12345678
Published to keyserver.ubuntu.com
```

## Notes

- **HTTPS POST, not HKP.** `publish` uses HTTPS submit endpoints, not the legacy `hkp://` protocol.
- **Fingerprint validation.** The fingerprint is hex-validated before being interpolated into the verification URL `https://keys.openpgp.org/vks/vby/<fingerprint>`. See [Security](../security.md).
- **No passphrase needed.** Publishing the public key does not require the private key or passphrase — only the public key armor. If `--pubkey-file` is not given, `publish` calls `gpg --armor --export` (which does not require a passphrase).
- **Keyserver choice from config.** `--keyserver` overrides `config.keyserver.preferred`; the `all` option publishes to both `preferred` and `fallback`.
- **Runtime dependency.** Requires the `gpg` binary if `--pubkey-file` is not given.

## See also

- [`export`](./export.md) — produce the `--pubkey-file` ahead of time
- [`status`](./status.md) — check keyserver publication by fingerprint
- [`wizard`](./wizard.md) — run `publish` as the sixth step of the full flow
- [`config`](./config.md) — set the default keyserver