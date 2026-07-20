# `generate`

Generate a new GPG key by driving `gpg --gen-key` with a batch parameter file.

## Synopsis

```
keysmith generate [flags]
```

`generate` writes a batch parameter file and runs `gpg --gen-key --batch --pinentry-mode loopback --passphrase-fd 0`, piping the passphrase via stdin. The passphrase is collected via a masked `survey.Password` prompt — it never appears in the batch file, the process args, or logs.

Use `--name` and `--email` to skip the interactive prompts for those fields (non-interactive mode). The passphrase is **always** prompted via a masked survey field, even in non-interactive mode.

## Flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `--comment` | string | `""` | Comment for the key's user id (optional) |
| `--email` | string | `""` | Email for the key's user id |
| `--expiry` | string | `"0"` | Expiry date spec (`0` = never, `2y` = 2 years) |
| `--key-length` | int | `4096` | RSA key length in bits |
| `--name` | string | `""` | Real name for the key's user id |
| `-h`, `--help` | bool | `false` | Print help for `generate` |
| `--config` | string | `~/.config/gpg-keysmith/config.yaml` | Path to the config file (global flag) |

## Examples

### Fully interactive (prompt for everything except passphrase input)

```bash
keysmith generate
```

The survey prompts for name, email, comment, expiry, and key length; the passphrase is collected via a masked field.

### Non-interactive with explicit name and email

```bash
keysmith generate --name "Jane Doe" --email jane@example.com
```

Only the passphrase is prompted (masked); the rest is taken from flags.

### Generate a 2-year key with a comment for project identification

```bash
keysmith generate --name "Jane Doe" --email jane@example.com \
  --comment "acme-corp signing" --expiry 2y
```

### Generate a 3072-bit key (smaller, faster)

```bash
keysmith generate --name "Jane Doe" --email jane@example.com --key-length 3072
```

### Use config-file defaults

```bash
keysmith config init   # writes a template with defaults: RSA 4096, expire "0"
keysmith generate --name "Jane Doe" --email jane@example.com
```

The `key.length` and `key.expire` values from config are used unless overridden by flags.

## Notes

- **Passphrase handling.** The passphrase is piped to `gpg` via `--passphrase-fd 0` (stdin) with `--pinentry-mode loopback`. It never appears in the batch file, never appears as a CLI arg, and is never logged. See [Security](../security.md).
- **Algorithm.** Only RSA is supported (`key.type: RSA` in config; `--key-length` sets the bit count). ECC/EdDSA are out of scope for v1.0.0.
- **`%no-protection` is forbidden.** The batch file deliberately omits the `%no-protection` directive — `gpg-keysmith` always requires a passphrase.
- **Runtime dependency.** Requires the `gpg` binary (GnuPG 2.x) on `PATH`.
- **Config overrides.** `--key-length` and `--expiry` override `config.key.length` and `config.key.expire`; `--name` / `--email` / `--comment` are not in config (they are per-key identity, not defaults).

## See also

- [`detect`](./detect.md) — verify the new key was created
- [`export`](./export.md) — export the public key to a file
- [`wizard`](./wizard.md) — run `generate` as the second step of the full flow
- [`config`](./config.md) — set persistent defaults for key generation