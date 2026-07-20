# `export`

Export the public key to an ASCII-armored file and capture the private key in memory.

## Synopsis

```
keysmith export [flags]
```

`export` runs `gpg --armor --export <keyID>` and writes the public key to an ASCII-armored file (default `gpg-public-key.asc`). It also runs `gpg --armor --export-secret-keys --pinentry-mode loopback --passphrase-fd 0 <keyID>` and captures the private key in memory only — it is never written to disk, never logged, and never printed. The captured private key is held for use by the `github` command (M6) to upload it as a repository secret for CI signing.

The passphrase is collected via a masked prompt and piped to `gpg` via stdin. It is never read from a flag (which would leak via shell history / `ps`) and never passed to `gpg` as a CLI arg.

## Flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `--email` | string | `""` | Email of the key to export (alternative to `--keyid`) |
| `--keyid` | string | `""` | Long-form key id or fingerprint to export |
| `--pubkey` | string | `gpg-public-key.asc` | Output path for the ASCII-armored public key |
| `-h`, `--help` | bool | `false` | Print help for `export` |
| `--config` | string | `~/.config/gpg-keysmith/config.yaml` | Path to the config file (global flag) |

Either `--keyid` or `--email` must be given. If `--email` is given, `export` resolves it to a key id via `DetectKeyForEmail`.

## Examples

### Export by key id

```bash
keysmith export --keyid F49BE957CD553B1C
```

Writes the public key to `gpg-public-key.asc` in the current directory.

### Export by email (resolve via `detect`)

```bash
keysmith export --email korrnals@gmail.com
```

### Export to a custom path

```bash
keysmith export --keyid F49BE957CD553B1C --pubkey ./keys/my-pubkey.asc
```

### Export for use by `github`

```bash
keysmith export --keyid F49BE957CD553B1C --pubkey ./gpg-public-key.asc
keysmith github --repo owner/name --pubkey-file ./gpg-public-key.asc
```

The `github` command can read the pre-exported public key via `--pubkey-file` instead of calling `gpg --export` itself.

## Notes

- **Private key in memory only.** The private key is captured in a Go `[]byte` and held for the `github` step's secrets upload. It is never written to disk, never logged, never printed. See [Security](../security.md).
- **Key ID validation.** `ValidateKeyID` rejects non-hex characters and lengths over 40 chars before the key id reaches `gpg` argv. This prevents `--keyid "ABCD; rm -rf ~"` from being passed as a single argv element.
- **Passphrase handling.** The passphrase is piped to `gpg` via `--passphrase-fd 0` stdin with `--pinentry-mode loopback`. It never appears as a CLI arg.
- **Public key file mode.** The public key file is written mode `0644` (public keys are not secret).
- **Runtime dependency.** Requires the `gpg` binary (GnuPG 2.x) on `PATH`.

## See also

- [`detect`](./detect.md) — find the key id or email to export
- [`github`](./github.md) — upload the public key and store the private key as a repo secret
- [`publish`](./publish.md) — publish the exported public key to a keyserver
- [`wizard`](./wizard.md) — run `export` as the third step of the full flow