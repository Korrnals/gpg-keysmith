# Security

This document describes the threat model, the controls `gpg-keysmith` applies, and the explicit non-goals. It is the reference for anyone reviewing the security posture of the tool.

## Protected assets

| Asset | Why it matters | Where it lives |
|---|---|---|
| Passphrase | Unlocks the private key; leaks it = leaks the key | Held in memory only, piped to `gpg` via stdin |
| Private key | Can sign commits/attacks as the user | GPG keyring on disk (`~/.gnupg`), but `gpg-keysmith` exports it into memory only — never to a file, never to a log |
| GitHub PAT | Can write to repos, set secrets, upload keys | Env var named by `config.github.token_env` (default `GITHUB_TOKEN`), fallback `GH_TOKEN` |

## Controls

### Passphrase — stdin only, never a CLI arg

The passphrase is collected via a masked `survey.Password` field and piped to `gpg` via `--passphrase-fd 0` (stdin) with `--pinentry-mode loopback`.

| Leak surface | Avoided how |
|---|---|
| `ps` / `/proc/cmdline` | Passphrase is never a CLI arg — `exec.Command` argv contains only `gpg`, the flags, and the validated key ID |
| Batch file | The `%no-protection` directive is deliberately absent; the passphrase is never written to the batch file used by `gpg --gen-key` |
| Logs | Passphrase is never printed, never logged, never returned from a function in a value that gets logged |
| Shell history | Passphrase is collected via `survey.Password` (masked input), not via a flag the user types at the shell |

### Private key — in memory only

`gpg --armor --export-secret-keys` output is captured in a Go `[]byte` in process memory. It is:

- Never written to disk (no temp file, no cache).
- Never logged.
- Never printed to stdout.
- Held in memory between the `export` step and the `github` step (for the `github` command's secrets upload), then discarded at process exit.

The `WizardState` struct carries `Passphrase`, `PrivateKey`, and `PubKeyArmor` fields with the `json:"-"` tag, so they are held in memory between wizard steps but never serialised to the `state.json` file. The invariant is verified by `TestSaveStateOmitsSecrets`.

### GitHub PAT — env var only, no `--token` flag

The PAT is resolved from env vars only:

1. `config.github.token_env` (default `GITHUB_TOKEN`)
2. `GH_TOKEN` (fallback)

The `--token` flag was **removed** in security hardening (S1) because a flag value leaks via `ps` and `/proc/cmdline` on any multi-user system. The config stores only the **env var name** that holds the token, never the token value. The config file is written mode `0600`.

### Identifier validation — anti-injection

Every user-supplied identifier that reaches a subprocess or a URL path is validated before it gets there.

| Identifier | Validator | Rejects | Used by |
|---|---|---|---|
| Key ID | `ValidateKeyID` | Non-hex chars, length > 40 | `export`, `github`, `publish`, `wizard` |
| Fingerprint | hex check | Non-hex chars | `publish` (keyserver URL), `status` (keyserver check) |
| owner/repo | `ValidateOwnerRepo` | Anything outside `^[A-Za-z0-9._-]+$` | `github`, `status`, `wizard` |

`ValidateOwnerRepo` is called at every public entry point that takes owner and repo (`SetRepoSecret`, `SetGPGSecrets`, `CommitPublicKeyFile`, `ListRepoSecrets`). As defense-in-depth, callers that interpolate owner/repo into URL paths also apply `url.PathEscape`.

Because `exec.Command` does not invoke a shell, there is no shell-injection vector even if a validator missed something — the validated string only ever becomes a single argv element.

### Config file — 0600, token_env name only

| Property | Value |
|---|---|
| File mode | `0600` (written by `config.Save` / `config.Init`) |
| Parent dir mode | `0700` |
| Token storage | Only the env var **name** (`token_env: GITHUB_TOKEN`), never the value |
| Empty `token_env` | `Save` refuses to write — `ErrEmptyTokenEnv` — to prevent an accidental "store the token value directly" workaround |

### State file — no secrets

The wizard state file (`~/.config/gpg-keysmith/state.json`) records only step names, key id, email, and repo. It **never** contains the passphrase or the private key — the `Passphrase`, `PrivateKey`, and `PubKeyArmor` fields on `WizardState` carry the `json:"-"` tag, verified by `TestSaveStateOmitsSecrets`.

### Secret-name validation (repo secrets)

`SetRepoSecret` validates the secret name against GitHub's allowed character set (`^[A-Za-z_][A-Za-z0-9_]*$`) before shelling out to `gh secret set`. This prevents a malformed name from being interpolated into a `gh` invocation.

## Threat model

| Threat | Vector | Control |
|---|---|---|
| Passphrase leak via `ps` | Someone on the same host runs `ps` while `keysmith generate` is running | Passphrase piped via stdin, never a CLI arg |
| Passphrase leak via batch file | The `gpg --gen-key` batch file is left on disk | Passphrase never written to the batch file |
| Private key written to disk | `gpg --armor --export-secret-keys` output is redirected to a file | Output captured in a Go `[]byte`, never to a file |
| Private key in state file | The wizard writes its state to `state.json` between steps | `json:"-"` on `WizardState.PrivateKey`; verified by `TestSaveStateOmitsSecrets` |
| PAT leak via `ps` | `--token ghp_...` visible in `ps` | `--token` flag removed; PAT read from env var only |
| PAT leak via config file | Someone reads `~/.config/gpg-keysmith/config.yaml` | Config stores env var name only; file is `0600` |
| Key ID injection into `gpg` argv | `--keyid "ABCD; rm -rf ~"` passed as a single argv element | `ValidateKeyID` rejects non-hex; `exec.Command` does not invoke a shell |
| Owner/repo injection into GitHub REST URL | `--repo "owner/bar/../other"` interpolates into `/repos/%s/%s/...` | `ValidateOwnerRepo` rejects anything outside `^[A-Za-z0-9._-]+$`; `url.PathEscape` as defense-in-depth |
| Fingerprint injection into keyserver URL | Non-hex fingerprint interpolates into `https://keys.openpgp.org/vks/vby/<fp>` | Fingerprint hex-validated before URL construction |

## Non-goals (what keysmith does NOT do)

- **No HSM / hardware key support.** The tool drives the software `gpg` keyring. Smartcard / YubiKey OpenPGP support is out of scope.
- **No custom keyserver.** We publish to existing keyservers (`keys.openpgp.org`, `keyserver.ubuntu.com`) only.
- **No SSH keys.** Only OpenPGP signing keys — `gpg.format=openpgp` is the only `gpg.format` value `git-config` sets.
- **No age / X.509 / other signing schemes.** OpenPGP only.
- **No key rotation workflow.** `generate` creates a new key; it does not supersede or revoke an existing one. Use `gpg` directly for revocation.
- **No multi-tenant key isolation.** The tool is single-user; the GPG keyring it drives is the user's `~/.gnupg`.

## Reporting security issues

If you believe you have found a security issue in `gpg-keysmith`, please report it responsibly rather than opening a public issue:

1. Do **not** open a public GitHub issue.
2. Email the maintainer at `korrnals@gmail.com` with a description of the issue and reproduction steps.
3. If the issue involves leaked secret material, rotate the affected credential immediately (passphrase, PAT, or key) before reporting — the report itself should never contain live secrets.

Reports are acknowledged within 7 days. A fix and disclosure are coordinated with the reporter.