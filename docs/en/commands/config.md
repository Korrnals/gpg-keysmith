# `config`

Manage the `gpg-keysmith` config file at `~/.config/gpg-keysmith/config.yaml` (or the path passed via `--config`).

## Synopsis

```
keysmith config [command]
```

The config holds persistent defaults for key generation, keyserver choice, and the GitHub PAT env var reference. Subcommands that read config (`generate`, `publish`, `github`, `status`, `wizard`) use its values as defaults; explicit flags always override config values.

### Security

The config **never** stores the GitHub PAT value — only the env var name that holds it. The file is mode `0600`; the parent directory is mode `0700`.

## Subcommands

| Subcommand | What it does |
|---|---|
| [`config init`](#config-init) | Write a commented config template to the config path |
| [`config show`](#config-show) | Print the current config (loaded from the path or defaults) |
| [`config path`](#config-path) | Print the config file path |

## `config init`

Write a commented `config.yaml` template to the config path (`~/.config/gpg-keysmith/config.yaml` by default, or the path passed via `--config`). The template explains each field and is safe to edit by hand.

Refuses to overwrite an existing file unless `--force` is given.

```
keysmith config init [flags]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `--force` | bool | `false` | Overwrite an existing config file |
| `-h`, `--help` | bool | `false` | Print help for `init` |
| `--config` | string | `~/.config/gpg-keysmith/config.yaml` | Path to the config file (global flag) |

### Examples

#### Write a template (first run)

```bash
keysmith config init
```

#### Overwrite an existing config

```bash
keysmith config init --force
```

#### Write to a custom path

```bash
keysmith config init --config ~/my-keysmith-config.yaml
```

## `config show`

Print the current config. If a `config.yaml` exists at the config path (or the path passed via `--config`), it is loaded and printed. If no file exists, the built-in defaults are printed so you can see what you would get by running `keysmith config init`.

```
keysmith config show [flags]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `-h`, `--help` | bool | `false` | Print help for `show` |
| `--config` | string | `~/.config/gpg-keysmith/config.yaml` | Path to the config file (global flag) |

### Examples

#### Show the loaded config (or defaults)

```bash
keysmith config show
```

#### Show a specific config file

```bash
keysmith config show --config ~/my-keysmith-config.yaml
```

## `config path`

Print the config file path that `keysmith` reads (`~/.config/gpg-keysmith/config.yaml` by default, or the path passed via `--config`).

```
keysmith config path [flags]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `-h`, `--help` | bool | `false` | Print help for `path` |
| `--config` | string | `~/.config/gpg-keysmith/config.yaml` | Path to the config file (global flag) |

### Examples

#### Print the default config path

```bash
keysmith config path
```

Output:

```
/home/user/.config/gpg-keysmith/config.yaml
```

#### Print the path that `--config` resolves to

```bash
keysmith config path --config ~/my-keysmith-config.yaml
```

## Config schema

The config file is YAML. The schema (with defaults written by `config init`):

```yaml
# Key generation defaults (used by 'generate' and 'wizard').
key:
  type: RSA          # key algorithm (only RSA is supported)
  length: 4096       # RSA key length in bits
  expire: "0"        # expiry spec: 0 = never, 2y = 2 years

# GitHub integration defaults (used by 'github', 'status', 'wizard').
github:
  token_env: GITHUB_TOKEN  # env var name holding your GitHub PAT (never the value)
  repo: ""                 # default target repo as owner/name (empty = prompt)

# Keyserver defaults (used by 'publish', 'wizard').
keyserver:
  preferred: keys.openpgp.org      # primary keyserver
  fallback: keyserver.ubuntu.com   # fallback keyserver
```

### Field reference

| Field | Used by | Default | Notes |
|---|---|---|---|
| `key.type` | `generate`, `wizard` | `RSA` | Only `RSA` is supported |
| `key.length` | `generate`, `wizard` | `4096` | Overridden by `--key-length` |
| `key.expire` | `generate`, `wizard` | `"0"` | Overridden by `--expiry` |
| `github.token_env` | `github`, `status`, `wizard` | `GITHUB_TOKEN` | Env var **name**; never the token value |
| `github.repo` | `github`, `status`, `wizard` | `""` | Empty = prompt; overridden by `--repo` |
| `keyserver.preferred` | `publish`, `wizard` | `keys.openpgp.org` | Overridden by `--keyserver` (non-`all` values) |
| `keyserver.fallback` | `publish`, `wizard` | `keyserver.ubuntu.com` | Used when `--keyserver=all` |

## Notes

- **File mode.** `config.Save` and `config.Init` write mode `0600`; the parent directory is created mode `0700`.
- **`token_env` is required.** `Save` refuses to write a config with an empty `github.token_env` (`ErrEmptyTokenEnv`) — this prevents an accidental "store the token value directly" workaround.
- **Missing config is not an error.** `config.Load` returns `Default()` and a nil error when the file does not exist — a missing config just means "use the built-in defaults".
- **XDG-aware.** The default path respects `$XDG_CONFIG_HOME`; if it is unset, `~/.config/gpg-keysmith/config.yaml` is used.

## See also

- [`generate`](./generate.md) — reads `key.length` and `key.expire`
- [`github`](./github.md) — reads `github.token_env` and `github.repo`
- [`status`](./status.md) — reads `github.token_env`
- [`publish`](./publish.md) — reads `keyserver.preferred` and `keyserver.fallback`
- [`wizard`](./wizard.md) — reads all of the above
- [Installation](../installation.md) — config file location and shell completion