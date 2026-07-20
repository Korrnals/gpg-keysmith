# Installation

This document covers prerequisites, install methods, config file location, and shell completion setup for `gpg-keysmith`.

## Prerequisites

`gpg-keysmith` shells out to system tools. All three must be installed and on your `PATH`:

| Tool | Version | Required by | Install check |
|---|---|---|---|
| `gpg` (GnuPG) | 2.x | every command (key generation, export, listing) | `gpg --version` |
| `git` | any recent | `git-config`, `wizard`, `status` | `git --version` |
| `gh` (GitHub CLI) | any recent | `github`, `wizard`, `status` (repo secrets only) | `gh --version` |

The `gh` CLI is only needed for the repository-secrets step of `github` (and therefore `wizard` and the `status` secrets check). If you never use `github`, `gh` is not required.

### Linux

```bash
# Debian / Ubuntu
sudo apt install gnupg git
# gh CLI (Debian/Ubuntu)
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt update && sudo apt install gh

# Fedora
sudo dnf install gnupg git gh
```

### macOS

```bash
brew install gnupg git gh
```

### Windows

Install [Git for Windows](https://git-scm.com/download/win) (includes `git` and `gpg`), then install `gh` from [cli.github.com](https://cli.github.com/) or via `winget`:

```powershell
winget install --id GitHub.cli
```

## Installing keysmith

### From source (recommended for development)

```bash
git clone https://github.com/Korrnals/gpg-keysmith.git
cd gpg-keysmith
make install   # installs to $GOBIN (or $GOPATH/bin)
```

To build a local binary without installing:

```bash
make build     # produces ./bin/keysmith (UPX-compressed if upx is available)
```

### From a release binary

1. Download the archive for your platform from [GitHub Releases](https://github.com/Korrnals/gpg-keysmith/releases).
2. Verify the SHA-256 checksum against the `checksums.txt` file published alongside the release:

   ```bash
   sha256sum keysmith-*.tar.gz
   ```

3. Extract and put the binary on your `PATH`:

   ```bash
   tar xzf keysmith-linux-amd64.tar.gz
   chmod +x keysmith
   sudo mv keysmith /usr/local/bin/
   ```

### Via `go install`

```bash
go install github.com/Korrnals/gpg-keysmith/cmd/keysmith@latest
```

This installs to `$GOBIN` (or `$GOPATH/bin`).

## Config file location

`gpg-keysmith` reads its config from:

- The path passed via the global `--config <path>` flag, OR
- `$XDG_CONFIG_HOME/gpg-keysmith/config.yaml`, OR
- `~/.config/gpg-keysmith/config.yaml` (default when `XDG_CONFIG_HOME` is unset).

The config holds persistent defaults for key generation, keyserver choice, and the GitHub PAT env var reference. It never stores the PAT value itself — only the env var name. The file is mode `0600`.

To write a commented template:

```bash
keysmith config init
```

To print the resolved path:

```bash
keysmith config path
```

See [`config` command](./commands/config.md) for the full config schema.

## Shell completion

`gpg-keysmith` can generate shell completion scripts via cobra's built-in `completion` command:

```bash
keysmith completion bash       # bash
keysmith completion zsh         # zsh
keysmith completion fish        # fish
keysmith completion powershell  # PowerShell
```

### bash

```bash
keysmith completion bash > ~/.local/share/bash-completion/completions/keysmith
# or, for older setups:
keysmith completion bash >> ~/.bashrc
```

### zsh

If `~/.zsh/completions` is on your `$fpath`:

```bash
keysmith completion zsh > ~/.zsh/completions/_keysmith
```

Otherwise append to `~/.zshrc` and reload.

### fish

```bash
keysmith completion fish > ~/.config/fish/completions/keysmith.fish
```

### PowerShell

```powershell
keysmith completion powershell | Out-String | Invoke-Expression
```

Or save to a profile script and import it in your `$PROFILE`.

## Verifying the install

```bash
keysmith --help          # lists all subcommands
keysmith detect          # lists existing GPG keys (or "no keys found")
keysmith config path     # prints the config file path
```

If `detect` reports `No GPG keys found`, run `keysmith generate` or `keysmith wizard` to create one.