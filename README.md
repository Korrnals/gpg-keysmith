# gpg-keysmith

A Go CLI tool for **automated GPG key generation and GitHub integration**. It walks a developer from "no GPG key" to "signed commits on GitHub" in a single guided flow: generate a key, export it, publish the public key to GitHub and a keyserver, configure `git config user.signingkey`, and upload the private key as a repository secret for CI signing.

## Status

Pre-alpha. Milestones 1–2 (scaffold + `detect` command) are implemented; the remaining milestones are stubs.

## Features

- `detect` — list existing GPG secret keys for the current user (implemented).
- `generate` — generate a new GPG key via `gpg --full-generate-key` (stub).
- `export` — export private/public key material (stub).
- `github` — upload public key to GitHub, set repo secret, commit `gpg-public-key.asc` (stub).
- `git-config` — set `user.signingkey`, `commit.gpgsign`, `gpg.format` (stub).
- `publish` — publish the public key to a keyserver (stub).
- `status` — show current setup state (stub).
- `wizard` — interactive end-to-end setup flow (default command).

## Install

From source (requires Go 1.22+):

```bash
git clone https://github.com/Korrnals/gpg-keysmith.git
cd gpg-keysmith
make install   # installs to $GOBIN (or $GOPATH/bin)
```

Or build a local binary:

```bash
make build     # produces ./bin/keysmith
```

## Usage

```bash
# List existing GPG keys (works today)
keysmith detect

# Run the full interactive setup wizard (stub)
keysmith wizard

# Show available commands
keysmith --help
```

### Example: `detect` output

```
Found 1 GPG key(s):

  KEY ID              TYPE  CREATED             EXPIRES             USER ID
  F49BE957CD553B1C    sec   2026-07-17 12:25     2028-07-17 12:25    Leonid Golikhin (ollama-cloud-provider signing) <korrnals@gmail.com>
```

If no keys are found:

```
No GPG keys found. Run 'gpg-keysmith generate' to create one.
```

## Development

See [DEVELOPMENT.md](./DEVELOPMENT.md) for the full 10-milestone roadmap and contributor guide.

## License

MIT — see [LICENSE](./LICENSE). Copyright (c) 2026 Leonid Golikhin.