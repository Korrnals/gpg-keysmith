// Package config loads and writes the user-level gpg-keysmith config
// at ~/.config/gpg-keysmith/config.yaml.
//
// The config holds persistent defaults for key generation (type, length,
// expiry), keyserver choice, and a reference to the GitHub PAT (the
// env var name — NEVER the token value itself). Other gpg-keysmith
// subcommands load the config and use its values as defaults; explicit
// flags always override config values.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config is the in-memory representation of config.yaml.
type Config struct {
	Key struct {
		Type   string `yaml:"type"`
		Length int    `yaml:"length"`
		Expire string `yaml:"expire"`
	} `yaml:"key"`
	GitHub struct {
		// TokenEnv is the name of the environment variable that
		// holds the GitHub PAT. The token value itself is NEVER
		// stored in config.yaml — only the env var name is.
		TokenEnv string `yaml:"token_env"`
		Repo     string `yaml:"repo"`
	} `yaml:"github"`
	Keyserver struct {
		Preferred string `yaml:"preferred"`
		Fallback  string `yaml:"fallback"`
	} `yaml:"keyserver"`
}

// Default returns the built-in default Config used when no config.yaml
// exists yet. These match the defaults the CLI flags already use, so
// the behaviour of a fresh install is unchanged.
func Default() Config {
	var c Config
	c.Key.Type = "RSA"
	c.Key.Length = 4096
	c.Key.Expire = "0"
	c.GitHub.TokenEnv = "GITHUB_TOKEN"
	c.Keyserver.Preferred = "keys.openpgp.org"
	c.Keyserver.Fallback = "keyserver.ubuntu.com"
	return c
}

// DefaultDir returns the default config directory
// ($XDG_CONFIG_HOME/gpg-keysmith or ~/.config/gpg-keysmith).
func DefaultDir() (string, error) {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "gpg-keysmith"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("config: resolve home dir: %w", err)
	}
	return filepath.Join(home, ".config", "gpg-keysmith"), nil
}

// DefaultPath returns the default config file path
// ($XDG_CONFIG_HOME/gpg-keysmith/config.yaml or
// ~/.config/gpg-keysmith/config.yaml).
func DefaultPath() (string, error) {
	dir, err := DefaultDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.yaml"), nil
}

// ErrEmptyTokenEnv is returned by Save when the config's GitHub
// token_env is empty. The token_env field references the env var that
// holds the PAT; an empty value means the user has not told keysmith
// where to look, and we refuse to write a config that silently drops
// the token reference rather than allowing an accidental "store the
// token value" workaround.
var ErrEmptyTokenEnv = errors.New(
	"config: github.token_env must be non-empty (set the env var NAME, " +
		"never the token value)",
)

// Load reads a YAML config from path. If the file does not exist, it
// returns Default() and a nil error — a missing config is not an
// error, it just means "use the built-in defaults". If the file
// exists but cannot be parsed, an error is returned so the user is
// not silently running on stale or malformed defaults.
//
// An empty path falls back to DefaultPath().
func Load(path string) (Config, error) {
	if path == "" {
		p, err := DefaultPath()
		if err != nil {
			return Config{}, err
		}
		path = p
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Default(), nil
		}
		return Config{}, fmt.Errorf("config: read %s: %w", path, err)
	}

	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return Config{}, fmt.Errorf("config: parse %s: %w", path, err)
	}
	return c, nil
}

// Save writes the config to path as YAML. The parent directory is
// created with mode 0700 and the file is written with mode 0600 —
// the config contains the repo name (mild PII) and references the
// env var holding the GitHub PAT.
//
// Save validates that GitHub.TokenEnv is non-empty before writing:
// the token_env field references the env var that holds the PAT, and
// an empty value would either silently drop the reference or tempt
// the user to store the token value directly (which this package
// never does).
//
// An empty path falls back to DefaultPath().
func Save(c Config, path string) error {
	if path == "" {
		p, err := DefaultPath()
		if err != nil {
			return err
		}
		path = p
	}
	if c.GitHub.TokenEnv == "" {
		return ErrEmptyTokenEnv
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("config: create dir %s: %w", dir, err)
	}

	data, err := yaml.Marshal(&c)
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("config: write %s: %w", path, err)
	}
	return nil
}

// Init writes a default config as a template to path. The template is
// a commented YAML file explaining each field, so a user editing it
// by hand knows what each value does. If the file already exists,
// Init returns an error unless force is true (in which case the
// file is overwritten).
//
// An empty path falls back to DefaultPath().
func Init(path string, force bool) error {
	if path == "" {
		p, err := DefaultPath()
		if err != nil {
			return err
		}
		path = p
	}

	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("config: %s already exists (use --force to overwrite)", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("config: stat %s: %w", path, err)
		}
	}

	tmpl := template()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("config: create dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(tmpl), 0o600); err != nil {
		return fmt.Errorf("config: write template %s: %w", path, err)
	}
	return nil
}

// template returns the commented default config. The comments explain
// each field so a user editing config.yaml by hand knows the contract.
// The values match Default() so loading the template (with comments
// stripped by the YAML parser) gives the same in-memory Config.
func template() string {
	return `# gpg-keysmith config — persistent defaults for key generation,
# keyserver choice, and the GitHub PAT env var reference.
#
# The token_env field names the environment variable that holds your
# GitHub PAT. NEVER put the token value in this file — only the env var
# name. The file is mode 0600; do not loosen it.
#
# Generated by 'keysmith config init'. Edit by hand or re-run with --force.

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
`
}
