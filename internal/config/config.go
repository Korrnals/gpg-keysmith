// Package config loads and writes the user-level gpg-keysmith config
// at ~/.config/gpg-keysmith/config.yaml.
package config

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
		// stored in config.yaml.
		TokenEnv string `yaml:"token_env"`
		Repo     string `yaml:"repo"`
	} `yaml:"github"`
	Keyserver struct {
		Preferred string `yaml:"preferred"`
		Fallback  string `yaml:"fallback"`
	} `yaml:"keyserver"`
}

// Default returns the built-in default Config used when no config.yaml
// exists yet.
//
// TODO(milestone 10): implement.
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

// Load reads ~/.config/gpg-keysmith/config.yaml. If the file does not
// exist, returns Default() and a nil error.
//
// TODO(milestone 10): implement.
func Load() (Config, error) {
	return Config{}, errNotImplemented("load")
}

// Save writes the config to ~/.config/gpg-keysmith/config.yaml with
// mode 0600.
//
// TODO(milestone 10): implement.
func Save(c Config) error {
	return errNotImplemented("save")
}

// errNotImplemented is the standard sentinel returned by stub functions.
func errNotImplemented(op string) error {
	return &notImplementedError{op: op}
}

type notImplementedError struct{ op string }

func (e *notImplementedError) Error() string {
	return "config: " + e.op + ": not implemented yet"
}
