// Package git wraps the local git CLI for setting signing-related
// configuration: user.name, user.email, user.signingkey,
// commit.gpgsign, gpg.format, tag.gpgsign.
//
// The git package shells out to the 'git' binary via exec.Command. It
// does NOT import internal/gpg — the hex-key-id validation is
// duplicated locally to keep this package independent and avoid tight
// coupling. The only package allowed to shell out to the gpg binary
// is internal/gpg; this package only shells out to git.
package git

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// ConfigOptions describes the inputs for 'keysmith git-config'.
type ConfigOptions struct {
	// KeyID is the long-form GPG key id or fingerprint to set as
	// user.signingkey. Required — validated via validateHexKeyID
	// before any git config command is run, to reject malformed input
	// early (defence-in-depth: exec.Command does not invoke a shell,
	// but validating the shape gives a clean error and prevents
	// confusing git diagnostics).
	KeyID string
	// Name is the real name to set as user.name. Optional — if
	// empty, ApplyGitConfig reads the existing user.name from git
	// config and keeps it. If no user.name is set anywhere and Name
	// is empty, ApplyGitConfig returns an error telling the user to
	// pass --name or set user.name first.
	Name string
	// Email is the email to set as user.email. Optional — same
	// resolution rule as Name: empty means "read existing, error if
	// missing".
	Email string
	// Global controls the scope: false (default) writes to the
	// local repo config (--local, the default for 'git config' in a
	// repo); true writes to the global user config (--global).
	Global bool
}

// configEntry is a single git config key/value pair to set. It is the
// pure output of configKeysToSet, extracted so tests can assert the
// exact keys and values without shelling out to git.
type configEntry struct {
	key   string
	value string
}

// validateHexKeyID rejects key IDs that could be used to inject extra
// arguments into the git command line. GPG key IDs are hex strings or
// fingerprints — at most 40 hex chars, optionally starting with "0x".
// Anything else (spaces, quotes, dashes that aren't part of a
// fingerprint, shell metacharacters) is rejected.
//
// This is a local duplicate of gpg.ValidateKeyID (M4). We duplicate
// rather than import internal/gpg to keep internal/git independent —
// the two packages have no runtime dependency on each other, and the
// validation rule is small enough (~20 lines) that the duplication
// cost is lower than the coupling cost. If the rule ever diverges,
// the tests for both copies will catch it.
func validateHexKeyID(keyID string) error {
	if keyID == "" {
		return fmt.Errorf("git config: key id is required")
	}
	s := keyID
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s = s[2:]
	}
	if s == "" {
		return fmt.Errorf("git config: key id is empty after 0x prefix")
	}
	if len(s) > 40 {
		return fmt.Errorf("git config: key id too long (max 40 hex chars, got %d)", len(s))
	}
	for _, r := range s {
		isHex := (r >= '0' && r <= '9') ||
			(r >= 'a' && r <= 'f') ||
			(r >= 'A' && r <= 'F')
		if !isHex {
			return fmt.Errorf("git config: key id must be hex (0-9, A-F), got %q", keyID)
		}
	}
	return nil
}

// configKeysToSet returns the six git config key/value pairs that
// ApplyGitConfig writes for the given options. It is a pure function
// (no I/O) so it can be unit-tested without invoking git.
//
// The six keys, per the M5 spec:
//   - user.name        = opts.Name
//   - user.email       = opts.Email
//   - user.signingkey  = opts.KeyID
//   - commit.gpgsign   = "true"
//   - gpg.format       = "openpgp"
//   - tag.gpgsign      = "true"
//
// Name and Email are included unconditionally; ApplyGitConfig is
// responsible for resolving them to non-empty values before calling
// this function (it reads existing config or errors out). This keeps
// the pure function simple and makes the resolution logic testable
// separately.
func configKeysToSet(opts ConfigOptions) []configEntry {
	return []configEntry{
		{key: "user.name", value: opts.Name},
		{key: "user.email", value: opts.Email},
		{key: "user.signingkey", value: opts.KeyID},
		{key: "commit.gpgsign", value: "true"},
		{key: "gpg.format", value: "openpgp"},
		{key: "tag.gpgsign", value: "true"},
	}
}

// gitConfigScope returns the flag that selects the config scope for
// 'git config'. An empty slice means "default" (local repo config
// when run inside a repo, which is what we want for Global=false).
func gitConfigScope(global bool) []string {
	if global {
		return []string{"--global"}
	}
	return nil
}

// runGitConfigGet reads a single git config value via
// 'git config [--global] --get <key>'. Returns the trimmed value and
// a nil error if the key is set; returns ("", nil) if the key is not
// set (exit code 1 from git config --get is the "not found" signal,
// not an error); returns an error only if git fails to run.
func runGitConfigGet(global bool, key string) (string, error) {
	args := append(append([]string{}, "config"), append(gitConfigScope(global), "--get", key)...)
	cmd := exec.Command("git", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// git config --get exits 1 when the key is not set. This is
		// the "not found" case, not a real failure — return empty.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return "", nil
		}
		return "", fmt.Errorf("git config --get %s failed: %w: %s",
			key, err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// runGitConfigSet writes a single git config value via
// 'git config [--global] <key> <value>'. Returns an error if git
// fails. This is the only mutating call in the package.
func runGitConfigSet(global bool, key, value string) error {
	args := append(append([]string{}, "config"), append(gitConfigScope(global), key, value)...)
	cmd := exec.Command("git", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git config %s %s failed: %w: %s",
			key, value, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// ApplyGitConfig sets the six git config keys that enable commit and
// tag signing with the given GPG key. It validates the KeyID first,
// resolves empty Name/Email from existing config (or errors if they
// are missing and needed), then writes all six keys.
//
// The scope is controlled by opts.Global: false (default) writes to
// the local repo config, true writes to --global.
//
// Resolution rule for Name and Email:
//   - If opts.Name is non-empty, it is used as-is.
//   - If opts.Name is empty, the existing user.name is read from the
//     same scope (local or global). If it is also empty, ApplyGitConfig
//     returns an error telling the user to pass --name or set
//     user.name first.
//   - Same rule for Email.
//
// This means a user who already has user.name/user.email set (locally
// or globally) can run 'keysmith git-config --keyid <id>' without
// re-specifying their identity — the existing identity is preserved
// and re-asserted (idempotent).
func ApplyGitConfig(opts ConfigOptions) error {
	if err := validateHexKeyID(opts.KeyID); err != nil {
		return err
	}

	resolved := opts

	// Resolve Name: if empty, read existing; if still empty, error.
	if resolved.Name == "" {
		existing, err := runGitConfigGet(opts.Global, "user.name")
		if err != nil {
			return fmt.Errorf("git config: read existing user.name: %w", err)
		}
		if existing == "" {
			return fmt.Errorf("git config: user.name is not set; pass --name or run 'git config user.name \"Your Name\"' first")
		}
		resolved.Name = existing
	}

	// Resolve Email: same rule as Name.
	if resolved.Email == "" {
		existing, err := runGitConfigGet(opts.Global, "user.email")
		if err != nil {
			return fmt.Errorf("git config: read existing user.email: %w", err)
		}
		if existing == "" {
			return fmt.Errorf("git config: user.email is not set; pass --email or run 'git config user.email \"you@example.com\"' first")
		}
		resolved.Email = existing
	}

	// Build the six key/value pairs from the resolved options and
	// write each one. We write in the order returned by
	// configKeysToSet (user.name, user.email, user.signingkey,
	// commit.gpgsign, gpg.format, tag.gpgsign) so a partial failure
	// leaves the most important keys (identity) set and the
	// signing-specific keys last.
	for _, entry := range configKeysToSet(resolved) {
		if err := runGitConfigSet(opts.Global, entry.key, entry.value); err != nil {
			return err
		}
	}
	return nil
}

// DetectSigningKey reads 'git config [--global] --get user.signingkey'
// and returns the current signing key id, or an empty string if none
// is set. An empty string is NOT an error — the caller decides what to
// do (e.g. prompt the user to pick a key). An error is returned only
// if git fails to run.
func DetectSigningKey(global bool) (string, error) {
	return runGitConfigGet(global, "user.signingkey")
}
