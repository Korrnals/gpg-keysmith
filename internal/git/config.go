// Package git wraps the local git CLI for setting signing-related
// configuration: user.signingkey, commit.gpgsign, gpg.format,
// tag.gpgsign.
package git

// SigningConfig holds the git config values written by 'keysmith
// git-config'.
type SigningConfig struct {
	UserName       string
	UserEmail      string
	SigningKeyID   string
	CommitGpgSign  bool
	TagGpgSign     bool
	GpgFormat      string // "openpgp" or "x509"
	Global         bool   // write to --global instead of --local
}

// Apply writes the signing config via 'git config [--global] <key>
// <value>'. It does not create or modify commits.
//
// TODO(milestone 5): implement.
func Apply(cfg SigningConfig) error {
	return errNotImplemented("apply signing config")
}

// errNotImplemented is the standard sentinel returned by stub functions.
func errNotImplemented(op string) error {
	return &notImplementedError{op: op}
}

type notImplementedError struct{ op string }

func (e *notImplementedError) Error() string {
	return "git: " + e.op + ": not implemented yet"
}