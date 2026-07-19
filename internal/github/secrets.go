// Package github wraps the GitHub REST API for uploading GPG public
// keys, setting repository secrets, and committing the public key
// file to a repo.
package github

// SetRepoSecret stores a single repository action secret, performing
// libsodium sealed-box encryption of the value before upload. Requires
// a PAT with the 'repo' scope.
//
// TODO(milestone 6): implement. Use
// github.com/bradleyfalzon/ghinstallation-style sealed secrets or
// shell out to 'gh secret set' when a 'gh' CLI is available.
func SetRepoSecret(owner, repo, name, value, token string) error {
	return errNotImplemented("set repo secret")
}

// errNotImplemented is the standard sentinel returned by stub functions.
func errNotImplemented(op string) error {
	return &notImplementedError{op: op}
}

type notImplementedError struct{ op string }

func (e *notImplementedError) Error() string {
	return "github: " + e.op + ": not implemented yet"
}