package github

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
)

// secretNameGPGPrivateKey and secretNameGPGPassphrase are the two repo
// secrets gpg-keysmith uploads for CI signing.
const (
	secretNameGPGPrivateKey = "GPG_PRIVATE_KEY"
	secretNameGPGPassphrase = "GPG_PASSPHRASE"
)

// ErrGhCLINotFound is returned when SetRepoSecret falls back to the
// 'gh' CLI and 'gh' is not on PATH. The error message directs the user
// to install it.
type ErrGhCLINotFound struct{}

func (e *ErrGhCLINotFound) Error() string {
	return "gh CLI not found — install it from https://cli.github.com"
}

// lookPath is a package var so tests can replace it with a fake to
// simulate 'gh' being missing without manipulating PATH.
var lookPath = func(file string) (string, error) {
	return exec.LookPath(file)
}

// SetRepoSecret stores a single repository Action secret by shelling
// out to the 'gh' CLI. 'gh secret set' handles the libsodium sealed-box
// encryption and the PUT to the secrets API in one call — this keeps
// gpg-keysmith CGo-free and avoids pulling a native libsodium binding.
//
// If 'gh' is not on PATH, SetRepoSecret returns *ErrGhCLINotFound.
//
// token is not used by the gh CLI path (gh uses its own auth via
// 'gh auth login' or the GH_TOKEN env var). We keep it in the
// signature for symmetry with the REST API path used by
// UploadPublicKey and for a future pure-Go migration. We validate it
// is non-empty so callers cannot accidentally omit auth.
//
// Security: the secret value is passed to gh via stdin (--body -),
// NEVER via the -b flag (which would leak via ps/proc). gh reads the
// value from stdin and does not echo it. We never log secretValue;
// error messages use the literal "<REDACTED>" placeholder.
func SetRepoSecret(token, owner, repo, secretName, secretValue string) error {
	if token == "" {
		return fmt.Errorf("github: set repo secret: token is required")
	}
	if err := ValidateOwnerRepo(owner, repo); err != nil {
		return err
	}
	if err := validateSecretName(secretName); err != nil {
		return fmt.Errorf("github: set repo secret: %w", err)
	}
	if secretValue == "" {
		return fmt.Errorf("github: set repo secret: secret value is required (got <REDACTED>)")
	}

	if _, err := lookPath("gh"); err != nil {
		return &ErrGhCLINotFound{}
	}

	// gh secret set <name> --repo <owner>/<repo> --body -
	// feeds the value via stdin, never via argv. This avoids leaking
	// the secret through the process arg list (ps/proc). The
	// owner/repo pair is validated by ValidateOwnerRepo above before
	// it reaches the CLI arg vector.
	repoArg, err := ownerRepoArg(owner, repo)
	if err != nil {
		return err
	}
	cmd := exec.Command("gh", "secret", "set", secretName, "--repo", repoArg, "--body", "-")
	cmd.Stdin = strings.NewReader(secretValue)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// gh never echoes the secret value in stderr, but we apply
		// redactInString as defence-in-depth so a future gh version
		// that did echo would not leak the secret through our error.
		return fmt.Errorf("github: set repo secret %q on %s: %w: %s",
			secretName, repoArg, err, redactInString(stderr.String(), secretValue))
	}
	return nil
}

// SetGPGSecrets is the convenience wrapper used by the github command
// and the wizard. It uploads two secrets:
//   - GPG_PRIVATE_KEY = privateKey (ASCII-armored)
//   - GPG_PASSPHRASE  = passphrase
//
// Both values are secret material and MUST NOT appear in logs, error
// messages, or stdout. The function returns the name of the first
// secret that failed (if any) so the caller can print a diagnostic
// without leaking the value.
func SetGPGSecrets(token, owner, repo, privateKey, passphrase string) error {
	if privateKey == "" {
		return fmt.Errorf("github: set GPG secrets: private key is required (got <REDACTED>)")
	}
	if passphrase == "" {
		return fmt.Errorf("github: set GPG secrets: passphrase is required (got <REDACTED>)")
	}
	if err := SetRepoSecret(token, owner, repo, secretNameGPGPrivateKey, privateKey); err != nil {
		return fmt.Errorf("github: set GPG_PRIVATE_KEY: %w", err)
	}
	if err := SetRepoSecret(token, owner, repo, secretNameGPGPassphrase, passphrase); err != nil {
		return fmt.Errorf("github: set GPG_PASSPHRASE: %w", err)
	}
	return nil
}

// validateSecretName enforces GitHub's naming rules for action
// secrets: letters, digits, underscore; must not start with a digit;
// must not start with the reserved GITHUB_ prefix.
func validateSecretName(name string) error {
	if name == "" {
		return fmt.Errorf("secret name is required")
	}
	if strings.HasPrefix(name, "GITHUB_") {
		return fmt.Errorf("secret name %q must not start with GITHUB_ (reserved)", name)
	}
	if name[0] >= '0' && name[0] <= '9' {
		return fmt.Errorf("secret name %q must not start with a digit", name)
	}
	for _, r := range name {
		ok := (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_'
		if !ok {
			return fmt.Errorf("secret name %q must be letters, digits, or underscore", name)
		}
	}
	return nil
}

// redactInString replaces any occurrence of a secret value in a
// string with the literal "<REDACTED>". Used when surfacing gh stderr
// in an error — gh never echoes the secret value, but we apply this
// as defence-in-depth so a future gh version that did echo would not
// leak the secret through our error message.
func redactInString(s, secret string) string {
	if secret == "" {
		return s
	}
	return strings.ReplaceAll(s, secret, "<REDACTED>")
}

// repoSecretsResponse is the JSON shape returned by
// GET /repos/{owner}/{repo}/actions/secrets. We only care about the
// "secrets" array of name objects.
type repoSecretsResponse struct {
	Secrets []struct {
		Name string `json:"name"`
	} `json:"secrets"`
}

// ListRepoSecrets lists the names of the Actions secrets set on the
// given repository via GET /repos/{owner}/{repo}/actions/secrets.
// Requires a PAT with 'repo' scope. Returns just the secret names —
// values are never returned by this endpoint (GitHub never exposes
// secret values via the API, only names).
//
// token is a GitHub PAT with repo scope. owner and repo identify the
// target repository (e.g. "Korrnals", "gpg-keysmith").
//
// Security: token is never logged or echoed. The response contains
// only secret names, not values — GitHub does not expose values via
// this endpoint.
func ListRepoSecrets(token, owner, repo string) ([]string, error) {
	return ListRepoSecretsWithClient(token, owner, repo, defaultHTTPClient)
}

// ListRepoSecretsWithClient is the testable form of ListRepoSecrets:
// it accepts a Doer so tests can inject a fake HTTP transport without
// touching the network.
func ListRepoSecretsWithClient(token, owner, repo string, c Doer) ([]string, error) {
	if token == "" {
		return nil, fmt.Errorf("github: list repo secrets: token is required")
	}
	if err := ValidateOwnerRepo(owner, repo); err != nil {
		return nil, err
	}
	if c == nil {
		c = defaultHTTPClient
	}

	path, err := reposPath(owner, repo, "/actions/secrets")
	if err != nil {
		return nil, err
	}
	req, err := newGitHubRequest(http.MethodGet, path, token, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github: list repo secrets: HTTP request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("github: list repo secrets: GitHub API returned status %d: %s",
			resp.StatusCode, truncateForError(resp.Body))
	}

	var body repoSecretsResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("github: list repo secrets: decode response: %w", err)
	}
	names := make([]string, 0, len(body.Secrets))
	for _, s := range body.Secrets {
		if s.Name != "" {
			names = append(names, s.Name)
		}
	}
	return names, nil
}
