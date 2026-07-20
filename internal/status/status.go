// Package status is a read-only inspector that reports the current
// state of a user's GPG + GitHub setup: existing keys, git signing
// config, uploaded GitHub GPG keys, repo CI secrets, and keyserver
// presence. It emits a table with per-step ✅ / ❌ / ⚠️ indicators and
// one-line remediation hints when a step is not green.
package status

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"

	"github.com/Korrnals/gpg-keysmith/internal/git"
	"github.com/Korrnals/gpg-keysmith/internal/github"
	"github.com/Korrnals/gpg-keysmith/internal/gpg"
)

// Status indicator constants used in CheckResult.Status.
const (
	StatusOK   = "✅"
	StatusFail = "❌"
	StatusWarn = "⚠️"
)

// CheckResult is the outcome of a single status check. Status is one
// of StatusOK, StatusFail, StatusWarn. Detail is a short human-readable
// description of what was found. Hint is a one-line remediation
// suggestion, non-empty only when Status is not OK.
type CheckResult struct {
	Status string
	Detail string
	Hint   string
}

// StatusReport aggregates the five status checks performed by
// CollectStatus.
type StatusReport struct {
	GpgKeys      CheckResult
	GitConfig    CheckResult
	GitHubPubKey CheckResult
	RepoSecrets  CheckResult
	Keyserver    CheckResult
}

// StatusOptions configures CollectStatus. GitHubToken is the PAT used
// for the GitHub API checks (may be empty — those checks degrade to
// ⚠️). Repo is the "owner/name" target repo for the CI secrets check
// (may be empty — that check degrades to ⚠️). Keyserver is the
// keyserver hostname to check for publication (defaults to
// "keys.openpgp.org" when empty). Fingerprint is an optional
// 40-char fingerprint used for the keyserver check; when empty it is
// derived from the first key returned by the GPG check.
type StatusOptions struct {
	GitHubToken string
	Repo        string
	Keyserver   string
	Fingerprint string
}

// Injectable function variables. Tests override these with mocks to
// avoid real exec/HTTP calls. Each is restored via t.Cleanup in tests.
var (
	detectKeysFn       = gpg.DetectExistingKeys
	detectSigningKeyFn = git.DetectSigningKey
	getCommitGpgsignFn = getCommitGpgsign
	listUserGpgKeysFn  = github.ListUserGpgKeys
	listRepoSecretsFn  = github.ListRepoSecrets
)

// httpDoer is the HTTP client interface used by the keyserver check.
// It matches *http.Client.Do. Tests inject a fake to avoid the
// network.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// keyserverClient is the injectable HTTP client for the keyserver
// check. Defaults to http.DefaultClient; tests swap it.
var keyserverClient httpDoer = http.DefaultClient

// CollectStatus runs all five checks and returns a StatusReport. It
// does NOT abort on individual check failure — each check is wrapped
// in its own error recovery so a failing check produces a ❌ or ⚠️
// result without preventing the others from running.
func CollectStatus(opts StatusOptions) StatusReport {
	ks := opts.Keyserver
	if ks == "" {
		ks = "keys.openpgp.org"
	}

	var report StatusReport
	report.GpgKeys = checkGpgKeys()
	report.GitConfig = checkGitConfig()

	// Derive fingerprint from the first GPG key if not provided
	// explicitly. This lets the keyserver check run without the user
	// having to pass --fingerprint.
	fp := opts.Fingerprint
	if fp == "" {
		if keys, err := detectKeysFn(); err == nil && len(keys) > 0 {
			fp = keys[0].Fingerprint
		}
	}

	report.GitHubPubKey = checkGitHubPubKey(opts.GitHubToken)
	report.RepoSecrets = checkRepoSecrets(opts.GitHubToken, opts.Repo)
	report.Keyserver = checkKeyserver(fp, ks)
	return report
}

// checkGpgKeys calls gpg.DetectExistingKeys (via the injectable
// detectKeysFn) and reports ✅ if at least one key exists, ❌ if none.
func checkGpgKeys() CheckResult {
	keys, err := detectKeysFn()
	if err != nil {
		return CheckResult{
			Status: StatusFail,
			Detail: fmt.Sprintf("gpg detect failed: %v", err),
			Hint:   "Check that gpg is installed and your keyring is accessible",
		}
	}
	if len(keys) == 0 {
		return CheckResult{
			Status: StatusFail,
			Detail: "no GPG keys found",
			Hint:   "Run 'keysmith generate'",
		}
	}
	return CheckResult{
		Status: StatusOK,
		Detail: fmt.Sprintf("%d key(s) found", len(keys)),
	}
}

// checkGitConfig reads user.signingkey (via detectSigningKeyFn) and
// commit.gpgsign (via getCommitGpgsignFn) from the local repo config.
// ✅ if both are set and gpgsign=true; ⚠️ if partial; ❌ if neither.
func checkGitConfig() CheckResult {
	signingKey, err := detectSigningKeyFn(false)
	if err != nil {
		return CheckResult{
			Status: StatusFail,
			Detail: fmt.Sprintf("git config read failed: %v", err),
			Hint:   "Ensure you are inside a git repository",
		}
	}
	gpgsign, err := getCommitGpgsignFn()
	if err != nil {
		return CheckResult{
			Status: StatusFail,
			Detail: fmt.Sprintf("git config read failed: %v", err),
			Hint:   "Ensure you are inside a git repository",
		}
	}

	hasKey := signingKey != ""
	hasSign := strings.EqualFold(strings.TrimSpace(gpgsign), "true")

	switch {
	case hasKey && hasSign:
		return CheckResult{
			Status: StatusOK,
			Detail: fmt.Sprintf("signing configured (signingkey=%s)", truncateKey(signingKey, 16)),
		}
	case hasKey && !hasSign:
		return CheckResult{
			Status: StatusWarn,
			Detail: fmt.Sprintf("signingkey set but commit.gpgsign is %q", gpgsign),
			Hint:   "Run 'keysmith git-config' to enable commit signing",
		}
	case !hasKey && hasSign:
		return CheckResult{
			Status: StatusWarn,
			Detail: "commit.gpgsign=true but user.signingkey is not set",
			Hint:   "Run 'keysmith git-config' to set the signing key",
		}
	default:
		return CheckResult{
			Status: StatusFail,
			Detail: "no signing configured",
			Hint:   "Run 'keysmith git-config'",
		}
	}
}

// checkGitHubPubKey calls github.ListUserGpgKeys (via the injectable
// listUserGpgKeysFn) and reports ✅ if at least one key is uploaded,
// ❌ if none. ⚠️ if the token is empty (cannot check).
func checkGitHubPubKey(token string) CheckResult {
	if token == "" {
		return CheckResult{
			Status: StatusWarn,
			Detail: "no token — set GITHUB_TOKEN",
			Hint:   "Set GITHUB_TOKEN env var or pass --token",
		}
	}
	keys, err := listUserGpgKeysFn(token)
	if err != nil {
		return CheckResult{
			Status: StatusFail,
			Detail: fmt.Sprintf("GitHub API call failed: %v", err),
			Hint:   "Check your token has admin:gpg_key scope",
		}
	}
	if len(keys) == 0 {
		return CheckResult{
			Status: StatusFail,
			Detail: "no GPG keys uploaded to GitHub",
			Hint:   "Run 'keysmith github'",
		}
	}
	return CheckResult{
		Status: StatusOK,
		Detail: fmt.Sprintf("%d key(s) uploaded", len(keys)),
	}
}

// checkRepoSecrets calls github.ListRepoSecrets (via the injectable
// listRepoSecretsFn) and checks for GPG_PRIVATE_KEY and GPG_PASSPHRASE.
// ✅ if both are set; ⚠️ if only one; ❌ if neither. ⚠️ if token or
// repo is empty (cannot check).
func checkRepoSecrets(token, repo string) CheckResult {
	if token == "" {
		return CheckResult{
			Status: StatusWarn,
			Detail: "no token — set GITHUB_TOKEN",
			Hint:   "Set GITHUB_TOKEN env var or pass --token",
		}
	}
	if repo == "" {
		return CheckResult{
			Status: StatusWarn,
			Detail: "no --repo specified",
			Hint:   "Pass --repo owner/name to check CI secrets",
		}
	}
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return CheckResult{
			Status: StatusFail,
			Detail: fmt.Sprintf("invalid repo %q (expected owner/name)", repo),
			Hint:   "Pass --repo owner/name",
		}
	}
	owner, repoName := parts[0], parts[1]
	names, err := listRepoSecretsFn(token, owner, repoName)
	if err != nil {
		return CheckResult{
			Status: StatusFail,
			Detail: fmt.Sprintf("GitHub API call failed: %v", err),
			Hint:   "Check your token has repo scope and the repo exists",
		}
	}
	hasPriv := containsString(names, "GPG_PRIVATE_KEY")
	hasPass := containsString(names, "GPG_PASSPHRASE")
	switch {
	case hasPriv && hasPass:
		return CheckResult{
			Status: StatusOK,
			Detail: "GPG_PRIVATE_KEY and GPG_PASSPHRASE set",
		}
	case hasPriv && !hasPass:
		return CheckResult{
			Status: StatusWarn,
			Detail: "GPG_PRIVATE_KEY set, GPG_PASSPHRASE missing",
			Hint:   "Run 'keysmith github' to set GPG_PASSPHRASE",
		}
	case !hasPriv && hasPass:
		return CheckResult{
			Status: StatusWarn,
			Detail: "GPG_PASSPHRASE set, GPG_PRIVATE_KEY missing",
			Hint:   "Run 'keysmith github' to set GPG_PRIVATE_KEY",
		}
	default:
		return CheckResult{
			Status: StatusFail,
			Detail: "neither GPG_PRIVATE_KEY nor GPG_PASSPHRASE set",
			Hint:   "Run 'keysmith github'",
		}
	}
}

// checkKeyserver makes an HTTP GET to the keyserver lookup URL for the
// given fingerprint and reports ✅ if the keyserver returns 200 (key
// present), ❌ if 404 (not found). ⚠️ if the request errors or the
// keyserver returns an unexpected status. ⚠️ if fingerprint is empty.
func checkKeyserver(fingerprint, keyserver string) CheckResult {
	if fingerprint == "" {
		return CheckResult{
			Status: StatusWarn,
			Detail: "no GPG key to check",
			Hint:   "Run 'keysmith generate' first",
		}
	}
	urlStr := keyserverLookupURL(keyserver, fingerprint)
	req, err := http.NewRequest(http.MethodGet, urlStr, nil)
	if err != nil {
		return CheckResult{
			Status: StatusFail,
			Detail: fmt.Sprintf("build request failed: %v", err),
			Hint:   "Check the --keyserver value",
		}
	}
	resp, err := keyserverClient.Do(req)
	if err != nil {
		return CheckResult{
			Status: StatusWarn,
			Detail: fmt.Sprintf("keyserver request failed: %v", err),
			Hint:   "Check your network connection",
		}
	}
	defer resp.Body.Close()
	// Drain the body so the connection can be reused.
	_, _ = io.Copy(io.Discard, resp.Body)

	switch {
	case resp.StatusCode == http.StatusOK:
		return CheckResult{
			Status: StatusOK,
			Detail: fmt.Sprintf("published (%s)", keyserver),
		}
	case resp.StatusCode == http.StatusNotFound:
		return CheckResult{
			Status: StatusFail,
			Detail: fmt.Sprintf("not found on %s", keyserver),
			Hint:   "Run 'keysmith publish'",
		}
	default:
		return CheckResult{
			Status: StatusWarn,
			Detail: fmt.Sprintf("%s returned status %d", keyserver, resp.StatusCode),
			Hint:   "Run 'keysmith publish'",
		}
	}
}

// getCommitGpgsign reads commit.gpgsign from the local git config via
// 'git config --get commit.gpgsign'. Returns an empty string (no
// error) if the key is not set. This is the default implementation of
// getCommitGpgsignFn; tests override the variable with a mock.
func getCommitGpgsign() (string, error) {
	cmd := exec.Command("git", "config", "--get", "commit.gpgsign")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &bytes.Buffer{}
	if err := cmd.Run(); err != nil {
		// git config --get exits 1 when the key is not set — this
		// is the "not found" case, not a real failure.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return "", nil
		}
		return "", fmt.Errorf("git config --get commit.gpgsign: %w", err)
	}
	return strings.TrimSpace(out.String()), nil
}

// keyserverLookupURL builds the lookup URL for the given keyserver and
// fingerprint. For keys.openpgp.org it uses the VKS by-fingerprint
// endpoint; for keyserver.ubuntu.com and other HKP keyservers it uses
// the pks/lookup endpoint with op=vindex.
func keyserverLookupURL(keyserver, fingerprint string) string {
	fp := normaliseFingerprint(fingerprint)
	switch keyserver {
	case "keys.openpgp.org":
		return fmt.Sprintf("https://keys.openpgp.org/vks/vby/%s", fp)
	case "keyserver.ubuntu.com":
		return fmt.Sprintf("https://keyserver.ubuntu.com/pks/lookup?op=vindex&search=0x%s", fp)
	default:
		// Generic HKP-over-HTTPS lookup — works for most keyservers.
		return fmt.Sprintf("https://%s/pks/lookup?op=vindex&search=0x%s", keyserver, fp)
	}
}

// normaliseFingerprint strips spaces and lowercases a fingerprint so
// two fingerprints from different sources can be compared and embedded
// in a URL consistently. This is a local duplicate of
// keyserver.normaliseFingerprint (unexported) — kept local to avoid an
// import dependency on internal/keyserver.
func normaliseFingerprint(fp string) string {
	s := strings.ReplaceAll(fp, " ", "")
	return strings.ToLower(s)
}

// truncateKey returns s truncated to n characters with a trailing
// ellipsis if it is longer than n. Used for display in checkGitConfig.
func truncateKey(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// containsString reports whether slice contains s. Used by
// checkRepoSecrets to test for the two expected secret names.
func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
