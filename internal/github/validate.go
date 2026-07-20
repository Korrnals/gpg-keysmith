package github

import (
	"fmt"
	"net/url"
	"strings"
)

// ValidateOwnerRepo rejects owner/repo pairs that could be used to
// inject path segments into GitHub REST API URLs. GitHub owner and
// repo names match ^[A-Za-z0-9._-]+$ — no slashes, no spaces, no query
// characters, no percent-encoding. This is a defense against a
// malicious or mistyped owner/repo like "owner/bar/../other" being
// interpolated into /repos/%s/%s/... and silently hitting a different
// endpoint.
//
// ValidateOwnerRepo is called at every public entry point that takes
// owner and repo (UploadPublicKey does not take them, but
// SetRepoSecret, SetGPGSecrets, CommitPublicKeyFile, ListRepoSecrets
// do). It rejects empty strings, strings with '/', '?', spaces, or any
// character outside the GitHub name set.
//
// As defense-in-depth, callers that interpolate owner/repo into URL
// paths also wrap them with url.PathEscape (the validation already
// rejects bad chars, but PathEscape is the belt-and-suspenders
// pattern).
func ValidateOwnerRepo(owner, repo string) error {
	if err := validateNamePart(owner, "owner"); err != nil {
		return err
	}
	if err := validateNamePart(repo, "repo"); err != nil {
		return err
	}
	return nil
}

// validateNamePart checks a single owner or repo name part against the
// GitHub name character set. label is "owner" or "repo" and is used in
// the error message so the caller knows which part failed.
func validateNamePart(s, label string) error {
	if s == "" {
		return fmt.Errorf("github: %s is required", label)
	}
	for _, r := range s {
		ok := (r >= 'A' && r <= 'Z') ||
			(r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') ||
			r == '.' || r == '_' || r == '-'
		if !ok {
			return fmt.Errorf("github: %s %q must match ^[A-Za-z0-9._-]+$ (rejected %q)", label, s, string(r))
		}
	}
	return nil
}

// validateBranch rejects branch names that could inject path or query
// segments into GitHub REST API URLs. Unlike owner/repo, branch names
// legitimately contain '/' (e.g. "chore/add-gpg-public-key"), so we do NOT
// PathEscape them — we validate and pass through. Rejected: empty, '?', '#',
// '..', control chars, leading/trailing '/'. Allowed: alphanumerics, '-', '_',
// '.', '/' (interior only).
func validateBranch(branch string) error {
	if branch == "" {
		return fmt.Errorf("github: branch is required")
	}
	if strings.HasPrefix(branch, "/") || strings.HasSuffix(branch, "/") {
		return fmt.Errorf("github: branch %q must not have leading/trailing '/'", branch)
	}
	if strings.Contains(branch, "..") {
		return fmt.Errorf("github: branch %q must not contain '..' (path traversal)", branch)
	}
	for _, r := range branch {
		if r == '?' || r == '#' || r == ' ' {
			return fmt.Errorf("github: branch %q must not contain %q", branch, string(r))
		}
		if r < 0x20 {
			return fmt.Errorf("github: branch %q must not contain control chars", branch)
		}
	}
	return nil
}

// escapeOwnerRepo returns owner and repo percent-escaped for safe
// interpolation into a GitHub REST API URL path. ValidateOwnerRepo
// already rejects any character that PathEscape would transform, so
// in practice the escaped form equals the input — but we apply
// PathEscape anyway as defense-in-depth so a future caller that
// forgets to validate cannot introduce a path-injection.
func escapeOwnerRepo(owner, repo string) (string, string) {
	return url.PathEscape(owner), url.PathEscape(repo)
}

// reposPath builds a /repos/{owner}/{repo}... path segment with both
// parts validated and PathEscape'd. It is a convenience used by the
// repo.go and secrets.go HTTP helpers so every URL is built through
// one validated code path. The suffix is appended verbatim (it is a
// constant like "/git/blobs" controlled by the caller, not user
// input); if a suffix carries user input it must be escaped by the
// caller before passing it in.
func reposPath(owner, repo, suffix string) (string, error) {
	if err := ValidateOwnerRepo(owner, repo); err != nil {
		return "", err
	}
	o, r := escapeOwnerRepo(owner, repo)
	return fmt.Sprintf("/repos/%s/%s%s", o, r, suffix), nil
}

// ownerRepoArg rebuilds the "owner/repo" display string used in
// non-URL contexts (e.g. the gh CLI --repo argument). It validates
// first so a bad pair is rejected before it reaches the CLI. The
// returned string is the literal owner+"/"+repo (no escaping needed —
// the validation already rejected any '/' inside either part).
func ownerRepoArg(owner, repo string) (string, error) {
	if err := ValidateOwnerRepo(owner, repo); err != nil {
		return "", err
	}
	return owner + "/" + repo, nil
}
