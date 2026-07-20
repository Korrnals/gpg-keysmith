// Package github wraps the GitHub REST API for uploading GPG public
// keys, setting repository secrets, and committing the public key
// file to a repo.
package github

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Doer is the HTTP client interface used by the github package. It
// matches *http.Client.Do. Tests inject a fake Doer to exercise the
// GitHub API surface without hitting api.github.com.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// apiBase is the GitHub REST API root. Exposed as a package var so
// tests can point it at an httptest.Server if they prefer the full
// net/http path over a fake Doer.
var apiBase = "https://api.github.com"

// defaultHTTPClient is used when a caller does not inject a Doer. It
// is a package var so tests can swap it.
var defaultHTTPClient Doer = &http.Client{}

// GpgKeyRef is a minimal view of a GitHub GPG key record returned by
// the user/gpg_keys endpoints.
type GpgKeyRef struct {
	// ID is the GitHub-internal integer key id (used for DELETE).
	ID int64 `json:"id"`
	// KeyID is the GitHub-visible hex key id (short form).
	KeyID string `json:"key_id"`
	// Fingerprint is the full 40-char fingerprint, lowercase hex.
	Fingerprint string `json:"fingerprint"`
}

// uploadPublicKeyResponse is the JSON shape returned by POST
// /user/gpg_keys on success.
type uploadPublicKeyResponse struct {
	ID          int64  `json:"id"`
	KeyID       string `json:"key_id"`
	Fingerprint string `json:"fingerprint"`
}

// pgpArmorHeader is the mandatory first line of an ASCII-armored PGP
// public key block. It is used as a cheap sanity check before sending
// the armor to GitHub — it does not validate the PGP packet structure
// (GitHub will reject malformed armor and we surface that error).
const pgpArmorHeader = "-----BEGIN PGP PUBLIC KEY BLOCK-----"

// UploadPublicKey uploads an ASCII-armored public key to the
// authenticated user's GitHub account via POST /user/gpg_keys.
// Requires a PAT with 'admin:gpg_key' scope. If a key with the same
// fingerprint already exists, it is NOT re-uploaded — the existing
// fingerprint is returned without error.
//
// token is a GitHub PAT with admin:gpg_key scope. armoredPubKey is
// the ASCII-armored public key (must start with the PGP armor header).
// Returns the fingerprint of the uploaded (or already-present) key.
//
// Security: token is never logged, never echoed, never written to
// disk. armoredPubKey is public material — it is safe to log a
// fingerprint, but the full armor is only sent to GitHub.
func UploadPublicKey(token, armoredPubKey string) (string, error) {
	return UploadPublicKeyWithClient(token, armoredPubKey, defaultHTTPClient)
}

// UploadPublicKeyWithClient is the testable form of UploadPublicKey:
// it accepts a Doer so tests can inject a fake HTTP transport without
// touching the network.
func UploadPublicKeyWithClient(token, armoredPubKey string, c Doer) (string, error) {
	if token == "" {
		return "", fmt.Errorf("github: upload public key: token is required")
	}
	if !strings.HasPrefix(armoredPubKey, pgpArmorHeader) {
		return "", fmt.Errorf("github: upload public key: armored public key must start with %q", pgpArmorHeader)
	}
	if c == nil {
		c = defaultHTTPClient
	}

	// Detect existing keys first. The dedup-by-fingerprint path
	// lives in UploadPublicKeyWithFingerprint (the caller-friendly
	// form). UploadPublicKey itself does not dedup — on a 422 it
	// returns an error pointing the caller at the
	// fingerprint-matching variant, because returning the first
	// existing key's fingerprint as a guess silently hides which
	// key the caller actually intended.
	existing, err := listUserGpgKeys(token, c)
	if err != nil {
		return "", fmt.Errorf("github: list existing GPG keys: %w", err)
	}
	_ = existing

	body, err := json.Marshal(struct {
		ArmoredPublicKey string `json:"armored_public_key"`
	}{ArmoredPublicKey: armoredPubKey})
	if err != nil {
		return "", fmt.Errorf("github: marshal upload body: %w", err)
	}

	req, err := newGitHubRequest(http.MethodPost, "/user/gpg_keys", token, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("github: upload public key: HTTP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 422 from /user/gpg_keys means the key is already uploaded.
	// GitHub returns a body like
	//   {"message": "Validation Failed", "errors": [...]}
	// We do NOT return the first existing key's fingerprint — without
	// a local fingerprint match we cannot tell which key the caller
	// intended, and returning a guess silently hides a real problem.
	// Callers that want "upload or get existing" semantics MUST use
	// UploadPublicKeyWithFingerprint, which matches by fingerprint
	// and returns the correct existing key.
	if resp.StatusCode == http.StatusUnprocessableEntity {
		return "", fmt.Errorf("github: a GPG key is already uploaded for this user, but the fingerprint could not be matched automatically; call UploadPublicKeyWithFingerprint with the explicit fingerprint")
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("github: upload public key: GitHub API returned status %d: %s",
			resp.StatusCode, truncateForError(resp.Body))
	}

	var out uploadPublicKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("github: upload public key: decode response: %w", err)
	}
	if out.Fingerprint == "" {
		return "", fmt.Errorf("github: upload public key: GitHub returned empty fingerprint")
	}
	return out.Fingerprint, nil
}

// UploadPublicKeyWithFingerprint is the caller-friendly form: the
// caller (cmd/keysmith) already has the fingerprint from
// gpg.DetectExistingKeys, so we pass it in for an exact dedup match.
// If the fingerprint matches an existing key, the upload is skipped
// and the existing fingerprint is returned.
func UploadPublicKeyWithFingerprint(token, armoredPubKey, fingerprint string) (string, error) {
	return UploadPublicKeyWithFingerprintAndClient(token, armoredPubKey, fingerprint, defaultHTTPClient)
}

// UploadPublicKeyWithFingerprintAndClient is the testable form.
func UploadPublicKeyWithFingerprintAndClient(token, armoredPubKey, fingerprint string, c Doer) (string, error) {
	if token == "" {
		return "", fmt.Errorf("github: upload public key: token is required")
	}
	if !strings.HasPrefix(armoredPubKey, pgpArmorHeader) {
		return "", fmt.Errorf("github: upload public key: armored public key must start with %q", pgpArmorHeader)
	}
	if c == nil {
		c = defaultHTTPClient
	}

	existing, err := listUserGpgKeys(token, c)
	if err != nil {
		return "", fmt.Errorf("github: list existing GPG keys: %w", err)
	}
	// Normalise the fingerprint for comparison — GitHub returns
	// lowercase hex without spaces; gpg prints uppercase with spaces
	// in some modes. Strip spaces and lowercase both sides.
	want := normaliseFingerprint(fingerprint)
	for _, k := range existing {
		if normaliseFingerprint(k.Fingerprint) == want && want != "" {
			return k.Fingerprint, nil
		}
	}

	body, err := json.Marshal(struct {
		ArmoredPublicKey string `json:"armored_public_key"`
	}{ArmoredPublicKey: armoredPubKey})
	if err != nil {
		return "", fmt.Errorf("github: marshal upload body: %w", err)
	}
	req, err := newGitHubRequest(http.MethodPost, "/user/gpg_keys", token, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("github: upload public key: HTTP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("github: upload public key: GitHub API returned status %d: %s",
			resp.StatusCode, truncateForError(resp.Body))
	}
	var out uploadPublicKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("github: upload public key: decode response: %w", err)
	}
	if out.Fingerprint == "" {
		return "", fmt.Errorf("github: upload public key: GitHub returned empty fingerprint")
	}
	return out.Fingerprint, nil
}

// ListUserGpgKeys lists the GPG public keys already uploaded to the
// authenticated user's GitHub account. Used by 'status' to detect
// whether the publish step has been run.
func ListUserGpgKeys(token string) ([]GpgKeyRef, error) {
	if token == "" {
		return nil, fmt.Errorf("github: list user GPG keys: token is required")
	}
	return listUserGpgKeys(token, defaultHTTPClient)
}

// ListUserGpgKeysWithClient is the testable form of ListUserGpgKeys.
func ListUserGpgKeysWithClient(token string, c Doer) ([]GpgKeyRef, error) {
	if token == "" {
		return nil, fmt.Errorf("github: list user GPG keys: token is required")
	}
	if c == nil {
		c = defaultHTTPClient
	}
	return listUserGpgKeys(token, c)
}

func listUserGpgKeys(token string, c Doer) ([]GpgKeyRef, error) {
	req, err := newGitHubRequest(http.MethodGet, "/user/gpg_keys", token, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github: list GPG keys: HTTP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("github: list GPG keys: GitHub API returned status %d: %s",
			resp.StatusCode, truncateForError(resp.Body))
	}
	var keys []GpgKeyRef
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return nil, fmt.Errorf("github: list GPG keys: decode response: %w", err)
	}
	return keys, nil
}

// newGitHubRequest builds a request to the GitHub REST API with the
// required Authorization, Accept, and content-type headers. path is
// relative to apiBase (e.g. "/user/gpg_keys"). body may be nil for GET.
func newGitHubRequest(method, path, token string, body io.Reader) (*http.Request, error) {
	url := apiBase + path
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("github: build request %s %s: %w", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	// The GitHub GPG keys API requires this Accept header to render
	// the fingerprint/key_id fields in the response.
	req.Header.Set("Accept", "application/vnd.github+json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// truncateForError reads up to 200 bytes of an HTTP response body for
// inclusion in an error message. It never returns secret material —
// GitHub error payloads are JSON like {"message": "..."} and do not
// echo the request body. The body is consumed once; callers should
// only invoke this when they intend to discard the body.
func truncateForError(body io.Reader) string {
	if body == nil {
		return ""
	}
	b := make([]byte, 200)
	n, _ := body.Read(b)
	s := string(b[:n])
	s = strings.TrimSpace(s)
	// Collapse newlines so the error stays on one line.
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// normaliseFingerprint strips spaces and lowercases a fingerprint so
// two fingerprints from different sources (gpg uppercase with spaces,
// GitHub lowercase without) can be compared for equality.
func normaliseFingerprint(fp string) string {
	s := strings.ReplaceAll(fp, " ", "")
	return strings.ToLower(s)
}
