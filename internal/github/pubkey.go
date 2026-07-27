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
	"strconv"
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
// the user/gpg_keys endpoints. It includes the subkey fingerprints
// and email list because the dedup preflight in UploadPublicKey needs
// to detect "this subkey is already on the account under a different
// primary key" — the dogfooded case (a key with multiple subkeys was
// partially uploaded; only the subkey conflict surfaces as a 422).
type GpgKeyRef struct {
	// ID is the GitHub-internal integer key id (used for DELETE).
	ID int64 `json:"id"`
	// KeyID is the GitHub-visible hex key id (short form).
	KeyID string `json:"key_id"`
	// Fingerprint is the full 40-char primary fingerprint, lowercase
	// hex. Empty if GitHub returned no primary fingerprint.
	Fingerprint string `json:"fingerprint"`
	// Emails lists the email addresses associated with the GPG key on
	// GitHub. Empty if GitHub returned no emails. Surfaced to the
	// wizard so the "already on GitHub" message can name the user.
	Emails []string `json:"emails"`
	// Subkeys lists the subkey fingerprints for this primary key. The
	// dogfooding bug (korrnals, 2026-07-22) was a subkey collision: a
	// 422 from GitHub whose body named the conflicting subkey. The
	// preflight walks this slice.
	Subkeys []GpgKeySubkey `json:"subkeys"`
}

// GpgKeySubkey is a single subkey entry in the GitHub /user/gpg_keys
// response. We only model the fields we need for dedup matching.
type GpgKeySubkey struct {
	ID           int64  `json:"id"`
	PrimaryKeyID int64  `json:"primary_key_id"`
	Fingerprint  string `json:"fingerprint"`
}

// uploadPublicKeyResponse is the JSON shape returned by POST
// /user/gpg_keys on success.
type uploadPublicKeyResponse struct {
	ID          int64  `json:"id"`
	KeyID       string `json:"key_id"`
	Fingerprint string `json:"fingerprint"`
}

// githubErrorBody is the standard GitHub REST error payload: a
// top-level "message" plus a list of "errors", each with a "code" and
// "message". The /user/gpg_keys 422 body that names the conflicting
// subkey uses this shape (code: custom, message: "The key was not
// added because one or more subkeys already exist: <fp>"). Parsed
// only for the 422 subkey-already-exists detection; non-matching
// 422s are surfaced verbatim.
type githubErrorBody struct {
	Message string             `json:"message"`
	Errors  []githubErrorEntry `json:"errors"`
}

type githubErrorEntry struct {
	Resource string `json:"resource"`
	Field    string `json:"field"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

// subkeyAlreadyExistsMarker is the GitHub error code that means "a
// subkey of the uploaded key is already on the account under another
// key". The 422 fallback in UploadPublicKey matches on this code and
// on the message containing the subkey fingerprint.
const subkeyAlreadyExistsMarker = "custom"

// subkeyAlreadyExistsSubstring is the human-readable substring GitHub
// includes in the error message when the subkey-already-exists case
// fires. Used to confirm the matched 422 is the case we handle, not a
// different `code: custom` condition.
const subkeyAlreadyExistsSubstring = "one or more subkeys already exist"

// ErrKeyAlreadyExists is returned when the GPG subkey is already
// associated with another GPG key on the user's GitHub account. The
// accompanying (KeyID, Emails, Fingerprint) describe the existing key
// so the caller can render "already on GitHub as <key_id> (<emails>)
// — step is effectively done" without a follow-up API call.
//
// Use errors.As to detect: target is *github.ErrKeyAlreadyExists.
type ErrKeyAlreadyExists struct {
	// KeyID is GitHub's integer key id of the existing key, as a
	// string (e.g. "72834") for stable formatting in error
	// messages and state files.
	KeyID string
	// Emails is the list of email addresses GitHub has associated
	// with the existing key. May be empty.
	Emails []string
	// Fingerprint is the subkey fingerprint that triggered the
	// collision. Stored normalised (lowercase, no spaces) so it can
	// be compared directly against future gpg output.
	Fingerprint string
}

func (e *ErrKeyAlreadyExists) Error() string {
	emails := strings.Join(e.Emails, ", ")
	if emails == "" {
		emails = "<no emails>"
	}
	return fmt.Sprintf("gpg subkey %s is already on GitHub as key %s (%s)",
		e.Fingerprint, e.KeyID, emails)
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
//
// On a 422 with the subkey-already-exists payload (GitHub's
// `code: custom` + "one or more subkeys already exist: <fp>"), this
// function does a follow-up ListUserGpgKeys to find which existing
// key now holds the subkey and returns *ErrKeyAlreadyExists. The
// caller (typically the wizard) treats *ErrKeyAlreadyExists as "step
// effectively done" and proceeds to the next step — retrying the
// upload will hit the same 422 because the server-side state is
// already correct, and surfacing the 422 to the user creates a
// retry loop with no forward progress.
func UploadPublicKeyWithClient(token, armoredPubKey string, c Doer) (string, error) {
	return uploadPublicKey(token, armoredPubKey, "", c)
}

// UploadPublicKeyWithFingerprint is the caller-friendly form: the
// caller (cmd/keysmith) already has the fingerprint from
// gpg.DetectExistingKeys, so we pass it in for an exact dedup match.
// If the fingerprint matches an existing key (by primary OR any
// subkey fingerprint), the upload is skipped and
// *ErrKeyAlreadyExists is returned with the existing key's
// (key_id, emails, fingerprint).
//
// This is the wizard's primary entry point. The 422-fallback inside
// uploadPublicKey covers the case where the preflight missed (race
// with another upload, or the PAT cannot see the conflicting key
// because of scope) — GitHub still surfaces the subkey conflict as
// a 422 with a parseable body.
func UploadPublicKeyWithFingerprint(token, armoredPubKey, fingerprint string) (string, error) {
	return UploadPublicKeyWithFingerprintAndClient(token, armoredPubKey, fingerprint, defaultHTTPClient)
}

// UploadPublicKeyWithFingerprintAndClient is the testable form.
func UploadPublicKeyWithFingerprintAndClient(token, armoredPubKey, fingerprint string, c Doer) (string, error) {
	return uploadPublicKey(token, armoredPubKey, fingerprint, c)
}

// uploadPublicKey is the shared implementation of UploadPublicKey and
// UploadPublicKeyWithFingerprint. fingerprint is optional; when
// non-empty it is used in the preflight to short-circuit an upload
// whose subkey is already on the account (so we never POST, we just
// return *ErrKeyAlreadyExists).
//
// Returns the fingerprint of the uploaded (or already-present) key.
// On a subkey-already-exists 422 from GitHub, returns
// *ErrKeyAlreadyExists (the caller treats this as success — the
// subkey is on the account, the goal is achieved). On any other
// error, returns the error as-is so the caller can decide.
func uploadPublicKey(token, armoredPubKey, fingerprint string, c Doer) (string, error) {
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

	// Preflight: if the caller passed a fingerprint and it matches
	// any existing key (primary OR any subkey), the subkey is
	// already on the account under another key. Return as success —
	// do NOT POST, do NOT offer retry. The wizard renders this as
	// "already on GitHub, step done".
	if fingerprint != "" {
		if hit := findExistingByFingerprint(existing, fingerprint); hit != nil {
			return hit.Fingerprint, &ErrKeyAlreadyExists{
				KeyID:       strconv.FormatInt(hit.ID, 10),
				Emails:      hit.Emails,
				Fingerprint: normaliseFingerprint(fingerprint),
			}
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

	// 422 subkey-already-exists fallback. If the preflight missed
	// (e.g. the conflicting key is owned by another user the PAT
	// can see but the subkey wasn't listed in the first GET, or a
	// race with a concurrent upload), GitHub still returns 422 with
	// a parseable body naming the subkey. We follow up with a fresh
	// list to find which key now holds the subkey, then return
	// *ErrKeyAlreadyExists.
	if resp.StatusCode == http.StatusUnprocessableEntity {
		if subkeyFP, matched := matchSubkeyAlreadyExists(resp.Body); matched {
			// Follow-up list — the existing key may have appeared
			// in the account since the first GET (race) or was
			// always there but our preflight didn't have the
			// fingerprint to check it. Either way, the second
			// GET is the ground truth.
			fresh, listErr := listUserGpgKeys(token, c)
			if listErr != nil {
				return "", fmt.Errorf("github: list existing GPG keys (422 fallback): %w", listErr)
			}
			if hit := findExistingByFingerprint(fresh, subkeyFP); hit != nil {
				return hit.Fingerprint, &ErrKeyAlreadyExists{
					KeyID:       strconv.FormatInt(hit.ID, 10),
					Emails:      hit.Emails,
					Fingerprint: normaliseFingerprint(subkeyFP),
				}
			}
			// 422 said the subkey is on the account, but the
			// follow-up list could not find it. This is rare
			// (eventual consistency at GitHub, or the conflicting
			// key belongs to a different user the PAT can see
			// under a different endpoint). Return a typed error
			// with the subkey fingerprint so the wizard can still
			// log it; the email list is empty because we could
			// not resolve it.
			return subkeyFP, &ErrKeyAlreadyExists{
				KeyID:       "",
				Emails:      nil,
				Fingerprint: normaliseFingerprint(subkeyFP),
			}
		}
		// 422 with a different `code` (missing_field, invalid,
		// unprocessable, etc.) is a real validation failure.
		// Surface it as before — do NOT silently swallow.
		return "", fmt.Errorf("github: upload public key: GitHub API returned status %d: %s",
			resp.StatusCode, truncateForError(resp.Body))
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

// findExistingByFingerprint returns the first existing key whose
// primary fingerprint OR any subkey fingerprint matches want (after
// normalising whitespace and case). Returns nil if no key matches.
//
// want is the subkey fingerprint the caller is about to upload (or
// the fingerprint GitHub named in the 422 body). It is matched
// against the primary fingerprint AND every subkey of every existing
// key on the account — the dogfooded case is the latter (korrnals,
// 2026-07-22): a subkey was already on the account under a different
// primary key.
func findExistingByFingerprint(existing []GpgKeyRef, want string) *GpgKeyRef {
	norm := normaliseFingerprint(want)
	if norm == "" {
		return nil
	}
	for i := range existing {
		k := &existing[i]
		if normaliseFingerprint(k.Fingerprint) == norm {
			return k
		}
		for j := range k.Subkeys {
			if normaliseFingerprint(k.Subkeys[j].Fingerprint) == norm {
				return k
			}
		}
	}
	return nil
}

// FindExistingByKeyID reports whether any GPG key in existing has the
// given GitHub integer key id. The id is the same form stored in
// wizard.WizardState.GithubKeyID and in ErrKeyAlreadyExists.KeyID:
// the decimal representation of GpgKeyRef.ID (e.g. "72834").
//
// Used by the wizard's re-run short-circuit in stepGitHub to
// re-validate that a cached state.GithubKeyID still refers to a key
// on the account under the current token (defence against token
// rotation, key deletion, or a state file authored by a different
// account). Returns the matching key reference, or nil if no key has
// the id or id is not a valid decimal integer.
func FindExistingByKeyID(existing []GpgKeyRef, id string) *GpgKeyRef {
	if id == "" {
		return nil
	}
	want, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return nil
	}
	for i := range existing {
		if existing[i].ID == want {
			return &existing[i]
		}
	}
	return nil
}

// matchSubkeyAlreadyExists parses a 422 body from /user/gpg_keys and
// reports whether it is the subkey-already-exists case. Returns
// (subkey_fingerprint, true) when matched, ("", false) otherwise.
//
// GitHub's 422 body for this case looks like:
//
//	{"message":"Validation Failed","errors":[{"resource":"GpgKey",
//	  "code":"custom","message":"The key was not added because one
//	  or more subkeys already exist: FD910BA1AF89641A"}]}
//
// The subkey fingerprint is the trailing hex token of the error
// message. We match on (a) `code: custom` and (b) the human-readable
// substring "one or more subkeys already exist" so unrelated
// `code: custom` 422s (different validation rules) are not
// misclassified.
func matchSubkeyAlreadyExists(body io.Reader) (string, bool) {
	if body == nil {
		return "", false
	}
	var errBody githubErrorBody
	if err := json.NewDecoder(body).Decode(&errBody); err != nil {
		return "", false
	}
	for _, e := range errBody.Errors {
		if e.Code != subkeyAlreadyExistsMarker {
			continue
		}
		if !strings.Contains(e.Message, subkeyAlreadyExistsSubstring) {
			continue
		}
		// Trailing hex token is the subkey fingerprint. We accept
		// either the short (16-hex) or long (40-hex) form. Strip
		// trailing punctuation that occasionally appears in
		// GitHub's error messages.
		fp := extractTrailingFingerprint(e.Message)
		if fp == "" {
			return "", false
		}
		return fp, true
	}
	return "", false
}

// extractTrailingFingerprint returns the last whitespace-delimited
// hex token of msg whose length is a valid GPG fingerprint (40-char
// long form or 16-char short id), or "" if none is found. This is
// tailored to GitHub's subkey-already-exists error message, which
// ends with "subkeys already exist: <fingerprint>".
func extractTrailingFingerprint(msg string) string {
	// Trim trailing punctuation that sometimes appears in
	// GitHub's error messages (".", "]", ")", etc.).
	msg = strings.TrimRight(msg, " .)]}\"'")
	fields := strings.Fields(msg)
	if len(fields) == 0 {
		return ""
	}
	tok := fields[len(fields)-1]
	// Accept either 40-char fingerprint or 16-char short key id.
	if !isHex(tok) {
		return ""
	}
	if len(tok) == 40 || len(tok) == 16 {
		return tok
	}
	return ""
}

// isHex reports whether s is non-empty and contains only hex digits
// (0-9, a-f, A-F). Used to filter tokens before treating them as a
// fingerprint candidate.
func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// subkeyFingerprints flattens a list of GitHub GPG keys into the
// slice of every subkey fingerprint (including the primary
// fingerprint, because it is itself a valid subkey target — the
// dedup preflight accepts it as a match). The order is preserved
// (primary first, then each key's subkeys in order). Empty inputs
// produce an empty (non-nil) slice.
//
// Exposed for tests and for any future caller that wants the flat
// list without re-parsing the GitHub response.
func subkeyFingerprints(keys []GpgKeyRef) []string {
	out := make([]string, 0, len(keys))
	for i := range keys {
		k := &keys[i]
		if k.Fingerprint != "" {
			out = append(out, k.Fingerprint)
		}
		for j := range k.Subkeys {
			if k.Subkeys[j].Fingerprint != "" {
				out = append(out, k.Subkeys[j].Fingerprint)
			}
		}
	}
	return out
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
