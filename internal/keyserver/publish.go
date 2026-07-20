// Package keyserver publishes a public GPG key to a public keyserver
// (keys.openpgp.org preferred, keyserver.ubuntu.com fallback) via
// HTTPS submit endpoints. It does NOT use the legacy HKP hkp://
// protocol.
package keyserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// pgpArmorHeader is the mandatory first line of an ASCII-armored PGP
// public key block. It is used as a cheap sanity check before POSTing
// the armor to a keyserver — it does not validate the PGP packet
// structure (the keyserver will reject malformed armor and we surface
// that error).
const pgpArmorHeader = "-----BEGIN PGP PUBLIC KEY BLOCK-----"

// httpDoer is the HTTP client interface used by the keyserver package.
// It matches *http.Client.Do. Tests inject a fake Doer to exercise the
// keyserver API surface without hitting the network.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// defaultHTTPClient is used when a caller does not inject a Doer. It
// is a package var so tests can swap it.
var defaultHTTPClient httpDoer = http.DefaultClient

// Keyserver identifiers accepted by PublishPubKey.
const (
	// KeyserverOpenPGP is the preferred keyserver (no email
	// verification needed for the key itself, but a verification
	// email is sent for the UID).
	KeyserverOpenPGP = "keys.openpgp.org"
	// KeyserverUbuntu is the fallback keyserver.
	KeyserverUbuntu = "keyserver.ubuntu.com"
	// KeyserverAll publishes to both keys.openpgp.org and
	// keyserver.ubuntu.com.
	KeyserverAll = "all"
)

// PublishOptions describes the inputs for a keyserver publish.
type PublishOptions struct {
	// ArmoredPubKey is the ASCII-armored public key (must start with
	// the PGP armor header). Required.
	ArmoredPubKey string
	// Keyserver selects the target keyserver(s). Accepted values:
	//   - "keys.openpgp.org" (default) — preferred keyserver
	//   - "keyserver.ubuntu.com" — fallback keyserver
	//   - "all" — publish to both
	// The CLI flag aliases ("openpgp", "ubuntu") are normalised by
	// the caller; PublishPubKey accepts only the canonical names plus
	// "all".
	Keyserver string
	// Fingerprint is the optional 40-char fingerprint of the public
	// key. If set, it is used to build the verification URL for
	// keys.openpgp.org. If empty, PublishPubKey attempts to extract
	// the fingerprint from the armor; if extraction fails, the URL
	// is returned empty with a note in PublishResult.Err.
	Fingerprint string
	// Doer is the injectable HTTP client. If nil, http.DefaultClient
	// is used. Tests inject a fake Doer to exercise the API surface
	// without hitting the network.
	Doer httpDoer
}

// PublishResult holds the outcome of a single keyserver publish
// attempt. One PublishResult is returned per keyserver that was
// contacted.
type PublishResult struct {
	// Keyserver is the canonical keyserver name
	// ("keys.openpgp.org" or "keyserver.ubuntu.com").
	Keyserver string
	// Success is true if the keyserver accepted the upload (HTTP 2xx).
	Success bool
	// URL is the fetchable URL of the uploaded key, if available.
	// For keys.openpgp.org it is
	//   https://keys.openpgp.org/vks/vby/<fingerprint>
	// For keyserver.ubuntu.com it is
	//   https://keyserver.ubuntu.com/pks/lookup?op=vindex&search=<fingerprint>
	// Empty if the fingerprint is unknown or the upload failed.
	URL string
	// Err is the error encountered during the publish attempt, if
	// any. nil on success. When Success is true and URL is empty, Err
	// carries a note explaining that the fingerprint is unknown (the
	// upload itself succeeded).
	Err error
}

// publishError is a sentinel error type used to distinguish "upload
// succeeded but URL is empty" from a real failure. It is returned in
// PublishResult.Err when Success is true and URL is empty.
type publishError struct{ msg string }

func (e *publishError) Error() string { return e.msg }

// endpoint definitions. Exposed as package vars so tests can point
// them at an httptest.Server if they prefer the full net/http path
// over a fake Doer.
var (
	openpgpUploadURL = "https://keys.openpgp.org/vks/v1/upload"
	ubuntuUploadURL  = "https://keyserver.ubuntu.com/pks/add"
)

// PublishPubKey publishes the armored public key to the selected
// keyserver(s). Returns one PublishResult per keyserver that was
// contacted, in the order keys.openpgp.org first, then
// keyserver.ubuntu.com (when "all" is selected).
//
// The function validates the armor header before any HTTP call. If
// the keyserver name is invalid, an error is returned and no HTTP
// call is made.
//
// If opts.Doer is nil, http.DefaultClient is used.
func PublishPubKey(opts PublishOptions) ([]PublishResult, error) {
	if opts.ArmoredPubKey == "" {
		return nil, fmt.Errorf("keyserver: publish: armored public key is required")
	}
	if !strings.HasPrefix(opts.ArmoredPubKey, pgpArmorHeader) {
		return nil, fmt.Errorf("keyserver: publish: armored public key must start with %q", pgpArmorHeader)
	}

	ks := opts.Keyserver
	if ks == "" {
		ks = KeyserverOpenPGP
	}
	targets, err := resolveKeyservers(ks)
	if err != nil {
		return nil, err
	}

	doer := opts.Doer
	if doer == nil {
		doer = defaultHTTPClient
	}

	// Resolve the fingerprint: prefer the explicit option, then try
	// to extract it from the armor.
	fp := strings.TrimSpace(opts.Fingerprint)
	if fp == "" {
		fp = extractFingerprintFromArmor(opts.ArmoredPubKey)
	}

	var results []PublishResult
	for _, target := range targets {
		switch target {
		case KeyserverOpenPGP:
			results = append(results, publishToOpenPGP(opts.ArmoredPubKey, fp, doer))
		case KeyserverUbuntu:
			results = append(results, publishToUbuntu(opts.ArmoredPubKey, fp, doer))
		}
	}
	return results, nil
}

// resolveKeyservers maps the Keyserver option (canonical name or
// "all") to the ordered list of keyserver targets to contact.
func resolveKeyservers(ks string) ([]string, error) {
	switch ks {
	case KeyserverOpenPGP:
		return []string{KeyserverOpenPGP}, nil
	case KeyserverUbuntu:
		return []string{KeyserverUbuntu}, nil
	case KeyserverAll:
		return []string{KeyserverOpenPGP, KeyserverUbuntu}, nil
	default:
		return nil, fmt.Errorf("keyserver: publish: invalid keyserver %q (want %q, %q, or %q)",
			ks, KeyserverOpenPGP, KeyserverUbuntu, KeyserverAll)
	}
}

// publishToOpenPGP POSTs the armored key to keys.openpgp.org with a
// JSON body {"keytext":"<armored>"}. On success, the verification URL
// is https://keys.openpgp.org/vks/vby/<fingerprint>. If the
// fingerprint is empty, the URL is empty and a note is set in Err.
func publishToOpenPGP(armoredPubKey, fingerprint string, doer httpDoer) PublishResult {
	body, err := json.Marshal(struct {
		Keytext string `json:"keytext"`
	}{Keytext: armoredPubKey})
	if err != nil {
		return PublishResult{
			Keyserver: KeyserverOpenPGP,
			Success:   false,
			Err:       fmt.Errorf("keyserver: publish to %s: marshal body: %w", KeyserverOpenPGP, err),
		}
	}

	req, err := http.NewRequest(http.MethodPost, openpgpUploadURL, bytes.NewReader(body))
	if err != nil {
		return PublishResult{
			Keyserver: KeyserverOpenPGP,
			Success:   false,
			Err:       fmt.Errorf("keyserver: publish to %s: build request: %w", KeyserverOpenPGP, err),
		}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := doer.Do(req)
	if err != nil {
		return PublishResult{
			Keyserver: KeyserverOpenPGP,
			Success:   false,
			Err:       fmt.Errorf("keyserver: publish to %s: HTTP request failed: %w", KeyserverOpenPGP, err),
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return PublishResult{
			Keyserver: KeyserverOpenPGP,
			Success:   false,
			Err: fmt.Errorf("keyserver: publish to %s: keyserver returned status %d: %s",
				KeyserverOpenPGP, resp.StatusCode, truncateForError(resp.Body)),
		}
	}

	// Drain the body so the connection can be reused.
	_, _ = io.Copy(io.Discard, resp.Body)

	urlStr := ""
	if fingerprint != "" {
		urlStr = fmt.Sprintf("https://keys.openpgp.org/vks/vby/%s", normaliseFingerprint(fingerprint))
	}

	res := PublishResult{
		Keyserver: KeyserverOpenPGP,
		Success:   true,
		URL:       urlStr,
	}
	if urlStr == "" {
		res.Err = &publishError{msg: fmt.Sprintf(
			"keyserver: publish to %s: upload succeeded but verification URL is empty (fingerprint unknown)",
			KeyserverOpenPGP)}
	}
	return res
}

// publishToUbuntu POSTs the armored key to keyserver.ubuntu.com with
// a form field keytext=<armored> (application/x-www-form-urlencoded).
// On success, the lookup URL is
// https://keyserver.ubuntu.com/pks/lookup?op=vindex&search=<fingerprint>.
func publishToUbuntu(armoredPubKey, fingerprint string, doer httpDoer) PublishResult {
	form := url.Values{}
	form.Set("keytext", armoredPubKey)

	req, err := http.NewRequest(http.MethodPost, ubuntuUploadURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return PublishResult{
			Keyserver: KeyserverUbuntu,
			Success:   false,
			Err:       fmt.Errorf("keyserver: publish to %s: build request: %w", KeyserverUbuntu, err),
		}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := doer.Do(req)
	if err != nil {
		return PublishResult{
			Keyserver: KeyserverUbuntu,
			Success:   false,
			Err:       fmt.Errorf("keyserver: publish to %s: HTTP request failed: %w", KeyserverUbuntu, err),
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return PublishResult{
			Keyserver: KeyserverUbuntu,
			Success:   false,
			Err: fmt.Errorf("keyserver: publish to %s: keyserver returned status %d: %s",
				KeyserverUbuntu, resp.StatusCode, truncateForError(resp.Body)),
		}
	}

	// Drain the body so the connection can be reused.
	_, _ = io.Copy(io.Discard, resp.Body)

	urlStr := ""
	if fingerprint != "" {
		urlStr = fmt.Sprintf("https://keyserver.ubuntu.com/pks/lookup?op=vindex&search=%s",
			normaliseFingerprint(fingerprint))
	}

	res := PublishResult{
		Keyserver: KeyserverUbuntu,
		Success:   true,
		URL:       urlStr,
	}
	if urlStr == "" {
		res.Err = &publishError{msg: fmt.Sprintf(
			"keyserver: publish to %s: upload succeeded but lookup URL is empty (fingerprint unknown)",
			KeyserverUbuntu)}
	}
	return res
}

// extractFingerprintFromArmor attempts to read the fingerprint from
// the armored public key block. The OpenPGP armor format does not
// embed the fingerprint in a stable, parseable way without a full
// PGP packet parser (which gpg-keysmith does not ship). The only
// reliable in-armor source is an optional "Comment:" line that some
// tools emit with the fingerprint — but this is not guaranteed.
//
// We do a best-effort scan for a "Comment: Fingerprint:" or
// "Comment:" line matching the 40-char hex fingerprint shape. If
// none is found, an empty string is returned and the caller should
// fall back to passing the fingerprint via PublishOptions.
func extractFingerprintFromArmor(armor string) string {
	for _, line := range strings.Split(armor, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Comment:") {
			continue
		}
		// Strip the "Comment:" prefix and look for a 40-char hex
		// token anywhere in the rest of the line.
		rest := strings.TrimSpace(strings.TrimPrefix(line, "Comment:"))
		// Common forms:
		//   Comment: Fingerprint: ABCD EF01 ...
		//   Comment: ABCD EF01 2345 ...
		if idx := strings.Index(rest, ":"); idx >= 0 {
			rest = strings.TrimSpace(rest[idx+1:])
		}
		// Remove spaces to get a compact hex candidate.
		compact := strings.ReplaceAll(rest, " ", "")
		if isFingerprint(compact) {
			return compact
		}
	}
	return ""
}

// isFingerprint reports whether s is a 40-char lowercase/uppercase
// hex string (the standard OpenPGP v4 fingerprint length).
func isFingerprint(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, r := range s {
		isHex := (r >= '0' && r <= '9') ||
			(r >= 'a' && r <= 'f') ||
			(r >= 'A' && r <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}

// normaliseFingerprint strips spaces and lowercases a fingerprint so
// two fingerprints from different sources (gpg uppercase with spaces,
// the keyserver lowercase without) can be compared for equality and
// embedded in a URL consistently.
func normaliseFingerprint(fp string) string {
	s := strings.ReplaceAll(fp, " ", "")
	return strings.ToLower(s)
}

// truncateForError reads up to 200 bytes of an HTTP response body for
// inclusion in an error message. The body is consumed once; callers
// should only invoke this when they intend to discard the body.
func truncateForError(body io.Reader) string {
	if body == nil {
		return ""
	}
	b := make([]byte, 200)
	n, _ := body.Read(b)
	s := string(b[:n])
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
