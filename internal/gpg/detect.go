// Package gpg wraps the local gpg CLI for key detection, generation,
// and export. It is the only package in gpg-keysmith allowed to shell
// out to the gpg binary.
package gpg

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// GpgKey describes a single secret key known to the local gpg keyring.
type GpgKey struct {
	// KeyID is the long-form key id, e.g. "F49BE957CD553B1C".
	KeyID string
	// Type is the colon record type of the primary record, e.g. "sec".
	Type string
	// Created is the key creation time.
	Created time.Time
	// Expires is the key expiry time. Zero value means "never expires".
	Expires time.Time
	// UserId is the primary user id string, e.g.
	// "Leonid Golikhin (comment) <user@example.com>".
	UserId string
	// Fingerprint is the full 40-char fingerprint.
	Fingerprint string
}

// DetectExistingKeys lists all secret keys in the current user's gpg
// keyring by parsing 'gpg --list-secret-keys --keyid-format=long
// --with-colons'. Returns an empty (non-nil) slice if no keys exist.
func DetectExistingKeys() ([]GpgKey, error) {
	cmd := exec.Command("gpg",
		"--list-secret-keys",
		"--keyid-format=long",
		"--with-colons",
		"--with-fingerprint",
	)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &bytes.Buffer{}
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("gpg --list-secret-keys failed: %w", err)
	}
	return parseColonOutput(out.Bytes())
}

// DetectKeyForEmail returns the first secret key whose primary user id
// contains "<email>" in angle brackets. Returns (nil, nil) if no key
// matches — callers should distinguish this from an error.
func DetectKeyForEmail(email string) (*GpgKey, error) {
	keys, err := DetectExistingKeys()
	if err != nil {
		return nil, err
	}
	needle := "<" + email + ">"
	for i := range keys {
		if strings.Contains(keys[i].UserId, needle) {
			return &keys[i], nil
		}
	}
	return nil, nil
}

// parseColonOutput parses the colon-separated output of
// 'gpg --list-secret-keys --with-colons'. The format is documented in
// the gpg DETAILS file: one record per line, fields separated by ':',
// record type in field 0. We care about 'sec' (primary secret key),
// 'fpr' (fingerprint of the preceding record), and 'uid' (user id).
//
// Field reference (subset):
//
//	sec: <trust>:<len>:<algo>:<keyid>:<created>:<expires>:...
//	fpr: :::::::<fingerprint>:
//	uid: <state>::::<created>:<expires>:...:<uid-string>:...
func parseColonOutput(data []byte) ([]GpgKey, error) {
	var keys []GpgKey
	var current *GpgKey

	sc := bufio.NewScanner(bytes.NewReader(data))
	// gpg uid strings can be long; raise the per-line limit well above
	// the default 64 KiB.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 1 {
			continue
		}
		switch fields[0] {
		case "sec", "ssc":
			// Flush the previous key.
			if current != nil {
				keys = append(keys, *current)
			}
			current = &GpgKey{Type: fields[0]}
			if len(fields) > 4 {
				current.KeyID = fields[4]
			}
			if len(fields) > 5 {
				current.Created = parseUnix(fields[5])
			}
			if len(fields) > 6 {
				current.Expires = parseUnix(fields[6])
			}
		case "fpr":
			// The fingerprint line follows the record it describes.
			// Field 9 holds the fingerprint for sec/ssc/uid records.
			if current != nil && current.Fingerprint == "" && len(fields) > 9 {
				current.Fingerprint = fields[9]
			}
		case "uid":
			// Take the first (primary) uid only — subsequent uids on
			// the same key are aliases we don't surface in the table.
			if current != nil && current.UserId == "" && len(fields) > 9 {
				current.UserId = fields[9]
			}
		default:
			// ssb, grp, rvk, etc. — not relevant to secret-key listing.
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("parse gpg colon output: %w", err)
	}
	if current != nil {
		keys = append(keys, *current)
	}
	return keys, nil
}

// parseUnix parses a unix timestamp string from the gpg colon format.
// Returns the zero time on empty input or parse error.
func parseUnix(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	ts, err := strconv.ParseInt(s, 10, 64)
	if err != nil || ts <= 0 {
		return time.Time{}
	}
	return time.Unix(ts, 0).UTC()
}