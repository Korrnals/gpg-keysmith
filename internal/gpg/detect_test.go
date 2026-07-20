package gpg

import (
	"testing"
	"time"
)

// --- parseUnix tests ----------------------------------------------------

// TestParseUnix_TableDriven verifies parseUnix handles empty input,
// invalid input, zero/negative timestamps, and valid unix timestamps.
// Returns the zero time for empty/invalid/non-positive input.
func TestParseUnix_TableDriven(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want time.Time
	}{
		{name: "empty", in: "", want: time.Time{}},
		{name: "non-numeric", in: "not-a-timestamp", want: time.Time{}},
		{name: "float-not-int", in: "1.5", want: time.Time{}},
		{name: "zero", in: "0", want: time.Time{}},
		{name: "negative", in: "-100", want: time.Time{}},
		{name: "valid-epoch", in: "0", want: time.Time{}},
		{name: "valid-timestamp", in: "1609459200", want: time.Unix(1609459200, 0).UTC()},
		{name: "large-timestamp", in: "2147483647", want: time.Unix(2147483647, 0).UTC()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseUnix(tc.in)
			if !got.Equal(tc.want) {
				t.Errorf("parseUnix(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// --- parseColonOutput tests ---------------------------------------------

// colonFixture is a representative slice of 'gpg --list-secret-keys
// --with-colons --with-fingerprint' output. The field layout follows
// the gpg DETAILS file:
//
//	sec: <trust>:<len>:<algo>:<keyid>:<created>:<expires>:...
//	fpr: :::::::<fingerprint>:
//	uid: <state>::::<created>:<expires>:...:<uid-string>:...
const colonFixtureSingle = `sec:u:4096:1:F49BE957CD553B1C:1609459200:1735689600:::::RSA::: ++++++++++
fpr:::::::::F49BE957CD553B1CF49BE957CD553B1CF49BE957:
uid:u::::1609459200:1735689600:::Leonid Golikhin (keysmith test) <user@example.com>::::::::::0:
ssb:u:4096:1:AAAAAAAAAAAAAAAA:1609459200:1735689600:::::RSA::: ++++++++++
fpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:
`

// TestParseColonOutput_SingleKey verifies a fixture with one sec
// record, its fpr, and a uid produces a single GpgKey with the
// expected KeyID, Type, Fingerprint, UserId, Created, Expires.
func TestParseColonOutput_SingleKey(t *testing.T) {
	keys, err := parseColonOutput([]byte(colonFixtureSingle))
	if err != nil {
		t.Fatalf("parseColonOutput: unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1 (ssb is not a primary record)", len(keys))
	}

	want := GpgKey{
		KeyID:       "F49BE957CD553B1C",
		Type:        "sec",
		Created:     time.Unix(1609459200, 0).UTC(),
		Expires:     time.Unix(1735689600, 0).UTC(),
		UserId:      "Leonid Golikhin (keysmith test) <user@example.com>",
		Fingerprint: "F49BE957CD553B1CF49BE957CD553B1CF49BE957",
	}
	got := keys[0]
	if got.KeyID != want.KeyID {
		t.Errorf("KeyID = %q, want %q", got.KeyID, want.KeyID)
	}
	if got.Type != want.Type {
		t.Errorf("Type = %q, want %q", got.Type, want.Type)
	}
	if !got.Created.Equal(want.Created) {
		t.Errorf("Created = %v, want %v", got.Created, want.Created)
	}
	if !got.Expires.Equal(want.Expires) {
		t.Errorf("Expires = %v, want %v", got.Expires, want.Expires)
	}
	if got.UserId != want.UserId {
		t.Errorf("UserId = %q, want %q", got.UserId, want.UserId)
	}
	if got.Fingerprint != want.Fingerprint {
		t.Errorf("Fingerprint = %q, want %q", got.Fingerprint, want.Fingerprint)
	}
}

// colonFixtureTwoKeys contains two primary sec records with their
// fingerprints and uids, plus a subkey (ssb) to verify the parser
// flushes the first key correctly when the second sec appears.
const colonFixtureTwoKeys = `sec:u:4096:1:F49BE957CD553B1C:1609459200:1735689600:::::RSA:::
fpr:::::::::F49BE957CD553B1CF49BE957CD553B1CF49BE957:
uid:u::::1609459200:1735689600:::Alice <alice@example.com>::::::::::0:
ssb:u:4096:1:BBBBBBBBBBBBBBBB:1609459200:1735689600:::::RSA:::
fpr:::::::::BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:
sec:u:2048:1:AAAAAAAAAAAAAAAA:1500000000:0:::::RSA:::
fpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:
uid:u::::1500000000:0:::Bob (work) <bob@example.com>::::::::::0:
`

// TestParseColonOutput_MultipleKeys verifies the parser flushes the
// first key when the second sec record appears, and that ssb records
// are not treated as primary keys.
func TestParseColonOutput_MultipleKeys(t *testing.T) {
	keys, err := parseColonOutput([]byte(colonFixtureTwoKeys))
	if err != nil {
		t.Fatalf("parseColonOutput: unexpected error: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2 (ssb must not be a primary key)", len(keys))
	}

	// First key: Alice, expires 2025-01-01.
	if keys[0].KeyID != "F49BE957CD553B1C" {
		t.Errorf("keys[0].KeyID = %q, want F49BE957CD553B1C", keys[0].KeyID)
	}
	if keys[0].UserId != "Alice <alice@example.com>" {
		t.Errorf("keys[0].UserId = %q, want Alice", keys[0].UserId)
	}
	if keys[0].Fingerprint != "F49BE957CD553B1CF49BE957CD553B1CF49BE957" {
		t.Errorf("keys[0].Fingerprint = %q", keys[0].Fingerprint)
	}
	if !keys[0].Expires.Equal(time.Unix(1735689600, 0).UTC()) {
		t.Errorf("keys[0].Expires = %v, want 2025-01-01", keys[0].Expires)
	}

	// Second key: Bob, never expires (Expires zero).
	if keys[1].KeyID != "AAAAAAAAAAAAAAAA" {
		t.Errorf("keys[1].KeyID = %q, want AAAAAAAAAAAAAAAA", keys[1].KeyID)
	}
	if keys[1].UserId != "Bob (work) <bob@example.com>" {
		t.Errorf("keys[1].UserId = %q, want Bob", keys[1].UserId)
	}
	if keys[1].Fingerprint != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Errorf("keys[1].Fingerprint = %q", keys[1].Fingerprint)
	}
	if !keys[1].Expires.IsZero() {
		t.Errorf("keys[1].Expires = %v, want zero (never expires)", keys[1].Expires)
	}
}

// TestParseColonOutput_Empty verifies empty input returns an empty
// (non-nil) slice with no error.
func TestParseColonOutput_Empty(t *testing.T) {
	keys, err := parseColonOutput(nil)
	if err != nil {
		t.Fatalf("parseColonOutput(nil): unexpected error: %v", err)
	}
	// A nil or zero-length slice is acceptable — production code
	// only checks len(keys) == 0. Assert length, not non-nil, so
	// the test does not over-constrain the implementation.
	if len(keys) != 0 {
		t.Errorf("parseColonOutput(nil) returned %d keys, want 0", len(keys))
	}

	// A whitespace-only input should also yield an empty slice.
	keys, err = parseColonOutput([]byte("\n\n  \n"))
	if err != nil {
		t.Fatalf("parseColonOutput whitespace: unexpected error: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("parseColonOutput whitespace returned %d keys, want 0", len(keys))
	}
}

// TestParseColonOutput_OnlySubkey verifies a fixture with only an ssb
// (subkey) record and no primary sec record produces a single key —
// the ssb/ssc branch of the parser. This guards against regressions
// in the switch that handles secondary secret subkeys.
func TestParseColonOutput_OnlySubkey(t *testing.T) {
	fixture := []byte("ssc:u:2048:1:CCCCCCCCCCCCCCCC:1609459200:0:::::RSA:::\n" +
		"fpr:::::::::CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC:\n" +
		"uid:u::::1609459200:0:::Subkey User <sub@example.com>::::::::::0:\n")
	keys, err := parseColonOutput(fixture)
	if err != nil {
		t.Fatalf("parseColonOutput: unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	if keys[0].Type != "ssc" {
		t.Errorf("Type = %q, want ssc", keys[0].Type)
	}
	if keys[0].KeyID != "CCCCCCCCCCCCCCCC" {
		t.Errorf("KeyID = %q, want CCCCCCCCCCCCCCCC", keys[0].KeyID)
	}
}

// TestParseColonOutput_TruncatedLines verifies the parser does not
// panic on records shorter than the expected field count. A sec
// record with only 3 fields should not crash; it just leaves KeyID
// and timestamps at zero values.
func TestParseColonOutput_TruncatedLines(t *testing.T) {
	fixture := []byte("sec:u:4096\n") // only 3 fields, no keyid/created/expires
	keys, err := parseColonOutput(fixture)
	if err != nil {
		t.Fatalf("parseColonOutput truncated: unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	if keys[0].KeyID != "" {
		t.Errorf("KeyID = %q, want empty (field missing)", keys[0].KeyID)
	}
	if !keys[0].Created.IsZero() {
		t.Errorf("Created = %v, want zero (field missing)", keys[0].Created)
	}
}

// TestParseColonOutput_TakesOnlyFirstUid verifies the parser takes
// only the first (primary) uid on a key and ignores subsequent uid
// records — the table view surfaces only the primary identity.
func TestParseColonOutput_TakesOnlyFirstUid(t *testing.T) {
	fixture := []byte("sec:u:4096:1:F49BE957CD553B1C:1609459200:0:::::RSA:::\n" +
		"fpr:::::::::F49BE957CD553B1CF49BE957CD553B1CF49BE957:\n" +
		"uid:u::::1609459200:0:::Primary <primary@example.com>::::::::::0:\n" +
		"uid:u::::1609459200:0:::Alias <alias@example.com>::::::::::0:\n")
	keys, err := parseColonOutput(fixture)
	if err != nil {
		t.Fatalf("parseColonOutput: unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	if keys[0].UserId != "Primary <primary@example.com>" {
		t.Errorf("UserId = %q, want primary uid", keys[0].UserId)
	}
}

// TestParseColonOutput_TakesOnlyFirstFingerprint verifies the parser
// takes only the first fpr record for a key — a second fpr (e.g. from
// a subkey appearing before the next sec) must not overwrite the
// primary fingerprint.
func TestParseColonOutput_TakesOnlyFirstFingerprint(t *testing.T) {
	fixture := []byte("sec:u:4096:1:F49BE957CD553B1C:1609459200:0:::::RSA:::\n" +
		"fpr:::::::::PRIMARYFINGERPRINT0PRIMARYFINGERPRINT0PRI:\n" +
		"uid:u::::1609459200:0:::User <user@example.com>::::::::::0:\n" +
		"ssb:u:4096:1:BBBBBBBBBBBBBBBB:1609459200:0:::::RSA:::\n" +
		"fpr:::::::::SUBKEYFINGERPRINT0SUBKEYFINGERPRINT0SUBK:\n")
	keys, err := parseColonOutput(fixture)
	if err != nil {
		t.Fatalf("parseColonOutput: unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1 (ssb flushed only at next sec)", len(keys))
	}
	if keys[0].Fingerprint != "PRIMARYFINGERPRINT0PRIMARYFINGERPRINT0PRI" {
		t.Errorf("Fingerprint = %q, want primary fpr (not overwritten by subkey fpr)",
			keys[0].Fingerprint)
	}
}
