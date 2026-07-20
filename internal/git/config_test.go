package git

import (
	"strings"
	"testing"
)

// TestValidateHexKeyID_AcceptsValidHex verifies that valid hex key ids
// (short, long, fingerprint, with/without 0x prefix, mixed case) pass
// validation. This mirrors gpg.ValidateKeyID's acceptance set — the two
// copies must agree so a key id accepted by one is accepted by the
// other.
func TestValidateHexKeyID_AcceptsValidHex(t *testing.T) {
	good := []string{
		"F49BE957CD553B1C",
		"0xF49BE957CD553B1C",
		"0xf49be957cd553b1c",
		"F49BE957CD553B1CF49BE957CD553B1CF49BE95", // 40-char fingerprint (uppercase)
		"0x1234",
		"ABCD",
		"abcdef0123456789",
	}
	for _, k := range good {
		if err := validateHexKeyID(k); err != nil {
			t.Errorf("validateHexKeyID(%q) must accept a hex key id, got: %v", k, err)
		}
	}
}

// TestValidateHexKeyID_RejectsEmpty verifies an empty key id is
// rejected before any git command is run — the most common misuse.
func TestValidateHexKeyID_RejectsEmpty(t *testing.T) {
	if err := validateHexKeyID(""); err == nil {
		t.Fatal("validateHexKeyID(\"\") must return an error")
	}
}

// TestValidateHexKeyID_RejectsNonHex verifies that a key id with
// non-hex characters (which could be an injection attempt or a typo)
// is rejected. exec.Command does not invoke a shell, so this is
// defence-in-depth, not a shell-injection guard.
func TestValidateHexKeyID_RejectsNonHex(t *testing.T) {
	bad := []string{
		"ABCD; rm -rf ~",
		"ABCD $(whoami)",
		"ABCD|cat /etc/passwd",
		"not-a-key-id",
		"ABCDEF xyz",
		"1234-5678",
		"  ABCDEF",
		"ABCDEF ",
		"0x",
	}
	for _, k := range bad {
		if err := validateHexKeyID(k); err == nil {
			t.Errorf("validateHexKeyID(%q) must reject non-hex, got nil", k)
		}
	}
}

// TestValidateHexKeyID_RejectsTooLong verifies that a key id longer
// than 40 hex chars (the max fingerprint length) is rejected.
func TestValidateHexKeyID_RejectsTooLong(t *testing.T) {
	long := strings.Repeat("a", 41)
	if err := validateHexKeyID(long); err == nil {
		t.Errorf("validateHexKeyID(%q...) must reject >40 chars, got nil", long[:8])
	}
}

// TestConfigKeysToSet_ReturnsSixEntries verifies the pure builder
// returns exactly the six keys mandated by the M5 spec, in the
// expected order, with the expected values derived from opts.
func TestConfigKeysToSet_ReturnsSixEntries(t *testing.T) {
	opts := ConfigOptions{
		KeyID:  "F49BE957CD553B1C",
		Name:   "Leonid Golikhin",
		Email:  "korrnals@example.com",
		Global: false,
	}
	entries := configKeysToSet(opts)

	want := []struct {
		key, value string
	}{
		{"user.name", "Leonid Golikhin"},
		{"user.email", "korrnals@example.com"},
		{"user.signingkey", "F49BE957CD553B1C"},
		{"commit.gpgsign", "true"},
		{"gpg.format", "openpgp"},
		{"tag.gpgsign", "true"},
	}

	if len(entries) != len(want) {
		t.Fatalf("configKeysToSet returned %d entries, want %d", len(entries), len(want))
	}
	for i, w := range want {
		if entries[i].key != w.key || entries[i].value != w.value {
			t.Errorf("entry %d = {%q: %q}, want {%q: %q}",
				i, entries[i].key, entries[i].value, w.key, w.value)
		}
	}
}

// TestConfigKeysToSet_BooleansAreLiteralTrue verifies the two boolean
// keys (commit.gpgsign, tag.gpgsign) are always the literal string
// "true", regardless of opts — there is no "disable" path via this
// function. gpg.format is always "openpgp" (this tool only supports
// OpenPGP signing, per the non-goals in DEVELOPMENT.md).
func TestConfigKeysToSet_BooleansAreLiteralTrue(t *testing.T) {
	opts := ConfigOptions{KeyID: "ABCD", Name: "X", Email: "x@y.z"}
	entries := configKeysToSet(opts)
	for _, e := range entries {
		switch e.key {
		case "commit.gpgsign", "tag.gpgsign":
			if e.value != "true" {
				t.Errorf("%s = %q, want \"true\"", e.key, e.value)
			}
		case "gpg.format":
			if e.value != "openpgp" {
				t.Errorf("gpg.format = %q, want \"openpgp\"", e.value)
			}
		}
	}
}

// TestApplyGitConfig_EmptyKeyIDReturnsError verifies that an empty
// KeyID is rejected before any git command is run. No git process is
// spawned — validation happens first.
func TestApplyGitConfig_EmptyKeyIDReturnsError(t *testing.T) {
	opts := ConfigOptions{
		KeyID: "",
		Name:  "Test User",
		Email: "test@example.com",
	}
	err := ApplyGitConfig(opts)
	if err == nil {
		t.Fatal("ApplyGitConfig with empty KeyID must return an error before shelling out")
	}
	if !strings.Contains(err.Error(), "key id") {
		t.Errorf("error should mention key id, got: %v", err)
	}
}

// TestApplyGitConfig_InvalidKeyIDReturnsError verifies a non-hex
// KeyID is rejected before any git command is run.
func TestApplyGitConfig_InvalidKeyIDReturnsError(t *testing.T) {
	opts := ConfigOptions{
		KeyID: "not-a-key-id",
		Name:  "Test User",
		Email: "test@example.com",
	}
	err := ApplyGitConfig(opts)
	if err == nil {
		t.Fatal("ApplyGitConfig with non-hex KeyID must return an error before shelling out")
	}
	if !strings.Contains(err.Error(), "key id") {
		t.Errorf("error should mention key id, got: %v", err)
	}
}

// TestGitConfigScope verifies the scope-flag helper returns the right
// flag slice for the two scopes. Empty (local) means git config uses
// its default — the local repo config when run inside a repo.
func TestGitConfigScope(t *testing.T) {
	if got := gitConfigScope(false); len(got) != 0 {
		t.Errorf("gitConfigScope(false) = %v, want empty (local default)", got)
	}
	if got := gitConfigScope(true); len(got) != 1 || got[0] != "--global" {
		t.Errorf("gitConfigScope(true) = %v, want [\"--global\"]", got)
	}
}
