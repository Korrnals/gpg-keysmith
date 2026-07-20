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

// --- ApplyGitConfig / DetectSigningKey happy-path tests (mocked exec) ---
//
// runGitConfigGet and runGitConfigSet are package-level function
// variables so tests can override them to return canned values without
// shelling out to real git. These tests exercise the resolution + write
// logic of ApplyGitConfig and the read path of DetectSigningKey.

// saveGitFns snapshots runGitConfigGet/Set and returns a restore
// closure. Tests MUST defer it so mocks do not leak.
func saveGitFns() func() {
	savedGet := runGitConfigGet
	savedSet := runGitConfigSet
	return func() {
		runGitConfigGet = savedGet
		runGitConfigSet = savedSet
	}
}

// TestApplyGitConfig_HappyPath verifies ApplyGitConfig writes all six
// signing config keys when Name, Email, and a valid KeyID are supplied.
// runGitConfigGet is mocked to return empty (so the flag values are
// used, not existing config) and runGitConfigSet records every write
// into a map so we can assert all six keys land with the right values.
func TestApplyGitConfig_HappyPath(t *testing.T) {
	defer saveGitFns()()

	// runGitConfigGet is only called when Name or Email is empty. We
	// pass both, so it should NOT be invoked — wire it to fail loudly.
	runGitConfigGet = func(bool, string) (string, error) {
		t.Error("runGitConfigGet should not be called when Name and Email are supplied")
		return "", nil
	}

	written := make(map[string]string)
	runGitConfigSet = func(global bool, key, value string) error {
		if global {
			t.Errorf("set should use local scope (global=false), got global=true for %s", key)
		}
		written[key] = value
		return nil
	}

	opts := ConfigOptions{
		KeyID:  "F49BE957CD553B1C",
		Name:   "Leonid Golikhin",
		Email:  "korrnals@example.com",
		Global: false,
	}
	if err := ApplyGitConfig(opts); err != nil {
		t.Fatalf("ApplyGitConfig happy path: %v", err)
	}

	want := map[string]string{
		"user.name":       "Leonid Golikhin",
		"user.email":      "korrnals@example.com",
		"user.signingkey": "F49BE957CD553B1C",
		"commit.gpgsign":  "true",
		"gpg.format":      "openpgp",
		"tag.gpgsign":     "true",
	}
	if len(written) != len(want) {
		t.Fatalf("wrote %d keys, want %d: %v", len(written), len(want), written)
	}
	for k, w := range want {
		if written[k] != w {
			t.Errorf("written[%q] = %q, want %q", k, written[k], w)
		}
	}
}

// TestApplyGitConfig_ResolvesNameFromExisting verifies that when Name
// is empty, ApplyGitConfig reads the existing user.name from git
// config (via runGitConfigGet) and uses it. Email is supplied so only
// the Name resolution path is exercised.
func TestApplyGitConfig_ResolvesNameFromExisting(t *testing.T) {
	defer saveGitFns()()

	getCalls := 0
	runGitConfigGet = func(global bool, key string) (string, error) {
		getCalls++
		if key == "user.name" {
			return "Existing Name", nil
		}
		// user.email should not be queried because Email is supplied.
		t.Errorf("runGitConfigGet queried unexpected key %q", key)
		return "", nil
	}

	written := make(map[string]string)
	runGitConfigSet = func(bool, string, string) error { return nil }
	_ = written

	opts := ConfigOptions{
		KeyID: "ABCD1234DEF05678",
		Name:  "", // empty → resolve from existing
		Email: "resolved@example.com",
	}
	if err := ApplyGitConfig(opts); err != nil {
		t.Fatalf("ApplyGitConfig resolve-name: %v", err)
	}
	if getCalls != 1 {
		t.Errorf("runGitConfigGet called %d times, want 1 (user.name)", getCalls)
	}
}

// TestApplyGitConfig_MissingNameErrors verifies that when Name is
// empty AND the existing user.name is also empty, ApplyGitConfig
// returns a clear error instead of silently writing an empty name.
func TestApplyGitConfig_MissingNameErrors(t *testing.T) {
	defer saveGitFns()()
	runGitConfigGet = func(bool, string) (string, error) { return "", nil }
	runGitConfigSet = func(bool, string, string) error {
		t.Error("runGitConfigSet should not be called when name resolution fails")
		return nil
	}
	opts := ConfigOptions{
		KeyID: "ABCD1234DEF05678",
		Name:  "",
		Email: "x@y.z",
	}
	err := ApplyGitConfig(opts)
	if err == nil {
		t.Fatal("ApplyGitConfig with missing name must error")
	}
	if !strings.Contains(err.Error(), "user.name") {
		t.Errorf("error should mention user.name, got: %v", err)
	}
}

// TestApplyGitConfig_MissingEmailErrors verifies the email resolution
// guard. Name is supplied so only the email path is exercised.
func TestApplyGitConfig_MissingEmailErrors(t *testing.T) {
	defer saveGitFns()()
	runGitConfigGet = func(bool, string) (string, error) { return "", nil }
	runGitConfigSet = func(bool, string, string) error {
		t.Error("runGitConfigSet should not be called when email resolution fails")
		return nil
	}
	opts := ConfigOptions{
		KeyID: "ABCD1234DEF05678",
		Name:  "Has Name",
		Email: "",
	}
	err := ApplyGitConfig(opts)
	if err == nil {
		t.Fatal("ApplyGitConfig with missing email must error")
	}
	if !strings.Contains(err.Error(), "user.email") {
		t.Errorf("error should mention user.email, got: %v", err)
	}
}

// TestApplyGitConfig_GetErrorPropagates verifies a git config --get
// failure (not the "not found" empty-string case, but a real git
// error) is propagated as a wrapped error rather than swallowed.
func TestApplyGitConfig_GetErrorPropagates(t *testing.T) {
	defer saveGitFns()()
	runGitConfigGet = func(bool, string) (string, error) {
		return "", errForTest("git binary missing")
	}
	runGitConfigSet = func(bool, string, string) error { return nil }
	opts := ConfigOptions{
		KeyID: "ABCD1234DEF05678",
		Name:  "",
		Email: "x@y.z",
	}
	err := ApplyGitConfig(opts)
	if err == nil {
		t.Fatal("ApplyGitConfig must propagate a get error")
	}
	if !strings.Contains(err.Error(), "read existing user.name") {
		t.Errorf("error should wrap the read-existing-user.name failure, got: %v", err)
	}
}

// TestApplyGitConfig_SetErrorPropagates verifies a git config <key>
// <value> failure is propagated as a wrapped error and the run stops
// (no further keys are written after the failure).
func TestApplyGitConfig_SetErrorPropagates(t *testing.T) {
	defer saveGitFns()()
	runGitConfigGet = func(bool, string) (string, error) { return "", nil }

	setCalls := 0
	runGitConfigSet = func(bool, string, string) error {
		setCalls++
		return errForTest("write permission denied")
	}
	opts := ConfigOptions{
		KeyID: "ABCD1234DEF05678",
		Name:  "Name",
		Email: "x@y.z",
	}
	err := ApplyGitConfig(opts)
	if err == nil {
		t.Fatal("ApplyGitConfig must propagate a set error")
	}
	if setCalls != 1 {
		t.Errorf("runGitConfigSet called %d times, want exactly 1 (stop on first failure)", setCalls)
	}
}

// TestDetectSigningKey_HappyPath verifies DetectSigningKey returns the
// signing key id read from git config via the mocked runGitConfigGet.
func TestDetectSigningKey_HappyPath(t *testing.T) {
	defer saveGitFns()()
	runGitConfigGet = func(global bool, key string) (string, error) {
		if global {
			t.Errorf("DetectSigningKey(false) should not pass global=true, got key=%q", key)
		}
		if key != "user.signingkey" {
			t.Errorf("DetectSigningKey queried %q, want user.signingkey", key)
		}
		return "SIGN0000KEY00000", nil
	}
	got, err := DetectSigningKey(false)
	if err != nil {
		t.Fatalf("DetectSigningKey: %v", err)
	}
	if got != "SIGN0000KEY00000" {
		t.Errorf("DetectSigningKey = %q, want SIGN0000KEY00000", got)
	}
}

// TestDetectSigningKey_NotSetReturnsEmpty verifies that a missing
// user.signingkey (the "not found" empty-string case, not an error)
// returns ("", nil) — the caller decides what to do.
func TestDetectSigningKey_NotSetReturnsEmpty(t *testing.T) {
	defer saveGitFns()()
	runGitConfigGet = func(bool, string) (string, error) { return "", nil }
	got, err := DetectSigningKey(true)
	if err != nil {
		t.Fatalf("DetectSigningKey on missing key returned error: %v", err)
	}
	if got != "" {
		t.Errorf("DetectSigningKey on missing key = %q, want empty", got)
	}
}

// errForTest is a tiny sentinel error used by the git config tests to
// simulate git failures. Local to avoid importing the wizard package.
type gitTestError struct{ msg string }

func (e *gitTestError) Error() string { return e.msg }

func errForTest(msg string) error { return &gitTestError{msg: msg} }
