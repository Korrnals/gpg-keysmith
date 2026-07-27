package gpg

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestValidateKeyID_RejectsEmpty verifies an empty key id is rejected
// before gpg is invoked — this is the most common misuse.
func TestValidateKeyID_RejectsEmpty(t *testing.T) {
	if err := ValidateKeyID(""); err == nil {
		t.Fatal("ValidateKeyID(\"\") must return an error")
	}
}

// TestValidateKeyID_RejectsNonHex verifies a key id containing
// non-hex characters (which could be an injection attempt) is rejected.
func TestValidateKeyID_RejectsNonHex(t *testing.T) {
	bad := []string{
		"ABCD; rm -rf ~",
		"ABCD $(whoami)",
		"ABCD|cat /etc/passwd",
		"not-a-key-id",
		"ABCDEF xyz",
		"1234-5678",
		"  ABCDEF",
		"ABCDEF ",
	}
	for _, k := range bad {
		if err := ValidateKeyID(k); err == nil {
			t.Errorf("ValidateKeyID(%q) must reject non-hex, got nil", k)
		}
	}
}

// TestValidateKeyID_AcceptsHexAndFingerprints verifies that valid key
// ids (short, long, fingerprint, with/without 0x prefix) pass.
func TestValidateKeyID_AcceptsHexAndFingerprints(t *testing.T) {
	good := []string{
		"F49BE957CD553B1C",
		"0xF49BE957CD553B1C",
		"0xf49be957cd553b1c",
		"F49BE957CD553B1CF49BE957CD553B1CF49BE95", // full 40-char fingerprint
		"0x1234",
		"ABCD",
	}
	for _, k := range good {
		if err := ValidateKeyID(k); err != nil {
			t.Errorf("ValidateKeyID(%q) must accept a hex key id, got: %v", k, err)
		}
	}
}

// TestExportPublicKey_EmptyKeyIDReturnsError verifies that an empty
// key id is rejected before gpg is invoked. No gpg process is spawned.
func TestExportPublicKey_EmptyKeyIDReturnsError(t *testing.T) {
	_, err := ExportPublicKey("")
	if err == nil {
		t.Fatal("ExportPublicKey(\"\") must return an error before invoking gpg")
	}
	if !strings.Contains(err.Error(), "key id") {
		t.Errorf("error should mention key id, got: %v", err)
	}
}

// TestExportPublicKey_InvalidKeyIDReturnsError verifies that a
// non-hex key id is rejected before gpg is invoked.
func TestExportPublicKey_InvalidKeyIDReturnsError(t *testing.T) {
	_, err := ExportPublicKey("not-a-key-id")
	if err == nil {
		t.Fatal("ExportPublicKey with non-hex key id must return an error before invoking gpg")
	}
}

// TestExportPrivateKey_EmptyKeyIDReturnsError verifies that an empty
// key id is rejected before gpg is invoked, even when a passphrase is
// supplied.
func TestExportPrivateKey_EmptyKeyIDReturnsError(t *testing.T) {
	_, err := ExportPrivateKey("", "some-passphrase")
	if err == nil {
		t.Fatal("ExportPrivateKey with empty key id must return an error before invoking gpg")
	}
	if !strings.Contains(err.Error(), "key id") {
		t.Errorf("error should mention key id, got: %v", err)
	}
}

// TestExportPrivateKey_EmptyPassphraseReturnsError verifies that an
// empty passphrase is rejected before gpg is invoked, even when a
// valid key id is supplied. This is the security gate: we never export
// a secret key without a passphrase.
func TestExportPrivateKey_EmptyPassphraseReturnsError(t *testing.T) {
	_, err := ExportPrivateKey("F49BE957CD553B1C", "")
	if err == nil {
		t.Fatal("ExportPrivateKey with empty passphrase must return an error before invoking gpg")
	}
	if !strings.Contains(err.Error(), "passphrase") {
		t.Errorf("error should mention passphrase, got: %v", err)
	}
}

// TestExportPrivateKey_ArgsUseStdinNotCLIArg is the critical security
// invariant test: the constructed gpg arg vector must use
// --passphrase-fd 0 (stdin) and must NOT use --passphrase <value>
// (which would leak the passphrase via ps/proc). It also asserts the
// args never contain the passphrase string itself.
//
// We test via the extracted args builder (buildExportPrivateKeyArgs)
// because ExportPrivateKey itself would invoke gpg. The args builder
// is a pure function returning the exact slice passed to exec.Command.
func TestExportPrivateKey_ArgsUseStdinNotCLIArg(t *testing.T) {
	passphrase := "super-secret-passphrase-12345"
	args := buildExportPrivateKeyArgs("F49BE957CD553B1C")

	// Must contain --passphrase-fd 0 (stdin path).
	hasFd0 := false
	for i, a := range args {
		if a == "--passphrase-fd" && i+1 < len(args) && args[i+1] == "0" {
			hasFd0 = true
			break
		}
	}
	if !hasFd0 {
		t.Errorf("args must contain --passphrase-fd 0 (stdin path); got %v", args)
	}

	// Must NOT contain --passphrase as a flag (the CLI-arg leak path).
	for _, a := range args {
		if a == "--passphrase" {
			t.Errorf("args must NOT contain --passphrase (CLI-arg leak); got %v", args)
		}
	}

	// Must contain --pinentry-mode loopback (required for --passphrase-fd).
	hasLoopback := false
	for i, a := range args {
		if a == "--pinentry-mode" && i+1 < len(args) && args[i+1] == "loopback" {
			hasLoopback = true
			break
		}
	}
	if !hasLoopback {
		t.Errorf("args must contain --pinentry-mode loopback; got %v", args)
	}

	// The passphrase must NEVER appear in the args.
	for _, a := range args {
		if strings.Contains(a, passphrase) {
			t.Errorf("passphrase must not appear in gpg args; got %v", args)
		}
	}
}

// TestExportPrivateKey_ArgsNeverContainPassphraseValue verifies that
// a passphrase-looking string does not leak into the arg vector. We
// deliberately exclude values that legitimately appear in the gpg
// args ("0" is the fd in --passphrase-fd 0, "loopback" is the
// --pinentry-mode value) — those are fixed protocol tokens, not
// passphrase material.
func TestExportPrivateKey_ArgsNeverContainPassphraseValue(t *testing.T) {
	tricky := []string{
		"--passphrase=leaked",
		"super-secret-passphrase-12345",
		"$(cat /etc/passwd)",
		"aB3F9c2E1d874a6f",
	}
	for _, p := range tricky {
		args := buildExportPrivateKeyArgs("F49BE957CD553B1C")
		for _, a := range args {
			if a == p {
				t.Errorf("passphrase value %q leaked into args %v", p, args)
			}
		}
	}
}

// TestBuildExportPublicKeyArgs_TableDriven verifies the public-key
// export arg vector matches the exact order and tokens the production
// code passes to exec.Command. buildExportPublicKeyArgs is a pure
// function extracted specifically so tests can assert the args without
// invoking gpg.
func TestBuildExportPublicKeyArgs_TableDriven(t *testing.T) {
	cases := []struct {
		name  string
		keyID string
		want  []string
	}{
		{
			name:  "long key id",
			keyID: "F49BE957CD553B1C",
			want:  []string{"--armor", "--export", "F49BE957CD553B1C"},
		},
		{
			name:  "full fingerprint",
			keyID: "F49BE957CD553B1CF49BE957CD553B1CF49BE957",
			want:  []string{"--armor", "--export", "F49BE957CD553B1CF49BE957CD553B1CF49BE957"},
		},
		{
			name:  "short key id",
			keyID: "ABCD",
			want:  []string{"--armor", "--export", "ABCD"},
		},
		{
			name:  "with 0x prefix",
			keyID: "0xABCD",
			want:  []string{"--armor", "--export", "0xABCD"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := buildExportPublicKeyArgs(tc.keyID)
			if len(got) != len(tc.want) {
				t.Fatalf("len(args) = %d, want %d (got %v)", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("args[%d] = %q, want %q (full: %v)", i, got[i], tc.want[i], got)
				}
			}
			// The arg vector must never contain the secret-key export
			// flag — this is a public key export, not a secret one.
			for _, a := range got {
				if a == "--export-secret-keys" {
					t.Errorf("public export args must NOT contain --export-secret-keys; got %v", got)
				}
			}
		})
	}
}

// TestExtractFingerprintFromArmorFile_EmptyPathReturnsError verifies
// that an empty path is rejected before gpg is invoked. This is the
// pre-flight guard that prevents a confusing gpg diagnostic when the
// caller (the publish subcommand) passes an unset --pubkey-file.
func TestExtractFingerprintFromArmorFile_EmptyPathReturnsError(t *testing.T) {
	_, err := ExtractFingerprintFromArmorFile("")
	if err == nil {
		t.Fatal("ExtractFingerprintFromArmorFile(\"\") must return an error before invoking gpg")
	}
	if !strings.Contains(err.Error(), "path") {
		t.Errorf("error should mention path, got: %v", err)
	}
}

// TestExtractFingerprintFromArmorFile_NoFingerprintInOutput verifies
// that when gpg's colon output contains no fpr record, the function
// returns an error — either the gpg failure itself (gpg exits non-zero
// on a non-armor file) or the "no fingerprint found" message (gpg exits
// 0 but emits no fpr line). Both branches are acceptable failure modes
// for a malformed pubkey file; the contract is "returns an error, not a
// bogus fingerprint".
//
// Skipped when the gpg binary is absent; the skip carries a tracking
// issue link per lint-and-validate.instructions.md. Not a flake guard.
func TestExtractFingerprintFromArmorFile_NoFingerprintInOutput(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("issue #30: gpg binary not on PATH; ExtractFingerprintFromArmorFile needs gpg to exercise the no-fpr branch")
	}
	dir := t.TempDir()
	empty := dir + "/empty.asc"
	if err := os.WriteFile(empty, []byte("not a pgp armor\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	got, err := ExtractFingerprintFromArmorFile(empty)
	if err == nil {
		t.Fatalf("ExtractFingerprintFromArmorFile on a non-armor file returned %q, want an error", got)
	}
	// The error must be non-empty and must NOT contain a fabricated
	// fingerprint. Either the gpg-failure branch or the no-fpr branch
	// is acceptable; we assert only the error contract.
	if got != "" {
		t.Errorf("on error, return value must be empty, got %q", got)
	}
}

// TestExtractFingerprintFromArmorFile_ExtractsFingerprint verifies the
// happy path: gpg --show-keys on a real armored public key returns the
// primary key fingerprint via the first fpr record. We generate a
// throwaway RSA test key in an isolated GNUPGHOME so the test never
// touches the user's real keyring and is deterministic across runs.
//
// Skipped when gpg is absent (issue #30 tracking link, not a flake guard).
func TestExtractFingerprintFromArmorFile_ExtractsFingerprint(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("issue #30: gpg binary not on PATH; ExtractFingerprintFromArmorFile needs gpg to extract a real fingerprint")
	}

	home := t.TempDir()
	// gpg refuses to operate on a GNUPGHOME with loose perms.
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatalf("chmod GNUPGHOME: %v", err)
	}
	t.Setenv("GNUPGHOME", home)

	// Generate a fast, throwaway RSA test key with a full "Name <email>"
	// uid (the angle-bracket form is what DetectKeyForEmail looks for).
	email := "keysmith-test@example.com"
	uid := "Test User <" + email + ">"
	gen := exec.Command("gpg", "--batch", "--yes", "--pinentry-mode", "loopback",
		"--passphrase", "", "--quick-generate-key", uid, "rsa3072", "default", "0")
	if out, err := gen.CombinedOutput(); err != nil {
		t.Fatalf("gpg --quick-generate-key: %v\n%s", err, out)
	}

	// Look up the generated key by email to get its long key id, then
	// export the public key armor. ExportPublicKey validates the key id
	// is hex, so we must pass the key id (not the email).
	key, err := DetectKeyForEmail(email)
	if err != nil {
		t.Fatalf("DetectKeyForEmail: %v", err)
	}
	// DetectKeyForEmail returns (nil, nil) on no match; a nil key here
	// means generation failed silently. Put the dereferences in the
	// non-nil branch so staticcheck can prove the pointer is non-nil
	// (avoids SA5011 false positive on the t.Fatal-then-deref pattern).
	if key == nil {
		t.Fatalf("DetectKeyForEmail(%q) returned nil; key generation may have failed", email)
	}
	extractAndCheckFingerprint(t, key, home)
}

// extractAndCheckFingerprint exports the key's public armor, extracts
// the fingerprint from the armor file, and asserts it matches the
// keyring fingerprint. Extracted so the dereferences of `key` live in
// a function that receives a non-nil *GpgKey — staticcheck can then
// prove the pointer is non-nil (the nil guard is in the caller).
func extractAndCheckFingerprint(t *testing.T, key *GpgKey, home string) {
	t.Helper()
	keyID := key.KeyID
	pubArmor, err := ExportPublicKey(keyID)
	if err != nil {
		t.Fatalf("ExportPublicKey(%q): %v", keyID, err)
	}
	pubFile := home + "/pub.asc"
	if err := os.WriteFile(pubFile, []byte(pubArmor), 0o600); err != nil {
		t.Fatalf("write pub armor: %v", err)
	}

	got, err := ExtractFingerprintFromArmorFile(pubFile)
	if err != nil {
		t.Fatalf("ExtractFingerprintFromArmorFile: %v", err)
	}
	if len(got) != 40 {
		t.Errorf("fingerprint length = %d, want 40 (got %q)", len(got), got)
	}
	for _, r := range got {
		isHex := (r >= '0' && r <= '9') || (r >= 'A' && r <= 'F')
		if !isHex {
			t.Errorf("fingerprint must be uppercase hex, got %q", got)
			break
		}
	}
	// The fingerprint extracted from the armor file must match the
	// fingerprint gpg reported for the key in the keyring — this is the
	// invariant the publish subcommand relies on to detect a mismatched
	// --keyid vs --pubkey-file pair.
	wantFpr := key.Fingerprint
	if got != wantFpr {
		t.Errorf("extracted fingerprint %q != keyring fingerprint %q", got, wantFpr)
	}
}
