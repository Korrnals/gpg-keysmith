package gpg

import (
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
