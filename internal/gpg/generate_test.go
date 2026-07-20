package gpg

import (
	"strings"
	"testing"
)

// TestBuildBatchFile_ContainsExpectedFields verifies the pure batch-file
// builder produces all required gpg directives with the right values.
// No gpg invocation — buildBatchFile is a pure function.
func TestBuildBatchFile_ContainsExpectedFields(t *testing.T) {
	opts := GenerateOptions{
		Name:       "Leonid Golikhin",
		Email:      "korrnals@example.com",
		Comment:    "keysmith test",
		KeyType:    "RSA",
		KeyLength:  4096,
		Expiry:     "0",
		Passphrase: "<REDACTED>", // not used by buildBatchFile, set for realism
	}
	batch, err := buildBatchFile(opts)
	if err != nil {
		t.Fatalf("buildBatchFile: %v", err)
	}

	checks := []struct {
		name string
		want string
	}{
		{"key type", "Key-Type: RSA"},
		{"key length", "Key-Length: 4096"},
		{"subkey type", "Subkey-Type: RSA"},
		{"subkey length", "Subkey-Length: 4096"},
		{"name real", "Name-Real: Leonid Golikhin"},
		{"name email", "Name-Email: korrnals@example.com"},
		{"name comment", "Name-Comment: keysmith test"},
		{"expire date", "Expire-Date: 0"},
		{"commit directive", "%commit"},
		{"echo done", "%echo done"},
	}
	for _, c := range checks {
		if !strings.Contains(batch, c.want) {
			t.Errorf("batch missing %q (%s)\n--- batch ---\n%s", c.want, c.name, batch)
		}
	}
}

// TestBuildBatchFile_NoNoProtection asserts the batch file never
// contains %no-protection — that directive creates an unprotected key,
// which this tool must never do. The passphrase is always piped via
// stdin with --pinentry-mode loopback.
func TestBuildBatchFile_NoNoProtection(t *testing.T) {
	opts := GenerateOptions{
		Name:       "Test User",
		Email:      "test@example.com",
		Comment:    "test",
		KeyType:    "RSA",
		KeyLength:  4096,
		Expiry:     "0",
		Passphrase: "<REDACTED>",
	}
	batch, err := buildBatchFile(opts)
	if err != nil {
		t.Fatalf("buildBatchFile: %v", err)
	}
	if strings.Contains(batch, "%no-protection") {
		t.Errorf("batch must NOT contain %%no-protection (creates unprotected key)\n--- batch ---\n%s", batch)
	}
}

// TestBuildBatchFile_OmitsCommentWhenEmpty verifies the batch file
// omits the Name-Comment directive when Comment is empty, rather than
// emitting an empty "Name-Comment: " line.
func TestBuildBatchFile_OmitsCommentWhenEmpty(t *testing.T) {
	opts := GenerateOptions{
		Name:       "Test User",
		Email:      "test@example.com",
		Comment:    "",
		KeyType:    "RSA",
		KeyLength:  4096,
		Expiry:     "0",
		Passphrase: "<REDACTED>",
	}
	batch, err := buildBatchFile(opts)
	if err != nil {
		t.Fatalf("buildBatchFile: %v", err)
	}
	if strings.Contains(batch, "Name-Comment:") {
		t.Errorf("batch must NOT contain Name-Comment when Comment is empty\n--- batch ---\n%s", batch)
	}
}

// TestBuildBatchFile_NoPassphraseInBatch verifies the passphrase never
// appears in the batch file content — it is piped via stdin, not
// written to the batch. This is a security-critical invariant.
func TestBuildBatchFile_NoPassphraseInBatch(t *testing.T) {
	opts := GenerateOptions{
		Name:       "Test User",
		Email:      "test@example.com",
		Comment:    "test",
		KeyType:    "RSA",
		KeyLength:  4096,
		Expiry:     "0",
		Passphrase: "super-secret-passphrase-12345",
	}
	batch, err := buildBatchFile(opts)
	if err != nil {
		t.Fatalf("buildBatchFile: %v", err)
	}
	if strings.Contains(batch, opts.Passphrase) {
		t.Errorf("batch must NOT contain the passphrase (it goes via stdin, not the batch)\n--- batch ---\n%s", batch)
	}
}

// TestGenerateKey_EmptyPassphraseReturnsError verifies that an empty
// passphrase is rejected before gpg is invoked. This is the security
// gate: we never create unprotected keys.
func TestGenerateKey_EmptyPassphraseReturnsError(t *testing.T) {
	opts := GenerateOptions{
		Name:       "Test User",
		Email:      "test@example.com",
		KeyType:    "RSA",
		KeyLength:  4096,
		Expiry:     "0",
		Passphrase: "",
	}
	_, err := GenerateKey(opts)
	if err == nil {
		t.Fatal("GenerateKey with empty passphrase must return an error")
	}
	if !strings.Contains(err.Error(), "passphrase") {
		t.Errorf("error should mention passphrase, got: %v", err)
	}
}

// TestGenerateKey_EmptyEmailReturnsError verifies that an empty email
// is rejected before gpg is invoked — DetectKeyForEmail needs it to
// find the new key.
func TestGenerateKey_EmptyEmailReturnsError(t *testing.T) {
	opts := GenerateOptions{
		Name:       "Test User",
		Email:      "",
		KeyType:    "RSA",
		KeyLength:  4096,
		Expiry:     "0",
		Passphrase: "nonempty-passphrase",
	}
	_, err := GenerateKey(opts)
	if err == nil {
		t.Fatal("GenerateKey with empty email must return an error")
	}
	if !strings.Contains(err.Error(), "email") {
		t.Errorf("error should mention email, got: %v", err)
	}
}

// TestGenerateKey_EmptyNameReturnsError verifies that an empty name is
// rejected before gpg is invoked — gpg rejects empty Name-Real.
func TestGenerateKey_EmptyNameReturnsError(t *testing.T) {
	opts := GenerateOptions{
		Name:       "",
		Email:      "test@example.com",
		KeyType:    "RSA",
		KeyLength:  4096,
		Expiry:     "0",
		Passphrase: "nonempty-passphrase",
	}
	_, err := GenerateKey(opts)
	if err == nil {
		t.Fatal("GenerateKey with empty name must return an error")
	}
	if !strings.Contains(err.Error(), "name") {
		t.Errorf("error should mention name, got: %v", err)
	}
}
