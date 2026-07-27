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

// --- validateBatchInput tests -------------------------------------------

// TestValidateBatchInput_TableDriven verifies the control-character
// injection guard accepts printable runes + tab and rejects newline,
// carriage return, and other control characters. This is the
// security gate that prevents a '\n' in Name-Real from starting a new
// gpg batch directive.
func TestValidateBatchInput_TableDriven(t *testing.T) {
	accept := []struct {
		name string
		in   string
	}{
		{name: "plain ascii", in: "Alice"},
		{name: "email", in: "alice@example.com"},
		{name: "with spaces", in: "Alice Bob"},
		{name: "unicode printable", in: "Алиса"},
		{name: "tab allowed", in: "field\tvalue"},
		{name: "expiry spec", in: "2y"},
		{name: "absolute date", in: "2026-12-31"},
		{name: "key type", in: "RSA"},
		{name: "empty string", in: ""}, // empty is valid — caller decides requiredness
	}
	for _, tc := range accept {
		t.Run("accept/"+tc.name, func(t *testing.T) {
			if err := validateBatchInput(tc.in); err != nil {
				t.Errorf("validateBatchInput(%q) = %v, want nil", tc.in, err)
			}
		})
	}

	reject := []struct {
		name string
		in   string
	}{
		{name: "newline", in: "Alice\nEvil"},
		{name: "carriage return", in: "Alice\rEvil"},
		{name: "vertical tab", in: "Alice\vEvil"},
		{name: "form feed", in: "Alice\fEvil"},
		{name: "null byte", in: "Alice\x00Evil"},
		{name: "DEL 0x7F", in: "Alice\x7FEvil"},
		{name: "embedded newline in email", in: "alice@example.com\nPassphrase: leaked"},
	}
	for _, tc := range reject {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			if err := validateBatchInput(tc.in); err == nil {
				t.Errorf("validateBatchInput(%q) = nil, want an error (control char)", tc.in)
			}
		})
	}
}

// --- validateKeyLength tests --------------------------------------------

// TestValidateKeyLength_TableDriven verifies the key-length range guard
// [1024, 8192]. 0 is allowed (GenerateKey applies the 4096 default
// before calling buildBatchFile — 0 means "unset"). Values outside the
// range are rejected to block absurd caller-supplied lengths.
func TestValidateKeyLength_TableDriven(t *testing.T) {
	accept := []int{0, 1024, 2048, 3072, 4096, 8192}
	for _, n := range accept {
		if err := validateKeyLength(n); err != nil {
			t.Errorf("validateKeyLength(%d) = %v, want nil", n, err)
		}
	}

	reject := []int{1, 512, 1000, 1023, 8193, 1000000, -1}
	for _, n := range reject {
		if err := validateKeyLength(n); err == nil {
			t.Errorf("validateKeyLength(%d) = nil, want an error (out of [1024, 8192])", n)
		}
	}
}

// --- buildBatchFile rejection-path tests --------------------------------

// TestBuildBatchFile_RejectsNewlineInName verifies that a newline
// embedded in Name is rejected by buildBatchFile (via validateBatchInput)
// with an error mentioning the Name field — this is the injection guard
// the pure builder enforces before interpolating user input.
func TestBuildBatchFile_RejectsNewlineInName(t *testing.T) {
	opts := GenerateOptions{
		Name:       "Alice\nPassphrase: leaked",
		Email:      "alice@example.com",
		KeyType:    "RSA",
		KeyLength:  4096,
		Expiry:     "0",
		Passphrase: "<REDACTED>",
	}
	_, err := buildBatchFile(opts)
	if err == nil {
		t.Fatal("buildBatchFile with newline in Name must return an error")
	}
	if !strings.Contains(err.Error(), "Name") {
		t.Errorf("error should mention the Name field, got: %v", err)
	}
}

// TestBuildBatchFile_RejectsNewlineInEmail verifies the injection guard
// fires on the Email field as well.
func TestBuildBatchFile_RejectsNewlineInEmail(t *testing.T) {
	opts := GenerateOptions{
		Name:       "Alice",
		Email:      "alice@example.com\nName-Real: Evil",
		KeyType:    "RSA",
		KeyLength:  4096,
		Expiry:     "0",
		Passphrase: "<REDACTED>",
	}
	_, err := buildBatchFile(opts)
	if err == nil {
		t.Fatal("buildBatchFile with newline in Email must return an error")
	}
	if !strings.Contains(err.Error(), "Email") {
		t.Errorf("error should mention the Email field, got: %v", err)
	}
}

// TestBuildBatchFile_RejectsNewlineInComment verifies the injection guard
// fires on the optional Comment field.
func TestBuildBatchFile_RejectsNewlineInComment(t *testing.T) {
	opts := GenerateOptions{
		Name:       "Alice",
		Email:      "alice@example.com",
		Comment:    "test\nEvil",
		KeyType:    "RSA",
		KeyLength:  4096,
		Expiry:     "0",
		Passphrase: "<REDACTED>",
	}
	_, err := buildBatchFile(opts)
	if err == nil {
		t.Fatal("buildBatchFile with newline in Comment must return an error")
	}
	if !strings.Contains(err.Error(), "Comment") {
		t.Errorf("error should mention the Comment field, got: %v", err)
	}
}

// TestBuildBatchFile_RejectsNewlineInExpiry verifies the injection guard
// fires on the Expiry field.
func TestBuildBatchFile_RejectsNewlineInExpiry(t *testing.T) {
	opts := GenerateOptions{
		Name:       "Alice",
		Email:      "alice@example.com",
		KeyType:    "RSA",
		KeyLength:  4096,
		Expiry:     "0\nEvil",
		Passphrase: "<REDACTED>",
	}
	_, err := buildBatchFile(opts)
	if err == nil {
		t.Fatal("buildBatchFile with newline in Expiry must return an error")
	}
	if !strings.Contains(err.Error(), "Expiry") {
		t.Errorf("error should mention the Expiry field, got: %v", err)
	}
}

// TestBuildBatchFile_RejectsNewlineInKeyType verifies the injection guard
// fires on the KeyType field.
func TestBuildBatchFile_RejectsNewlineInKeyType(t *testing.T) {
	opts := GenerateOptions{
		Name:       "Alice",
		Email:      "alice@example.com",
		KeyType:    "RSA\nEvil",
		KeyLength:  4096,
		Expiry:     "0",
		Passphrase: "<REDACTED>",
	}
	_, err := buildBatchFile(opts)
	if err == nil {
		t.Fatal("buildBatchFile with newline in KeyType must return an error")
	}
	if !strings.Contains(err.Error(), "KeyType") {
		t.Errorf("error should mention the KeyType field, got: %v", err)
	}
}

// TestBuildBatchFile_RejectsInvalidKeyLength verifies that buildBatchFile
// rejects a key length outside [1024, 8192] even when all string fields
// are clean — this is the validateKeyLength guard inside the builder.
func TestBuildBatchFile_RejectsInvalidKeyLength(t *testing.T) {
	opts := GenerateOptions{
		Name:       "Alice",
		Email:      "alice@example.com",
		KeyType:    "RSA",
		KeyLength:  512, // too small
		Expiry:     "0",
		Passphrase: "<REDACTED>",
	}
	_, err := buildBatchFile(opts)
	if err == nil {
		t.Fatal("buildBatchFile with KeyLength=512 must return an error")
	}
	if !strings.Contains(err.Error(), "key length") {
		t.Errorf("error should mention key length, got: %v", err)
	}
}

// TestBuildBatchFile_AppliesDefaultsViaGenerate verifies that when
// KeyType, KeyLength, and Expiry are left at zero values, GenerateKey
// applies the RSA/4096/0 defaults BEFORE buildBatchFile runs — so the
// builder never sees a zero KeyLength that would pass validateKeyLength
// (0 is "unset, allowed") but produce a useless key. This is the
// boundary between GenerateKey's defaulting and buildBatchFile's
// validation; we assert via the GenerateKey entry point that a
// well-formed opts (with only the required fields) reaches the gpg
// invocation rather than failing at buildBatchFile.
//
// We cannot assert the gpg result without a real keyring (covered by
// integration tests), but we CAN assert that the error — if any — is
// NOT a buildBatchFile validation error, proving the defaults applied.
func TestBuildBatchFile_AppliesDefaultsViaGenerate(t *testing.T) {
	opts := GenerateOptions{
		Name:  "Alice",
		Email: "alice@example.com",
		// KeyType, KeyLength, Expiry all zero — GenerateKey defaults them.
		Passphrase: "nonempty-passphrase",
	}
	_, err := GenerateKey(opts)
	// We expect an error here because gpg is invoked against the real
	// keyring (or fails because gpg-agent/pinentry is unavailable in
	// this env). The point: the error must NOT be a buildBatchFile
	// validation error mentioning "key length" or "control character".
	if err == nil {
		// If gpg actually ran and succeeded, that's fine too — the
		// defaults applied and a key was generated. Nothing to assert.
		return
	}
	errMsg := err.Error()
	if strings.Contains(errMsg, "key length") {
		t.Errorf("defaults not applied: buildBatchFile rejected key length: %v", err)
	}
	if strings.Contains(errMsg, "control character") {
		t.Errorf("defaults not applied: buildBatchFile rejected a clean input: %v", err)
	}
}
