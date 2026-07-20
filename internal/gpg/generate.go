package gpg

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// GenerateOptions describes the inputs for a new GPG key.
type GenerateOptions struct {
	// Name is the real name portion of the key's user id, e.g. "Leonid
	// Golikhin". Required — gpg rejects empty Name-Real.
	Name string
	// Email is the email portion of the key's user id, e.g.
	// "korrnals@example.com". Required — used by DetectKeyForEmail to
	// find the freshly-generated key.
	Email string
	// Comment is the optional comment portion of the user id, e.g.
	// "keysmith". May be empty — the batch file omits Name-Comment when
	// Comment is "".
	Comment string
	// KeyType is the gpg key algorithm, default "RSA".
	KeyType string
	// KeyLength is the key size in bits, default 4096.
	KeyLength int
	// Expiry is the gpg expire-date spec, default "0" (never expires).
	// Other examples: "2y" (2 years), "2026-12-31" (absolute date).
	Expiry string
	// Passphrase protects the new key. Required — never empty. The
	// passphrase is piped to gpg via stdin (--passphrase-fd 0 with
	// --pinentry-mode loopback), never written to the batch file, never
	// passed as a CLI arg, and never logged.
	Passphrase string
}

// buildBatchFile constructs the gpg batch parameter file content from
// opts. It is a pure function (no I/O) so it can be unit-tested without
// invoking gpg. The passphrase is deliberately NOT included here — it
// is piped via stdin to gpg --pinentry-mode loopback, never written to
// the batch file. The %no-protection directive is deliberately absent:
// it would create an unprotected key, which this tool never does.
//
// buildBatchFile validates its string inputs via validateBatchInput
// before interpolating them into the batch directives. This rejects
// newline/control-char injection (a '\n' in Name would let a malicious
// or mistyped value start a new gpg directive). Callers that already
// validated (e.g. GenerateKey) can ignore the returned error is nil.
func buildBatchFile(opts GenerateOptions) (string, error) {
	if err := validateBatchInput(opts.Name); err != nil {
		return "", fmt.Errorf("gpg generate: field Name contains newline or control char (injection risk): %w", err)
	}
	if err := validateBatchInput(opts.Email); err != nil {
		return "", fmt.Errorf("gpg generate: field Email contains newline or control char (injection risk): %w", err)
	}
	if opts.Comment != "" {
		if err := validateBatchInput(opts.Comment); err != nil {
			return "", fmt.Errorf("gpg generate: field Comment contains newline or control char (injection risk): %w", err)
		}
	}
	if err := validateBatchInput(opts.Expiry); err != nil {
		return "", fmt.Errorf("gpg generate: field Expiry contains newline or control char (injection risk): %w", err)
	}
	if err := validateBatchInput(opts.KeyType); err != nil {
		return "", fmt.Errorf("gpg generate: field KeyType contains newline or control char (injection risk): %w", err)
	}
	if err := validateKeyLength(opts.KeyLength); err != nil {
		return "", err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%%echo Generating a key for %s\n", opts.Email)
	fmt.Fprintf(&b, "Key-Type: %s\n", opts.KeyType)
	fmt.Fprintf(&b, "Key-Length: %d\n", opts.KeyLength)
	fmt.Fprintf(&b, "Subkey-Type: %s\n", opts.KeyType)
	fmt.Fprintf(&b, "Subkey-Length: %d\n", opts.KeyLength)
	fmt.Fprintf(&b, "Name-Real: %s\n", opts.Name)
	fmt.Fprintf(&b, "Name-Email: %s\n", opts.Email)
	if opts.Comment != "" {
		fmt.Fprintf(&b, "Name-Comment: %s\n", opts.Comment)
	}
	fmt.Fprintf(&b, "Expire-Date: %s\n", opts.Expiry)
	b.WriteString("%commit\n")
	b.WriteString("%echo done\n")
	return b.String(), nil
}

// validateBatchInput rejects any newline, carriage return, or other
// control character (except tab) in a string that will be interpolated
// into a gpg batch directive. A '\n' in Name-Real would let a malicious
// value start a new directive (e.g. "Alice\nPassphrase: ..."), so every
// user-supplied batch field is validated before it reaches the file.
//
// Tab is allowed because gpg treats it as whitespace inside a value
// and it does not start a new directive.
func validateBatchInput(s string) error {
	for _, r := range s {
		// Allow printable runes and tab. Reject \n, \r, \v, \f, and
		// any other control char (\x00-\x1F minus tab, plus \x7F).
		if r == '\t' {
			continue
		}
		if r < 0x20 || r == 0x7F {
			return fmt.Errorf("control character 0x%02X in input", r)
		}
	}
	return nil
}

// validateKeyLength rejects a key length outside [1024, 8192]. 0
// (unset, then defaulted) is allowed because GenerateKey applies the
// 4096 default before calling buildBatchFile — but buildBatchFile
// defends against a caller that bypasses GenerateKey with an absurd
// value like 1 or 1000000. The range matches gpg's own RSA limits.
func validateKeyLength(n int) error {
	if n == 0 {
		return nil
	}
	if n < 1024 || n > 8192 {
		return fmt.Errorf("gpg generate: key length must be in [1024, 8192], got %d", n)
	}
	return nil
}

// GenerateKey drives 'gpg --gen-key' with a batch parameter file and
// --pinentry-mode loopback so the passphrase collected by the wizard is
// piped in via stdin without an interactive pinentry dialog. The
// passphrase never appears in the batch file, process args, or logs.
//
// After generation, DetectKeyForEmail(opts.Email) (from detect.go) is
// called to look up and return the new key's long-form key id.
func GenerateKey(opts GenerateOptions) (keyID string, err error) {
	// Validate required fields before touching the filesystem or gpg.
	// Empty passphrase is a hard error — we never create unprotected keys.
	if opts.Passphrase == "" {
		return "", fmt.Errorf("gpg generate: passphrase is required (never empty)")
	}
	if opts.Email == "" {
		return "", fmt.Errorf("gpg generate: email is required")
	}
	if opts.Name == "" {
		return "", fmt.Errorf("gpg generate: name is required")
	}
	// Apply defaults for optional fields.
	if opts.KeyType == "" {
		opts.KeyType = "RSA"
	}
	if opts.KeyLength == 0 {
		opts.KeyLength = 4096
	}
	if opts.Expiry == "" {
		opts.Expiry = "0"
	}

	batch, err := buildBatchFile(opts)
	if err != nil {
		return "", err
	}

	// Create the temp batch file with 0600 perms — it contains the
	// user's name and email (PII), not the passphrase, but still must
	// not be world-readable. Remove it on exit regardless of success
	// or failure.
	tmp, err := os.CreateTemp("", "keysmith-gpg-batch-*.gpg")
	if err != nil {
		return "", fmt.Errorf("gpg generate: create temp batch file: %w", err)
	}
	tmpName := tmp.Name()
	if err := os.Chmod(tmpName, 0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("gpg generate: chmod batch file: %w", err)
	}
	if _, err := tmp.WriteString(batch); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("gpg generate: write batch file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("gpg generate: close batch file: %w", err)
	}
	defer func() { _ = os.Remove(tmpName) }()

	// --passphrase-fd 0 tells gpg to read the passphrase from stdin
	// (fd 0). This avoids leaking the passphrase via the process arg
	// list (ps/proc), which --passphrase <value> would do. The batch
	// file is passed as a filename argument to --gen-key, so stdin is
	// dedicated to the passphrase.
	cmd := exec.Command("gpg",
		"--batch",
		"--pinentry-mode", "loopback",
		"--passphrase-fd", "0",
		"--gen-key", tmpName,
	)
	cmd.Stdin = strings.NewReader(opts.Passphrase)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// Never include the passphrase in the error message. stderr
		// from gpg may contain diagnostics but not the passphrase
		// (it was piped via stdin, not echoed).
		return "", fmt.Errorf("gpg generate: gpg --gen-key failed: %w: %s", err, stderr.String())
	}

	// Look up the freshly-generated key by email to return its key id.
	key, err := DetectKeyForEmail(opts.Email)
	if err != nil {
		return "", fmt.Errorf("gpg generate: detect new key: %w", err)
	}
	if key == nil {
		// gpg ran successfully but the key isn't visible — this can
		// happen if gpg wrote to a different keyring or if detection
		// raced the keyring update. Surface it as an error with the
		// email (not the passphrase) for diagnosis.
		return "", fmt.Errorf("gpg generate: key not found after generation (email=%s)", opts.Email)
	}
	return key.KeyID, nil
}
