package gpg

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// ValidateKeyID rejects key IDs that could be used to inject extra
// arguments into the gpg command line. gpg key IDs are hex strings or
// fingerprints — at most 40 hex chars, optionally starting with "0x".
// Anything else (spaces, quotes, dashes that aren't part of a
// fingerprint, shell metacharacters) is rejected.
//
// This is a defense against a malicious or mistyped key ID like
// "ABCD; rm -rf ~" being passed as a single argv element. exec.Command
// does NOT invoke a shell, so this is not strictly a shell-injection
// vector, but validating the shape early gives a clean error and
// prevents confusing gpg diagnostics.
func ValidateKeyID(keyID string) error {
	if keyID == "" {
		return fmt.Errorf("gpg export: key id is required")
	}
	s := keyID
	// Accept an optional "0x" prefix.
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s = s[2:]
	}
	if s == "" {
		return fmt.Errorf("gpg export: key id is empty after 0x prefix")
	}
	if len(s) > 40 {
		return fmt.Errorf("gpg export: key id too long (max 40 hex chars, got %d)", len(s))
	}
	for _, r := range s {
		isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
		if !isHex {
			return fmt.Errorf("gpg export: key id must be hex (0-9, A-F), got %q", keyID)
		}
	}
	return nil
}

// ExportPublicKey runs 'gpg --armor --export <keyID>' and returns the
// ASCII-armored public key as a string. It does NOT write the key to
// disk — the caller (main.go or M6 github) is responsible for writing
// the returned armor to the desired path with the desired perms.
//
// The keyID is validated via ValidateKeyID before gpg is invoked to
// prevent malformed input from reaching the gpg arg vector. The
// public key is not secret material, so stdout capture is safe.
func ExportPublicKey(keyID string) (string, error) {
	if err := ValidateKeyID(keyID); err != nil {
		return "", err
	}
	args := buildExportPublicKeyArgs(keyID)
	cmd := exec.Command("gpg", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("gpg export: gpg --export failed: %w: %s",
			err, strings.TrimSpace(stderr.String()))
	}
	armor := stdout.String()
	if armor == "" {
		return "", fmt.Errorf("gpg export: gpg --export produced no output (key id %q may not exist)", keyID)
	}
	if !strings.HasPrefix(armor, "-----BEGIN PGP") {
		return "", fmt.Errorf("gpg export: output is not ASCII-armored (missing PGP header)")
	}
	return armor, nil
}

// ExportPrivateKey runs 'gpg --armor --export-secret-keys <keyID>
// --pinentry-mode loopback --passphrase-fd 0' and returns the
// ASCII-armored private key as a string. The passphrase is piped to
// gpg via stdin (fd 0) — it is NEVER passed as a CLI arg
// (--passphrase <value> would leak via ps/proc).
//
// Security invariants enforced by this function:
//   - The private key is captured in memory (the returned string)
//     and never written to disk by this package.
//   - The passphrase is never logged, never echoed in error messages,
//     and never placed in the gpg arg vector.
//   - Empty keyID or empty passphrase is rejected before gpg is
//     invoked.
func ExportPrivateKey(keyID, passphrase string) (string, error) {
	if err := ValidateKeyID(keyID); err != nil {
		return "", err
	}
	if passphrase == "" {
		return "", fmt.Errorf("gpg export: passphrase is required (never empty)")
	}
	args := buildExportPrivateKeyArgs(keyID)
	cmd := exec.Command("gpg", args...)
	// --passphrase-fd 0 reads the passphrase from stdin (fd 0). This
	// avoids leaking the passphrase via the process arg list, which
	// --passphrase <value> would do. Use a reader that supplies the
	// passphrase followed by a newline (gpg reads a line from fd 0).
	cmd.Stdin = strings.NewReader(passphrase + "\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// Never include the passphrase or the private key content in
		// the error message. stderr from gpg may contain diagnostics
		// but not the passphrase (it was piped via stdin, not echoed).
		return "", fmt.Errorf("gpg export: gpg --export-secret-keys failed: %w: %s",
			err, strings.TrimSpace(stderr.String()))
	}
	armor := stdout.String()
	if armor == "" {
		return "", fmt.Errorf("gpg export: gpg --export-secret-keys produced no output (key id %q may not exist)", keyID)
	}
	if !strings.HasPrefix(armor, "-----BEGIN PGP") {
		return "", fmt.Errorf("gpg export: secret-key output is not ASCII-armored (missing PGP header)")
	}
	return armor, nil
}

// buildExportPublicKeyArgs constructs the gpg arg vector for a public
// key export. It is extracted as a pure function so tests can assert
// the args without invoking gpg.
func buildExportPublicKeyArgs(keyID string) []string {
	return []string{
		"--armor",
		"--export",
		keyID,
	}
}

// buildExportPrivateKeyArgs constructs the gpg arg vector for a secret
// key export. It is extracted as a pure function so tests can assert:
//   - the args contain --passphrase-fd 0 (stdin path), NOT
//     --passphrase <value> (CLI-arg leak path)
//   - the args contain --pinentry-mode loopback
//   - the args never contain the passphrase string itself
//
// The passphrase is supplied via the returned cmd's Stdin in
// ExportPrivateKey, not via these args.
func buildExportPrivateKeyArgs(keyID string) []string {
	return []string{
		"--armor",
		"--export-secret-keys",
		keyID,
		"--pinentry-mode", "loopback",
		"--passphrase-fd", "0",
	}
}

// ExtractFingerprintFromArmorFile reads an ASCII-armored public key file
// and returns the key's fingerprint by shelling out to
// `gpg --with-colons --show-keys <path>`. The first `fpr:` record in the
// colon output is the primary key fingerprint.
//
// This is used by the 'publish' subcommand to validate that the keyid
// the user passed via --keyid actually matches the key in the --pubkey-file
// they provided — without this check, a mismatched keyid would silently
// publish the wrong key under a misleading keyid label.
func ExtractFingerprintFromArmorFile(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("gpg: extract fingerprint: path is required")
	}
	cmd := exec.Command("gpg", "--with-colons", "--show-keys", path)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("gpg: extract fingerprint from %s: %w", path, err)
	}
	for _, line := range strings.Split(stdout.String(), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 10 && fields[0] == "fpr" {
			return fields[9], nil
		}
	}
	return "", fmt.Errorf("gpg: no fingerprint found in %s (not a valid armored public key?)", path)
}
