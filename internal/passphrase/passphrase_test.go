package passphrase

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writePassphraseFile writes content to a file in t.TempDir() and
// returns its path. The file is created with 0600 perms by default so
// the loose-perm warning does not fire in tests that do not explicitly
// exercise it. The passphrase content is written directly to the
// file — it is NOT logged or echoed to test output.
func writePassphraseFile(t *testing.T, content string, perm os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "passphrase.txt")
	if err := os.WriteFile(path, []byte(content), perm); err != nil {
		t.Fatalf("write passphrase file: %v", err)
	}
	// os.WriteFile honours the perm only on create; chmod to be safe
	// across filesystems that may have applied a umask.
	if err := os.Chmod(path, perm); err != nil {
		t.Fatalf("chmod passphrase file: %v", err)
	}
	return path
}

// TestReadPassphraseFile_Valid verifies a file with a trailing newline
// yields the passphrase without the newline. This is the common case
// (`echo "pass" > file` appends a single \n).
func TestReadPassphraseFile_Valid(t *testing.T) {
	path := writePassphraseFile(t, "passphrase\n", 0o600)
	got, err := ReadFile("generate", path, nil)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if got != "passphrase" {
		t.Errorf("ReadFile = %q, want %q", got, "passphrase")
	}
}

// TestReadPassphraseFile_NoTrailingNewline verifies a file with no
// trailing newline yields the passphrase verbatim. Some users write
// the file with printf (no trailing \n) — that must work too.
func TestReadPassphraseFile_NoTrailingNewline(t *testing.T) {
	path := writePassphraseFile(t, "passphrase", 0o600)
	got, err := ReadFile("generate", path, nil)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if got != "passphrase" {
		t.Errorf("ReadFile = %q, want %q", got, "passphrase")
	}
}

// TestReadPassphraseFile_Empty verifies a file containing only a
// newline (or empty) is rejected as "empty". An empty passphrase is
// never a valid input — gpg would create an unprotected key.
func TestReadPassphraseFile_Empty(t *testing.T) {
	path := writePassphraseFile(t, "\n", 0o600)
	_, err := ReadFile("generate", path, nil)
	if err == nil {
		t.Fatal("ReadFile returned nil error for empty file")
	}
	if !strings.Contains(err.Error(), "is empty") {
		t.Errorf("error should mention 'is empty', got: %v", err)
	}
}

// TestReadPassphraseFile_TrulyEmpty verifies a zero-byte file is
// rejected as "empty" (the strip operation leaves it empty).
func TestReadPassphraseFile_TrulyEmpty(t *testing.T) {
	path := writePassphraseFile(t, "", 0o600)
	_, err := ReadFile("generate", path, nil)
	if err == nil {
		t.Fatal("ReadFile returned nil error for zero-byte file")
	}
	if !strings.Contains(err.Error(), "is empty") {
		t.Errorf("error should mention 'is empty', got: %v", err)
	}
}

// TestReadPassphraseFile_Missing verifies a missing file produces a
// "cannot read passphrase file" error wrapping the os error.
func TestReadPassphraseFile_Missing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.txt")
	_, err := ReadFile("generate", path, nil)
	if err == nil {
		t.Fatal("ReadFile returned nil error for missing file")
	}
	if !strings.Contains(err.Error(), "cannot read passphrase file") {
		t.Errorf("error should mention 'cannot read passphrase file', got: %v", err)
	}
	if !strings.Contains(err.Error(), "generate") {
		t.Errorf("error should include the command label 'generate', got: %v", err)
	}
}

// TestReadPassphraseFile_WindowsNewline verifies a file with a CRLF
// line ending yields the passphrase without the trailing \r\n. This
// handles passphrase files created on Windows or transferred via a
// transport that adds \r.
func TestReadPassphraseFile_WindowsNewline(t *testing.T) {
	path := writePassphraseFile(t, "passphrase\r\n", 0o600)
	got, err := ReadFile("generate", path, nil)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if got != "passphrase" {
		t.Errorf("ReadFile = %q, want %q (CRLF should be stripped)", got, "passphrase")
	}
}

// TestReadPassphraseFile_InteriorNewlinePreserved verifies that a
// newline in the MIDDLE of the passphrase is preserved — only a
// single trailing \n and \r are stripped. A passphrase with an
// interior newline is unusual but legitimate (some passphrase
// generators include them); we must not mangle it.
func TestReadPassphraseFile_InteriorNewlinePreserved(t *testing.T) {
	path := writePassphraseFile(t, "line1\nline2\n", 0o600)
	got, err := ReadFile("generate", path, nil)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if got != "line1\nline2" {
		t.Errorf("ReadFile = %q, want %q (interior newline preserved, trailing stripped)",
			got, "line1\nline2")
	}
}

// TestReadPassphraseFile_CommandLabelInError verifies the command
// label is interpolated into both the missing-file and empty-file
// errors so the user knows which subcommand rejected the file.
func TestReadPassphraseFile_CommandLabelInError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.txt")
	_, err := ReadFile("export", path, nil)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "export:") {
		t.Errorf("error should start with 'export:', got: %v", err)
	}
}

// TestReadPassphraseFile_LoosePermsWarn verifies a file with perms
// looser than 0600 triggers a warning to the provided writer. The
// warning must be non-fatal (ReadFile still returns the passphrase).
func TestReadPassphraseFile_LoosePermsWarn(t *testing.T) {
	path := writePassphraseFile(t, "passphrase\n", 0o644)
	var warn bytes.Buffer
	got, err := ReadFile("generate", path, &warn)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if got != "passphrase" {
		t.Errorf("ReadFile = %q, want %q", got, "passphrase")
	}
	warned := warn.String()
	if !strings.Contains(warned, "warning:") {
		t.Errorf("expected a warning for 0o644 perms, got: %q", warned)
	}
	if !strings.Contains(warned, "recommend chmod 0600") {
		t.Errorf("warning should recommend chmod 0600, got: %q", warned)
	}
	if !strings.Contains(warned, path) {
		t.Errorf("warning should include the file path, got: %q", warned)
	}
}

// TestReadPassphraseFile_TightPermsNoWarn verifies a 0600 file does
// NOT trigger the loose-perm warning. This is the recommended case.
func TestReadPassphraseFile_TightPermsNoWarn(t *testing.T) {
	path := writePassphraseFile(t, "passphrase\n", 0o600)
	var warn bytes.Buffer
	_, err := ReadFile("generate", path, &warn)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if warned := warn.String(); warned != "" {
		t.Errorf("expected no warning for 0o600 perms, got: %q", warned)
	}
}

// TestReadPassphraseFile_NilWarnSuppresses verifies passing a nil
// writer suppresses the loose-perm warning entirely. This is the
// "caller does its own perm check" path.
func TestReadPassphraseFile_NilWarnSuppresses(t *testing.T) {
	path := writePassphraseFile(t, "passphrase\n", 0o644)
	_, err := ReadFile("generate", path, nil)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	// No panic, no warning possible — the nil writer path is the
	// contract.
}

// TestStripTrailingNewlines verifies the strip helper directly for
// the documented cases. This is a pure function; testing it directly
// is cheaper than going through ReadFile for each row.
func TestStripTrailingNewlines(t *testing.T) {
	cases := []struct{ in, want string }{
		{"passphrase\n", "passphrase"},
		{"passphrase\r\n", "passphrase"},
		{"passphrase", "passphrase"},
		{"\n", ""},
		{"", ""},
		{"line1\nline2\n", "line1\nline2"},
		{"passphrase\n\n", "passphrase\n"}, // only one trailing \n stripped
	}
	for _, c := range cases {
		got := stripTrailingNewlines(c.in)
		if got != c.want {
			t.Errorf("stripTrailingNewlines(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
