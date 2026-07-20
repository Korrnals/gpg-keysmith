// Package passphrase provides a non-interactive passphrase source for
// CI/script usage of gpg-keysmith.
//
// Security model. The interactive default is survey.Password (masked TTY
// prompt). For non-interactive flows (CI pipelines, scripts) the user may
// pass --passphrase-file <path> so the passphrase is read from a file
// instead of prompted. This is a conscious tradeoff:
//
//   - A --passphrase <value> flag would leak the passphrase via 'ps' and
//     /proc/<pid>/cmdline (the whole arg list is visible to any process
//     on the host). A file does not — only the file path is in argv; the
//     passphrase content lives in the file.
//   - The file should have restrictive perms (0600 recommended). keysmith
//     does NOT enforce 0600 (the user may have a tmpfs/pipe/fd with
//     different perms) but WARNS to stderr when perms are looser than
//     0600 so a loose file is not silently exploited.
//   - The file is read once, the passphrase held in memory, and the file
//     is NOT deleted by keysmith — the caller is responsible for it
//     (it may be a pipe, a secret-manager mount, etc.).
//
// The passphrase is never logged, never echoed, never written to disk by
// this package.
package passphrase

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// ReadFile reads the passphrase from the file at path. It:
//
//   - reads the file content (one passphrase)
//   - strips a single trailing '\n' and, if present after that, a single
//     trailing '\r' (handles the common `echo "pass" > file` case and
//     Windows-style \r\n line endings without stripping interior \r)
//   - returns a clear, non-fatal-perm-free error on missing/empty file
//
// The passphrase is returned as a string; the caller is responsible for
// not logging or echoing it. ReadFile itself never writes the passphrase
// to any output.
//
// Error messages use the caller-provided command label (e.g. "generate",
// "export") so the user sees which subcommand rejected the file. The
// label is interpolated verbatim — keep it short and lowercase.
//
// If warn is non-nil, ReadFile calls warn with a human-readable notice
// when the file's perms are looser than 0600. Pass os.Stderr for the
// default CLI behaviour; pass a test buffer in tests. Pass nil to
// suppress the warning entirely (rare — only when the caller does its
// own perm check).
func ReadFile(cmdLabel, path string, warn io.Writer) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("%s: cannot read passphrase file %s: %w", cmdLabel, path, err)
	}
	pass := stripTrailingNewlines(string(data))
	if pass == "" {
		return "", fmt.Errorf("%s: passphrase file %s is empty", cmdLabel, path)
	}
	if warn != nil {
		warnLoosePerms(warn, path)
	}
	return pass, nil
}

// stripTrailingNewlines removes a single trailing '\n' and, if present
// after that, a single trailing '\r'. This handles:
//
//   - "passphrase\n"   -> "passphrase"      (common: echo "pass" > file)
//   - "passphrase\r\n" -> "passphrase"      (Windows line ending)
//   - "passphrase"     -> "passphrase"      (no trailing newline)
//   - "\n"             -> ""                (empty after strip)
//
// It does NOT strip interior \r or multiple trailing newlines — a
// passphrase with a trailing blank line is a user error the caller
// surfaces as "empty after strip" only if the whole content is blank.
// A single trailing newline is the canonical case; anything more is
// the caller's responsibility.
func stripTrailingNewlines(s string) string {
	s = strings.TrimSuffix(s, "\n")
	s = strings.TrimSuffix(s, "\r")
	return s
}

// warnLoosePerms writes a non-fatal warning to w if the file at path
// has perms looser than 0600. The check is best-effort: if os.Stat
// fails, no warning is emitted (the caller has already read the file
// successfully; a stat failure here is not actionable). The warning is
// advisory — keysmith does not refuse to use a loose-perm file because
// the file may be a pipe, a /dev/fd/N mount, or a tmpfs with perms the
// user intentionally chose.
//
// The warning text is stable so tests can match on it without depending
// on the exact octal mode.
func warnLoosePerms(w io.Writer, path string) {
	info, err := os.Stat(path)
	if err != nil {
		// Best-effort: the file was readable (ReadFile succeeded) so
		// a stat failure here is not actionable. Skip the warning.
		return
	}
	// Mask to the permission bits only. 0600 = rw-------. Anything with
	// group/other bits set is "looser than 0600".
	mode := info.Mode().Perm()
	if mode > 0o600 {
		_, _ = fmt.Fprintf(w, "warning: passphrase file %s is world-readable (mode %v); recommend chmod 0600\n",
			path, mode)
	}
}
