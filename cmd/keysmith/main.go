// Package main is the entry point for the gpg-keysmith CLI.
//
// gpg-keysmith automates GPG key generation and GitHub integration:
// generate a key, export it, publish the public key to GitHub and a
// keyserver, configure git signing, and upload the private key as a
// repository secret for CI signing.
package main

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/Korrnals/gpg-keysmith/internal/gpg"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "keysmith",
	Short: "Automated GPG key generation and GitHub integration",
	Long: `gpg-keysmith walks a developer from "no GPG key" to "signed commits on GitHub"
in a single guided flow: generate a key, export it, publish the public key to
GitHub and a keyserver, configure git config user.signingkey, and upload the
private key as a repository secret for CI signing.

Run 'keysmith wizard' for the full interactive setup, or 'keysmith detect'
to list existing GPG keys.`,
	SilenceUsage: true,
}

var detectCmd = &cobra.Command{
	Use:   "detect",
	Short: "List existing GPG secret keys for the current user",
	Long: `Detect existing GPG secret keys by parsing 'gpg --list-secret-keys
--keyid-format=long --with-colons'. Prints a table of found keys, or a hint
to run 'gpg-keysmith generate' if none exist.`,
	Args: cobra.NoArgs,
	RunE: runDetect,
}

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a new GPG key",
	Long: `Generate a new GPG key by driving 'gpg --gen-key' with a batch parameter
file. The passphrase is collected via a masked prompt and piped to gpg via
stdin (--pinentry-mode loopback) — it never appears in the batch file,
process args, or logs.

Use --name and --email to skip the interactive prompts for those fields
(non-interactive mode). The passphrase is always prompted via a masked
survey field.`,
	Args: cobra.NoArgs,
	RunE: runGenerate,
}

// generate command flags. Defaults match GenerateOptions defaults.
var (
	genName      string
	genEmail     string
	genComment   string
	genKeyLength int
	genExpiry    string
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export GPG public key to a file and capture the private key in memory",
	Long: `Export the public key for the given key id (or resolved email) to an ASCII-armored
file (default gpg-public-key.asc). The private key is also exported and captured
in memory ONLY — it is never written to disk, never logged, and never printed.
The captured private key is held for use by the 'github' command (M6) to upload
it as a repository secret for CI signing.

Passphrase is collected via a masked prompt — it is never read from a flag
(which would leak via shell history / ps) and never passed to gpg as a CLI
arg (it is piped via stdin with --passphrase-fd 0).`,
	Args: cobra.NoArgs,
	RunE: runExport,
}

// export command flags.
var (
	expKeyID  string
	expEmail  string
	expPubkey string
)

var githubCmd = &cobra.Command{
	Use:   "github",
	Short: "Upload public key, set repo secrets, open PR (stub)",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintln(cmd.OutOrStdout(), "github: not implemented yet")
		return nil
	},
}

var gitConfigCmd = &cobra.Command{
	Use:   "git-config",
	Short: "Configure git signing settings (stub)",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintln(cmd.OutOrStdout(), "git-config: not implemented yet")
		return nil
	},
}

var publishCmd = &cobra.Command{
	Use:   "publish",
	Short: "Publish public key to a keyserver (stub)",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintln(cmd.OutOrStdout(), "publish: not implemented yet")
		return nil
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current GPG + GitHub setup state (stub)",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintln(cmd.OutOrStdout(), "status: not implemented yet")
		return nil
	},
}

var wizardCmd = &cobra.Command{
	Use:   "wizard",
	Short: "Run the full interactive setup wizard (stub)",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintln(cmd.OutOrStdout(), "wizard: not implemented yet")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(
		generateCmd,
		exportCmd,
		githubCmd,
		gitConfigCmd,
		publishCmd,
		detectCmd,
		statusCmd,
		wizardCmd,
	)

	generateCmd.Flags().StringVar(&genName, "name", "", "real name for the key's user id")
	generateCmd.Flags().StringVar(&genEmail, "email", "", "email for the key's user id")
	generateCmd.Flags().StringVar(&genComment, "comment", "", "comment for the key's user id (optional)")
	generateCmd.Flags().IntVar(&genKeyLength, "key-length", 4096, "RSA key length in bits")
	generateCmd.Flags().StringVar(&genExpiry, "expiry", "0", "expiry date spec (0 = never, 2y = 2 years)")

	exportCmd.Flags().StringVar(&expKeyID, "keyid", "", "long-form key id or fingerprint to export")
	exportCmd.Flags().StringVar(&expEmail, "email", "", "email of the key to export (alternative to --keyid)")
	exportCmd.Flags().StringVar(&expPubkey, "pubkey", "gpg-public-key.asc", "output path for the ASCII-armored public key")
}

func runDetect(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	keys, err := gpg.DetectExistingKeys()
	if err != nil {
		return fmt.Errorf("detect: %w", err)
	}
	if len(keys) == 0 {
		fmt.Fprintln(out, "No GPG keys found. Run 'gpg-keysmith generate' to create one.")
		return nil
	}
	fmt.Fprintf(out, "Found %d GPG key(s):\n\n", len(keys))
	tw := tabwriter.NewWriter(out, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  KEY ID\tTYPE\tCREATED\tEXPIRES\tUSER ID")
	for _, k := range keys {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n",
			k.KeyID,
			k.Type,
			k.Created.Format("2006-01-02 15:04"),
			formatExpiry(k.Expires),
			k.UserId,
		)
	}
	return tw.Flush()
}

func formatExpiry(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.Format("2006-01-02 15:04")
}

// runGenerate collects key parameters via flags + survey prompts, then
// calls gpg.GenerateKey. Required fields (name, email) that were not set
// via flags are collected interactively via survey. The passphrase is
// always prompted via a masked survey.Password field — it is never read
// from a flag (which would leak via shell history / ps).
func runGenerate(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()

	opts := gpg.GenerateOptions{
		Name:      genName,
		Email:     genEmail,
		Comment:   genComment,
		KeyType:   "RSA",
		KeyLength: genKeyLength,
		Expiry:    genExpiry,
	}

	// Collect missing required fields via survey. If --name and --email
	// are both set via flags, we skip the interactive prompts (non-
	// interactive mode). Comment is optional — prompt only if empty.
	if opts.Name == "" {
		prompt := &survey.Input{Message: "Real name for the key:"}
		if err := survey.AskOne(prompt, &opts.Name); err != nil {
			return fmt.Errorf("generate: name prompt: %w", err)
		}
	}
	if opts.Email == "" {
		prompt := &survey.Input{Message: "Email for the key:"}
		if err := survey.AskOne(prompt, &opts.Email); err != nil {
			return fmt.Errorf("generate: email prompt: %w", err)
		}
	}
	if opts.Comment == "" {
		prompt := &survey.Input{Message: "Comment (optional, press Enter to skip):"}
		if err := survey.AskOne(prompt, &opts.Comment); err != nil {
			return fmt.Errorf("generate: comment prompt: %w", err)
		}
	}

	// Passphrase is ALWAYS prompted via a masked survey field — never
	// via a flag (it would leak via shell history / ps). The user must
	// type it each time; --passphrase-file is a later enhancement.
	passphrasePrompt := &survey.Password{Message: "Passphrase for the new key:"}
	if err := survey.AskOne(passphrasePrompt, &opts.Passphrase); err != nil {
		return fmt.Errorf("generate: passphrase prompt: %w", err)
	}
	if opts.Passphrase == "" {
		return fmt.Errorf("generate: passphrase is required (cannot be empty)")
	}

	keyID, err := gpg.GenerateKey(opts)
	if err != nil {
		return fmt.Errorf("generate: %w", err)
	}
	fmt.Fprintf(out, "Generated new GPG key: %s\n", keyID)
	fmt.Fprintln(out, "Run 'keysmith detect' to verify.")
	return nil
}

// runExport resolves the key id (from --keyid, --email, or an interactive
// pick), prompts for the passphrase via a masked survey field, exports
// the public key to the --pubkey path (0644 — it's public, not secret),
// and captures the private key in memory ONLY (never written to disk).
//
// The private key is held in memory for the future 'github' command
// (M6) to upload as a repository secret. For M4 it is simply captured
// and a confirmation is printed — it is never echoed, never logged,
// never written to a file.
func runExport(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()

	// Resolve the key id. Precedence: --keyid flag > --email flag
	// (resolved via DetectKeyForEmail from M2) > interactive pick
	// from DetectExistingKeys.
	keyID := expKeyID
	if keyID == "" {
		if expEmail != "" {
			key, err := gpg.DetectKeyForEmail(expEmail)
			if err != nil {
				return fmt.Errorf("export: detect key for email: %w", err)
			}
			if key == nil {
				return fmt.Errorf("export: no GPG key found for email %q", expEmail)
			}
			keyID = key.KeyID
			fmt.Fprintf(out, "Resolved key id %s for email %s\n", keyID, expEmail)
		}
	}
	if keyID == "" {
		// Interactive: list keys and let the user pick.
		keys, err := gpg.DetectExistingKeys()
		if err != nil {
			return fmt.Errorf("export: detect existing keys: %w", err)
		}
		if len(keys) == 0 {
			return fmt.Errorf("export: no GPG keys found; run 'keysmith generate' first")
		}
		options := make([]string, 0, len(keys))
		for _, k := range keys {
			options = append(options, fmt.Sprintf("%s  %s", k.KeyID, k.UserId))
		}
		var choice string
		prompt := &survey.Select{
			Message: "Select a key to export:",
			Options: options,
		}
		if err := survey.AskOne(prompt, &choice); err != nil {
			return fmt.Errorf("export: key selection: %w", err)
		}
		// choice is "<keyid>  <userid>" — take the first field.
		if i := strings.IndexByte(choice, ' '); i > 0 {
			keyID = choice[:i]
		} else {
			keyID = choice
		}
	}

	// Passphrase is ALWAYS prompted via a masked survey field — never
	// via a flag (would leak via shell history / ps), never via a CLI
	// arg to gpg (would leak via ps/proc). Piped to gpg via stdin.
	var passphrase string
	prompt := &survey.Password{Message: "Passphrase for the key:"}
	if err := survey.AskOne(prompt, &passphrase); err != nil {
		return fmt.Errorf("export: passphrase prompt: %w", err)
	}
	if passphrase == "" {
		return fmt.Errorf("export: passphrase is required (cannot be empty)")
	}

	// Export the public key to disk (0644 — it's public, not secret).
	pubArmor, err := gpg.ExportPublicKey(keyID)
	if err != nil {
		return fmt.Errorf("export: %w", err)
	}
	if err := os.WriteFile(expPubkey, []byte(pubArmor), 0o644); err != nil {
		return fmt.Errorf("export: write public key to %s: %w", expPubkey, err)
	}
	fmt.Fprintf(out, "Public key written to %s\n", expPubkey)

	// Capture the private key in memory ONLY — never written to disk,
	// never logged, never printed. For M4 it is simply captured; M6
	// (github secrets) will consume it. We assert non-empty so a
	// silently-empty export is caught here rather than failing later
	// in M6; the content itself is never inspected or echoed.
	privArmor, err := gpg.ExportPrivateKey(keyID, passphrase)
	if err != nil {
		return fmt.Errorf("export: %w", err)
	}
	if len(privArmor) == 0 {
		return fmt.Errorf("export: private key export returned empty armor (unexpected)")
	}
	// Explicitly clear the in-memory private key copy at the end of
	// the command. We do not zero the string (Go strings are
	// immutable), but we drop our reference so it can be GC'd. The
	// future M6 flow will hold it for the duration of the github
	// upload only.
	_ = privArmor

	// Look up the fingerprint for the confirmation message.
	fingerprint := ""
	if key, err := gpg.DetectKeyForEmail(expEmail); err == nil && key != nil && key.Fingerprint != "" {
		fingerprint = key.Fingerprint
	}
	// If --email wasn't given, try to find the fingerprint by scanning
	// the keyring for the keyid.
	if fingerprint == "" {
		if keys, err := gpg.DetectExistingKeys(); err == nil {
			for _, k := range keys {
				if k.KeyID == keyID {
					fingerprint = k.Fingerprint
					break
				}
			}
		}
	}

	fmt.Fprintln(out)
	fmt.Fprintf(out, "Exported public key:\n")
	fmt.Fprintf(out, "  Key id:      %s\n", keyID)
	if fingerprint != "" {
		fmt.Fprintf(out, "  Fingerprint: %s\n", fingerprint)
	}
	fmt.Fprintf(out, "  Public key:  %s\n", expPubkey)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Private key captured in memory (not written to disk) —")
	fmt.Fprintln(out, "will be used by 'github' command in M6.")
	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
