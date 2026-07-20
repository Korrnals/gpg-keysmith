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
	Short: "Export GPG public/private key material (stub)",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintln(cmd.OutOrStdout(), "export: not implemented yet")
		return nil
	},
}

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

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
