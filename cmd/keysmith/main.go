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
	Short: "Generate a new GPG key (stub)",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintln(cmd.OutOrStdout(), "generate: not implemented yet")
		return nil
	},
}

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

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
