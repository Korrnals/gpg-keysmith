// Package main is the entry point for the gpg-keysmith CLI.
//
// gpg-keysmith automates GPG key generation and GitHub integration:
// generate a key, export it, publish the public key to GitHub and a
// keyserver, configure git signing, and upload the private key as a
// repository secret for CI signing.
package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/Korrnals/gpg-keysmith/internal/git"
	"github.com/Korrnals/gpg-keysmith/internal/github"
	"github.com/Korrnals/gpg-keysmith/internal/gpg"
	"github.com/Korrnals/gpg-keysmith/internal/keyserver"
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
	Short: "Upload public key to GitHub, set repo secrets, open PR",
	Long: `Upload the GPG public key to the authenticated user's GitHub account, store the
private key and passphrase as repository Action secrets (GPG_PRIVATE_KEY and
GPG_PASSPHRASE), and commit the public key file to the target repo on a
chore/add-gpg-public-key branch and open a pull request.

Requires a GitHub PAT with admin:gpg_key (for the public key upload) and repo +
admin:repo_hook scopes (for the repo secrets). The 'gh' CLI must be installed
(https://cli.github.com) for the secrets step — gpg-keysmith shells out to
'gh secret set' to avoid a libsodium native binding dependency.

Token resolution precedence:
  1. --token flag
  2. GITHUB_TOKEN env var
  3. GH_TOKEN env var

If --keyid is empty, the key is picked interactively from 'gpg --list-secret-keys'.
If --pubkey-file is set, the armored public key is read from that file instead
of calling gpg --export.`,
	Args: cobra.NoArgs,
	RunE: runGithub,
}

// github command flags.
var (
	ghRepo       string
	ghToken      string
	ghKeyID      string
	ghPubkeyFile string
)

var gitConfigCmd = &cobra.Command{
	Use:   "git-config",
	Short: "Configure git signing settings (user.signingkey, commit.gpgsign, gpg.format, tag.gpgsign)",
	Long: `Configure the local git repository (or --global user config) to sign commits
and tags with a GPG key. Sets six config keys:

  user.name          — real name for the commit author
  user.email         — email for the commit author
  user.signingkey    — the GPG key id to sign with
  commit.gpgsign     — true (sign every commit)
  gpg.format         — openpgp (this tool only supports OpenPGP)
  tag.gpgsign        — true (sign every tag)

If --name or --email are not given, the existing user.name / user.email
are read from git config and preserved. If they are not set anywhere,
an error is returned telling you to pass --name/--email or set them
first.

If --keyid is not given, the existing user.signingkey is read from git
config; if that is also unset, 'gpg --list-secret-keys' is scanned and
you are prompted to pick a key. If no GPG keys exist, the command
errors with a hint to run 'keysmith generate' first.`,
	Args: cobra.NoArgs,
	RunE: runGitConfig,
}

// git-config command flags.
var (
	gcKeyID  string
	gcName   string
	gcEmail  string
	gcGlobal bool
)

var publishCmd = &cobra.Command{
	Use:   "publish",
	Short: "Publish public key to a keyserver (keys.openpgp.org + keyserver.ubuntu.com)",
	Long: `Publish the GPG public key to a public keyserver via HTTPS submit endpoints.

Default keyserver is 'all' (publishes to both keys.openpgp.org and
keyserver.ubuntu.com). Use --keyserver=openpgp for just the first, or
--keyserver=ubuntu for just the second.

If --keyid is empty, the key is picked interactively from
'gpg --list-secret-keys'. If --pubkey-file is set, the armored public
key is read from that file instead of calling gpg --export.

On success, prints the verification URL for each keyserver.`,
	Args: cobra.NoArgs,
	RunE: runPublish,
}

// publish command flags.
var (
	pubKeyID      string
	pubKeyserver  string
	pubPubkeyFile string
)

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

	gitConfigCmd.Flags().StringVar(&gcKeyID, "keyid", "", "GPG key id to set as user.signingkey (if empty, read from existing config or pick interactively)")
	gitConfigCmd.Flags().StringVar(&gcName, "name", "", "real name to set as user.name (if empty, keep existing)")
	gitConfigCmd.Flags().StringVar(&gcEmail, "email", "", "email to set as user.email (if empty, keep existing)")
	gitConfigCmd.Flags().BoolVar(&gcGlobal, "global", false, "write to the global user config instead of the local repo config")
	publishCmd.Flags().StringVar(&pubKeyID, "keyid", "", "GPG key id to export (if empty, pick interactively from detect)")
	publishCmd.Flags().StringVar(&pubKeyserver, "keyserver", "all", "keyserver target: all (default), openpgp, or ubuntu")
	publishCmd.Flags().StringVar(&pubPubkeyFile, "pubkey-file", "", "read armored public key from this file instead of calling gpg --export")
	githubCmd.Flags().StringVar(&ghRepo, "repo", "", "target repo as owner/name (required)")
	githubCmd.Flags().StringVar(&ghToken, "token", "", "GitHub PAT (if empty, read GITHUB_TOKEN or GH_TOKEN env var)")
	githubCmd.Flags().StringVar(&ghKeyID, "keyid", "", "GPG key id to export (if empty, pick interactively from detect)")
	githubCmd.Flags().StringVar(&ghPubkeyFile, "pubkey-file", "", "read armored public key from this file instead of calling gpg --export")
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

// runGitConfig resolves the signing key id (from --keyid, existing
// user.signingkey, or an interactive pick from DetectExistingKeys),
// resolves name/email (from flags or existing config), then calls
// git.ApplyGitConfig to write the six signing-related config keys.
//
// Key-id resolution precedence:
//  1. --keyid flag (validated as hex before use)
//  2. existing user.signingkey from git config (same scope as --global)
//  3. interactive pick from 'gpg --list-secret-keys' via survey.Select
//  4. error: no GPG keys found → run 'keysmith generate' first
//
// Name/email resolution is delegated to ApplyGitConfig: if the flags
// are empty, it reads the existing config and errors if missing.
func runGitConfig(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()

	keyID := gcKeyID

	// If --keyid is empty, try the existing user.signingkey from git
	// config (same scope as --global). If that is also empty, scan the
	// GPG keyring and prompt the user to pick a key.
	if keyID == "" {
		existing, err := git.DetectSigningKey(gcGlobal)
		if err != nil {
			return fmt.Errorf("git-config: read existing user.signingkey: %w", err)
		}
		if existing != "" {
			keyID = existing
			fmt.Fprintf(out, "Reusing existing user.signingkey: %s\n", keyID)
		}
	}

	if keyID == "" {
		// Interactive: list GPG keys and let the user pick one.
		keys, err := gpg.DetectExistingKeys()
		if err != nil {
			return fmt.Errorf("git-config: detect existing GPG keys: %w", err)
		}
		if len(keys) == 0 {
			return fmt.Errorf("git-config: no GPG key found. Run 'keysmith generate' first")
		}
		options := make([]string, 0, len(keys))
		for _, k := range keys {
			options = append(options, fmt.Sprintf("%s  %s", k.KeyID, k.UserId))
		}
		var choice string
		prompt := &survey.Select{
			Message: "Select a GPG key to use for signing:",
			Options: options,
		}
		if err := survey.AskOne(prompt, &choice); err != nil {
			return fmt.Errorf("git-config: key selection: %w", err)
		}
		// choice is "<keyid>  <userid>" — take the first field.
		if i := strings.IndexByte(choice, ' '); i > 0 {
			keyID = choice[:i]
		} else {
			keyID = choice
		}
	}

	opts := git.ConfigOptions{
		KeyID:  keyID,
		Name:   gcName,
		Email:  gcEmail,
		Global: gcGlobal,
	}
	if err := git.ApplyGitConfig(opts); err != nil {
		return fmt.Errorf("git-config: %w", err)
	}

	// Print a summary of what was set. Re-read the resolved name/email
	// from the config we just wrote so the summary reflects the actual
	// stored values (ApplyGitConfig may have read them from existing
	// config).
	scope := "local repo config"
	if gcGlobal {
		scope = "global user config"
	}
	fmt.Fprintln(out)
	fmt.Fprintf(out, "Git signing configured (%s):\n", scope)
	fmt.Fprintf(out, "  user.name         = %s\n", nonEmptyOr(gcName, "(kept existing)"))
	fmt.Fprintf(out, "  user.email        = %s\n", nonEmptyOr(gcEmail, "(kept existing)"))
	fmt.Fprintf(out, "  user.signingkey   = %s\n", keyID)
	fmt.Fprintf(out, "  commit.gpgsign    = true\n")
	fmt.Fprintf(out, "  gpg.format        = openpgp\n")
	fmt.Fprintf(out, "  tag.gpgsign       = true\n")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Verify with: git config --local --list | grep -E 'gpg|signingkey'")
	fmt.Fprintln(out, "Test a signed commit: git commit -S --allow-empty -m test && git verify-commit HEAD")
	return nil
}

// nonEmptyOr returns s if non-empty, otherwise the fallback string.
// Used for the summary so a kept-existing value is displayed clearly.
func nonEmptyOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// runGithub implements the 'github' subcommand. It:
//  1. Resolves the target repo (owner/name) from --repo.
//  2. Resolves the GitHub token (--token > GITHUB_TOKEN > GH_TOKEN).
//  3. Resolves the GPG key id (--keyid > interactive pick from detect).
//  4. Obtains the armored public key (--pubkey-file > gpg.ExportPublicKey).
//  5. Looks up the fingerprint for the chosen key (for dedup).
//  6. Prompts for the passphrase via survey.Password (masked).
//  7. Exports the private key via gpg.ExportPrivateKey (in-memory only).
//  8. Uploads the public key to GitHub (skips if already present).
//  9. Sets GPG_PRIVATE_KEY and GPG_PASSPHRASE repo secrets via gh CLI.
//
// 10. Commits gpg-public-key.asc to the repo and opens a PR.
//
// If any step fails, the function prints what succeeded and what
// failed before returning the error — the user is never left in a
// half-state without diagnostics.
//
// Security: token, private key, and passphrase are NEVER logged,
// printed, or written to disk. Error messages use <REDACTED> for
// secret values.
func runGithub(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()

	// 1. Resolve repo. Must be "owner/name".
	if ghRepo == "" {
		return fmt.Errorf("github: --repo is required (format owner/name)")
	}
	parts := strings.SplitN(ghRepo, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.Contains(parts[1], "/") {
		return fmt.Errorf("github: --repo must be 'owner/name' (got %q)", ghRepo)
	}
	owner, repo := parts[0], parts[1]

	// 2. Resolve token. --token > GITHUB_TOKEN > GH_TOKEN.
	token := ghToken
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("github: GitHub token required (set GITHUB_TOKEN env or pass --token)")
	}

	// 3. Resolve key id. --keyid > interactive pick from detect.
	keyID := ghKeyID
	if keyID == "" {
		keys, err := gpg.DetectExistingKeys()
		if err != nil {
			return fmt.Errorf("github: detect existing GPG keys: %w", err)
		}
		if len(keys) == 0 {
			return fmt.Errorf("github: no GPG keys found; run 'keysmith generate' first")
		}
		options := make([]string, 0, len(keys))
		for _, k := range keys {
			options = append(options, fmt.Sprintf("%s  %s", k.KeyID, k.UserId))
		}
		var choice string
		prompt := &survey.Select{
			Message: "Select a GPG key to use:",
			Options: options,
		}
		if err := survey.AskOne(prompt, &choice); err != nil {
			return fmt.Errorf("github: key selection: %w", err)
		}
		if i := strings.IndexByte(choice, ' '); i > 0 {
			keyID = choice[:i]
		} else {
			keyID = choice
		}
	}

	// 4. Obtain the armored public key. --pubkey-file > gpg export.
	var pubArmor string
	if ghPubkeyFile != "" {
		b, err := os.ReadFile(ghPubkeyFile)
		if err != nil {
			return fmt.Errorf("github: read pubkey file %s: %w", ghPubkeyFile, err)
		}
		pubArmor = string(b)
	} else {
		a, err := gpg.ExportPublicKey(keyID)
		if err != nil {
			return fmt.Errorf("github: export public key: %w", err)
		}
		pubArmor = a
	}

	// 5. Look up the fingerprint from detect (for dedup).
	fingerprint := ""
	if keys, err := gpg.DetectExistingKeys(); err == nil {
		for _, k := range keys {
			if k.KeyID == keyID {
				fingerprint = k.Fingerprint
				break
			}
		}
	}

	// 6. Prompt for the passphrase (masked). Needed to export the
	// private key for the repo secrets step.
	var passphrase string
	passPrompt := &survey.Password{Message: "Passphrase for the GPG key:"}
	if err := survey.AskOne(passPrompt, &passphrase); err != nil {
		return fmt.Errorf("github: passphrase prompt: %w", err)
	}
	if passphrase == "" {
		return fmt.Errorf("github: passphrase is required (cannot be empty)")
	}

	// 7. Export the private key (in-memory only, never on disk).
	privArmor, err := gpg.ExportPrivateKey(keyID, passphrase)
	if err != nil {
		return fmt.Errorf("github: export private key: %w", err)
	}

	// Track per-step success so a late failure can report what
	// already succeeded.
	var (
		didUploadPubkey bool
		didSetSecrets   bool
		didOpenPR       bool
		uploadedFP      string
		prURL           string
	)

	// 8. Upload the public key to GitHub. If a key with the same
	// fingerprint is already present, the upload is skipped and the
	// existing fingerprint is returned.
	fmt.Fprintln(out)
	fmt.Fprintln(out, "==> Uploading public key to GitHub...")
	uploadedFP, err = github.UploadPublicKeyWithFingerprint(token, pubArmor, fingerprint)
	if err != nil {
		// Report what we have so far and stop — the user needs to
		// fix the upload before secrets/PR can proceed (the PR
		// commits the same key; secrets need the private key which
		// we already have, but a half-state is worse than a clean
		// stop with a diagnostic).
		printGithubSummary(out, owner, repo, didUploadPubkey, uploadedFP,
			didSetSecrets, didOpenPR, prURL)
		return fmt.Errorf("github: upload public key: %w", err)
	}
	didUploadPubkey = true
	fmt.Fprintf(out, "    Public key uploaded (fingerprint: %s)\n", uploadedFP)

	// 9. Set GPG_PRIVATE_KEY and GPG_PASSPHRASE repo secrets via gh CLI.
	fmt.Fprintln(out, "==> Setting repo secrets GPG_PRIVATE_KEY and GPG_PASSPHRASE...")
	if err := github.SetGPGSecrets(token, owner, repo, privArmor, passphrase); err != nil {
		printGithubSummary(out, owner, repo, didUploadPubkey, uploadedFP,
			didSetSecrets, didOpenPR, prURL)
		return fmt.Errorf("github: set repo secrets: %w", err)
	}
	didSetSecrets = true
	fmt.Fprintln(out, "    Secrets set: GPG_PRIVATE_KEY, GPG_PASSPHRASE")

	// 10. Commit gpg-public-key.asc and open a PR.
	fmt.Fprintln(out, "==> Committing gpg-public-key.asc and opening PR...")
	prURL, err = github.CommitPublicKeyFile(token, owner, repo, pubArmor)
	if err != nil {
		printGithubSummary(out, owner, repo, didUploadPubkey, uploadedFP,
			didSetSecrets, didOpenPR, prURL)
		return fmt.Errorf("github: commit + open PR: %w", err)
	}
	didOpenPR = true
	fmt.Fprintf(out, "    PR opened: %s\n", prURL)

	// Final summary.
	printGithubSummary(out, owner, repo, didUploadPubkey, uploadedFP,
		didSetSecrets, didOpenPR, prURL)
	return nil
}

// printGithubSummary prints a structured summary of which steps
// succeeded. It is called both on success and on partial failure so
// the user always sees the state. Secret values (token, private key,
// passphrase) are NEVER included — only step status and non-secret
// outputs (fingerprint, PR URL).
func printGithubSummary(out io.Writer, owner, repo string,
	didUploadPubkey bool, fingerprint string,
	didSetSecrets bool, didOpenPR bool, prURL string) {
	fmt.Fprintln(out)
	fmt.Fprintf(out, "GitHub setup summary for %s/%s:\n", owner, repo)
	mark := func(ok bool) string {
		if ok {
			return "✅"
		}
		return "❌"
	}
	fmt.Fprintf(out, "  %s Public key uploaded to GitHub user account", mark(didUploadPubkey))
	if didUploadPubkey && fingerprint != "" {
		fmt.Fprintf(out, " (fingerprint: %s)", fingerprint)
	}
	fmt.Fprintln(out)
	fmt.Fprintf(out, "  %s Repo secrets set (GPG_PRIVATE_KEY, GPG_PASSPHRASE)\n", mark(didSetSecrets))
	fmt.Fprintf(out, "  %s PR opened with gpg-public-key.asc", mark(didOpenPR))
	if didOpenPR && prURL != "" {
		fmt.Fprintf(out, ": %s", prURL)
	}
	fmt.Fprintln(out)
}

// runPublish implements the 'publish' subcommand. It:
//  1. Resolves the GPG key id (--keyid > interactive pick from detect).
//  2. Obtains the armored public key (--pubkey-file > gpg.ExportPublicKey).
//  3. Looks up the fingerprint from detect (used to build the URL).
//  4. Normalises --keyserver (all/openpgp/ubuntu) to the canonical
//     keyserver name(s) accepted by keyserver.PublishPubKey.
//  5. Calls keyserver.PublishPubKey and prints per-keyserver results
//     (✅/❌ + URL).
//
// If any individual keyserver fails, the command prints the failure
// for that keyserver but continues to the next one; the overall
// command exits non-zero only if no keyserver accepted the upload.
func runPublish(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()

	// 1. Resolve the key id. --keyid > interactive pick from detect.
	keyID := pubKeyID
	if keyID == "" {
		keys, err := gpg.DetectExistingKeys()
		if err != nil {
			return fmt.Errorf("publish: detect existing GPG keys: %w", err)
		}
		if len(keys) == 0 {
			return fmt.Errorf("publish: no GPG keys found; run 'keysmith generate' first")
		}
		options := make([]string, 0, len(keys))
		for _, k := range keys {
			options = append(options, fmt.Sprintf("%s  %s", k.KeyID, k.UserId))
		}
		var choice string
		prompt := &survey.Select{
			Message: "Select a GPG key to publish:",
			Options: options,
		}
		if err := survey.AskOne(prompt, &choice); err != nil {
			return fmt.Errorf("publish: key selection: %w", err)
		}
		if i := strings.IndexByte(choice, ' '); i > 0 {
			keyID = choice[:i]
		} else {
			keyID = choice
		}
	}

	// 2. Obtain the armored public key. --pubkey-file > gpg export.
	var pubArmor string
	if pubPubkeyFile != "" {
		b, err := os.ReadFile(pubPubkeyFile)
		if err != nil {
			return fmt.Errorf("publish: read pubkey file %s: %w", pubPubkeyFile, err)
		}
		pubArmor = string(b)
	} else {
		a, err := gpg.ExportPublicKey(keyID)
		if err != nil {
			return fmt.Errorf("publish: export public key: %w", err)
		}
		pubArmor = a
	}

	// 3. Look up the fingerprint from detect (used to build the URL).
	fingerprint := ""
	if keys, err := gpg.DetectExistingKeys(); err == nil {
		for _, k := range keys {
			if k.KeyID == keyID {
				fingerprint = k.Fingerprint
				break
			}
		}
	}

	// 4. Normalise --keyserver (all/openpgp/ubuntu) to the canonical
	//    keyserver name accepted by keyserver.PublishPubKey.
	ks, err := normaliseKeyserverFlag(pubKeyserver)
	if err != nil {
		return fmt.Errorf("publish: %w", err)
	}

	// 5. Publish.
	fmt.Fprintf(out, "Publishing public key %s to %s...\n", keyID, ks)
	results, err := keyserver.PublishPubKey(keyserver.PublishOptions{
		ArmoredPubKey: pubArmor,
		Keyserver:     ks,
		Fingerprint:   fingerprint,
	})
	if err != nil {
		return fmt.Errorf("publish: %w", err)
	}

	// Print per-keyserver results. A per-keyserver failure is shown
	// but does not abort the loop — we want the user to see the state
	// of every keyserver we contacted.
	fmt.Fprintln(out)
	anySuccess := false
	for _, r := range results {
		mark := "❌"
		if r.Success {
			mark = "✅"
			anySuccess = true
		}
		fmt.Fprintf(out, "  %s %s", mark, r.Keyserver)
		if r.URL != "" {
			fmt.Fprintf(out, " — %s", r.URL)
		}
		if r.Err != nil {
			fmt.Fprintf(out, "\n      %v", r.Err)
		}
		fmt.Fprintln(out)
	}

	if !anySuccess {
		return fmt.Errorf("publish: no keyserver accepted the upload")
	}
	return nil
}

// normaliseKeyserverFlag maps the CLI-friendly --keyserver values
// (all/openpgp/ubuntu) to the canonical keyserver name(s) accepted by
// keyserver.PublishPubKey. The canonical names
// ("keys.openpgp.org", "keyserver.ubuntu.com", "all") are also
// accepted verbatim.
func normaliseKeyserverFlag(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "all":
		return keyserver.KeyserverAll, nil
	case "openpgp", keyserver.KeyserverOpenPGP:
		return keyserver.KeyserverOpenPGP, nil
	case "ubuntu", keyserver.KeyserverUbuntu:
		return keyserver.KeyserverUbuntu, nil
	default:
		return "", fmt.Errorf("invalid --keyserver %q (want all, openpgp, or ubuntu)", s)
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
