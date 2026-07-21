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
	"gopkg.in/yaml.v3"

	"github.com/Korrnals/gpg-keysmith/internal/config"
	"github.com/Korrnals/gpg-keysmith/internal/git"
	"github.com/Korrnals/gpg-keysmith/internal/github"
	"github.com/Korrnals/gpg-keysmith/internal/gpg"
	"github.com/Korrnals/gpg-keysmith/internal/keyserver"
	passphrasepkg "github.com/Korrnals/gpg-keysmith/internal/passphrase"
	"github.com/Korrnals/gpg-keysmith/internal/status"
	"github.com/Korrnals/gpg-keysmith/internal/wizard"
	"github.com/spf13/cobra"
)

// version is the keysmith build version. It is overridden at build time
// via -ldflags "-X main.version=v$(cat VERSION)" (see the Makefile build
// target). The default "dev" is used by `go run` and `go test` (no
// ldflags injection). cobra's Version field auto-registers a --version / -v
// flag that prints this value.
var version = "dev"

// configFile is the path to the gpg-keysmith config.yaml. Set by the
// global --config flag. An empty value means "use the default path"
// (~/.config/gpg-keysmith/config.yaml), resolved lazily so a missing
// file degrades to Default() without error.
var configFile string

var rootCmd = &cobra.Command{
	Use:   "keysmith",
	Short: "Automated GPG key generation and GitHub integration",
	Long: `gpg-keysmith walks a developer from "no GPG key" to "signed commits on GitHub"
in a single guided flow: generate a key, export it, publish the public key to
GitHub and a keyserver, configure git config user.signingkey, and upload the
private key as a repository secret for CI signing.

Run 'keysmith wizard' for the full interactive setup, or 'keysmith detect'
to list existing GPG keys.`,
	// Version is wired so cobra auto-adds a --version / -v flag that
	// prints "keysmith <version>" and exits 0. The Makefile build target
	// injects the real version via -ldflags "-X main.version=v$(cat VERSION)".
	Version:      version,
	SilenceUsage: true,
}

func init() {
	// Custom version template: "keysmith <version>\n" (cleaner than
	// cobra's default "keysmith version <version>\n"). Set in init() so
	// it applies after cobra has resolved the Version field.
	rootCmd.SetVersionTemplate("keysmith {{.Version}}\n")
}

// loadConfig loads the config from the --config path (or the default
// path if --config is empty). A missing file returns Default() with no
// error, so callers always get a usable Config. A malformed file
// returns an error so the user is not silently running on stale or
// broken defaults.
func loadConfig() (config.Config, error) {
	return config.Load(configFile)
}

// resolveGitHubToken resolves the GitHub PAT from the environment using
// the precedence:
//
//  1. env var named by cfg.GitHub.TokenEnv (default "GITHUB_TOKEN")
//  2. GH_TOKEN env var as fallback
//
// The token is NEVER read from a flag — a --token flag would leak the
// PAT via 'ps' and /proc/cmdline (S1). This wires the previously-dead
// config.TokenEnv field into the real token-resolution path (S5): a
// user can set config.github.token_env: MY_CUSTOM_TOKEN and the tool
// will read MY_CUSTOM_TOKEN from the env.
//
// Returns an error if both env vars are empty so the caller can show a
// clear "set GITHUB_TOKEN or GH_TOKEN env var" message. If cfg.GitHub.TokenEnv
// is empty (config missing or malformed), Default() "GITHUB_TOKEN" is
// used as the primary env var name.
func resolveGitHubToken(cfg config.Config) (string, error) {
	primary := cfg.GitHub.TokenEnv
	if primary == "" {
		primary = "GITHUB_TOKEN"
	}
	if token := os.Getenv(primary); token != "" {
		return token, nil
	}
	if token := os.Getenv("GH_TOKEN"); token != "" {
		return token, nil
	}
	return "", fmt.Errorf("github: GitHub token required (set %s or GH_TOKEN env var)", primary)
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
survey field, UNLESS --passphrase-file <path> is given — then the
passphrase is read from the file (one passphrase, trailing newline
stripped) and the masked prompt is skipped entirely. This is intended
for CI/script usage where no TTY is available. The file should have
0600 perms; keysmith warns to stderr if the perms are looser. A
--passphrase <value> flag is deliberately NOT provided because it
would leak the passphrase via 'ps' and /proc/<pid>/cmdline.`,
	Args: cobra.NoArgs,
	RunE: runGenerate,
}

// generate command flags. Defaults match GenerateOptions defaults.
var (
	genName           string
	genEmail          string
	genComment        string
	genKeyLength      int
	genExpiry         string
	genPassphraseFile string
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
arg (it is piped via stdin with --passphrase-fd 0).

For non-interactive CI/script usage, pass --passphrase-file <path>: the
passphrase is read from the file (one passphrase, trailing newline
stripped) and the masked prompt is skipped entirely. The file should
have 0600 perms; keysmith warns to stderr if the perms are looser. This
only affects the private-key export path; the public-key export does
not need a passphrase and is unaffected.`,
	Args: cobra.NoArgs,
	RunE: runExport,
}

// export command flags.
var (
	expKeyID          string
	expEmail          string
	expPubkey         string
	expPassphraseFile string
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
  1. env var named by config.github.token_env (default GITHUB_TOKEN)
  2. GH_TOKEN env var as fallback

The token is NEVER read from a flag — a --token flag would leak via 'ps'
and /proc/cmdline. Passphrase uses stdin for the same reason; the two
must stay symmetric.

If --keyid is empty, the key is picked interactively from 'gpg --list-secret-keys'.
If --pubkey-file is set, the armored public key is read from that file instead
of calling gpg --export.`,
	Args: cobra.NoArgs,
	RunE: runGithub,
}

// github command flags.
var (
	ghRepo       string
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

// configCmd is the parent for the 'config' subcommand group
// (init / show / path).
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage the gpg-keysmith config file",
	Long: `Manage the gpg-keysmith config file at ~/.config/gpg-keysmith/config.yaml
(or the path passed via --config).

The config holds persistent defaults for key generation, keyserver choice, and
the GitHub PAT env var reference. Subcommands that read config (generate,
publish, github, status, wizard) use its values as defaults; explicit flags
always override config values.

Security: the config NEVER stores the GitHub PAT value — only the env var name
that holds it. The file is mode 0600.

Subcommands:
  keysmith config init   Write a commented template to the config path.
  keysmith config show   Print the current (loaded or default) config.
  keysmith config path   Print the config file path.`,
	Args: cobra.NoArgs,
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Write a commented config template to the config path",
	Long: `Write a commented config.yaml template to the config path (~/.config/gpg-keysmith/config.yaml
by default, or the path passed via --config). The template explains each field
and is safe to edit by hand.

Refuses to overwrite an existing file unless --force is given.`,
	Args: cobra.NoArgs,
	RunE: runConfigInit,
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Print the current config (loaded from the path or defaults)",
	Long: `Print the current config. If a config.yaml exists at the config path (or the
path passed via --config), it is loaded and printed. If no file exists, the
built-in defaults are printed so the user can see what they would get by
running 'keysmith config init'.`,
	Args: cobra.NoArgs,
	RunE: runConfigShow,
}

var configPathCmd = &cobra.Command{
	Use:   "path",
	Short: "Print the config file path",
	Long:  `Print the config file path that keysmith reads (~/.config/gpg-keysmith/config.yaml by default, or the path passed via --config).`,
	Args:  cobra.NoArgs,
	RunE:  runConfigPath,
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current GPG + GitHub setup state",
	Long: `Show the current state of your GPG + GitHub setup with per-step ✅ / ❌ / ⚠️ indicators.

Five checks are performed:
  1. GPG keys        — local gpg keyring (via 'gpg --list-secret-keys')
  2. Git config      — user.signingkey + commit.gpgsign in the local repo
  3. GitHub pubkey   — GPG keys uploaded to your GitHub account
  4. Repo secrets    — GPG_PRIVATE_KEY and GPG_PASSPHRASE on the target repo
  5. Keyserver       — public key published to the keyserver (by fingerprint)

Each check emits a one-line remediation hint when it is not green.

Token resolution precedence:
  1. env var named by config.github.token_env (default GITHUB_TOKEN)
  2. GH_TOKEN env var as fallback

The token is NEVER read from a flag — a --token flag would leak via 'ps'
and /proc/cmdline.

If --repo is omitted, the repo-secrets check degrades to ⚠️.`,
	Args: cobra.NoArgs,
	RunE: runStatus,
}

// status command flags.
var (
	stRepo        string
	stKeyserver   string
	stFingerprint string
)

var wizardCmd = &cobra.Command{
	Use:   "wizard",
	Short: "Run the full interactive setup wizard (detect → generate → export → git-config → github → publish)",
	Long: `Run the full gpg-keysmith setup flow end-to-end. The wizard orchestrates the six
milestones in order: detect existing keys, generate a new key if none, export the
key, configure git signing, upload the public key to GitHub + set repo secrets +
open a PR, and publish the public key to a keyserver.

Each step prompts for confirmation, offers retry/skip/abort on failure, and writes
its completion to ~/.config/gpg-keysmith/state.json so a failed run can be
resumed from the last successful step. On full completion the state file is
cleared.

Flags pre-fill the survey prompts; any flag left empty is collected
interactively. --reset clears the state file and starts fresh. The passphrase
is ALWAYS prompted via a masked survey.Password field (never read from a
flag — that would leak via shell history / ps), UNLESS --passphrase-file
<path> is given — then the passphrase is read from the file and the masked
prompt inside the generate/export steps is skipped entirely. This is intended
for CI/script usage where no TTY is available. The file should have 0600
perms; keysmith warns to stderr if the perms are looser.

Security: the state file NEVER contains the passphrase or the private key.
They are held in memory between steps and discarded at the end of the run.`,
	Args: cobra.NoArgs,
	RunE: runWizard,
}

// wizard command flags.
var (
	wzEmail          string
	wzName           string
	wzComment        string
	wzRepo           string
	wzKeyLength      int
	wzExpiry         string
	wzKeyserver      string
	wzStatePath      string
	wzReset          bool
	wzPassphraseFile string
)

// config subcommand flags.
var configInitForce bool

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
		configCmd,
	)

	// --config is a global flag on the root command so every subcommand
	// can override the default config path. PersistentFlags propagate
	// to all subcommands.
	rootCmd.PersistentFlags().StringVar(&configFile, "config", "",
		"path to the config file (default ~/.config/gpg-keysmith/config.yaml)")

	// config subcommand group.
	configCmd.AddCommand(configInitCmd, configShowCmd, configPathCmd)
	configInitCmd.Flags().BoolVar(&configInitForce, "force", false,
		"overwrite an existing config file")

	generateCmd.Flags().StringVar(&genName, "name", "", "real name for the key's user id")
	generateCmd.Flags().StringVar(&genEmail, "email", "", "email for the key's user id")
	generateCmd.Flags().StringVar(&genComment, "comment", "", "comment for the key's user id (optional)")
	generateCmd.Flags().IntVar(&genKeyLength, "key-length", 4096, "RSA key length in bits")
	generateCmd.Flags().StringVar(&genExpiry, "expiry", "0", "expiry date spec (0 = never, 2y = 2 years)")
	generateCmd.Flags().StringVar(&genPassphraseFile, "passphrase-file", "",
		"read passphrase from this file (non-interactive CI/script usage; skips the masked prompt; file perms warn if looser than 0600)")

	exportCmd.Flags().StringVar(&expKeyID, "keyid", "", "long-form key id or fingerprint to export")
	exportCmd.Flags().StringVar(&expEmail, "email", "", "email of the key to export (alternative to --keyid)")
	exportCmd.Flags().StringVar(&expPubkey, "pubkey", "gpg-public-key.asc", "output path for the ASCII-armored public key")
	exportCmd.Flags().StringVar(&expPassphraseFile, "passphrase-file", "",
		"read passphrase from this file (non-interactive CI/script usage; skips the masked prompt; file perms warn if looser than 0600)")

	gitConfigCmd.Flags().StringVar(&gcKeyID, "keyid", "", "GPG key id to set as user.signingkey (if empty, read from existing config or pick interactively)")
	gitConfigCmd.Flags().StringVar(&gcName, "name", "", "real name to set as user.name (if empty, keep existing)")
	gitConfigCmd.Flags().StringVar(&gcEmail, "email", "", "email to set as user.email (if empty, keep existing)")
	gitConfigCmd.Flags().BoolVar(&gcGlobal, "global", false, "write to the global user config instead of the local repo config")

	wizardCmd.Flags().StringVar(&wzEmail, "email", "", "email for the key + git user.email (prompted if empty)")
	wizardCmd.Flags().StringVar(&wzName, "name", "", "real name for the key + git user.name (prompted if empty)")
	wizardCmd.Flags().StringVar(&wzComment, "comment", "", "optional comment for the key user id (prompted if empty)")
	wizardCmd.Flags().StringVar(&wzRepo, "repo", "", "target GitHub repo as owner/name (prompted if empty)")
	wizardCmd.Flags().IntVar(&wzKeyLength, "key-length", 4096, "RSA key length in bits")
	wizardCmd.Flags().StringVar(&wzExpiry, "expiry", "0", "expiry date spec (0 = never, 2y = 2 years)")
	wizardCmd.Flags().StringVar(&wzKeyserver, "keyserver", "all", "keyserver target: all (default), openpgp, or ubuntu")
	wizardCmd.Flags().StringVar(&wzStatePath, "state-path", "", "override state file location (default ~/.config/gpg-keysmith/state.json)")
	wizardCmd.Flags().BoolVar(&wzReset, "reset", false, "clear the state file and start fresh (ignore prior progress)")
	wizardCmd.Flags().StringVar(&wzPassphraseFile, "passphrase-file", "",
		"read passphrase from this file (non-interactive CI/script usage; skips the masked prompt inside generate/export steps; file perms warn if looser than 0600)")

	publishCmd.Flags().StringVar(&pubKeyID, "keyid", "", "GPG key id to export (if empty, pick interactively from detect)")
	publishCmd.Flags().StringVar(&pubKeyserver, "keyserver", "all", "keyserver target: all (default), openpgp, or ubuntu")
	publishCmd.Flags().StringVar(&pubPubkeyFile, "pubkey-file", "", "read armored public key from this file instead of calling gpg --export")
	statusCmd.Flags().StringVar(&stRepo, "repo", "", "target repo as owner/name (optional — secrets check degrades to ⚠️ if omitted)")
	statusCmd.Flags().StringVar(&stKeyserver, "keyserver", "keys.openpgp.org", "keyserver to check for key publication")
	statusCmd.Flags().StringVar(&stFingerprint, "fingerprint", "", "GPG key fingerprint (optional — derived from first key if empty)")
	githubCmd.Flags().StringVar(&ghRepo, "repo", "", "target repo as owner/name (required)")
	githubCmd.Flags().StringVar(&ghKeyID, "keyid", "", "GPG key id to export (if empty, pick interactively from detect)")
	githubCmd.Flags().StringVar(&ghPubkeyFile, "pubkey-file", "", "read armored public key from this file instead of calling gpg --export")
}

// runConfigInit implements 'keysmith config init'. It writes the
// commented template to the config path, refusing to overwrite an
// existing file unless --force is given.
func runConfigInit(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	path := configFile
	if path == "" {
		p, err := config.DefaultPath()
		if err != nil {
			return fmt.Errorf("config init: resolve default path: %w", err)
		}
		path = p
	}
	if err := config.Init(path, configInitForce); err != nil {
		return fmt.Errorf("config init: %w", err)
	}
	_, _ = fmt.Fprintf(out, "Wrote config template to %s\n", path)
	_, _ = fmt.Fprintln(out, "Edit it by hand, then run 'keysmith config show' to verify.")
	return nil
}

// runConfigShow implements 'keysmith config show'. It loads the
// config (or Default if no file exists) and prints it as YAML.
func runConfigShow(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	c, err := loadConfig()
	if err != nil {
		return fmt.Errorf("config show: %w", err)
	}
	_, _ = fmt.Fprintf(out, "# config path: %s\n", resolveConfigPathForShow())
	data, err := yamlMarshal(c)
	if err != nil {
		return fmt.Errorf("config show: marshal: %w", err)
	}
	_, _ = fmt.Fprint(out, string(data))
	return nil
}

// runConfigPath implements 'keysmith config path'. It prints the
// config file path keysmith reads.
func runConfigPath(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintln(out, resolveConfigPathForShow())
	return nil
}

// resolveConfigPathForShow returns the config path that would be
// loaded — either the --config value or the default path.
func resolveConfigPathForShow() string {
	if configFile != "" {
		return configFile
	}
	p, err := config.DefaultPath()
	if err != nil {
		return "(unable to resolve default path: " + err.Error() + ")"
	}
	return p
}

// yamlMarshal is a thin wrapper kept in main so the config package
// stays free of a yaml import that callers must share. It uses the
// same gopkg.in/yaml.v3 the config package uses.
func yamlMarshal(c config.Config) ([]byte, error) {
	return yaml.Marshal(&c)
}

// detectExistingKeysFn is the function-variable seam for
// gpg.DetectExistingKeys. Tests override it to return canned output
// without shelling out to real gpg. Production code calls it via this
// indirection only in runDetect (the detect subcommand) — other
// subcommands that shell out to gpg are not unit-tested here.
var detectExistingKeysFn = gpg.DetectExistingKeys

// generateKeyFn is the function-variable seam for gpg.GenerateKey.
// Tests override it to assert runGenerate wires opts.Passphrase from
// --passphrase-file without shelling out to real gpg or prompting
// via survey (which would block in a non-TTY test harness). Production
// code calls the real gpg.GenerateKey through this indirection.
var generateKeyFn = gpg.GenerateKey

// The seams below are the same pattern as detectExistingKeysFn /
// generateKeyFn: package-level vars pointing at the real internal/*
// functions, replaced by tests to avoid shelling out to gpg / git /
// gh / keyservers. They keep runExport / runGitConfig / runGithub /
// runPublish / runWizard / runStatus testable end-to-end (flag
// parsing → external call) without a real TTY or real subprocess.
var (
	// gpg seams.
	exportPublicKeyFn             = gpg.ExportPublicKey
	exportPrivateKeyFn            = gpg.ExportPrivateKey
	extractFingerprintFromArmorFn = gpg.ExtractFingerprintFromArmorFile
	detectKeyForEmailFn           = gpg.DetectKeyForEmail

	// git seams.
	applyGitConfigFn   = git.ApplyGitConfig
	detectSigningKeyFn = git.DetectSigningKey

	// github seams.
	uploadPublicKeyWithFingerprintFn = github.UploadPublicKeyWithFingerprint
	setGPGSecretsFn                  = github.SetGPGSecrets
	commitPublicKeyFileFn            = github.CommitPublicKeyFile

	// keyserver seam.
	publishPubKeyFn = keyserver.PublishPubKey

	// wizard seam. RunWizard orchestrates the six steps with resume
	// support; tests replace it to assert the 'wizard' command wires
	// flags into WizardOptions without running real gpg/git/gh.
	runWizardFn = wizard.RunWizard

	// status seam. CollectStatus lives in internal/status and has its
	// own internal seams (detectKeysFn etc.) that are package-private
	// and thus unreachable from cmd/keysmith tests. Hoisting the
	// top-level call lets runStatus be exercised without a real
	// keyring/git/gh/keyserver.
	collectStatusFn = status.CollectStatus

	// surveyAskOneFn is the seam for survey.AskOne. The run* commands
	// prompt interactively for missing flags (name, email, key
	// selection, passphrase). In a non-TTY test harness survey reads
	// EOF from os.Stdin and returns an error, which would abort the
	// command before the hoisted external-call seams run. Tests that
	// exercise the interactive paths replace this with a stub that
	// sets the response and returns nil.
	surveyAskOneFn = survey.AskOne
)

func runDetect(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	keys, err := detectExistingKeysFn()
	if err != nil {
		return fmt.Errorf("detect: %w", err)
	}
	if len(keys) == 0 {
		_, _ = fmt.Fprintln(out, "No GPG keys found. Run 'gpg-keysmith generate' to create one.")
		return nil
	}
	_, _ = fmt.Fprintf(out, "Found %d GPG key(s):\n\n", len(keys))
	tw := tabwriter.NewWriter(out, 2, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "  KEY ID\tTYPE\tCREATED\tEXPIRES\tUSER ID")
	for _, k := range keys {
		_, _ = fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n",
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
// resolved with precedence: --passphrase-file (non-interactive, skips
// the masked prompt) > survey.Password (interactive default). It is
// never read from a --passphrase <value> flag (which would leak via
// shell history / ps).
func runGenerate(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()

	// Apply config defaults for flags the user did not set explicitly.
	// Flags always win — we only fall back to config when the flag is
	// still at its zero value. key-length and expiry are the two
	// generate flags that have a sensible config default; the rest
	// (name, email, comment) are per-key and never persisted.
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("generate: load config: %w", err)
	}
	keyLength := genKeyLength
	if !cmd.Flags().Changed("key-length") && cfg.Key.Length > 0 {
		keyLength = cfg.Key.Length
	}
	expiry := genExpiry
	if !cmd.Flags().Changed("expiry") && cfg.Key.Expire != "" {
		expiry = cfg.Key.Expire
	}

	opts := gpg.GenerateOptions{
		Name:      genName,
		Email:     genEmail,
		Comment:   genComment,
		KeyType:   "RSA",
		KeyLength: keyLength,
		Expiry:    expiry,
	}

	// Collect missing required fields via survey. If --name and --email
	// are both set via flags, we skip the interactive prompts (non-
	// interactive mode). Comment is optional — prompt only if empty.
	if opts.Name == "" {
		prompt := &survey.Input{Message: "Real name for the key:"}
		if err := surveyAskOneFn(prompt, &opts.Name); err != nil {
			return fmt.Errorf("generate: name prompt: %w", err)
		}
	}
	if opts.Email == "" {
		prompt := &survey.Input{Message: "Email for the key:"}
		if err := surveyAskOneFn(prompt, &opts.Email); err != nil {
			return fmt.Errorf("generate: email prompt: %w", err)
		}
	}
	// Comment is optional. In non-interactive mode (--passphrase-file
	// set, indicating a CI/script run without a TTY), skip the prompt
	// entirely — an empty Comment is valid and the survey would block on
	// EOF in a non-TTY environment. In interactive mode, prompt so the
	// user can add a comment or press Enter to skip.
	if opts.Comment == "" && genPassphraseFile == "" {
		prompt := &survey.Input{Message: "Comment (optional, press Enter to skip):"}
		if err := surveyAskOneFn(prompt, &opts.Comment); err != nil {
			return fmt.Errorf("generate: comment prompt: %w", err)
		}
	}

	// Passphrase resolution precedence:
	//   1. --passphrase-file <path> → read from the file, SKIP the
	//      masked survey prompt entirely (non-interactive CI/script
	//      mode). The file path is in argv but the passphrase content
	//      is not — a file does not leak via 'ps' the way a
	//      --passphrase <value> flag would.
	//   2. otherwise → masked survey.Password prompt (interactive
	//      default; requires a real TTY).
	//
	// A --passphrase <value> flag is deliberately NOT provided because
	// it would leak the passphrase via 'ps' and /proc/<pid>/cmdline.
	if genPassphraseFile != "" {
		p, err := passphrasepkg.ReadFile("generate", genPassphraseFile, os.Stderr)
		if err != nil {
			return err
		}
		opts.Passphrase = p
	} else {
		// Interactive: masked survey.Password field — never a flag
		// (would leak via shell history / ps).
		passphrasePrompt := &survey.Password{Message: "Passphrase for the new key:"}
		if err := surveyAskOneFn(passphrasePrompt, &opts.Passphrase); err != nil {
			return fmt.Errorf("generate: passphrase prompt: %w", err)
		}
		if opts.Passphrase == "" {
			return fmt.Errorf("generate: passphrase is required (cannot be empty)")
		}
	}

	keyID, err := generateKeyFn(opts)
	if err != nil {
		return fmt.Errorf("generate: %w", err)
	}
	_, _ = fmt.Fprintf(out, "Generated new GPG key: %s\n", keyID)
	_, _ = fmt.Fprintln(out, "Run 'keysmith detect' to verify.")
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
			key, err := detectKeyForEmailFn(expEmail)
			if err != nil {
				return fmt.Errorf("export: detect key for email: %w", err)
			}
			if key == nil {
				return fmt.Errorf("export: no GPG key found for email %q", expEmail)
			}
			keyID = key.KeyID
			_, _ = fmt.Fprintf(out, "Resolved key id %s for email %s\n", keyID, expEmail)
		}
	}
	if keyID == "" {
		// Interactive: list keys and let the user pick.
		keys, err := detectExistingKeysFn()
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
		if err := surveyAskOneFn(prompt, &choice); err != nil {
			return fmt.Errorf("export: key selection: %w", err)
		}
		// choice is "<keyid>  <userid>" — take the first field.
		if i := strings.IndexByte(choice, ' '); i > 0 {
			keyID = choice[:i]
		} else {
			keyID = choice
		}
	}

	// Passphrase resolution precedence:
	//   1. --passphrase-file <path> → read from the file, SKIP the
	//      masked survey prompt (non-interactive CI/script mode).
	//   2. otherwise → masked survey.Password prompt (interactive
	//      default; requires a real TTY).
	//
	// A --passphrase <value> flag is deliberately NOT provided (S1:
	// leaks via 'ps' / /proc/cmdline). The passphrase is piped to gpg
	// via stdin (--passphrase-fd 0), never as a CLI arg.
	var passphrase string
	if expPassphraseFile != "" {
		p, err := passphrasepkg.ReadFile("export", expPassphraseFile, os.Stderr)
		if err != nil {
			return err
		}
		passphrase = p
	} else {
		prompt := &survey.Password{Message: "Passphrase for the key:"}
		if err := surveyAskOneFn(prompt, &passphrase); err != nil {
			return fmt.Errorf("export: passphrase prompt: %w", err)
		}
		if passphrase == "" {
			return fmt.Errorf("export: passphrase is required (cannot be empty)")
		}
	}

	// Export the public key to disk (0644 — it's public, not secret).
	pubArmor, err := exportPublicKeyFn(keyID)
	if err != nil {
		return fmt.Errorf("export: %w", err)
	}
	if err := os.WriteFile(expPubkey, []byte(pubArmor), 0o644); err != nil {
		return fmt.Errorf("export: write public key to %s: %w", expPubkey, err)
	}
	_, _ = fmt.Fprintf(out, "Public key written to %s\n", expPubkey)

	// Capture the private key in memory ONLY — never written to disk,
	// never logged, never printed. For M4 it is simply captured; M6
	// (github secrets) will consume it. We assert non-empty so a
	// silently-empty export is caught here rather than failing later
	// in M6; the content itself is never inspected or echoed.
	privArmor, err := exportPrivateKeyFn(keyID, passphrase)
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
	if key, err := detectKeyForEmailFn(expEmail); err == nil && key != nil && key.Fingerprint != "" {
		fingerprint = key.Fingerprint
	}
	// If --email wasn't given, try to find the fingerprint by scanning
	// the keyring for the keyid.
	if fingerprint == "" {
		if keys, err := detectExistingKeysFn(); err == nil {
			for _, k := range keys {
				if k.KeyID == keyID {
					fingerprint = k.Fingerprint
					break
				}
			}
		}
	}

	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintf(out, "Exported public key:\n")
	_, _ = fmt.Fprintf(out, "  Key id:      %s\n", keyID)
	if fingerprint != "" {
		_, _ = fmt.Fprintf(out, "  Fingerprint: %s\n", fingerprint)
	}
	_, _ = fmt.Fprintf(out, "  Public key:  %s\n", expPubkey)
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "Private key captured in memory (not written to disk) —")
	_, _ = fmt.Fprintln(out, "will be used by 'github' command in M6.")
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
		existing, err := detectSigningKeyFn(gcGlobal)
		if err != nil {
			return fmt.Errorf("git-config: read existing user.signingkey: %w", err)
		}
		if existing != "" {
			keyID = existing
			_, _ = fmt.Fprintf(out, "Reusing existing user.signingkey: %s\n", keyID)
		}
	}

	if keyID == "" {
		// Interactive: list GPG keys and let the user pick one.
		keys, err := detectExistingKeysFn()
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
		if err := surveyAskOneFn(prompt, &choice); err != nil {
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
	if err := applyGitConfigFn(opts); err != nil {
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
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintf(out, "Git signing configured (%s):\n", scope)
	_, _ = fmt.Fprintf(out, "  user.name         = %s\n", nonEmptyOr(gcName, "(kept existing)"))
	_, _ = fmt.Fprintf(out, "  user.email        = %s\n", nonEmptyOr(gcEmail, "(kept existing)"))
	_, _ = fmt.Fprintf(out, "  user.signingkey   = %s\n", keyID)
	_, _ = fmt.Fprintf(out, "  commit.gpgsign    = true\n")
	_, _ = fmt.Fprintf(out, "  gpg.format        = openpgp\n")
	_, _ = fmt.Fprintf(out, "  tag.gpgsign       = true\n")
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "Verify with: git config --local --list | grep -E 'gpg|signingkey'")
	_, _ = fmt.Fprintln(out, "Test a signed commit: git commit -S --allow-empty -m test && git verify-commit HEAD")
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
//  2. Resolves the GitHub token (env var named by config.github.token_env, then GH_TOKEN).
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
// secret values. The token is never read from a flag (S1) — env-only
// resolution avoids leaking the PAT via 'ps' and /proc/cmdline.
func runGithub(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()

	// Load config once — used for both --repo default and token-env
	// name resolution.
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("github: load config: %w", err)
	}

	// Apply config default for --repo if the user did not set it.
	repo := ghRepo
	if !cmd.Flags().Changed("repo") && repo == "" {
		repo = cfg.GitHub.Repo
	}

	// 1. Resolve repo. Must be "owner/name".
	if repo == "" {
		return fmt.Errorf("github: --repo is required (format owner/name)")
	}
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.Contains(parts[1], "/") {
		return fmt.Errorf("github: --repo must be 'owner/name' (got %q)", ghRepo)
	}
	owner, repo := parts[0], parts[1]

	// 2. Resolve token from the env var named by config.github.token_env
	// (default GITHUB_TOKEN), then GH_TOKEN as fallback. The token is
	// NEVER read from a flag — a --token flag would leak via ps/proc.
	token, err := resolveGitHubToken(cfg)
	if err != nil {
		return err
	}

	// 3. Resolve key id. --keyid > interactive pick from detect.
	keyID := ghKeyID
	if keyID == "" {
		keys, err := detectExistingKeysFn()
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
		if err := surveyAskOneFn(prompt, &choice); err != nil {
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
		a, err := exportPublicKeyFn(keyID)
		if err != nil {
			return fmt.Errorf("github: export public key: %w", err)
		}
		pubArmor = a
	}

	// 5. Look up the fingerprint from detect (for dedup).
	fingerprint := ""
	if keys, err := detectExistingKeysFn(); err == nil {
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
	if err := surveyAskOneFn(passPrompt, &passphrase); err != nil {
		return fmt.Errorf("github: passphrase prompt: %w", err)
	}
	if passphrase == "" {
		return fmt.Errorf("github: passphrase is required (cannot be empty)")
	}

	// 7. Export the private key (in-memory only, never on disk).
	privArmor, err := exportPrivateKeyFn(keyID, passphrase)
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
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "==> Uploading public key to GitHub...")
	uploadedFP, err = uploadPublicKeyWithFingerprintFn(token, pubArmor, fingerprint)
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
	_, _ = fmt.Fprintf(out, "    Public key uploaded (fingerprint: %s)\n", uploadedFP)

	// 9. Set GPG_PRIVATE_KEY and GPG_PASSPHRASE repo secrets via gh CLI.
	_, _ = fmt.Fprintln(out, "==> Setting repo secrets GPG_PRIVATE_KEY and GPG_PASSPHRASE...")
	if err := setGPGSecretsFn(token, owner, repo, privArmor, passphrase); err != nil {
		printGithubSummary(out, owner, repo, didUploadPubkey, uploadedFP,
			didSetSecrets, didOpenPR, prURL)
		return fmt.Errorf("github: set repo secrets: %w", err)
	}
	didSetSecrets = true
	_, _ = fmt.Fprintln(out, "    Secrets set: GPG_PRIVATE_KEY, GPG_PASSPHRASE")

	// 10. Commit gpg-public-key.asc and open a PR.
	_, _ = fmt.Fprintln(out, "==> Committing gpg-public-key.asc and opening PR...")
	prURL, err = commitPublicKeyFileFn(token, owner, repo, pubArmor)
	if err != nil {
		printGithubSummary(out, owner, repo, didUploadPubkey, uploadedFP,
			didSetSecrets, didOpenPR, prURL)
		return fmt.Errorf("github: commit + open PR: %w", err)
	}
	didOpenPR = true
	_, _ = fmt.Fprintf(out, "    PR opened: %s\n", prURL)

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
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintf(out, "GitHub setup summary for %s/%s:\n", owner, repo)
	mark := func(ok bool) string {
		if ok {
			return "✅"
		}
		return "❌"
	}
	_, _ = fmt.Fprintf(out, "  %s Public key uploaded to GitHub user account", mark(didUploadPubkey))
	if didUploadPubkey && fingerprint != "" {
		_, _ = fmt.Fprintf(out, " (fingerprint: %s)", fingerprint)
	}
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintf(out, "  %s Repo secrets set (GPG_PRIVATE_KEY, GPG_PASSPHRASE)\n", mark(didSetSecrets))
	_, _ = fmt.Fprintf(out, "  %s PR opened with gpg-public-key.asc", mark(didOpenPR))
	if didOpenPR && prURL != "" {
		_, _ = fmt.Fprintf(out, ": %s", prURL)
	}
	_, _ = fmt.Fprintln(out)
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
		keys, err := detectExistingKeysFn()
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
		if err := surveyAskOneFn(prompt, &choice); err != nil {
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

		// Validate that the --keyid matches the fingerprint in the
		// pubkey file. Without this, a mismatched --keyid would
		// silently publish the wrong key under a misleading keyid
		// label and report success (e2e bug B1).
		if keyID != "" {
			fileFp, err := extractFingerprintFromArmorFn(pubPubkeyFile)
			if err != nil {
				return fmt.Errorf("publish: validate pubkey file: %w", err)
			}
			if keys, derr := detectExistingKeysFn(); derr == nil {
				for _, k := range keys {
					if k.KeyID == keyID {
						if k.Fingerprint != "" && !strings.EqualFold(k.Fingerprint, fileFp) {
							return fmt.Errorf("publish: --keyid %s (fingerprint %s) does not match the fingerprint in --pubkey-file %s (got %s); refusing to publish a key under a mismatched keyid", keyID, k.Fingerprint, pubPubkeyFile, fileFp)
						}
						break
					}
				}
			}
		}
	} else {
		a, err := exportPublicKeyFn(keyID)
		if err != nil {
			return fmt.Errorf("publish: export public key: %w", err)
		}
		pubArmor = a
	}

	// 3. Look up the fingerprint from detect (used to build the URL).
	fingerprint := ""
	if keys, err := detectExistingKeysFn(); err == nil {
		for _, k := range keys {
			if k.KeyID == keyID {
				fingerprint = k.Fingerprint
				break
			}
		}
	}

	// 4. Normalise --keyserver (all/openpgp/ubuntu) to the canonical
	//    keyserver name accepted by keyserver.PublishPubKey. If the
	//    user did not pass --keyserver, fall back to the config's
	//    preferred keyserver (a single keyserver, not "all", because
	//    config stores one preferred + one fallback).
	ksFlag := pubKeyserver
	if !cmd.Flags().Changed("keyserver") {
		cfg, err := loadConfig()
		if err != nil {
			return fmt.Errorf("publish: load config: %w", err)
		}
		if cfg.Keyserver.Preferred != "" {
			ksFlag = cfg.Keyserver.Preferred
		}
	}
	ks, err := normaliseKeyserverFlag(ksFlag)
	if err != nil {
		return fmt.Errorf("publish: %w", err)
	}

	// 5. Publish.
	_, _ = fmt.Fprintf(out, "Publishing public key %s to %s...\n", keyID, ks)
	results, err := publishPubKeyFn(keyserver.PublishOptions{
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
	_, _ = fmt.Fprintln(out)
	anySuccess := false
	for _, r := range results {
		mark := "❌"
		if r.Success {
			mark = "✅"
			anySuccess = true
		}
		_, _ = fmt.Fprintf(out, "  %s %s", mark, r.Keyserver)
		if r.URL != "" {
			_, _ = fmt.Fprintf(out, " — %s", r.URL)
		}
		if r.Err != nil {
			_, _ = fmt.Fprintf(out, "\n      %v", r.Err)
		}
		_, _ = fmt.Fprintln(out)
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

// runWizard implements the 'wizard' subcommand. It translates the
// CLI flags into a wizard.WizardOptions struct and delegates to
// wizard.RunWizard, which orchestrates the six steps with resume
// support.
//
// --reset clears the state file before starting so a fresh run
// ignores prior progress. Without --reset, the wizard loads the
// existing state and resumes from the last incomplete step.
//
// The passphrase is NEVER read from a --passphrase <value> flag (it
// would leak via shell history / ps). It is collected via
// survey.Password inside the wizard steps and held in memory, never
// written to the state file — UNLESS --passphrase-file <path> is
// given, in which case the passphrase is read from the file and the
// wizard steps skip their masked prompts (non-interactive CI/script
// mode).
func runWizard(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()

	statePath := wzStatePath
	if statePath == "" {
		p, err := wizard.DefaultStatePath()
		if err != nil {
			return fmt.Errorf("wizard: resolve default state path: %w", err)
		}
		statePath = p
	}

	if wzReset {
		if err := wizard.ClearState(statePath); err != nil {
			return fmt.Errorf("wizard: --reset: %w", err)
		}
		_, _ = fmt.Fprintln(out, "State file cleared. Starting fresh.")
	}

	// Apply config defaults for flags the user did not set explicitly.
	// Flags always win; config only fills the gaps.
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("wizard: load config: %w", err)
	}
	keyLength := wzKeyLength
	if !cmd.Flags().Changed("key-length") && cfg.Key.Length > 0 {
		keyLength = cfg.Key.Length
	}
	expiry := wzExpiry
	if !cmd.Flags().Changed("expiry") && cfg.Key.Expire != "" {
		expiry = cfg.Key.Expire
	}
	keyserver := wzKeyserver
	if !cmd.Flags().Changed("keyserver") {
		if cfg.Keyserver.Preferred != "" {
			keyserver = cfg.Keyserver.Preferred
		}
	}
	repo := wzRepo
	if !cmd.Flags().Changed("repo") && repo == "" {
		repo = cfg.GitHub.Repo
	}

	// Passphrase resolution precedence:
	//   1. --passphrase-file <path> → read from the file, populate
	//      opts.Passphrase so the generate/export steps SKIP their
	//      masked survey.Password prompts (non-interactive CI/script
	//      mode). The file path is in argv but the passphrase content
	//      is not — a file does not leak via 'ps' the way a
	//      --passphrase <value> flag would.
	//   2. otherwise → opts.Passphrase is empty, and the wizard
	//      steps prompt via survey.Password (interactive default).
	//
	// A --passphrase <value> flag is deliberately NOT provided (S1:
	// leaks via 'ps' / /proc/cmdline). The passphrase is held in
	// memory and piped to gpg via stdin; it is never written to the
	// state file (json:"-" tag on WizardState.Passphrase).
	var passFromOptions string
	if wzPassphraseFile != "" {
		p, err := passphrasepkg.ReadFile("wizard", wzPassphraseFile, os.Stderr)
		if err != nil {
			return err
		}
		passFromOptions = p
	}

	opts := wizard.WizardOptions{
		Email:     wzEmail,
		Name:      wzName,
		Comment:   wzComment,
		Repo:      repo,
		KeyLength: keyLength,
		Expiry:    expiry,
		Keyserver: keyserver,
		StatePath: statePath,
		// GitHubToken and Passphrase are intentionally NOT wired from
		// --token / --passphrase flags — a flag would leak via 'ps'
		// and /proc/cmdline. The wizard collects the token via the
		// env var named by GitHubTokenEnv (config.github.token_env,
		// default GITHUB_TOKEN), then GH_TOKEN, then a masked prompt
		// (S1/S5). The passphrase is collected via survey.Password
		// inside the wizard steps — UNLESS --passphrase-file was
		// given, in which case it is populated here from the file and
		// the wizard steps skip their prompts.
		GitHubTokenEnv: cfg.GitHub.TokenEnv,
		Passphrase:     passFromOptions,
	}

	_, _ = fmt.Fprintln(out, "Starting gpg-keysmith wizard...")
	_, _ = fmt.Fprintln(out, "State file:", statePath)
	_, _ = fmt.Fprintln(out)
	if err := runWizardFn(opts); err != nil {
		return fmt.Errorf("wizard: %w", err)
	}
	return nil
}

// runStatus implements the 'status' subcommand. It collects the five
// status checks via status.CollectStatus and prints them as a single
// aligned table with per-step ✅ / ❌ / ⚠️ indicators.
func runStatus(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()

	// Load config once — used for --repo/--keyserver defaults and
	// token-env name resolution.
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("status: load config: %w", err)
	}

	// Resolve token from the env var named by config.github.token_env
	// (default GITHUB_TOKEN), then GH_TOKEN as fallback. The token is
	// NEVER read from a flag — env-only resolution avoids leaking the
	// PAT via 'ps' and /proc/cmdline (S1).
	token, err := resolveGitHubToken(cfg)
	if err != nil {
		// status degrades to ⚠️ on missing token rather than failing,
		// so an absent token is not a hard error here. resolveGitHubToken
		// returns an error only when both env vars are empty; we keep
		// the token empty and let CollectStatus emit the ⚠️ rows.
		token = ""
		_ = err
	}

	// Apply config defaults for --repo and --keyserver when the user
	// did not set them.
	repo := stRepo
	keyserverVal := stKeyserver
	if !cmd.Flags().Changed("repo") {
		if repo == "" {
			repo = cfg.GitHub.Repo
		}
	}
	if !cmd.Flags().Changed("keyserver") && cfg.Keyserver.Preferred != "" {
		keyserverVal = cfg.Keyserver.Preferred
	}

	report := collectStatusFn(status.StatusOptions{
		GitHubToken: token,
		Repo:        repo,
		Keyserver:   keyserverVal,
		Fingerprint: stFingerprint,
	})

	rows := []struct {
		label string
		cr    status.CheckResult
	}{
		{"GPG KEYS", report.GpgKeys},
		{"GIT CONFIG", report.GitConfig},
		{"GITHUB PUBKEY", report.GitHubPubKey},
		{"REPO SECRETS", report.RepoSecrets},
		{"KEYSERVER", report.Keyserver},
	}

	tw := tabwriter.NewWriter(out, 2, 4, 2, ' ', 0)
	for _, r := range rows {
		_, _ = fmt.Fprintf(tw, "  %s\t%s\t%s\n", r.label, r.cr.Status, r.cr.Detail)
		if r.cr.Hint != "" {
			_, _ = fmt.Fprintf(tw, "  \t\t→ %s\n", r.cr.Hint)
		}
	}
	return tw.Flush()
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
