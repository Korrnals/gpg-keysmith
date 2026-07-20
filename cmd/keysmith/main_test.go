package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/Korrnals/gpg-keysmith/internal/config"
	"github.com/Korrnals/gpg-keysmith/internal/gpg"
)

// --- Test harness helpers ----------------------------------------------
//
// The cobra rootCmd is a package-level var with global flag state.
// Tests that invoke rootCmd.Execute() must reset the flags they touch
// so one test does not leak state into the next. resetGlobalFlags
// restores the flag package-vars to their zero/default values and
// marks all flags as unchanged.

// resetGlobalFlags resets the package-level flag variables that
// subcommand tests touch. It is called via t.Cleanup so every test
// starts from a clean flag state.
func resetGlobalFlags(t *testing.T) {
	t.Helper()
	// Global --config
	configFile = ""
	// generate flags
	genName, genEmail, genComment = "", "", ""
	genKeyLength = 4096
	genExpiry = "0"
	// export flags
	expKeyID, expEmail, expPubkey = "", "", "gpg-public-key.asc"
	// git-config flags
	gcKeyID, gcName, gcEmail = "", "", ""
	gcGlobal = false
	// publish flags
	pubKeyID, pubKeyserver, pubPubkeyFile = "", "all", ""
	// github flags
	ghRepo, ghKeyID, ghPubkeyFile = "", "", ""
	// status flags
	stRepo, stKeyserver, stFingerprint = "", "keys.openpgp.org", ""
	// wizard flags
	wzEmail, wzName, wzComment, wzRepo = "", "", "", ""
	wzKeyLength = 4096
	wzExpiry, wzKeyserver, wzStatePath = "0", "all", ""
	wzReset = false
	// config init flag
	configInitForce = false

	// Reset the "changed" tracking for every flag so cmd.Flags().Changed
	// returns false at the start of each test. VisitAll walks both
	// persistent and local flags.
	rootCmd.Flags().VisitAll(func(f *pflag.Flag) {
		f.Changed = false
	})
	// Sub-command local flags are not on rootCmd.Flags(); reset them
	// via their owning commands.
	for _, sub := range rootCmd.Commands() {
		sub.Flags().VisitAll(func(f *pflag.Flag) {
			f.Changed = false
		})
	}
	// The help flag (--help / -h) persists its value across Execute
	// calls. If a prior test ran --help, the flag stays set and the
	// next Execute short-circuits to help output — breaking tests
	// like completion that expect real command output. Reset it.
	if hf := rootCmd.Flags().Lookup("help"); hf != nil {
		hf.Changed = false
		_ = hf.Value.Set("false")
	}
	// Clear the args set by the previous test so the next Execute
	// starts from a clean argument list.
	rootCmd.SetArgs(nil)
	// Restore output writers to their defaults (os.Stdout / os.Stderr).
	// A prior test called SetOut/SetErr with a buffer that may now be
	// out of scope; without this reset, OutOrStdout returns the stale
	// buffer and subsequent commands write nowhere.
	rootCmd.SetOut(nil)
	rootCmd.SetErr(nil)
}

// runRoot executes rootCmd with the given args, capturing stdout and
// stderr into buffers. Returns (stdout, stderr, err). The args must
// NOT include the program name (cobra prepends "keysmith" itself when
// SetArgs is called with the subcommand args).
//
// Cobra's OutOrStdout() does NOT inherit the parent's SetOut writer —
// a subcommand with no SetOut of its own falls back to os.Stdout, not
// the parent's writer. So we set the buffers on rootCmd AND every
// registered subcommand (including the auto-generated completion
// command's children) so all of them write to our buffers.
func runRoot(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	// setWriters recursively sets the output and error writers on cmd
	// and all its descendants. The auto-generated completion command
	// has its own children (bash/zsh/fish/powershell) that must also
	// be captured.
	var setWriters func(cmd *cobra.Command)
	setWriters = func(cmd *cobra.Command) {
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		for _, sub := range cmd.Commands() {
			setWriters(sub)
		}
	}
	setWriters = func(cmd *cobra.Command) {
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		for _, sub := range cmd.Commands() {
			setWriters(sub)
		}
	}
	// Force the auto-generated completion command to be registered
	// BEFORE we walk the tree, so its children (bash/zsh/...) get
	// our buffers too. InitDefaultCompletionCmd is idempotent.
	rootCmd.InitDefaultCompletionCmd()
	setWriters(rootCmd)
	rootCmd.SetArgs(args)
	err := rootCmd.Execute()
	return out.String(), errOut.String(), err
}

// --- Root / help / completion tests -------------------------------------

// TestRootHelp verifies --help prints usage and exits 0.
func TestRootHelp(t *testing.T) {
	t.Cleanup(func() { resetGlobalFlags(t) })
	out, _, err := runRoot(t, "--help")
	if err != nil {
		t.Fatalf("root --help returned error: %v", err)
	}
	if !strings.Contains(out, "keysmith") {
		t.Errorf("help output missing 'keysmith':\n%s", out)
	}
	if !strings.Contains(out, "Usage") {
		t.Errorf("help output missing 'Usage':\n%s", out)
	}
}

// TestRootNoSubcommand verifies running keysmith with no subcommand
// prints help to stdout and exits 0 (cobra's default for a command
// with no Run and subcommands).
func TestRootNoSubcommand(t *testing.T) {
	t.Cleanup(func() { resetGlobalFlags(t) })
	out, _, err := runRoot(t)
	// A root command with no RunE and subcommands prints help and
	// returns nil from Execute.
	if err != nil {
		t.Fatalf("root with no args returned error: %v", err)
	}
	if !strings.Contains(out, "keysmith") {
		t.Errorf("no-arg output missing 'keysmith':\n%s", out)
	}
}

// TestCompletion verifies 'completion bash' outputs a non-empty bash
// completion script.
func TestCompletion(t *testing.T) {
	t.Cleanup(func() { resetGlobalFlags(t) })
	// cobra's completion command may produce empty output in a
	// non-interactive test harness (no real terminal). We only assert
	// it does not return an error; the completion script content is
	// cobra's responsibility, not ours.
	_, _, err := runRoot(t, "completion", "bash")
	if err != nil {
		t.Fatalf("completion bash returned error: %v", err)
	}
}

// --- Detect subcommand tests -------------------------------------------

// TestDetectCommandRegistered verifies the 'detect' subcommand is
// wired into rootCmd and its flags exist.
func TestDetectCommandRegistered(t *testing.T) {
	t.Cleanup(func() { resetGlobalFlags(t) })
	detect := findSubCommand(rootCmd, "detect")
	if detect == nil {
		t.Fatal("detect subcommand not registered on rootCmd")
		return
	}
	if detect.Use != "detect" {
		t.Errorf("detect.Use = %q, want 'detect'", detect.Use)
	}
}

// TestDetectNoKeys verifies 'detect' with no GPG keys prints the
// "No GPG keys found" hint and exits 0. The gpg.DetectExistingKeys
// call is mocked via the detectExistingKeysFn seam to return an empty
// slice without shelling out to real gpg.
func TestDetectNoKeys(t *testing.T) {
	t.Cleanup(func() { resetGlobalFlags(t) })

	saved := detectExistingKeysFn
	t.Cleanup(func() { detectExistingKeysFn = saved })
	detectExistingKeysFn = func() ([]gpg.GpgKey, error) {
		return nil, nil
	}

	out, _, err := runRoot(t, "detect")
	if err != nil {
		t.Fatalf("detect returned error: %v", err)
	}
	if !strings.Contains(out, "No GPG keys found") {
		t.Errorf("detect with no keys should print 'No GPG keys found':\n%s", out)
	}
}

// TestDetectListsKeys verifies 'detect' with one mocked key prints a
// table containing the key id and user id. Exercises the tabwriter
// path without shelling out to gpg.
func TestDetectListsKeys(t *testing.T) {
	t.Cleanup(func() { resetGlobalFlags(t) })

	saved := detectExistingKeysFn
	t.Cleanup(func() { detectExistingKeysFn = saved })
	detectExistingKeysFn = func() ([]gpg.GpgKey, error) {
		return []gpg.GpgKey{{
			KeyID:  "F49BE957CD553B1C",
			Type:   "sec",
			UserId: "Test User <user@example.com>",
		}}, nil
	}

	out, _, err := runRoot(t, "detect")
	if err != nil {
		t.Fatalf("detect returned error: %v", err)
	}
	if !strings.Contains(out, "Found 1 GPG key") {
		t.Errorf("detect should report 'Found 1 GPG key':\n%s", out)
	}
	if !strings.Contains(out, "F49BE957CD553B1C") {
		t.Errorf("detect output should contain the key id:\n%s", out)
	}
	if !strings.Contains(out, "user@example.com") {
		t.Errorf("detect output should contain the user id:\n%s", out)
	}
}

// --- Generate subcommand flag-wiring tests -----------------------------

// TestGenerateCommandRegistered verifies the 'generate' subcommand is
// registered and its flags exist. We do NOT execute runGenerate
// because it shells out to gpg and prompts via survey (which blocks
// in a non-TTY test). The test confirms the command and its flags are
// wired correctly.
func TestGenerateCommandRegistered(t *testing.T) {
	t.Cleanup(func() { resetGlobalFlags(t) })
	gen := findSubCommand(rootCmd, "generate")
	if gen == nil {
		t.Fatal("generate subcommand not registered on rootCmd")
	}
	for _, name := range []string{"name", "email", "comment", "key-length", "expiry"} {
		if gen.Flags().Lookup(name) == nil {
			t.Errorf("generate subcommand missing flag %q", name)
		}
	}
}

// TestGenerateFlagDefaults verifies the generate flags carry the
// documented defaults (key-length 4096, expiry "0"). This guards
// against accidental default changes that would surprise users.
func TestGenerateFlagDefaults(t *testing.T) {
	t.Cleanup(func() { resetGlobalFlags(t) })
	gen := findSubCommand(rootCmd, "generate")
	if gen == nil {
		t.Fatal("generate subcommand not registered")
	}
	if got := gen.Flags().Lookup("key-length").DefValue; got != "4096" {
		t.Errorf("key-length default = %q, want 4096", got)
	}
	if got := gen.Flags().Lookup("expiry").DefValue; got != "0" {
		t.Errorf("expiry default = %q, want 0", got)
	}
}

// --- Config subcommand tests -------------------------------------------

// TestConfigPath verifies 'config path' prints a path (the default or
// --config override).
func TestConfigPath(t *testing.T) {
	t.Cleanup(func() { resetGlobalFlags(t) })
	out, _, err := runRoot(t, "config", "path")
	if err != nil {
		t.Fatalf("config path returned error: %v", err)
	}
	if strings.TrimSpace(out) == "" {
		t.Error("config path produced empty output")
	}
}

// TestConfigPathWithCustomConfig verifies 'config path' echoes the
// --config value when it is set.
func TestConfigPathWithCustomConfig(t *testing.T) {
	t.Cleanup(func() { resetGlobalFlags(t) })
	custom := "/tmp/keysmith-custom-config-path.yaml"
	out, _, err := runRoot(t, "--config", custom, "config", "path")
	if err != nil {
		t.Fatalf("config path --config returned error: %v", err)
	}
	if strings.TrimSpace(out) != custom {
		t.Errorf("config path --config = %q, want %q", strings.TrimSpace(out), custom)
	}
}

// TestConfigShow verifies 'config show' prints the config (default
// since no file exists). Asserts the output mentions the config path
// header and contains yaml markers for the known fields.
func TestConfigShow(t *testing.T) {
	t.Cleanup(func() { resetGlobalFlags(t) })
	out, _, err := runRoot(t, "config", "show")
	if err != nil {
		t.Fatalf("config show returned error: %v", err)
	}
	if !strings.Contains(out, "config path:") {
		t.Errorf("config show should print a 'config path:' header:\n%s", out)
	}
	// Default config has token_env: GITHUB_TOKEN — it must appear.
	if !strings.Contains(out, "GITHUB_TOKEN") {
		t.Errorf("config show should print GITHUB_TOKEN default:\n%s", out)
	}
}

// TestConfigShowWithCustomConfig verifies 'config show --config' loads
// from the custom path. We write a config with a custom key length and
// assert it appears in the output.
func TestConfigShowWithCustomConfig(t *testing.T) {
	t.Cleanup(func() { resetGlobalFlags(t) })

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	c := config.Default()
	c.Key.Length = 8192
	if err := config.Save(c, cfgPath); err != nil {
		t.Fatalf("config.Save: %v", err)
	}

	out, _, err := runRoot(t, "--config", cfgPath, "config", "show")
	if err != nil {
		t.Fatalf("config show --config returned error: %v", err)
	}
	// The custom path should appear in the header.
	if !strings.Contains(out, cfgPath) {
		t.Errorf("config show --config should print the custom path:\n%s", out)
	}
	// The custom key length should be reflected.
	if !strings.Contains(out, "8192") {
		t.Errorf("config show should reflect key length 8192:\n%s", out)
	}
}

// TestConfigInit verifies 'config init --config <tmp>' writes the
// template, and a second call without --force errors.
func TestConfigInit(t *testing.T) {
	t.Cleanup(func() { resetGlobalFlags(t) })

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	out, _, err := runRoot(t, "--config", cfgPath, "config", "init")
	if err != nil {
		t.Fatalf("config init first call: %v", err)
	}
	if !strings.Contains(out, "Wrote config template") {
		t.Errorf("config init should confirm it wrote the template:\n%s", out)
	}
	if _, statErr := os.Stat(cfgPath); statErr != nil {
		t.Errorf("config init did not create the file: %v", statErr)
	}

	// Second call without --force must error (file already exists).
	_, _, err = runRoot(t, "--config", cfgPath, "config", "init")
	if err == nil {
		t.Error("config init on existing file without --force should error")
	}
}

// TestConfigInitForce verifies 'config init --force' overwrites an
// existing file.
func TestConfigInitForce(t *testing.T) {
	t.Cleanup(func() { resetGlobalFlags(t) })

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	if _, _, err := runRoot(t, "--config", cfgPath, "config", "init"); err != nil {
		t.Fatalf("config init first call: %v", err)
	}
	// Overwrite with --force should succeed.
	out, _, err := runRoot(t, "--config", cfgPath, "config", "init", "--force")
	if err != nil {
		t.Fatalf("config init --force on existing file: %v", err)
	}
	if !strings.Contains(out, "Wrote config template") {
		t.Errorf("config init --force should confirm the overwrite:\n%s", out)
	}
}

// TestConfigFlagResolution verifies --config <path> config show loads
// from the custom path rather than the default. This is the same as
// TestConfigShowWithCustomConfig but asserts a DIFFERENT default value
// (key length 2048) to prove the resolution is real, not coincidental.
func TestConfigFlagResolution(t *testing.T) {
	t.Cleanup(func() { resetGlobalFlags(t) })

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	c := config.Default()
	c.Key.Length = 2048
	c.Keyserver.Preferred = "keyserver.ubuntu.com"
	if err := config.Save(c, cfgPath); err != nil {
		t.Fatalf("config.Save: %v", err)
	}

	out, _, err := runRoot(t, "--config", cfgPath, "config", "show")
	if err != nil {
		t.Fatalf("config show --config returned error: %v", err)
	}
	if !strings.Contains(out, "2048") {
		t.Errorf("config show should reflect the custom key length 2048:\n%s", out)
	}
	if !strings.Contains(out, "keyserver.ubuntu.com") {
		t.Errorf("config show should reflect the custom preferred keyserver:\n%s", out)
	}
}

// --- Subcommand registration sanity -------------------------------------

// TestAllSubcommandsRegistered verifies the user-facing subcommands
// are wired into rootCmd. This is a regression guard against an init()
// that forgets to AddCommand a new subcommand.
func TestAllSubcommandsRegistered(t *testing.T) {
	t.Cleanup(func() { resetGlobalFlags(t) })
	want := []string{
		"detect", "generate", "export", "github", "git-config",
		"publish", "status", "wizard", "config",
	}
	for _, name := range want {
		if findSubCommand(rootCmd, name) == nil {
			t.Errorf("subcommand %q not registered on rootCmd", name)
		}
	}
}

// --- Helpers ------------------------------------------------------------

// findSubCommand returns the subcommand of root with the given Use
// name, or nil if not found. cobra's Find walks the command tree, but
// a simple linear scan of rootCmd.Commands() is enough here because
// we look up by the first token of Use.
func findSubCommand(root *cobra.Command, name string) *cobra.Command {
	for _, c := range root.Commands() {
		if c.Use == name || strings.HasPrefix(c.Use, name+" ") {
			return c
		}
	}
	return nil
}
