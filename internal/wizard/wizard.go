// Package wizard orchestrates the full gpg-keysmith setup flow:
// detect → generate → export → git-config → github → publish. Each
// step is recorded in a state file so a failed run can be resumed
// from the last successful step.
//
// The wizard is the only package allowed to import every other
// internal/ package (gpg, git, github, keyserver). It is the
// orchestrator that ties milestones 2–7 together into a single
// guided flow.
//
// Security invariants enforced by this package:
//   - The state file (~/.config/gpg-keysmith/state.json) contains
//     ONLY step names, key id, email, and repo. It NEVER contains
//     the passphrase or the private key. The Passphrase, PrivateKey,
//     and PubKeyArmor fields on WizardState carry the `json:"-"` tag
//     so they are held in memory between steps but never serialised.
//   - The passphrase is collected once via survey.Password, held in
//
// memory, and passed to the generate/export steps. It is never
// written to disk, never logged, never echoed.
//   - The private key is exported into memory (WizardState.PrivateKey,
//     `json:"-"`) and consumed by the github step. It is never
//
// written to disk.
package wizard

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/Korrnals/gpg-keysmith/internal/git"
	"github.com/Korrnals/gpg-keysmith/internal/github"
	"github.com/Korrnals/gpg-keysmith/internal/gpg"
	"github.com/Korrnals/gpg-keysmith/internal/keyserver"
)

// StepName constants identify the six wizard steps. They are used as
// keys in WizardState.CompletedSteps and in the dispatch map so the
// order is defined exactly once (in stepOrder).
const (
	StepDetect    = "detect"
	StepGenerate  = "generate"
	StepExport    = "export"
	StepGitConfig = "git-config"
	StepGitHub    = "github"
	StepPublish   = "publish"
)

// stepOrder is the canonical execution order. RunWizard iterates this
// slice; the dispatch map looks up the runner by name. Defining the
// order in one place makes the resume logic and the ordering test
// share a single source of truth.
var stepOrder = []string{
	StepDetect,
	StepGenerate,
	StepExport,
	StepGitConfig,
	StepGitHub,
	StepPublish,
}

// WizardState tracks progress across wizard runs so a failed run can
// be resumed from the last successful step. It is persisted as JSON
// at StatePath.
//
// The Passphrase, PrivateKey, and PubKeyArmor fields carry the
// `json:"-"` tag: they are held in memory between steps
// (generate→export→github) but are NEVER written to the state file.
// The security invariant is verified by TestSaveStateOmitsSecrets.
type WizardState struct {
	// Step is the name of the step currently being executed (or the
	// last attempted step if the run aborted). It is informational;
	// CompletedSteps is the source of truth for resume.
	Step string `json:"step"`
	// CompletedSteps is the ordered list of steps that have completed
	// successfully in this or a prior run. RunWizard skips any step
	// whose name is in this slice.
	CompletedSteps []string `json:"completed_steps"`
	// KeyID is the long-form GPG key id once a key is detected or
	// generated. It is carried into the export, git-config, github,
	// and publish steps.
	KeyID string `json:"key_id"`
	// Email is the email associated with the key. Collected once,
	// reused by generate and git-config.
	Email string `json:"email"`
	// Repo is the owner/name of the target GitHub repo once the
	// github step has run (or is about to run).
	Repo string `json:"repo"`
	// GithubKeyID records the integer key id GitHub assigned to the
	// uploaded GPG public key (the id field of the /user/gpg_keys
	// response). Populated when the github step succeeds OR when
	// the preflight finds the subkey already on the account (the
	// 2026-07-22 dogfooded case). Optional: omitted when the user
	// has not yet reached the github step. When set, a re-run of
	// the wizard recognises the github step as already-done at
	// the seam BEFORE the upload — even if CompletedSteps was
	// cleared (e.g. by manual intervention), the preflight
	// short-circuits the POST. Use omitempty so old state files
	// without the field still parse.
	GithubKeyID string `json:"github_key_id,omitempty"`
	// StatePath is where the state is persisted. It is populated by
	// LoadState / RunWizard and used by SaveState.
	StatePath string `json:"-"`

	// Passphrase protects the GPG key. Collected once via
	// survey.Password, held in memory, passed to generate/export.
	// NEVER serialised — `json:"-"` enforces the invariant.
	Passphrase string `json:"-"`
	// PrivateKey is the ASCII-armored private key, exported into
	// memory by the export step and consumed by the github step.
	// NEVER serialised — `json:"-"` enforces the invariant.
	PrivateKey string `json:"-"`
	// PubKeyArmor is the ASCII-armored public key, exported into
	// memory by the export step and consumed by the github and
	// publish steps. It is public material but kept out of the state
	// file to avoid leaving a copy on disk between runs; the github
	// step commits it to the repo, which is the intended durable
	// home. NEVER serialised — `json:"-"`.
	PubKeyArmor string `json:"-"`
}

// WizardOptions carries the user-supplied parameters for a wizard
// run. Any field left empty is collected interactively via survey
// during the relevant step.
type WizardOptions struct {
	// Email is the email for the GPG key user id and git user.email.
	Email string
	// Name is the real name for the GPG key user id and git user.name.
	Name string
	// Comment is the optional comment for the GPG key user id.
	Comment string
	// Repo is the target GitHub repo as "owner/name".
	Repo string
	// GitHubToken is a PAT with admin:gpg_key + repo + admin:repo_hook.
	// If empty, the wizard resolves it from the env var named by
	// GitHubTokenEnv (default GITHUB_TOKEN), then GH_TOKEN, then a
	// masked survey prompt. The token is NEVER read from a CLI flag —
	// a flag would leak via 'ps' and /proc/cmdline (S1).
	GitHubToken string
	// GitHubTokenEnv is the name of the env var that holds the GitHub
	// PAT. Defaults to "GITHUB_TOKEN" when empty. Wires the
	// config.github.token_env field into the wizard's token resolution
	// (S5).
	GitHubTokenEnv string
	// Passphrase protects the GPG key. If empty, it is prompted via
	// survey.Password. It is NEVER written to the state file.
	Passphrase string
	// KeyLength is the RSA key size in bits (default 4096).
	KeyLength int
	// Expiry is the gpg expire-date spec (default "0" = never).
	Expiry string
	// Keyserver is the publish target (all/openpgp/ubuntu).
	Keyserver string
	// StatePath overrides the default state file location
	// (~/.config/gpg-keysmith/state.json).
	StatePath string
}

// DefaultStatePath returns the canonical state file location:
// ~/.config/gpg-keysmith/state.json. It is resolved from
// os.UserHomeDir so it respects HOME on Unix and USERPROFILE on
// Windows.
func DefaultStatePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("wizard: resolve home dir: %w", err)
	}
	return filepath.Join(home, ".config", "gpg-keysmith", "state.json"), nil
}

// LoadState reads the state file at path. If the file does not exist,
// LoadState returns a zero-value WizardState with StatePath set and a
// nil error — a fresh run starts from the detect step.
//
// If the file exists but is malformed, LoadState returns an error so
// a corrupted state is not silently ignored.
func LoadState(path string) (*WizardState, error) {
	state := &WizardState{StatePath: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Fresh run — no prior state. StatePath is set so the
			// first SaveState knows where to write.
			return state, nil
		}
		return nil, fmt.Errorf("wizard: read state %s: %w", path, err)
	}
	if err := json.Unmarshal(data, state); err != nil {
		return nil, fmt.Errorf("wizard: parse state %s: %w", path, err)
	}
	state.StatePath = path
	return state, nil
}

// SaveState writes the state to StatePath as JSON. The parent
// directory is created with 0700 perms if it does not exist. The file
// is written with 0600 perms because it contains the user's email
// and key id (PII), even though it never contains secrets.
//
// Security: the Passphrase, PrivateKey, and PubKeyArmor fields carry
// `json:"-"` and are therefore NEVER written by this function. The
// invariant is verified by TestSaveStateOmitsSecrets.
func SaveState(state *WizardState) error {
	if state.StatePath == "" {
		return fmt.Errorf("wizard: save state: StatePath is empty")
	}
	dir := filepath.Dir(state.StatePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("wizard: create state dir %s: %w", dir, err)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("wizard: marshal state: %w", err)
	}
	if err := os.WriteFile(state.StatePath, data, 0o600); err != nil {
		return fmt.Errorf("wizard: write state %s: %w", state.StatePath, err)
	}
	return nil
}

// ClearState removes the state file. It is called after a fully
// successful run so a subsequent wizard invocation starts fresh. A
// missing file is not an error — clearing an already-cleared state
// is a no-op.
func ClearState(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("wizard: clear state %s: %w", path, err)
	}
	return nil
}

// --- Step runners (dispatch map) ---------------------------------------
//
// stepRunner is the uniform step-function type used by the dispatch
// map. All six steps conform to it; stepDetect simply ignores opts.
// Tests override entries in stepRunners to mock the steps without
// touching gpg/git/github/keyserver.
type stepRunner func(state *WizardState, opts WizardOptions) error

// stepRunners maps StepName → stepRunner. RunWizard looks up each
// step here. Tests replace entries to inject mocks (see
// wizard_test.go). The map is a package var so tests can swap it in
// parallel-safe fashion by saving/restoring the original.
var stepRunners = map[string]stepRunner{
	StepDetect:    stepDetectRunner,
	StepGenerate:  stepGenerateRunner,
	StepExport:    stepExportRunner,
	StepGitConfig: stepGitConfigRunner,
	StepGitHub:    stepGitHubRunner,
	StepPublish:   stepPublishRunner,
}

// --- Function-variable seams for the real step bodies ------------------
//
// The step* functions shell out to real gpg/git/gh binaries. To unit-
// test the step bodies (input handling, state plumbing, branching)
// without spawning those binaries, the calls are routed through
// package-level function variables. Tests override them with mocks
// (save/restore via t.Cleanup) and pre-fill every WizardOptions field
// so no survey prompt fires. Production code calls the real functions
// through this indirection — the only production change is the
// `var xFn = x` hoist plus the `xFn(...)` call site swap.
var (
	gpgDetectExistingKeysFn     = gpg.DetectExistingKeys
	gpgGenerateKeyFn            = gpg.GenerateKey
	gpgExportPublicKeyFn        = gpg.ExportPublicKey
	gpgExportPrivateKeyFn       = gpg.ExportPrivateKey
	gitApplyGitConfigFn         = git.ApplyGitConfig
	githubUploadPublicKeyFn     = github.UploadPublicKeyWithFingerprint
	githubSetGPGSecretsFn       = github.SetGPGSecrets
	githubCommitPublicKeyFileFn = github.CommitPublicKeyFile
	githubListUserGpgKeysFn     = github.ListUserGpgKeys
	keyserverPublishPubKeyFn    = keyserver.PublishPubKey
)

// --- Real step implementations -----------------------------------------
//
// Each stepRunner wrapper delegates to a private step function with
// the signature described in the M8 spec. The wrappers exist so the
// dispatch map has a uniform type; the private functions keep the
// spec's signatures (stepDetect takes no opts; the others do).

// stepDetect calls gpg.DetectExistingKeys. If keys exist, it offers
// to reuse an existing key or generate a new one. If the user chooses
// an existing key, state.KeyID is set and the generate step becomes
// a no-op (the wizard still records it as completed so the resume
// order is preserved).
func stepDetect(state *WizardState) error {
	keys, err := gpgDetectExistingKeysFn()
	if err != nil {
		return fmt.Errorf("detect: %w", err)
	}
	if len(keys) == 0 {
		// No existing keys — generate step will create one.
		fmt.Println("  No existing GPG keys found; a new key will be generated.")
		return nil
	}
	fmt.Printf("  Found %d existing GPG key(s).\n", len(keys))
	options := make([]string, 0, len(keys)+1)
	for _, k := range keys {
		options = append(options, fmt.Sprintf("%s  %s", k.KeyID, k.UserId))
	}
	options = append(options, "Generate a new key")
	var choice string
	prompt := &survey.Select{
		Message: "An existing GPG key was found. Reuse it or generate a new one?",
		Options: options,
	}
	if err := survey.AskOne(prompt, &choice); err != nil {
		return fmt.Errorf("detect: key selection: %w", err)
	}
	if choice == "Generate a new key" {
		// Leave state.KeyID empty so the generate step runs.
		return nil
	}
	// choice is "<keyid>  <userid>" — take the first field.
	if i := strings.IndexByte(choice, ' '); i > 0 {
		state.KeyID = choice[:i]
	} else {
		state.KeyID = choice
	}
	fmt.Printf("  Reusing existing key: %s\n", state.KeyID)
	return nil
}

// stepGenerate calls gpg.GenerateKey with survey-collected params.
// If state.KeyID is already set (an existing key was chosen in the
// detect step), this step is a no-op that succeeds immediately.
func stepGenerate(state *WizardState, opts WizardOptions) error {
	if state.KeyID != "" {
		fmt.Printf("  Skipping key generation — reusing existing key %s.\n", state.KeyID)
		return nil
	}
	// Collect missing identity fields via survey. The passphrase is
	// always prompted via a masked survey.Password field — it is
	// never read from a flag (which would leak via shell history / ps).
	if opts.Name == "" {
		prompt := &survey.Input{Message: "Real name for the key:"}
		if err := survey.AskOne(prompt, &opts.Name); err != nil {
			return fmt.Errorf("generate: name prompt: %w", err)
		}
	}
	if state.Email == "" && opts.Email == "" {
		prompt := &survey.Input{Message: "Email for the key:"}
		if err := survey.AskOne(prompt, &opts.Email); err != nil {
			return fmt.Errorf("generate: email prompt: %w", err)
		}
	}
	if state.Email == "" {
		state.Email = opts.Email
	}
	if state.Passphrase == "" && opts.Passphrase == "" {
		prompt := &survey.Password{Message: "Passphrase for the new key:"}
		if err := survey.AskOne(prompt, &state.Passphrase); err != nil {
			return fmt.Errorf("generate: passphrase prompt: %w", err)
		}
		if state.Passphrase == "" {
			return fmt.Errorf("generate: passphrase is required (cannot be empty)")
		}
	}
	if state.Passphrase == "" {
		state.Passphrase = opts.Passphrase
	}

	genOpts := gpg.GenerateOptions{
		Name:       opts.Name,
		Email:      state.Email,
		Comment:    opts.Comment,
		KeyType:    "RSA",
		KeyLength:  opts.KeyLength,
		Expiry:     opts.Expiry,
		Passphrase: state.Passphrase,
	}
	keyID, err := gpgGenerateKeyFn(genOpts)
	if err != nil {
		return fmt.Errorf("generate: %w", err)
	}
	state.KeyID = keyID
	fmt.Printf("  Generated new GPG key: %s\n", keyID)
	return nil
}

// stepExport calls gpg.ExportPublicKey and gpg.ExportPrivateKey. The
// public key is held in memory (not written to disk by the wizard —
// the github step commits it to the repo). The private key is held
// in WizardState.PrivateKey (`json:"-"`) for the github step. Both
// are never written to the state file.
func stepExport(state *WizardState, opts WizardOptions) error {
	if state.KeyID == "" {
		return fmt.Errorf("export: no key id available (run detect/generate first)")
	}
	// Ensure we have the passphrase for the private-key export. It
	// was collected in generate; if missing (e.g. resuming after a
	// crash with an existing key), prompt now.
	if state.Passphrase == "" && opts.Passphrase == "" {
		prompt := &survey.Password{Message: "Passphrase for the key:"}
		if err := survey.AskOne(prompt, &state.Passphrase); err != nil {
			return fmt.Errorf("export: passphrase prompt: %w", err)
		}
		if state.Passphrase == "" {
			return fmt.Errorf("export: passphrase is required (cannot be empty)")
		}
	}
	if state.Passphrase == "" {
		state.Passphrase = opts.Passphrase
	}

	pubArmor, err := gpgExportPublicKeyFn(state.KeyID)
	if err != nil {
		return fmt.Errorf("export: public key: %w", err)
	}
	privArmor, err := gpgExportPrivateKeyFn(state.KeyID, state.Passphrase)
	if err != nil {
		return fmt.Errorf("export: private key: %w", err)
	}
	// Carry the armored keys in memory for the github step. The
	// public key is committed to the repo by stepGitHub; the private
	// key is uploaded as a repo secret. Neither is written to the
	// state file (json:"-" tags).
	state.PubKeyArmor = pubArmor
	state.PrivateKey = privArmor
	fmt.Printf("  Exported public and private key armor for %s (held in memory).\n", state.KeyID)
	return nil
}

// stepGitConfig calls git.ApplyGitConfig with the resolved key id and
// identity. It writes to the local repo config (Global=false per the
// M8 spec).
func stepGitConfig(state *WizardState, opts WizardOptions) error {
	if state.KeyID == "" {
		return fmt.Errorf("git-config: no key id available")
	}
	gitOpts := git.ConfigOptions{
		KeyID:  state.KeyID,
		Name:   opts.Name,
		Email:  state.Email,
		Global: false,
	}
	if err := gitApplyGitConfigFn(gitOpts); err != nil {
		return fmt.Errorf("git-config: %w", err)
	}
	fmt.Printf("  Git signing configured for key %s (local repo config).\n", state.KeyID)
	return nil
}

// stepGitHub calls github.UploadPublicKeyWithFingerprint,
// github.SetGPGSecrets, and github.CommitPublicKeyFile. It sets
// state.Repo on success. The private key and passphrase come from
// state (held in memory, never persisted).
//
// When the upload returns *github.ErrKeyAlreadyExists (the subkey is
// already on the account — the 2026-07-22 dogfooded case), the
// step records the existing GitHub key id in state.GithubKeyID,
// prints an info message, and returns nil so the orchestrator
// marks the step done. The follow-up steps (setGPGSecrets,
// commit+PR) are still attempted because the user has not yet
// configured them; if they have already been run they no-op on
// GitHub's side (gh secret set is idempotent; committing a public
// key the repo already has will fail in a non-retryable way and
// the wizard will surface that as a normal retry/skip/abort).
// resolveGitHubToken resolves the GitHub PAT from WizardOptions and
// the environment, prompting via survey as a last resort. Resolution
// order: opts.GitHubToken > env var named by opts.GitHubTokenEnv
// (default GITHUB_TOKEN) > GH_TOKEN env var > survey.Password prompt.
// The token is NEVER read from a CLI flag (S1) and the env var name
// is configurable via config.github.token_env (S5).
//
// Extracted from stepGitHub so the re-run short-circuit re-validation
// (issue #22) can resolve the token without duplicating the chain.
func resolveGitHubToken(opts WizardOptions) (string, error) {
	token := opts.GitHubToken
	if token == "" {
		primary := opts.GitHubTokenEnv
		if primary == "" {
			primary = "GITHUB_TOKEN"
		}
		token = os.Getenv(primary)
	}
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	if token == "" {
		prompt := &survey.Password{Message: "GitHub PAT (admin:gpg_key + repo):"}
		if err := survey.AskOne(prompt, &token); err != nil {
			return "", fmt.Errorf("github: token prompt: %w", err)
		}
	}
	if token == "" {
		return "", fmt.Errorf("github: token is required")
	}
	return token, nil
}

func stepGitHub(state *WizardState, opts WizardOptions) error {
	if state.KeyID == "" {
		return fmt.Errorf("github: no key id available")
	}
	if state.PubKeyArmor == "" {
		return fmt.Errorf("github: no public key armor in memory (run export first)")
	}
	// Re-run short-circuit: on a re-run with
	// state.GithubKeyID set, the subkey was already confirmed
	// on the account in a prior run. We skip the entire step
	// (upload + secrets + PR) — none of them would do useful
	// work:
	//   - upload: the POST is guaranteed to 422 again with the
	//     same subkey-already-exists body.
	//   - secrets: gh secret set is idempotent but produces
	//     redundant network traffic and noisy "already set"
	//     output on the user's terminal.
	//   - PR: committing a public key the repo already has is
	//     not a no-op — `gh pr create` will fail with a
	//     "nothing to commit" error and surface a confusing
	//     retry prompt.
	// So we skip everything for correctness (no false error to
	// the operator) and for observability (no spurious "already
	// set" output). The step is recorded as done; state.Repo is
	// preserved so downstream steps know the target.
	//
	// This branch is reached only when the prior runWizard
	// recorded state.GithubKeyID (after a 422 fallback). If
	// the prior run failed mid-step, the state file does not
	// contain GithubKeyID and the normal path below runs.
	//
	// Re-validation (issue #22): before trusting the cached
	// key id, confirm it is still on the account under the
	// current token. If the token has been rotated, the key
	// has been deleted from GitHub, or the state file was
	// authored by a different account, the cached id no
	// longer refers to a key the current token can see —
	// silently skipping would mis-inform the user and proceed
	// to setGPGSecrets / commitPublicKeyFile on the wrong
	// account. This mirrors the defence the 422-fallback path
	// already applies (it calls listUserGpgKeys after a 422
	// to confirm which key holds the subkey).
	if state.GithubKeyID != "" {
		token, terr := resolveGitHubToken(opts)
		if terr != nil {
			// No token available — we cannot re-validate.
			// Be lenient (match the network-error policy
			// below): trust the state, short-circuit as
			// today. The follow-up steps would re-prompt
			// for the token if they actually ran, but we
			// are skipping them, so the missing token is
			// not surfaced here.
			fmt.Printf("      ⚠️ Could not re-validate GitHub key %s (no token available: %v). Trusting state.\n",
				state.GithubKeyID, terr)
			if opts.Repo != "" {
				state.Repo = opts.Repo
			}
			return nil
		}
		keys, lerr := githubListUserGpgKeysFn(token)
		if lerr != nil {
			// Network / API error — be lenient,
			// trust the state, log a warning, and
			// short-circuit. This matches the issue's
			// proposed policy: a transient API failure
			// must not force a redundant upload the user
			// cannot verify either.
			fmt.Printf("      ⚠️ Could not re-validate GitHub key %s (network error: %v). Trusting state.\n",
				state.GithubKeyID, lerr)
			if opts.Repo != "" {
				state.Repo = opts.Repo
			}
			return nil
		}
		if github.FindExistingByKeyID(keys, state.GithubKeyID) == nil {
			// The cached key id is no longer on the
			// account under the current token. Clear
			// it and fall through to the normal
			// upload path so the user is correctly
			// informed and the upload runs against
			// the current account.
			fmt.Printf("      ⚠️ GitHub key %s is no longer on the account under the current token. Re-running upload.\n",
				state.GithubKeyID)
			state.GithubKeyID = ""
		} else {
			// Key confirmed — short-circuit as today.
			fmt.Printf("      Public key already on GitHub as key %s (confirmed via API). Skipping upload.\n",
				state.GithubKeyID)
			if opts.Repo != "" {
				state.Repo = opts.Repo
			}
			return nil
		}
	}
	// Resolve repo. opts.Repo > state.Repo > survey prompt.
	repo := opts.Repo
	if repo == "" {
		repo = state.Repo
	}
	if repo == "" {
		prompt := &survey.Input{Message: "Target GitHub repo (owner/name):"}
		if err := survey.AskOne(prompt, &repo); err != nil {
			return fmt.Errorf("github: repo prompt: %w", err)
		}
	}
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.Contains(parts[1], "/") {
		return fmt.Errorf("github: repo must be 'owner/name' (got %q)", repo)
	}
	owner, name := parts[0], parts[1]

	// Resolve token. opts.GitHubToken > env var named by
	// opts.GitHubTokenEnv (default GITHUB_TOKEN) > GH_TOKEN env var
	// > survey prompt. The token is NEVER read from a CLI flag (S1)
	// and the env var name is configurable via config.github.token_env
	// (S5).
	token, err := resolveGitHubToken(opts)
	if err != nil {
		return err
	}

	// Look up the fingerprint from detect for dedup.
	fingerprint := ""
	if keys, err := gpgDetectExistingKeysFn(); err == nil {
		for _, k := range keys {
			if k.KeyID == state.KeyID {
				fingerprint = k.Fingerprint
				break
			}
		}
	}

	fmt.Println("  ==> Uploading public key to GitHub...")
	uploadedFP, err := githubUploadPublicKeyFn(token, state.PubKeyArmor, fingerprint)
	// *github.ErrKeyAlreadyExists is the typed "the subkey is
	// already on the account" signal. The 2026-07-22 dogfooded case
	// is exactly this: korrnals added a GPG key to GitHub for
	// commit signing, then ran the wizard on the gpg-keysmith repo
	// itself. The subkey was already on the account; GitHub
	// returned 422 with `code: custom` + "one or more subkeys
	// already exist". Treat as success: record the existing key
	// id in state (so a re-run short-circuits the upload), print
	// an info line, and continue to the secrets + PR steps. We
	// deliberately do NOT offer retry — the server-side state
	// will not change between retries.
	var keyExists *github.ErrKeyAlreadyExists
	switch {
	case err == nil:
		// Normal upload succeeded.
		fmt.Printf("      Public key uploaded (fingerprint: %s)\n", uploadedFP)
	case errors.As(err, &keyExists):
		// Subkey already on the account under another key. The
		// signing pipeline will work — the goal of this step is
		// achieved. Persist the discovered key id so a re-run
		// does not even attempt the upload (the preflight at
		// the top of this function short-circuits on the
		// second run).
		state.GithubKeyID = keyExists.KeyID
		fmt.Printf("      Public key subkey %s is already on GitHub as key %s (%s). Marking github step as done.\n",
			keyExists.Fingerprint, keyExists.KeyID, strings.Join(keyExists.Emails, ", "))
	default:
		return fmt.Errorf("github: upload public key: %w", err)
	}

	fmt.Println("  ==> Setting repo secrets GPG_PRIVATE_KEY and GPG_PASSPHRASE...")
	if err := githubSetGPGSecretsFn(token, owner, name, state.PrivateKey, state.Passphrase); err != nil {
		return fmt.Errorf("github: set repo secrets: %w", err)
	}
	fmt.Println("      Secrets set: GPG_PRIVATE_KEY, GPG_PASSPHRASE")

	fmt.Println("  ==> Committing gpg-public-key.asc and opening PR...")
	prURL, err := githubCommitPublicKeyFileFn(token, owner, name, state.PubKeyArmor)
	if err != nil {
		return fmt.Errorf("github: commit + open PR: %w", err)
	}
	fmt.Printf("      PR opened: %s\n", prURL)

	state.Repo = repo
	return nil
}

// stepPublish calls keyserver.PublishPubKey with the armored public
// key held in memory. It prints per-keyserver results.
func stepPublish(state *WizardState, opts WizardOptions) error {
	if state.PubKeyArmor == "" {
		return fmt.Errorf("publish: no public key armor in memory (run export first)")
	}
	ks := opts.Keyserver
	if ks == "" {
		ks = keyserver.KeyserverAll
	}
	// Look up the fingerprint for the verification URL.
	fingerprint := ""
	if keys, err := gpgDetectExistingKeysFn(); err == nil {
		for _, k := range keys {
			if k.KeyID == state.KeyID {
				fingerprint = k.Fingerprint
				break
			}
		}
	}
	results, err := keyserverPublishPubKeyFn(keyserver.PublishOptions{
		ArmoredPubKey: state.PubKeyArmor,
		Keyserver:     ks,
		Fingerprint:   fingerprint,
	})
	if err != nil {
		return fmt.Errorf("publish: %w", err)
	}
	anySuccess := false
	for _, r := range results {
		mark := "❌"
		if r.Success {
			mark = "✅"
			anySuccess = true
		}
		fmt.Printf("    %s %s", mark, r.Keyserver)
		if r.URL != "" {
			fmt.Printf(" — %s", r.URL)
		}
		if r.Err != nil {
			fmt.Printf("\n      %v", r.Err)
		}
		fmt.Println()
	}
	if !anySuccess {
		return fmt.Errorf("publish: no keyserver accepted the upload")
	}
	return nil
}

// --- Dispatch wrappers (uniform signature for the map) -----------------

func stepDetectRunner(state *WizardState, _ WizardOptions) error {
	return stepDetect(state)
}

func stepGenerateRunner(state *WizardState, opts WizardOptions) error {
	return stepGenerate(state, opts)
}

func stepExportRunner(state *WizardState, opts WizardOptions) error {
	return stepExport(state, opts)
}

func stepGitConfigRunner(state *WizardState, opts WizardOptions) error {
	return stepGitConfig(state, opts)
}

func stepGitHubRunner(state *WizardState, opts WizardOptions) error {
	return stepGitHub(state, opts)
}

func stepPublishRunner(state *WizardState, opts WizardOptions) error {
	return stepPublish(state, opts)
}

// --- Survey prompts for the retry/skip/abort decision -------------------

// askRetrySkipAbort prompts the user for what to do after a step
// failure. Returns one of "retry", "skip", "abort". On a survey error
// (e.g. EOF), it defaults to abort so the wizard does not loop
// forever on a broken TTY.
//
// askRetrySkipAbort is a package var so tests can replace it with a
// deterministic stub that does not touch the TTY.
var askRetrySkipAbort = func(stepName string) string {
	choice := "abort"
	prompt := &survey.Select{
		Message: fmt.Sprintf("Step %q failed. What next?", stepName),
		Options: []string{"retry", "skip", "abort"},
		Default: "retry",
	}
	_ = survey.AskOne(prompt, &choice)
	return choice
}

// askContinue prompts the user to confirm before each step. Returns
// true to proceed, false to abort. On a survey error, it defaults to
// true so a non-interactive run does not stall.
//
// askContinue is a package var so tests can replace it with a
// deterministic stub.
var askContinue = func(stepName string) bool {
	choice := "yes"
	prompt := &survey.Select{
		Message: fmt.Sprintf("Run step %q?", stepName),
		Options: []string{"yes", "no"},
		Default: "yes",
	}
	_ = survey.AskOne(prompt, &choice)
	return choice == "yes"
}

// --- RunWizard: the orchestrator ---------------------------------------

// errStepSkipped is a sentinel returned by runStepWithRetry when the
// user chooses "skip" after a step failure. It lets the orchestrator
// distinguish "step succeeded" (nil) from "step was skipped" (this
// sentinel): a skipped step must NOT be appended to
// CompletedSteps, but the wizard continues to the next step.
type errStepSkipped struct{ step string }

func (e *errStepSkipped) Error() string {
	return "wizard: step " + e.step + " was skipped"
}

// isStepSkipped reports whether err is the skip sentinel.
func isStepSkipped(err error) bool {
	_, ok := err.(*errStepSkipped)
	return ok
}

// RunWizard orchestrates the six steps in order. For each step:
//   - If the step is already in state.CompletedSteps, it is skipped
//     with a "✅ Step <name>: already done" message.
//   - Otherwise the step runner is invoked. On success, the step is
//     appended to CompletedSteps and the state is saved.
//   - On failure, the user is offered retry / skip / abort. Retry
//     re-runs the step. Skip marks the step as skipped (NOT completed)
//     and continues. Abort returns the error.
//
// After all steps complete, the state file is cleared so a subsequent
// run starts fresh.
func RunWizard(opts WizardOptions) error {
	statePath := opts.StatePath
	if statePath == "" {
		p, err := DefaultStatePath()
		if err != nil {
			return fmt.Errorf("wizard: resolve state path: %w", err)
		}
		statePath = p
	}
	state, err := LoadState(statePath)
	if err != nil {
		return fmt.Errorf("wizard: load state: %w", err)
	}
	return runWizardWithState(state, opts)
}

// runWizardWithState is the testable core of RunWizard: it takes a
// pre-loaded state and runs the orchestration loop. Tests call this
// directly to inject a state with pre-completed steps (resume test)
// and to override stepRunners (ordering test).
func runWizardWithState(state *WizardState, opts WizardOptions) error {
	completed := make(map[string]bool, len(state.CompletedSteps))
	for _, s := range state.CompletedSteps {
		completed[s] = true
	}

	for _, name := range stepOrder {
		state.Step = name
		if completed[name] {
			fmt.Printf("✅ Step %s: already done\n", name)
			continue
		}

		// Per-step confirmation. Skip the prompt for already-done
		// steps (handled above) — the user gets a chance to abort
		// before each remaining step.
		if !askContinue(name) {
			return fmt.Errorf("wizard: aborted at step %q", name)
		}

		// Run the step with retry/skip/abort on failure.
		err := runStepWithRetry(state, opts, name)
		if err != nil {
			if isStepSkipped(err) {
				// Skipped: do NOT append to CompletedSteps, do NOT
				// print "done". Continue to the next step.
				continue
			}
			return fmt.Errorf("wizard: step %s: %w", name, err)
		}

		// On success, record and persist.
		state.CompletedSteps = append(state.CompletedSteps, name)
		if err := SaveState(state); err != nil {
			return fmt.Errorf("wizard: save state after step %s: %w", name, err)
		}
		fmt.Printf("✅ Step %s: done\n", name)
	}

	// All steps complete — clear the state so the next run starts
	// fresh and print a summary.
	printSummary(state)
	if err := ClearState(state.StatePath); err != nil {
		return fmt.Errorf("wizard: clear state after completion: %w", err)
	}
	return nil
}

// runStepWithRetry runs a single step, offering retry/skip/abort on
// failure. Retry re-runs the step. Skip returns *errStepSkipped so
// the orchestrator can continue without marking the step completed.
// Abort returns the underlying error.
func runStepWithRetry(state *WizardState, opts WizardOptions, name string) error {
	runner, ok := stepRunners[name]
	if !ok {
		return fmt.Errorf("wizard: no runner registered for step %q", name)
	}
	for {
		err := runner(state, opts)
		if err == nil {
			return nil
		}
		fmt.Printf("❌ Step %s failed: %v\n", name, err)
		switch askRetrySkipAbort(name) {
		case "retry":
			fmt.Printf("  Retrying step %s...\n", name)
			continue
		case "skip":
			fmt.Printf("  Skipping step %s (NOT marked completed).\n", name)
			return &errStepSkipped{step: name}
		default: // "abort"
			return fmt.Errorf("wizard: aborted at step %s: %w", name, err)
		}
	}
}

// printSummary prints a final summary of the completed setup. It
// never includes the passphrase or private key — only non-secret
// outcomes (key id, repo, fingerprints).
func printSummary(state *WizardState) {
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println("  gpg-keysmith wizard — setup complete")
	fmt.Println("═══════════════════════════════════════════")
	if state.KeyID != "" {
		fmt.Printf("  GPG key id:    %s\n", state.KeyID)
	}
	if state.Email != "" {
		fmt.Printf("  Email:         %s\n", state.Email)
	}
	if state.Repo != "" {
		fmt.Printf("  GitHub repo:   %s\n", state.Repo)
	}
	fmt.Printf("  Steps done:    %d (%s)\n",
		len(state.CompletedSteps),
		strings.Join(state.CompletedSteps, " → "))
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println()
	fmt.Println("State file cleared. Re-run 'keysmith wizard' to start fresh.")
}
