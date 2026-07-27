package wizard

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Korrnals/gpg-keysmith/internal/github"
	"github.com/Korrnals/gpg-keysmith/internal/gpg"
)

// TestRunGithubStep_KeyAlreadyExists_MarksDone exercises the
// 2026-07-22 dogfooded scenario: the github step's upload returns
// *github.ErrKeyAlreadyExists. The step must:
//
//   - log an info line naming the existing fingerprint and key id
//   - set state.GithubKeyID to the discovered key id (so a re-run
//     short-circuits the upload entirely via the preflight at the
//     top of stepGitHub)
//   - NOT propagate the error (no retry/skip/abort prompt)
//   - continue to the next wizard step (publish)
//
// We exercise the real stepGitHub with the function-variable seams
// stubbed. No survey prompts fire because every WizardOptions field
// is pre-filled.
func TestRunGithubStep_KeyAlreadyExists_MarksDone(t *testing.T) {
	defer saveStepFns()()

	// Inject a mock github.UploadPublicKeyWithFingerprint that
	// returns *github.ErrKeyAlreadyExists (the dogfooded case).
	githubUploadPublicKeyFn = func(token, armor, fingerprint string) (string, error) {
		return "fd910ba1af89641a", &github.ErrKeyAlreadyExists{
			KeyID:       "72834",
			Emails:      []string{"korrnals@example.com", "korrnals2@example.com"},
			Fingerprint: "fd910ba1af89641a",
		}
	}
	// The follow-up steps (setGPGSecrets, commitPublicKeyFile) must
	// still be called — the user has not necessarily configured
	// those yet. Stub them as no-ops so the test does not depend on
	// the network.
	githubSetGPGSecretsFn = func(token, owner, repo, privKey, passphrase string) error {
		return nil
	}
	githubCommitPublicKeyFileFn = func(token, owner, repo, armor string) (string, error) {
		return "https://github.com/owner/repo/pull/1", nil
	}
	// gpg.DetectExistingKeys is called by stepGitHub to look up
	// the primary fingerprint for dedup. Empty result is fine
	// here — fingerprint stays empty, the seam still returns
	// *ErrKeyAlreadyExists.
	gpgDetectExistingKeysFn = func() ([]gpg.GpgKey, error) {
		return []gpg.GpgKey{{
			KeyID:       "FD910BA1AF89641A",
			Fingerprint: "fd910ba1af89641afd910ba1af89641afd910ba1",
			UserId:      "Korrnals <korrnals@example.com>",
		}}, nil
	}

	state := &WizardState{
		KeyID:       "FD910BA1AF89641A",
		PubKeyArmor: "-----BEGIN PGP PUBLIC KEY BLOCK-----\nMOCK\n-----END-----",
		PrivateKey:  "-----BEGIN PGP PRIVATE KEY BLOCK-----\nMOCK\n-----END-----",
		Passphrase:  "gh-pass",
	}
	opts := WizardOptions{
		Repo:        "owner/repo",
		GitHubToken: "ghp-token",
	}

	// stepGitHub must return nil — the orchestrator treats nil as
	// "step succeeded, mark CompletedSteps" and the next step
	// (publish) runs in the outer test loop.
	if err := stepGitHub(state, opts); err != nil {
		t.Fatalf("stepGitHub with *ErrKeyAlreadyExists must NOT return an error, got: %v", err)
	}

	// The discovered key id is persisted on the state so a re-run
	// short-circuits the upload (the preflight at the top of
	// stepGitHub reads state.GithubKeyID).
	if state.GithubKeyID != "72834" {
		t.Errorf("state.GithubKeyID = %q, want %q (existing GitHub key id)", state.GithubKeyID, "72834")
	}
	// Repo is still set so downstream steps know the target.
	if state.Repo != "owner/repo" {
		t.Errorf("state.Repo = %q, want owner/repo", state.Repo)
	}
}

// TestRunGithubStep_KeyAlreadyExists_RerunShortCircuits verifies the
// second line of defence: when state.GithubKeyID is already set
// (because a prior run hit *ErrKeyAlreadyExists), a re-run of
// stepGitHub must NOT call the upload function at all. The POST is
// guaranteed to 422 again — short-circuiting avoids the wasted
// round-trip and the survey-less "retry?" prompt.
func TestRunGithubStep_KeyAlreadyExists_RerunShortCircuits(t *testing.T) {
	defer saveStepFns()()

	// This MUST NOT be called.
	githubUploadPublicKeyFn = func(token, armor, fingerprint string) (string, error) {
		t.Fatal("uploadPublicKeyFn must NOT be called when state.GithubKeyID is already set")
		return "", nil
	}
	// The follow-up steps (setGPGSecrets, commit) may be called —
	// in the re-run case, they will run normally. Stub them.
	githubSetGPGSecretsFn = func(string, string, string, string, string) error { return nil }
	githubCommitPublicKeyFileFn = func(string, string, string, string) (string, error) {
		return "https://github.com/owner/repo/pull/1", nil
	}
	// Re-validation (issue #22): stepGitHub now calls
	// ListUserGpgKeys before short-circuiting. Inject a mock
	// that confirms the cached key id is still on the account
	// so the short-circuit path is taken.
	githubListUserGpgKeysFn = func(token string) ([]github.GpgKeyRef, error) {
		return []github.GpgKeyRef{{
			ID:    72834,
			KeyID: "ABC123",
		}}, nil
	}

	state := &WizardState{
		KeyID:       "FD910BA1AF89641A",
		PubKeyArmor: "-----BEGIN PGP PUBLIC KEY BLOCK-----\nMOCK\n-----END-----",
		PrivateKey:  "-----BEGIN PGP PRIVATE KEY BLOCK-----\nMOCK\n-----END-----",
		Passphrase:  "gh-pass",
		// Pre-set as if a prior run hit *ErrKeyAlreadyExists and
		// recorded the discovered key id. This is the second-line
		// short-circuit case.
		GithubKeyID: "72834",
	}
	opts := WizardOptions{
		Repo:        "owner/repo",
		GitHubToken: "ghp-token",
	}

	if err := stepGitHub(state, opts); err != nil {
		t.Fatalf("stepGitHub rerun: %v", err)
	}
	// KeyID must be preserved.
	if state.GithubKeyID != "72834" {
		t.Errorf("state.GithubKeyID = %q, want %q (preserved)", state.GithubKeyID, "72834")
	}
}

// TestRunGithubStep_NormalUpload_LeavesKeyIDEmpty verifies the
// happy-path: a normal upload (no *ErrKeyAlreadyExists) leaves
// state.GithubKeyID empty. The field is only populated when the
// subkey is already on the account.
func TestRunGithubStep_NormalUpload_LeavesKeyIDEmpty(t *testing.T) {
	defer saveStepFns()()

	githubUploadPublicKeyFn = func(token, armor, fingerprint string) (string, error) {
		return "fd910ba1af89641afd910ba1af89641afd910ba1", nil
	}
	githubSetGPGSecretsFn = func(string, string, string, string, string) error { return nil }
	githubCommitPublicKeyFileFn = func(string, string, string, string) (string, error) {
		return "https://github.com/owner/repo/pull/1", nil
	}

	state := &WizardState{
		KeyID:       "FD910BA1AF89641A",
		PubKeyArmor: "-----BEGIN PGP PUBLIC KEY BLOCK-----\nMOCK\n-----END-----",
		PrivateKey:  "-----BEGIN PGP PRIVATE KEY BLOCK-----\nMOCK\n-----END-----",
		Passphrase:  "gh-pass",
	}
	opts := WizardOptions{
		Repo:        "owner/repo",
		GitHubToken: "ghp-token",
	}

	if err := stepGitHub(state, opts); err != nil {
		t.Fatalf("stepGitHub happy path: %v", err)
	}
	if state.GithubKeyID != "" {
		t.Errorf("state.GithubKeyID = %q, want empty for normal upload", state.GithubKeyID)
	}
}

// TestRunWizard_KeyAlreadyExists_AllStepsInvoked exercises the
// orchestrator-level behaviour: when the github step returns nil
// (because the upload returned *ErrKeyAlreadyExists and the step
// swallowed it), the wizard must NOT surface the typed error and
// must move on to the publish step. This test asserts the typed
// error is not surfaced to the user; the re-run short-circuit is
// covered separately by
// TestRunGithubStep_KeyAlreadyExists_RerunShortCircuits.
func TestRunWizard_KeyAlreadyExists_AllStepsInvoked(t *testing.T) {
	swapRunners(t)
	autoConfirm(t)

	var invoked []string
	// Override every step with a recording mock. The github
	// runner is replaced by a wrapper around the real
	// stepGitHub, so the existing function-variable seams do
	// their work. The publish runner is a simple recorder.
	stepRunners[StepGitHub] = func(state *WizardState, opts WizardOptions) error {
		invoked = append(invoked, StepGitHub)
		// Force the seam into the dogfooded branch: the
		// upload returns *ErrKeyAlreadyExists.
		githubUploadPublicKeyFn = func(string, string, string) (string, error) {
			return "fd910ba1af89641a", &github.ErrKeyAlreadyExists{
				KeyID:       "72834",
				Emails:      []string{"korrnals@example.com"},
				Fingerprint: "fd910ba1af89641a",
			}
		}
		githubSetGPGSecretsFn = func(string, string, string, string, string) error { return nil }
		githubCommitPublicKeyFileFn = func(string, string, string, string) (string, error) {
			return "https://github.com/owner/repo/pull/1", nil
		}
		// gpgDetectExistingKeysFn must succeed (otherwise
		// stepGitHub returns an error before reaching the
		// upload).
		gpgDetectExistingKeysFn = func() ([]gpg.GpgKey, error) {
			return []gpg.GpgKey{{
				KeyID:       "FD910BA1AF89641A",
				Fingerprint: "fd910ba1af89641afd910ba1af89641afd910ba1",
				UserId:      "Korrnals <korrnals@example.com>",
			}}, nil
		}
		// Reset the uploadFn when this step completes so the
		// follow-up steps (none, but defensive) see a sane
		// default.
		defer func() { githubUploadPublicKeyFn = github.UploadPublicKeyWithFingerprint }()
		return stepGitHub(state, opts)
	}
	for _, name := range stepOrder {
		if name == StepGitHub {
			continue // already set above
		}
		name := name
		stepRunners[name] = func(state *WizardState, opts WizardOptions) error {
			invoked = append(invoked, name)
			if name == StepDetect {
				state.KeyID = "FD910BA1AF89641A"
			}
			if name == StepExport {
				state.PubKeyArmor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nMOCK\n-----END-----"
				state.PrivateKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nMOCK\n-----END-----"
			}
			return nil
		}
	}

	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")

	opts := WizardOptions{
		StatePath:   statePath,
		Repo:        "owner/repo",
		GitHubToken: "ghp-token",
		Passphrase:  "skip-survey-pass",
		Name:        "Korrnals",
		Email:       "korrnals@example.com",
	}
	if err := RunWizard(opts); err != nil {
		t.Fatalf("RunWizard: %v", err)
	}

	// All six steps must have been invoked in order, including
	// the github step (it ran, returned *ErrKeyAlreadyExists, the
	// step returned nil, the orchestrator marked it done).
	if len(invoked) != len(stepOrder) {
		t.Fatalf("invoked %d steps, want %d (order=%v)", len(invoked), len(stepOrder), invoked)
	}
	for i, got := range invoked {
		if got != stepOrder[i] {
			t.Errorf("step %d = %q, want %q (order=%v)", i, got, stepOrder[i], invoked)
		}
	}
	if !contains(invoked, StepGitHub) {
		t.Errorf("github step must have been invoked: %v", invoked)
	}
	if !contains(invoked, StepPublish) {
		t.Errorf("publish step must have run after github: %v", invoked)
	}
}

// TestRunWizard_KeyAlreadyExists_ErrorNotSurfaced is a regression
// test: it asserts that *github.ErrKeyAlreadyExists is NOT
// propagated as the wizard's top-level error. If a future refactor
// accidentally removes the `errors.As` switch, this test fails
// loudly because the wizard would return a non-nil error.
func TestRunWizard_KeyAlreadyExists_ErrorNotSurfaced(t *testing.T) {
	swapRunners(t)
	autoConfirm(t)

	// Replace github step with a runner that returns the typed
	// error wrapped in fmt.Errorf (the production code path
	// does NOT wrap it; it consumes it — but we want to assert
	// the orchestrator does not treat it as a fatal). Use the
	// real stepGitHub with the seam to be sure.
	stepRunners[StepGitHub] = func(state *WizardState, opts WizardOptions) error {
		githubUploadPublicKeyFn = func(string, string, string) (string, error) {
			return "", &github.ErrKeyAlreadyExists{
				KeyID:       "72834",
				Emails:      []string{"korrnals@example.com"},
				Fingerprint: "fd910ba1af89641a",
			}
		}
		githubSetGPGSecretsFn = func(string, string, string, string, string) error { return nil }
		githubCommitPublicKeyFileFn = func(string, string, string, string) (string, error) {
			return "https://github.com/owner/repo/pull/1", nil
		}
		gpgDetectExistingKeysFn = func() ([]gpg.GpgKey, error) {
			return []gpg.GpgKey{{
				KeyID:       "FD910BA1AF89641A",
				Fingerprint: "fd910ba1af89641afd910ba1af89641afd910ba1",
				UserId:      "Korrnals <korrnals@example.com>",
			}}, nil
		}
		return stepGitHub(state, opts)
	}
	// Make every other step a recorder.
	for _, name := range stepOrder {
		if name == StepGitHub {
			continue
		}
		name := name
		stepRunners[name] = func(state *WizardState, opts WizardOptions) error {
			if name == StepDetect {
				state.KeyID = "FD910BA1AF89641A"
			}
			if name == StepExport {
				state.PubKeyArmor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nMOCK\n-----END-----"
				state.PrivateKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nMOCK\n-----END-----"
			}
			return nil
		}
	}

	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")

	opts := WizardOptions{
		StatePath:   statePath,
		Repo:        "owner/repo",
		GitHubToken: "ghp-token",
		Passphrase:  "skip-survey-pass",
		Name:        "Korrnals",
		Email:       "korrnals@example.com",
	}
	err := RunWizard(opts)
	if err != nil {
		var keyExists *github.ErrKeyAlreadyExists
		if errors.As(err, &keyExists) {
			t.Errorf("RunWizard returned *ErrKeyAlreadyExists to the caller — the wizard must consume it: %v", err)
		}
		if strings.Contains(err.Error(), "subkey") {
			t.Errorf("RunWizard error mentions subkey — typed error leaked: %v", err)
		}
		t.Fatalf("RunWizard returned unexpected error: %v", err)
	}
}

// TestRunGithubStep_RevalidationFails_FallsThroughToUpload covers
// issue #22: when state.GithubKeyID is set but the key is no longer
// on the account under the current token (token rotated, key
// deleted, or state authored by a different account), stepGitHub
// must NOT silently skip. It must clear state.GithubKeyID and fall
// through to the normal upload path so the user is correctly
// informed and the upload runs against the current account.
//
// The re-validation mirrors the defence the 422-fallback path
// already applies (it calls listUserGpgKeys after a 422 to confirm
// which key holds the subkey).
func TestRunGithubStep_RevalidationFails_FallsThroughToUpload(t *testing.T) {
	defer saveStepFns()()

	// ListUserGpgKeys returns a key set that does NOT contain the
	// cached key id 72834. This simulates: token rotated, key
	// deleted, or state authored by a different account.
	githubListUserGpgKeysFn = func(token string) ([]github.GpgKeyRef, error) {
		return []github.GpgKeyRef{{
			ID:    11111,
			KeyID: "OTHER",
		}}, nil
	}

	uploadCalled := false
	githubUploadPublicKeyFn = func(token, armor, fingerprint string) (string, error) {
		uploadCalled = true
		// Normal upload succeeds — the re-run is now treated as
		// a fresh upload against the current account.
		return "fd910ba1af89641afd910ba1af89641afd910ba1", nil
	}
	githubSetGPGSecretsFn = func(string, string, string, string, string) error { return nil }
	githubCommitPublicKeyFileFn = func(string, string, string, string) (string, error) {
		return "https://github.com/owner/repo/pull/1", nil
	}

	state := &WizardState{
		KeyID:       "FD910BA1AF89641A",
		PubKeyArmor: "-----BEGIN PGP PUBLIC KEY BLOCK-----\nMOCK\n-----END-----",
		PrivateKey:  "-----BEGIN PGP PRIVATE KEY BLOCK-----\nMOCK\n-----END-----",
		Passphrase:  "gh-pass",
		// Pre-set as if a prior run recorded the key id, but
		// the key is no longer on the account under the
		// current token.
		GithubKeyID: "72834",
	}
	opts := WizardOptions{
		Repo:        "owner/repo",
		GitHubToken: "ghp-token",
	}

	if err := stepGitHub(state, opts); err != nil {
		t.Fatalf("stepGitHub revalidation fall-through: %v", err)
	}
	// The cached key id must be cleared — silently keeping it
	// would mis-inform the user on the next re-run.
	if state.GithubKeyID != "" {
		t.Errorf("state.GithubKeyID = %q, want empty (cleared after re-validation failed)", state.GithubKeyID)
	}
	// The normal upload path must have run.
	if !uploadCalled {
		t.Fatal("uploadPublicKeyFn was NOT called — stepGitHub silently skipped after re-validation failed")
	}
}

// TestRunGithubStep_RevalidationNetworkError_TrustsState covers the
// lenient branch of issue #22: when ListUserGpgKeys returns a
// network/API error, stepGitHub must trust the cached state and
// short-circuit (a transient API failure must not force a redundant
// upload the user cannot verify either). A warning is logged.
func TestRunGithubStep_RevalidationNetworkError_TrustsState(t *testing.T) {
	defer saveStepFns()()

	// ListUserGpgKeys returns a network error.
	githubListUserGpgKeysFn = func(token string) ([]github.GpgKeyRef, error) {
		return nil, errors.New("dial tcp: connection refused")
	}

	// The upload MUST NOT be called — the short-circuit trusts
	// the state on network error.
	githubUploadPublicKeyFn = func(token, armor, fingerprint string) (string, error) {
		t.Fatal("uploadPublicKeyFn must NOT be called when re-validation hits a network error (lenient short-circuit)")
		return "", nil
	}
	githubSetGPGSecretsFn = func(string, string, string, string, string) error { return nil }
	githubCommitPublicKeyFileFn = func(string, string, string, string) (string, error) {
		return "https://github.com/owner/repo/pull/1", nil
	}

	state := &WizardState{
		KeyID:       "FD910BA1AF89641A",
		PubKeyArmor: "-----BEGIN PGP PUBLIC KEY BLOCK-----\nMOCK\n-----END-----",
		PrivateKey:  "-----BEGIN PGP PRIVATE KEY BLOCK-----\nMOCK\n-----END-----",
		Passphrase:  "gh-pass",
		GithubKeyID: "72834",
	}
	opts := WizardOptions{
		Repo:        "owner/repo",
		GitHubToken: "ghp-token",
	}

	if err := stepGitHub(state, opts); err != nil {
		t.Fatalf("stepGitHub network-error lenient: %v", err)
	}
	// The cached key id must be preserved (lenient trust).
	if state.GithubKeyID != "72834" {
		t.Errorf("state.GithubKeyID = %q, want %q (preserved on network error)", state.GithubKeyID, "72834")
	}
}

// TestRunGithubStep_RevalidationConfirms_ShortCircuits covers the
// happy branch of issue #22: when ListUserGpgKeys confirms the
// cached key id is still on the account, stepGitHub short-circuits
// as before (no upload). This complements
// TestRunGithubStep_KeyAlreadyExists_RerunShortCircuits, which now
// also injects a confirming list — this test makes the confirmation
// explicit and asserts the upload is NOT called.
func TestRunGithubStep_RevalidationConfirms_ShortCircuits(t *testing.T) {
	defer saveStepFns()()

	githubListUserGpgKeysFn = func(token string) ([]github.GpgKeyRef, error) {
		return []github.GpgKeyRef{{
			ID:    72834,
			KeyID: "ABC123",
		}}, nil
	}
	githubUploadPublicKeyFn = func(token, armor, fingerprint string) (string, error) {
		t.Fatal("uploadPublicKeyFn must NOT be called when re-validation confirms the key")
		return "", nil
	}
	githubSetGPGSecretsFn = func(string, string, string, string, string) error { return nil }
	githubCommitPublicKeyFileFn = func(string, string, string, string) (string, error) {
		return "https://github.com/owner/repo/pull/1", nil
	}

	state := &WizardState{
		KeyID:       "FD910BA1AF89641A",
		PubKeyArmor: "-----BEGIN PGP PUBLIC KEY BLOCK-----\nMOCK\n-----END-----",
		PrivateKey:  "-----BEGIN PGP PRIVATE KEY BLOCK-----\nMOCK\n-----END-----",
		Passphrase:  "gh-pass",
		GithubKeyID: "72834",
	}
	opts := WizardOptions{
		Repo:        "owner/repo",
		GitHubToken: "ghp-token",
	}

	if err := stepGitHub(state, opts); err != nil {
		t.Fatalf("stepGitHub confirmed short-circuit: %v", err)
	}
	if state.GithubKeyID != "72834" {
		t.Errorf("state.GithubKeyID = %q, want %q (preserved on confirmation)", state.GithubKeyID, "72834")
	}
}
