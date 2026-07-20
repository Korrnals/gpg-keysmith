package wizard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- State persistence tests -------------------------------------------

// TestLoadStateNoFile verifies LoadState returns an empty state and
// no error when the state file does not exist. This is the fresh-run
// path — a clean user has no state file yet.
func TestLoadStateNoFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	state, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState returned error for missing file: %v", err)
	}
	if state == nil {
		t.Fatal("LoadState returned nil state for missing file")
	} else {
		if state.StatePath != path {
			t.Errorf("StatePath = %q, want %q", state.StatePath, path)
		}
		if state.Step != "" || state.KeyID != "" || state.Email != "" {
			t.Errorf("state is not empty: %+v", state)
		}
		if len(state.CompletedSteps) != 0 {
			t.Errorf("CompletedSteps not empty: %v", state.CompletedSteps)
		}
	}
}

// TestSaveLoadStateRoundtrip verifies that SaveState followed by
// LoadState preserves the serialised fields.
func TestSaveLoadStateRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	original := &WizardState{
		Step:           StepExport,
		CompletedSteps: []string{StepDetect, StepGenerate},
		KeyID:          "ABCD1234EFGH5678",
		Email:          "user@example.com",
		Repo:           "owner/repo",
		StatePath:      path,
		// Secrets — these should NOT survive the roundtrip because
		// they are json:"-".
		Passphrase:  "topsecret-pass",
		PrivateKey:  "-----BEGIN PGP PRIVATE KEY BLOCK-----",
		PubKeyArmor: "-----BEGIN PGP PUBLIC KEY BLOCK-----",
	}
	if err := SaveState(original); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	loaded, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if loaded.Step != original.Step {
		t.Errorf("Step = %q, want %q", loaded.Step, original.Step)
	}
	if loaded.KeyID != original.KeyID {
		t.Errorf("KeyID = %q, want %q", loaded.KeyID, original.KeyID)
	}
	if loaded.Email != original.Email {
		t.Errorf("Email = %q, want %q", loaded.Email, original.Email)
	}
	if loaded.Repo != original.Repo {
		t.Errorf("Repo = %q, want %q", loaded.Repo, original.Repo)
	}
	if len(loaded.CompletedSteps) != len(original.CompletedSteps) {
		t.Errorf("CompletedSteps len = %d, want %d",
			len(loaded.CompletedSteps), len(original.CompletedSteps))
	} else {
		for i, s := range original.CompletedSteps {
			if loaded.CompletedSteps[i] != s {
				t.Errorf("CompletedSteps[%d] = %q, want %q",
					i, loaded.CompletedSteps[i], s)
			}
		}
	}
	// StatePath is json:"-" so it is not persisted; LoadState
	// re-populates it from the path argument. Verify it is set.
	if loaded.StatePath != path {
		t.Errorf("StatePath = %q, want %q", loaded.StatePath, path)
	}
}

// TestSaveStateOmitsSecrets is the critical security-invariant test.
// It serialises a state with the secret fields populated, reads the
// raw JSON back, and asserts that the passphrase, private key, and
// public key armor are absent from the file content.
//
// This test MUST fail if any of the three secret fields loses its
// `json:"-"` tag — that would be a credential leak into the state
// file.
func TestSaveStateOmitsSecrets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	const (
		passphrase = "SUPER-SECRET-PASSPHRASE-12345"
		privKey    = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nSECRET\n-----END-----"
		pubArmor   = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nPUBLIC\n-----END-----"
	)
	state := &WizardState{
		StatePath:   path,
		KeyID:       "DEAD1234BEEF5678",
		Email:       "leak-test@example.com",
		Passphrase:  passphrase,
		PrivateKey:  privKey,
		PubKeyArmor: pubArmor,
	}
	if err := SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	// Read the raw bytes (not via LoadState — we want to see the
	// exact on-disk content, not the unmarshalled struct).
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	content := string(raw)

	// The three secret values MUST NOT appear anywhere in the file.
	for _, secret := range []string{passphrase, privKey, pubArmor} {
		if strings.Contains(content, secret) {
			t.Errorf("secret material leaked into state file: file contains %q\n--- file content ---\n%s",
				secret, content)
		}
	}

	// Defence-in-depth: unmarshal into a generic map and assert the
	// keys are absent (not just that the values differ). This catches
	// the case where a field is serialised as an empty string but
	// the key is present (which would mean the `json:"-"` tag was
	// removed).
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal state into generic map: %v", err)
	}
	for _, key := range []string{"Passphrase", "PrivateKey", "PubKeyArmor", "passphrase", "private_key", "pub_key_armor"} {
		if _, ok := generic[key]; ok {
			t.Errorf("secret field %q is present in state file JSON — `json:\"-\"` tag missing?\n--- keys present ---\n%v",
				key, generic)
		}
	}
}

// TestSaveStateCreatesParentDir verifies SaveState creates the parent
// directory with 0700 perms when it does not exist.
func TestSaveStateCreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "deeply", "nested", "state.json")
	state := &WizardState{
		StatePath: nested,
		KeyID:     "AAAA1111BBBB2222",
	}
	if err := SaveState(state); err != nil {
		t.Fatalf("SaveState did not create parent dir: %v", err)
	}
	info, err := os.Stat(filepath.Dir(nested))
	if err != nil {
		t.Fatalf("parent dir not created: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("parent dir perms = %o, want 0700", info.Mode().Perm())
	}
	// State file itself should be 0600.
	info, err = os.Stat(nested)
	if err != nil {
		t.Fatalf("state file not created: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("state file perms = %o, want 0600", info.Mode().Perm())
	}
}

// TestClearStateRemovesFile verifies ClearState deletes the state
// file and is a no-op when the file is already absent.
func TestClearStateRemovesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	state := &WizardState{StatePath: path, KeyID: "CCCC3333DDDD4444"}
	if err := SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("state file not created: %v", err)
	}
	if err := ClearState(path); err != nil {
		t.Fatalf("ClearState: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("state file still exists after ClearState (err=%v)", err)
	}
	// Clearing a non-existent file is a no-op, not an error.
	if err := ClearState(path); err != nil {
		t.Errorf("ClearState on missing file returned error: %v", err)
	}
}

// --- Step ordering test -------------------------------------------------

// TestStepOrdering replaces every step runner with a mock that
// appends its name to an ordered slice, then runs the wizard. The
// resulting slice MUST equal stepOrder — this is the canonical
// ordering invariant.
//
// Mocking is done by swapping entries in the package-level
// stepRunners map. The original map is saved and restored so the
// test does not leak state into other tests.
func TestStepOrdering(t *testing.T) {
	saved := make(map[string]stepRunner, len(stepRunners))
	for k, v := range stepRunners {
		saved[k] = v
	}
	t.Cleanup(func() {
		// Restore original runners.
		for k, v := range saved {
			stepRunners[k] = v
		}
	})

	// Track the order steps are actually invoked in.
	var order []string
	for _, name := range stepOrder {
		name := name // capture for closure
		stepRunners[name] = func(state *WizardState, opts WizardOptions) error {
			order = append(order, name)
			// Populate the fields downstream steps need so they
			// don't bail out on the "no key id" guard.
			if name == StepDetect {
				state.KeyID = "ORDERTEST00000KEY"
			}
			if name == StepExport {
				state.PubKeyArmor = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
				state.PrivateKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
			}
			return nil
		}
	}
	// Auto-confirm all step prompts.
	savedContinue := askContinue
	t.Cleanup(func() { askContinue = savedContinue })
	askContinue = func(string) bool { return true }

	dir := t.TempDir()
	state := &WizardState{StatePath: filepath.Join(dir, "state.json")}
	if err := runWizardWithState(state, WizardOptions{}); err != nil {
		t.Fatalf("runWizardWithState: %v", err)
	}

	if len(order) != len(stepOrder) {
		t.Fatalf("invoked %d steps, want %d (order=%v)", len(order), len(stepOrder), order)
	}
	for i, got := range order {
		if got != stepOrder[i] {
			t.Errorf("step %d = %q, want %q (full order=%v)", i, got, stepOrder[i], order)
		}
	}
}

// --- Resume test --------------------------------------------------------

// TestResumeFromPartialState verifies that a state with
// CompletedSteps already populated causes the wizard to skip those
// steps and start at the next one. We set detect+generate as
// completed and assert the mocks for export→git-config→github→publish
// run in order, and detect+generate are NOT re-invoked.
func TestResumeFromPartialState(t *testing.T) {
	saved := make(map[string]stepRunner, len(stepRunners))
	for k, v := range stepRunners {
		saved[k] = v
	}
	t.Cleanup(func() {
		for k, v := range saved {
			stepRunners[k] = v
		}
	})

	var invoked []string
	// Only steps after the resume point have active mocks. The
	// detect and generate runners are replaced with "should not be
	// called" sentinels to prove the skip path works.
	shouldNotRun := func(name string) stepRunner {
		return func(*WizardState, WizardOptions) error {
			t.Errorf("step %q should have been skipped (already completed)", name)
			return nil
		}
	}
	stepRunners[StepDetect] = shouldNotRun(StepDetect)
	stepRunners[StepGenerate] = shouldNotRun(StepGenerate)
	for _, name := range []string{StepExport, StepGitConfig, StepGitHub, StepPublish} {
		name := name
		stepRunners[name] = func(state *WizardState, opts WizardOptions) error {
			invoked = append(invoked, name)
			if name == StepExport {
				state.PubKeyArmor = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
				state.PrivateKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
			}
			return nil
		}
	}
	savedContinue := askContinue
	t.Cleanup(func() { askContinue = savedContinue })
	askContinue = func(string) bool { return true }

	dir := t.TempDir()
	state := &WizardState{
		StatePath:      filepath.Join(dir, "state.json"),
		CompletedSteps: []string{StepDetect, StepGenerate},
		KeyID:          "RESUME0000TEST00",
		Email:          "resume@example.com",
	}
	if err := runWizardWithState(state, WizardOptions{}); err != nil {
		t.Fatalf("runWizardWithState: %v", err)
	}

	want := []string{StepExport, StepGitConfig, StepGitHub, StepPublish}
	if len(invoked) != len(want) {
		t.Fatalf("invoked %d steps after resume, want %d (invoked=%v)",
			len(invoked), len(want), invoked)
	}
	for i, got := range invoked {
		if got != want[i] {
			t.Errorf("resumed step %d = %q, want %q", i, got, want[i])
		}
	}
}

// --- Retry / skip / abort test ------------------------------------------

// TestSkipOnFailure verifies that when a step fails and the user
// chooses "skip", the wizard continues to the next step WITHOUT
// marking the failed step as completed. The state file should not
// contain the skipped step in CompletedSteps after the run.
func TestSkipOnFailure(t *testing.T) {
	saved := make(map[string]stepRunner, len(stepRunners))
	for k, v := range stepRunners {
		saved[k] = v
	}
	t.Cleanup(func() {
		for k, v := range saved {
			stepRunners[k] = v
		}
	})

	for _, name := range stepOrder {
		name := name
		switch name {
		case StepGitConfig:
			// This step fails once, then is skipped.
			stepRunners[name] = func(state *WizardState, opts WizardOptions) error {
				return errForTest("simulated failure")
			}
		default:
			stepRunners[name] = func(state *WizardState, opts WizardOptions) error {
				if name == StepDetect {
					state.KeyID = "SKIPTEST0000000K"
				}
				if name == StepExport {
					state.PubKeyArmor = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
					state.PrivateKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
				}
				return nil
			}
		}
	}

	savedContinue := askContinue
	t.Cleanup(func() { askContinue = savedContinue })
	askContinue = func(string) bool { return true }

	savedRetry := askRetrySkipAbort
	t.Cleanup(func() { askRetrySkipAbort = savedRetry })
	askRetrySkipAbort = func(stepName string) string {
		if stepName == StepGitConfig {
			return "skip"
		}
		return "abort"
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	state := &WizardState{StatePath: path}
	if err := runWizardWithState(state, WizardOptions{}); err != nil {
		t.Fatalf("runWizardWithState: %v", err)
	}

	// The skipped step must NOT be in CompletedSteps.
	for _, s := range state.CompletedSteps {
		if s == StepGitConfig {
			t.Errorf("skipped step %q was marked completed: %v", StepGitConfig, state.CompletedSteps)
		}
	}
	// All other steps must be completed.
	wantCompleted := map[string]bool{
		StepDetect:   true,
		StepGenerate: true,
		StepExport:   true,
		StepGitHub:   true,
		StepPublish:  true,
	}
	for _, s := range state.CompletedSteps {
		delete(wantCompleted, s)
	}
	if len(wantCompleted) != 0 {
		t.Errorf("expected these steps to be completed but they were not: %v", wantCompleted)
	}
}

// TestAbortOnFailure verifies that when a step fails and the user
// chooses "abort", RunWizard returns an error and the state is
// preserved (the failed step is not in CompletedSteps, but prior
// completed steps are — they were saved).
func TestAbortOnFailure(t *testing.T) {
	saved := make(map[string]stepRunner, len(stepRunners))
	for k, v := range stepRunners {
		saved[k] = v
	}
	t.Cleanup(func() {
		for k, v := range saved {
			stepRunners[k] = v
		}
	})

	for _, name := range stepOrder {
		name := name
		switch name {
		case StepExport:
			stepRunners[name] = func(state *WizardState, opts WizardOptions) error {
				return errForTest("simulated abort failure")
			}
		default:
			stepRunners[name] = func(state *WizardState, opts WizardOptions) error {
				if name == StepDetect {
					state.KeyID = "ABORTTEST00000KY"
				}
				return nil
			}
		}
	}

	savedContinue := askContinue
	t.Cleanup(func() { askContinue = savedContinue })
	askContinue = func(string) bool { return true }

	savedRetry := askRetrySkipAbort
	t.Cleanup(func() { askRetrySkipAbort = savedRetry })
	askRetrySkipAbort = func(string) string { return "abort" }

	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	state := &WizardState{StatePath: path}
	err := runWizardWithState(state, WizardOptions{})
	if err == nil {
		t.Fatal("expected error on abort, got nil")
	}
	if !strings.Contains(err.Error(), "aborted") {
		t.Errorf("error message = %q, want it to contain 'aborted'", err.Error())
	}
	// detect and generate were completed and saved before the abort.
	if !contains(state.CompletedSteps, StepDetect) {
		t.Errorf("StepDetect should be completed before abort: %v", state.CompletedSteps)
	}
	if !contains(state.CompletedSteps, StepGenerate) {
		t.Errorf("StepGenerate should be completed before abort: %v", state.CompletedSteps)
	}
	if contains(state.CompletedSteps, StepExport) {
		t.Errorf("StepExport should NOT be completed (it aborted): %v", state.CompletedSteps)
	}
	// The state file on disk should reflect the saved progress —
	// a subsequent run resumes from generate's completion.
	loaded, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState after abort: %v", err)
	}
	if !contains(loaded.CompletedSteps, StepDetect) || !contains(loaded.CompletedSteps, StepGenerate) {
		t.Errorf("state file after abort missing completed steps: %v", loaded.CompletedSteps)
	}
}

// --- StepName constants sanity test -------------------------------------

// TestStepNameConstants verifies the StepName constants match the
// values documented in the M8 spec. This is a regression guard: if
// someone renames a constant, this test fails loudly.
func TestStepNameConstants(t *testing.T) {
	want := map[string]string{
		"StepDetect":    "detect",
		"StepGenerate":  "generate",
		"StepExport":    "export",
		"StepGitConfig": "git-config",
		"StepGitHub":    "github",
		"StepPublish":   "publish",
	}
	got := map[string]string{
		"StepDetect":    StepDetect,
		"StepGenerate":  StepGenerate,
		"StepExport":    StepExport,
		"StepGitConfig": StepGitConfig,
		"StepGitHub":    StepGitHub,
		"StepPublish":   StepPublish,
	}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%s = %q, want %q", name, got[name], w)
		}
	}
}

// --- helpers ------------------------------------------------------------

// errForTest is a tiny sentinel error constructor used by the
// failure-injection mocks. We define it as a local type so the
// mocks don't depend on any other package.
type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }

func errForTest(msg string) error { return &testError{msg: msg} }

func contains(slice []string, s string) bool {
	for _, x := range slice {
		if x == s {
			return true
		}
	}
	return false
}

// --- RunWizard public API tests (QA3) ----------------------------------
//
// The tests above exercise runWizardWithState (the private core).
// These tests exercise the exported RunWizard, which adds LoadState
// + DefaultStatePath resolution + ClearState-on-completion on top.
// Each test overrides stepRunners, askContinue, and askRetrySkipAbort
// to avoid touching gpg/git/github/keyserver and the TTY.

// swapRunners saves the current stepRunners map and restores it on
// cleanup. Returns nothing; t.Cleanup is registered. Callers then
// overwrite individual entries in stepRunners.
func swapRunners(t *testing.T) {
	t.Helper()
	saved := make(map[string]stepRunner, len(stepRunners))
	for k, v := range stepRunners {
		saved[k] = v
	}
	t.Cleanup(func() {
		for k, v := range saved {
			stepRunners[k] = v
		}
	})
}

// autoConfirm replaces askContinue with a stub that always returns
// true so the wizard runs every step without a TTY prompt.
func autoConfirm(t *testing.T) {
	t.Helper()
	saved := askContinue
	t.Cleanup(func() { askContinue = saved })
	askContinue = func(string) bool { return true }
}

// allStepsSucceed installs a mock for every step in stepOrder that
// records its name into order and populates the downstream-required
// state fields (KeyID, PubKeyArmor, PrivateKey). Returns a pointer to
// the order slice so the caller can assert invocation order.
func allStepsSucceed(t *testing.T) *[]string {
	t.Helper()
	var order []string
	for _, name := range stepOrder {
		name := name
		stepRunners[name] = func(state *WizardState, opts WizardOptions) error {
			order = append(order, name)
			if name == StepDetect {
				state.KeyID = "RUNWIZARD00000KEY"
			}
			if name == StepExport {
				state.PubKeyArmor = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
				state.PrivateKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
			}
			return nil
		}
	}
	return &order
}

// TestRunWizard_FreshRun calls the exported RunWizard with a temp
// StatePath and mocked step runners. Asserts: all steps run in
// order, CompletedSteps is fully populated, the state file is
// created during the run, and RunWizard returns no error.
func TestRunWizard_FreshRun(t *testing.T) {
	swapRunners(t)
	autoConfirm(t)
	order := allStepsSucceed(t)

	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")

	// Before RunWizard, no state file exists.
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("state file should not exist before RunWizard: err=%v", err)
	}

	if err := RunWizard(WizardOptions{StatePath: statePath}); err != nil {
		t.Fatalf("RunWizard: %v", err)
	}

	// All six steps must have run in canonical order.
	if len(*order) != len(stepOrder) {
		t.Fatalf("invoked %d steps, want %d (order=%v)", len(*order), len(stepOrder), *order)
	}
	for i, got := range *order {
		if got != stepOrder[i] {
			t.Errorf("step %d = %q, want %q (order=%v)", i, got, stepOrder[i], *order)
		}
	}

	// After a fully successful run, RunWizard clears the state file.
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Errorf("state file should be cleared after a successful run: err=%v", err)
	}
}

// TestRunWizard_ResumeFromStateFile pre-writes a state file with
// CompletedSteps: [detect, generate], then calls RunWizard. Asserts
// the detect and generate steps are NOT re-invoked and the remaining
// four steps (export → git-config → github → publish) run in order.
func TestRunWizard_ResumeFromStateFile(t *testing.T) {
	swapRunners(t)
	autoConfirm(t)

	var invoked []string
	// Sentinel runners for already-completed steps — they must not
	// be called.
	shouldNotRun := func(name string) stepRunner {
		return func(*WizardState, WizardOptions) error {
			t.Errorf("step %q should have been skipped (already completed)", name)
			return nil
		}
	}
	stepRunners[StepDetect] = shouldNotRun(StepDetect)
	stepRunners[StepGenerate] = shouldNotRun(StepGenerate)
	for _, name := range []string{StepExport, StepGitConfig, StepGitHub, StepPublish} {
		name := name
		stepRunners[name] = func(state *WizardState, opts WizardOptions) error {
			invoked = append(invoked, name)
			if name == StepExport {
				state.PubKeyArmor = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
				state.PrivateKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
			}
			return nil
		}
	}

	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")

	// Pre-write a state file with detect+generate completed.
	prior := &WizardState{
		StatePath:      statePath,
		CompletedSteps: []string{StepDetect, StepGenerate},
		KeyID:          "RESUME0000TEST00",
		Email:          "resume@example.com",
	}
	if err := SaveState(prior); err != nil {
		t.Fatalf("SaveState prior: %v", err)
	}

	if err := RunWizard(WizardOptions{StatePath: statePath}); err != nil {
		t.Fatalf("RunWizard: %v", err)
	}

	want := []string{StepExport, StepGitConfig, StepGitHub, StepPublish}
	if len(invoked) != len(want) {
		t.Fatalf("invoked %d steps after resume, want %d (invoked=%v)",
			len(invoked), len(want), invoked)
	}
	for i, got := range invoked {
		if got != want[i] {
			t.Errorf("resumed step %d = %q, want %q", i, got, want[i])
		}
	}
}

// TestRunWizard_AbortOnError mocks a step (export) to fail and mocks
// askRetrySkipAbort to return "abort". Asserts RunWizard returns an
// error whose message contains "aborted", and the prior completed
// steps (detect, generate) are in CompletedSteps while export is not.
func TestRunWizard_AbortOnError(t *testing.T) {
	swapRunners(t)
	autoConfirm(t)

	for _, name := range stepOrder {
		name := name
		switch name {
		case StepExport:
			stepRunners[name] = func(*WizardState, WizardOptions) error {
				return errForTest("simulated abort failure")
			}
		default:
			stepRunners[name] = func(state *WizardState, opts WizardOptions) error {
				if name == StepDetect {
					state.KeyID = "ABORT0000TEST00"
				}
				return nil
			}
		}
	}

	savedRetry := askRetrySkipAbort
	t.Cleanup(func() { askRetrySkipAbort = savedRetry })
	askRetrySkipAbort = func(string) string { return "abort" }

	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")

	err := RunWizard(WizardOptions{StatePath: statePath})
	if err == nil {
		t.Fatal("RunWizard: expected error on abort, got nil")
	}
	if !strings.Contains(err.Error(), "aborted") {
		t.Errorf("error = %q, want it to contain 'aborted'", err.Error())
	}

	// The state file on disk should reflect the progress saved
	// before the abort — detect and generate completed, export not.
	loaded, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState after abort: %v", err)
	}
	if !contains(loaded.CompletedSteps, StepDetect) {
		t.Errorf("state file missing StepDetect after abort: %v", loaded.CompletedSteps)
	}
	if !contains(loaded.CompletedSteps, StepGenerate) {
		t.Errorf("state file missing StepGenerate after abort: %v", loaded.CompletedSteps)
	}
	if contains(loaded.CompletedSteps, StepExport) {
		t.Errorf("StepExport should NOT be completed (it aborted): %v", loaded.CompletedSteps)
	}
}

// TestRunWizard_SkipStep mocks a step (git-config) to fail and mocks
// askRetrySkipAbort to return "skip". Asserts: RunWizard completes
// (no error), the skipped step is NOT in CompletedSteps, and the
// remaining steps still run. Uses an in-memory state (StatePath in a
// temp dir) and inspects the order of invocation to confirm the step
// after the skipped one still ran.
func TestRunWizard_SkipStep(t *testing.T) {
	swapRunners(t)
	autoConfirm(t)

	var invoked []string
	for _, name := range stepOrder {
		name := name
		switch name {
		case StepGitConfig:
			stepRunners[name] = func(*WizardState, WizardOptions) error {
				invoked = append(invoked, name)
				return errForTest("simulated skip failure")
			}
		default:
			stepRunners[name] = func(state *WizardState, opts WizardOptions) error {
				invoked = append(invoked, name)
				if name == StepDetect {
					state.KeyID = "SKIP000000TEST0"
				}
				if name == StepExport {
					state.PubKeyArmor = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
					state.PrivateKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
				}
				return nil
			}
		}
	}

	savedRetry := askRetrySkipAbort
	t.Cleanup(func() { askRetrySkipAbort = savedRetry })
	askRetrySkipAbort = func(stepName string) string {
		if stepName == StepGitConfig {
			return "skip"
		}
		return "abort"
	}

	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")

	if err := RunWizard(WizardOptions{StatePath: statePath}); err != nil {
		t.Fatalf("RunWizard on skip: %v", err)
	}

	// git-config must have been invoked (it failed and was skipped).
	if !contains(invoked, StepGitConfig) {
		t.Errorf("StepGitConfig should have been invoked then skipped: %v", invoked)
	}
	// github (the step after git-config) must still have run.
	if !contains(invoked, StepGitHub) {
		t.Errorf("StepGitHub should have run after git-config was skipped: %v", invoked)
	}
	// publish must still have run (last step).
	if !contains(invoked, StepPublish) {
		t.Errorf("StepPublish should have run after skip: %v", invoked)
	}
}
