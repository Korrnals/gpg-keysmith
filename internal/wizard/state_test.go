package wizard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestSaveState_IsAtomic verifies SaveState writes to <path>.tmp,
// fsyncs, then os.Renames over the final path — so a crash mid-write
// never leaves a truncated/empty state file at the final path.
//
// Two subtests cover the two torn-write scenarios called out in
// issue #21:
//
//  1. No prior state, a new save succeeds, LoadState returns the new
//     state (proving the rename replaced any non-existent content
//     atomically — there is never a window where the final path
//     points at a half-written file).
//  2. A valid prior state exists at the final path AND a stale
//     truncated .tmp from a "previous crash" lingers. SaveState must
//     overwrite the stale .tmp and rename over the final path;
//     LoadState then returns the NEW state, never the stale garbage
//     in the .tmp and never a torn final path.
//
// We do NOT actually kill the process mid-write — real SIGKILL tests
// are flaky and not needed. The atomicity guarantee comes from
// os.Rename being atomic on POSIX (same filesystem): the final path
// either points at the old file or the new file, never at a partial
// write. t.TempDir() is on the same filesystem as its parent, so the
// rename is atomic here.
func TestSaveState_IsAtomic(t *testing.T) {
	t.Run("fresh_save_loads_new_state", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "state.json")

		newState := &WizardState{
			Step:           StepExport,
			CompletedSteps: []string{StepDetect, StepGenerate},
			KeyID:          "ATOM0001NEW00001",
			Email:          "fresh@example.com",
			Repo:           "owner/fresh",
			GithubKeyID:    "12345",
			StatePath:      path,
		}
		if err := SaveState(newState); err != nil {
			t.Fatalf("SaveState: %v", err)
		}

		// The .tmp must be gone after a successful save (rename
		// moved it; on error the cleanup removes it).
		if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
			t.Errorf("stale .tmp left behind after successful save: %v", err)
		}

		loaded, err := LoadState(path)
		if err != nil {
			t.Fatalf("LoadState: %v", err)
		}
		if loaded.KeyID != newState.KeyID {
			t.Errorf("KeyID = %q, want %q (new state)", loaded.KeyID, newState.KeyID)
		}
		if loaded.GithubKeyID != newState.GithubKeyID {
			t.Errorf("GithubKeyID = %q, want %q", loaded.GithubKeyID, newState.GithubKeyID)
		}
		if loaded.Email != newState.Email {
			t.Errorf("Email = %q, want %q", loaded.Email, newState.Email)
		}
	})

	t.Run("stale_truncated_tmp_is_overwritten_not_read", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "state.json")
		tmp := path + ".tmp"

		// Pre-populate the final path with a VALID prior state.
		prior := &WizardState{
			Step:           StepGenerate,
			CompletedSteps: []string{StepDetect},
			KeyID:          "PRIOR000OLD0000",
			Email:          "prior@example.com",
			Repo:           "owner/prior",
			GithubKeyID:    "67890",
			StatePath:      path,
		}
		priorData, err := json.MarshalIndent(prior, "", "  ")
		if err != nil {
			t.Fatalf("marshal prior state: %v", err)
		}
		if err := os.WriteFile(path, priorData, 0o600); err != nil {
			t.Fatalf("write prior state: %v", err)
		}

		// Simulate a crashed previous run: leave a truncated .tmp
		// that is NOT valid JSON (a half-written state file).
		truncated := []byte(`{"step":"export","completed_steps":["detect","generate` + "\x00" + ``)
		if err := os.WriteFile(tmp, truncated, 0o600); err != nil {
			t.Fatalf("write stale truncated .tmp: %v", err)
		}

		// The truncated .tmp must NOT parse as valid JSON — this
		// is the corruption SaveState must never expose at the
		// final path.
		if err := json.Unmarshal(truncated, &struct{}{}); err == nil {
			t.Fatal("truncated .tmp unexpectedly parses as valid JSON — test fixture is broken")
		}

		// Now save a NEW state. SaveState must overwrite the stale
		// .tmp (O_TRUNC) and rename it over the final path. The
		// final path must never point at the truncated bytes.
		newState := &WizardState{
			Step:           StepGitHub,
			CompletedSteps: []string{StepDetect, StepGenerate, StepExport, StepGitConfig},
			KeyID:          "ATOM0002NEW00002",
			Email:          "new@example.com",
			Repo:           "owner/new",
			GithubKeyID:    "99999",
			StatePath:      path,
		}
		if err := SaveState(newState); err != nil {
			t.Fatalf("SaveState: %v", err)
		}

		// Stale .tmp must be gone.
		if _, err := os.Stat(tmp); !os.IsNotExist(err) {
			t.Errorf("stale .tmp left behind after successful save: %v", err)
		}

		// Final path must contain the NEW state — load and compare.
		loaded, err := LoadState(path)
		if err != nil {
			t.Fatalf("LoadState after atomic save: %v — final path may contain torn bytes", err)
		}
		if loaded.KeyID != newState.KeyID {
			t.Errorf("KeyID = %q, want %q (new state, not prior %q and not torn .tmp)",
				loaded.KeyID, newState.KeyID, prior.KeyID)
		}
		if loaded.GithubKeyID != newState.GithubKeyID {
			t.Errorf("GithubKeyID = %q, want %q", loaded.GithubKeyID, newState.GithubKeyID)
		}
		if loaded.Step != newState.Step {
			t.Errorf("Step = %q, want %q", loaded.Step, newState.Step)
		}
		if loaded.Email == prior.Email {
			t.Errorf("Email = %q — loaded the PRIOR state, not the new one", loaded.Email)
		}
	})
}
