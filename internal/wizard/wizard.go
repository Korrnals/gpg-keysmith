// Package wizard orchestrates the full gpg-keysmith setup flow:
// detect → generate → export → git-config → github → publish. Each
// step is recorded in a state file so a failed run can be resumed from
// the last successful step.
package wizard

// Run executes the interactive setup wizard. It prompts the user for
// each missing piece (name, email, passphrase, GitHub PAT), runs the
// appropriate gpg-keysmith operation, and writes progress to
// ~/.config/gpg-keysmith/state.json so a later 'keysmith wizard' run
// resumes from the last incomplete step.
//
// TODO(milestone 8): implement.
func Run() error {
	return errNotImplemented("run")
}

// errNotImplemented is the standard sentinel returned by stub functions.
func errNotImplemented(op string) error {
	return &notImplementedError{op: op}
}

type notImplementedError struct{ op string }

func (e *notImplementedError) Error() string {
	return "wizard: " + e.op + ": not implemented yet"
}