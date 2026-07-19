package gpg

// GenerateParams describes the inputs for a new GPG key.
type GenerateParams struct {
	NameReal    string
	NameEmail   string
	NameComment string
	KeyType     string // e.g. "RSA"
	KeyLength   int    // e.g. 4096
	ExpireDate  string // gpg date spec, e.g. "2y" or "0" for never
	Passphrase  string
}

// GenerateKey drives 'gpg --full-generate-key' with a batch parameter
// file and --pinentry-mode loopback so the passphrase collected by the
// wizard is piped in without an interactive pinentry dialog.
//
// TODO(milestone 3): implement. Build the batch file from GenerateParams,
// write it to a temp file (mode 0600), shell out to gpg, and shred the
// file on success or error. Never log the passphrase.
func GenerateKey(p GenerateParams) (KeyID string, err error) {
	return "", errNotImplemented("generate")
}

// errNotImplemented is the standard sentinel returned by stub functions
// so callers can distinguish "not yet built" from a real failure.
func errNotImplemented(op string) error {
	return &notImplementedError{op: op}
}

type notImplementedError struct{ op string }

func (e *notImplementedError) Error() string {
	return "gpg: " + e.op + ": not implemented yet"
}