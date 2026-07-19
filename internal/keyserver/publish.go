// Package keyserver publishes a public GPG key to a public keyserver
// (keys.openpgp.org preferred, keyserver.ubuntu.com fallback).
package keyserver

// PublishResult holds the outcome of a publish attempt, including the
// fetchable URL of the uploaded key.
type PublishResult struct {
	Keyserver string
	URL       string
}

// Publish uploads the armored public key to keys.openpgp.org (preferred)
// and keyserver.ubuntu.com (fallback). Returns one PublishResult per
// keyserver that accepted the upload.
//
// TODO(milestone 7): implement. Use the HTTPS submit endpoints, not
// the legacy HKP hkp:// protocol.
func Publish(armoredPubKey string) ([]PublishResult, error) {
	return nil, errNotImplemented("publish")
}

// errNotImplemented is the standard sentinel returned by stub functions.
func errNotImplemented(op string) error {
	return &notImplementedError{op: op}
}

type notImplementedError struct{ op string }

func (e *notImplementedError) Error() string {
	return "keyserver: " + e.op + ": not implemented yet"
}
