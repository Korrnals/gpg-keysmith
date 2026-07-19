package gpg

import "io"

// ExportPublicKey runs 'gpg --armor --export <keyid>' and writes the
// ASCII-armored public key to w.
//
// TODO(milestone 4): implement.
func ExportPublicKey(keyID string, w io.Writer) error {
	return errNotImplemented("export public key")
}

// ExportPrivateKey runs 'gpg --armor --export-secret-keys <keyid>' with
// --pinentry-mode loopback and the supplied passphrase, writing the
// ASCII-armored private key to w. The private key MUST NOT be written
// to disk in plaintext; callers should pipe it directly to the GitHub
// secrets step.
//
// TODO(milestone 4): implement.
func ExportPrivateKey(keyID, passphrase string, w io.Writer) error {
	return errNotImplemented("export private key")
}