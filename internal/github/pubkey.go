package github

// UploadPublicKey uploads an ASCII-armored public key to the
// authenticated user's GitHub account via the users/gpg_keys REST API.
// Requires a PAT with 'admin:gpg_key' scope. If a key with the same
// fingerprint already exists, it is not re-uploaded.
//
// TODO(milestone 6): implement.
func UploadPublicKey(armoredPubKey, token string) (keyID int, err error) {
	return 0, errNotImplemented("upload public key")
}

// ListUserGpgKeys lists the GPG public keys already uploaded to the
// authenticated user's GitHub account. Used by 'status' to detect
// whether the publish step has been run.
//
// TODO(milestone 6): implement.
func ListUserGpgKeys(token string) ([]GpgKeyRef, error) {
	return nil, errNotImplemented("list user gpg keys")
}

// GpgKeyRef is a minimal view of a GitHub GPG key record.
type GpgKeyRef struct {
	ID          int64
	KeyID       string
	Fingerprint string
}
