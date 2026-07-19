package github

// CommitPublicKeyFile commits the supplied armored public key text as
// 'gpg-public-key.asc' to the target repo on a
// 'chore/add-gpg-public-key' branch and opens a pull request. Returns
// the PR URL.
//
// TODO(milestone 6): implement. Prefer go-git for the branch + commit;
// fall back to shelling out to 'git' if go-git proves limiting.
func CommitPublicKeyFile(owner, repo, armoredPubKey, token string) (prURL string, err error) {
	return "", errNotImplemented("commit public key file")
}
