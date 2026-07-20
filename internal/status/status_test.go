package status

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Korrnals/gpg-keysmith/internal/github"
	"github.com/Korrnals/gpg-keysmith/internal/gpg"
)

// fakeDoer implements httpDoer by returning a canned response. Used
// by the keyserver check tests to avoid real HTTP calls.
type fakeDoer struct {
	status int
	body   string
	err    error
	calls  int
}

func (f *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &http.Response{
		StatusCode: f.status,
		Body:       io.NopCloser(strings.NewReader(f.body)),
		Header:     make(http.Header),
	}, nil
}

// saveMocks saves all injectable function variables and returns a
// restore closure. Callers MUST defer it so tests do not leak mocks
// into other tests.
func saveMocks() func() {
	savedDetect := detectKeysFn
	savedSigning := detectSigningKeyFn
	savedGpgsign := getCommitGpgsignFn
	savedListUser := listUserGpgKeysFn
	savedListRepo := listRepoSecretsFn
	savedClient := keyserverClient
	return func() {
		detectKeysFn = savedDetect
		detectSigningKeyFn = savedSigning
		getCommitGpgsignFn = savedGpgsign
		listUserGpgKeysFn = savedListUser
		listRepoSecretsFn = savedListRepo
		keyserverClient = savedClient
	}
}

// allGreenMock wires every check to return a successful result.
func allGreenMock() {
	detectKeysFn = func() ([]gpg.GpgKey, error) {
		return []gpg.GpgKey{{KeyID: "ABCDEF0123456789", Fingerprint: "ABCDEF0123456789ABCDEF0123456789ABCDEF01"}}, nil
	}
	detectSigningKeyFn = func(bool) (string, error) { return "ABCDEF0123456789", nil }
	getCommitGpgsignFn = func() (string, error) { return "true", nil }
	listUserGpgKeysFn = func(string) ([]github.GpgKeyRef, error) {
		return []github.GpgKeyRef{{KeyID: "ABC123"}}, nil
	}
	listRepoSecretsFn = func(string, string, string) ([]string, error) {
		return []string{"GPG_PRIVATE_KEY", "GPG_PASSPHRASE"}, nil
	}
	keyserverClient = &fakeDoer{status: http.StatusOK, body: ""}
}

// TestCollectStatus_AllGreen verifies that when every check succeeds
// the report is all ✅.
func TestCollectStatus_AllGreen(t *testing.T) {
	restore := saveMocks()
	defer restore()
	allGreenMock()

	report := CollectStatus(StatusOptions{
		GitHubToken: "fake-token",
		Repo:        "owner/repo",
		Keyserver:   "keys.openpgp.org",
	})

	checks := []struct {
		name string
		got  CheckResult
	}{
		{"GpgKeys", report.GpgKeys},
		{"GitConfig", report.GitConfig},
		{"GitHubPubKey", report.GitHubPubKey},
		{"RepoSecrets", report.RepoSecrets},
		{"Keyserver", report.Keyserver},
	}
	for _, c := range checks {
		if c.got.Status != StatusOK {
			t.Errorf("%s: got %s (detail=%q, hint=%q), want %s",
				c.name, c.got.Status, c.got.Detail, c.got.Hint, StatusOK)
		}
		if c.got.Hint != "" {
			t.Errorf("%s: ✅ should have empty hint, got %q", c.name, c.got.Hint)
		}
	}
}

// TestCollectStatus_AllRed verifies the no-keys cascading case: GPG
// keys ❌, git config ❌, GitHub pubkey ❌, repo secrets ❌, keyserver
// ⚠️ (no key to check).
func TestCollectStatus_AllRed(t *testing.T) {
	restore := saveMocks()
	defer restore()

	detectKeysFn = func() ([]gpg.GpgKey, error) { return nil, nil }
	detectSigningKeyFn = func(bool) (string, error) { return "", nil }
	getCommitGpgsignFn = func() (string, error) { return "", nil }
	listUserGpgKeysFn = func(string) ([]github.GpgKeyRef, error) {
		return nil, nil
	}
	listRepoSecretsFn = func(string, string, string) ([]string, error) {
		return nil, nil
	}
	keyserverClient = &fakeDoer{status: http.StatusNotFound}

	report := CollectStatus(StatusOptions{
		GitHubToken: "fake-token",
		Repo:        "owner/repo",
		Keyserver:   "keys.openpgp.org",
	})

	if report.GpgKeys.Status != StatusFail {
		t.Errorf("GpgKeys: got %s, want %s", report.GpgKeys.Status, StatusFail)
	}
	if report.GitConfig.Status != StatusFail {
		t.Errorf("GitConfig: got %s, want %s", report.GitConfig.Status, StatusFail)
	}
	if report.GitHubPubKey.Status != StatusFail {
		t.Errorf("GitHubPubKey: got %s, want %s", report.GitHubPubKey.Status, StatusFail)
	}
	if report.RepoSecrets.Status != StatusFail {
		t.Errorf("RepoSecrets: got %s, want %s", report.RepoSecrets.Status, StatusFail)
	}
	// Keyserver is ⚠️ because fingerprint derived from gpg keys is
	// empty (no keys → no fingerprint).
	if report.Keyserver.Status != StatusWarn {
		t.Errorf("Keyserver: got %s, want %s (detail=%q)",
			report.Keyserver.Status, StatusWarn, report.Keyserver.Detail)
	}
}

// TestCollectStatus_TokenMissing verifies that when GitHubToken is
// empty the GitHub pubkey and repo secrets checks degrade to ⚠️.
func TestCollectStatus_TokenMissing(t *testing.T) {
	restore := saveMocks()
	defer restore()
	allGreenMock()

	report := CollectStatus(StatusOptions{
		GitHubToken: "",
		Repo:        "owner/repo",
		Keyserver:   "keys.openpgp.org",
	})

	if report.GitHubPubKey.Status != StatusWarn {
		t.Errorf("GitHubPubKey: got %s, want %s (detail=%q)",
			report.GitHubPubKey.Status, StatusWarn, report.GitHubPubKey.Detail)
	}
	if report.RepoSecrets.Status != StatusWarn {
		t.Errorf("RepoSecrets: got %s, want %s (detail=%q)",
			report.RepoSecrets.Status, StatusWarn, report.RepoSecrets.Detail)
	}
}

// TestCollectStatus_RepoMissing verifies that when Repo is empty the
// repo secrets check degrades to ⚠️.
func TestCollectStatus_RepoMissing(t *testing.T) {
	restore := saveMocks()
	defer restore()
	allGreenMock()

	report := CollectStatus(StatusOptions{
		GitHubToken: "fake-token",
		Repo:        "",
		Keyserver:   "keys.openpgp.org",
	})

	if report.RepoSecrets.Status != StatusWarn {
		t.Errorf("RepoSecrets: got %s, want %s (detail=%q)",
			report.RepoSecrets.Status, StatusWarn, report.RepoSecrets.Detail)
	}
}

// TestCollectStatus_PartialSecrets verifies the ⚠️ case where only one
// of the two CI secrets is set.
func TestCollectStatus_PartialSecrets(t *testing.T) {
	restore := saveMocks()
	defer restore()
	allGreenMock()

	listRepoSecretsFn = func(string, string, string) ([]string, error) {
		return []string{"GPG_PRIVATE_KEY"}, nil
	}

	report := CollectStatus(StatusOptions{
		GitHubToken: "fake-token",
		Repo:        "owner/repo",
		Keyserver:   "keys.openpgp.org",
	})

	if report.RepoSecrets.Status != StatusWarn {
		t.Errorf("RepoSecrets: got %s, want %s (detail=%q)",
			report.RepoSecrets.Status, StatusWarn, report.RepoSecrets.Detail)
	}
	if !strings.Contains(report.RepoSecrets.Detail, "GPG_PASSPHRASE missing") {
		t.Errorf("RepoSecrets detail should mention missing passphrase, got %q",
			report.RepoSecrets.Detail)
	}
}

// TestCollectStatus_OneCheckFailsDoesNotAbortOthers verifies that when
// the GPG check fails (error), the other checks still run.
func TestCollectStatus_OneCheckFailsDoesNotAbortOthers(t *testing.T) {
	restore := saveMocks()
	defer restore()
	allGreenMock()

	detectKeysFn = func() ([]gpg.GpgKey, error) {
		return nil, errors.New("gpg binary not found")
	}

	report := CollectStatus(StatusOptions{
		GitHubToken: "fake-token",
		Repo:        "owner/repo",
		Keyserver:   "keys.openpgp.org",
	})

	if report.GpgKeys.Status != StatusFail {
		t.Errorf("GpgKeys: got %s, want %s", report.GpgKeys.Status, StatusFail)
	}
	// Other checks must still have results (not zero-value).
	if report.GitConfig.Status == "" {
		t.Error("GitConfig must still run after GpgKeys failure")
	}
	if report.GitHubPubKey.Status == "" {
		t.Error("GitHubPubKey must still run after GpgKeys failure")
	}
	if report.RepoSecrets.Status == "" {
		t.Error("RepoSecrets must still run after GpgKeys failure")
	}
	if report.Keyserver.Status == "" {
		t.Error("Keyserver must still run after GpgKeys failure")
	}
}

// TestCheckGitConfig_PartialWarn verifies the ⚠️ case where
// signingkey is set but commit.gpgsign is not true.
func TestCheckGitConfig_PartialWarn(t *testing.T) {
	restore := saveMocks()
	defer restore()

	detectSigningKeyFn = func(bool) (string, error) { return "ABCDEF0123456789", nil }
	getCommitGpgsignFn = func() (string, error) { return "", nil }

	r := checkGitConfig()
	if r.Status != StatusWarn {
		t.Errorf("got %s, want %s (detail=%q)", r.Status, StatusWarn, r.Detail)
	}
}

// TestCheckKeyserver_404 verifies that a 404 response from the
// keyserver produces a ❌ with a publish hint.
func TestCheckKeyserver_404(t *testing.T) {
	restore := saveMocks()
	defer restore()

	keyserverClient = &fakeDoer{status: http.StatusNotFound}

	r := checkKeyserver("ABCDEF0123456789ABCDEF0123456789ABCDEF01", "keys.openpgp.org")
	if r.Status != StatusFail {
		t.Errorf("got %s, want %s (detail=%q)", r.Status, StatusFail, r.Detail)
	}
	if r.Hint == "" {
		t.Error("404 should produce a non-empty hint")
	}
}

// TestCheckKeyserver_RequestError verifies that a transport error
// produces ⚠️ (not ❌).
func TestCheckKeyserver_RequestError(t *testing.T) {
	restore := saveMocks()
	defer restore()

	keyserverClient = &fakeDoer{err: errors.New("network down")}

	r := checkKeyserver("ABCDEF0123456789ABCDEF0123456789ABCDEF01", "keys.openpgp.org")
	if r.Status != StatusWarn {
		t.Errorf("got %s, want %s (detail=%q)", r.Status, StatusWarn, r.Detail)
	}
}

// TestCheckKeyserver_EmptyFingerprint verifies that an empty
// fingerprint produces ⚠️.
func TestCheckKeyserver_EmptyFingerprint(t *testing.T) {
	restore := saveMocks()
	defer restore()

	keyserverClient = &fakeDoer{status: http.StatusOK}

	r := checkKeyserver("", "keys.openpgp.org")
	if r.Status != StatusWarn {
		t.Errorf("got %s, want %s (detail=%q)", r.Status, StatusWarn, r.Detail)
	}
}

// TestKeyserverLookupURL verifies URL construction for the supported
// keyservers.
func TestKeyserverLookupURL(t *testing.T) {
	fp := "AB CD EF 01 23 45 67 89 AB CD EF 01 23 45 67 89 AB CD EF 01"
	tests := []struct {
		keyserver string
		wantHas   string
	}{
		{"keys.openpgp.org", "https://keys.openpgp.org/vks/vby/abcdef0123456789abcdef0123456789abcdef01"},
		{"keyserver.ubuntu.com", "https://keyserver.ubuntu.com/pks/lookup?op=vindex&search=0xabcdef0123456789abcdef0123456789abcdef01"},
		{"custom.example.com", "https://custom.example.com/pks/lookup?op=vindex&search=0xabcdef0123456789abcdef0123456789abcdef01"},
	}
	for _, tc := range tests {
		got := keyserverLookupURL(tc.keyserver, fp)
		if got != tc.wantHas {
			t.Errorf("keyserverLookupURL(%q) = %q, want %q", tc.keyserver, got, tc.wantHas)
		}
	}
}

// TestTruncateKey verifies that long key ids are truncated with an
// ellipsis.
func TestTruncateKey(t *testing.T) {
	if got := truncateKey("ABCDEF0123456789ABCDEF0123456789ABCDEF01", 16); got != "ABCDEF0123456789..." {
		t.Errorf("got %q, want %q", got, "ABCDEF0123456789...")
	}
	if got := truncateKey("ABC123", 16); got != "ABC123" {
		t.Errorf("short key should be unchanged, got %q", got)
	}
}

// TestContainsString verifies the helper.
func TestContainsString(t *testing.T) {
	s := []string{"GPG_PRIVATE_KEY", "GPG_PASSPHRASE"}
	if !containsString(s, "GPG_PRIVATE_KEY") {
		t.Error("containsString should find GPG_PRIVATE_KEY")
	}
	if containsString(s, "MISSING") {
		t.Error("containsString should not find MISSING")
	}
}
