package github

import (
	"errors"
	"net/http"
	"os/exec"
	"strings"
	"testing"
)

// TestSetRepoSecret_EmptyTokenReturnsError verifies the token guard
// fires before lookPath or any shell-out.
func TestSetRepoSecret_EmptyTokenReturnsError(t *testing.T) {
	orig := lookPath
	lookPath = func(string) (string, error) { return "", errors.New("not found") }
	t.Cleanup(func() { lookPath = orig })

	err := SetRepoSecret("", "owner", "repo", "MY_SECRET", "value")
	if err == nil {
		t.Fatal("SetRepoSecret with empty token must error")
	}
	if !strings.Contains(err.Error(), "token") {
		t.Errorf("error should mention token, got: %v", err)
	}
}

// TestSetRepoSecret_EmptyOwnerReturnsError verifies the owner guard.
func TestSetRepoSecret_EmptyOwnerReturnsError(t *testing.T) {
	err := SetRepoSecret("tok", "", "repo", "MY_SECRET", "value")
	if err == nil {
		t.Fatal("SetRepoSecret with empty owner must error")
	}
	if !strings.Contains(err.Error(), "owner") {
		t.Errorf("error should mention owner, got: %v", err)
	}
}

// TestSetRepoSecret_EmptyRepoReturnsError verifies the repo guard.
func TestSetRepoSecret_EmptyRepoReturnsError(t *testing.T) {
	err := SetRepoSecret("tok", "owner", "", "MY_SECRET", "value")
	if err == nil {
		t.Fatal("SetRepoSecret with empty repo must error")
	}
	if !strings.Contains(err.Error(), "repo") {
		t.Errorf("error should mention repo, got: %v", err)
	}
}

// TestSetRepoSecret_EmptySecretNameReturnsError verifies the
// secret-name guard.
func TestSetRepoSecret_EmptySecretNameReturnsError(t *testing.T) {
	err := SetRepoSecret("tok", "owner", "repo", "", "value")
	if err == nil {
		t.Fatal("SetRepoSecret with empty name must error")
	}
}

// TestSetRepoSecret_InvalidSecretNameReturnsError verifies the
// validateSecretName rules.
func TestSetRepoSecret_InvalidSecretNameReturnsError(t *testing.T) {
	bad := []string{
		"1SECRET",      // starts with digit
		"GITHUB_TOKEN", // reserved prefix
		"secret-name",  // dash not allowed
		"secret.name",  // dot not allowed
		"has space",    // space not allowed
	}
	for _, name := range bad {
		err := SetRepoSecret("tok", "owner", "repo", name, "value")
		if err == nil {
			t.Errorf("SetRepoSecret(%q) must error", name)
		}
	}
}

// TestSetRepoSecret_EmptySecretValueReturnsError verifies the value
// guard fires before lookPath.
func TestSetRepoSecret_EmptySecretValueReturnsError(t *testing.T) {
	orig := lookPath
	called := false
	lookPath = func(string) (string, error) {
		called = true
		return "/usr/bin/gh", nil
	}
	t.Cleanup(func() { lookPath = orig })

	err := SetRepoSecret("tok", "owner", "repo", "MY_SECRET", "")
	if err == nil {
		t.Fatal("SetRepoSecret with empty value must error")
	}
	if !strings.Contains(err.Error(), "REDACTED") {
		t.Errorf("error should use <REDACTED>, got: %v", err)
	}
	if called {
		t.Error("lookPath must NOT be called when value is empty")
	}
}

// TestSetRepoSecret_GhNotFound verifies the *ErrGhCLINotFound path.
// We replace lookPath to simulate 'gh' missing.
func TestSetRepoSecret_GhNotFound(t *testing.T) {
	orig := lookPath
	lookPath = func(string) (string, error) {
		return "", exec.ErrNotFound
	}
	t.Cleanup(func() { lookPath = orig })

	err := SetRepoSecret("tok", "owner", "repo", "MY_SECRET", "value")
	if err == nil {
		t.Fatal("SetRepoSecret with missing gh must error")
	}
	var e *ErrGhCLINotFound
	if !errors.As(err, &e) {
		t.Errorf("error must be *ErrGhCLINotFound, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "cli.github.com") {
		t.Errorf("error should mention install URL, got: %v", err)
	}
}

// TestValidateSecretName_AcceptsValid verifies valid names pass.
func TestValidateSecretName_AcceptsValid(t *testing.T) {
	good := []string{
		"GPG_PRIVATE_KEY",
		"GPG_PASSPHRASE",
		"MY_SECRET",
		"SECRET_1",
		"_LEADING_UNDERSCORE",
	}
	for _, name := range good {
		if err := validateSecretName(name); err != nil {
			t.Errorf("validateSecretName(%q) must pass, got: %v", name, err)
		}
	}
}

// TestSetGPGSecrets_EmptyPrivateKeyReturnsError verifies the private
// key guard fires before any SetRepoSecret call.
func TestSetGPGSecrets_EmptyPrivateKeyReturnsError(t *testing.T) {
	orig := lookPath
	called := false
	lookPath = func(string) (string, error) {
		called = true
		return "/usr/bin/gh", nil
	}
	t.Cleanup(func() { lookPath = orig })

	err := SetGPGSecrets("tok", "owner", "repo", "", "passphrase")
	if err == nil {
		t.Fatal("SetGPGSecrets with empty private key must error")
	}
	if called {
		t.Error("lookPath must NOT be called when private key is empty")
	}
}

// TestSetGPGSecrets_EmptyPassphraseReturnsError verifies the
// passphrase guard.
func TestSetGPGSecrets_EmptyPassphraseReturnsError(t *testing.T) {
	err := SetGPGSecrets("tok", "owner", "repo", "private", "")
	if err == nil {
		t.Fatal("SetGPGSecrets with empty passphrase must error")
	}
	if !strings.Contains(err.Error(), "passphrase") {
		t.Errorf("error should mention passphrase, got: %v", err)
	}
}

// TestSetGPGSecrets_GhNotFoundOnFirstSecret verifies that when gh is
// missing, the first SetRepoSecret call surfaces ErrGhCLINotFound.
func TestSetGPGSecrets_GhNotFoundOnFirstSecret(t *testing.T) {
	orig := lookPath
	lookPath = func(string) (string, error) {
		return "", exec.ErrNotFound
	}
	t.Cleanup(func() { lookPath = orig })

	err := SetGPGSecrets("tok", "owner", "repo", "private-key-armor", "passphrase")
	if err == nil {
		t.Fatal("SetGPGSecrets with missing gh must error")
	}
	var e *ErrGhCLINotFound
	if !errors.As(err, &e) {
		t.Errorf("error must wrap *ErrGhCLINotFound, got %T: %v", err, err)
	}
}

// TestRedactInString verifies secret values are replaced.
func TestRedactInString(t *testing.T) {
	got := redactInString("error: my-secret-value failed", "my-secret-value")
	if strings.Contains(got, "my-secret-value") {
		t.Errorf("redactInString must replace the secret, got: %q", got)
	}
	if !strings.Contains(got, "<REDACTED>") {
		t.Errorf("redactInString must insert <REDACTED>, got: %q", got)
	}
}

// TestListRepoSecrets_EmptyTokenReturnsError verifies the token guard
// fires before any HTTP call.
func TestListRepoSecrets_EmptyTokenReturnsError(t *testing.T) {
	f := &fakeDoer{responses: map[string]func(*http.Request) *http.Response{}}
	_, err := ListRepoSecretsWithClient("", "owner", "repo", f)
	if err == nil {
		t.Fatal("ListRepoSecrets with empty token must error")
	}
	if !strings.Contains(err.Error(), "token") {
		t.Errorf("error should mention token, got: %v", err)
	}
	if len(f.calls) != 0 {
		t.Errorf("no HTTP calls should be made with empty token, got %d", len(f.calls))
	}
}

// TestListRepoSecrets_EmptyOwnerReturnsError verifies the owner guard.
func TestListRepoSecrets_EmptyOwnerReturnsError(t *testing.T) {
	f := &fakeDoer{responses: map[string]func(*http.Request) *http.Response{}}
	_, err := ListRepoSecretsWithClient("tok", "", "repo", f)
	if err == nil {
		t.Fatal("ListRepoSecrets with empty owner must error")
	}
	if !strings.Contains(err.Error(), "owner") {
		t.Errorf("error should mention owner, got: %v", err)
	}
}

// TestListRepoSecrets_EmptyRepoReturnsError verifies the repo guard.
func TestListRepoSecrets_EmptyRepoReturnsError(t *testing.T) {
	f := &fakeDoer{responses: map[string]func(*http.Request) *http.Response{}}
	_, err := ListRepoSecretsWithClient("tok", "owner", "", f)
	if err == nil {
		t.Fatal("ListRepoSecrets with empty repo must error")
	}
	if !strings.Contains(err.Error(), "repo") {
		t.Errorf("error should mention repo, got: %v", err)
	}
}

// TestListRepoSecrets_Success verifies that a 200 response with a
// secrets array returns the secret names.
func TestListRepoSecrets_Success(t *testing.T) {
	f := &fakeDoer{responses: map[string]func(*http.Request) *http.Response{
		"GET /repos/owner/repo/actions/secrets": func(*http.Request) *http.Response {
			return jsonResp(200, map[string]interface{}{
				"secrets": []map[string]string{
					{"name": "GPG_PRIVATE_KEY"},
					{"name": "GPG_PASSPHRASE"},
				},
			})
		},
	}}
	names, err := ListRepoSecretsWithClient("tok", "owner", "repo", f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(names) != 2 {
		t.Fatalf("got %d names, want 2", len(names))
	}
	if !containsStr(names, "GPG_PRIVATE_KEY") {
		t.Errorf("names should contain GPG_PRIVATE_KEY, got %v", names)
	}
	if !containsStr(names, "GPG_PASSPHRASE") {
		t.Errorf("names should contain GPG_PASSPHRASE, got %v", names)
	}
	// Verify Authorization header was set.
	var lastCall recordedCall
	for _, c := range f.calls {
		lastCall = c
	}
	if lastCall.header.Get("Authorization") != "Bearer tok" {
		t.Errorf("Authorization = %q, want 'Bearer tok'", lastCall.header.Get("Authorization"))
	}
}

// TestListRepoSecrets_EmptyList verifies that a 200 response with no
// secrets returns an empty slice (not nil, not an error).
func TestListRepoSecrets_EmptyList(t *testing.T) {
	f := &fakeDoer{responses: map[string]func(*http.Request) *http.Response{
		"GET /repos/owner/repo/actions/secrets": func(*http.Request) *http.Response {
			return jsonResp(200, map[string]interface{}{"secrets": []map[string]string{}})
		},
	}}
	names, err := ListRepoSecretsWithClient("tok", "owner", "repo", f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("got %d names, want 0", len(names))
	}
}

// TestListRepoSecrets_APIError verifies a non-2xx status is surfaced as
// an error.
func TestListRepoSecrets_APIError(t *testing.T) {
	f := &fakeDoer{responses: map[string]func(*http.Request) *http.Response{
		"GET /repos/owner/repo/actions/secrets": func(*http.Request) *http.Response {
			return textResp(http.StatusNotFound, `{"message":"Not Found"}`)
		},
	}}
	_, err := ListRepoSecretsWithClient("tok", "owner", "repo", f)
	if err == nil {
		t.Fatal("ListRepoSecrets with 404 must error")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error should mention status 404, got: %v", err)
	}
}

// containsStr is a local helper for test assertions.
func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
