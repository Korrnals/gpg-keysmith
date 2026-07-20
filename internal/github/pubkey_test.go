package github

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// fakeDoer implements Doer by returning canned responses keyed by the
// request method+URL. It lets tests exercise the GitHub API surface
// without touching the network.
type fakeDoer struct {
	// responses maps "METHOD URL" to a canned *http.Response builder.
	responses map[string]func(*http.Request) *http.Response
	// calls records every Do invocation for assertions.
	calls []recordedCall
}

type recordedCall struct {
	method string
	url    string
	header http.Header
	body   string
}

func (f *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	bodyBytes := ""
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		bodyBytes = string(b)
		req.Body = io.NopCloser(strings.NewReader(bodyBytes))
	}
	f.calls = append(f.calls, recordedCall{
		method: req.Method,
		url:    req.URL.String(),
		header: req.Header.Clone(),
		body:   bodyBytes,
	})
	key := req.Method + " " + req.URL.Path
	builder, ok := f.responses[key]
	if !ok {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(strings.NewReader(`{"message":"Not Found"}`)),
			Header:     make(http.Header),
		}, nil
	}
	return builder(req), nil
}

// jsonResp builds a 200 OK JSON response.
func jsonResp(status int, body interface{}) *http.Response {
	b, _ := json.Marshal(body)
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(string(b))),
		Header:     make(http.Header),
	}
}

// textResp builds a text response (used for error bodies).
func textResp(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

const sampleArmor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQEN...\n-----END PGP PUBLIC KEY BLOCK-----\n"

// TestUploadPublicKey_EmptyTokenReturnsError verifies the token guard
// fires before any HTTP call is made.
func TestUploadPublicKey_EmptyTokenReturnsError(t *testing.T) {
	f := &fakeDoer{responses: map[string]func(*http.Request) *http.Response{}}
	_, err := UploadPublicKeyWithClient("", sampleArmor, f)
	if err == nil {
		t.Fatal("UploadPublicKey with empty token must error before HTTP call")
	}
	if !strings.Contains(err.Error(), "token") {
		t.Errorf("error should mention token, got: %v", err)
	}
	if len(f.calls) != 0 {
		t.Errorf("no HTTP calls should be made with empty token, got %d", len(f.calls))
	}
}

// TestUploadPublicKey_InvalidArmorReturnsError verifies the armor
// sanity check fires before any HTTP call.
func TestUploadPublicKey_InvalidArmorReturnsError(t *testing.T) {
	f := &fakeDoer{responses: map[string]func(*http.Request) *http.Response{}}
	_, err := UploadPublicKeyWithClient("tok", "not a pgp key", f)
	if err == nil {
		t.Fatal("UploadPublicKey with invalid armor must error before HTTP call")
	}
	if !strings.Contains(err.Error(), "PGP PUBLIC KEY BLOCK") {
		t.Errorf("error should mention PGP armor header, got: %v", err)
	}
	if len(f.calls) != 0 {
		t.Errorf("no HTTP calls should be made with invalid armor, got %d", len(f.calls))
	}
}

// TestUploadPublicKey_SuccessfulUpload verifies a 201 response with a
// fingerprint is returned when no existing key matches.
func TestUploadPublicKey_SuccessfulUpload(t *testing.T) {
	f := &fakeDoer{responses: map[string]func(*http.Request) *http.Response{
		"GET /user/gpg_keys": func(*http.Request) *http.Response {
			return jsonResp(200, []GpgKeyRef{})
		},
		"POST /user/gpg_keys": func(*http.Request) *http.Response {
			return jsonResp(201, uploadPublicKeyResponse{
				ID:          42,
				KeyID:       "ABC123",
				Fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			})
		},
	}}
	fp, err := UploadPublicKeyWithClient("tok", sampleArmor, f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("fingerprint = %q, want 40-a", fp)
	}
	// Verify the POST body shape.
	var lastCall recordedCall
	for _, c := range f.calls {
		if c.method == "POST" {
			lastCall = c
		}
	}
	var body struct {
		ArmoredPublicKey string `json:"armored_public_key"`
	}
	if err := json.Unmarshal([]byte(lastCall.body), &body); err != nil {
		t.Fatalf("POST body not valid JSON: %v", err)
	}
	if body.ArmoredPublicKey != sampleArmor {
		t.Errorf("POST body armored_public_key mismatch")
	}
	if lastCall.header.Get("Authorization") != "Bearer tok" {
		t.Errorf("Authorization header = %q, want 'Bearer tok'", lastCall.header.Get("Authorization"))
	}
}

// TestUploadPublicKeyWithFingerprint_ExistingKeySkipsUpload verifies
// that when the caller passes a fingerprint matching an existing key,
// no POST is made and the existing fingerprint is returned.
func TestUploadPublicKeyWithFingerprint_ExistingKeySkipsUpload(t *testing.T) {
	existing := []GpgKeyRef{
		{ID: 1, KeyID: "K1", Fingerprint: "ABCDEF0123456789ABCDEF0123456789ABCDEF01"},
	}
	f := &fakeDoer{responses: map[string]func(*http.Request) *http.Response{
		"GET /user/gpg_keys": func(*http.Request) *http.Response {
			return jsonResp(200, existing)
		},
	}}
	fp, err := UploadPublicKeyWithFingerprintAndClient("tok", sampleArmor,
		"ABCDEF0123456789ABCDEF0123456789ABCDEF01", f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp != "ABCDEF0123456789ABCDEF0123456789ABCDEF01" {
		t.Errorf("fingerprint = %q, want existing", fp)
	}
	// Only the GET should have been made — no POST.
	for _, c := range f.calls {
		if c.method == "POST" {
			t.Errorf("no POST should be made when key exists, got %s %s", c.method, c.url)
		}
	}
}

// TestUploadPublicKeyWithFingerprint_NormalisesFingerprint verifies
// that fingerprints with spaces or mixed case are matched correctly.
func TestUploadPublicKeyWithFingerprint_NormalisesFingerprint(t *testing.T) {
	existing := []GpgKeyRef{
		{ID: 1, KeyID: "K1", Fingerprint: "abcdef0123456789abcdef0123456789abcdef01"},
	}
	f := &fakeDoer{responses: map[string]func(*http.Request) *http.Response{
		"GET /user/gpg_keys": func(*http.Request) *http.Response {
			return jsonResp(200, existing)
		},
	}}
	// Pass uppercase with spaces — should match the lowercase existing.
	fp, err := UploadPublicKeyWithFingerprintAndClient("tok", sampleArmor,
		"AB CD EF 01 23 45 67 89 AB CD EF 01 23 45 67 89 AB CD EF 01", f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp == "" {
		t.Error("fingerprint should not be empty")
	}
}

// TestUploadPublicKey_APIError verifies a non-2xx status is surfaced
// as an error.
func TestUploadPublicKey_APIError(t *testing.T) {
	f := &fakeDoer{responses: map[string]func(*http.Request) *http.Response{
		"GET /user/gpg_keys": func(*http.Request) *http.Response {
			return jsonResp(200, []GpgKeyRef{})
		},
		"POST /user/gpg_keys": func(*http.Request) *http.Response {
			return textResp(401, `{"message":"Bad credentials"}`)
		},
	}}
	_, err := UploadPublicKeyWithClient("tok", sampleArmor, f)
	if err == nil {
		t.Fatal("UploadPublicKey with 401 must error")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error should mention status 401, got: %v", err)
	}
}

// TestUploadPublicKey_NewGitHubRequestError verifies a transport
// error from Do is wrapped and returned.
func TestUploadPublicKey_NewGitHubRequestError(t *testing.T) {
	f := &fakeDoer{responses: map[string]func(*http.Request) *http.Response{
		"GET /user/gpg_keys": func(*http.Request) *http.Response {
			return nil
		},
	}}
	// Override Do to return an error.
	errDoer := &errorDoer{err: errors.New("network down")}
	_, err := UploadPublicKeyWithClient("tok", sampleArmor, errDoer)
	if err == nil {
		t.Fatal("UploadPublicKey with transport error must error")
	}
	_ = f // keep fakeDoer used for compile
}

type errorDoer struct{ err error }

func (e *errorDoer) Do(req *http.Request) (*http.Response, error) {
	return nil, e.err
}

// TestListUserGpgKeys_EmptyTokenReturnsError verifies the token guard.
func TestListUserGpgKeys_EmptyTokenReturnsError(t *testing.T) {
	_, err := ListUserGpgKeys("")
	if err == nil {
		t.Fatal("ListUserGpgKeys with empty token must error")
	}
}

// TestListUserGpgKeys_Success verifies the happy path returns the
// decoded key list.
func TestListUserGpgKeys_Success(t *testing.T) {
	want := []GpgKeyRef{
		{ID: 1, KeyID: "A", Fingerprint: "aaa"},
		{ID: 2, KeyID: "B", Fingerprint: "bbb"},
	}
	f := &fakeDoer{responses: map[string]func(*http.Request) *http.Response{
		"GET /user/gpg_keys": func(*http.Request) *http.Response {
			return jsonResp(200, want)
		},
	}}
	got, err := ListUserGpgKeysWithClient("tok", f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("len = %d, want 2", len(got))
	}
	if got[0].Fingerprint != "aaa" {
		t.Errorf("got[0].Fingerprint = %q, want aaa", got[0].Fingerprint)
	}
}

// TestNormaliseFingerprint verifies space stripping + lowercasing.
func TestNormaliseFingerprint(t *testing.T) {
	cases := []struct{ in, want string }{
		{"AB CD EF", "abcdef"},
		{"  AB C  ", "abc"},
		{"abcdef", "abcdef"},
		{"", ""},
	}
	for _, c := range cases {
		if got := normaliseFingerprint(c.in); got != c.want {
			t.Errorf("normaliseFingerprint(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
