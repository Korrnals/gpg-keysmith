package keyserver

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// fakeDoer implements httpDoer by returning canned responses keyed by
// the request URL. It lets tests exercise the keyserver API surface
// without touching the network.
type fakeDoer struct {
	// responses maps the full request URL to a canned *http.Response
	// builder. The key is req.URL.String().
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
	builder, ok := f.responses[req.URL.String()]
	if !ok {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(strings.NewReader(`{"message":"Not Found"}`)),
			Header:     make(http.Header),
		}, nil
	}
	return builder(req), nil
}

// textResp builds a response with the given status and body.
func textResp(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

const sampleArmor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQEN...\n-----END PGP PUBLIC KEY BLOCK-----\n"
const sampleFingerprint = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"

// TestPublishPubKey_EmptyArmoredKeyReturnsError verifies the empty
// armor guard fires before any HTTP call.
func TestPublishPubKey_EmptyArmoredKeyReturnsError(t *testing.T) {
	f := &fakeDoer{responses: map[string]func(*http.Request) *http.Response{}}
	_, err := PublishPubKey(PublishOptions{
		ArmoredPubKey: "",
		Keyserver:     KeyserverOpenPGP,
		Doer:          f,
	})
	if err == nil {
		t.Fatal("PublishPubKey with empty armor must error before HTTP call")
	}
	if !strings.Contains(err.Error(), "armored public key is required") {
		t.Errorf("error should mention armored public key, got: %v", err)
	}
	if len(f.calls) != 0 {
		t.Errorf("no HTTP calls should be made with empty armor, got %d", len(f.calls))
	}
}

// TestPublishPubKey_InvalidArmorReturnsError verifies the armor header
// sanity check fires before any HTTP call.
func TestPublishPubKey_InvalidArmorReturnsError(t *testing.T) {
	f := &fakeDoer{responses: map[string]func(*http.Request) *http.Response{}}
	_, err := PublishPubKey(PublishOptions{
		ArmoredPubKey: "not a pgp key",
		Keyserver:     KeyserverOpenPGP,
		Doer:          f,
	})
	if err == nil {
		t.Fatal("PublishPubKey with invalid armor must error before HTTP call")
	}
	if !strings.Contains(err.Error(), "PGP PUBLIC KEY BLOCK") {
		t.Errorf("error should mention PGP armor header, got: %v", err)
	}
	if len(f.calls) != 0 {
		t.Errorf("no HTTP calls should be made with invalid armor, got %d", len(f.calls))
	}
}

// TestPublishPubKey_InvalidKeyserverReturnsError verifies an unknown
// keyserver name is rejected before any HTTP call.
func TestPublishPubKey_InvalidKeyserverReturnsError(t *testing.T) {
	f := &fakeDoer{responses: map[string]func(*http.Request) *http.Response{}}
	_, err := PublishPubKey(PublishOptions{
		ArmoredPubKey: sampleArmor,
		Keyserver:     "nope.example",
		Doer:          f,
	})
	if err == nil {
		t.Fatal("PublishPubKey with invalid keyserver must error")
	}
	if !strings.Contains(err.Error(), "invalid keyserver") {
		t.Errorf("error should mention invalid keyserver, got: %v", err)
	}
	if len(f.calls) != 0 {
		t.Errorf("no HTTP calls should be made with invalid keyserver, got %d", len(f.calls))
	}
}

// TestPublishPubKey_OpenPGPSuccess verifies a 2xx response from
// keys.openpgp.org produces a PublishResult with the verification
// URL and no error.
func TestPublishPubKey_OpenPGPSuccess(t *testing.T) {
	f := &fakeDoer{responses: map[string]func(*http.Request) *http.Response{
		openpgpUploadURL: func(*http.Request) *http.Response {
			return textResp(http.StatusOK, `{"status":"ok"}`)
		},
	}}
	results, err := PublishPubKey(PublishOptions{
		ArmoredPubKey: sampleArmor,
		Keyserver:     KeyserverOpenPGP,
		Fingerprint:   sampleFingerprint,
		Doer:          f,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	r := results[0]
	if r.Keyserver != KeyserverOpenPGP {
		t.Errorf("Keyserver = %q, want %q", r.Keyserver, KeyserverOpenPGP)
	}
	if !r.Success {
		t.Errorf("Success = false, want true")
	}
	wantURL := "https://keys.openpgp.org/vks/vby/" + strings.ToLower(sampleFingerprint)
	if r.URL != wantURL {
		t.Errorf("URL = %q, want %q", r.URL, wantURL)
	}
	if r.Err != nil {
		t.Errorf("Err = %v, want nil", r.Err)
	}
	// Verify the request shape.
	if len(f.calls) != 1 {
		t.Fatalf("len(calls) = %d, want 1", len(f.calls))
	}
	c := f.calls[0]
	if c.method != http.MethodPost {
		t.Errorf("method = %q, want POST", c.method)
	}
	if c.header.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", c.header.Get("Content-Type"))
	}
	// Body must be JSON {"keytext":"..."}. Decode it to verify the
	// armored key was sent verbatim (JSON escapes newlines, so a raw
	// substring match against sampleArmor would fail).
	var body struct {
		Keytext string `json:"keytext"`
	}
	if err := json.Unmarshal([]byte(c.body), &body); err != nil {
		t.Fatalf("POST body not valid JSON: %v", err)
	}
	if body.Keytext != sampleArmor {
		t.Errorf("POST body keytext mismatch: got %q, want %q", body.Keytext, sampleArmor)
	}
}

// TestPublishPubKey_UbuntuSuccess verifies a 2xx response from
// keyserver.ubuntu.com produces a PublishResult with the lookup URL
// and the form-encoded body.
func TestPublishPubKey_UbuntuSuccess(t *testing.T) {
	f := &fakeDoer{responses: map[string]func(*http.Request) *http.Response{
		ubuntuUploadURL: func(*http.Request) *http.Response {
			return textResp(http.StatusOK, `ok`)
		},
	}}
	results, err := PublishPubKey(PublishOptions{
		ArmoredPubKey: sampleArmor,
		Keyserver:     KeyserverUbuntu,
		Fingerprint:   sampleFingerprint,
		Doer:          f,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	r := results[0]
	if r.Keyserver != KeyserverUbuntu {
		t.Errorf("Keyserver = %q, want %q", r.Keyserver, KeyserverUbuntu)
	}
	if !r.Success {
		t.Errorf("Success = false, want true")
	}
	wantURL := "https://keyserver.ubuntu.com/pks/lookup?op=vindex&search=" +
		strings.ToLower(sampleFingerprint)
	if r.URL != wantURL {
		t.Errorf("URL = %q, want %q", r.URL, wantURL)
	}
	if r.Err != nil {
		t.Errorf("Err = %v, want nil", r.Err)
	}
	// Verify the request shape — form-encoded body.
	if len(f.calls) != 1 {
		t.Fatalf("len(calls) = %d, want 1", len(f.calls))
	}
	c := f.calls[0]
	if c.method != http.MethodPost {
		t.Errorf("method = %q, want POST", c.method)
	}
	if c.header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded",
			c.header.Get("Content-Type"))
	}
	// The body is form-encoded; decode it to verify keytext.
	vals, err := url.ParseQuery(c.body)
	if err != nil {
		t.Fatalf("body is not form-encoded: %v", err)
	}
	if vals.Get("keytext") != sampleArmor {
		t.Errorf("keytext form field = %q, want sampleArmor", vals.Get("keytext"))
	}
}

// TestPublishPubKey_AllPublishesToBoth verifies KeyserverAll contacts
// both keyservers and returns two results in the canonical order
// (openpgp first, ubuntu second).
func TestPublishPubKey_AllPublishesToBoth(t *testing.T) {
	f := &fakeDoer{responses: map[string]func(*http.Request) *http.Response{
		openpgpUploadURL: func(*http.Request) *http.Response {
			return textResp(http.StatusOK, `ok`)
		},
		ubuntuUploadURL: func(*http.Request) *http.Response {
			return textResp(http.StatusOK, `ok`)
		},
	}}
	results, err := PublishPubKey(PublishOptions{
		ArmoredPubKey: sampleArmor,
		Keyserver:     KeyserverAll,
		Fingerprint:   sampleFingerprint,
		Doer:          f,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}
	if results[0].Keyserver != KeyserverOpenPGP {
		t.Errorf("results[0].Keyserver = %q, want %q",
			results[0].Keyserver, KeyserverOpenPGP)
	}
	if results[1].Keyserver != KeyserverUbuntu {
		t.Errorf("results[1].Keyserver = %q, want %q",
			results[1].Keyserver, KeyserverUbuntu)
	}
	if !results[0].Success || !results[1].Success {
		t.Errorf("both results should be successful, got %+v", results)
	}
	if len(f.calls) != 2 {
		t.Fatalf("len(calls) = %d, want 2", len(f.calls))
	}
	if f.calls[0].url != openpgpUploadURL {
		t.Errorf("first call url = %q, want %q", f.calls[0].url, openpgpUploadURL)
	}
	if f.calls[1].url != ubuntuUploadURL {
		t.Errorf("second call url = %q, want %q", f.calls[1].url, ubuntuUploadURL)
	}
}

// TestPublishPubKey_HTTPErrorPropagates verifies a non-2xx status is
// surfaced as PublishResult.Err with Success=false.
func TestPublishPubKey_HTTPErrorPropagates(t *testing.T) {
	f := &fakeDoer{responses: map[string]func(*http.Request) *http.Response{
		openpgpUploadURL: func(*http.Request) *http.Response {
			return textResp(http.StatusBadGateway, `{"error":"down"}`)
		},
	}}
	results, err := PublishPubKey(PublishOptions{
		ArmoredPubKey: sampleArmor,
		Keyserver:     KeyserverOpenPGP,
		Fingerprint:   sampleFingerprint,
		Doer:          f,
	})
	if err != nil {
		t.Fatalf("PublishPubKey should not return a top-level error on HTTP failure, got: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	r := results[0]
	if r.Success {
		t.Errorf("Success = true, want false on HTTP 502")
	}
	if r.Err == nil {
		t.Fatal("Err = nil, want a non-nil error on HTTP 502")
	}
	if !strings.Contains(r.Err.Error(), "502") {
		t.Errorf("Err should mention status 502, got: %v", r.Err)
	}
	if r.URL != "" {
		t.Errorf("URL = %q, want empty on failure", r.URL)
	}
}

// TestPublishPubKey_TransportErrorPropagates verifies a transport
// error from Do is wrapped and surfaced as PublishResult.Err.
func TestPublishPubKey_TransportErrorPropagates(t *testing.T) {
	errDoer := &errorDoer{err: errors.New("network down")}
	results, err := PublishPubKey(PublishOptions{
		ArmoredPubKey: sampleArmor,
		Keyserver:     KeyserverOpenPGP,
		Fingerprint:   sampleFingerprint,
		Doer:          errDoer,
	})
	if err != nil {
		t.Fatalf("PublishPubKey should not return a top-level error on transport failure, got: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	r := results[0]
	if r.Success {
		t.Errorf("Success = true, want false on transport error")
	}
	if r.Err == nil {
		t.Fatal("Err = nil, want a non-nil error on transport failure")
	}
	if !strings.Contains(r.Err.Error(), "network down") {
		t.Errorf("Err should wrap 'network down', got: %v", r.Err)
	}
}

type errorDoer struct{ err error }

func (e *errorDoer) Do(req *http.Request) (*http.Response, error) {
	return nil, e.err
}

// TestPublishPubKey_MissingFingerprintReturnsNote verifies that when
// the fingerprint is not available (no option, not extractable from
// armor), the upload still succeeds but the URL is empty and Err
// carries a note explaining why.
func TestPublishPubKey_MissingFingerprintReturnsNote(t *testing.T) {
	f := &fakeDoer{responses: map[string]func(*http.Request) *http.Response{
		openpgpUploadURL: func(*http.Request) *http.Response {
			return textResp(http.StatusOK, `ok`)
		},
	}}
	results, err := PublishPubKey(PublishOptions{
		ArmoredPubKey: sampleArmor, // no Comment line with fingerprint
		Keyserver:     KeyserverOpenPGP,
		// Fingerprint intentionally empty
		Doer: f,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	r := results[0]
	if !r.Success {
		t.Errorf("Success = false, want true (upload itself succeeded)")
	}
	if r.URL != "" {
		t.Errorf("URL = %q, want empty when fingerprint is unknown", r.URL)
	}
	if r.Err == nil {
		t.Fatal("Err = nil, want a note about the empty URL")
	}
	if !strings.Contains(r.Err.Error(), "fingerprint unknown") {
		t.Errorf("Err should mention 'fingerprint unknown', got: %v", r.Err)
	}
}

// TestPublishPubKey_ExtractsFingerprintFromArmorComment verifies that
// when the armor carries a "Comment: Fingerprint: ..." line, the
// fingerprint is extracted and the URL is built without the caller
// passing Fingerprint explicitly.
func TestPublishPubKey_ExtractsFingerprintFromArmorComment(t *testing.T) {
	// 40 hex chars split into 10 groups of 4 (the gpg-style format).
	fp40 := "ABCD EF01 2345 6789 ABCD EF01 2345 6789 ABCD EF01"
	wantFP := "abcdef0123456789abcdef0123456789abcdef01"
	armorWithComment := "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
		"Comment: Fingerprint: " + fp40 + "\n" +
		"\nmQEN...\n-----END PGP PUBLIC KEY BLOCK-----\n"

	f := &fakeDoer{responses: map[string]func(*http.Request) *http.Response{
		openpgpUploadURL: func(*http.Request) *http.Response {
			return textResp(http.StatusOK, `ok`)
		},
	}}
	results, err := PublishPubKey(PublishOptions{
		ArmoredPubKey: armorWithComment,
		Keyserver:     KeyserverOpenPGP,
		// Fingerprint intentionally empty — must be extracted
		Doer: f,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := results[0]
	if !r.Success {
		t.Errorf("Success = false, want true")
	}
	wantURL := "https://keys.openpgp.org/vks/vby/" + wantFP
	if r.URL != wantURL {
		t.Errorf("URL = %q, want %q", r.URL, wantURL)
	}
	if r.Err != nil {
		t.Errorf("Err = %v, want nil (fingerprint was extracted)", r.Err)
	}
}

// TestPublishPubKey_DefaultsToOpenPGP verifies an empty Keyserver
// option defaults to keys.openpgp.org.
func TestPublishPubKey_DefaultsToOpenPGP(t *testing.T) {
	f := &fakeDoer{responses: map[string]func(*http.Request) *http.Response{
		openpgpUploadURL: func(*http.Request) *http.Response {
			return textResp(http.StatusOK, `ok`)
		},
	}}
	results, err := PublishPubKey(PublishOptions{
		ArmoredPubKey: sampleArmor,
		// Keyserver intentionally empty — defaults to openpgp
		Fingerprint: sampleFingerprint,
		Doer:        f,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 || results[0].Keyserver != KeyserverOpenPGP {
		t.Errorf("default keyserver should be %q, got %+v", KeyserverOpenPGP, results)
	}
}

// TestPublishPubKey_NilDoerUsesDefault verifies a nil Doer does not
// panic during option resolution (the real default client is only
// used when an HTTP call is made; this test points the default at a
// fake to avoid hitting the network).
func TestPublishPubKey_NilDoerUsesDefault(t *testing.T) {
	// Swap the package default so the nil-Doer path does not hit the
	// network. Restore it at the end of the test.
	orig := defaultHTTPClient
	defer func() { defaultHTTPClient = orig }()
	f := &fakeDoer{responses: map[string]func(*http.Request) *http.Response{
		openpgpUploadURL: func(*http.Request) *http.Response {
			return textResp(http.StatusOK, `ok`)
		},
	}}
	defaultHTTPClient = f

	results, err := PublishPubKey(PublishOptions{
		ArmoredPubKey: sampleArmor,
		Keyserver:     KeyserverOpenPGP,
		Fingerprint:   sampleFingerprint,
		// Doer intentionally nil — uses defaultHTTPClient
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 || !results[0].Success {
		t.Errorf("expected one successful result, got %+v", results)
	}
}

// TestResolveKeyservers verifies the keyserver name resolution.
func TestResolveKeyservers(t *testing.T) {
	cases := []struct {
		in      string
		want    []string
		wantErr bool
	}{
		{KeyserverOpenPGP, []string{KeyserverOpenPGP}, false},
		{KeyserverUbuntu, []string{KeyserverUbuntu}, false},
		{KeyserverAll, []string{KeyserverOpenPGP, KeyserverUbuntu}, false},
		{"nope", nil, true},
		// "" is rejected by resolveKeyservers; the default-to-openpgp
		// logic lives in PublishPubKey (which fills "" before calling
		// resolveKeyservers).
		{"", nil, true},
	}
	for _, c := range cases {
		got, err := resolveKeyservers(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("resolveKeyservers(%q) = %v, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("resolveKeyservers(%q) error: %v", c.in, err)
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("resolveKeyservers(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("resolveKeyservers(%q)[%d] = %q, want %q",
					c.in, i, got[i], c.want[i])
			}
		}
	}
}

// TestExtractFingerprintFromArmor verifies the best-effort extraction
// from "Comment: Fingerprint: ..." lines.
func TestExtractFingerprintFromArmor(t *testing.T) {
	fp40 := "ABCD EF01 2345 6789 ABCD EF01 2345 6789 ABCD EF01"
	want := "abcdef0123456789abcdef0123456789abcdef01"

	cases := []struct {
		name  string
		armor string
		want  string
	}{
		{
			name: "with Fingerprint label",
			armor: "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
				"Comment: Fingerprint: " + fp40 + "\n" +
				"\nmQEN...\n-----END PGP PUBLIC KEY BLOCK-----\n",
			want: want,
		},
		{
			name: "bare comment with hex",
			armor: "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
				"Comment: " + fp40 + "\n" +
				"\nmQEN...\n-----END PGP PUBLIC KEY BLOCK-----\n",
			want: want,
		},
		{
			name: "no comment line",
			armor: "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
				"\nmQEN...\n-----END PGP PUBLIC KEY BLOCK-----\n",
			want: "",
		},
		{
			name: "comment with non-fingerprint content",
			armor: "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
				"Comment: some tool version\n" +
				"\nmQEN...\n-----END PGP PUBLIC KEY BLOCK-----\n",
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := extractFingerprintFromArmor(c.armor)
			// normaliseFingerprint is applied by the caller; here we
			// compare the raw extracted value (uppercased, no spaces).
			if got != "" {
				got = normaliseFingerprint(got)
			}
			if got != c.want {
				t.Errorf("extractFingerprintFromArmor(%s) = %q, want %q",
					c.name, got, c.want)
			}
		})
	}
}

// TestNormaliseFingerprint verifies space stripping + lowercasing.
func TestNormaliseFingerprint(t *testing.T) {
	cases := []struct{ in, want string }{
		{"AB CD EF", "abcdef"},
		{"  AB C  ", "abc"},
		{"abcdef", "abcdef"},
		{"ABCDEF0123456789ABCDEF0123456789ABCDEF01",
			"abcdef0123456789abcdef0123456789abcdef01"},
	}
	for _, c := range cases {
		got := normaliseFingerprint(c.in)
		if got != c.want {
			t.Errorf("normaliseFingerprint(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
