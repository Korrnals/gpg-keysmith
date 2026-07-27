package github

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// sequenceDoer is a Doer that returns a different response on each
// call. The existing fakeDoer keys on (method, URL), which means the
// same endpoint always returns the same canned response. The new
// tests need to distinguish the first GET (preflight) from the
// second GET (422 fallback follow-up), so a sequence-aware mock is
// the cleanest fit. The handler is called in the order the responses
// slice declares; once exhausted, an additional call returns 500 to
// make the test fail loudly.
type sequenceDoer struct {
	mu        sync.Mutex
	responses []func(*http.Request) *http.Response
	calls     []recordedCall
}

func (s *sequenceDoer) Do(req *http.Request) (*http.Response, error) {
	bodyBytes := ""
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		bodyBytes = string(b)
		req.Body = io.NopCloser(strings.NewReader(bodyBytes))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := len(s.calls)
	s.calls = append(s.calls, recordedCall{
		method: req.Method,
		url:    req.URL.Path,
		header: req.Header.Clone(),
		body:   bodyBytes,
	})
	if idx >= len(s.responses) {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(strings.NewReader(`{"message":"sequenceDoer: no more canned responses"}`)),
			Header:     make(http.Header),
		}, nil
	}
	return s.responses[idx](req), nil
}

func (s *sequenceDoer) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func (s *sequenceDoer) callsByMethod(method string) []recordedCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []recordedCall
	for _, c := range s.calls {
		if c.method == method {
			out = append(out, c)
		}
	}
	return out
}

// TestUploadPublicKey_PreflightDetectsExistingSubkey verifies that
// when the preflight GET returns an existing key whose subkey
// fingerprints include the one we are about to upload, the function
// returns *ErrKeyAlreadyExists without ever POSTing.
func TestUploadPublicKey_PreflightDetectsExistingSubkey(t *testing.T) {
	const wantFP = "FD910BA1AF89641A" // 16-char short form (matches GitHub's 422 body)
	d := &sequenceDoer{responses: []func(*http.Request) *http.Response{
		// 1st call: GET /user/gpg_keys — returns an existing key
		// whose subkeys include the one we want to upload.
		func(*http.Request) *http.Response {
			return jsonResp(200, []GpgKeyRef{
				{
					ID:          72834,
					KeyID:       "ABC123",
					Fingerprint: "1111111111111111111111111111111111111111",
					Emails:      []string{"korrnals@example.com"},
					Subkeys: []GpgKeySubkey{
						{ID: 999, PrimaryKeyID: 72834, Fingerprint: strings.ToLower(wantFP)},
					},
				},
			})
		},
	}}

	// The caller knows the subkey fingerprint up front (the wizard
	// gets it from gpg via the same GetSubkeyFingerprints-style
	// helper that detects keys). The bare UploadPublicKey
	// signature does not take a fingerprint — so we use
	// UploadPublicKeyWithFingerprintAndClient here, which is the
	// public API the wizard calls and which the preflight lives in.
	// For UploadPublicKeyWithClient the preflight is the 422
	// fallback (tested separately below); with no fingerprint and
	// no 422, it cannot pre-detect.
	_, err := UploadPublicKeyWithFingerprintAndClient("tok", sampleArmor, wantFP, d)
	var keyExists *ErrKeyAlreadyExists
	if !errors.As(err, &keyExists) {
		t.Fatalf("error is not *ErrKeyAlreadyExists: %v", err)
	}
	if keyExists.KeyID != "72834" {
		t.Errorf("KeyID = %q, want 72834", keyExists.KeyID)
	}
	if keyExists.Fingerprint != strings.ToLower(wantFP) {
		t.Errorf("Fingerprint = %q, want %q (normalised)", keyExists.Fingerprint, strings.ToLower(wantFP))
	}
	if len(keyExists.Emails) != 1 || keyExists.Emails[0] != "korrnals@example.com" {
		t.Errorf("Emails = %v, want [korrnals@example.com]", keyExists.Emails)
	}
	// No POST was made.
	for _, c := range d.callsByMethod("POST") {
		t.Errorf("no POST should be made when subkey already on account, got %s %s", c.method, c.url)
	}
	// Exactly one GET (the preflight).
	gets := d.callsByMethod("GET")
	if len(gets) != 1 {
		t.Errorf("GET count = %d, want 1 (preflight only)", len(gets))
	}
}

// TestUploadPublicKey_422SubkeyAlreadyExists_AsSuccess exercises the
// 422 fallback path: the preflight GET did not see the subkey (it
// was not on the account yet, or the PAT could not see it), the
// POST returns 422 with the exact dogfooded body, and a follow-up
// GET finds the subkey. Result: *ErrKeyAlreadyExists with the
// discovered key id. The POST is made exactly once.
func TestUploadPublicKey_422SubkeyAlreadyExists_AsSuccess(t *testing.T) {
	const subkeyFP = "FD910BA1AF89641A" // matches the dogfooded case
	const dogfoodedBody = `{"message":"Validation Failed","errors":[{"resource":"GpgKey","code":"custom","message":"The key was not added because one or more subkeys already exist: ` + subkeyFP + `"}]}`

	d := &sequenceDoer{responses: []func(*http.Request) *http.Response{
		// 1st: GET /user/gpg_keys — empty, no existing key with the
		// subkey. (The preflight cannot prevent the POST.)
		func(*http.Request) *http.Response {
			return jsonResp(200, []GpgKeyRef{
				{ID: 11111, KeyID: "OTHER", Fingerprint: "2222222222222222222222222222222222222222"},
			})
		},
		// 2nd: POST /user/gpg_keys — 422 with subkey-already-exists body.
		func(*http.Request) *http.Response {
			return textResp(422, dogfoodedBody)
		},
		// 3rd: GET /user/gpg_keys (follow-up) — now lists the
		// existing key with the conflicting subkey.
		func(*http.Request) *http.Response {
			return jsonResp(200, []GpgKeyRef{
				{
					ID:          72834,
					KeyID:       "ABC123",
					Fingerprint: "1111111111111111111111111111111111111111",
					Emails:      []string{"korrnals@example.com", "korrnals2@example.com"},
					Subkeys: []GpgKeySubkey{
						{ID: 999, PrimaryKeyID: 72834, Fingerprint: strings.ToLower(subkeyFP)},
					},
				},
			})
		},
	}}

	// Use the bare UploadPublicKeyWithClient (no fingerprint) so
	// the preflight is forced to fall through to POST — this
	// exactly mirrors the dogfooded scenario where the preflight
	// could not know about the conflicting key.
	_, err := UploadPublicKeyWithClient("tok", sampleArmor, d)
	var keyExists *ErrKeyAlreadyExists
	if !errors.As(err, &keyExists) {
		t.Fatalf("error is not *ErrKeyAlreadyExists: %v", err)
	}
	if keyExists.KeyID != "72834" {
		t.Errorf("KeyID = %q, want 72834", keyExists.KeyID)
	}
	if keyExists.Fingerprint != strings.ToLower(subkeyFP) {
		t.Errorf("Fingerprint = %q, want %q", keyExists.Fingerprint, strings.ToLower(subkeyFP))
	}
	if len(keyExists.Emails) != 2 {
		t.Errorf("Emails = %v, want 2 entries", keyExists.Emails)
	}
	// Exactly one POST.
	posts := d.callsByMethod("POST")
	if len(posts) != 1 {
		t.Errorf("POST count = %d, want exactly 1", len(posts))
	}
	// Two GETs (preflight + follow-up).
	gets := d.callsByMethod("GET")
	if len(gets) != 2 {
		t.Errorf("GET count = %d, want 2 (preflight + follow-up)", len(gets))
	}
	if d.callCount() != 3 {
		t.Errorf("total calls = %d, want 3", d.callCount())
	}
}

// TestUploadPublicKey_422OtherCode_StillError verifies that a 422
// with a different `code` (not the subkey-already-exists case) is
// still surfaced as a raw error. No follow-up GET, no typed error.
func TestUploadPublicKey_422OtherCode_StillError(t *testing.T) {
	d := &sequenceDoer{responses: []func(*http.Request) *http.Response{
		// 1st: GET /user/gpg_keys — empty.
		func(*http.Request) *http.Response {
			return jsonResp(200, []GpgKeyRef{})
		},
		// 2nd: POST /user/gpg_keys — 422 with `code: missing_field`.
		func(*http.Request) *http.Response {
			return textResp(422, `{"message":"Validation Failed","errors":[{"resource":"GpgKey","field":"armored_public_key","code":"missing_field","message":"is required"}]}`)
		},
	}}

	_, err := UploadPublicKeyWithClient("tok", sampleArmor, d)
	if err == nil {
		t.Fatal("expected error for 422 missing_field, got nil")
	}
	var keyExists *ErrKeyAlreadyExists
	if errors.As(err, &keyExists) {
		t.Errorf("error must NOT be *ErrKeyAlreadyExists for non-subkey 422, got %v", err)
	}
	if !strings.Contains(err.Error(), "422") {
		t.Errorf("error should mention status 422, got: %v", err)
	}
	// Exactly one POST, exactly one GET — no follow-up because the
	// 422 was not the subkey-already-exists case.
	posts := d.callsByMethod("POST")
	if len(posts) != 1 {
		t.Errorf("POST count = %d, want exactly 1", len(posts))
	}
	gets := d.callsByMethod("GET")
	if len(gets) != 1 {
		t.Errorf("GET count = %d, want 1 (preflight only, no follow-up)", len(gets))
	}
	if d.callCount() != 2 {
		t.Errorf("total calls = %d, want 2", d.callCount())
	}
}

// TestSubkeyFingerprints_Parse is a pure unit test for the
// subkeyFingerprints helper. Feeds a hand-built GpgKeyRef slice and
// asserts the flat output.
func TestSubkeyFingerprints_Parse(t *testing.T) {
	cases := []struct {
		name string
		in   []GpgKeyRef
		want []string
	}{
		{
			name: "empty input returns empty (non-nil) slice",
			in:   nil,
			want: []string{},
		},
		{
			name: "primary fingerprint only",
			in: []GpgKeyRef{
				{ID: 1, KeyID: "K1", Fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			},
			want: []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		},
		{
			name: "primary plus subkeys",
			in: []GpgKeyRef{
				{
					ID:          1,
					KeyID:       "K1",
					Fingerprint: "1111111111111111111111111111111111111111",
					Subkeys: []GpgKeySubkey{
						{ID: 10, Fingerprint: "2222222222222222222222222222222222222222"},
						{ID: 11, Fingerprint: "3333333333333333333333333333333333333333"},
					},
				},
			},
			want: []string{
				"1111111111111111111111111111111111111111",
				"2222222222222222222222222222222222222222",
				"3333333333333333333333333333333333333333",
			},
		},
		{
			name: "multiple keys, empty subkey fingerprint skipped",
			in: []GpgKeyRef{
				{
					ID:          1,
					Fingerprint: "1111111111111111111111111111111111111111",
					Subkeys: []GpgKeySubkey{
						{ID: 10, Fingerprint: ""}, // empty skipped
						{ID: 11, Fingerprint: "2222222222222222222222222222222222222222"},
					},
				},
				{
					ID:          2,
					Fingerprint: "", // empty primary skipped
					Subkeys: []GpgKeySubkey{
						{ID: 20, Fingerprint: "3333333333333333333333333333333333333333"},
					},
				},
			},
			want: []string{
				"1111111111111111111111111111111111111111",
				"2222222222222222222222222222222222222222",
				"3333333333333333333333333333333333333333",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := subkeyFingerprints(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("len = %d, want %d (got=%v want=%v)", len(got), len(tc.want), got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestMatchSubkeyAlreadyExists_Valid verifies the body parser
// recognises the dogfooded 422 body and extracts the subkey
// fingerprint.
func TestMatchSubkeyAlreadyExists_Valid(t *testing.T) {
	const subkeyFP = "FD910BA1AF89641A"
	body := `{"message":"Validation Failed","errors":[{"resource":"GpgKey","code":"custom","message":"The key was not added because one or more subkeys already exist: ` + subkeyFP + `"}]}`
	fp, matched := matchSubkeyAlreadyExists(strings.NewReader(body))
	if !matched {
		t.Fatal("body should match subkey-already-exists case")
	}
	if fp != subkeyFP {
		t.Errorf("fp = %q, want %q", fp, subkeyFP)
	}
}

// TestMatchSubkeyAlreadyExists_DifferentCode verifies that a 422
// with `code: missing_field` is NOT misclassified.
func TestMatchSubkeyAlreadyExists_DifferentCode(t *testing.T) {
	body := `{"message":"Validation Failed","errors":[{"resource":"GpgKey","code":"missing_field","message":"is required"}]}`
	_, matched := matchSubkeyAlreadyExists(strings.NewReader(body))
	if matched {
		t.Error("missing_field 422 must NOT match subkey-already-exists")
	}
}

// TestMatchSubkeyAlreadyExists_CustomCodeWrongMessage verifies that
// `code: custom` with a different message (not the subkey case) is
// NOT misclassified.
func TestMatchSubkeyAlreadyExists_CustomCodeWrongMessage(t *testing.T) {
	body := `{"message":"Validation Failed","errors":[{"resource":"GpgKey","code":"custom","message":"some other custom validation"}]}`
	_, matched := matchSubkeyAlreadyExists(strings.NewReader(body))
	if matched {
		t.Error("custom code with non-subkey message must NOT match")
	}
}

// TestErrKeyAlreadyExists_ErrorString verifies the typed error
// message includes the fingerprint, key id, and emails so the
// wizard can render a useful "already on GitHub" line.
func TestErrKeyAlreadyExists_ErrorString(t *testing.T) {
	e := &ErrKeyAlreadyExists{
		KeyID:       "72834",
		Emails:      []string{"a@example.com", "b@example.com"},
		Fingerprint: "fd910ba1af89641a",
	}
	msg := e.Error()
	if !strings.Contains(msg, "72834") {
		t.Errorf("message %q should contain KeyID", msg)
	}
	if !strings.Contains(msg, "fd910ba1af89641a") {
		t.Errorf("message %q should contain Fingerprint", msg)
	}
	if !strings.Contains(msg, "a@example.com") || !strings.Contains(msg, "b@example.com") {
		t.Errorf("message %q should contain emails", msg)
	}
	// Empty emails case shows <no emails> rather than an empty
	// string, so the message is never blank.
	e2 := &ErrKeyAlreadyExists{KeyID: "1", Fingerprint: "abc"}
	msg2 := e2.Error()
	if !strings.Contains(msg2, "<no emails>") {
		t.Errorf("empty-emails message %q should contain '<no emails>'", msg2)
	}
}

// Ensure the response JSON shape we build in the existing tests is
// also still parseable with the extended GpgKeyRef (defence-in-depth
// against accidental struct field renames).
func TestGpgKeyRef_ExtendedJSONParse(t *testing.T) {
	raw := `{"id":72834,"key_id":"ABC123","fingerprint":"1111111111111111111111111111111111111111","emails":["a@b.c"],"subkeys":[{"id":99,"primary_key_id":72834,"fingerprint":"2222222222222222222222222222222222222222"}]}`
	var k GpgKeyRef
	if err := json.Unmarshal([]byte(raw), &k); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if k.ID != 72834 || k.KeyID != "ABC123" {
		t.Errorf("parse mismatch: %+v", k)
	}
	if len(k.Emails) != 1 || k.Emails[0] != "a@b.c" {
		t.Errorf("emails = %v", k.Emails)
	}
	if len(k.Subkeys) != 1 || k.Subkeys[0].Fingerprint != "2222222222222222222222222222222222222222" {
		t.Errorf("subkeys = %+v", k.Subkeys)
	}
}

// callCountingErrDoer wraps the package-level errorDoer with a
// mutex-guarded call counter, so the preflight-bail subtests can
// assert that no POST was made. The existing errorDoer (in
// pubkey_test.go) is not concurrency-safe enough for the call
// counter check.
type callCountingErrDoer struct {
	mu    sync.Mutex
	err   error
	calls int
}

func (e *callCountingErrDoer) Do(req *http.Request) (*http.Response, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls++
	return nil, e.err
}

func (e *callCountingErrDoer) callCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls
}

// TestUploadPublicKey_PreflightErrorBailsBeforePost pins the
// contract that any preflight failure (HTTP error status OR
// transport-level error) MUST abort before the POST. The 422
// subkey-already-exists path is reachable only on a successful
// preflight + a 422 POST; a failed preflight must short-circuit
// the entire flow and never reach POST.
func TestUploadPublicKey_PreflightErrorBailsBeforePost(t *testing.T) {
	cases := []struct {
		name        string
		preflightDo Doer // returns (resp, err) on the GET
		wantErrSub  string
	}{
		{
			name: "401 Unauthorized on preflight",
			preflightDo: &sequenceDoer{responses: []func(*http.Request) *http.Response{
				func(*http.Request) *http.Response {
					return textResp(401, `{"message":"Bad credentials"}`)
				},
			}},
			wantErrSub: "401",
		},
		{
			name: "500 Internal Server Error on preflight",
			preflightDo: &sequenceDoer{responses: []func(*http.Request) *http.Response{
				func(*http.Request) *http.Response {
					return textResp(500, `{"message":"internal server error"}`)
				},
			}},
			wantErrSub: "500",
		},
		{
			name:        "transport-level error on preflight (connection refused)",
			preflightDo: &callCountingErrDoer{err: errors.New("connection refused")},
			wantErrSub:  "connection refused",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := UploadPublicKeyWithClient("tok", sampleArmor, tc.preflightDo)
			if err == nil {
				t.Fatalf("expected error from preflight failure, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Errorf("error %q should contain %q", err.Error(), tc.wantErrSub)
			}
			// The typed error must NEVER be the result of a
			// preflight failure — the subkey-already-exists case
			// requires a successful 201 OR a 422 from POST, not
			// a 401/500/network on GET.
			var keyExists *ErrKeyAlreadyExists
			if errors.As(err, &keyExists) {
				t.Errorf("error must NOT be *ErrKeyAlreadyExists on preflight failure, got %v", err)
			}
			// No POST may have been made.
			switch d := tc.preflightDo.(type) {
			case *sequenceDoer:
				if posts := d.callsByMethod("POST"); len(posts) != 0 {
					t.Errorf("no POST should be made on preflight failure, got %d POSTs", len(posts))
				}
				if gets := d.callsByMethod("GET"); len(gets) != 1 {
					t.Errorf("exactly one GET (the preflight) should fire, got %d", len(gets))
				}
			case *callCountingErrDoer:
				if d.callCount() != 1 {
					t.Errorf("exactly one Do call (the preflight) should fire, got %d", d.callCount())
				}
			}
		})
	}
}

// TestMatchSubkeyAlreadyExists_EdgeCases pins the parser contract
// for bodies that LOOK like 422 subkey-already-exists responses but
// are not. The parser must return matched=false so the upload
// surfaces the raw 422 to the caller (a 422 with a non-matching
// body is a real validation failure the user needs to see).
func TestMatchSubkeyAlreadyExists_EdgeCases(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		matched bool
	}{
		{
			name:    "non-JSON body",
			body:    `<html>502 Bad Gateway</html>`,
			matched: false,
		},
		{
			name:    "JSON with empty errors array",
			body:    `{"message":"Validation Failed","errors":[]}`,
			matched: false,
		},
		{
			name:    "code: custom with non-hex trailing token (XYZ123!@#)",
			body:    `{"errors":[{"code":"custom","message":"The key was not added because one or more subkeys already exist: XYZ123!@#"}]}`,
			matched: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, matched := matchSubkeyAlreadyExists(strings.NewReader(tc.body))
			if matched != tc.matched {
				t.Errorf("matched = %v, want %v (body=%q)", matched, tc.matched, tc.body)
			}
		})
	}
}
