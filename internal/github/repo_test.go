package github

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestCommitPublicKeyFile_EmptyTokenReturnsError verifies the token
// guard.
func TestCommitPublicKeyFile_EmptyTokenReturnsError(t *testing.T) {
	_, err := CommitPublicKeyFileWithClient("", "owner", "repo", sampleArmor, &fakeDoer{})
	if err == nil {
		t.Fatal("CommitPublicKeyFile with empty token must error")
	}
	if !strings.Contains(err.Error(), "token") {
		t.Errorf("error should mention token, got: %v", err)
	}
}

// TestCommitPublicKeyFile_EmptyOwnerReturnsError verifies the owner
// guard.
func TestCommitPublicKeyFile_EmptyOwnerReturnsError(t *testing.T) {
	_, err := CommitPublicKeyFileWithClient("tok", "", "repo", sampleArmor, &fakeDoer{})
	if err == nil {
		t.Fatal("CommitPublicKeyFile with empty owner must error")
	}
	if !strings.Contains(err.Error(), "owner") {
		t.Errorf("error should mention owner, got: %v", err)
	}
}

// TestCommitPublicKeyFile_EmptyRepoReturnsError verifies the repo
// guard.
func TestCommitPublicKeyFile_EmptyRepoReturnsError(t *testing.T) {
	_, err := CommitPublicKeyFileWithClient("tok", "owner", "", sampleArmor, &fakeDoer{})
	if err == nil {
		t.Fatal("CommitPublicKeyFile with empty repo must error")
	}
}

// TestCommitPublicKeyFile_InvalidArmorReturnsError verifies the
// armor sanity check.
func TestCommitPublicKeyFile_InvalidArmorReturnsError(t *testing.T) {
	_, err := CommitPublicKeyFileWithClient("tok", "owner", "repo", "not a key", &fakeDoer{})
	if err == nil {
		t.Fatal("CommitPublicKeyFile with invalid armor must error")
	}
	if !strings.Contains(err.Error(), "PGP PUBLIC KEY BLOCK") {
		t.Errorf("error should mention PGP armor header, got: %v", err)
	}
}

// TestCommitPublicKeyFile_Success verifies the full 8-call happy path
// returns the PR URL.
func TestCommitPublicKeyFile_Success(t *testing.T) {
	f := &fakeDoer{responses: map[string]func(*http.Request) *http.Response{
		// 1. GET /repos/{owner}/{repo}
		"GET /repos/owner/repo": func(*http.Request) *http.Response {
			return jsonResp(200, struct {
				DefaultBranch string `json:"default_branch"`
			}{DefaultBranch: "main"})
		},
		// 2. GET /repos/{owner}/{repo}/branches/main
		"GET /repos/owner/repo/branches/main": func(*http.Request) *http.Response {
			return jsonResp(200, struct {
				Commit struct {
					SHA string `json:"sha"`
				} `json:"commit"`
			}{Commit: struct {
				SHA string `json:"sha"`
			}{SHA: "base-commit-sha"}})
		},
		// 3. GET /repos/{owner}/{repo}/git/commits/base-commit-sha
		"GET /repos/owner/repo/git/commits/base-commit-sha": func(*http.Request) *http.Response {
			return jsonResp(200, struct {
				Tree struct {
					SHA string `json:"sha"`
				} `json:"tree"`
			}{Tree: struct {
				SHA string `json:"sha"`
			}{SHA: "base-tree-sha"}})
		},
		// 4. POST /repos/{owner}/{repo}/git/blobs
		"POST /repos/owner/repo/git/blobs": func(*http.Request) *http.Response {
			return jsonResp(201, struct {
				SHA string `json:"sha"`
			}{SHA: "blob-sha"})
		},
		// 5. POST /repos/{owner}/{repo}/git/trees
		"POST /repos/owner/repo/git/trees": func(*http.Request) *http.Response {
			return jsonResp(201, struct {
				SHA string `json:"sha"`
			}{SHA: "new-tree-sha"})
		},
		// 6. POST /repos/{owner}/{repo}/git/commits
		"POST /repos/owner/repo/git/commits": func(*http.Request) *http.Response {
			return jsonResp(201, struct {
				SHA string `json:"sha"`
			}{SHA: "new-commit-sha"})
		},
		// 7. PATCH /repos/{owner}/{repo}/git/refs/heads/{branch}
		"PATCH /repos/owner/repo/git/refs/heads/chore/add-gpg-public-key": func(*http.Request) *http.Response {
			// Return 422 to force the POST fallback path so we
			// exercise upsertBranchRef's create branch path.
			return textResp(422, `{"message":"Reference does not exist"}`)
		},
		// 7b. POST /repos/{owner}/{repo}/git/refs (fallback)
		"POST /repos/owner/repo/git/refs": func(*http.Request) *http.Response {
			return jsonResp(201, struct {
				Ref string `json:"ref"`
			}{Ref: "refs/heads/chore/add-gpg-public-key"})
		},
		// 8. POST /repos/{owner}/{repo}/pulls
		"POST /repos/owner/repo/pulls": func(*http.Request) *http.Response {
			return jsonResp(201, struct {
				HTMLURL string `json:"html_url"`
			}{HTMLURL: "https://github.com/owner/repo/pull/1"})
		},
	}}

	prURL, err := CommitPublicKeyFileWithClient("tok", "owner", "repo", sampleArmor, f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if prURL != "https://github.com/owner/repo/pull/1" {
		t.Errorf("prURL = %q, want pull/1", prURL)
	}

	// Verify all expected calls were made.
	expectedPaths := []string{
		"GET /repos/owner/repo",
		"GET /repos/owner/repo/branches/main",
		"GET /repos/owner/repo/git/commits/base-commit-sha",
		"POST /repos/owner/repo/git/blobs",
		"POST /repos/owner/repo/git/trees",
		"POST /repos/owner/repo/git/commits",
		"PATCH /repos/owner/repo/git/refs/heads/chore/add-gpg-public-key",
		"POST /repos/owner/repo/git/refs",
		"POST /repos/owner/repo/pulls",
	}
	for _, p := range expectedPaths {
		found := false
		for _, c := range f.calls {
			// c.url is the full URL (https://api.github.com/...);
			// strip the scheme+host so we can compare against the
			// path-only expected entries.
			pathOnly := c.url
			if i := strings.Index(pathOnly, "://"); i >= 0 {
				rest := pathOnly[i+3:]
				if slash := strings.Index(rest, "/"); slash >= 0 {
					pathOnly = rest[slash:]
				}
			}
			if c.method+" "+pathOnly == p {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected call %q not made; calls were: %v", p, callList(f.calls))
		}
	}
}

func callList(calls []recordedCall) []string {
	out := make([]string, len(calls))
	for i, c := range calls {
		out[i] = c.method + " " + c.url
	}
	return out
}

// TestCommitPublicKeyFile_PrAlreadyExists verifies the 422 PR path
// returns a clear error pointing to the existing PR.
func TestCommitPublicKeyFile_PrAlreadyExists(t *testing.T) {
	f := &fakeDoer{responses: map[string]func(*http.Request) *http.Response{
		"GET /repos/owner/repo": func(*http.Request) *http.Response {
			return jsonResp(200, struct {
				DefaultBranch string `json:"default_branch"`
			}{DefaultBranch: "main"})
		},
		"GET /repos/owner/repo/branches/main": func(*http.Request) *http.Response {
			return jsonResp(200, struct {
				Commit struct {
					SHA string `json:"sha"`
				} `json:"commit"`
			}{Commit: struct {
				SHA string `json:"sha"`
			}{SHA: "base"}})
		},
		"GET /repos/owner/repo/git/commits/base": func(*http.Request) *http.Response {
			return jsonResp(200, struct {
				Tree struct {
					SHA string `json:"sha"`
				} `json:"tree"`
			}{Tree: struct {
				SHA string `json:"sha"`
			}{SHA: "tree"}})
		},
		"POST /repos/owner/repo/git/blobs": func(*http.Request) *http.Response {
			return jsonResp(201, struct {
				SHA string `json:"sha"`
			}{SHA: "blob"})
		},
		"POST /repos/owner/repo/git/trees": func(*http.Request) *http.Response {
			return jsonResp(201, struct {
				SHA string `json:"sha"`
			}{SHA: "newtree"})
		},
		"POST /repos/owner/repo/git/commits": func(*http.Request) *http.Response {
			return jsonResp(201, struct {
				SHA string `json:"sha"`
			}{SHA: "newcommit"})
		},
		"PATCH /repos/owner/repo/git/refs/heads/chore/add-gpg-public-key": func(*http.Request) *http.Response {
			return jsonResp(200, struct {
				Ref string `json:"ref"`
			}{Ref: "refs/heads/chore/add-gpg-public-key"})
		},
		"POST /repos/owner/repo/pulls": func(*http.Request) *http.Response {
			return textResp(422, `{"message":"A pull request for branch ... already exists"}`)
		},
	}}

	_, err := CommitPublicKeyFileWithClient("tok", "owner", "repo", sampleArmor, f)
	if err == nil {
		t.Fatal("CommitPublicKeyFile with 422 PR must error")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error should mention 'already exists', got: %v", err)
	}
}

// TestCommitPublicKeyFile_GetRepoError verifies a 404 on the first
// call is surfaced.
func TestCommitPublicKeyFile_GetRepoError(t *testing.T) {
	f := &fakeDoer{responses: map[string]func(*http.Request) *http.Response{
		"GET /repos/owner/repo": func(*http.Request) *http.Response {
			return textResp(404, `{"message":"Not Found"}`)
		},
	}}
	_, err := CommitPublicKeyFileWithClient("tok", "owner", "repo", sampleArmor, f)
	if err == nil {
		t.Fatal("CommitPublicKeyFile with 404 repo must error")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error should mention 404, got: %v", err)
	}
}

// TestCommitPublicKeyFile_BlobBodyShape verifies the blob create
// request body is base64-encoded content with encoding="base64".
func TestCommitPublicKeyFile_BlobBodyShape(t *testing.T) {
	f := &fakeDoer{responses: map[string]func(*http.Request) *http.Response{
		"GET /repos/owner/repo": func(*http.Request) *http.Response {
			return jsonResp(200, struct {
				DefaultBranch string `json:"default_branch"`
			}{DefaultBranch: "main"})
		},
		"GET /repos/owner/repo/branches/main": func(*http.Request) *http.Response {
			return jsonResp(200, struct {
				Commit struct {
					SHA string `json:"sha"`
				} `json:"commit"`
			}{Commit: struct {
				SHA string `json:"sha"`
			}{SHA: "base"}})
		},
		"GET /repos/owner/repo/git/commits/base": func(*http.Request) *http.Response {
			return jsonResp(200, struct {
				Tree struct {
					SHA string `json:"sha"`
				} `json:"tree"`
			}{Tree: struct {
				SHA string `json:"sha"`
			}{SHA: "tree"}})
		},
		"POST /repos/owner/repo/git/blobs": func(*http.Request) *http.Response {
			return jsonResp(201, struct {
				SHA string `json:"sha"`
			}{SHA: "blob"})
		},
		"POST /repos/owner/repo/git/trees": func(*http.Request) *http.Response {
			return jsonResp(201, struct {
				SHA string `json:"sha"`
			}{SHA: "newtree"})
		},
		"POST /repos/owner/repo/git/commits": func(*http.Request) *http.Response {
			return jsonResp(201, struct {
				SHA string `json:"sha"`
			}{SHA: "newcommit"})
		},
		"PATCH /repos/owner/repo/git/refs/heads/chore/add-gpg-public-key": func(*http.Request) *http.Response {
			return jsonResp(200, struct {
				Ref string `json:"ref"`
			}{Ref: "refs/heads/chore/add-gpg-public-key"})
		},
		"POST /repos/owner/repo/pulls": func(*http.Request) *http.Response {
			return jsonResp(201, struct {
				HTMLURL string `json:"html_url"`
			}{HTMLURL: "https://github.com/owner/repo/pull/1"})
		},
	}}

	if _, err := CommitPublicKeyFileWithClient("tok", "owner", "repo", sampleArmor, f); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Find the blob POST and verify the body shape.
	for _, c := range f.calls {
		if c.method == "POST" && strings.HasSuffix(c.url, "/git/blobs") {
			var body struct {
				Content  string `json:"content"`
				Encoding string `json:"encoding"`
			}
			if err := json.Unmarshal([]byte(c.body), &body); err != nil {
				t.Fatalf("blob body not valid JSON: %v", err)
			}
			if body.Encoding != "base64" {
				t.Errorf("blob encoding = %q, want base64", body.Encoding)
			}
			if body.Content == "" {
				t.Error("blob content must not be empty")
			}
			// We could decode and compare to sampleArmor, but the
			// base64 round-trip is exercised by the createBlob
			// function itself; here we just assert shape.
			return
		}
	}
	t.Error("blob POST call not found")
}

// TestCreateBlob_Base64Content verifies createBlob base64-encodes the
// content. Direct test of the helper.
func TestCreateBlob_Base64Content(t *testing.T) {
	var capturedBody string
	f := &fakeDoer{responses: map[string]func(*http.Request) *http.Response{
		"POST /repos/o/r/git/blobs": func(req *http.Request) *http.Response {
			b, _ := io.ReadAll(req.Body)
			capturedBody = string(b)
			return jsonResp(201, struct {
				SHA string `json:"sha"`
			}{SHA: "sha"})
		},
	}}
	sha, err := createBlob("tok", "o", "r", "hello world", f)
	if err != nil {
		t.Fatalf("createBlob: %v", err)
	}
	if sha != "sha" {
		t.Errorf("sha = %q, want sha", sha)
	}
	var body struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := json.Unmarshal([]byte(capturedBody), &body); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	// base64("hello world") = "aGVsbG8gd29ybGQ="
	if body.Content != "aGVsbG8gd29ybGQ=" {
		t.Errorf("content = %q, want aGVsbG8gd29ybGQ=", body.Content)
	}
}
