package github

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// branchName is the git branch name used by CommitPublicKeyFile. It
// is a constant per the M6 spec — every repo gets the same branch
// name so a re-run is a no-op (the branch already exists → we push a
// new commit to it, then open or find the existing PR).
const branchName = "chore/add-gpg-public-key"

// fileName is the path inside the repo where the armored public key
// is committed.
const fileName = "gpg-public-key.asc"

// defaultBranchName is the GitHub default branch placeholder when
// the repo does not declare one explicitly. We resolve the real
// default branch via GET /repos/{owner}/{repo}; this constant is
// only a fallback for repos with a malformed default_branch field.
const defaultBranchName = "main"

// commitMessage is the git commit message used for the public key
// file commit. Extracted as a constant so tests can assert it.
const commitMessage = "chore: add GPG public key"

// prTitle is the title of the pull request opened by
// CommitPublicKeyFile. Extracted as a constant so tests can assert it.
const prTitle = "chore: add GPG public key"

// prBody is the markdown body of the pull request. Extracted as a
// constant so tests can assert it.
const prBody = "Adds the GPG public key produced by gpg-keysmith so commits can be verified with this key."

// CommitPublicKeyFile commits the supplied armored public key text
// as 'gpg-public-key.asc' to the target repo on the
// 'chore/add-gpg-public-key' branch and opens a pull request.
// Returns the PR HTML URL.
//
// Implementation approach: pure GitHub REST API via net/http. We
// chose the REST path over shelling out to git+gh because:
//   - it is fully testable with a fake Doer (no git binary needed
//     in tests, no temp repo clone);
//   - it avoids the complexity of a git clone + branch + commit +
//     push + gh pr create chain, which is hard to unit-test;
//   - the GitHub git database API (blobs → tree → commit → ref →
//     PR) is well-documented and stable.
//
// The API calls performed:
//  1. GET  /repos/{owner}/{repo}                            — resolve default branch
//  2. GET  /repos/{owner}/{repo}/branches/{branch}         — base commit SHA
//  3. GET  /repos/{owner}/{repo}/git/commits/{sha}         — base tree SHA
//  4. POST /repos/{owner}/{repo}/git/blobs                 — create blob with file content
//  5. POST /repos/{owner}/{repo}/git/trees                 — create tree (blob + base tree)
//  6. POST /repos/{owner}/{repo}/git/commits              — create commit (tree + parent)
//  7. PATCH/POST /repos/{owner}/{repo}/git/refs[/heads/{branch}] — update/create branch ref
//  8. POST /repos/{owner}/{repo}/pulls                    — open PR (branch → default)
//
// Callers may inject a Doer via CommitPublicKeyFileWithClient for
// testing.
func CommitPublicKeyFile(token, owner, repo, armoredPubKey string) (string, error) {
	return CommitPublicKeyFileWithClient(token, owner, repo, armoredPubKey, defaultHTTPClient)
}

// CommitPublicKeyFileWithClient is the testable form of
// CommitPublicKeyFile.
func CommitPublicKeyFileWithClient(token, owner, repo, armoredPubKey string, c Doer) (string, error) {
	if token == "" {
		return "", fmt.Errorf("github: commit public key file: token is required")
	}
	// Validate owner/repo before any HTTP call — rejects path
	// injection into the /repos/{owner}/{repo} URL segments.
	if err := ValidateOwnerRepo(owner, repo); err != nil {
		return "", err
	}
	if !strings.HasPrefix(armoredPubKey, pgpArmorHeader) {
		return "", fmt.Errorf("github: commit public key file: armored public key must start with %q", pgpArmorHeader)
	}
	if c == nil {
		c = defaultHTTPClient
	}

	// 1. Resolve the repo's default branch.
	defaultBranch, err := getDefaultBranch(token, owner, repo, c)
	if err != nil {
		return "", err
	}

	// 2. Get the SHA of the default branch HEAD (parent commit).
	baseSHA, err := getBranchHeadSHA(token, owner, repo, defaultBranch, c)
	if err != nil {
		return "", err
	}

	// 3. Get the base tree SHA of the parent commit (so the new tree
	// inherits all existing files, not just our one).
	baseTreeSHA, err := getCommitTreeSHA(token, owner, repo, baseSHA, c)
	if err != nil {
		return "", err
	}

	// 4. Create a blob with the armored public key content.
	blobSHA, err := createBlob(token, owner, repo, armoredPubKey, c)
	if err != nil {
		return "", err
	}

	// 5. Create a new tree that adds gpg-public-key.asc on top of
	// the base tree.
	newTreeSHA, err := createTree(token, owner, repo, baseTreeSHA, fileName, blobSHA, c)
	if err != nil {
		return "", err
	}

	// 6. Create a commit on top of the default branch HEAD.
	commitSHA, err := createCommit(token, owner, repo, commitMessage, newTreeSHA, []string{baseSHA}, c)
	if err != nil {
		return "", err
	}

	// 7. Create (or update) the branch ref to point at the new
	// commit. If the branch does not exist, POST a new ref; if it
	// exists, PATCH it.
	if err := upsertBranchRef(token, owner, repo, branchName, commitSHA, c); err != nil {
		return "", err
	}

	// 8. Open a PR from the branch into the default branch. If a PR
	// is already open, GitHub returns 422; we surface a clear error
	// pointing the user to the existing PR.
	prURL, err := createPullRequest(token, owner, repo, branchName, defaultBranch, c)
	if err != nil {
		return "", err
	}
	return prURL, nil
}

// getDefaultBranch fetches the repo's configured default branch via
// GET /repos/{owner}/{repo}. Falls back to "main" if the field is
// empty (should not happen on a real repo, but keeps the function
// total).
func getDefaultBranch(token, owner, repo string, c Doer) (string, error) {
	path, err := reposPath(owner, repo, "")
	if err != nil {
		return "", err
	}
	req, err := newGitHubRequest(http.MethodGet, path, token, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("github: get repo: HTTP request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("github: get repo: status %d: %s",
			resp.StatusCode, truncateForError(resp.Body))
	}
	var body struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("github: get repo: decode response: %w", err)
	}
	if body.DefaultBranch == "" {
		return defaultBranchName, nil
	}
	return body.DefaultBranch, nil
}

// getBranchHeadSHA returns the SHA of the HEAD commit of the given
// branch via GET /repos/{owner}/{repo}/branches/{branch}.
func getBranchHeadSHA(token, owner, repo, branch string, c Doer) (string, error) {
	path, err := reposPath(owner, repo, "/branches/"+branch)
	if err != nil {
		return "", err
	}
	req, err := newGitHubRequest(http.MethodGet, path, token, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("github: get branch %s: HTTP request failed: %w", branch, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("github: get branch %s: status %d: %s",
			branch, resp.StatusCode, truncateForError(resp.Body))
	}
	var body struct {
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("github: get branch %s: decode response: %w", branch, err)
	}
	if body.Commit.SHA == "" {
		return "", fmt.Errorf("github: get branch %s: empty commit sha", branch)
	}
	return body.Commit.SHA, nil
}

// getCommitTreeSHA returns the tree SHA of the given commit via
// GET /repos/{owner}/{repo}/git/commits/{sha}.
func getCommitTreeSHA(token, owner, repo, commitSHA string, c Doer) (string, error) {
	path, err := reposPath(owner, repo, "/git/commits/"+url.PathEscape(commitSHA))
	if err != nil {
		return "", err
	}
	req, err := newGitHubRequest(http.MethodGet, path, token, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("github: get commit %s: HTTP request failed: %w", commitSHA, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("github: get commit %s: status %d: %s",
			commitSHA, resp.StatusCode, truncateForError(resp.Body))
	}
	var body struct {
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("github: get commit %s: decode response: %w", commitSHA, err)
	}
	if body.Tree.SHA == "" {
		return "", fmt.Errorf("github: get commit %s: empty tree sha", commitSHA)
	}
	return body.Tree.SHA, nil
}

// createBlob creates a git blob with the given content via
// POST /repos/{owner}/{repo}/git/blobs. Returns the blob SHA.
// Content is base64-encoded per the GitHub git database API spec.
func createBlob(token, owner, repo, content string, c Doer) (string, error) {
	body, err := json.Marshal(struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}{Content: base64.StdEncoding.EncodeToString([]byte(content)), Encoding: "base64"})
	if err != nil {
		return "", fmt.Errorf("github: create blob: marshal body: %w", err)
	}
	path, err := reposPath(owner, repo, "/git/blobs")
	if err != nil {
		return "", err
	}
	req, err := newGitHubRequest(http.MethodPost, path, token, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("github: create blob: HTTP request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("github: create blob: status %d: %s",
			resp.StatusCode, truncateForError(resp.Body))
	}
	var out struct {
		SHA string `json:"sha"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("github: create blob: decode response: %w", err)
	}
	if out.SHA == "" {
		return "", fmt.Errorf("github: create blob: empty sha")
	}
	return out.SHA, nil
}

// treeEntry is the JSON shape of a single entry in a git tree create
// request. Extracted so createTree and its tests can share the shape.
type treeEntry struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
}

// createTree creates a new git tree that adds a single file (with
// the given blob SHA) on top of baseTreeSHA via
// POST /repos/{owner}/{repo}/git/trees.
func createTree(token, owner, repo, baseTreeSHA, filePath, blobSHA string, c Doer) (string, error) {
	entry := treeEntry{Path: filePath, Mode: "100644", Type: "blob", SHA: blobSHA}
	body, err := json.Marshal(struct {
		BaseTree string      `json:"base_tree"`
		Tree     []treeEntry `json:"tree"`
	}{BaseTree: baseTreeSHA, Tree: []treeEntry{entry}})
	if err != nil {
		return "", fmt.Errorf("github: create tree: marshal body: %w", err)
	}
	urlPath, err := reposPath(owner, repo, "/git/trees")
	if err != nil {
		return "", err
	}
	req, err := newGitHubRequest(http.MethodPost, urlPath, token, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("github: create tree: HTTP request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("github: create tree: status %d: %s",
			resp.StatusCode, truncateForError(resp.Body))
	}
	var out struct {
		SHA string `json:"sha"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("github: create tree: decode response: %w", err)
	}
	if out.SHA == "" {
		return "", fmt.Errorf("github: create tree: empty sha")
	}
	return out.SHA, nil
}

// createCommit creates a git commit with the given message, tree,
// and parents via POST /repos/{owner}/{repo}/git/commits. Returns
// the commit SHA.
func createCommit(token, owner, repo, message, treeSHA string, parents []string, c Doer) (string, error) {
	body, err := json.Marshal(struct {
		Message string   `json:"message"`
		Tree    string   `json:"tree"`
		Parents []string `json:"parents"`
	}{Message: message, Tree: treeSHA, Parents: parents})
	if err != nil {
		return "", fmt.Errorf("github: create commit: marshal body: %w", err)
	}
	path, err := reposPath(owner, repo, "/git/commits")
	if err != nil {
		return "", fmt.Errorf("github: create commit: build path: %w", err)
	}
	req, err := newGitHubRequest(http.MethodPost, path, token, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("github: create commit: build request: %w", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("github: create commit: HTTP request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("github: create commit: status %d: %s",
			resp.StatusCode, truncateForError(resp.Body))
	}
	var out struct {
		SHA string `json:"sha"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("github: create commit: decode response: %w", err)
	}
	if out.SHA == "" {
		return "", fmt.Errorf("github: create commit: empty sha")
	}
	return out.SHA, nil
}

// upsertBranchRef creates or updates the branch ref to point at the
// given commit SHA. Tries PATCH first (branch exists); on 422 or 404
// falls back to POST (branch does not exist). Returns an error only
// if both fail with a non-422/404 status.
func upsertBranchRef(token, owner, repo, branch, commitSHA string, c Doer) error {
	patchBody, _ := json.Marshal(struct {
		SHA string `json:"sha"`
	}{SHA: commitSHA})

	// Try PATCH first — assumes the branch already exists from a
	// previous run.
	patchPath, err := reposPath(owner, repo, "/git/refs/heads/"+branch)
	if err != nil {
		return fmt.Errorf("github: upsert branch ref (PATCH): build path: %w", err)
	}
	patchReq, err := newGitHubRequest(http.MethodPatch, patchPath, token, bytes.NewReader(patchBody))
	if err != nil {
		return fmt.Errorf("github: upsert branch ref (PATCH): build request: %w", err)
	}
	patchResp, err := c.Do(patchReq)
	if err != nil {
		return fmt.Errorf("github: upsert branch ref (PATCH): HTTP request failed: %w", err)
	}
	defer patchResp.Body.Close()
	if patchResp.StatusCode >= 200 && patchResp.StatusCode < 300 {
		return nil
	}
	if patchResp.StatusCode != http.StatusUnprocessableEntity && patchResp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("github: upsert branch ref (PATCH): status %d: %s",
			patchResp.StatusCode, truncateForError(patchResp.Body))
	}
	// PATCH returned 422 or 404 — branch likely does not exist.
	// Create it via POST.
	postBody, _ := json.Marshal(struct {
		Ref string `json:"ref"`
		SHA string `json:"sha"`
	}{Ref: "refs/heads/" + branch, SHA: commitSHA})
	postPath, err := reposPath(owner, repo, "/git/refs")
	if err != nil {
		return fmt.Errorf("github: upsert branch ref (POST): build path: %w", err)
	}
	postReq, err := newGitHubRequest(http.MethodPost, postPath, token, bytes.NewReader(postBody))
	if err != nil {
		return fmt.Errorf("github: upsert branch ref (POST): build request: %w", err)
	}
	postResp, err := c.Do(postReq)
	if err != nil {
		return fmt.Errorf("github: upsert branch ref (POST): HTTP request failed: %w", err)
	}
	defer postResp.Body.Close()
	if postResp.StatusCode < 200 || postResp.StatusCode >= 300 {
		return fmt.Errorf("github: upsert branch ref (POST): status %d: %s",
			postResp.StatusCode, truncateForError(postResp.Body))
	}
	return nil
}

// createPullRequest opens a PR from branch → baseBranch via
// POST /repos/{owner}/{repo}/pulls. Returns the PR HTML URL. If a PR
// is already open, GitHub returns 422; we surface a clear error
// pointing the user to the existing PR.
func createPullRequest(token, owner, repo, branch, baseBranch string, c Doer) (string, error) {
	body, err := json.Marshal(struct {
		Title string `json:"title"`
		Head  string `json:"head"`
		Base  string `json:"base"`
		Body  string `json:"body"`
	}{Title: prTitle, Head: branch, Base: baseBranch, Body: prBody})
	if err != nil {
		return "", fmt.Errorf("github: create PR: marshal body: %w", err)
	}
	path, err := reposPath(owner, repo, "/pulls")
	if err != nil {
		return "", err
	}
	req, err := newGitHubRequest(http.MethodPost, path, token, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("github: create PR: HTTP request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var out struct {
			HTMLURL string `json:"html_url"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return "", fmt.Errorf("github: create PR: decode response: %w", err)
		}
		if out.HTMLURL == "" {
			return "", fmt.Errorf("github: create PR: empty html_url")
		}
		return out.HTMLURL, nil
	}
	// 422 means a PR already exists for this branch+base combo.
	if resp.StatusCode == http.StatusUnprocessableEntity {
		return "", fmt.Errorf("github: create PR: a pull request for %s → %s already exists (look it up via 'gh pr view %s/%s' or the GitHub UI)",
			branch, baseBranch, owner, repo)
	}
	return "", fmt.Errorf("github: create PR: status %d: %s",
		resp.StatusCode, truncateForError(resp.Body))
}

// readerForString returns an io.Reader for the given string. Kept as
// a helper so the package does not need to import strings.NewReader
// at multiple call sites.
func readerForString(s string) io.Reader {
	return bytes.NewReader([]byte(s))
}
