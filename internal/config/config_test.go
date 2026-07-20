package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tmpConfigPath returns a unique config path inside a temp dir for the
// test. Tests never touch the real ~/.config — they always pass a
// path inside t.TempDir().
func tmpConfigPath(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, name)
}

func TestDefault(t *testing.T) {
	c := Default()

	if c.Key.Type != "RSA" {
		t.Errorf("Key.Type = %q, want RSA", c.Key.Type)
	}
	if c.Key.Length != 4096 {
		t.Errorf("Key.Length = %d, want 4096", c.Key.Length)
	}
	if c.Key.Expire != "0" {
		t.Errorf("Key.Expire = %q, want 0", c.Key.Expire)
	}
	if c.GitHub.TokenEnv != "GITHUB_TOKEN" {
		t.Errorf("GitHub.TokenEnv = %q, want GITHUB_TOKEN", c.GitHub.TokenEnv)
	}
	if c.GitHub.Repo != "" {
		t.Errorf("GitHub.Repo = %q, want empty", c.GitHub.Repo)
	}
	if c.Keyserver.Preferred != "keys.openpgp.org" {
		t.Errorf("Keyserver.Preferred = %q, want keys.openpgp.org", c.Keyserver.Preferred)
	}
	if c.Keyserver.Fallback != "keyserver.ubuntu.com" {
		t.Errorf("Keyserver.Fallback = %q, want keyserver.ubuntu.com", c.Keyserver.Fallback)
	}
}

func TestLoadMissingFileReturnsDefaultNoError(t *testing.T) {
	path := tmpConfigPath(t, "absent.yaml")

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load missing file: unexpected error: %v", err)
	}
	want := Default()
	if c != want {
		t.Errorf("Load missing file: got %+v, want Default() %+v", c, want)
	}
}

func TestSaveLoadRoundtrip(t *testing.T) {
	path := tmpConfigPath(t, "config.yaml")

	c := Default()
	c.Key.Length = 8192
	c.Key.Expire = "2y"
	c.GitHub.Repo = "octocat/hello-world"
	c.Keyserver.Preferred = "keyserver.ubuntu.com"

	if err := Save(c, path); err != nil {
		t.Fatalf("Save: unexpected error: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load after Save: unexpected error: %v", err)
	}

	if loaded.Key.Length != 8192 {
		t.Errorf("loaded Key.Length = %d, want 8192", loaded.Key.Length)
	}
	if loaded.Key.Expire != "2y" {
		t.Errorf("loaded Key.Expire = %q, want 2y", loaded.Key.Expire)
	}
	if loaded.GitHub.Repo != "octocat/hello-world" {
		t.Errorf("loaded GitHub.Repo = %q, want octocat/hello-world", loaded.GitHub.Repo)
	}
	if loaded.Keyserver.Preferred != "keyserver.ubuntu.com" {
		t.Errorf("loaded Keyserver.Preferred = %q, want keyserver.ubuntu.com", loaded.Keyserver.Preferred)
	}
	// TokenEnv must survive the roundtrip — it is the security-
	// critical field (the PAT reference must not be silently lost).
	if loaded.GitHub.TokenEnv != "GITHUB_TOKEN" {
		t.Errorf("loaded GitHub.TokenEnv = %q, want GITHUB_TOKEN", loaded.GitHub.TokenEnv)
	}
}

func TestSaveCreatesParentDirWith0700(t *testing.T) {
	dir := t.TempDir()
	// Nested non-existent dirs — Save must create them.
	path := filepath.Join(dir, "nested", "deep", "config.yaml")

	if err := Save(Default(), path); err != nil {
		t.Fatalf("Save nested: unexpected error: %v", err)
	}

	info, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("Stat parent dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("parent dir perm = %o, want 0700", perm)
	}
}

func TestSaveFileModeIs0600(t *testing.T) {
	path := tmpConfigPath(t, "config.yaml")

	if err := Save(Default(), path); err != nil {
		t.Fatalf("Save: unexpected error: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat config file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("config file perm = %o, want 0600", perm)
	}
}

func TestSaveEmptyTokenEnvErrors(t *testing.T) {
	path := tmpConfigPath(t, "config.yaml")

	c := Default()
	c.GitHub.TokenEnv = ""

	err := Save(c, path)
	if err == nil {
		t.Fatalf("Save with empty TokenEnv: expected error, got nil")
	}
	if err != ErrEmptyTokenEnv {
		t.Errorf("Save with empty TokenEnv: error = %v, want ErrEmptyTokenEnv", err)
	}

	// And nothing must have been written — the validation gate fires
	// before any filesystem side effect.
	if _, statErr := os.Stat(path); statErr == nil {
		t.Errorf("Save with empty TokenEnv: file was created despite the error")
	}
}

func TestLoadMalformedYAMLErrors(t *testing.T) {
	path := tmpConfigPath(t, "bad.yaml")

	bad := []byte("key: [unterminated\n  : not valid yaml:\n   - also: not: valid")
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatalf("WriteFile bad yaml: %v", err)
	}

	if _, err := Load(path); err == nil {
		t.Fatalf("Load malformed YAML: expected error, got nil")
	}
}

func TestInitWritesTemplate(t *testing.T) {
	path := tmpConfigPath(t, "config.yaml")

	if err := Init(path, false); err != nil {
		t.Fatalf("Init first call: unexpected error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile after Init: %v", err)
	}
	s := string(data)
	// The template must explain the token_env contract — it is the
	// security-critical field a hand-editor needs to understand.
	if !strings.Contains(s, "token_env") {
		t.Errorf("template missing 'token_env'")
	}
	if !strings.Contains(s, "NEVER") {
		t.Errorf("template missing the NEVER-store-the-token warning")
	}
	// The template must round-trip through Load back to Default(),
	// so a user who runs 'config init' and then loads the file gets
	// the same defaults as a fresh install with no file.
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load after Init: unexpected error: %v", err)
	}
	if loaded != Default() {
		t.Errorf("Load after Init: got %+v, want Default() %+v", loaded, Default())
	}
}

func TestInitRefusesExistingWithoutForce(t *testing.T) {
	path := tmpConfigPath(t, "config.yaml")

	if err := Init(path, false); err != nil {
		t.Fatalf("Init first call: unexpected error: %v", err)
	}

	if err := Init(path, false); err == nil {
		t.Fatalf("Init second call without --force: expected error, got nil")
	}

	// With --force it overwrites.
	if err := Init(path, true); err != nil {
		t.Fatalf("Init second call with --force: unexpected error: %v", err)
	}
}

func TestInitFileMode0600(t *testing.T) {
	path := tmpConfigPath(t, "config.yaml")

	if err := Init(path, false); err != nil {
		t.Fatalf("Init: unexpected error: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat after Init: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("Init file perm = %o, want 0600", perm)
	}
}
