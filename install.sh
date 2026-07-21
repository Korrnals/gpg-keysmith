#!/usr/bin/env bash
# gpg-keysmith one-line installer — downloads a fresh binary from the latest
# GitHub release (matched to your OS/arch), verifies the SHA256 checksum,
# installs it to ~/.local/bin (or --install-dir), ensures that dir is in PATH,
# and checks that runtime dependencies (gpg, git, gh) are present (printing
# install hints if not). No build step, no Go toolchain required.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Korrnals/gpg-keysmith/main/install.sh | bash
#   # or, to pin a version:
#   ... | bash -s -- --version v1.2.0
#   # or, system-wide:
#   ... | bash -s -- --install-dir /usr/local/bin
#   # for private repos, export GH_TOKEN first.
#
# Flags:
#   --version <ver>      install a specific release (default: latest)
#   --install-dir <dir>  install to this dir (default: ~/.local/bin)
#   --no-checksum        skip SHA256 verification (NOT recommended)
#   --help               print this help
set -euo pipefail

REPO="Korrnals/gpg-keysmith"
VERSION=""
INSTALL_DIR="${INSTALL_DIR:-${HOME}/.local/bin}"
VERIFY_CHECKSUM=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2;;
    --install-dir) INSTALL_DIR="$2"; shift 2;;
    --no-checksum) VERIFY_CHECKSUM=0; shift;;
    --help|-h) sed -n '2,20p' "$0" 2>/dev/null || true; exit 0;;
    *) echo "Unknown flag: $1" >&2; exit 1;;
  esac
done

err()  { echo "❌ $*" >&2; exit 1; }
info() { echo "==> $*"; }
ok()   { echo "✅ $*"; }

# Auth header for private repos (set GH_TOKEN or GITHUB_TOKEN in env).
AUTH_HDR=()
if [[ -n "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ]]; then
  AUTH_HDR=(-H "Authorization: Bearer ${GH_TOKEN:-${GITHUB_TOKEN}}")
fi

# Detect OS / arch.
OS="$(uname -s 2>/dev/null || echo unknown)"
ARCH="$(uname -m 2>/dev/null || echo unknown)"
case "$OS/$ARCH" in
  Linux/x86_64|Linux/amd64)   OS=linux;  ARCH=amd64;;
  Linux/aarch64|Linux/arm64) OS=linux;  ARCH=arm64;;
  Darwin/x86_64|Darwin/amd64) OS=darwin; ARCH=amd64;;
  Darwin/arm64|Darwin/aarch64) OS=darwin; ARCH=arm64;;
  MINGW*|MSYS*|CYGWIN*) err "Windows: download the .exe from https://github.com/${REPO}/releases";;
  *) err "Unsupported OS/arch: $OS/$ARCH. Download manually from https://github.com/${REPO}/releases";;
esac

# Resolve version via the GitHub API (works for both public and private
# repos when GH_TOKEN/GITHUB_TOKEN is set; for public repos, also works
# unauthenticated with a lower rate limit).
if [[ -z "$VERSION" ]]; then
  info "Detecting latest release"
  API_URL="https://api.github.com/repos/${REPO}/releases/latest"
  API_RESP="$(curl -fsSL "${AUTH_HDR[@]}" "$API_URL" 2>/dev/null || true)"
  VERSION="$(printf '%s\n' "$API_RESP" | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')" || true
  [[ -z "$VERSION" ]] && \
    err "could not detect latest release (repo may be private — set GH_TOKEN, or pin with --version v1.2.0)"
fi

info "Installing gpg-keysmith ${VERSION} for ${OS}/${ARCH}"

ASSET="keysmith-${OS}-${ARCH}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# GitHub release download URLs (github.com/.../releases/download/...) 404 for
# private repos even with an auth header. The reliable path for both public and
# private repos is: query the release asset list via the API to find the asset
# id, then GET the /releases/assets/{id} endpoint with Accept: octet-stream (the
# API redirects to a temporary S3 URL that carries its own auth token). For
# public repos the direct github.com/.../download/... URL also works, so try
# that first as a fast path (no extra API round-trip).
DIRECT_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
info "Downloading ${ASSET}"
if ! curl -fsSL "${AUTH_HDR[@]}" -o "${TMP}/${ASSET}" "${DIRECT_URL}" 2>/dev/null; then
  info "Direct URL failed (likely private repo) — resolving asset via API"
  RELEASE_API="https://api.github.com/repos/${REPO}/releases/tags/${VERSION}"
  API_RESP="$(curl -fsSL "${AUTH_HDR[@]}" "$RELEASE_API" 2>/dev/null || true)"
  [[ -z "$API_RESP" ]] && err "could not fetch release ${VERSION} via API"
  ASSET_ID="$(printf '%s\n' "$API_RESP" | python3 -c "import json,sys; d=json.load(sys.stdin); print(next((a['id'] for a in d.get('assets',[]) if a['name']=='${ASSET}'), ''))" 2>/dev/null || true)"
  [[ -z "$ASSET_ID" ]] && err "asset ${ASSET} not found in release ${VERSION}"
  ASSET_API="https://api.github.com/repos/${REPO}/releases/assets/${ASSET_ID}"
  curl -fsSL "${AUTH_HDR[@]}" -H "Accept: application/octet-stream" -o "${TMP}/${ASSET}" "${ASSET_API}" || err "API download failed for asset ${ASSET_ID}"
fi

if [[ "$VERIFY_CHECKSUM" == "1" ]]; then
  info "Downloading checksums"
  CHECKSUMS_DIRECT="https://github.com/${REPO}/releases/download/${VERSION}/checksums-sha256.txt"
  if ! curl -fsSL "${AUTH_HDR[@]}" -o "${TMP}/checksums.txt" "${CHECKSUMS_DIRECT}" 2>/dev/null; then
    CS_ASSET_ID="$(printf '%s\n' "$API_RESP" | python3 -c "import json,sys; d=json.load(sys.stdin); print(next((a['id'] for a in d.get('assets',[]) if a['name']=='checksums-sha256.txt'), ''))" 2>/dev/null || true)"
    if [[ -n "$CS_ASSET_ID" ]]; then
      curl -fsSL "${AUTH_HDR[@]}" -H "Accept: application/octet-stream" -o "${TMP}/checksums.txt" "https://api.github.com/repos/${REPO}/releases/assets/${CS_ASSET_ID}" 2>/dev/null || true
    fi
  fi
  if [[ -s "${TMP}/checksums.txt" ]]; then
    EXPECTED="$(grep -E "[ /]${ASSET}\$" "${TMP}/checksums.txt" | awk '{print $1}')"
    if [[ -n "$EXPECTED" ]]; then
      ACTUAL="$(sha256sum "${TMP}/${ASSET}" | awk '{print $1}')"
      [[ "$ACTUAL" == "$EXPECTED" ]] && ok "checksum verified" || err "checksum mismatch: expected ${EXPECTED}, got ${ACTUAL}"
    else
      echo "⚠️  no checksum entry for ${ASSET} — skipping verification"
    fi
  else
    echo "⚠️  checksums file not found for ${VERSION} — skipping verification"
  fi
fi

info "Installing to ${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"
chmod +x "${TMP}/${ASSET}"
mv "${TMP}/${ASSET}" "${INSTALL_DIR}/keysmith"
ok "binary installed: ${INSTALL_DIR}/keysmith"

info "Ensuring ${INSTALL_DIR} is in PATH"
case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ok "${INSTALL_DIR} already in PATH";;
  *)
    SHELL_NAME="${SHELL##*/}"
    case "$SHELL_NAME" in
      bash) RC="${HOME}/.bashrc"; LINE="export PATH=\"${INSTALL_DIR}:\$PATH\"";;
      zsh)  RC="${HOME}/.zshrc";  LINE="export PATH=\"${INSTALL_DIR}:\$PATH\"";;
      fish) RC="${HOME}/.config/fish/config.fish"; LINE="set -gx PATH ${INSTALL_DIR} \$PATH";;
      *)    RC="${HOME}/.bashrc"; LINE="export PATH=\"${INSTALL_DIR}:\$PATH\""; echo "  (unknown shell ${SHELL_NAME}, defaulting to ~/.bashrc)";;
    esac
    mkdir -p "$(dirname "$RC")"
    if [[ -f "$RC" ]] && grep -q "${INSTALL_DIR}" "$RC" 2>/dev/null; then
      ok "${INSTALL_DIR} already referenced in ${RC}"
    else
      printf '\n# Added by gpg-keysmith installer\n%s\n' "$LINE" >> "$RC"
      echo "⚠️  added to ${RC}. Restart your shell or run: source ${RC}"
    fi
    ;;
esac

info "Checking runtime dependencies (gpg, git, gh)"
for dep in gpg git gh; do
  if command -v "$dep" >/dev/null 2>&1; then
    ok "$dep: $(command -v $dep)"
  else
    case "$dep" in
      gpg) echo "⚠️  gpg not found. Install: sudo apt install gnupg | brew install gnupg | https://gnupg.org";;
      git) echo "⚠️  git not found. Install: sudo apt install git | brew install git | https://git-scm.com";;
      gh)  echo "⚠️  gh not found (only needed for 'github' repo-secrets step). Install: https://cli.github.com";;
    esac
  fi
done

info "Verifying"
if "${INSTALL_DIR}/keysmith" --version >/dev/null 2>&1; then
  ok "keysmith $(${INSTALL_DIR}/keysmith --version 2>&1 | head -1)"
else
  err "keysmith binary failed to execute — check architecture and file permissions"
fi

echo
echo "🎉 gpg-keysmith ${VERSION} installed to ${INSTALL_DIR}"
echo "   Next: export GITHUB_TOKEN=ghp_... && keysmith wizard"
