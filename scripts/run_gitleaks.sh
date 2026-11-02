#!/usr/bin/env bash
# Scan full git history with the OSS gitleaks CLI.
# The GitHub Action refuses organization repositories that have no paid
# GITLEAKS_LICENSE and then the rest of the security-scan job never runs.
# Pin: https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1
# Checksums file sha256 061476c21adaf5441516f96f185c1a4706a83cd6329b9b38762271b3d4a52fae
# (gitleaks_8.30.1_checksums.txt). A repo-root .gitleaks.toml and
# .gitleaksignore are loaded by gitleaks itself.
set -euo pipefail

VERSION="8.30.1"
SHA_LINUX_X64="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
SHA_LINUX_ARM64="e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-$ROOT}"
INSTALL_DIR="${GITLEAKS_INSTALL_DIR:-/tmp/gitleaks-v${VERSION}}"

# An ambient config would replace the repository ruleset. Discovery of
# ${TARGET}/.gitleaks.toml remains gitleaks' own default.
unset GITLEAKS_CONFIG GITLEAKS_CONFIG_TOML

case "$(uname -m)" in
  x86_64)
    asset="gitleaks_${VERSION}_linux_x64.tar.gz"
    expected="$SHA_LINUX_X64"
    ;;
  aarch64|arm64)
    asset="gitleaks_${VERSION}_linux_arm64.tar.gz"
    expected="$SHA_LINUX_ARM64"
    ;;
  *)
    echo "::error::unsupported architecture $(uname -m); refusing to run an unpinned gitleaks binary" >&2
    exit 1
    ;;
esac

bin="${INSTALL_DIR}/gitleaks"
stamp="${INSTALL_DIR}/VERSION"
if [[ ! -x "$bin" || "$(cat "$stamp" 2>/dev/null || true)" != "$VERSION" ]]; then
  mkdir -p "$INSTALL_DIR"
  tmp="$(mktemp -d)"
  cleanup() { rm -rf "$tmp"; }
  trap cleanup EXIT
  url="https://github.com/gitleaks/gitleaks/releases/download/v${VERSION}/${asset}"
  curl --proto =https --proto-redir =https -fsSL -o "${tmp}/gitleaks.tgz" "$url"
  echo "${expected}  ${tmp}/gitleaks.tgz" | sha256sum -c -
  tar -xzf "${tmp}/gitleaks.tgz" -C "$tmp" gitleaks
  install -m 0755 "${tmp}/gitleaks" "$bin"
  printf '%s\n' "$VERSION" > "$stamp"
  rm -rf "$tmp"
  trap - EXIT
fi

got="$("$bin" version)"
if [[ "$got" != "$VERSION" ]]; then
  echo "::error::gitleaks version ${got} does not match pinned ${VERSION}" >&2
  exit 1
fi

"$bin" git "$TARGET" --redact --verbose --exit-code 1 --no-banner
