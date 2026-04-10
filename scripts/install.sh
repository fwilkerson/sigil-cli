#!/bin/sh
# Sigil CLI installer
# Usage: curl -fsSL https://sigil-trust.dev/install.sh | sh
set -e

INSTALL_DIR="$HOME/.sigil/bin"
BINARY="$INSTALL_DIR/sigil"
BASE_URL="https://sigil-trust.dev/dl"

# Detect OS
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
  darwin|linux) ;;
  *)
    echo "error: unsupported OS: $OS" >&2
    exit 1
    ;;
esac

# Detect architecture
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64)         ARCH="amd64" ;;
  aarch64|arm64)  ARCH="arm64" ;;
  *)
    echo "error: unsupported architecture: $ARCH_RAW" >&2
    exit 1
    ;;
esac

DOWNLOAD_URL="$BASE_URL/sigil-${OS}-${ARCH}"

echo "Installing Sigil CLI for ${OS}/${ARCH} ..."

# Create install directory if it doesn't exist
mkdir -p "$INSTALL_DIR"

# Download binary using curl or wget
if command -v curl > /dev/null 2>&1; then
  curl -fsSL "$DOWNLOAD_URL" -o "$BINARY"
elif command -v wget > /dev/null 2>&1; then
  wget -qO "$BINARY" "$DOWNLOAD_URL"
else
  echo "error: neither curl nor wget is available" >&2
  exit 1
fi

# Verify checksum
CHECKSUM_URL="${DOWNLOAD_URL}.sha256"
echo "Verifying checksum ..."
EXPECTED=""
if command -v curl > /dev/null 2>&1; then
  EXPECTED=$(curl -fsSL "$CHECKSUM_URL" 2>/dev/null) || true
elif command -v wget > /dev/null 2>&1; then
  EXPECTED=$(wget -qO- "$CHECKSUM_URL" 2>/dev/null) || true
fi

if [ -n "$EXPECTED" ]; then
  if command -v shasum > /dev/null 2>&1; then
    ACTUAL=$(shasum -a 256 "$BINARY" | awk '{print $1}')
  elif command -v sha256sum > /dev/null 2>&1; then
    ACTUAL=$(sha256sum "$BINARY" | awk '{print $1}')
  else
    echo "  Warning: no checksum tool available — skipping verification."
    ACTUAL=""
  fi
  if [ -n "$ACTUAL" ] && [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "error: checksum mismatch (expected $EXPECTED, got $ACTUAL)" >&2
    rm -f "$BINARY"
    exit 1
  fi
  echo "  Checksum verified."
else
  echo "  Warning: could not fetch checksum — skipping verification."
fi

chmod +x "$BINARY"

# Configure PATH for the user's shell
configure_path_bash() {
  RC="$HOME/.bashrc"
  LINE='export PATH="$HOME/.sigil/bin:$PATH"'
  if ! grep -qF '.sigil/bin' "$RC" 2>/dev/null; then
    printf '\n# Sigil CLI\n%s\n' "$LINE" >> "$RC"
    echo "  Added PATH entry to $RC"
  fi
}

configure_path_zsh() {
  RC="$HOME/.zshrc"
  LINE='export PATH="$HOME/.sigil/bin:$PATH"'
  if ! grep -qF '.sigil/bin' "$RC" 2>/dev/null; then
    printf '\n# Sigil CLI\n%s\n' "$LINE" >> "$RC"
    echo "  Added PATH entry to $RC"
  fi
}

configure_path_fish() {
  CFG="$HOME/.config/fish/config.fish"
  mkdir -p "$(dirname "$CFG")"
  if ! grep -qF '.sigil/bin' "$CFG" 2>/dev/null; then
    printf '\n# Sigil CLI\nfish_add_path ~/.sigil/bin\n' >> "$CFG"
    echo "  Added fish_add_path to $CFG"
  fi
}

# Detect shell — $FISH_VERSION overrides $SHELL since macOS $SHELL
# reflects chsh, not the active shell.
if [ -n "$FISH_VERSION" ]; then
    SHELL_NAME="fish"
else
    SHELL_NAME="$(basename "${SHELL:-sh}")"
fi
case "$SHELL_NAME" in
  bash) configure_path_bash ;;
  zsh)  configure_path_zsh  ;;
  fish) configure_path_fish ;;
  *)
    echo "  Note: unknown shell '$SHELL_NAME'. Add $INSTALL_DIR to your PATH manually."
    ;;
esac

echo ""
echo "Sigil CLI installed to $BINARY"
echo ""

# Print version, using full path in case the shell hasn't reloaded PATH yet
"$BINARY" version 2>/dev/null || true

echo ""
echo "Restart your shell (or run: source ~/.bashrc / source ~/.zshrc) to use 'sigil' from anywhere."
