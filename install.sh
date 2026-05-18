#!/usr/bin/env bash
# install.sh — git-clone installer for Deepcrypt (dpc)
# Usage: bash install.sh
# No Node.js or npm required.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$SCRIPT_DIR/binaries"
INSTALL_DIR="$HOME/.local/bin"
PATH_LINE="export PATH=\"\$HOME/.local/bin:\$PATH\""

# ── Platform detection ───────────────────────────────────────────────────────
case "$(uname -s)" in
  Linux*)  PLAT="linux"  ;;
  Darwin*) PLAT="darwin" ;;
  *) echo "[dpc] Unsupported OS: $(uname -s)"; exit 1 ;;
esac

# ── Arch detection ───────────────────────────────────────────────────────────
case "$(uname -m)" in
  x86_64)        ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  armv7l|armv6l) ARCH="arm"   ;;
  *) echo "[dpc] Unsupported arch: $(uname -m)"; exit 1 ;;
esac

BINARY_NAME="dpc-${PLAT}-${ARCH}"
BINARY_PATH="$BIN_DIR/$BINARY_NAME"

# ── Verify binary exists ─────────────────────────────────────────────────────
if [ ! -f "$BINARY_PATH" ]; then
  echo "[dpc] Pre-built binary not found: $BINARY_NAME"
  echo "      Build from source with: bash build/build.sh"
  exit 1
fi

# ── Make executable ──────────────────────────────────────────────────────────
chmod +x "$BINARY_PATH"
echo "[dpc] $BINARY_NAME marked executable."

# ── Symlink into ~/.local/bin ────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR"
ln -sf "$BINARY_PATH" "$INSTALL_DIR/dpc"
echo "[dpc] Linked -> $INSTALL_DIR/dpc"

# ── Ensure ~/.local/bin is in PATH (auto-add to shell profiles) ──────────────
ADDED_TO=""

for PROFILE in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
  # Only touch profiles that already exist
  [ -f "$PROFILE" ] || continue
  # Skip if the line is already there
  grep -qF '.local/bin' "$PROFILE" && continue
  echo "" >> "$PROFILE"
  echo "# Added by deepcrypt installer" >> "$PROFILE"
  echo "$PATH_LINE" >> "$PROFILE"
  ADDED_TO="$ADDED_TO $PROFILE"
done

# If no profile existed yet, create ~/.bashrc
if [ -z "$ADDED_TO" ] && ! echo ":${PATH}:" | grep -q ":${INSTALL_DIR}:"; then
  echo "" >> "$HOME/.bashrc"
  echo "# Added by deepcrypt installer" >> "$HOME/.bashrc"
  echo "$PATH_LINE" >> "$HOME/.bashrc"
  ADDED_TO=" $HOME/.bashrc"
fi

if [ -n "$ADDED_TO" ]; then
  echo "[dpc] Added \$HOME/.local/bin to PATH in:$ADDED_TO"
fi

# ── Apply PATH for the current session ──────────────────────────────────────
export PATH="$INSTALL_DIR:$PATH"

echo ""
echo "[dpc] Installation complete!"
echo ""
echo "  Run now (current shell):  $INSTALL_DIR/dpc --version"
echo "  After opening a new terminal:  dpc --version"
