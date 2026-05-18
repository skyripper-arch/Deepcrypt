#!/usr/bin/env bash
# install.sh — git-clone installer for Deepcrypt (dpc)
# Usage: bash install.sh
# No Node.js or npm required.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$SCRIPT_DIR/binaries"
INSTALL_DIR="$HOME/.local/bin"

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

# ── PATH check ───────────────────────────────────────────────────────────────
if ! echo ":${PATH}:" | grep -q ":${INSTALL_DIR}:"; then
  echo ""
  echo "[dpc] '$INSTALL_DIR' is not in your PATH."
  echo "      Add this line to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
  echo ""
  echo "        export PATH=\"\$HOME/.local/bin:\$PATH\""
  echo ""
  echo "      Then reload it:  source ~/.bashrc   (or open a new terminal)"
fi

echo ""
echo "[dpc] Installation complete. Run: dpc --version"
