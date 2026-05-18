#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
GO_DIR="$ROOT_DIR/go-core"
OUT_DIR="$ROOT_DIR/binaries"

mkdir -p "$OUT_DIR"
LDFLAGS="-s -w"

# Format: GOOS GOARCH GOARM(or-) NAME
targets=(
  "linux   amd64  -  dpc-linux-amd64"
  "linux   arm64  -  dpc-linux-arm64"
  "linux   arm    7  dpc-linux-arm"       # Termux 32-bit ARM
  "darwin  amd64  -  dpc-darwin-amd64"
  "darwin  arm64  -  dpc-darwin-arm64"
  "windows amd64  -  dpc-win-amd64.exe"
  "windows arm64  -  dpc-win-arm64.exe"
)

echo "==> Building Deepcrypt (dpc) Go core"
cd "$GO_DIR"
go mod download

for entry in "${targets[@]}"; do
  read -r goos goarch goarm name <<< "$entry"
  printf "    %-10s %-6s -> %s\n" "$goos" "$goarch" "$name"
  arm_env=""
  if [ "$goarm" != "-" ]; then
    arm_env="GOARM=$goarm"
  fi
  env GOOS="$goos" GOARCH="$goarch" $arm_env \
    go build -ldflags="$LDFLAGS" -trimpath -o "$OUT_DIR/$name" .
done

echo "==> Done. Binaries in $OUT_DIR"
