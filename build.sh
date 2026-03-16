#!/usr/bin/env bash
# ============================================================
#  vless-diag Build Script (Linux / macOS / WSL)
#  Cross-compiles to Windows x64
#  Requires: Go 1.21+
# ============================================================

set -euo pipefail

echo ""
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║    vless-diag Build Script                   ║"
echo "  ║    Target: Windows AMD64                     ║"
echo "  ╚══════════════════════════════════════════════╝"
echo ""

# Check Go
if ! command -v go &>/dev/null; then
    echo "[ERROR] Go not found. Install from https://go.dev/dl/"
    exit 1
fi
echo "[INFO]  $(go version)"
echo ""

# Download deps
echo "[1/3] Downloading dependencies..."
go mod tidy

# Parse mode argument
MODE="${1:-}"

if [[ -z "$MODE" ]]; then
    echo "  Choose build mode:"
    echo "  [1] STANDARD  — sing-box auto-downloaded at runtime"
    echo "  [2] EMBEDDED  — sing-box baked into the .exe"
    echo ""
    read -rp "  Enter 1 or 2 [default: 1]: " MODE
    MODE="${MODE:-1}"
fi

if [[ "$MODE" == "2" || "$MODE" == "embedded" ]]; then
    # Embedded mode
    EMBED_PATH="internal/embedded/sing-box.exe"
    if [[ ! -f "$EMBED_PATH" ]]; then
        echo ""
        echo "[ERROR] $EMBED_PATH not found!"
        echo "        Download sing-box from:"
        echo "        https://github.com/SagerNet/sing-box/releases"
        echo "        Look for: sing-box-*-windows-amd64.zip → extract sing-box.exe"
        echo "        Place at: $EMBED_PATH"
        exit 1
    fi
    echo "[INFO]  Found embedded $(du -sh $EMBED_PATH | cut -f1) sing-box"
    echo "[2/3] Building EMBEDDED mode (single .exe with sing-box inside)..."
    GOOS=windows GOARCH=amd64 go build \
        -tags embed_singbox \
        -ldflags="-s -w -X main.buildMode=embedded" \
        -trimpath \
        -o vless-diag.exe .
    echo "[3/3] Done!"
    echo ""
    echo "  Output: vless-diag.exe ($(du -sh vless-diag.exe | cut -f1)) — fully self-contained"
else
    # Standard mode
    echo "[2/3] Building STANDARD mode..."
    GOOS=windows GOARCH=amd64 go build \
        -ldflags="-s -w -X main.buildMode=standard" \
        -trimpath \
        -o vless-diag.exe .
    echo "[3/3] Done!"
    echo ""
    echo "  Output: vless-diag.exe ($(du -sh vless-diag.exe | cut -f1))"
    echo "  Note:   sing-box auto-downloaded to %TEMP%\\vless-diag\\ on first run"
fi

echo ""
echo "  Usage:"
echo '    vless-diag.exe "vless://uuid@host:443?security=reality&..."'
echo ""
