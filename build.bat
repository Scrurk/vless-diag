@echo off
REM ============================================================
REM  vless-diag Build Script (Windows)
REM  Requires: Go 1.21+
REM ============================================================

setlocal enabledelayedexpansion

echo.
echo  ╔══════════════════════════════════════════════╗
echo  ║    vless-diag Build Script                   ║
echo  ╚══════════════════════════════════════════════╝
echo.

REM ── Check Go is installed ──────────────────────────────────
where go >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Go not found in PATH.
    echo         Download from: https://go.dev/dl/
    exit /b 1
)

for /f "tokens=*" %%v in ('go version') do echo [INFO]  %%v
echo.

REM ── Download dependencies ──────────────────────────────────
echo [1/3] Downloading dependencies...
go mod tidy
if errorlevel 1 goto :error

REM ── Ask build mode ─────────────────────────────────────────
echo.
echo  Choose build mode:
echo  [1] STANDARD  — sing-box auto-downloaded at runtime (no embedding)
echo  [2] EMBEDDED  — sing-box baked into the .exe (requires sing-box.exe in internal\embedded\)
echo.
set /p MODE="  Enter 1 or 2 [default: 1]: "
if "%MODE%"=="" set MODE=1

if "%MODE%"=="2" goto :build_embedded
goto :build_standard

:build_standard
echo.
echo [2/3] Building STANDARD mode...
set GOOS=windows
set GOARCH=amd64
go build -ldflags="-s -w -X main.buildMode=standard" -trimpath -o vless-diag.exe .
if errorlevel 1 goto :error
echo [3/3] Done!
echo.
echo  Output: vless-diag.exe
echo  Mode:   sing-box will be auto-downloaded on first run to:
echo          %%TEMP%%\vless-diag\sing-box.exe
goto :success

:build_embedded
echo.
if not exist "internal\embedded\sing-box.exe" (
    echo [ERROR] internal\embedded\sing-box.exe not found!
    echo         Download sing-box.exe from:
    echo         https://github.com/SagerNet/sing-box/releases
    echo         and place it at: internal\embedded\sing-box.exe
    exit /b 1
)
echo [INFO]  Found embedded sing-box.exe
echo [2/3] Building EMBEDDED mode (single .exe)...
set GOOS=windows
set GOARCH=amd64
go build -tags embed_singbox -ldflags="-s -w -X main.buildMode=embedded" -trimpath -o vless-diag.exe .
if errorlevel 1 goto :error
echo [3/3] Done!
echo.
echo  Output: vless-diag.exe
echo  Mode:   sing-box is embedded — fully self-contained!
goto :success

:success
echo.
for %%F in (vless-diag.exe) do echo  Size: %%~zF bytes
echo.
echo  Usage:
echo    vless-diag.exe "vless://uuid@host:443?security=reality&..."
echo.
exit /b 0

:error
echo.
echo [ERROR] Build failed!
exit /b 1
