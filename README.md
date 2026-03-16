# vless-diag

A diagnostic tool for VLESS proxy URIs. Runs a full health check on a VLESS key: protocol handshake analysis, network path inspection, performance measurement, DNS/IPv6 leak detection, and a security score.

Supports VLESS with **Reality**, **TLS**, **XTLS**, **WebSocket**, **gRPC**, and **HTTP/2** transports.

Available in two modes:
- **GUI** — browser-based interface, opens automatically
- **CLI** — terminal output with colored metrics

---

## Quick Start (pre-built binary)

### Windows

1. Download `vless-diag.exe` from [Releases](../../releases)
2. Double-click it — the GUI opens in your browser at `http://127.0.0.1:7878`
3. Paste a `vless://` URI and click **Scan**

Or use the CLI:

```
vless-diag.exe "vless://uuid@host:443?security=reality&sni=yahoo.com&pbk=...&sid=...&fp=chrome"
```

### Linux / macOS

```bash
chmod +x vless-diag
./vless-diag "vless://uuid@host:443?security=tls&sni=example.com&fp=chrome"
```

Or launch the GUI:

```bash
./vless-diag --gui
```

---

## sing-box Engine

vless-diag uses [sing-box](https://github.com/SagerNet/sing-box) internally to establish the proxy tunnel. It is located automatically in this order:

1. **Embedded** — if built with the `embed_singbox` tag (see below)
2. **Same directory** as `vless-diag.exe`
3. **Current working directory**
4. **System PATH**
5. **Cache** — `%TEMP%\vless-diag\sing-box.exe` (Windows) or `$TMPDIR/vless-diag/sing-box` (Linux/macOS)
6. **Auto-download** — fetched from [GitHub Releases](https://github.com/SagerNet/sing-box/releases) on first run and cached

If auto-download fails (e.g. no internet access on first run), manually place `sing-box.exe` next to `vless-diag.exe`.

---

## What Gets Checked

| Stage | What it measures |
|---|---|
| URI Breakdown | UUID, host, port, transport, security, SNI, fingerprint, Reality params |
| Protocol Health | DNS resolution time, TCP connect time, TLS/Reality handshake time, cipher suite, ALPN, certificate CN & expiry, uTLS fingerprint status, Reality config validity |
| Network Path | Local IP & interface, server IP geolocation (ISP, ASN, country), exit node IP, datacenter/proxy score |
| Performance | RTT average/min/max/jitter over 15 samples, packet loss, TTFB, download speed (peak & average) |
| Security & Leaks | DNS leak detection, SOCKS5 UDP ASSOCIATE support, IPv6 availability through tunnel |

---

## URI Format

Standard VLESS URI format:

```
vless://<uuid>@<host>:<port>?<params>#<remark>
```

### Supported parameters

| Parameter | Description |
|---|---|
| `type` | Transport: `tcp` (default), `ws`, `grpc`, `h2`, `quic` |
| `security` | `tls`, `reality`, `xtls`, `none` |
| `sni` | Server Name Indication |
| `fp` | uTLS fingerprint: `chrome`, `firefox`, `safari`, `ios`, `android`, `edge`, `random` |
| `pbk` | Reality public key |
| `sid` | Reality short ID |
| `spx` | Reality SpiderX path |
| `alpn` | ALPN protocols, comma-separated (e.g. `h2,http/1.1`) |
| `path` | WebSocket path or gRPC service name |
| `host` | WebSocket Host header override |
| `flow` | XTLS flow (e.g. `xtls-rprx-vision`) |
| `allowInsecure` | `1` or `true` — skip TLS certificate verification |

### Example URIs

**VLESS + Reality:**
```
vless://de1362cf-dfdf-4ded-8597-1e9a3097de45@192.0.2.1:443?type=tcp&security=reality&sni=yahoo.com&pbk=AbCdEfGh...&sid=5f5607&fp=random#my-server
```

**VLESS + TLS + WebSocket:**
```
vless://de1362cf-dfdf-4ded-8597-1e9a3097de45@192.0.2.1:443?type=ws&security=tls&sni=example.com&path=/ws&fp=chrome#my-server
```

**VLESS + TLS + gRPC:**
```
vless://de1362cf-dfdf-4ded-8597-1e9a3097de45@192.0.2.1:443?type=grpc&security=tls&sni=example.com&serviceName=myservice&fp=firefox
```

---

## Building from Source

### Prerequisites

- [Go 1.21+](https://go.dev/dl/)
- Git

### Clone and build

```bash
git clone https://github.com/yourname/vless-diag
cd vless-diag
go build -o vless-diag .
```

On Windows:

```cmd
go build -o vless-diag.exe .
```

### Build with embedded sing-box (single self-contained binary)

This produces one `.exe` that needs no internet access on first run.

1. Download `sing-box.exe` for your platform from [sing-box Releases](https://github.com/SagerNet/sing-box/releases)
2. Place it at `internal/embedded/sing-box.exe`
3. Build with the `embed_singbox` tag:

```bash
go build -tags embed_singbox -o vless-diag.exe .
```

> **Note:** The embedded binary adds ~20–30 MB to the output file size.

### Cross-compile

```bash
# Windows amd64 from Linux/macOS
GOOS=windows GOARCH=amd64 go build -o vless-diag.exe .

# Linux amd64
GOOS=linux GOARCH=amd64 go build -o vless-diag-linux .

# macOS arm64
GOOS=darwin GOARCH=arm64 go build -o vless-diag-macos .
```

---

## Project Structure

```
vless-diag/
├── main.go                           Entry point, CLI/GUI routing
├── internal/
│   ├── cli/         cli.go           CLI runner and output formatting
│   ├── gui/
│   │   ├── server.go                HTTP server, WebSocket hub, Sink
│   │   ├── runner.go                GUI diagnostic runner
│   │   ├── websocket.go             WebSocket framing (no external deps)
│   │   └── static/index.html        Single-file web UI
│   ├── parser/      parser.go        VLESS URI parser
│   ├── probes/
│   │   ├── protocol.go              Direct TLS/Reality handshake probe
│   │   ├── network_path.go          IP geolocation, exit node detection
│   │   ├── performance.go           RTT latency, speed test
│   │   └── leaks.go                 DNS leak, UDP, IPv6 tests
│   ├── manager/     manager.go       sing-box lifecycle management
│   ├── downloader/  downloader.go    sing-box auto-download from GitHub
│   ├── socks5dialer/dialer.go        SOCKS5 HTTP client with local DNS
│   ├── embedded/                    Optional sing-box binary embedding
│   └── ui/          ui.go           CLI colored output helpers
```

---

## Troubleshooting

**`Failed to start sing-box: config validation failed`**
sing-box version mismatch. Delete the cache (`%TEMP%\vless-diag\` on Windows, `$TMPDIR/vless-diag/` on Linux/macOS) and restart — it will re-download the latest version.

**`Port 10808 is already in use`**
Another VPN or proxy client (Clash, Nekoray, v2ray) is running on port 10808. Close it and retry.

**`Permission denied` on Linux/macOS**
Run `chmod +x vless-diag` or run with `sudo` if the binary needs to bind low-numbered ports.

**`Cannot obtain sing-box: auto-download failed`**
Manually download `sing-box` from [github.com/SagerNet/sing-box/releases](https://github.com/SagerNet/sing-box/releases) and place it next to `vless-diag`.

**TLS/Reality Handshake shows `POOR` (1000+ ms)**
Expected for Reality — the probe measures a raw TLS handshake directly to the server port, which Reality intentionally slows down for non-Reality clients. The actual tunnel latency shown in the Performance section is the meaningful number.

**GUI doesn't open automatically**
Navigate manually to `http://127.0.0.1:7878` in your browser.

---

## Dependencies

| Package | Purpose |
|---|---|
| `golang.org/x/net/proxy` | SOCKS5 dialer |
| `github.com/fatih/color` | Terminal colors (CLI mode) |
| `github.com/mattn/go-colorable` | Windows console color support |

sing-box is a **runtime** dependency, not a Go module dependency — it is either embedded at build time or downloaded automatically at runtime.

---

## License

MIT
