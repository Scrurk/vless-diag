package manager

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"vless-diag/internal/parser"
	"vless-diag/internal/ui"
)

type SingBox struct {
	ExePath    string
	ConfigPath string
	cmd        *exec.Cmd
	cancel     context.CancelFunc
	LocalPort  int
	stderrBuf  bytes.Buffer
}

func New(exePath string, localPort int) *SingBox {
	return &SingBox{
		ExePath:   exePath,
		LocalPort: localPort,
	}
}

func (s *SingBox) Start(cfg *parser.VLESSConfig) error {
	if conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", s.LocalPort), 300*time.Millisecond); err == nil {
		conn.Close()
		return fmt.Errorf("port %d is already in use — close any running VPN/proxy software and retry", s.LocalPort)
	}

	sbCfg, err := buildConfig(cfg, s.LocalPort)
	if err != nil {
		return fmt.Errorf("build config: %w", err)
	}

	data, err := json.MarshalIndent(sbCfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	tmpDir := os.TempDir()
	s.ConfigPath = filepath.Join(tmpDir, fmt.Sprintf("vless-diag-%d.json", time.Now().UnixNano()))
	if err := os.WriteFile(s.ConfigPath, data, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	ui.PrintProgress(fmt.Sprintf("Config written to %s", s.ConfigPath))

	if checkErr := s.validateConfig(); checkErr != nil {
		_ = os.Remove(s.ConfigPath)
		return fmt.Errorf("config validation failed:\n%s", checkErr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.stderrBuf.Reset()

	s.cmd = exec.CommandContext(ctx, s.ExePath, "run", "-c", s.ConfigPath)
	s.cmd.Stdout = nil
	s.cmd.Stderr = &s.stderrBuf

	if err := s.cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("start sing-box: %w", err)
	}
	ui.PrintProgress(fmt.Sprintf("sing-box started (PID %d)", s.cmd.Process.Pid))

	exitCh := make(chan error, 1)
	go func() { exitCh <- s.cmd.Wait() }()

	deadline := time.Now().Add(15 * time.Second)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	for time.Now().Before(deadline) {
		select {
		case exitErr := <-exitCh:
			_ = os.Remove(s.ConfigPath)
			s.ConfigPath = ""
			stderr := strings.TrimSpace(s.stderrBuf.String())
			hint := diagnoseStderr(stderr)
			msg := "sing-box exited immediately"
			if exitErr != nil {
				msg += fmt.Sprintf(" (%v)", exitErr)
			}
			if stderr != "" {
				msg += fmt.Sprintf("\n\n  sing-box output:\n%s", indentLines(stderr, "    "))
			}
			if hint != "" {
				msg += fmt.Sprintf("\n\n  Hint: %s", hint)
			}
			cancel()
			return fmt.Errorf("%s", msg)

		case <-ticker.C:
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", s.LocalPort), 200*time.Millisecond)
			if err == nil {
				conn.Close()
				ui.PrintOK(fmt.Sprintf("SOCKS5 proxy ready on 127.0.0.1:%d", s.LocalPort))
				return nil
			}
		}
	}

	s.Stop()
	stderr := strings.TrimSpace(s.stderrBuf.String())
	msg := "sing-box did not open port within 15 seconds"
	if stderr != "" {
		msg += fmt.Sprintf("\n\n  sing-box output:\n%s", indentLines(stderr, "    "))
		if hint := diagnoseStderr(stderr); hint != "" {
			msg += fmt.Sprintf("\n\n  Hint: %s", hint)
		}
	}
	return fmt.Errorf("%s", msg)
}

func (s *SingBox) validateConfig() error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.ExePath, "check", "-c", s.ConfigPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		output := strings.TrimSpace(string(out))
		if output == "" {
			output = err.Error()
		}
		return fmt.Errorf("%s", output)
	}
	return nil
}

func (s *SingBox) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		_ = s.cmd.Wait()
	}
	if s.ConfigPath != "" {
		_ = os.Remove(s.ConfigPath)
		s.ConfigPath = ""
	}
}

func diagnoseStderr(stderr string) string {
	lower := strings.ToLower(stderr)
	switch {
	case strings.Contains(lower, "address already in use") ||
		strings.Contains(lower, "bind: only one usage"):
		return "Port 10808 is occupied. Close any VPN/proxy app (Clash, Nekoray, v2ray) and retry."
	case strings.Contains(lower, "unknown field") ||
		strings.Contains(lower, "cannot unmarshal"):
		return "Config schema error — possible sing-box version mismatch. Delete cache and re-download sing-box."
	case strings.Contains(lower, "flow") && strings.Contains(lower, "not supported"):
		return "The 'flow' value in your URI is not supported by this sing-box build."
	case strings.Contains(lower, "permission denied"):
		return "sing-box blocked by Windows/antivirus. Try running as Administrator."
	case strings.Contains(lower, "certificate") || strings.Contains(lower, "tls handshake"):
		return "TLS issue — check SNI setting in your URI."
	}
	return ""
}

func indentLines(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}

func buildConfig(cfg *parser.VLESSConfig, localPort int) (map[string]interface{}, error) {
	outbound := buildOutbound(cfg)

	inbound := map[string]interface{}{
		"type":        "socks",
		"tag":         "socks-in",
		"listen":      "127.0.0.1",
		"listen_port": localPort,
	}

	return map[string]interface{}{
		"log": map[string]interface{}{
			"level": "info",
		},
		"inbounds":  []interface{}{inbound},
		"outbounds": []interface{}{outbound},
		"route": map[string]interface{}{
			"final": "vless-out",
		},
	}, nil
}

func buildOutbound(cfg *parser.VLESSConfig) map[string]interface{} {
	out := map[string]interface{}{
		"type":        "vless",
		"tag":         "vless-out",
		"server":      cfg.Host,
		"server_port": cfg.Port,
		"uuid":        cfg.UUID,
	}

	if cfg.Flow != "" {
		out["flow"] = cfg.Flow
	}

	if cfg.Network == "tcp" || cfg.Network == "" {
		out["packet_encoding"] = "xudp"
	}

	switch cfg.Network {
	case "ws":
		transport := map[string]interface{}{
			"type": "ws",
		}
		if cfg.Path != "" {
			transport["path"] = cfg.Path
		}
		hostHeader := cfg.Host_Header
		if hostHeader == "" {
			hostHeader = cfg.SNI
		}
		if hostHeader == "" {
			hostHeader = cfg.Host
		}
		transport["headers"] = map[string]interface{}{
			"Host": hostHeader,
		}
		out["transport"] = transport

	case "grpc":
		transport := map[string]interface{}{
			"type": "grpc",
		}
		if cfg.Path != "" {
			transport["service_name"] = cfg.Path
		}
		out["transport"] = transport

	case "h2", "http":
		transport := map[string]interface{}{
			"type": "http",
		}
		if cfg.Path != "" {
			transport["path"] = cfg.Path
		}
		if cfg.Host_Header != "" {
			transport["host"] = []string{cfg.Host_Header}
		}
		out["transport"] = transport

	case "quic":
		out["transport"] = map[string]interface{}{"type": "quic"}
	}

	switch cfg.Security {
	case "tls":
		tlsCfg := map[string]interface{}{
			"enabled":  true,
			"insecure": cfg.AllowInsecure,
		}
		if cfg.SNI != "" {
			tlsCfg["server_name"] = cfg.SNI
		}
		if cfg.Fingerprint != "" {
			tlsCfg["utls"] = map[string]interface{}{
				"enabled":     true,
				"fingerprint": cfg.Fingerprint,
			}
		}
		if len(cfg.ALPN) > 0 {
			tlsCfg["alpn"] = cfg.ALPN
		}
		out["tls"] = tlsCfg

	case "reality":
		fp := cfg.Fingerprint
		if fp == "" {
			fp = "chrome"
		}
		realityCfg := map[string]interface{}{
			"enabled": true,
			"utls": map[string]interface{}{
				"enabled":     true,
				"fingerprint": fp,
			},
			"reality": map[string]interface{}{
				"enabled":    true,
				"public_key": cfg.PublicKey,
				"short_id":   cfg.ShortID,
			},
		}
		if cfg.SNI != "" {
			realityCfg["server_name"] = cfg.SNI
		}
		out["tls"] = realityCfg

	case "xtls":
		tlsCfg := map[string]interface{}{
			"enabled":  true,
			"insecure": cfg.AllowInsecure,
		}
		if cfg.SNI != "" {
			tlsCfg["server_name"] = cfg.SNI
		}
		out["tls"] = tlsCfg
	}

	return out
}
