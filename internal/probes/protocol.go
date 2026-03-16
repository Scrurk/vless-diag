package probes

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"vless-diag/internal/parser"
)

type HandshakeTimings struct {
	DNSResolutionMs  float64
	TCPConnectMs     float64
	TLSHandshakeMs   float64
	TotalMs          float64
}

type ProtocolHealth struct {
	Timings         HandshakeTimings
	NegotiatedALPN  string
	CipherSuite     string
	TLSVersion      string
	ServerCert      string
	CertExpiry      string
	UTLSMatch       string
	RealityValid    bool
	SNIReachable    bool
	SNIStatusCode   int
	ShortIDPresent  bool
	Error           string
}

func ProbeProtocol(cfg *parser.VLESSConfig) (*ProtocolHealth, error) {
	ph := &ProtocolHealth{}

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)

	dnsStart := time.Now()
	ips, err := net.LookupHost(cfg.Host)
	ph.Timings.DNSResolutionMs = float64(time.Since(dnsStart).Milliseconds())
	if err != nil {
		ph.Error = fmt.Sprintf("DNS failed: %v", err)
		return ph, nil
	}
	_ = ips

	tcpStart := time.Now()
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.Dial("tcp", addr)
	ph.Timings.TCPConnectMs = float64(time.Since(tcpStart).Milliseconds())
	if err != nil {
		ph.Error = fmt.Sprintf("TCP connect failed: %v", err)
		return ph, nil
	}
	defer conn.Close()

	sni := cfg.SNI
	if sni == "" {
		sni = cfg.Host
	}

	tlsConf := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}

	if len(cfg.ALPN) > 0 {
		tlsConf.NextProtos = cfg.ALPN
	} else {
		tlsConf.NextProtos = []string{"h2", "http/1.1"}
	}

	tlsStart := time.Now()
	tlsConn := tls.Client(conn, tlsConf)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = tlsConn.HandshakeContext(ctx)
	ph.Timings.TLSHandshakeMs = float64(time.Since(tlsStart).Milliseconds())
	ph.Timings.TotalMs = ph.Timings.DNSResolutionMs + ph.Timings.TCPConnectMs + ph.Timings.TLSHandshakeMs

	if err != nil {
		ph.Error = fmt.Sprintf("TLS handshake note: %v", err)
		if cfg.Security == "reality" {
			ph.RealityValid = true
		}
	} else {
		state := tlsConn.ConnectionState()
		ph.NegotiatedALPN = state.NegotiatedProtocol
		ph.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
		ph.TLSVersion = tlsVersionName(state.Version)

		if len(state.PeerCertificates) > 0 {
			cert := state.PeerCertificates[0]
			ph.ServerCert = cert.Subject.CommonName
			ph.CertExpiry = cert.NotAfter.Format("2006-01-02")
		}
	}

	fp := cfg.Fingerprint
	if fp == "" {
		fp = "none"
		ph.UTLSMatch = "No uTLS configured (using Go stdlib TLS)"
	} else {
		knownFingerprints := map[string]string{
			"chrome":           "Chrome",
			"firefox":          "Firefox",
			"safari":           "Safari",
			"ios":              "iOS Safari",
			"android":          "Android Chrome",
			"edge":             "Edge",
			"randomized":       "Randomized",
			"random":           "Random",
			"chrome_auto":      "Chrome Auto",
		}
		if name, ok := knownFingerprints[strings.ToLower(fp)]; ok {
			ph.UTLSMatch = fmt.Sprintf("uTLS active — mimicking %s browser fingerprint", name)
		} else {
			ph.UTLSMatch = fmt.Sprintf("uTLS fingerprint: %s", fp)
		}
	}

	if cfg.Security == "reality" && sni != "" {
		ph.SNIReachable, ph.SNIStatusCode = checkSNIReachability(sni)
		ph.ShortIDPresent = cfg.ShortID != ""
		ph.RealityValid = ph.SNIReachable && ph.ShortIDPresent && cfg.PublicKey != ""
	}

	return ph, nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", v)
	}
}

func checkSNIReachability(sni string) (reachable bool, statusCode int) {
	client := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
				ServerName:         sni,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get("https://" + sni)
	if err != nil {
		return false, 0
	}
	defer resp.Body.Close()
	return true, resp.StatusCode
}
