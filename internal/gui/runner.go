package gui

import (
	"fmt"
	"strings"
	"time"

	"vless-diag/internal/downloader"
	"vless-diag/internal/manager"
	"vless-diag/internal/parser"
	"vless-diag/internal/probes"
)

const localProxyPort = 10808

func Run(rawURI, singboxPath string, sink *Sink) error {
	startTime := time.Now()

	sink.Step(0, 0, "Locating sing-box engine")
	if singboxPath == "" {
		path, cleanup, err := downloader.EnsureSingBox(nil)
		if err != nil {
			return fmt.Errorf("cannot obtain sing-box: %w", err)
		}
		defer cleanup()
		singboxPath = path
		sink.OK(fmt.Sprintf("sing-box ready: %s", singboxPath))
	} else {
		sink.OK(fmt.Sprintf("Using sing-box: %s", singboxPath))
	}

	sink.Step(1, 6, "Parsing VLESS URI")
	cfg, err := parser.Parse(rawURI)
	if err != nil {
		return fmt.Errorf("URI parse error: %w", err)
	}
	sink.OK(cfg.Describe())

	sink.Section("URI BREAKDOWN")
	sink.Field("UUID", maskUUID(cfg.UUID), "neutral")
	sink.Field("Server", fmt.Sprintf("%s:%d", cfg.Host, cfg.Port), "info")
	sink.Field("Security", strings.ToUpper(cfg.Security), securityStatus(cfg.Security))
	sink.Field("Transport", strings.ToUpper(cfg.Network), "neutral")
	if cfg.SNI != "" {
		sink.Field("SNI", cfg.SNI, "neutral")
	}
	if cfg.Fingerprint != "" {
		sink.Field("uTLS Fingerprint", cfg.Fingerprint, "ok")
	}
	if cfg.Flow != "" {
		sink.Field("Flow (XTLS)", cfg.Flow, "neutral")
	}
	if cfg.PublicKey != "" {
		sink.Field("Reality Public Key", cfg.PublicKey[:min(16, len(cfg.PublicKey))]+"...", "neutral")
	}
	if cfg.ShortID != "" {
		sink.Field("Reality Short ID", cfg.ShortID, "neutral")
	}
	if len(cfg.ALPN) > 0 {
		sink.Field("ALPN", strings.Join(cfg.ALPN, ", "), "neutral")
	}
	if cfg.Remark != "" {
		sink.Field("Remark", cfg.Remark, "neutral")
	}

	sink.Step(2, 6, "Protocol Handshake Analysis")
	ph, err := probes.ProbeProtocol(cfg)
	if err != nil {
		sink.Warn(fmt.Sprintf("Protocol probe: %v", err))
	}

	sink.Section("PROTOCOL HEALTH")
	sink.SubSection("Handshake Timings")
	sink.LatBar("DNS Resolution", ph.Timings.DNSResolutionMs)
	sink.LatBar("TCP Connect", ph.Timings.TCPConnectMs)
	if ph.Timings.TLSHandshakeMs > 0 {
		sink.LatBar("TLS/Reality Handshake", ph.Timings.TLSHandshakeMs)
	} else {
		sink.Field("TLS/Reality Handshake", "N/A (Reality)", "info")
	}
	totalMs := ph.Timings.DNSResolutionMs + ph.Timings.TCPConnectMs + ph.Timings.TLSHandshakeMs
	sink.Metric("Total Connection Time", fmt.Sprintf("%.1f", totalMs), "ms", latQuality(totalMs), totalMs)

	sink.SubSection("Transport Details")
	if ph.NegotiatedALPN != "" {
		sink.Field("Negotiated ALPN", ph.NegotiatedALPN, "ok")
	}
	if ph.CipherSuite != "" {
		sink.Field("Cipher Suite", ph.CipherSuite, "ok")
	}
	if ph.TLSVersion != "" {
		sink.Field("TLS Version", ph.TLSVersion, tlsVersionStatus(ph.TLSVersion))
	}
	if ph.ServerCert != "" {
		sink.Field("Server Certificate CN", ph.ServerCert, "info")
		sink.Field("Certificate Expiry", ph.CertExpiry, "info")
	}

	sink.SubSection("Fingerprint & Reality")
	if ph.UTLSMatch != "" {
		st := "ok"
		if strings.Contains(ph.UTLSMatch, "No uTLS") {
			st = "warn"
		}
		sink.Field("uTLS Status", ph.UTLSMatch, st)
	}
	if cfg.Security == "reality" {
		sink.Field("SNI Reachability", sniStr(ph.SNIReachable, ph.SNIStatusCode), boolStatus(ph.SNIReachable))
		sink.Field("Short ID Present", boolStr(ph.ShortIDPresent), boolStatus(ph.ShortIDPresent))
		sink.Field("Public Key Set", boolStr(cfg.PublicKey != ""), boolStatus(cfg.PublicKey != ""))
		sink.Field("Reality Config Valid", boolStr(ph.RealityValid), boolStatus(ph.RealityValid))
	}

	sink.Step(3, 6, "Starting sing-box proxy tunnel")
	sbManager := manager.New(singboxPath, localProxyPort)
	if err := sbManager.Start(cfg); err != nil {
		sink.Error(fmt.Sprintf("Failed to start sing-box: %v", err))
		sink.Warn("Skipping proxy-dependent tests")
		calcAndSendSummary(sink, cfg, ph, nil, nil, nil, startTime)
		sink.Done()
		return nil
	}
	defer func() {
		sink.Progress("Stopping sing-box...")
		sbManager.Stop()
	}()

	time.Sleep(500 * time.Millisecond)

	sink.Step(4, 6, "Network Path Analysis")
	np, err := probes.ProbeNetworkPath(cfg.Host, localProxyPort)
	if err != nil {
		sink.Warn(fmt.Sprintf("Network path: %v", err))
	}

	sink.Section("NETWORK PATH")
	sink.SubSection("Local Entry Point")
	sink.Field("Local IP", np.LocalIP, "neutral")
	sink.Field("Network Interface", np.LocalInterface, "neutral")

	sink.SubSection("Proxy Endpoint (Server)")
	sink.Field("Server IP", np.ServerIP, "info")
	if np.ServerInfo.ISP != "" {
		sink.Field("ISP / Provider", np.ServerInfo.ISP, "neutral")
	}
	if np.ServerInfo.ASN != "" {
		sink.Field("ASN", np.ServerInfo.ASN, "neutral")
	}
	if np.ServerInfo.Country != "" {
		sink.Field("Location", fmt.Sprintf("%s, %s [%s]", np.ServerInfo.City, np.ServerInfo.Country, np.ServerInfo.CountryCode), "neutral")
	}
	if np.DNSResolvMs == 0 {
		sink.Field("DNS Resolution", "< 1 ms (cached)", "ok")
	} else {
		sink.Metric("DNS Resolution", fmt.Sprintf("%.0f", np.DNSResolvMs), "ms", latQuality(np.DNSResolvMs), np.DNSResolvMs)
	}

	sink.SubSection("Exit Node (Your visible IP)")
	if np.ExitInfo.IP != "" {
		sink.Field("Exit IP", np.ExitInfo.IP, "ok")
		sink.Field("Country", fmt.Sprintf("%s, %s [%s]", np.ExitInfo.City, np.ExitInfo.Country, np.ExitInfo.CountryCode), "neutral")
		sink.Field("Timezone", np.ExitInfo.Timezone, "neutral")
		sink.Field("ISP / Org", np.ExitInfo.ISP, "neutral")
		sink.Field("ASN", np.ExitInfo.ASN, "neutral")
		psStatus := proxyScoreStatus(np.ExitInfo.ProxyScore)
		sink.Field("Datacenter/VPN Score", fmt.Sprintf("%d/100", np.ExitInfo.ProxyScore), psStatus)
		sink.Field("Flagged as Proxy", boolStr(np.ExitInfo.Proxy), invertBool(np.ExitInfo.Proxy))
		sink.Field("Flagged as Hosting", boolStr(np.ExitInfo.Hosting), invertBool(np.ExitInfo.Hosting))
	} else {
		sink.Field("Exit IP", "Could not determine", "warn")
	}

	sink.Step(5, 6, "Performance Measurement")
	perf, perfErr := probes.ProbePerformance(localProxyPort)
	if perfErr != nil {
		sink.Warn(fmt.Sprintf("Performance: %v", perfErr))
	}

	sink.Section("PERFORMANCE METRICS")
	sampleLabel := fmt.Sprintf("%d samples", len(perf.Latency.Samples))
	if perf.Latency.Endpoint != "" {
		sampleLabel += " · " + perf.Latency.Endpoint
	}
	sink.SubSection("Latency (RTT) — " + sampleLabel)
	if len(perf.Latency.Samples) > 0 {
		sink.LatBar("Average RTT", perf.Latency.Avg)
		sink.LatBar("Minimum RTT", perf.Latency.Min)
		sink.LatBar("Maximum RTT", perf.Latency.Max)
		sink.Metric("Jitter", fmt.Sprintf("%.1f", perf.Latency.Jitter), "ms", jitterQuality(perf.Latency.Jitter), perf.Latency.Jitter)
		sink.Metric("Packet Loss", fmt.Sprintf("%.1f", perf.Latency.PacketLoss), "%", lossQuality(perf.Latency.PacketLoss), perf.Latency.PacketLoss)
	} else {
		sink.Field("RTT", "No samples", "warn")
	}

	if perf.MTUEstimate > 0 {
		sink.SubSection("TCP / MTU")
		sink.Field("Estimated Effective MTU", fmt.Sprintf("%d bytes", perf.MTUEstimate), "info")
	}

	sink.SubSection("Speed Test")
	if perf.Speed.AvgMbps > 0 {
		sink.Metric("TTFB", fmt.Sprintf("%.0f", perf.Speed.TTFBMs), "ms", ttfbQuality(perf.Speed.TTFBMs), perf.Speed.TTFBMs)
		sink.SpeedBar("Peak Speed", perf.Speed.PeakMbps)
		sink.SpeedBar("Average Speed", perf.Speed.AvgMbps)
		sink.Metric("Data Transferred", fmt.Sprintf("%.2f", float64(perf.Speed.BytesTested)/1024/1024), "MB", "na", 0)
		sink.Metric("Test Duration", fmt.Sprintf("%.1f", perf.Speed.DurationSec), "s", "na", 0)
	} else if perf.SpeedError != "" {
		sink.Field("Speed Test", "Failed", "warn")
		for _, line := range strings.Split(perf.SpeedError, "\n") {
			if l := strings.TrimSpace(line); l != "" {
				sink.Progress(l)
			}
		}
	} else {
		sink.Field("Speed Test", "No data", "warn")
	}

	sink.Step(6, 6, "Security & Leak Tests")
	leaks, err := probes.ProbeLeaks(localProxyPort)
	if err != nil {
		sink.Warn(fmt.Sprintf("Leak tests: %v", err))
	}

	sink.Section("SECURITY & LEAK ANALYSIS")
	sink.SubSection("DNS Leak Test")
	if len(leaks.DNSServersProxy) > 0 {
		limit := leaks.DNSServersProxy
		if len(limit) > 3 {
			limit = limit[:3]
		}
		sink.Field("Exit Resolver IP(s)", strings.Join(limit, ", "), "info")
	}
	if len(leaks.DNSServersDirect) > 0 && leaks.DNSServersDirect[0] != "unknown" {
		limit := leaks.DNSServersDirect
		if len(limit) > 3 {
			limit = limit[:3]
		}
		sink.Field("Local IP (direct)", strings.Join(limit, ", "), "info")
	}
	if leaks.DNSLeakDetected {
		sink.Field("DNS Leak Status", "LEAK DETECTED — "+leaks.DNSLeakDetail, "fail")
	} else {
		sink.Field("DNS Leak Status", leaks.DNSLeakDetail, "ok")
	}

	sink.SubSection("UDP Support")
	udpSt := "ok"
	if !leaks.UDPSupported {
		udpSt = "warn"
	}
	sink.Field("UDP Connectivity", leaks.UDPDetail, udpSt)

	sink.SubSection("IPv6 Readiness")
	ipv6St := "ok"
	if !leaks.IPv6Supported {
		ipv6St = "info"
	}
	if leaks.IPv6Address != "" {
		sink.Field("IPv6 Address", leaks.IPv6Address, ipv6St)
	}
	sink.Field("IPv6 Status", leaks.IPv6Detail, ipv6St)

	calcAndSendSummary(sink, cfg, ph, np, perf, leaks, startTime)
	sink.Done()
	return nil
}

func calcAndSendSummary(
	sink *Sink,
	cfg *parser.VLESSConfig,
	ph *probes.ProtocolHealth,
	np *probes.NetworkPath,
	perf *probes.PerformanceResult,
	leaks *probes.LeakTestResult,
	start time.Time,
) {
	score := 100
	var issues []string

	if cfg.Security == "none" {
		score -= 25
		issues = append(issues, "No encryption configured (security=none)")
	}
	if cfg.Fingerprint == "" && (cfg.Security == "tls" || cfg.Security == "reality") {
		score -= 5
		issues = append(issues, "uTLS fingerprint not set — Go default TLS fingerprint may be detected")
	}
	if cfg.Security == "reality" {
		if !ph.SNIReachable {
			score -= 15
			issues = append(issues, "Reality SNI target not reachable")
		}
		if cfg.PublicKey == "" {
			score -= 20
			issues = append(issues, "Reality public key missing")
		}
	}
	if cfg.AllowInsecure {
		score -= 10
		issues = append(issues, "allowInsecure=true — vulnerable to MITM")
	}
	if perf != nil {
		if perf.Latency.Avg > 300 {
			score -= 15
			issues = append(issues, fmt.Sprintf("High latency: avg %.0f ms", perf.Latency.Avg))
		} else if perf.Latency.Avg > 150 {
			score -= 7
		}
		if perf.Latency.Jitter > 50 {
			score -= 10
			issues = append(issues, fmt.Sprintf("High jitter: %.0f ms", perf.Latency.Jitter))
		}
		if perf.Latency.PacketLoss > 5 {
			score -= 15
			issues = append(issues, fmt.Sprintf("Packet loss: %.1f%%", perf.Latency.PacketLoss))
		}
	}
	if leaks != nil && leaks.DNSLeakDetected {
		score -= 20
		issues = append(issues, "DNS leak detected")
	}
	if np != nil && np.ExitInfo.ProxyScore > 70 {
		score -= 5
		issues = append(issues, fmt.Sprintf("Exit IP has high datacenter score (%d/100)", np.ExitInfo.ProxyScore))
	}
	if score < 0 {
		score = 0
	}

	verdict := ""
	switch {
	case score >= 90:
		verdict = "EXCELLENT — Channel is clean, fast, and well-hidden"
	case score >= 75:
		verdict = "GOOD — Minor issues detected, usable for most tasks"
	case score >= 55:
		verdict = "FAIR — Noticeable degradation or exposure risks"
	case score >= 35:
		verdict = "POOR — Significant problems, use with caution"
	default:
		verdict = "CRITICAL — Severe issues, channel unreliable or exposed"
	}

	elapsed := time.Since(start)
	sink.Progress(fmt.Sprintf("Scan completed in %.1f seconds", elapsed.Seconds()))
	sink.Summary(score, verdict, issues)
}

func maskUUID(uuid string) string {
	if len(uuid) < 8 {
		return "****"
	}
	return uuid[:8] + "-****-****-****-" + uuid[len(uuid)-12:]
}

func boolStr(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

func boolStatus(b bool) string {
	if b {
		return "ok"
	}
	return "warn"
}

func invertBool(b bool) string {
	if b {
		return "warn"
	}
	return "ok"
}

func securityStatus(sec string) string {
	switch sec {
	case "reality", "tls", "xtls":
		return "ok"
	case "none":
		return "fail"
	default:
		return "warn"
	}
}

func sniStr(reachable bool, code int) string {
	if reachable {
		return fmt.Sprintf("Reachable (HTTP %d)", code)
	}
	return "Not reachable"
}

func tlsVersionStatus(ver string) string {
	if strings.Contains(ver, "1.3") || strings.Contains(ver, "1.2") {
		return "ok"
	}
	return "warn"
}

func proxyScoreStatus(score int) string {
	if score < 30 {
		return "ok"
	}
	if score < 60 {
		return "warn"
	}
	return "fail"
}

func latQuality(ms float64) string {
	switch {
	case ms < 50:
		return "excellent"
	case ms < 150:
		return "good"
	case ms < 300:
		return "fair"
	default:
		return "poor"
	}
}

func ttfbQuality(ms float64) string {
	switch {
	case ms < 200:
		return "excellent"
	case ms < 500:
		return "good"
	case ms < 1000:
		return "fair"
	default:
		return "poor"
	}
}

func jitterQuality(ms float64) string {
	switch {
	case ms < 10:
		return "excellent"
	case ms < 30:
		return "good"
	case ms < 60:
		return "fair"
	default:
		return "poor"
	}
}

func lossQuality(pct float64) string {
	switch {
	case pct == 0:
		return "excellent"
	case pct < 1:
		return "good"
	case pct < 5:
		return "fair"
	default:
		return "poor"
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
