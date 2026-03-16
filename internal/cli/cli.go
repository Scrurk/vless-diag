package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
	"vless-diag/internal/manager"
	"vless-diag/internal/parser"
	"vless-diag/internal/probes"
	"vless-diag/internal/ui"
)

const localProxyPort = 10808

func Run(rawURI, singboxPath string) error {
	startTime := time.Now()

	ui.PrintStep(1, 6, "Parsing VLESS URI")

	cfg, err := parser.Parse(rawURI)
	if err != nil {
		return fmt.Errorf("URI parse error: %w", err)
	}
	ui.PrintOK(cfg.Describe())

	ui.PrintSection("URI BREAKDOWN")
	ui.PrintField("UUID", maskUUID(cfg.UUID), ui.StatusNeutral)
	ui.PrintField("Server", fmt.Sprintf("%s:%d", cfg.Host, cfg.Port), ui.StatusInfo)
	ui.PrintField("Security", strings.ToUpper(cfg.Security), securityStatus(cfg.Security))
	ui.PrintField("Transport", strings.ToUpper(cfg.Network), ui.StatusNeutral)
	if cfg.SNI != "" {
		ui.PrintField("SNI", cfg.SNI, ui.StatusNeutral)
	}
	if cfg.Fingerprint != "" {
		ui.PrintField("uTLS Fingerprint", cfg.Fingerprint, ui.StatusOK)
	}
	if cfg.Flow != "" {
		ui.PrintField("Flow (XTLS)", cfg.Flow, ui.StatusNeutral)
	}
	if cfg.PublicKey != "" {
		ui.PrintField("Reality Public Key", cfg.PublicKey[:min(16, len(cfg.PublicKey))]+"...", ui.StatusNeutral)
	}
	if cfg.ShortID != "" {
		ui.PrintField("Reality Short ID", cfg.ShortID, ui.StatusNeutral)
	}
	if len(cfg.ALPN) > 0 {
		ui.PrintField("ALPN", strings.Join(cfg.ALPN, ", "), ui.StatusNeutral)
	}
	if cfg.Remark != "" {
		ui.PrintField("Remark", cfg.Remark, ui.StatusNeutral)
	}

	ui.PrintStep(2, 6, "Protocol Handshake Analysis (direct connection)")

	ph, err := probes.ProbeProtocol(cfg)
	if err != nil {
		ui.PrintWarn(fmt.Sprintf("Protocol probe warning: %v", err))
	}

	ui.PrintSection("PROTOCOL HEALTH")

	ui.PrintSubSection("Handshake Timings")
	ui.PrintLatencyBar("DNS Resolution", ph.Timings.DNSResolutionMs)
	ui.PrintLatencyBar("TCP Connect", ph.Timings.TCPConnectMs)
	if ph.Timings.TLSHandshakeMs > 0 {
		ui.PrintLatencyBar("TLS/Reality Handshake", ph.Timings.TLSHandshakeMs)
	} else {
		ui.PrintField("TLS/Reality Handshake", "N/A (Reality uses custom protocol)", ui.StatusInfo)
	}
	totalMs := ph.Timings.DNSResolutionMs + ph.Timings.TCPConnectMs + ph.Timings.TLSHandshakeMs
	ui.PrintMetric("Total Connection Time", fmt.Sprintf("%.1f", totalMs), "ms", latencyQuality(totalMs))

	ui.PrintSubSection("Transport Details")
	if ph.NegotiatedALPN != "" {
		ui.PrintField("Negotiated ALPN", ph.NegotiatedALPN, ui.StatusOK)
	} else {
		ui.PrintField("Negotiated ALPN", "Not available (Reality/custom)", ui.StatusInfo)
	}
	if ph.CipherSuite != "" {
		ui.PrintField("Cipher Suite", ph.CipherSuite, ui.StatusOK)
	}
	if ph.TLSVersion != "" {
		ui.PrintField("TLS Version", ph.TLSVersion, tlsVersionStatus(ph.TLSVersion))
	}
	if ph.ServerCert != "" {
		ui.PrintField("Server Certificate CN", ph.ServerCert, ui.StatusInfo)
		ui.PrintField("Certificate Expiry", ph.CertExpiry, ui.StatusInfo)
	}

	ui.PrintSubSection("Fingerprint & Reality")
	if ph.UTLSMatch != "" {
		st := ui.StatusOK
		if strings.Contains(ph.UTLSMatch, "No uTLS") {
			st = ui.StatusWarn
		}
		ui.PrintField("uTLS Status", ph.UTLSMatch, st)
	}

	if cfg.Security == "reality" {
		ui.PrintField("SNI Reachability", sniReachableStr(ph.SNIReachable, ph.SNIStatusCode), sniStatus(ph.SNIReachable))
		ui.PrintField("Short ID Present", boolStr(ph.ShortIDPresent), boolStatus(ph.ShortIDPresent))
		ui.PrintField("Public Key Set", boolStr(cfg.PublicKey != ""), boolStatus(cfg.PublicKey != ""))
		ui.PrintField("Reality Config Valid", boolStr(ph.RealityValid), boolStatus(ph.RealityValid))
	}

	if ph.Error != "" && !strings.Contains(ph.Error, "TLS handshake note") {
		ui.PrintField("Note", ph.Error, ui.StatusWarn)
	}

	ui.PrintStep(3, 6, "Starting sing-box proxy tunnel")

	sbManager := manager.New(singboxPath, localProxyPort)
	if err := sbManager.Start(cfg); err != nil {
		lines := strings.Split(err.Error(), "\n")
		for i, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if i == 0 {
				ui.PrintError("Failed to start sing-box: " + line)
			} else {
				ui.ColorRed.Fprintf(color.Output, "           %s\n", line)
			}
		}
		ui.PrintInfo("Skipping proxy-dependent tests (network path, performance, leak tests)")
		printSummaryWithoutProxy(cfg, ph, startTime)
		return nil
	}
	defer func() {
		ui.PrintProgress("Stopping sing-box...")
		sbManager.Stop()
	}()

	time.Sleep(500 * time.Millisecond)

	ui.PrintStep(4, 6, "Network Path Analysis")

	np, err := probes.ProbeNetworkPath(cfg.Host, localProxyPort)
	if err != nil {
		ui.PrintWarn(fmt.Sprintf("Network path probe warning: %v", err))
	}

	ui.PrintSection("NETWORK PATH")

	ui.PrintSubSection("Local Entry Point")
	ui.PrintField("Local IP", np.LocalIP, ui.StatusNeutral)
	ui.PrintField("Network Interface", np.LocalInterface, ui.StatusNeutral)

	ui.PrintSubSection("Proxy Endpoint (Server)")
	ui.PrintField("Server IP", np.ServerIP, ui.StatusInfo)
	if np.ServerInfo.ISP != "" {
		ui.PrintField("ISP / Provider", np.ServerInfo.ISP, ui.StatusNeutral)
	}
	if np.ServerInfo.ASN != "" {
		ui.PrintField("ASN", np.ServerInfo.ASN, ui.StatusNeutral)
	}
	if np.ServerInfo.Country != "" {
		ui.PrintField("Location", fmt.Sprintf("%s, %s [%s]", np.ServerInfo.City, np.ServerInfo.Country, np.ServerInfo.CountryCode), ui.StatusNeutral)
	}
	if np.DNSResolvMs == 0 {
		ui.PrintField("DNS Resolution", "< 1 ms (cached)", ui.StatusOK)
	} else {
		ui.PrintMetric("DNS Resolution", fmt.Sprintf("%.0f", np.DNSResolvMs), "ms", latencyQuality(np.DNSResolvMs))
	}

	ui.PrintSubSection("Exit Node (Your visible IP)")
	if np.ExitInfo.IP != "" {
		ui.PrintField("Exit IP", np.ExitInfo.IP, ui.StatusOK)
		ui.PrintField("Country", fmt.Sprintf("%s, %s [%s]", np.ExitInfo.City, np.ExitInfo.Country, np.ExitInfo.CountryCode), ui.StatusNeutral)
		ui.PrintField("Timezone", np.ExitInfo.Timezone, ui.StatusNeutral)
		ui.PrintField("ISP / Org", np.ExitInfo.ISP, ui.StatusNeutral)
		ui.PrintField("ASN", np.ExitInfo.ASN, ui.StatusNeutral)
		proxyScoreStr := fmt.Sprintf("%d/100", np.ExitInfo.ProxyScore)
		proxyScoreStatus := proxyScoreStatus(np.ExitInfo.ProxyScore)
		ui.PrintField("Datacenter/VPN Score", proxyScoreStr, proxyScoreStatus)
		ui.PrintField("Flagged as Proxy", boolStr(np.ExitInfo.Proxy), invertBoolStatus(np.ExitInfo.Proxy))
		ui.PrintField("Flagged as Hosting", boolStr(np.ExitInfo.Hosting), invertBoolStatus(np.ExitInfo.Hosting))
	} else {
		ui.PrintField("Exit IP", "Could not determine (proxy may need more time)", ui.StatusWarn)
	}

	ui.PrintStep(5, 6, "Performance Measurement (this may take ~30s)")

	perf, err := probes.ProbePerformance(localProxyPort)
	if err != nil {
		ui.PrintWarn(fmt.Sprintf("Performance probe warning: %v", err))
	}

	ui.PrintSection("PERFORMANCE METRICS")

	sampleLabel := fmt.Sprintf("%d samples", len(perf.Latency.Samples))
	if perf.Latency.Endpoint != "" {
		sampleLabel += " via " + perf.Latency.Endpoint
	}
	ui.PrintSubSection("Latency (RTT) — " + sampleLabel)

	if len(perf.Latency.Samples) > 0 {
		ui.PrintLatencyBar("Average RTT", perf.Latency.Avg)
		ui.PrintLatencyBar("Minimum RTT", perf.Latency.Min)
		ui.PrintLatencyBar("Maximum RTT", perf.Latency.Max)
		ui.PrintMetric("Jitter", fmt.Sprintf("%.1f", perf.Latency.Jitter), "ms", jitterQuality(perf.Latency.Jitter))
		ui.PrintMetric("Packet Loss", fmt.Sprintf("%.1f", perf.Latency.PacketLoss), "%", lossQuality(perf.Latency.PacketLoss))
	} else {
		ui.PrintField("RTT Measurement", "No samples collected — proxy may not pass HTTP traffic", ui.StatusWarn)
	}

	if perf.MTUEstimate > 0 {
		ui.PrintSubSection("TCP / MTU")
		ui.PrintField("Estimated Effective MTU", fmt.Sprintf("%d bytes", perf.MTUEstimate), ui.StatusInfo)
	}

	ui.PrintSubSection("Speed Test")
	if perf.Speed.AvgMbps > 0 {
		ui.PrintMetric("TTFB", fmt.Sprintf("%.0f", perf.Speed.TTFBMs), "ms", ttfbQuality(perf.Speed.TTFBMs))
		ui.PrintSpeedBar("Peak Speed", perf.Speed.PeakMbps)
		ui.PrintSpeedBar("Average Speed", perf.Speed.AvgMbps)
		ui.PrintMetric("Data Transferred", fmt.Sprintf("%.2f", float64(perf.Speed.BytesTested)/1024/1024), "MB", ui.QualityNA)
		ui.PrintMetric("Test Duration", fmt.Sprintf("%.1f", perf.Speed.DurationSec), "s", ui.QualityNA)
	} else if perf.SpeedError != "" {
		ui.PrintField("Speed Test", "Failed", ui.StatusWarn)
			for _, line := range strings.Split(perf.SpeedError, "\n") {
			if line = strings.TrimSpace(line); line != "" {
				ui.ColorGray.Fprintf(color.Output, "         %s\n", line)
			}
		}
	} else {
		ui.PrintField("Speed Test", "No data collected", ui.StatusWarn)
	}

	ui.PrintStep(6, 6, "Security & Leak Tests")

	leaks, err := probes.ProbeLeaks(localProxyPort)
	if err != nil {
		ui.PrintWarn(fmt.Sprintf("Leak probe warning: %v", err))
	}

	ui.PrintSection("SECURITY & LEAK ANALYSIS")

	ui.PrintSubSection("DNS Leak Test")
	if len(leaks.DNSServersProxy) > 0 && leaks.DNSServersProxy[0] != "unavailable" {
		limit := leaks.DNSServersProxy
		if len(limit) > 3 {
			limit = limit[:3]
		}
		ui.PrintField("Exit Resolver IP(s)", strings.Join(limit, ", "), ui.StatusInfo)
	}
	if len(leaks.DNSServersDirect) > 0 && leaks.DNSServersDirect[0] != "unknown" {
		limit := leaks.DNSServersDirect
		if len(limit) > 3 {
			limit = limit[:3]
		}
		ui.PrintField("Local IP (direct)", strings.Join(limit, ", "), ui.StatusInfo)
	}
	if leaks.DNSLeakDetected {
		ui.PrintField("DNS Leak Status", "LEAK DETECTED — "+leaks.DNSLeakDetail, ui.StatusFail)
	} else {
		ui.PrintField("DNS Leak Status", leaks.DNSLeakDetail, ui.StatusOK)
	}

	ui.PrintSubSection("UDP Support")
	udpStatus := ui.StatusOK
	if !leaks.UDPSupported {
		udpStatus = ui.StatusWarn
	}
	ui.PrintField("UDP Connectivity", leaks.UDPDetail, udpStatus)

	ui.PrintSubSection("IPv6 Readiness")
	ipv6Status := ui.StatusOK
	if !leaks.IPv6Supported {
		ipv6Status = ui.StatusInfo
	}
	if leaks.IPv6Address != "" {
		ui.PrintField("IPv6 Address", leaks.IPv6Address, ipv6Status)
	}
	ui.PrintField("IPv6 Status", leaks.IPv6Detail, ipv6Status)
	score, issues := calculateScore(cfg, ph, np, perf, leaks)

	elapsed := time.Since(startTime)
	ui.ColorGray.Fprintf(color.Output, "\n  Total scan time: %.1f seconds\n", elapsed.Seconds())

	ui.PrintSummary(score, issues)

	return nil
}

func calculateScore(
	cfg *parser.VLESSConfig,
	ph *probes.ProtocolHealth,
	np *probes.NetworkPath,
	perf *probes.PerformanceResult,
	leaks *probes.LeakTestResult,
) (int, []string) {
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
			issues = append(issues, "Reality SNI target not reachable — camouflage may fail")
		}
		if cfg.PublicKey == "" {
			score -= 20
			issues = append(issues, "Reality public key missing")
		}
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
			issues = append(issues, fmt.Sprintf("High jitter: %.0f ms (unstable channel)", perf.Latency.Jitter))
		}

		if perf.Latency.PacketLoss > 5 {
			score -= 15
			issues = append(issues, fmt.Sprintf("Packet loss: %.1f%%", perf.Latency.PacketLoss))
		}

		if perf.Speed.AvgMbps > 0 && perf.Speed.AvgMbps < 2 {
			score -= 10
			issues = append(issues, fmt.Sprintf("Low throughput: %.2f Mbps", perf.Speed.AvgMbps))
		}
	}

	if leaks != nil && leaks.DNSLeakDetected {
		score -= 20
		issues = append(issues, "DNS leak detected — your ISP may see your DNS queries")
	}

	if np != nil && np.ExitInfo.ProxyScore > 70 {
		score -= 5
		issues = append(issues, fmt.Sprintf("Exit IP has high datacenter score (%d/100) — may be blocked by some services", np.ExitInfo.ProxyScore))
	}

	if cfg.AllowInsecure {
		score -= 10
		issues = append(issues, "allowInsecure=true — TLS certificate not verified, vulnerable to MITM")
	}

	if score < 0 {
		score = 0
	}
	return score, issues
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

func boolStatus(b bool) ui.FieldStatus {
	if b {
		return ui.StatusOK
	}
	return ui.StatusWarn
}

func invertBoolStatus(b bool) ui.FieldStatus {
	if b {
		return ui.StatusWarn
	}
	return ui.StatusOK
}

func securityStatus(sec string) ui.FieldStatus {
	switch sec {
	case "reality", "tls", "xtls":
		return ui.StatusOK
	case "none":
		return ui.StatusFail
	default:
		return ui.StatusWarn
	}
}

func sniReachableStr(reachable bool, code int) string {
	if reachable {
		return fmt.Sprintf("Reachable (HTTP %d)", code)
	}
	return "Not reachable — camouflage website inaccessible"
}

func sniStatus(reachable bool) ui.FieldStatus {
	if reachable {
		return ui.StatusOK
	}
	return ui.StatusFail
}

func tlsVersionStatus(ver string) ui.FieldStatus {
	if strings.Contains(ver, "1.3") {
		return ui.StatusOK
	}
	if strings.Contains(ver, "1.2") {
		return ui.StatusOK
	}
	return ui.StatusWarn
}

func latencyQuality(ms float64) ui.Quality {
	switch {
	case ms < 50:
		return ui.QualityExcellent
	case ms < 150:
		return ui.QualityGood
	case ms < 300:
		return ui.QualityFair
	default:
		return ui.QualityPoor
	}
}

func ttfbQuality(ms float64) ui.Quality {
	switch {
	case ms < 200:
		return ui.QualityExcellent
	case ms < 500:
		return ui.QualityGood
	case ms < 1000:
		return ui.QualityFair
	default:
		return ui.QualityPoor
	}
}

func jitterQuality(ms float64) ui.Quality {
	switch {
	case ms < 10:
		return ui.QualityExcellent
	case ms < 30:
		return ui.QualityGood
	case ms < 60:
		return ui.QualityFair
	default:
		return ui.QualityPoor
	}
}

func lossQuality(pct float64) ui.Quality {
	switch {
	case pct == 0:
		return ui.QualityExcellent
	case pct < 1:
		return ui.QualityGood
	case pct < 5:
		return ui.QualityFair
	default:
		return ui.QualityPoor
	}
}

func proxyScoreStatus(score int) ui.FieldStatus {
	if score < 30 {
		return ui.StatusOK
	}
	if score < 60 {
		return ui.StatusWarn
	}
	return ui.StatusFail
}

func printSummaryWithoutProxy(cfg *parser.VLESSConfig, ph *probes.ProtocolHealth, start time.Time) {
	score := 70
	var issues []string
	if cfg.Security == "none" {
		score -= 25
		issues = append(issues, "No encryption")
	}
	if !ph.RealityValid && cfg.Security == "reality" {
		score -= 10
		issues = append(issues, "Could not verify Reality configuration")
	}
	issues = append(issues, "sing-box failed to start — performance and leak tests skipped")
	ui.PrintSummary(score, issues)
}
