package probes

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"vless-diag/internal/socks5dialer"
)

type LeakTestResult struct {
	DNSLeakDetected  bool
	DNSServersProxy  []string
	DNSServersDirect []string
	DNSLeakDetail    string

	UDPSupported bool
	UDPDetail    string

	IPv6Supported bool
	IPv6Address   string
	IPv6Detail    string
}

func ProbeLeaks(localPort int) (*LeakTestResult, error) {
	result := &LeakTestResult{}

	proxyResolvers, err := getDNSResolversViaProxy(localPort)
	if err != nil || len(proxyResolvers) == 0 {
		result.DNSServersProxy = nil
	} else {
		result.DNSServersProxy = proxyResolvers
	}

	result.DNSServersDirect = getLocalExternalIP()
	result.DNSLeakDetected, result.DNSLeakDetail = analyzeDNSLeak(
		result.DNSServersProxy, result.DNSServersDirect)

	result.UDPSupported, result.UDPDetail = probeUDP(localPort)

	result.IPv6Supported, result.IPv6Address, result.IPv6Detail = probeIPv6(localPort)

	return result, nil
}

func getDNSResolversViaProxy(localPort int) ([]string, error) {
	client := socks5dialer.NewHTTPClient(localPort, 20*time.Second)

	type ipFetcher struct {
		name string
		fn   func(*http.Client) (string, error)
	}
	fetchers := []ipFetcher{
		{"api.myip.com", fetchMyIP},
		{"1.1.1.1/cdn-cgi/trace", fetchCFTrace},
		{"ipinfo.io", fetchIPInfo},
		{"api.ipify.org", fetchIPify},
	}

	var results []string
	for _, f := range fetchers {
		ip, err := f.fn(client)
		if err == nil && ip != "" && !contains(results, ip) {
			results = append(results, ip)
			if len(results) >= 2 {
				break
			}
		}
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("all IP-check endpoints failed through proxy")
	}
	return results, nil
}

func fetchCFTrace(client *http.Client) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://1.1.1.1/cdn-cgi/trace", nil)
	req.Header.Set("User-Agent", "curl/7.88.0")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ip=") {
			if ip := strings.TrimPrefix(line, "ip="); ip != "" {
				return ip, nil
			}
		}
	}
	return "", fmt.Errorf("ip= not found in CF trace")
}

func fetchMyIP(client *http.Client) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.myip.com", nil)
	req.Header.Set("User-Agent", "curl/7.88.0")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	var data struct{ IP string `json:"ip"` }
	if err := json.Unmarshal(body, &data); err != nil {
		return "", err
	}
	return data.IP, nil
}

func fetchIPInfo(client *http.Client) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://ipinfo.io/ip", nil)
	req.Header.Set("User-Agent", "curl/7.88.0")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	ip := strings.TrimSpace(string(body))
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("not an IP: %s", ip)
	}
	return ip, nil
}

func fetchIPify(client *http.Client) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.ipify.org?format=json", nil)
	req.Header.Set("User-Agent", "curl/7.88.0")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	var data struct{ IP string `json:"ip"` }
	if err := json.Unmarshal(body, &data); err != nil {
		return "", err
	}
	return data.IP, nil
}

func getLocalExternalIP() []string {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		},
		Timeout: 8 * time.Second,
	}

	var results []string

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.myip.com", nil)
	if err == nil {
		if resp, err := client.Do(req); err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
			var data struct{ IP string `json:"ip"` }
			if json.Unmarshal(body, &data) == nil && data.IP != "" {
				results = append(results, data.IP)
			}
		}
	}

	if conn, err := net.Dial("udp", "8.8.8.8:80"); err == nil {
		defer conn.Close()
		localIP := conn.LocalAddr().(*net.UDPAddr).IP.String()
		if !contains(results, localIP) {
			results = append(results, localIP)
		}
	}

	if len(results) == 0 {
		return []string{"unknown"}
	}
	return results
}

func analyzeDNSLeak(proxyIPs, directIPs []string) (bool, string) {
	if len(proxyIPs) == 0 {
		return false, "Could not verify DNS routing through proxy"
	}

	exitIP := proxyIPs[0]

	for _, d := range directIPs {
		if exitIP == d {
			return true, fmt.Sprintf(
				"Exit IP %s matches your direct IP %s — DNS and traffic NOT going through proxy", exitIP, d)
		}
	}

	for _, d := range directIPs {
		if p := subnetPrefix(exitIP); p != "" && p == subnetPrefix(d) {
			return true, fmt.Sprintf(
				"Exit IP %s is in same /24 as local IP %s — possible DNS leak", exitIP, d)
		}
	}

	return false, fmt.Sprintf("Clean — exit node IP (%s) differs from your local IP", exitIP)
}

func probeUDP(localPort int) (bool, string) {
	tcpOK, tcpDetail := testTCPTunnel(localPort)
	if !tcpOK {
		return false, fmt.Sprintf("TCP tunnel not working: %s", tcpDetail)
	}

	if testSOCKS5UDP(localPort) {
		return true, "SOCKS5 UDP ASSOCIATE supported — UDP traffic can pass through proxy"
	}

	return true, fmt.Sprintf(
		"TCP tunnel OK; SOCKS5 UDP ASSOCIATE not supported (expected for WS/gRPC transport) — "+
			"UDP games/VoIP require a UDP-capable transport (e.g. QUIC/hysteria)")
}

func testTCPTunnel(localPort int) (bool, string) {
	client := socks5dialer.NewHTTPClient(localPort, 12*time.Second)

	endpoints := []string{
		"http://connectivitycheck.gstatic.com/generate_204",
		"http://detectportal.firefox.com/success.txt",
		"http://www.gstatic.com/generate_204",
		"http://clients3.google.com/generate_204",
		"http://ipv4.download.thinkbroadband.com/robots.txt",
	}

	for _, ep := range endpoints {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		req, _ := http.NewRequestWithContext(ctx, "GET", ep, nil)
		resp, err := client.Do(req)
		cancel()
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			return true, fmt.Sprintf("HTTP GET %s → %d", ep, resp.StatusCode)
		}
	}
	return false, "all TCP test endpoints unreachable"
}

func testSOCKS5UDP(localPort int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", localPort), 3*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(4 * time.Second))

	conn.Write([]byte{0x05, 0x01, 0x00})
	greet := make([]byte, 2)
	if _, err := io.ReadFull(conn, greet); err != nil || greet[0] != 0x05 || greet[1] != 0x00 {
		return false
	}

	conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return false
	}
	return reply[1] == 0x00
}

func probeIPv6(localPort int) (bool, string, string) {
	client := socks5dialer.NewHTTPClient(localPort, 15*time.Second)

	ipv6Endpoints := []struct {
		url    string
		parser func([]byte) string
	}{
		{
			"https://api6.ipify.org?format=json",
			func(b []byte) string {
				var d struct{ IP string `json:"ip"` }
				json.Unmarshal(b, &d)
				return d.IP
			},
		},
		{
			"https://ipv6.icanhazip.com",
			func(b []byte) string { return strings.TrimSpace(string(b)) },
		},
	}

	for _, ep := range ipv6Endpoints {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		req, _ := http.NewRequestWithContext(ctx, "GET", ep.url, nil)
		req.Header.Set("User-Agent", "curl/7.88.0")
		resp, err := client.Do(req)
		cancel()
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		resp.Body.Close()
		ip := ep.parser(body)
		if strings.Contains(ip, ":") {
			return true, ip, fmt.Sprintf("IPv6 address obtained through proxy: %s", ip)
		}
	}

	return false, "", "IPv6 not available through this proxy (server may be IPv4-only)"
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func subnetPrefix(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return ""
	}
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	return strings.Join(parts[:3], ".")
}

func deduplicateStrings(ss []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
