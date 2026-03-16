package probes

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"vless-diag/internal/socks5dialer"
)

type LatencyResult struct {
	Min        float64
	Max        float64
	Avg        float64
	Jitter     float64
	Samples    []float64
	PacketLoss float64
	Endpoint   string
}

type SpeedResult struct {
	TTFBMs      float64
	PeakMbps    float64
	AvgMbps     float64
	BytesTested int64
	DurationSec float64
}

type PerformanceResult struct {
	Latency     LatencyResult
	Speed       SpeedResult
	SpeedError  string
	MTUEstimate int
}

func ProbePerformance(localPort int) (*PerformanceResult, error) {
	result := &PerformanceResult{MTUEstimate: 1460}

	d := socks5dialer.New(localPort)
	transport := &http.Transport{
		DialContext:           d.DialContext,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		DisableCompression:    true,
	}

	latency, workingURL, err := probeLatency(transport, 15)
	if err != nil {
		return result, fmt.Errorf("latency probe: %w", err)
	}
	result.Latency = *latency

	speed, err := probeSpeed(transport, workingURL)
	if err != nil {
		result.SpeedError = err.Error()
	} else {
		result.Speed = *speed
	}

	transport.CloseIdleConnections()
	return result, nil
}

type rttCandidate struct {
	url  string
	host string
}

var rttCandidates = []rttCandidate{
	{url: "http://connectivitycheck.gstatic.com/generate_204", host: "connectivitycheck.gstatic.com"},
	{url: "http://detectportal.firefox.com/success.txt", host: "detectportal.firefox.com"},
	{url: "http://www.gstatic.com/generate_204", host: "www.gstatic.com"},
	{url: "http://clients3.google.com/generate_204", host: "clients3.google.com"},
	{url: "http://cp.cloudflare.com/", host: "cp.cloudflare.com"},
}

func probeLatency(transport *http.Transport, count int) (*LatencyResult, string, error) {
	client := &http.Client{
		Transport: transport,
		Timeout:   8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var workingURL, workingIP string

	for _, cand := range rttCandidates {
		ips, err := net.LookupHost(cand.host)
		if err != nil || len(ips) == 0 {
			continue
		}
		ip := ""
		for _, a := range ips {
			if net.ParseIP(a).To4() != nil {
				ip = a
				break
			}
		}
		if ip == "" {
			ip = ips[0]
		}

		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		req, _ := http.NewRequestWithContext(ctx, "GET", cand.url, nil)
		req.Header.Set("User-Agent", "curl/7.88.0")
		resp, err := client.Do(req)
		cancel()
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			workingURL = cand.url
			workingIP = ip
			time.Sleep(300 * time.Millisecond)
			break
		}
	}

	if workingURL == "" {
		return nil, "", fmt.Errorf("no RTT endpoint reachable through proxy (tried %d candidates)", len(rttCandidates))
	}

	sequential := make([]float64, 0, count)
	failed := 0

	for i := 0; i < count; i++ {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		req, _ := http.NewRequestWithContext(ctx, "GET", workingURL, nil)
		req.Header.Set("User-Agent", "curl/7.88.0")
		req.Header.Set("Accept-Encoding", "identity")
		resp, err := client.Do(req)
		elapsed := float64(time.Since(start).Milliseconds())
		cancel()

		if err != nil {
			failed++
		} else {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			sequential = append(sequential, elapsed)
		}

		if i < count-1 {
			time.Sleep(150 * time.Millisecond)
		}
	}

	if len(sequential) == 0 {
		return nil, "", fmt.Errorf("all %d RTT probes failed", count)
	}

	sorted := make([]float64, len(sequential))
	copy(sorted, sequential)
	sort.Float64s(sorted)

	sum := 0.0
	for _, v := range sorted {
		sum += v
	}
	avg := sum / float64(len(sorted))

	jitter := 0.0
	if len(sequential) > 1 {
		var jSum float64
		for i := 1; i < len(sequential); i++ {
			jSum += math.Abs(sequential[i] - sequential[i-1])
		}
		jitter = jSum / float64(len(sequential)-1)
	}

	return &LatencyResult{
		Samples:    sorted,
		Min:        sorted[0],
		Max:        sorted[len(sorted)-1],
		Avg:        avg,
		Jitter:     jitter,
		PacketLoss: float64(failed) / float64(count) * 100,
		Endpoint:   fmt.Sprintf("%s (IP: %s)", workingURL, workingIP),
	}, workingURL, nil
}

type speedCandidate struct {
	url     string
	sameHost bool
}

func buildSpeedCandidates(workingLatencyURL string) []speedCandidate {
	var candidates []speedCandidate

	if strings.Contains(workingLatencyURL, "gstatic.com") ||
		strings.Contains(workingLatencyURL, "google.com") {
		candidates = append(candidates,
			speedCandidate{"https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb", true},
		)
	}

	candidates = append(candidates,
		speedCandidate{"https://releases.ubuntu.com/24.04/ubuntu-24.04.1-desktop-amd64.iso.zsync", false},
		speedCandidate{"https://proof.ovh.net/files/10Mb.dat", false},
		speedCandidate{"https://proof.ovh.net/files/1Mb.dat", false},
		speedCandidate{"http://ipv4.download.thinkbroadband.com/10MB.zip", false},
		speedCandidate{"http://ipv4.download.thinkbroadband.com/5MB.zip", false},
		speedCandidate{"http://cachefly.cachefly.net/5mb.test", false},
		speedCandidate{"https://speed.cloudflare.com/__down?bytes=10000000", false},
		speedCandidate{"https://speed.cloudflare.com/__down?bytes=5000000", false},
	)

	return candidates
}

func probeSpeed(transport *http.Transport, workingLatencyURL string) (*SpeedResult, error) {
	client := &http.Client{
		Transport: transport,
		Timeout:   45 * time.Second,
	}

	candidates := buildSpeedCandidates(workingLatencyURL)

	var errs []string
	for _, cand := range candidates {
		result, err := downloadAndMeasure(client, cand.url)
		if err == nil && result.AvgMbps > 0 {
			return result, nil
		}
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", cand.url, err))
		}
	}
	return nil, fmt.Errorf("all speed test candidates failed:\n  %s", strings.Join(errs, "\n  "))
}

func downloadAndMeasure(client *http.Client, testURL string) (*SpeedResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible)")
	req.Header.Set("Cache-Control", "no-cache")

	reqStart := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	ttfb := float64(time.Since(reqStart).Milliseconds())

	buf := make([]byte, 65536)
	var totalBytes int64
	var peakMbps float64
	dlStart := time.Now()
	windowStart := dlStart
	var windowBytes int64

	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			totalBytes += int64(n)
			windowBytes += int64(n)
			now := time.Now()
			if winDur := now.Sub(windowStart).Seconds(); winDur >= 0.2 {
				mbps := float64(windowBytes) * 8 / winDur / 1e6
				if mbps > peakMbps {
					peakMbps = mbps
				}
				windowBytes = 0
				windowStart = now
			}
		}
		if err != nil {
			if winDur := time.Since(windowStart).Seconds(); winDur > 0.01 && windowBytes > 0 {
				mbps := float64(windowBytes) * 8 / winDur / 1e6
				if mbps > peakMbps {
					peakMbps = mbps
				}
			}
			break
		}
		if time.Since(dlStart) > 12*time.Second {
			break
		}
	}

	dur := time.Since(dlStart).Seconds()
	if totalBytes < 1_000_000 {
		return nil, fmt.Errorf("too little data: %.0f bytes in %.2fs", float64(totalBytes), dur)
	}
	if dur < 0.05 {
		dur = 0.05
	}

	avgMbps := float64(totalBytes) * 8 / dur / 1e6
	if peakMbps < avgMbps {
		peakMbps = avgMbps
	}

	return &SpeedResult{
		TTFBMs:      ttfb,
		PeakMbps:    peakMbps,
		AvgMbps:     avgMbps,
		BytesTested: totalBytes,
		DurationSec: dur,
	}, nil
}
