package socks5dialer

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/proxy"
)

type Dialer struct {
	proxyAddr string
	d         proxy.Dialer
}

func New(localPort int) *Dialer {
	addr := fmt.Sprintf("127.0.0.1:%d", localPort)
	d, _ := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
	return &Dialer{proxyAddr: addr, d: d}
}

func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("split %q: %w", addr, err)
	}

	if net.ParseIP(host) == nil {
		rCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		ips, err := net.DefaultResolver.LookupIPAddr(rCtx, host)
		if err == nil && len(ips) > 0 {
			resolved := ips[0].IP.String()
			for _, ip := range ips {
				if ip.IP.To4() != nil {
					resolved = ip.IP.String()
					break
				}
			}
			addr = net.JoinHostPort(resolved, port)
		}
	}

	if cd, ok := d.d.(proxy.ContextDialer); ok {
		return cd.DialContext(ctx, network, addr)
	}
	return d.d.Dial(network, addr)
}

func NewHTTPClient(localPort int, timeout time.Duration) *http.Client {
	d := New(localPort)
	return &http.Client{
		Transport: &http.Transport{
			DialContext:           d.DialContext,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 20 * time.Second,
			MaxIdleConnsPerHost:   4,
			IdleConnTimeout:       30 * time.Second,
		},
		Timeout: timeout,
	}
}

func RawRTT(d *Dialer, targetHost, targetIP string, timeout time.Duration) (float64, error) {
	start := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(targetIP, "80"))
	if err != nil {
		return 0, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: curl/7.88.0\r\n\r\n", targetHost)
	if _, err := conn.Write([]byte(req)); err != nil {
		return 0, fmt.Errorf("write: %w", err)
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return 0, fmt.Errorf("read: %w", err)
	}

	if len(statusLine) < 8 || statusLine[:5] != "HTTP/" {
		return 0, fmt.Errorf("unexpected: %.40s", statusLine)
	}

	return float64(time.Since(start).Milliseconds()), nil
}
