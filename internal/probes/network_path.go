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

type IPInfo struct {
	IP          string
	Country     string
	CountryCode string
	Region      string
	City        string
	Timezone    string
	ISP         string
	ASN         string
	Org         string
	Proxy       bool
	Hosting     bool
	ProxyScore  int
	Source      string
}

type NetworkPath struct {
	LocalIP        string
	LocalInterface string
	ServerIP       string
	ServerInfo     IPInfo
	ExitInfo       IPInfo
	DNSResolvMs    float64
}

func ProbeNetworkPath(host string, localPort int) (*NetworkPath, error) {
	result := &NetworkPath{}

	localIP, iface, err := getLocalIP()
	if err == nil {
		result.LocalIP = localIP
		result.LocalInterface = iface
	} else {
		result.LocalIP = "unknown"
		result.LocalInterface = "unknown"
	}

	dnsStart := time.Now()
	addrs, err := net.LookupHost(host)
	result.DNSResolvMs = float64(time.Since(dnsStart).Milliseconds())
	if err == nil && len(addrs) > 0 {
		result.ServerIP = addrs[0]
	} else {
		result.ServerIP = host
	}

	if info, err := getIPInfoWithFallback(result.ServerIP, 0); err == nil {
		result.ServerInfo = *info
	}

	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 800 * time.Millisecond)
		}
		if info, err := getIPInfoWithFallback("", localPort); err == nil {
			result.ExitInfo = *info
			break
		}
	}

	return result, nil
}

func getIPInfoWithFallback(ip string, localPort int) (*IPInfo, error) {
	type apiFunc func(string, int) (*IPInfo, error)
	apis := []struct {
		name string
		fn   apiFunc
	}{
		{"ip-api.com", getIPInfoIPAPI},
		{"ipinfo.io", getIPInfoIPInfo},
		{"ip.sb", getIPInfoIPSB},
	}

	var lastErr error
	for _, api := range apis {
		info, err := api.fn(ip, localPort)
		if err == nil && info != nil {
			info.Source = api.name
			return info, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("all IP info APIs failed; last: %w", lastErr)
}

func makeIPInfoClient(localPort int) *http.Client {
	if localPort > 0 {
		return socks5dialer.NewHTTPClient(localPort, 20*time.Second)
	}
	return &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		},
		Timeout: 20 * time.Second,
	}
}

func getIPInfoIPAPI(ip string, localPort int) (*IPInfo, error) {
	client := makeIPInfoClient(localPort)

	target := "http://ip-api.com/json/"
	if ip != "" && ip != "unknown" {
		target += ip
	}
	target += "?fields=status,message,country,countryCode,regionName,city,timezone,isp,org,as,query,proxy,hosting"

	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", target, nil)
	req.Header.Set("User-Agent", "curl/7.88.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	var data struct {
		Status      string `json:"status"`
		Query       string `json:"query"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		RegionName  string `json:"regionName"`
		City        string `json:"city"`
		Timezone    string `json:"timezone"`
		ISP         string `json:"isp"`
		Org         string `json:"org"`
		AS          string `json:"as"`
		Proxy       bool   `json:"proxy"`
		Hosting     bool   `json:"hosting"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("ip-api parse: %w", err)
	}
	if data.Status != "success" {
		return nil, fmt.Errorf("ip-api: status=%s", data.Status)
	}

	return &IPInfo{
		IP:          data.Query,
		Country:     data.Country,
		CountryCode: data.CountryCode,
		Region:      data.RegionName,
		City:        data.City,
		Timezone:    data.Timezone,
		ISP:         data.ISP,
		ASN:         extractASN(data.AS),
		Org:         data.Org,
		Proxy:       data.Proxy,
		Hosting:     data.Hosting,
		ProxyScore:  calcProxyScore(data.Proxy, data.Hosting, data.ISP, data.Org),
	}, nil
}

func getIPInfoIPInfo(ip string, localPort int) (*IPInfo, error) {
	client := makeIPInfoClient(localPort)

	target := "https://ipinfo.io/"
	if ip != "" && ip != "unknown" {
		target += ip + "/"
	}
	target += "json"

	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", target, nil)
	req.Header.Set("User-Agent", "curl/7.88.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	var data struct {
		IP       string `json:"ip"`
		Country  string `json:"country"`
		Region   string `json:"region"`
		City     string `json:"city"`
		Timezone string `json:"timezone"`
		Org      string `json:"org"`
	}
	if err := json.Unmarshal(body, &data); err != nil || data.IP == "" {
		return nil, fmt.Errorf("ipinfo.io: empty or invalid response")
	}

	isp := stripASN(data.Org)
	return &IPInfo{
		IP:          data.IP,
		Country:     countryName(data.Country),
		CountryCode: data.Country,
		Region:      data.Region,
		City:        data.City,
		Timezone:    data.Timezone,
		ISP:         isp,
		ASN:         extractASN(data.Org),
		Org:         isp,
		ProxyScore:  calcProxyScore(false, false, isp, data.Org),
	}, nil
}

func getIPInfoIPSB(ip string, localPort int) (*IPInfo, error) {
	client := makeIPInfoClient(localPort)

	target := "https://api.ip.sb/geoip"
	if ip != "" && ip != "unknown" {
		target += "/" + ip
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", target, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	var data struct {
		IP          string `json:"ip"`
		CountryCode string `json:"country_code"`
		Country     string `json:"country"`
		Region      string `json:"region"`
		City        string `json:"city"`
		Timezone    string `json:"timezone"`
		ISP         string `json:"isp"`
		ASN         int    `json:"asn"`
		ASNOrg      string `json:"asn_organization"`
	}
	if err := json.Unmarshal(body, &data); err != nil || data.IP == "" {
		return nil, fmt.Errorf("ip.sb: invalid response")
	}

	asnStr := ""
	if data.ASN > 0 {
		asnStr = fmt.Sprintf("AS%d", data.ASN)
	}
	return &IPInfo{
		IP:          data.IP,
		Country:     data.Country,
		CountryCode: data.CountryCode,
		Region:      data.Region,
		City:        data.City,
		Timezone:    data.Timezone,
		ISP:         data.ISP,
		ASN:         asnStr,
		Org:         data.ASNOrg,
		ProxyScore:  calcProxyScore(false, false, data.ISP, data.ASNOrg),
	}, nil
}

func getLocalIP() (string, string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", "", err
	}
	defer conn.Close()
	ip := conn.LocalAddr().(*net.UDPAddr).IP.String()

	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ifIP net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ifIP = v.IP
			case *net.IPAddr:
				ifIP = v.IP
			}
			if ifIP != nil && ifIP.String() == ip {
				return ip, iface.Name, nil
			}
		}
	}
	return ip, "unknown", nil
}

func extractASN(s string) string {
	parts := strings.SplitN(strings.TrimSpace(s), " ", 2)
	if len(parts) > 0 && strings.HasPrefix(strings.ToUpper(parts[0]), "AS") {
		return parts[0]
	}
	return ""
}

func stripASN(s string) string {
	parts := strings.SplitN(strings.TrimSpace(s), " ", 2)
	if len(parts) == 2 && strings.HasPrefix(strings.ToUpper(parts[0]), "AS") {
		return parts[1]
	}
	return s
}

func calcProxyScore(proxy, hosting bool, isp, org string) int {
	score := 0
	if proxy {
		score += 50
	}
	if hosting {
		score += 35
	}
	dcKeywords := []string{
		"Amazon", "AWS", "Google", "Microsoft", "Azure", "Cloudflare",
		"Hetzner", "OVH", "DigitalOcean", "Linode", "Vultr", "Akamai",
		"Fastly", "Choopa", "Contabo", "Leaseweb", "Equinix",
		"DataCenter", "Data Center", "Hosting", "VPS", "Cloud",
	}
	combined := strings.ToUpper(isp + " " + org)
	for _, kw := range dcKeywords {
		if strings.Contains(combined, strings.ToUpper(kw)) {
			score += 15
			break
		}
	}
	if score > 100 {
		score = 100
	}
	return score
}

func countryName(code string) string {
	names := map[string]string{
		"US": "United States", "GB": "United Kingdom", "DE": "Germany",
		"FR": "France", "NL": "Netherlands", "JP": "Japan", "SG": "Singapore",
		"HK": "Hong Kong", "AU": "Australia", "CA": "Canada", "RU": "Russia",
		"CN": "China", "KR": "South Korea", "BR": "Brazil", "IN": "India",
		"SE": "Sweden", "CH": "Switzerland", "FI": "Finland", "UA": "Ukraine",
		"PL": "Poland", "CZ": "Czech Republic", "AT": "Austria", "TR": "Turkey",
		"LU": "Luxembourg", "IS": "Iceland", "NO": "Norway", "DK": "Denmark",
	}
	if name, ok := names[strings.ToUpper(code)]; ok {
		return name
	}
	return code
}
