package parser

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)
type VLESSConfig struct {
	UUID     string
	Host     string
	Port     int
	Remark   string
	Network     string
	Security    string
	Path        string
	Host_Header string
	SNI         string
	Fingerprint string
	ALPN        []string
	AllowInsecure bool
	PublicKey string
	ShortID   string
	SpiderX   string
	Flow string
	RawURI string
}
func Parse(rawURI string) (*VLESSConfig, error) {
	if !strings.HasPrefix(rawURI, "vless://") {
		return nil, fmt.Errorf("not a VLESS URI (must start with vless://)")
	}

	u, err := url.Parse(rawURI)
	if err != nil {
		return nil, fmt.Errorf("invalid URI: %w", err)
	}

	cfg := &VLESSConfig{RawURI: rawURI}
	cfg.UUID = u.User.Username()
	if cfg.UUID == "" {
		return nil, fmt.Errorf("missing UUID in URI")
	}
	cfg.Host = u.Hostname()
	if cfg.Host == "" {
		return nil, fmt.Errorf("missing host in URI")
	}
	portStr := u.Port()
	if portStr == "" {
		portStr = "443"
	}
	cfg.Port, err = strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}
	cfg.Remark = u.Fragment
	if decoded, err := url.PathUnescape(cfg.Remark); err == nil {
		cfg.Remark = decoded
	}

	q := u.Query()
	cfg.Network = strings.ToLower(q.Get("type"))
	if cfg.Network == "" {
		cfg.Network = "tcp"
	}
	cfg.Security = strings.ToLower(q.Get("security"))
	if cfg.Security == "" {
		cfg.Security = "none"
	}
	cfg.Path = q.Get("path")
	if cfg.Path == "" {
		cfg.Path = q.Get("serviceName")
	}
	cfg.Host_Header = q.Get("host")
	cfg.SNI = q.Get("sni")
	if cfg.SNI == "" && (cfg.Security == "tls" || cfg.Security == "reality") {
		cfg.SNI = cfg.Host
	}
	cfg.Fingerprint = q.Get("fp")
	if cfg.Fingerprint == "" {
		cfg.Fingerprint = q.Get("fingerprint")
	}
	alpnRaw := q.Get("alpn")
	if alpnRaw != "" {
		decoded, _ := url.QueryUnescape(alpnRaw)
		cfg.ALPN = strings.Split(decoded, ",")
		for i, a := range cfg.ALPN {
			cfg.ALPN[i] = strings.TrimSpace(a)
		}
	}
	insecure := q.Get("allowInsecure")
	cfg.AllowInsecure = insecure == "1" || strings.EqualFold(insecure, "true")
	cfg.PublicKey = q.Get("pbk")
	cfg.ShortID = q.Get("sid")
	cfg.SpiderX = q.Get("spx")
	cfg.Flow = q.Get("flow")

	return cfg, nil
}
func (c *VLESSConfig) Describe() string {
	sb := strings.Builder{}
	sb.WriteString(fmt.Sprintf("VLESS → %s:%d", c.Host, c.Port))
	if c.Remark != "" {
		sb.WriteString(fmt.Sprintf(" [%s]", c.Remark))
	}
	sb.WriteString(fmt.Sprintf("\n  Security: %s | Transport: %s", strings.ToUpper(c.Security), strings.ToUpper(c.Network)))
	if c.SNI != "" {
		sb.WriteString(fmt.Sprintf(" | SNI: %s", c.SNI))
	}
	if c.Fingerprint != "" {
		sb.WriteString(fmt.Sprintf(" | uTLS: %s", c.Fingerprint))
	}
	return sb.String()
}
func (c *VLESSConfig) LocalProxyPort() int {
	return 10808
}
