package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	ListenAddr    string
	PanelURL      string
	EnrollToken   string
	StateDir      string
	NodeName      string
	AdvertiseHost string
	AdvertisePort int
}

func LoadConfig() (*Config, error) {
	listen := getenvDefault("VPSPANEL_AGENT_LISTEN", ":8443")
	panel := strings.TrimSpace(os.Getenv("VPSPANEL_PANEL_URL"))
	tok := strings.TrimSpace(os.Getenv("VPSPANEL_ENROLL_TOKEN"))
	state := getenvDefault("VPSPANEL_AGENT_STATE_DIR", "/var/lib/vpspanel-agent")
	name := getenvDefault("VPSPANEL_NODE_NAME", hostnameDefault())
	host := strings.TrimSpace(os.Getenv("VPSPANEL_ADVERTISE_HOST"))
	portStr := getenvDefault("VPSPANEL_ADVERTISE_PORT", "8443")
	port := atoiDefault(portStr, 8443)

	if panel == "" {
		return nil, errors.New("VPSPANEL_PANEL_URL is required")
	}
	if tok == "" {
		return nil, errors.New("VPSPANEL_ENROLL_TOKEN is required")
	}
	if host == "" {
		return nil, errors.New("VPSPANEL_ADVERTISE_HOST is required")
	}
	abs, _ := filepath.Abs(state)

	return &Config{
		ListenAddr:    listen,
		PanelURL:      panel,
		EnrollToken:   tok,
		StateDir:      abs,
		NodeName:      name,
		AdvertiseHost: host,
		AdvertisePort: port,
	}, nil
}

func getenvDefault(k, d string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return d
	}
	return v
}

func hostnameDefault() string {
	h, _ := os.Hostname()
	if h == "" {
		return "node"
	}
	return h
}

func atoiDefault(s string, d int) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return d
		}
		n = n*10 + int(r-'0')
	}
	if n <= 0 {
		return d
	}
	return n
}
