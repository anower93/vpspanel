package panel

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	ListenAddr  string
	PublicURL   string
	DatabaseURL string
	DataDir     string
	CookieKey   string
}

func LoadConfig() (*Config, error) {
	listen := getenvDefault("VPSPANEL_LISTEN", ":8080")
	publicURL := strings.TrimSpace(os.Getenv("VPSPANEL_PUBLIC_URL"))
	dbURL := strings.TrimSpace(os.Getenv("VPSPANEL_DATABASE_URL"))
	dataDir := getenvDefault("VPSPANEL_DATA_DIR", "/var/lib/vpspanel")
	cookieKey := strings.TrimSpace(os.Getenv("VPSPANEL_COOKIE_KEY"))

	if dbURL == "" {
		return nil, errors.New("VPSPANEL_DATABASE_URL is required")
	}
	if publicURL == "" {
		return nil, errors.New("VPSPANEL_PUBLIC_URL is required (e.g. https://panel.example.com)")
	}
	if cookieKey == "" {
		return nil, errors.New("VPSPANEL_COOKIE_KEY is required")
	}

	absData, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, fmt.Errorf("invalid VPSPANEL_DATA_DIR: %w", err)
	}

	return &Config{
		ListenAddr:  listen,
		PublicURL:   publicURL,
		DatabaseURL: dbURL,
		DataDir:     absData,
		CookieKey:   cookieKey,
	}, nil
}

func getenvDefault(k, d string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return d
	}
	return v
}
