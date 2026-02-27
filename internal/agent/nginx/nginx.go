package nginx

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Manager struct {
	ConfDir  string
	SitesDir string
}

func NewManager() *Manager {
	// Defaults for Debian/Ubuntu and RHEL/AlmaLinux
	sitesDir := "/etc/nginx/conf.d"
	if fi, err := os.Stat("/etc/nginx/sites-available"); err == nil && fi.IsDir() {
		sitesDir = "/etc/nginx/sites-available"
	}
	return &Manager{
		ConfDir:  "/etc/nginx",
		SitesDir: sitesDir,
	}
}

type Site struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Config  string `json:"config"`
}

func (m *Manager) ListSites() ([]Site, error) {
	entries, err := os.ReadDir(m.SitesDir)
	if err != nil {
		return nil, fmt.Errorf("read sites dir: %w", err)
	}

	var sites []Site
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}

		path := filepath.Join(m.SitesDir, name)
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		enabled := true
		if m.SitesDir == "/etc/nginx/sites-available" {
			enabledPath := filepath.Join("/etc/nginx/sites-enabled", name)
			if _, err := os.Stat(enabledPath); os.IsNotExist(err) {
				enabled = false
			}
		}

		sites = append(sites, Site{
			Name:    name,
			Enabled: enabled,
			Config:  string(content),
		})
	}
	return sites, nil
}

func (m *Manager) SaveSite(name, config string) error {
	if strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return fmt.Errorf("invalid site name")
	}
	path := filepath.Join(m.SitesDir, name)
	if !strings.HasSuffix(name, ".conf") && m.SitesDir == "/etc/nginx/conf.d" {
		path += ".conf"
	}
	return os.WriteFile(path, []byte(config), 0644)
}

func (m *Manager) ToggleSite(name string, enable bool) error {
	if m.SitesDir != "/etc/nginx/sites-available" {
		// On RHEL/conf.d systems, renaming the extension is the standard way to disable,
		// but for MVP we'll just return nil to keep it simple.
		return nil
	}

	if strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return fmt.Errorf("invalid site name")
	}

	avail := filepath.Join("/etc/nginx/sites-available", name)
	enabled := filepath.Join("/etc/nginx/sites-enabled", name)

	if enable {
		if _, err := os.Stat(avail); err != nil {
			return err
		}
		os.Symlink(avail, enabled)
	} else {
		os.Remove(enabled)
	}
	return nil
}

func (m *Manager) DeleteSite(name string) error {
	if strings.Contains(name, "/") {
		return fmt.Errorf("invalid site name")
	}
	if m.SitesDir == "/etc/nginx/sites-available" {
		os.Remove(filepath.Join("/etc/nginx/sites-enabled", name))
	}
	return os.Remove(filepath.Join(m.SitesDir, name))
}

func (m *Manager) TestConfig() (string, error) {
	cmd := exec.Command("sudo", "nginx", "-t")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("config test failed: %w", err)
	}
	return out.String(), nil
}

func (m *Manager) Reload() error {
	return exec.Command("sudo", "systemctl", "reload", "nginx").Run()
}

func (m *Manager) Restart() error {
	return exec.Command("sudo", "systemctl", "restart", "nginx").Run()
}
