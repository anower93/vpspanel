package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

type Agent struct {
	cfg    *Config
	server *http.Server
}

func NewAgent(cfg *Config) (*Agent, error) {
	if err := os.MkdirAll(cfg.StateDir, 0750); err != nil {
		return nil, fmt.Errorf("state dir: %w", err)
	}

	if err := ensureEnrolled(cfg); err != nil {
		return nil, err
	}

	serverTLS, clientCA, err := loadTLS(cfg)
	if err != nil {
		return nil, err
	}

	r := chi.NewRouter()
	r.Get("/v1/health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	r.Get("/v1/metrics", metricsHandler)

	s := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{serverTLS},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientCA,
		},
	}

	return &Agent{cfg: cfg, server: s}, nil
}

func (a *Agent) ListenAndServe() error {
	err := a.server.ListenAndServeTLS("", "")
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (a *Agent) Shutdown(ctx context.Context) error {
	return a.server.Shutdown(ctx)
}

func (a *Agent) Close() {}

func ensureEnrolled(cfg *Config) error {
	certPath := filepath.Join(cfg.StateDir, "agent.crt")
	keyPath := filepath.Join(cfg.StateDir, "agent.key")
	caPath := filepath.Join(cfg.StateDir, "panel-ca.crt")

	if fileExists(certPath) && fileExists(keyPath) && fileExists(caPath) {
		return nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cfg.NodeName},
	}, key)
	if err != nil {
		return err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	body, _ := json.Marshal(map[string]any{
		"token":   cfg.EnrollToken,
		"csr_pem": string(csrPEM),
		"name":    cfg.NodeName,
		"host":    cfg.AdvertiseHost,
		"port":    cfg.AdvertisePort,
	})

	url := stringsTrimRightSlash(cfg.PanelURL) + "/api/v1/agent/register"
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("register with panel: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		s, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("register failed: %s: %s", resp.Status, string(s))
	}
	var out struct {
		CertPEM string `json:"cert_pem"`
		CAPEM   string `json:"ca_pem"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certPath, []byte(out.CertPEM), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(caPath, []byte(out.CAPEM), 0644); err != nil {
		return err
	}
	return nil
}

func loadTLS(cfg *Config) (tls.Certificate, *x509.CertPool, error) {
	certPath := filepath.Join(cfg.StateDir, "agent.crt")
	keyPath := filepath.Join(cfg.StateDir, "agent.key")
	caPath := filepath.Join(cfg.StateDir, "panel-ca.crt")

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	return cert, pool, nil
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cpuP, _ := cpu.PercentWithContext(ctx, time.Second, false)
	vm, _ := mem.VirtualMemoryWithContext(ctx)
	du, _ := disk.UsageWithContext(ctx, "/")
	hi, _ := host.InfoWithContext(ctx)
	io, _ := net.IOCountersWithContext(ctx, false)

	out := map[string]any{
		"cpu_percent": func() float64 {
			if len(cpuP) > 0 {
				return cpuP[0]
			}
			return 0
		}(),
		"mem_used_percent":  vm.UsedPercent,
		"disk_used_percent": du.UsedPercent,
		"uptime_seconds":    hi.Uptime,
		"net_bytes_recv": func() uint64 {
			if len(io) > 0 {
				return io[0].BytesRecv
			}
			return 0
		}(),
		"net_bytes_sent": func() uint64 {
			if len(io) > 0 {
				return io[0].BytesSent
			}
			return 0
		}(),
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func stringsTrimRightSlash(s string) string {
	for stringsHasSuffix(s, "/") {
		s = s[:len(s)-1]
	}
	return s
}

func stringsHasSuffix(s, suf string) bool {
	if len(s) < len(suf) {
		return false
	}
	return s[len(s)-len(suf):] == suf
}
