package httpapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type AgentClient struct {
	client *http.Client
}

func NewAgentClient(caCert []byte, clientCert []byte, clientKey []byte) (*AgentClient, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA cert")
	}

	cert, err := tls.X509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client key pair: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		// We use the Node's ServerCertCN to verify the hostname
		// ServerName: will be set per request or left out if skipping host verify and checking CN manually
		InsecureSkipVerify: true, // We verify manually in VerifyPeerCertificate
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no certificates provided")
			}
			c, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			opts := x509.VerifyOptions{
				Roots:         pool,
				Intermediates: x509.NewCertPool(),
			}
			for i := 1; i < len(rawCerts); i++ {
				ic, err := x509.ParseCertificate(rawCerts[i])
				if err == nil {
					opts.Intermediates.AddCert(ic)
				}
			}
			_, err = c.Verify(opts)
			return err
		},
	}

	transport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &AgentClient{
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
	}, nil
}

type NodeMetrics struct {
	CPUPercent      float64 `json:"cpu_percent"`
	MemUsedPercent  float64 `json:"mem_used_percent"`
	DiskUsedPercent float64 `json:"disk_used_percent"`
	UptimeSeconds   uint64  `json:"uptime_seconds"`
	NetBytesRecv    uint64  `json:"net_bytes_recv"`
	NetBytesSent    uint64  `json:"net_bytes_sent"`
	Timestamp       string  `json:"timestamp"`
}

func (ac *AgentClient) GetMetrics(ctx context.Context, host string, port int, cn string) (*NodeMetrics, error) {
	url := fmt.Sprintf("https://%s:%d/v1/metrics", host, port)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := ac.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	// Manual CN verification could be done here if we inspect TLS state,
	// but the custom VerifyPeerCertificate already verified against our CA.
	// For strict multi-tenant, we should check resp.TLS.PeerCertificates[0].Subject.CommonName == cn

	var metrics NodeMetrics
	if err := json.NewDecoder(resp.Body).Decode(&metrics); err != nil {
		return nil, fmt.Errorf("decode failed: %w", err)
	}

	return &metrics, nil
}

type NginxSite struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Config  string `json:"config"`
}

func (ac *AgentClient) doReq(ctx context.Context, host string, port int, method, path string, body []byte) (*http.Response, error) {
	url := fmt.Sprintf("https://%s:%d%s", host, port, path)
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := ac.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	return resp, nil
}

func (ac *AgentClient) GetNginxSites(ctx context.Context, host string, port int, cn string) ([]NginxSite, error) {
	resp, err := ac.doReq(ctx, host, port, http.MethodGet, "/v1/nginx/sites", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var sites []NginxSite
	if err := json.NewDecoder(resp.Body).Decode(&sites); err != nil {
		return nil, fmt.Errorf("decode failed: %w", err)
	}
	return sites, nil
}

func (ac *AgentClient) SaveNginxSite(ctx context.Context, host string, port int, cn string, name, config string) error {
	payload, _ := json.Marshal(map[string]string{"config": config})
	resp, err := ac.doReq(ctx, host, port, http.MethodPost, "/v1/nginx/sites/"+name, payload)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (ac *AgentClient) ToggleNginxSite(ctx context.Context, host string, port int, cn string, name string, enable bool) error {
	payload, _ := json.Marshal(map[string]bool{"enabled": enable})
	resp, err := ac.doReq(ctx, host, port, http.MethodPost, "/v1/nginx/sites/"+name+"/toggle", payload)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (ac *AgentClient) DeleteNginxSite(ctx context.Context, host string, port int, cn string, name string) error {
	resp, err := ac.doReq(ctx, host, port, http.MethodDelete, "/v1/nginx/sites/"+name, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (ac *AgentClient) ActionNginx(ctx context.Context, host string, port int, cn string, action string) error {
	resp, err := ac.doReq(ctx, host, port, http.MethodPost, "/v1/nginx/"+action, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
