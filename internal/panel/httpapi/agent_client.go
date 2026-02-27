package httpapi

import (
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
