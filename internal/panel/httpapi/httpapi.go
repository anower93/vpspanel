package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"vpspanel/internal/panel/ca"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type Deps struct {
	DB        *sql.DB
	CA        *ca.CA
	PublicURL string
	CookieKey []byte
	Templates *template.Template
}

type API struct {
	Deps
	agentClient *AgentClient
}

func New(d Deps) http.Handler {
	a := &API{Deps: d}

	// Create client cert for panel to talk to agents
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(d.CA.Key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d.CA.Cert.Raw})

	ac, err := NewAgentClient(d.CA.CertPEM, certPEM, keyPEM)
	if err != nil {
		log.Printf("failed to init agent client: %v", err)
	}
	a.agentClient = ac

	r := chi.NewRouter()

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	r.Get("/login", a.loginPage)
	r.Post("/login", a.login)
	r.Post("/logout", a.logout)

	// Dashboard routes
	r.Get("/license", a.licensePage)
	r.Post("/license", a.licenseSubmit)

	r.Group(func(r chi.Router) {
		r.Use(a.requireLicense)
		r.Use(a.requireSession)
		r.Get("/", a.dashboard)
		r.Get("/nodes", a.nodesPage)
		r.Get("/nodes/{id}/metrics", a.nodeMetricsAPI)
		r.Post("/nodes/enroll", a.apiEnrollCommand)
		r.Post("/nodes/{id}/delete", a.nodeDelete)

		r.Get("/nodes/{id}/nginx", a.nginxPage)
		r.Post("/nodes/{id}/nginx/action", a.nginxAction)
		r.Post("/nodes/{id}/nginx/save", a.nginxSave)
		r.Post("/nodes/{id}/nginx/toggle", a.nginxToggle)
		r.Post("/nodes/{id}/nginx/delete", a.nginxDelete)
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/agent/register", a.agentRegister)
	})

	return r
}

func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(b), err
}

func (a *API) loginPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!doctype html><html><head><meta charset="utf-8"><title>Login</title></head><body><h1>VPS Panel</h1><form method="post" action="/login"><label>Email <input name="email"/></label><br/><label>Password <input type="password" name="password"/></label><br/><button type="submit">Login</button></form></body></html>`))
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	email := strings.TrimSpace(r.Form.Get("email"))
	pw := r.Form.Get("password")
	if email == "" || pw == "" {
		http.Error(w, "missing", http.StatusBadRequest)
		return
	}

	var userID uuid.UUID
	var hash string
	err := a.DB.QueryRowContext(r.Context(), `select id, password_hash from users where email=$1`, email).Scan(&userID, &hash)
	if err != nil {
		http.Error(w, "invalid", http.StatusUnauthorized)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) != nil {
		http.Error(w, "invalid", http.StatusUnauthorized)
		return
	}

	sid := uuid.New()
	expires := time.Now().Add(24 * time.Hour)
	_, err = a.DB.ExecContext(r.Context(), `insert into sessions (id, user_id, expires_at) values ($1,$2,$3)`, sid, userID, expires)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}

	val, err := sign(a.CookieKey, sid.String())
	if err != nil {
		http.Error(w, "cookie error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "vpspanel_session",
		Value:    val,
		Path:     "/",
		HttpOnly: true,
		Secure:   strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") || r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		Expires:  expires,
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	// Best-effort; remove cookie.
	http.SetCookie(w, &http.Cookie{Name: "vpspanel_session", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (a *API) dashboard(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/nodes", http.StatusFound)
}

func (a *API) requireLicense(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var key string
		err := a.DB.QueryRowContext(r.Context(), `select value from settings where key='license_key'`).Scan(&key)
		if err != nil || key == "" {
			http.Redirect(w, r, "/license", http.StatusFound)
			return
		}

		// Get the public IP of the panel server to send for verification
		serverIP := getOutboundIP()

		// Check license status
		status, err := VerifyLicense(r.Context(), key, serverIP)
		if err != nil || !status.Valid {
			// Clear it so they are forced to enter a new one
			a.DB.ExecContext(r.Context(), `delete from settings where key='license_key'`)
			http.Redirect(w, r, "/license", http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (a *API) licensePage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if a.Templates != nil {
		a.Templates.ExecuteTemplate(w, "license.html", map[string]any{
			"Error": r.URL.Query().Get("error"),
		})
		return
	}
	w.Write([]byte("License template missing"))
}

func (a *API) licenseSubmit(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimSpace(r.FormValue("license_key"))
	if key == "" {
		http.Redirect(w, r, "/license?error=Key+required", http.StatusFound)
		return
	}

	serverIP := getOutboundIP()
	status, err := VerifyLicense(r.Context(), key, serverIP)
	if err != nil {
		http.Redirect(w, r, "/license?error=Verification+server+error", http.StatusFound)
		return
	}

	if !status.Valid {
		http.Redirect(w, r, "/license?error="+status.Message, http.StatusFound)
		return
	}

	// Save to DB
	_, err = a.DB.ExecContext(r.Context(), `
		insert into settings (key, value) values ('license_key', $1)
		on conflict (key) do update set value = $1
	`, key)

	if err != nil {
		http.Redirect(w, r, "/license?error=Database+error", http.StatusFound)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func getOutboundIP() string {
	// A quick way to get the server's public IP using a reliable external service.
	// In production, you might want to cache this or use a local interface check.
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("https://api.ipify.org")
	if err == nil {
		defer resp.Body.Close()
		buf := new(bytes.Buffer)
		buf.ReadFrom(resp.Body)
		return strings.TrimSpace(buf.String())
	}
	return "unknown"
}

func (a *API) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("vpspanel_session")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		sidStr, err := verify(a.CookieKey, c.Value)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		sid, err := uuid.Parse(sidStr)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		var expires time.Time
		err = a.DB.QueryRowContext(r.Context(), `select expires_at from sessions where id=$1`, sid).Scan(&expires)
		if err != nil || time.Now().After(expires) {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type Node struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	AgentHost string    `json:"agent_host"`
	AgentPort int       `json:"agent_port"`
	CertCN    string    `json:"cert_cn"`
	CreatedAt time.Time `json:"created_at"`
}

func (a *API) nodesPage(w http.ResponseWriter, r *http.Request) {
	rows, err := a.DB.QueryContext(r.Context(), `select id, name, agent_host, agent_port, server_cert_cn, created_at from nodes order by created_at desc`)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var nodes []Node
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.ID, &n.Name, &n.AgentHost, &n.AgentPort, &n.CertCN, &n.CreatedAt); err != nil {
			continue
		}
		nodes = append(nodes, n)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if a.Templates != nil {
		a.Templates.ExecuteTemplate(w, "nodes.html", map[string]any{"Nodes": nodes})
		return
	}

	// Fallback basic UI
	html := `<!doctype html><html><head><style>body{font-family:sans-serif;margin:40px;background:#f4f4f5}table{width:100%;border-collapse:collapse;background:#fff}th,td{padding:12px;border:1px solid #ddd;text-align:left}th{background:#f8f9fa}</style></head><body>`
	html += `<h1>Enrolled Nodes</h1><table><tr><th>Name</th><th>Host</th><th>Joined</th><th>Actions</th></tr>`
	for _, n := range nodes {
		html += fmt.Sprintf(`<tr><td>%s</td><td>%s:%d</td><td>%s</td><td><a href="/nodes/%s/metrics">View Metrics</a></td></tr>`, n.Name, n.AgentHost, n.AgentPort, n.CreatedAt.Format(time.DateOnly), n.ID)
	}
	html += `</table><br><form method="post" action="/logout"><button>Logout</button></form></body></html>`
	w.Write([]byte(html))
}

func (a *API) nodeMetricsAPI(w http.ResponseWriter, r *http.Request) {
	nodeID := chi.URLParam(r, "id")
	if a.agentClient == nil {
		http.Error(w, "agent client not configured", http.StatusInternalServerError)
		return
	}

	var n Node
	err := a.DB.QueryRowContext(r.Context(), `select id, name, agent_host, agent_port, server_cert_cn from nodes where id=$1`, nodeID).
		Scan(&n.ID, &n.Name, &n.AgentHost, &n.AgentPort, &n.CertCN)
	if err != nil {
		http.Error(w, "node not found", http.StatusNotFound)
		return
	}

	metrics, err := a.agentClient.GetMetrics(r.Context(), n.AgentHost, n.AgentPort, n.CertCN)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to contact agent: %v", err), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

func (a *API) getNodeOr404(w http.ResponseWriter, r *http.Request) *Node {
	nodeID := chi.URLParam(r, "id")
	var n Node
	err := a.DB.QueryRowContext(r.Context(), `select id, name, agent_host, agent_port, server_cert_cn from nodes where id=$1`, nodeID).
		Scan(&n.ID, &n.Name, &n.AgentHost, &n.AgentPort, &n.CertCN)
	if err != nil {
		http.Error(w, "node not found", http.StatusNotFound)
		return nil
	}
	return &n
}

func (a *API) nodeDelete(w http.ResponseWriter, r *http.Request) {
	nodeID := chi.URLParam(r, "id")
	_, err := a.DB.ExecContext(r.Context(), `delete from nodes where id=$1`, nodeID)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/nodes", http.StatusFound)
}

func (a *API) nginxPage(w http.ResponseWriter, r *http.Request) {
	n := a.getNodeOr404(w, r)
	if n == nil {
		return
	}

	sites, err := a.agentClient.GetNginxSites(r.Context(), n.AgentHost, n.AgentPort, n.CertCN)
	if err != nil {
		http.Error(w, "failed to get nginx sites: "+err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if a.Templates != nil {
		if err := a.Templates.ExecuteTemplate(w, "nginx.html", map[string]any{"Node": n, "Sites": sites}); err != nil {
			log.Printf("template execution failed: %v", err)
		}
		return
	}

	w.Write([]byte("Nginx module loaded. (Templates not loaded)"))
}

func (a *API) nginxAction(w http.ResponseWriter, r *http.Request) {
	n := a.getNodeOr404(w, r)
	if n == nil {
		return
	}

	action := r.FormValue("action")
	if action != "reload" && action != "restart" && action != "test" {
		http.Error(w, "invalid action", http.StatusBadRequest)
		return
	}

	err := a.agentClient.ActionNginx(r.Context(), n.AgentHost, n.AgentPort, n.CertCN, action)
	if err != nil {
		http.Error(w, "agent error: "+err.Error(), http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/nodes/"+n.ID+"/nginx", http.StatusFound)
}

func (a *API) nginxSave(w http.ResponseWriter, r *http.Request) {
	n := a.getNodeOr404(w, r)
	if n == nil {
		return
	}

	name := r.FormValue("name")
	config := r.FormValue("config")
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}

	err := a.agentClient.SaveNginxSite(r.Context(), n.AgentHost, n.AgentPort, n.CertCN, name, config)
	if err != nil {
		http.Error(w, "agent error: "+err.Error(), http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/nodes/"+n.ID+"/nginx", http.StatusFound)
}

func (a *API) nginxToggle(w http.ResponseWriter, r *http.Request) {
	n := a.getNodeOr404(w, r)
	if n == nil {
		return
	}

	name := r.FormValue("name")
	enabled := r.FormValue("enabled") == "true"

	err := a.agentClient.ToggleNginxSite(r.Context(), n.AgentHost, n.AgentPort, n.CertCN, name, enabled)
	if err != nil {
		http.Error(w, "agent error: "+err.Error(), http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/nodes/"+n.ID+"/nginx", http.StatusFound)
}

func (a *API) nginxDelete(w http.ResponseWriter, r *http.Request) {
	n := a.getNodeOr404(w, r)
	if n == nil {
		return
	}

	name := r.FormValue("name")
	err := a.agentClient.DeleteNginxSite(r.Context(), n.AgentHost, n.AgentPort, n.CertCN, name)
	if err != nil {
		http.Error(w, "agent error: "+err.Error(), http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/nodes/"+n.ID+"/nginx", http.StatusFound)
}

type agentRegisterReq struct {
	Token  string `json:"token"`
	CSRPEM string `json:"csr_pem"`
	Name   string `json:"name"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
}

type agentRegisterResp struct {
	NodeID  string `json:"node_id"`
	CertPEM string `json:"cert_pem"`
	CAPEM   string `json:"ca_pem"`
	CertCN  string `json:"cert_cn"`
}

func (a *API) agentRegister(w http.ResponseWriter, r *http.Request) {
	var req agentRegisterReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if req.Token == "" || req.CSRPEM == "" || req.Name == "" || req.Host == "" || req.Port <= 0 {
		http.Error(w, "missing", http.StatusBadRequest)
		return
	}

	tokHash := sha256.Sum256([]byte(req.Token))
	var tokenID uuid.UUID
	var expires time.Time
	var usedAt sql.NullTime
	err := a.DB.QueryRowContext(r.Context(), `select id, expires_at, used_at from enroll_tokens where token_hash=$1`, tokHash[:]).Scan(&tokenID, &expires, &usedAt)
	if err != nil || usedAt.Valid || time.Now().After(expires) {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	_, _ = a.DB.ExecContext(r.Context(), `update enroll_tokens set used_at=now() where id=$1 and used_at is null`, tokenID)

	cn := "node-" + uuid.New().String()
	certPEM, err := a.CA.SignCSR([]byte(req.CSRPEM), cn)
	if err != nil {
		http.Error(w, "sign failed", http.StatusBadRequest)
		return
	}

	nodeID := uuid.New()

	// Check if a node with this IP/Host already exists. If so, overwrite it instead of duplicating.
	var existingID string
	err = a.DB.QueryRowContext(r.Context(), `select id from nodes where agent_host=$1`, req.Host).Scan(&existingID)
	if err == nil && existingID != "" {
		// Update existing node
		parsedID, _ := uuid.Parse(existingID)
		nodeID = parsedID
		_, err = a.DB.ExecContext(r.Context(), `update nodes set name=$1, agent_port=$2, server_cert_cn=$3, created_at=now() where id=$4`, req.Name, req.Port, cn, nodeID)
		if err != nil {
			http.Error(w, "db error during update", http.StatusInternalServerError)
			return
		}
	} else {
		// Insert new node
		_, err = a.DB.ExecContext(r.Context(), `insert into nodes (id, name, agent_host, agent_port, server_cert_cn) values ($1,$2,$3,$4,$5)`, nodeID, req.Name, req.Host, req.Port, cn)
		if err != nil {
			http.Error(w, "db error during insert", http.StatusInternalServerError)
			return
		}
	}

	resp := agentRegisterResp{NodeID: nodeID.String(), CertPEM: string(certPEM), CAPEM: string(a.CA.CertPEM), CertCN: cn}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func sign(key []byte, value string) (string, error) {
	if len(key) < 32 {
		return "", errors.New("cookie key too short")
	}
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(value))
	mac := h.Sum(nil)
	payload := value + "." + hex.EncodeToString(mac[:])
	return base64.RawURLEncoding.EncodeToString([]byte(payload)), nil
}

func verify(key []byte, signed string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(signed)
	if err != nil {
		return "", err
	}
	parts := strings.Split(string(b), ".")
	if len(parts) != 2 {
		return "", errors.New("invalid cookie")
	}
	value := parts[0]
	got := parts[1]
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(value))
	want := hex.EncodeToString(h.Sum(nil))
	if got != want {
		return "", errors.New("bad mac")
	}
	return value, nil
}

func (a *API) apiEnrollCommand(w http.ResponseWriter, r *http.Request) {
	tok, err := NewEnrollmentToken(r.Context(), a.DB, 24*time.Hour)
	if err != nil {
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}

	cmd := fmt.Sprintf(`curl -sSL https://raw.githubusercontent.com/anower93/vpspanel/main/install/agent-alma9.sh | VPSPANEL_PANEL_URL="%s" VPSPANEL_ENROLL_TOKEN="%s" bash`, a.PublicURL, tok)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token":   tok,
		"command": cmd,
	})
}

func NewEnrollmentToken(ctx context.Context, db *sql.DB, ttl time.Duration) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b)
	h := sha256.Sum256([]byte(tok))
	_, err := db.ExecContext(ctx, `insert into enroll_tokens (id, token_hash, expires_at) values (gen_random_uuid(), $1, $2)`, h[:], time.Now().Add(ttl))
	if err != nil {
		return "", err
	}
	return tok, nil
}
