package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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
}

type API struct {
	Deps
}

func New(d Deps) http.Handler {
	a := &API{Deps: d}
	r := chi.NewRouter()

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	r.Get("/login", a.loginPage)
	r.Post("/login", a.login)
	r.Post("/logout", a.logout)
	r.Get("/", a.requireSession(a.dashboard))

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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("<h1>VPS Panel</h1><p>Logged in.</p>"))
}

func (a *API) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
		next(w, r)
	}
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
	_, err = a.DB.ExecContext(r.Context(), `insert into nodes (id, name, agent_host, agent_port, server_cert_cn) values ($1,$2,$3,$4,$5)`, nodeID, req.Name, req.Host, req.Port, cn)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
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
