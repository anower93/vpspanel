package services

import (
	"net/http"
	"sync"

	"github.com/gorilla/securecookie"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	config      *Config
	cookieStore *securecookie.SecureCookie
	sessions    map[string]*Session
	sessionsMu  sync.RWMutex
}

type Session struct {
	Username  string
	CSRFToken string
}

func NewAuthService(config *Config) *AuthService {
	return &AuthService{
		config: config,
		cookieStore: securecookie.New(
			[]byte(config.Auth.SessionSecret),
			[]byte("vpspanel-session-hash"),
		),
		sessions: make(map[string]*Session),
	}
}

func (s *AuthService) ValidateUser(username, password string) bool {
	if username != s.config.Auth.Username {
		return false
	}

	err := bcrypt.CompareHashAndPassword([]byte(s.config.Auth.Password), []byte(password))
	return err == nil
}

func (s *AuthService) CreateSession(w http.ResponseWriter, username string) error {
	session := &Session{
		Username:  username,
		CSRFToken: generateCSRFToken(),
	}

	sessionID := generateSessionID()
	s.sessionsMu.Lock()
	s.sessions[sessionID] = session
	s.sessionsMu.Unlock()

	encoded, err := s.cookieStore.Encode("session", sessionID)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    encoded,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})

	return nil
}

func (s *AuthService) GetSession(r *http.Request) *Session {
	cookie, err := r.Cookie("session")
	if err != nil {
		return nil
	}

	var sessionID string
	if err := s.cookieStore.Decode("session", cookie.Value, &sessionID); err != nil {
		return nil
	}

	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()
	return s.sessions[sessionID]
}

func (s *AuthService) DestroySession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil {
		return
	}

	var sessionID string
	if err := s.cookieStore.Decode("session", cookie.Value, &sessionID); err != nil {
		return
	}

	s.sessionsMu.Lock()
	delete(s.sessions, sessionID)
	s.sessionsMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
}

func (s *AuthService) HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

func (s *AuthService) Config() *Config {
	return s.config
}
