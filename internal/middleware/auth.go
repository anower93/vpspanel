package middleware

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"vpspanel/internal/services"

	"github.com/gin-gonic/gin"
)

func Setup(r *gin.Engine, auth *services.AuthService, config *services.Config) {
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	r.Use(SecurityHeaders())
	if len(config.Security.AllowedIPs) > 0 {
		r.Use(IPAllowList(config.Security.AllowedIPs))
	}
	r.Use(SameOriginProtection())
}

func AuthRequired(auth *services.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := auth.GetSession(c.Request)
		if session == nil {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}
		c.Set("session", session)
		c.Next()
	}
}

func RequireUnsafe(config *services.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		if config.Security.SafeMode {
			c.String(http.StatusForbidden, "Disabled in safe mode")
			c.Abort()
			return
		}
		c.Next()
	}
}

func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' https://cdn.tailwindcss.com https://cdn.jsdelivr.net 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; connect-src 'self'")
		c.Next()
	}
}

func SameOriginProtection() gin.HandlerFunc {
	return func(c *gin.Context) {
		m := c.Request.Method
		if m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions {
			c.Next()
			return
		}

		origin := c.Request.Header.Get("Origin")
		referer := c.Request.Header.Get("Referer")
		if origin == "" && referer == "" {
			c.String(http.StatusForbidden, "Missing Origin/Referer")
			c.Abort()
			return
		}

		host := c.Request.Host
		if origin != "" {
			u, err := url.Parse(origin)
			if err != nil || !sameHost(u.Host, host) {
				c.String(http.StatusForbidden, "Bad Origin")
				c.Abort()
				return
			}
		}
		if referer != "" {
			u, err := url.Parse(referer)
			if err != nil || !sameHost(u.Host, host) {
				c.String(http.StatusForbidden, "Bad Referer")
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

func sameHost(a, b string) bool {
	a = strings.ToLower(stripPort(a))
	b = strings.ToLower(stripPort(b))
	return a != "" && a == b
}

func stripPort(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

func IPAllowList(allowed []string) gin.HandlerFunc {
	allowedIPs := make(map[string]struct{}, len(allowed))
	allowedNets := make([]*net.IPNet, 0)
	for _, a := range allowed {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if strings.Contains(a, "/") {
			_, n, err := net.ParseCIDR(a)
			if err == nil {
				allowedNets = append(allowedNets, n)
			}
			continue
		}
		allowedIPs[a] = struct{}{}
	}

	return func(c *gin.Context) {
		ipStr := c.ClientIP()
		if _, ok := allowedIPs[ipStr]; ok {
			c.Next()
			return
		}
		ip := net.ParseIP(ipStr)
		for _, n := range allowedNets {
			if ip != nil && n.Contains(ip) {
				c.Next()
				return
			}
		}
		c.String(http.StatusForbidden, "IP not allowed")
		c.Abort()
	}
}

type RateLimiter struct {
	mu     sync.Mutex
	visits map[string][]time.Time
	limit  int
	window time.Duration
}

func RateLimit(l *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.ClientIP()
		if !l.Allow(key) {
			c.String(http.StatusTooManyRequests, "Too many requests")
			c.Abort()
			return
		}
		c.Next()
	}
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{visits: make(map[string][]time.Time), limit: limit, window: window}
}

func (r *RateLimiter) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-r.window)
	arr := r.visits[key]
	kept := arr[:0]
	for _, t := range arr {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= r.limit {
		r.visits[key] = kept
		return false
	}
	kept = append(kept, now)
	r.visits[key] = kept
	return true
}
