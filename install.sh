#!/bin/bash

set -e

echo "Installing VPS Panel..."

# Install Go (always do this to ensure it's available)
echo "Installing Go..."
if [ -f /tmp/go.tar.gz ]; then
    rm -f /tmp/go.tar.gz
fi
wget -q https://go.dev/dl/go1.21.6.linux-amd64.tar.gz -O /tmp/go.tar.gz
rm -rf /usr/local/go
tar -C /usr/local -xzf /tmp/go.tar.gz
rm -f /tmp/go.tar.gz

# Set paths
export PATH=/usr/local/go/bin:$PATH
export GOROOT=/usr/local/go

# Generate random password and session secret
PASSWORD=$(openssl rand -base64 12)
SESSION_SECRET=$(openssl rand -base64 32)

# Create project directory
mkdir -p /opt/vpspanel/{cmd,internal/{handlers,middleware,services,templates,static/css},config}

# Create go.mod
cat > /opt/vpspanel/go.mod << 'EOF'
module vpspanel

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/gorilla/securecookie v1.1.2
	github.com/shirou/gopsutil/v3 v3.23.12
	golang.org/x/crypto v0.18.0
	gopkg.in/yaml.v3 v3.0.1
)
EOF

# Create config.yaml
cat > /opt/vpspanel/config/config.yaml << EOF
server:
  port: "8080"
  host: "0.0.0.0"

auth:
  username: "admin"
  password: "$PASSWORD"
  session_secret: "$SESSION_SECRET"

security:
  allowed_ips: []
  require_2fa: false
EOF

# Create main.go
cat > /opt/vpspanel/cmd/main.go << 'MAINEOF'
package main

import (
	"log"
	"vpspanel/internal/handlers"
	"vpspanel/internal/middleware"
	"vpspanel/internal/services"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	r.SetTrustedProxies(nil)

	config, err := services.LoadConfig("config/config.yaml")
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

	authService := services.NewAuthService(config)
	handlers := handlers.NewHandlers(authService, config)

	middleware.Setup(r, authService)

	r.GET("/", handlers.Home)
	r.GET("/login", handlers.LoginPage)
	r.POST("/login", handlers.Login)
	r.GET("/logout", handlers.Logout)

	admin := r.Group("/admin")
	admin.Use(middleware.AuthRequired(authService))
	{
		admin.GET("/dashboard", handlers.Dashboard)
		admin.GET("/system", handlers.SystemInfo)
		admin.GET("/processes", handlers.Processes)
		admin.POST("/processes/kill/:pid", handlers.KillProcess)
		admin.GET("/files/*path", handlers.FileManager)
		admin.POST("/files/upload", handlers.UploadFile)
		admin.POST("/files/create", handlers.CreateFile)
		admin.POST("/files/delete", handlers.DeleteFile)
		admin.POST("/files/rename", handlers.RenameFile)
		admin.GET("/terminal", handlers.Terminal)
		admin.POST("/terminal/exec", handlers.TerminalExec)
		admin.GET("/nginx", handlers.NginxManager)
		admin.POST("/nginx/reload", handlers.NginxReload)
		admin.POST("/nginx/restart", handlers.NginxRestart)
		admin.GET("/apache", handlers.ApacheManager)
		admin.POST("/apache/reload", handlers.ApacheReload)
		admin.POST("/apache/restart", handlers.ApacheRestart)
		admin.GET("/mysql", handlers.MySQLManager)
		admin.POST("/mysql/restart", handlers.MySQLRestart)
		admin.GET("/postgres", handlers.PostgresManager)
		admin.POST("/postgres/restart", handlers.PostgresRestart)
		admin.GET("/dns", handlers.DNSManager)
		admin.POST("/dns/create-zone", handlers.CreateDNSZone)
		admin.POST("/dns/delete-zone", handlers.DeleteDNSZone)
		admin.GET("/services", handlers.Services)
		admin.POST("/services/restart", handlers.RestartService)
	}

	r.Static("/static", "./internal/static")
	r.LoadHTMLGlob("./internal/templates/*.html")

	port := config.Server.Port
	if port == "" {
		port = "8080"
	}
	log.Printf("Server starting on port %s", port)
	log.Printf("Username: admin")
	log.Printf("Password: %s", "$PASSWORD")
	if err := r.Run(":" + port); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
MAINEOF

# Fix password in main.go - escape special chars
ESCAPED_PASSWORD=$(printf '%s' "$PASSWORD" | sed 's/[\/&]/\\&/g')
sed -i "s/\\\$PASSWORD/$ESCAPED_PASSWORD/" /opt/vpspanel/cmd/main.go

# Create services
cat > /opt/vpspanel/internal/services/config.go << 'EOF'
package services

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Auth     AuthConfig     `yaml:"auth"`
	Security SecurityConfig `yaml:"security"`
}

type ServerConfig struct {
	Port string `yaml:"port"`
	Host string `yaml:"host"`
}

type AuthConfig struct {
	Username      string `yaml:"username"`
	Password      string `yaml:"password"`
	SessionSecret string `yaml:"session_secret"`
}

type SecurityConfig struct {
	AllowedIPs []string `yaml:"allowed_ips"`
	Require2FA bool     `yaml:"require_2fa"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}
EOF

cat > /opt/vpspanel/internal/services/auth.go << 'EOF'
package services

import (
	"net/http"
	"sync"

	"github.com/gorilla/securecookie"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	config       *Config
	cookieStore  *securecookie.SecureCookie
	sessions     map[string]*Session
	sessionsMu   sync.RWMutex
}

type Session struct {
	Username string
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
		Username: username,
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
		Name: "session", Value: encoded, Path: "/", HttpOnly: true,
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

	http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", MaxAge: -1})
}

func (s *AuthService) HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

func (s *AuthService) Config() *Config {
	return s.config
}
EOF

cat > /opt/vpspanel/internal/services/helpers.go << 'EOF'
package services

import (
	"crypto/rand"
	"encoding/hex"
)

func generateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateCSRFToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}
EOF

# Create middleware
cat > /opt/vpspanel/internal/middleware/auth.go << 'EOF'
package middleware

import (
	"net/http"
	"vpspanel/internal/services"

	"github.com/gin-gonic/gin"
)

func Setup(r *gin.Engine, auth *services.AuthService) {
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
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
EOF

# Create handlers
cat > /opt/vpspanel/internal/handlers/handlers.go << 'EOF'
package handlers

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"vpspanel/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

type Handlers struct {
	auth   *services.AuthService
	config *services.Config
}

func NewHandlers(auth *services.AuthService, config *services.Config) *Handlers {
	return &Handlers{auth: auth, config: config}
}

func (h *Handlers) Home(c *gin.Context) {
	c.Redirect(http.StatusFound, "/admin/dashboard")
}

func (h *Handlers) LoginPage(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{"Title": "Login - VPS Panel"})
}

func (h *Handlers) Login(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	if h.auth.ValidateUser(username, password) {
		h.auth.CreateSession(c.Writer, username)
		c.Redirect(http.StatusFound, "/admin/dashboard")
		return
	}

	c.HTML(http.StatusOK, "login.html", gin.H{
		"Title": "Login - VPS Panel", "Error": "Invalid credentials", "Username": username,
	})
}

func (h *Handlers) Logout(c *gin.Context) {
	h.auth.DestroySession(c.Writer, c.Request)
	c.Redirect(http.StatusFound, "/login")
}

func (h *Handlers) Dashboard(c *gin.Context) {
	cpuPercent, _ := cpu.Percent(time.Second, false)
	memInfo, _ := mem.VirtualMemory()
	diskInfo, _ := disk.Usage("/")
	hostInfo, _ := host.Info()
	netInfo, _ := net.NetIOCounters(false)
	uptime := time.Duration(hostInfo.Uptime) * time.Second

	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"Title": "Dashboard - VPS Panel",
		"CPU": cpuPercent[0], "MemUsed": memInfo.UsedPercent, "MemTotal": memInfo.Total / 1024 / 1024 / 1024,
		"MemUsedGB": memInfo.Used / 1024 / 1024 / 1024, "DiskUsed": diskInfo.UsedPercent,
		"DiskTotal": diskInfo.Total / 1024 / 1024 / 1024, "DiskUsedGB": diskInfo.Used / 1024 / 1024 / 1024,
		"Hostname": hostInfo.Hostname, "OS": hostInfo.OS, "Platform": hostInfo.Platform, "Uptime": uptime.String(),
		"NetIn": netInfo[0].BytesRecv, "NetOut": netInfo[0].BytesSent,
	})
}

func (h *Handlers) SystemInfo(c *gin.Context) {
	cpuInfo, _ := cpu.Info()
	memInfo, _ := mem.VirtualMemory()
	diskInfo, _ := disk.Usage("/")
	hostInfo, _ := host.Info()

	c.HTML(http.StatusOK, "system.html", gin.H{
		"Title": "System Info - VPS Panel", "CPUInfo": cpuInfo, "MemInfo": memInfo, "DiskInfo": diskInfo, "HostInfo": hostInfo,
	})
}

func (h *Handlers) Processes(c *gin.Context) {
	procs, _ := process.Processes()
	var processList []gin.H
	for _, p := range procs {
		name, _ := p.Name()
		mem, _ := p.MemoryInfo()
		cpu, _ := p.CPUPercent()
		processList = append(processList, gin.H{"PID": p.Pid, "Name": name, "MemRSS": mem.RSS / 1024 / 1024, "CPU": cpu})
	}

	c.HTML(http.StatusOK, "processes.html", gin.H{"Title": "Processes - VPS Panel", "Processes": processList})
}

func (h *Handlers) KillProcess(c *gin.Context) {
	pid, _ := strconv.Atoi(c.Param("pid"))
	p, err := process.NewProcess(int32(pid))
	if err == nil {
		p.Kill()
	}
	c.Redirect(http.StatusFound, "/admin/processes")
}

func (h *Handlers) FileManager(c *gin.Context) {
	path := c.Param("path")
	if path == "" || path == "/" {
		path = "/"
	}

	files := make([]gin.H, 0)
	entries, err := os.ReadDir(path)
	if err == nil {
		for _, e := range entries {
			info, _ := e.Info()
			files = append(files, gin.H{"Name": e.Name(), "IsDir": e.IsDir(), "Size": info.Size(), "Mode": info.Mode().String(), "ModTime": info.ModTime().Format("2006-01-02 15:04")})
		}
	}

	parent := filepath.Dir(path)
	if parent == path {
		parent = "/"
	}

	c.HTML(http.StatusOK, "files.html", gin.H{"Title": "File Manager - VPS Panel", "Path": path, "Parent": parent, "Files": files})
}

func (h *Handlers) UploadFile(c *gin.Context) {
	path := c.PostForm("path")
	file, err := c.FormFile("file")
	if err == nil {
		dst := filepath.Join(path, file.Filename)
		c.SaveUploadedFile(file, dst)
	}
	c.Redirect(http.StatusFound, "/admin/files"+path)
}

func (h *Handlers) CreateFile(c *gin.Context) {
	path := c.PostForm("path")
	name := c.PostForm("name")
	fileType := c.PostForm("type")
	fullPath := filepath.Join(path, name)

	if fileType == "directory" {
		os.MkdirAll(fullPath, 0755)
	} else {
		os.WriteFile(fullPath, []byte(""), 0644)
	}
	c.Redirect(http.StatusFound, "/admin/files"+path)
}

func (h *Handlers) DeleteFile(c *gin.Context) {
	path := c.PostForm("path")
	os.RemoveAll(path)
	parent := filepath.Dir(path)
	c.Redirect(http.StatusFound, "/admin/files"+parent)
}

func (h *Handlers) RenameFile(c *gin.Context) {
	oldPath := c.PostForm("path")
	newName := c.PostForm("name")
	newPath := filepath.Join(filepath.Dir(oldPath), newName)
	os.Rename(oldPath, newPath)
	c.Redirect(http.StatusFound, "/admin/files"+filepath.Dir(newPath))
}

func (h *Handlers) Terminal(c *gin.Context) {
	c.HTML(http.StatusOK, "terminal.html", gin.H{"Title": "Terminal - VPS Panel"})
}

func (h *Handlers) TerminalExec(c *gin.Context) {
	cmd := c.PostForm("cmd")
	parts := strings.Fields(cmd)
	out, err := exec.Command(parts[0], parts[1:]...).Output()
	if err != nil {
		out = []byte(err.Error())
	}
	c.String(http.StatusOK, string(out))
}

func (h *Handlers) NginxManager(c *gin.Context) {
	status := h.getServiceStatus("nginx")
	var configs []string
	if files, err := filepath.Glob("/etc/nginx/sites-enabled/*"); err == nil {
		for _, f := range files {
			configs = append(configs, filepath.Base(f))
		}
	}
	c.HTML(http.StatusOK, "nginx.html", gin.H{"Title": "Nginx Manager - VPS Panel", "Status": status, "Configs": configs})
}

func (h *Handlers) NginxReload(c *gin.Context) { exec.Command("systemctl", "reload", "nginx").Run(); c.Redirect(http.StatusFound, "/admin/nginx") }
func (h *Handlers) NginxRestart(c *gin.Context) { exec.Command("systemctl", "restart", "nginx").Run(); c.Redirect(http.StatusFound, "/admin/nginx") }

func (h *Handlers) ApacheManager(c *gin.Context) {
	status := h.getServiceStatus("apache2")
	var configs []string
	if files, err := filepath.Glob("/etc/apache2/sites-enabled/*"); err == nil {
		for _, f := range files {
			configs = append(configs, filepath.Base(f))
		}
	}
	c.HTML(http.StatusOK, "apache.html", gin.H{"Title": "Apache Manager - VPS Panel", "Status": status, "Configs": configs})
}

func (h *Handlers) ApacheReload(c *gin.Context) { exec.Command("systemctl", "reload", "apache2").Run(); c.Redirect(http.StatusFound, "/admin/apache") }
func (h *Handlers) ApacheRestart(c *gin.Context) { exec.Command("systemctl", "restart", "apache2").Run(); c.Redirect(http.StatusFound, "/admin/apache") }

func (h *Handlers) MySQLManager(c *gin.Context) {
	status := h.getServiceStatus("mysql")
	c.HTML(http.StatusOK, "mysql.html", gin.H{"Title": "MySQL Manager - VPS Panel", "Status": status})
}

func (h *Handlers) MySQLRestart(c *gin.Context) { exec.Command("systemctl", "restart", "mysql").Run(); c.Redirect(http.StatusFound, "/admin/mysql") }

func (h *Handlers) PostgresManager(c *gin.Context) {
	status := h.getServiceStatus("postgresql")
	c.HTML(http.StatusOK, "postgres.html", gin.H{"Title": "PostgreSQL Manager - VPS Panel", "Status": status})
}

func (h *Handlers) PostgresRestart(c *gin.Context) { exec.Command("systemctl", "restart", "postgresql").Run(); c.Redirect(http.StatusFound, "/admin/postgres") }

func (h *Handlers) DNSManager(c *gin.Context) {
	var zones []string
	if files, err := filepath.Glob("/etc/bind/zones/*"); err == nil {
		for _, f := range files {
			zones = append(zones, filepath.Base(f))
		}
	}
	c.HTML(http.StatusOK, "dns.html", gin.H{"Title": "DNS Manager - VPS Panel", "Zones": zones})
}

func (h *Handlers) CreateDNSZone(c *gin.Context) { c.Redirect(http.StatusFound, "/admin/dns") }
func (h *Handlers) DeleteDNSZone(c *gin.Context) { c.Redirect(http.StatusFound, "/admin/dns") }

func (h *Handlers) Services(c *gin.Context) {
	services := []string{"nginx", "apache2", "mysql", "postgresql", "docker", "sshd", "fail2ban", "cron"}
	serviceList := make([]gin.H, 0)
	for _, s := range services {
		status := h.getServiceStatus(s)
		serviceList = append(serviceList, gin.H{"Name": s, "Status": status})
	}
	c.HTML(http.StatusOK, "services.html", gin.H{"Title": "Services - VPS Panel", "Services": serviceList})
}

func (h *Handlers) RestartService(c *gin.Context) {
	name := c.PostForm("name")
	exec.Command("systemctl", "restart", name).Run()
	c.Redirect(http.StatusFound, "/admin/services")
}

func (h *Handlers) getServiceStatus(name string) string {
	cmd := exec.Command("systemctl", "is-active", name)
	out, _ := cmd.Output()
	return strings.TrimSpace(string(out))
}
EOF

# Create templates
cat > /opt/vpspanel/internal/templates/login.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body class="login-page">
    <div class="login-box">
        <h1>VPS Panel</h1>
        {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
        <form method="POST" action="/login">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" value="{{.Username}}" required>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
EOF

cat > /opt/vpspanel/internal/templates/dashboard.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="sidebar">
        <div class="logo">VPS Panel</div>
        <nav>
            <a href="/admin/dashboard">Dashboard</a>
            <a href="/admin/system">System Info</a>
            <a href="/admin/processes">Processes</a>
            <a href="/admin/files">Files</a>
            <a href="/admin/terminal">Terminal</a>
            <a href="/admin/services">Services</a>
            <a href="/admin/nginx">Nginx</a>
            <a href="/admin/apache">Apache</a>
            <a href="/admin/mysql">MySQL</a>
            <a href="/admin/postgres">PostgreSQL</a>
            <a href="/logout">Logout</a>
        </nav>
    </div>
    <div class="main">
        <div class="header"><h1>{{.Title}}</h1></div>
        <div class="content">
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>System</h3>
                    <p>Hostname: {{.Hostname}}</p>
                    <p>OS: {{.OS}}</p>
                    <p>Platform: {{.Platform}}</p>
                    <p>Uptime: {{.Uptime}}</p>
                </div>
                <div class="stat-card">
                    <h3>CPU</h3>
                    <div class="progress-bar"><div class="progress" style="width: {{.CPU}}%">{{printf "%.1f" .CPU}}%</div></div>
                </div>
                <div class="stat-card">
                    <h3>Memory</h3>
                    <div class="progress-bar"><div class="progress" style="width: {{.MemUsed}}%">{{printf "%.1f" .MemUsed}}%</div></div>
                    <p>{{.MemUsedGB}} GB / {{.MemTotal}} GB</p>
                </div>
                <div class="stat-card">
                    <h3>Disk</h3>
                    <div class="progress-bar"><div class="progress" style="width: {{.DiskUsed}}%">{{printf "%.1f" .DiskUsed}}%</div></div>
                    <p>{{.DiskUsedGB}} GB / {{.DiskTotal}} GB</p>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
EOF

cat > /opt/vpspanel/internal/templates/system.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{.Title}}</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="sidebar">
        <div class="logo">VPS Panel</div>
        <nav>
            <a href="/admin/dashboard">Dashboard</a>
            <a href="/admin/system">System Info</a>
            <a href="/admin/processes">Processes</a>
            <a href="/admin/files">Files</a>
            <a href="/admin/terminal">Terminal</a>
            <a href="/admin/services">Services</a>
            <a href="/admin/nginx">Nginx</a>
            <a href="/admin/apache">Apache</a>
            <a href="/admin/mysql">MySQL</a>
            <a href="/logout">Logout</a>
        </nav>
    </div>
    <div class="main">
        <div class="header"><h1>{{.Title}}</h1></div>
        <div class="content">
            <div class="info-grid">
                <div class="info-card">
                    <h3>Host Info</h3>
                    <p>Hostname: {{.HostInfo.Hostname}}</p>
                    <p>OS: {{.HostInfo.OS}}</p>
                    <p>Kernel: {{.HostInfo.KernelVersion}}</p>
                </div>
                <div class="info-card">
                    <h3>Memory</h3>
                    <p>Total: {{.MemInfo.Total}}</p>
                    <p>Available: {{.MemInfo.Available}}</p>
                    <p>Used: {{.MemInfo.Used}}</p>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
EOF

cat > /opt/vpspanel/internal/templates/processes.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><title>{{.Title}}</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="sidebar">
        <div class="logo">VPS Panel</div>
        <nav>
            <a href="/admin/dashboard">Dashboard</a>
            <a href="/admin/system">System Info</a>
            <a href="/admin/processes">Processes</a>
            <a href="/admin/files">Files</a>
            <a href="/admin/terminal">Terminal</a>
            <a href="/admin/services">Services</a>
            <a href="/logout">Logout</a>
        </nav>
    </div>
    <div class="main">
        <div class="header"><h1>{{.Title}}</h1></div>
        <div class="content">
            <table class="data-table">
                <thead><tr><th>PID</th><th>Name</th><th>Memory (MB)</th><th>CPU %</th><th>Action</th></tr></thead>
                <tbody>
                    {{range .Processes}}
                    <tr><td>{{.PID}}</td><td>{{.Name}}</td><td>{{.MemRSS}}</td><td>{{printf "%.1f" .CPU}}</td>
                    <td><a href="/admin/processes/kill/{{.PID}}" class="btn-danger">Kill</a></td></tr>
                    {{end}}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
EOF

cat > /opt/vpspanel/internal/templates/files.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><title>{{.Title}}</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="sidebar">
        <div class="logo">VPS Panel</div>
        <nav>
            <a href="/admin/dashboard">Dashboard</a>
            <a href="/admin/files">Files</a>
            <a href="/admin/terminal">Terminal</a>
            <a href="/logout">Logout</a>
        </nav>
    </div>
    <div class="main">
        <div class="header"><h1>{{.Title}}</h1></div>
        <div class="content">
            <div class="toolbar">
                <a href="/admin/files{{.Parent}}" class="btn">Parent</a>
            </div>
            <p>Path: {{.Path}}</p>
            <table class="data-table">
                <thead><tr><th>Name</th><th>Type</th><th>Size</th><th>Actions</th></tr></thead>
                <tbody>
                    {{range .Files}}
                    <tr>
                        <td>{{if .IsDir}}<a href="/admin/files{{$.Path}}{{.Name}}/">📁 {{.Name}}</a>{{else}}📄 {{.Name}}{{end}}</td>
                        <td>{{if .IsDir}}Dir{{else}}File{{end}}</td>
                        <td>{{.Size}}</td>
                        <td>
                            <form method="POST" action="/admin/files/delete" style="display:inline">
                                <input type="hidden" name="path" value="{{$.Path}}{{.Name}}">
                                <button type="submit" class="btn-danger">Delete</button>
                            </form>
                        </td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
EOF

cat > /opt/vpspanel/internal/templates/terminal.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><title>{{.Title}}</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="sidebar">
        <div class="logo">VPS Panel</div>
        <nav>
            <a href="/admin/dashboard">Dashboard</a>
            <a href="/admin/terminal">Terminal</a>
            <a href="/logout">Logout</a>
        </nav>
    </div>
    <div class="main">
        <div class="header"><h1>{{.Title}}</h1></div>
        <div class="content">
            <div class="terminal">
                <div class="terminal-output" id="output"></div>
                <div class="terminal-input">
                    <span>$</span>
                    <input type="text" id="cmd" placeholder="Enter command..." autofocus>
                    <button onclick="execute()">Run</button>
                </div>
            </div>
        </div>
    </div>
    <script>
    async function execute() {
        const cmd = document.getElementById('cmd').value;
        const output = document.getElementById('output');
        output.innerHTML += '<div>$ ' + cmd + '</div>';
        const res = await fetch('/admin/terminal/exec', {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: 'cmd=' + encodeURIComponent(cmd)});
        const text = await res.text();
        output.innerHTML += '<pre>' + text + '</pre>';
        output.scrollTop = output.scrollHeight;
        document.getElementById('cmd').value = '';
    }
    document.getElementById('cmd').addEventListener('keypress', function(e) { if (e.key === 'Enter') execute(); });
    </script>
</body>
</html>
EOF

cat > /opt/vpspanel/internal/templates/services.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><title>{{.Title}}</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="sidebar">
        <div class="logo">VPS Panel</div>
        <nav>
            <a href="/admin/dashboard">Dashboard</a>
            <a href="/admin/services">Services</a>
            <a href="/logout">Logout</a>
        </nav>
    </div>
    <div class="main">
        <div class="header"><h1>{{.Title}}</h1></div>
        <div class="content">
            <table class="data-table">
                <thead><tr><th>Service</th><th>Status</th><th>Actions</th></tr></thead>
                <tbody>
                    {{range .Services}}
                    <tr><td>{{.Name}}</td><td class="status-{{.Status}}">{{.Status}}</td>
                    <td><form method="POST" action="/admin/services/restart"><input type="hidden" name="name" value="{{.Name}}"><button type="submit">Restart</button></form></td></tr>
                    {{end}}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
EOF

cat > /opt/vpspanel/internal/templates/nginx.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><title>{{.Title}}</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="sidebar">
        <div class="logo">VPS Panel</div>
        <nav>
            <a href="/admin/dashboard">Dashboard</a>
            <a href="/admin/nginx">Nginx</a>
            <a href="/admin/apache">Apache</a>
            <a href="/logout">Logout</a>
        </nav>
    </div>
    <div class="main">
        <div class="header"><h1>{{.Title}}</h1></div>
        <div class="content">
            <h3>Status: <span class="status-{{.Status}}">{{.Status}}</span></h3>
            <div class="actions">
                <form method="POST" action="/admin/nginx/reload"><button type="submit">Reload</button></form>
                <form method="POST" action="/admin/nginx/restart"><button type="submit" class="btn-danger">Restart</button></form>
            </div>
        </div>
    </div>
</body>
</html>
EOF

cat > /opt/vpspanel/internal/templates/apache.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><title>{{.Title}}</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="sidebar">
        <div class="logo">VPS Panel</div>
        <nav>
            <a href="/admin/dashboard">Dashboard</a>
            <a href="/admin/nginx">Nginx</a>
            <a href="/admin/apache">Apache</a>
            <a href="/logout">Logout</a>
        </nav>
    </div>
    <div class="main">
        <div class="header"><h1>{{.Title}}</h1></div>
        <div class="content">
            <h3>Status: <span class="status-{{.Status}}">{{.Status}}</span></h3>
            <div class="actions">
                <form method="POST" action="/admin/apache/reload"><button type="submit">Reload</button></form>
                <form method="POST" action="/admin/apache/restart"><button type="submit" class="btn-danger">Restart</button></form>
            </div>
        </div>
    </div>
</body>
</html>
EOF

cat > /opt/vpspanel/internal/templates/mysql.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><title>{{.Title}}</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="sidebar">
        <div class="logo">VPS Panel</div>
        <nav>
            <a href="/admin/dashboard">Dashboard</a>
            <a href="/admin/mysql">MySQL</a>
            <a href="/logout">Logout</a>
        </nav>
    </div>
    <div class="main">
        <div class="header"><h1>{{.Title}}</h1></div>
        <div class="content">
            <h3>Status: <span class="status-{{.Status}}">{{.Status}}</span></h3>
            <form method="POST" action="/admin/mysql/restart"><button type="submit" class="btn-danger">Restart</button></form>
        </div>
    </div>
</body>
</html>
EOF

cat > /opt/vpspanel/internal/templates/postgres.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><title>{{.Title}}</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="sidebar">
        <div class="logo">VPS Panel</div>
        <nav>
            <a href="/admin/dashboard">Dashboard</a>
            <a href="/admin/postgres">PostgreSQL</a>
            <a href="/logout">Logout</a>
        </nav>
    </div>
    <div class="main">
        <div class="header"><h1>{{.Title}}</h1></div>
        <div class="content">
            <h3>Status: <span class="status-{{.Status}}">{{.Status}}</span></h3>
            <form method="POST" action="/admin/postgres/restart"><button type="submit" class="btn-danger">Restart</button></form>
        </div>
    </div>
</body>
</html>
EOF

cat > /opt/vpspanel/internal/templates/dns.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><title>{{.Title}}</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="sidebar">
        <div class="logo">VPS Panel</div>
        <nav><a href="/admin/dashboard">Dashboard</a><a href="/logout">Logout</a></nav>
    </div>
    <div class="main">
        <div class="header"><h1>{{.Title}}</h1></div>
        <div class="content"><p>DNS zone management</p></div>
    </div>
</body>
</html>
EOF

# Create CSS
cat > /opt/vpspanel/internal/static/css/style.css << 'EOF'
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f5f5f5;display:flex;min-height:100vh}
.sidebar{width:220px;background:#1a1a2e;color:white;padding:20px 0;position:fixed;height:100vh}
.sidebar .logo{font-size:24px;font-weight:bold;padding 20px :020px;border-bottom:1px solid #333;margin-bottom:20px}
.sidebar nav a{display:block;color:#ccc;padding:12px 20px;text-decoration:none}
.sidebar nav a:hover{background:#16213e;color:white}
.main{margin-left:220px;flex:1;padding:20px}
.header{background:white;padding:20px;border-radius:8px;margin-bottom:20px;box-shadow:0 2px 4px rgba(0,0,0,0.1)}
.header h1{font-size:24px;color:#333}
.content{background:white;padding:20px;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,0.1)}
.login-page{display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#1a1a2e,#16213e)}
.login-box{background:white;padding:40px;border-radius:10px;width:400px;box-shadow:0 10px 40px rgba(0,0,0,0.3)}
.login-box h1{text-align:center;margin-bottom:30px;color:#1a1a2e}
.form-group{margin-bottom:20px}
.form-group label{display:block;margin-bottom:5px;color:#555;font-weight:500}
.form-group input{width:100%;padding:12px;border:1px solid #ddd;border-radius:5px;font-size:14px}
.login-box button{width:100%;padding:12px;background:#1a1a2e;color:white;border:none;border-radius:5px;font-size:16px;cursor:pointer}
.error{background:#fee;color:#c00;padding:10px;border-radius:5px;margin-bottom:20px}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:20px}
.stat-card{background:#f8f9fa;padding:20px;border-radius:8px;border-left:4px solid #1a1a2e}
.stat-card h3{margin-bottom:15px;color:#333}
.progress-bar{background:#e9ecef;height:25px;border-radius:5px;overflow:hidden;margin:10px 0}
.progress{background:#1a1a2e;height:100%;display:flex;align-items:center;justify-content:center;color:white;font-size:12px;font-weight:bold}
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px}
.info-card{background:#f8f9fa;padding:20px;border-radius:8px}
.data-table{width:100%;border-collapse:collapse}
.data-table th,.data-table td{padding:12px;text-align:left;border-bottom:1px solid #eee}
.data-table th{background:#f8f9fa;font-weight:600;color:#333}
.btn{padding:8px 16px;background:#1a1a2e;color:white;text-decoration:none;border-radius:5px;border:none;cursor:pointer;font-size:14px}
.btn-danger{padding:8px 16px;background:#dc3545;color:white;border-radius:5px;border:none;cursor:pointer;font-size:14px}
.terminal{background:#1e1e1e;border-radius:8px;overflow:hidden;height:500px;display:flex;flex-direction:column}
.terminal-output{flex:1;padding:15px;color:#d4d4d4;font-family:'Courier New',monospace;overflow-y:auto}
.terminal-output pre{white-space:pre-wrap;margin:5px 0}
.terminal-input{display:flex;align-items:center;padding:10px;background:#2d2d2d;border-top:1px solid #3d3d3d}
.terminal-input span{color:#4ec9b0;margin-right:10px;font-family:'Courier New',monospace}
.terminal-input input{flex:1;background:transparent;border:none;color:white;font-family:'Courier New',monospace;font-size:14px;outline:none}
.terminal-input button{margin-left:10px;padding:6px 16px;background:#4ec9b0;color:#1e1e1e;border:none;border-radius:3px;cursor:pointer}
.status-active{color:#28a745;font-weight:bold}
.status-inactive{color:#dc3545;font-weight:bold}
.actions{display:flex;gap:10px;margin:20px 0}
EOF

# Download dependencies and build
export PATH=/usr/local/go/bin:$PATH
export GOROOT=/usr/local/go
cd /opt/vpspanel
/usr/local/go/bin/go mod tidy
/usr/local/go/bin/go build -o vpspanel ./cmd

# Create systemd service
cat > /etc/systemd/system/vpspanel.service << 'EOF'
[Unit]
Description=VPS Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/vpspanel
Environment=PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=/opt/vpspanel/vpspanel
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Start service
systemctl daemon-reload
systemctl enable vpspanel
systemctl start vpspanel

echo ""
echo "========================================"
echo "VPS Panel installed successfully!"
echo "========================================"
echo "URL: http://$(hostname -I | awk '{print $1}'):8080"
echo "Username: admin"
echo "Password: $PASSWORD"
echo "========================================"
