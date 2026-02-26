package handlers

import (
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	c.HTML(http.StatusOK, "login.html", gin.H{
		"Title": "Login - VPS Panel",
	})
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
		"Title":    "Login - VPS Panel",
		"Error":    "Invalid credentials",
		"Username": username,
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
		"Title":      "Dashboard - VPS Panel",
		"CPU":        cpuPercent[0],
		"MemUsed":    memInfo.UsedPercent,
		"MemTotal":   memInfo.Total / 1024 / 1024 / 1024,
		"MemUsedGB":  memInfo.Used / 1024 / 1024 / 1024,
		"DiskUsed":   diskInfo.UsedPercent,
		"DiskTotal":  diskInfo.Total / 1024 / 1024 / 1024,
		"DiskUsedGB": diskInfo.Used / 1024 / 1024 / 1024,
		"Hostname":   hostInfo.Hostname,
		"OS":         hostInfo.OS,
		"Platform":   hostInfo.Platform,
		"Uptime":     uptime.String(),
		"NetIn":      netInfo[0].BytesRecv,
		"NetOut":     netInfo[0].BytesSent,
	})
}

func (h *Handlers) SystemInfo(c *gin.Context) {
	cpuInfo, _ := cpu.Info()
	memInfo, _ := mem.VirtualMemory()
	diskInfo, _ := disk.Usage("/")
	hostInfo, _ := host.Info()

	c.HTML(http.StatusOK, "system.html", gin.H{
		"Title":    "System Info - VPS Panel",
		"CPUInfo":  cpuInfo,
		"MemInfo":  memInfo,
		"DiskInfo": diskInfo,
		"HostInfo": hostInfo,
		"NumCPU":   runtime.NumCPU(),
	})
}

func (h *Handlers) Processes(c *gin.Context) {
	procs, _ := process.Processes()
	var processList []gin.H
	for _, p := range procs {
		name, _ := p.Name()
		mem, _ := p.MemoryInfo()
		cpu, _ := p.CPUPercent()

		processList = append(processList, gin.H{
			"PID":    p.Pid,
			"Name":   name,
			"MemRSS": mem.RSS / 1024 / 1024,
			"CPU":    cpu,
		})
	}

	c.HTML(http.StatusOK, "processes.html", gin.H{
		"Title":     "Processes - VPS Panel",
		"Processes": processList,
	})
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
			files = append(files, gin.H{
				"Name":    e.Name(),
				"IsDir":   e.IsDir(),
				"Size":    info.Size(),
				"Mode":    info.Mode().String(),
				"ModTime": info.ModTime().Format("2006-01-02 15:04"),
			})
		}
	}

	parent := filepath.Dir(path)
	if parent == path {
		parent = "/"
	}

	c.HTML(http.StatusOK, "files.html", gin.H{
		"Title":  "File Manager - VPS Panel",
		"Path":   path,
		"Parent": parent,
		"Files":  files,
	})
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
	c.HTML(http.StatusOK, "terminal.html", gin.H{
		"Title": "Terminal - VPS Panel",
	})
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

	c.HTML(http.StatusOK, "nginx.html", gin.H{
		"Title":   "Nginx Manager - VPS Panel",
		"Status":  status,
		"Configs": configs,
	})
}

func (h *Handlers) NginxReload(c *gin.Context) {
	exec.Command("systemctl", "reload", "nginx").Run()
	c.Redirect(http.StatusFound, "/admin/nginx")
}

func (h *Handlers) NginxRestart(c *gin.Context) {
	exec.Command("systemctl", "restart", "nginx").Run()
	c.Redirect(http.StatusFound, "/admin/nginx")
}

func (h *Handlers) ApacheManager(c *gin.Context) {
	status := h.getServiceStatus("apache2")
	var configs []string
	if files, err := filepath.Glob("/etc/apache2/sites-enabled/*"); err == nil {
		for _, f := range files {
			configs = append(configs, filepath.Base(f))
		}
	}

	c.HTML(http.StatusOK, "apache.html", gin.H{
		"Title":   "Apache Manager - VPS Panel",
		"Status":  status,
		"Configs": configs,
	})
}

func (h *Handlers) ApacheReload(c *gin.Context) {
	exec.Command("systemctl", "reload", "apache2").Run()
	c.Redirect(http.StatusFound, "/admin/apache")
}

func (h *Handlers) ApacheRestart(c *gin.Context) {
	exec.Command("systemctl", "restart", "apache2").Run()
	c.Redirect(http.StatusFound, "/admin/apache")
}

func (h *Handlers) MySQLManager(c *gin.Context) {
	status := h.getServiceStatus("mysql")

	c.HTML(http.StatusOK, "mysql.html", gin.H{
		"Title":  "MySQL Manager - VPS Panel",
		"Status": status,
	})
}

func (h *Handlers) MySQLRestart(c *gin.Context) {
	exec.Command("systemctl", "restart", "mysql").Run()
	c.Redirect(http.StatusFound, "/admin/mysql")
}

func (h *Handlers) MySQLDatabases(c *gin.Context) {
	out, _ := exec.Command("mysql", "-e", "SHOW DATABASES;").Output()
	c.String(http.StatusOK, string(out))
}

func (h *Handlers) CreateDatabase(c *gin.Context) {
	name := c.PostForm("name")
	exec.Command("mysql", "-e", "CREATE DATABASE "+name+";").Run()
	c.Redirect(http.StatusFound, "/admin/mysql")
}

func (h *Handlers) DropDatabase(c *gin.Context) {
	name := c.PostForm("name")
	exec.Command("mysql", "-e", "DROP DATABASE "+name+";").Run()
	c.Redirect(http.StatusFound, "/admin/mysql")
}

func (h *Handlers) PostgresManager(c *gin.Context) {
	status := h.getServiceStatus("postgresql")

	c.HTML(http.StatusOK, "postgres.html", gin.H{
		"Title":  "PostgreSQL Manager - VPS Panel",
		"Status": status,
	})
}

func (h *Handlers) PostgresRestart(c *gin.Context) {
	exec.Command("systemctl", "restart", "postgresql").Run()
	c.Redirect(http.StatusFound, "/admin/postgres")
}

func (h *Handlers) DNSManager(c *gin.Context) {
	var zones []string
	if files, err := filepath.Glob("/etc/bind/zones/*"); err == nil {
		for _, f := range files {
			zones = append(zones, filepath.Base(f))
		}
	}

	c.HTML(http.StatusOK, "dns.html", gin.H{
		"Title": "DNS Manager - VPS Panel",
		"Zones": zones,
	})
}

func (h *Handlers) CreateDNSZone(c *gin.Context) {
	zone := c.PostForm("zone")
	exec.Command("named-checkzone", zone, "/etc/bind/zones/"+zone).Run()
	c.Redirect(http.StatusFound, "/admin/dns")
}

func (h *Handlers) DeleteDNSZone(c *gin.Context) {
	zone := c.PostForm("zone")
	os.Remove("/etc/bind/zones/" + zone)
	c.Redirect(http.StatusFound, "/admin/dns")
}

func (h *Handlers) Services(c *gin.Context) {
	services := []string{"nginx", "apache2", "mysql", "postgresql", "docker", "sshd", "fail2ban", "cron"}
	serviceList := make([]gin.H, 0)
	for _, s := range services {
		status := h.getServiceStatus(s)
		serviceList = append(serviceList, gin.H{
			"Name":   s,
			"Status": status,
		})
	}

	c.HTML(http.StatusOK, "services.html", gin.H{
		"Title":    "Services - VPS Panel",
		"Services": serviceList,
	})
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

var funcMap = template.FuncMap{
	"add": func(a, b int) int {
		return a + b
	},
	"formatBytes": func(bytes uint64) string {
		const unit = 1024
		if bytes < unit {
			return fmt.Sprintf("%d B", bytes)
		}
		div, exp := uint64(unit), 0
		for n := bytes / unit; n >= unit; n /= unit {
			div *= unit
			exp++
		}
		return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
	},
}
