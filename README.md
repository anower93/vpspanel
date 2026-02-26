# VPS Control Panel

A lightweight VPS control panel written in Go, similar to cPanel.

## Features

- **Dashboard**: Real-time CPU, Memory, Disk, and Network monitoring
- **System Info**: Detailed system information
- **Process Manager**: View and kill running processes
- **File Manager**: Browse, upload, create, delete files
- **Terminal**: Execute commands via web interface
- **Services Manager**: Control system services (nginx, apache2, mysql, postgresql, etc.)
- **Nginx Manager**: Manage Nginx configurations
- **Apache Manager**: Manage Apache configurations
- **MySQL Manager**: Create/drop databases
- **PostgreSQL Manager**: Control PostgreSQL service
- **DNS Manager**: Manage DNS zones

## Requirements

- Go 1.21+
- Linux VPS (tested on Ubuntu/Debian)
- Root/sudo access for service management

## Installation

1. Clone and setup:
```bash
git clone <repo-url>
cd vpspanel
go mod tidy
```

2. Edit `config/config.yaml` with your credentials:
```yaml
server:
  port: "8080"

auth:
  username: "admin"
  password: "your-secure-password"
  session_secret: "generate-random-secret"
```

3. Build and run:
```bash
go build -o vpspanel ./cmd
sudo ./vpspanel
```

4. Access at `http://your-server:8080`

## Security Notes

- Change default password immediately
- Use HTTPS in production (reverse proxy with nginx)
- Consider adding IP whitelisting in config
- The terminal executes commands as the running user

## Project Structure

```
vpspanel/
├── cmd/
│   └── main.go          # Entry point
├── config/
│   └── config.yaml      # Configuration
├── internal/
│   ├── handlers/       # HTTP handlers
│   ├── middleware/     # Auth middleware
│   ├── services/       # Business logic
│   ├── static/         # CSS/JS
│   └── templates/      # HTML templates
└── go.mod
```
