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

One command (recommended):

```bash
curl -sSL https://raw.githubusercontent.com/anower93/vpspanel/main/install.sh | sudo bash
```

This installs to `/opt/vpspanel`, generates `/opt/vpspanel/config/config.yaml`, builds the binary, and registers a `systemd` service.

Public HTTPS (optional):

```bash
VPSPANEL_DOMAIN=panel.example.com VPSPANEL_EMAIL=you@example.com \
  curl -sSL https://raw.githubusercontent.com/anower93/vpspanel/main/install.sh | sudo bash
```

## Security Notes

- Default install runs in `safe_mode` and binds to `127.0.0.1:8080` (use SSH tunnel or enable the optional HTTPS setup).
- For public access, use the HTTPS install option and/or set `security.allowed_ips` to your IP/CIDR.
- Do not disable `safe_mode` unless you understand the risk (terminal/file actions/service restarts are powerful).

## Project Structure

```
vpspanel/
├── cmd/
│   └── main.go          # Entry point
├── config/
│   └── config.example.yaml  # Example configuration
├── internal/
│   ├── handlers/       # HTTP handlers
│   ├── middleware/     # Auth middleware
│   ├── services/       # Business logic
│   ├── static/         # CSS/JS
│   └── templates/      # HTML templates
└── go.mod
```
