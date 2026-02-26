#!/usr/bin/env bash

set -euo pipefail

REPO_URL="https://github.com/anower93/vpspanel.git"
INSTALL_DIR="/opt/vpspanel"
GO_VERSION="1.21.6"
GO_TGZ="go${GO_VERSION}.linux-amd64.tar.gz"
GO_URL="https://go.dev/dl/${GO_TGZ}"
GO_BIN="/usr/local/go/bin/go"

GOPATH_DIR="/var/lib/vpspanel-go"
GOCACHE_DIR="/var/cache/vpspanel-go"

DOMAIN="${VPSPANEL_DOMAIN:-}"
EMAIL="${VPSPANEL_EMAIL:-}"

need_cmd() { command -v "$1" >/dev/null 2>&1; }
as_user() {
	# run as a given user without requiring sudo
	local u="$1"
	shift
	if need_cmd runuser; then
		runuser -u "$u" -- "$@"
		return
	fi
	su -s /bin/bash -c "$(printf '%q ' "$@")" "$u"
}

echo "Installing VPS Panel..."

PKG_INSTALL=""
if need_cmd apt-get; then
	apt-get update -y
	PKG_INSTALL="apt-get install -y"
	$PKG_INSTALL ca-certificates curl git openssl tar
	$PKG_INSTALL apache2-utils
elif need_cmd yum; then
	PKG_INSTALL="yum install -y"
	$PKG_INSTALL ca-certificates curl git openssl tar
	$PKG_INSTALL httpd-tools
else
	echo "Unsupported distro: need apt-get or yum"
	exit 1
fi

if [ ! -x "$GO_BIN" ]; then
	echo "Installing Go ${GO_VERSION}..."
	rm -rf /usr/local/go
	curl -fsSL "$GO_URL" -o "/tmp/${GO_TGZ}"
	tar -C /usr/local -xzf "/tmp/${GO_TGZ}"
	rm -f "/tmp/${GO_TGZ}"
fi

if ! id -u vpspanel >/dev/null 2>&1; then
	useradd --system --home "$INSTALL_DIR" --shell /usr/sbin/nologin vpspanel
fi

mkdir -p "$INSTALL_DIR"

if [ -d "$INSTALL_DIR/.git" ]; then
	git -C "$INSTALL_DIR" fetch --depth=1 origin main
	git -C "$INSTALL_DIR" reset --hard origin/main
else
	rm -rf "$INSTALL_DIR"/*
	git clone --depth=1 "$REPO_URL" "$INSTALL_DIR"
fi

mkdir -p "$INSTALL_DIR/config"

mkdir -p "$GOPATH_DIR" "$GOCACHE_DIR"
chown -R vpspanel:vpspanel "$GOPATH_DIR" "$GOCACHE_DIR"

GENERATED_PASSWORD=""
if [ ! -f "$INSTALL_DIR/config/config.yaml" ]; then
	GENERATED_PASSWORD="$(openssl rand -base64 18 | tr -d '\n')"
	SESSION_SECRET="$(openssl rand -hex 32)"
	BCRYPT_HASH="$(htpasswd -bnBC 12 "" "$GENERATED_PASSWORD" | tr -d ':\n')"
	cat > "$INSTALL_DIR/config/config.yaml" <<EOF
server:
  port: "8080"
  host: "0.0.0.0"

auth:
  username: "admin"
  password: "${BCRYPT_HASH}"
  session_secret: "${SESSION_SECRET}"

security:
  allowed_ips: []
  require_2fa: false
  safe_mode: true
EOF
fi

# Cleanup from older broken installs where GOPATH was inside the repo.
rm -rf "$INSTALL_DIR/go" || true

chown -R vpspanel:vpspanel "$INSTALL_DIR"

echo "Building..."
cd "$INSTALL_DIR"
as_user vpspanel env GOPATH="$GOPATH_DIR" GOCACHE="$GOCACHE_DIR" "$GO_BIN" mod tidy
as_user vpspanel env GOPATH="$GOPATH_DIR" GOCACHE="$GOCACHE_DIR" "$GO_BIN" build -o "$INSTALL_DIR/vpspanel" ./cmd

cat > /etc/systemd/system/vpspanel.service <<'EOF'
[Unit]
Description=VPS Panel
After=network.target

[Service]
Type=simple
User=vpspanel
Group=vpspanel
WorkingDirectory=/opt/vpspanel
ExecStart=/opt/vpspanel/vpspanel
Restart=always
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
RestrictSUIDSGID=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now vpspanel

if [ -n "$DOMAIN" ]; then
	echo "Configuring Nginx + Let's Encrypt for ${DOMAIN}..."
	if need_cmd apt-get; then
		$PKG_INSTALL nginx certbot python3-certbot-nginx
	elif need_cmd yum; then
		$PKG_INSTALL nginx certbot python3-certbot-nginx
	fi
	systemctl enable --now nginx

	NGINX_CONF_DIR="/etc/nginx/conf.d"
	NGINX_SITE_DIR="/etc/nginx/sites-available"
	NGINX_ENABLED_DIR="/etc/nginx/sites-enabled"
	CONF_PATH="${NGINX_CONF_DIR}/vpspanel.conf"
	if [ -d "$NGINX_SITE_DIR" ] && [ -d "$NGINX_ENABLED_DIR" ]; then
		CONF_PATH="${NGINX_SITE_DIR}/vpspanel"
	fi

	cat > "$CONF_PATH" <<EOF
server {
  listen 80;
  server_name ${DOMAIN};

  location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
  }
}
EOF
	if [ -d "$NGINX_SITE_DIR" ] && [ -d "$NGINX_ENABLED_DIR" ]; then
		ln -sf "$CONF_PATH" "${NGINX_ENABLED_DIR}/vpspanel"
	fi
	nginx -t
	systemctl reload nginx

	if [ -z "$EMAIL" ]; then
		echo "VPSPANEL_EMAIL is required for Let's Encrypt"
		exit 1
	fi
	certbot --nginx -d "$DOMAIN" -m "$EMAIL" --agree-tos --non-interactive --redirect
fi

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"

echo "========================================"
echo "VPS Panel is running (safe mode ON)"
if [ -n "$DOMAIN" ]; then
	echo "URL: https://${DOMAIN}"
else
	echo "URL: http://${IP:-YOUR_SERVER_IP}:8080"
fi
echo "Username: admin"
if [ -n "$GENERATED_PASSWORD" ]; then
	echo "Password: $GENERATED_PASSWORD"
else
	echo "Password: (existing config preserved at /opt/vpspanel/config/config.yaml)"
fi
echo "Service: systemctl status vpspanel"
echo "========================================"
