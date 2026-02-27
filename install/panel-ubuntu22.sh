#!/usr/bin/env bash

set -euo pipefail

REPO_URL="https://github.com/anower93/vpspanel.git"
SRC_DIR="/opt/vpspanel"
BIN_DIR="/opt/vpspanel/bin"
DATA_DIR="/var/lib/vpspanel"
ENV_FILE="/etc/vpspanel/panel.env"

GO_VERSION="1.21.6"
GO_TGZ="go${GO_VERSION}.linux-amd64.tar.gz"
GO_URL="https://go.dev/dl/${GO_TGZ}"
GO_BIN="/usr/local/go/bin/go"

GOPATH_DIR="/var/lib/vpspanel-go"
GOCACHE_DIR="/var/cache/vpspanel-go"

need_cmd() { command -v "$1" >/dev/null 2>&1; }

echo "Installing vpspanel (panel) on Ubuntu 22.04..."

if ! need_cmd apt-get; then
	echo "This installer targets Ubuntu/Debian (apt-get)."
	exit 1
fi

apt-get update -y
apt-get install -y ca-certificates curl git openssl tar postgresql postgresql-contrib

cd /tmp

if [ ! -x "$GO_BIN" ]; then
	echo "Installing Go ${GO_VERSION}..."
	rm -rf /usr/local/go
	curl -fsSL "$GO_URL" -o "/tmp/${GO_TGZ}"
	tar -C /usr/local -xzf "/tmp/${GO_TGZ}"
	rm -f "/tmp/${GO_TGZ}"
fi

if ! id -u vpspanel >/dev/null 2>&1; then
	useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin vpspanel
fi

mkdir -p "$SRC_DIR" "$BIN_DIR" "$DATA_DIR" "$GOPATH_DIR" "$GOCACHE_DIR" "$(dirname "$ENV_FILE")"
chown -R vpspanel:vpspanel "$DATA_DIR" "$GOPATH_DIR" "$GOCACHE_DIR"

echo "Fetching source..."
# Always re-clone to avoid git safe.directory/ownership issues.
rm -rf "$SRC_DIR"
git clone --depth=1 "$REPO_URL" "$SRC_DIR"

echo "Setting up Postgres database..."
DB_NAME="vpspanel"
DB_USER="vpspanel"
DB_PASS="$(openssl rand -base64 24 | tr -d '\n')"

sudo -u postgres psql -tc "select 1 from pg_roles where rolname='${DB_USER}'" | grep -q 1 || \
  sudo -u postgres psql -c "create user ${DB_USER} with password '${DB_PASS}';"

sudo -u postgres psql -tc "select 1 from pg_database where datname='${DB_NAME}'" | grep -q 1 || \
  sudo -u postgres psql -c "create database ${DB_NAME} owner ${DB_USER};"

COOKIE_KEY="$(openssl rand -hex 32)"
IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
PUBLIC_URL="http://${IP:-127.0.0.1}:8080"

cat > "$ENV_FILE" <<EOF
VPSPANEL_LISTEN=:8080
VPSPANEL_PUBLIC_URL=${PUBLIC_URL}
VPSPANEL_DATABASE_URL=postgres://${DB_USER}:${DB_PASS}@127.0.0.1:5432/${DB_NAME}?sslmode=disable
VPSPANEL_DATA_DIR=${DATA_DIR}
VPSPANEL_COOKIE_KEY=${COOKIE_KEY}
EOF

chmod 0600 "$ENV_FILE"

echo "Building panel..."
cd "$SRC_DIR"
runuser -u vpspanel -- env GOTOOLCHAIN=local GOPATH="$GOPATH_DIR" GOCACHE="$GOCACHE_DIR" "$GO_BIN" mod download
runuser -u vpspanel -- env GOTOOLCHAIN=local GOPATH="$GOPATH_DIR" GOCACHE="$GOCACHE_DIR" "$GO_BIN" build -buildvcs=false -trimpath -o "$BIN_DIR/panel" ./cmd/panel
runuser -u vpspanel -- env GOTOOLCHAIN=local GOPATH="$GOPATH_DIR" GOCACHE="$GOCACHE_DIR" "$GO_BIN" build -buildvcs=false -trimpath -o "$BIN_DIR/panelctl" ./cmd/panelctl

cat > /etc/systemd/system/vpspanel-panel.service <<EOF
[Unit]
Description=vpspanel panel
After=network.target postgresql.service

[Service]
Type=simple
User=vpspanel
Group=vpspanel
EnvironmentFile=${ENV_FILE}
WorkingDirectory=${SRC_DIR}
ExecStart=${BIN_DIR}/panel
Restart=always
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now vpspanel-panel

sleep 2

BOOT_EMAIL="$(journalctl -u vpspanel-panel -n 200 --no-pager | awk -F= '/BOOTSTRAP_ADMIN_EMAIL=/{print $2}' | tail -n 1)"
BOOT_PASS="$(journalctl -u vpspanel-panel -n 200 --no-pager | awk -F= '/BOOTSTRAP_ADMIN_PASSWORD=/{print $2}' | tail -n 1)"

ENROLL_TOKEN="$(runuser -u vpspanel -- env VPSPANEL_DATABASE_URL="$(grep '^VPSPANEL_DATABASE_URL=' "$ENV_FILE" | cut -d= -f2-)" ${BIN_DIR}/panelctl enroll-token --ttl 30m)"

echo "========================================"
echo "Panel URL: ${PUBLIC_URL}"
echo "Admin email: ${BOOT_EMAIL:-admin@local}"
if [ -n "$BOOT_PASS" ]; then
	echo "Admin password: ${BOOT_PASS}"
else
	echo "Admin password: (check: journalctl -u vpspanel-panel -n 200 --no-pager)"
fi
echo "Enrollment token (30m): ${ENROLL_TOKEN}"
echo "Agent port: 8443/tcp (open this on nodes)"
echo "========================================"
