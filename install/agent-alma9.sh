#!/usr/bin/env bash

set -euo pipefail

REPO_URL="https://github.com/anower93/vpspanel.git"
SRC_DIR="/opt/vpspanel-agent-src"
BIN_DIR="/opt/vpspanel-agent"
ENV_FILE="/etc/vpspanel-agent/agent.env"
STATE_DIR="/var/lib/vpspanel-agent"

GO_VERSION="1.21.6"
GO_TGZ="go${GO_VERSION}.linux-amd64.tar.gz"
GO_URL="https://go.dev/dl/${GO_TGZ}"
GO_BIN="/usr/local/go/bin/go"

GOPATH_DIR="/var/lib/vpspanel-agent-go"
GOCACHE_DIR="/var/cache/vpspanel-agent-go"

PANEL_URL="${VPSPANEL_PANEL_URL:-}"
ENROLL_TOKEN="${VPSPANEL_ENROLL_TOKEN:-}"
ADVERTISE_HOST="${VPSPANEL_ADVERTISE_HOST:-}"
NODE_NAME="${VPSPANEL_NODE_NAME:-}"

need_cmd() { command -v "$1" >/dev/null 2>&1; }

echo "Installing vpspanel agent on AlmaLinux 9..."

if ! need_cmd yum; then
	echo "This installer targets AlmaLinux/RHEL (yum)."
	exit 1
fi

yum install -y ca-certificates curl git openssl tar

if [ ! -x "$GO_BIN" ]; then
	echo "Installing Go ${GO_VERSION}..."
	rm -rf /usr/local/go
	curl -fsSL "$GO_URL" -o "/tmp/${GO_TGZ}"
	tar -C /usr/local -xzf "/tmp/${GO_TGZ}"
	rm -f "/tmp/${GO_TGZ}"
fi

if [ -z "$PANEL_URL" ] || [ -z "$ENROLL_TOKEN" ]; then
	echo "VPSPANEL_PANEL_URL and VPSPANEL_ENROLL_TOKEN are required"
	exit 1
fi

if [ -z "$ADVERTISE_HOST" ]; then
	ADVERTISE_HOST="$(hostname -I 2>/dev/null | awk '{print $1}')"
fi

if [ -z "$NODE_NAME" ]; then
	NODE_NAME="$(hostname -s 2>/dev/null || hostname)"
fi

if ! id -u vpspanel-agent >/dev/null 2>&1; then
	useradd --system --home "$STATE_DIR" --shell /usr/sbin/nologin vpspanel-agent
fi

mkdir -p "$SRC_DIR" "$BIN_DIR" "$STATE_DIR" "$GOPATH_DIR" "$GOCACHE_DIR" "$(dirname "$ENV_FILE")"
chown -R vpspanel-agent:vpspanel-agent "$STATE_DIR" "$GOPATH_DIR" "$GOCACHE_DIR"

echo "Fetching source..."
if [ -d "$SRC_DIR/.git" ]; then
	git -C "$SRC_DIR" fetch --depth=1 origin main
	git -C "$SRC_DIR" reset --hard origin/main
else
	rm -rf "$SRC_DIR"/*
	git clone --depth=1 "$REPO_URL" "$SRC_DIR"
fi

echo "Building agent..."
cd "$SRC_DIR"
runuser -u vpspanel-agent -- env GOPATH="$GOPATH_DIR" GOCACHE="$GOCACHE_DIR" "$GO_BIN" mod tidy
runuser -u vpspanel-agent -- env GOPATH="$GOPATH_DIR" GOCACHE="$GOCACHE_DIR" "$GO_BIN" build -o "$BIN_DIR/agent" ./cmd/agent

cat > "$ENV_FILE" <<EOF
VPSPANEL_AGENT_LISTEN=:8443
VPSPANEL_PANEL_URL=${PANEL_URL}
VPSPANEL_ENROLL_TOKEN=${ENROLL_TOKEN}
VPSPANEL_AGENT_STATE_DIR=${STATE_DIR}
VPSPANEL_NODE_NAME=${NODE_NAME}
VPSPANEL_ADVERTISE_HOST=${ADVERTISE_HOST}
VPSPANEL_ADVERTISE_PORT=8443
EOF
chmod 0600 "$ENV_FILE"

cat > /etc/systemd/system/vpspanel-agent.service <<EOF
[Unit]
Description=vpspanel agent
After=network.target

[Service]
Type=simple
User=vpspanel-agent
Group=vpspanel-agent
EnvironmentFile=${ENV_FILE}
WorkingDirectory=${SRC_DIR}
ExecStart=${BIN_DIR}/agent
Restart=always
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now vpspanel-agent

if need_cmd firewall-cmd; then
	firewall-cmd --permanent --add-port=8443/tcp || true
	firewall-cmd --reload || true
fi

echo "========================================"
echo "Agent installed"
echo "Listening: ${ADVERTISE_HOST}:8443 (mTLS required)"
echo "Service: systemctl status vpspanel-agent"
echo "========================================"
