#!/usr/bin/env bash
#
# SSH Tunnel Panel - one-command installer (3x-ui style).
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/USER/REPO/main/scripts/install.sh)
#
# Override the source repo / version / port with env vars:
#   REPO=youruser/ssh-tunnel-panel PORT=2095 bash install.sh
#
set -euo pipefail

# Detect explicit overrides BEFORE applying defaults (so upgrades preserve settings).
PORT_SET=0; [ -n "${PORT:-}" ] && PORT_SET=1

REPO="${REPO:-salahk12/sshtunnel}"     # <-- change to your GitHub repo
VERSION="${VERSION:-latest}"
PORT="${PORT:-2095}"
MASTER="${MASTER:-0}"                       # MASTER=1 => enable the central dashboard
BIN="/usr/local/bin/sshtunnel-panel"
CONFIG_DIR="/etc/sshtunnel-panel"
DATA_DIR="/var/lib/sshtunnel-panel"
SERVICE="/etc/systemd/system/sshtunnel-panel.service"

red()  { echo -e "\033[31m$*\033[0m"; }
grn()  { echo -e "\033[32m$*\033[0m"; }
ylw()  { echo -e "\033[33m$*\033[0m"; }

[ "$(id -u)" -eq 0 ] || { red "This script must be run as root (use sudo)."; exit 1; }

# --- uninstall ---
if [ "${1:-}" = "uninstall" ]; then
  ylw "Uninstalling..."
  systemctl disable --now sshtunnel-panel 2>/dev/null || true
  for u in /etc/systemd/system/sshtunnel-*.service; do
    [ -e "$u" ] || continue
    name=$(basename "$u" .service)
    systemctl disable --now "$name" 2>/dev/null || true
    rm -f "$u"
  done
  systemctl daemon-reload
  rm -f "$BIN" "$SERVICE"
  ylw "Binary and services removed. Data kept in $DATA_DIR and $CONFIG_DIR."
  ylw "To remove everything: rm -rf $DATA_DIR $CONFIG_DIR"
  exit 0
fi

# --- detect arch ---
case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) red "Unsupported architecture: $(uname -m)"; exit 1 ;;
esac

# --- dependencies ---
for dep in curl tar systemctl ssh; do
  command -v "$dep" >/dev/null 2>&1 || { red "Missing dependency: $dep. Please install it first."; exit 1; }
done

# --- download binary ---
if [ "$VERSION" = "latest" ]; then
  URL="https://github.com/$REPO/releases/latest/download/sshtunnel-panel-linux-$ARCH.tar.gz"
else
  URL="https://github.com/$REPO/releases/download/$VERSION/sshtunnel-panel-linux-$ARCH.tar.gz"
fi

ylw "Downloading: $URL"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
if ! curl -fsSL "$URL" -o "$TMP/panel.tar.gz"; then
  red "Download failed. Make sure REPO is correct and a Release with binaries is published."
  red "You can retry with: REPO=youruser/yourrepo bash install.sh"
  exit 1
fi
tar -xzf "$TMP/panel.tar.gz" -C "$TMP"
install -m 0755 "$TMP/sshtunnel-panel" "$BIN"
grn "Binary installed: $BIN"

mkdir -p "$CONFIG_DIR" "$DATA_DIR"
chmod 700 "$CONFIG_DIR" "$DATA_DIR"

FIRST_INSTALL=0
[ -f "$DATA_DIR/store.json" ] || FIRST_INSTALL=1

# --- configure: random web path + random password on first install ---
MASTER_FLAG=""
[ "$MASTER" = "1" ] && MASTER_FLAG="--master on"
if [ "$FIRST_INSTALL" -eq 1 ]; then
  "$BIN" admin --listen "0.0.0.0:$PORT" --random-path $MASTER_FLAG
else
  # Upgrade: preserve existing port/path/credentials. Only change the port if
  # PORT was explicitly provided on this run.
  LISTEN_FLAG=""
  [ "$PORT_SET" -eq 1 ] && LISTEN_FLAG="--listen 0.0.0.0:$PORT"
  ylw "Existing installation detected - settings and credentials are preserved (upgrade)."
  "$BIN" admin $LISTEN_FLAG $MASTER_FLAG --show || true
fi

# --- systemd service for the panel itself ---
cat > "$SERVICE" <<EOF
[Unit]
Description=SSH Tunnel Web Panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN serve
Restart=always
RestartSec=3s
Environment=SSHTP_CONFIG_DIR=$CONFIG_DIR
Environment=SSHTP_DATA_DIR=$DATA_DIR
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sshtunnel-panel >/dev/null 2>&1 || true
# restart (not just start) so an upgrade actually loads the new binary
systemctl restart sshtunnel-panel

sleep 1
IP="$(curl -fsSL --max-time 4 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"
WEBPATH="$(grep -o '"base_path": *"[^"]*"' "$CONFIG_DIR/config.json" | sed 's/.*: *"//;s/"//')"
LISTEN="$(grep -o '"listen": *"[^"]*"' "$CONFIG_DIR/config.json" | sed 's/.*: *"//;s/"//')"
PORT="${LISTEN##*:}"   # actual port from config (may differ from default on upgrade)

echo
grn "============================================================"
grn " SSH Tunnel Panel installed and running"
grn "============================================================"
echo " Panel URL : http://${IP}:${PORT}${WEBPATH}"
if [ "$FIRST_INSTALL" -eq 1 ]; then
  echo " (A random username and password were printed above - save them.)"
fi
[ "$MASTER" = "1" ] && echo " Mode: central master enabled - see the 'Nodes' tab in the panel."
echo
echo " This node's token (to register it on the central master):"
echo "   $("$BIN" node-token)"
echo
echo " Useful commands:"
echo "   systemctl status sshtunnel-panel      # panel status"
echo "   systemctl restart sshtunnel-panel     # restart the panel"
echo "   $BIN admin --show                     # show URL and username"
echo "   $BIN admin --password 'NEWPASS'       # change password from CLI"
echo "   bash install.sh uninstall             # uninstall"
grn "============================================================"
