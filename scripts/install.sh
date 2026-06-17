#!/usr/bin/env bash
#
# SSH Tunnel Panel — one-command installer (3x-ui style).
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/USER/REPO/main/scripts/install.sh)
#
# Override the source repo / version / port with env vars:
#   REPO=youruser/ssh-tunnel-panel PORT=2095 bash install.sh
#
set -euo pipefail

REPO="${REPO:-USER/ssh-tunnel-panel}"     # <-- change to your GitHub repo
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

[ "$(id -u)" -eq 0 ] || { red "این اسکریپت باید با root اجرا شود (sudo)."; exit 1; }

# --- uninstall ---
if [ "${1:-}" = "uninstall" ]; then
  ylw "در حال حذف..."
  systemctl disable --now sshtunnel-panel 2>/dev/null || true
  for u in /etc/systemd/system/sshtunnel-*.service; do
    [ -e "$u" ] || continue
    name=$(basename "$u" .service)
    systemctl disable --now "$name" 2>/dev/null || true
    rm -f "$u"
  done
  systemctl daemon-reload
  rm -f "$BIN" "$SERVICE"
  ylw "باینری و سرویس‌ها حذف شدند. داده‌ها در $DATA_DIR و $CONFIG_DIR باقی ماندند."
  ylw "برای حذف کامل: rm -rf $DATA_DIR $CONFIG_DIR"
  exit 0
fi

# --- detect arch ---
case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) red "معماری پشتیبانی‌نشده: $(uname -m)"; exit 1 ;;
esac

# --- dependencies ---
for dep in curl tar systemctl ssh; do
  command -v "$dep" >/dev/null 2>&1 || { red "نیازمند $dep است. ابتدا نصبش کنید."; exit 1; }
done

# --- download binary ---
if [ "$VERSION" = "latest" ]; then
  URL="https://github.com/$REPO/releases/latest/download/sshtunnel-panel-linux-$ARCH.tar.gz"
else
  URL="https://github.com/$REPO/releases/download/$VERSION/sshtunnel-panel-linux-$ARCH.tar.gz"
fi

ylw "دانلود از: $URL"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
if ! curl -fsSL "$URL" -o "$TMP/panel.tar.gz"; then
  red "دانلود ناموفق بود. مطمئن شوید REPO درست است و یک Release با باینری منتشر شده."
  red "می‌توانید با REPO=youruser/yourrepo دوباره اجرا کنید."
  exit 1
fi
tar -xzf "$TMP/panel.tar.gz" -C "$TMP"
install -m 0755 "$TMP/sshtunnel-panel" "$BIN"
grn "باینری نصب شد: $BIN"

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
  "$BIN" admin --listen "0.0.0.0:$PORT" $MASTER_FLAG --show || true
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
systemctl enable --now sshtunnel-panel

sleep 1
IP="$(curl -fsSL --max-time 4 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"
WEBPATH="$(grep -o '"base_path": *"[^"]*"' "$CONFIG_DIR/config.json" | sed 's/.*: *"//;s/"//')"

echo
grn "============================================================"
grn " ✅ SSH Tunnel Panel نصب و اجرا شد"
grn "============================================================"
echo " آدرس پنل : http://${IP}:${PORT}${WEBPATH}"
if [ "$FIRST_INSTALL" -eq 1 ]; then
  echo " (نام کاربری و رمز عبور تصادفی در خروجی بالا چاپ شد — یادداشت کنید)"
fi
[ "$MASTER" = "1" ] && echo " حالت: سرور مرکزی (Master) فعال شد — تب «نودها» را در پنل ببینید."
echo
echo " توکن این نود (برای ثبت در سرور مرکزی):"
echo "   $("$BIN" node-token)"
echo
echo " دستورات مفید:"
echo "   systemctl status sshtunnel-panel      # وضعیت پنل"
echo "   systemctl restart sshtunnel-panel     # ری‌استارت پنل"
echo "   $BIN admin --show                     # نمایش آدرس و یوزرنیم"
echo "   $BIN admin --password 'NEWPASS'       # تغییر رمز از CLI"
echo "   bash install.sh uninstall             # حذف"
grn "============================================================"
