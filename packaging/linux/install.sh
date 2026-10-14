#!/usr/bin/env bash
# Installs FlowScope as a systemd service. Run as root from a built checkout (npm install && npm run build first).
#
#   install.sh            install or update
#   install.sh --sqlite   do not download or set up ClickHouse: use the embedded SQLite store (same as FLOWSCOPE_STORAGE=sqlite)
#   install.sh --clickhouse   set up ClickHouse (the default for a new install)
#
# Storage: a new install also sets up ClickHouse on this machine (official package from packages.clickhouse.com, listening on 127.0.0.1,
# its own random password) and points FlowScope at it. This needs Debian or Ubuntu (apt). --sqlite keeps the embedded
# SQLite store instead, and nothing about ClickHouse is downloaded; on another distribution install ClickHouse yourself and set FLOWSCOPE_CLICKHOUSE_URL in /etc/flowscope/flowscope.env.
# Re-running the script on an existing install leaves its storage alone unless FLOWSCOPE_STORAGE=clickhouse is given.
set -euo pipefail
say()  { printf '\033[1m==> %s\033[0m\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }
here="$(cd "$(dirname "$0")/../.." && pwd)"
[ -d "$here/dist/src" ] || { echo "dist/ not found. Run: npm install && npm run build" >&2; exit 1; }
. "$here/packaging/linux/clickhouse-setup.sh"
for a in "$@"; do
  case "$a" in
    --sqlite) FLOWSCOPE_STORAGE=sqlite ;;
    --clickhouse) FLOWSCOPE_STORAGE=clickhouse ;;
    *) die "Unknown option: $a (use --sqlite or --clickhouse)." ;;
  esac
done
new_install=0; [ -f /etc/flowscope/flowscope.env ] || new_install=1
want_ch=0
case "${FLOWSCOPE_STORAGE:-}" in
  clickhouse) want_ch=1 ;;
  sqlite) want_ch=0 ;;
  "") want_ch=$new_install ;;
  *) die "FLOWSCOPE_STORAGE must be clickhouse or sqlite." ;;
esac
[ "$want_ch" = 0 ] || ch_install_package
if [ "$want_ch" = 1 ] && ! ch_binary_works; then
  warn "$(ch_cpu_message) Using SQLite for now."
  systemctl disable --now clickhouse-server >/dev/null 2>&1 || true
  want_ch=0
fi
command -v node >/dev/null || { echo "Node.js 22.13 or newer is required." >&2; exit 1; }
node -e 'const [a,b]=process.versions.node.split(".").map(Number); process.exit(a>22||(a===22&&b>=13)?0:1)' || { echo "Node.js 22.13 or newer is required (found $(node -v))." >&2; exit 1; }
id flowscope >/dev/null 2>&1 || useradd --system --home /var/lib/flowscope --shell /usr/sbin/nologin flowscope
install -d /opt/flowscope /etc/flowscope
cp -a "$here/dist" "$here/package.json" /opt/flowscope/
[ -d "$here/node_modules" ] && cp -a "$here/node_modules" /opt/flowscope/ || (cd /opt/flowscope && npm install --omit=dev --no-audit --no-fund)
[ -f /etc/flowscope/flowscope.env ] || cat > /etc/flowscope/flowscope.env <<'ENV'
# One KEY=value per line. See the README for all settings.
# FLOWSCOPE_ADMIN_PASSWORD=change-me-please-12+
# FLOWSCOPE_HTTPS_PORT=8443
# FLOWSCOPE_FLOW_PORTS=2055,4739
# FLOWSCOPE_CLICKHOUSE_URL=http://user:password@127.0.0.1:8123/flowscope
ENV
chmod 640 /etc/flowscope/flowscope.env; chown root:flowscope /etc/flowscope/flowscope.env
if [ "$want_ch" = 1 ]; then
  ch_write_listen_config
  if ! grep -Eq '^[[:space:]]*FLOWSCOPE_CLICKHOUSE_URL=.+' /etc/flowscope/flowscope.env; then
    ch_pw="$(ch_gen_password)"
    ch_write_user "$ch_pw"
    printf '\n# Storage: the ClickHouse server on this machine, set up by the installer. Remove this line and restart to use another server.\nFLOWSCOPE_CLICKHOUSE_URL=%s\n' "$(ch_url "$ch_pw")" >> /etc/flowscope/flowscope.env
  fi
  systemctl enable clickhouse-server >/dev/null 2>&1 || true
  # a restart, not a start: the package may have started the server already, before it was told to listen on 127.0.0.1 only
  systemctl restart clickhouse-server
  say "Waiting for ClickHouse"
  ch_wait || warn "ClickHouse did not answer within 90 seconds. Look at: journalctl -u clickhouse-server -n 50 (FlowScope keeps trying for a minute, then uses SQLite for this run)"
fi
install -m 644 "$here/packaging/linux/flowscope.service" /etc/systemd/system/flowscope.service
systemctl daemon-reload
systemctl enable --now flowscope
echo "FlowScope is starting. Web console: https://$(hostname):8443/   (journalctl -u flowscope shows the first-run admin password if none was set)"
echo "Open TCP 8443 and UDP 2055/4739 in the host firewall if needed."
if grep -Eq '^[[:space:]]*FLOWSCOPE_CLICKHOUSE_URL=.+' /etc/flowscope/flowscope.env; then echo "Storage: ClickHouse on this machine (data in /var/lib/clickhouse; back it up with /var/lib/flowscope)."
else echo "Storage: embedded SQLite (FLOWSCOPE_STORAGE=clickhouse sets up ClickHouse instead; see docs/deployment.md)."; fi
