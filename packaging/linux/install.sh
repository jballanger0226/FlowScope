#!/usr/bin/env bash
# Installs FlowScope as a systemd service. Run as root from a built checkout (npm install && npm run build first).
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }
here="$(cd "$(dirname "$0")/../.." && pwd)"
[ -d "$here/dist/src" ] || { echo "dist/ not found. Run: npm install && npm run build" >&2; exit 1; }
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
ENV
chmod 640 /etc/flowscope/flowscope.env; chown root:flowscope /etc/flowscope/flowscope.env
install -m 644 "$here/packaging/linux/flowscope.service" /etc/systemd/system/flowscope.service
systemctl daemon-reload
systemctl enable --now flowscope
echo "FlowScope is starting. Web console: https://$(hostname):8443/   (journalctl -u flowscope shows the first-run admin password if none was set)"
echo "Open TCP 8443 and UDP 2055/4739 in the host firewall if needed."
