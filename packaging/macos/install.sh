#!/usr/bin/env bash
# Installs FlowScope as a launchd daemon on macOS. Run with sudo from a built checkout (npm install && npm run build first).
# Adjust /usr/local/bin/node in the plist if Node.js lives elsewhere (Homebrew on Apple silicon: /opt/homebrew/bin/node).
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo." >&2; exit 1; }
here="$(cd "$(dirname "$0")/../.." && pwd)"
[ -d "$here/dist/src" ] || { echo "dist/ not found. Run: npm install && npm run build" >&2; exit 1; }
node_bin="$(command -v node || true)"; [ -n "$node_bin" ] || { echo "Node.js 22.13 or newer is required." >&2; exit 1; }
mkdir -p /usr/local/lib/flowscope "/Library/Application Support/FlowScope"
cp -R "$here/dist" "$here/package.json" /usr/local/lib/flowscope/
[ -d "$here/node_modules" ] && cp -R "$here/node_modules" /usr/local/lib/flowscope/ || (cd /usr/local/lib/flowscope && npm install --omit=dev --no-audit --no-fund)
sed "s#/usr/local/bin/node#$node_bin#" "$here/packaging/macos/io.flowscope.plist" > /Library/LaunchDaemons/io.flowscope.plist
chown root:wheel /Library/LaunchDaemons/io.flowscope.plist; chmod 644 /Library/LaunchDaemons/io.flowscope.plist
launchctl bootout system/io.flowscope 2>/dev/null || true
launchctl bootstrap system /Library/LaunchDaemons/io.flowscope.plist
echo "FlowScope is starting: https://localhost:8443/  (first-run admin password: grep 'generated password' /var/log/flowscope.log)"
echo "macOS may ask to allow incoming connections for node; allow it so exporters can reach UDP 2055/4739."
