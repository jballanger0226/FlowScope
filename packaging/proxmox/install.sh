#!/usr/bin/env bash
# FlowScope installer for a Debian or Ubuntu system, written for a Proxmox VE LXC container but fine on any systemd host.
# Run it as root INSIDE the container. flowscope-lxc.sh (on the Proxmox host) does that for you.
#
#   install.sh                 install, or update an existing install, from the source in FLOWSCOPE_SRC
#   install.sh --update        same, but refuse to run if FlowScope is not installed yet
#   install.sh --sqlite        do not download or set up ClickHouse: store everything in the embedded SQLite file (same as FLOWSCOPE_STORAGE=sqlite)
#   install.sh --clickhouse    set up ClickHouse (the default for a new install; same as FLOWSCOPE_STORAGE=clickhouse)
#
# Where the source comes from (first match wins):
#   FLOWSCOPE_SRC=/path/to/flowscope.tar.gz   a tarball of the repository (what flowscope-lxc.sh pushes in)
#   FLOWSCOPE_SRC=/path/to/checkout           a checkout of the repository
#   FLOWSCOPE_REPO=owner/name [FLOWSCOPE_REF=main] [GITHUB_TOKEN=...]   download from GitHub (a token is needed for a private repository)
#
# Other settings: FLOWSCOPE_ADMIN_PASSWORD (first install only; generated when unset), FLOWSCOPE_NODE=system to use the Node.js
# already on the machine instead of downloading one, FLOWSCOPE_TEMPLATE_BUILD=1 when making the Proxmox CT template (no admin password is
# written; the template's first-boot service creates one for every container made from it).
#
# Storage: a new install sets up ClickHouse on this machine (official package, listening on 127.0.0.1, its own random password) and
# points FlowScope at it. --sqlite (or FLOWSCOPE_STORAGE=sqlite) skips that: nothing about ClickHouse is downloaded and keeps the embedded SQLite store. An update leaves the storage of an
# existing install alone; FLOWSCOPE_STORAGE=clickhouse on an update adds the ClickHouse server and the setting, and you then pick
# ClickHouse under Storage in the web console (the old data is not copied over).
set -euo pipefail

OPT="${FLOWSCOPE_OPT:-/opt/flowscope}"
ETC="${FLOWSCOPE_ETC:-/etc/flowscope}"
VAR="${FLOWSCOPE_VAR:-/var/lib/flowscope}"
UNIT_DIR="${FLOWSCOPE_UNIT_DIR:-/etc/systemd/system}"
BIN_DIR="${FLOWSCOPE_BIN_DIR:-/usr/local/bin}"
NODE_DIR="${FLOWSCOPE_NODE_DIR:-/opt/node}"
NODE_MAJOR=22
NODE_MIN_MINOR=13
MODE="install"

say()  { printf '\033[1m==> %s\033[0m\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

for a in "$@"; do
  case "$a" in
    --update) MODE="update" ;;
    --sqlite) FLOWSCOPE_STORAGE=sqlite ;;
    --clickhouse) FLOWSCOPE_STORAGE=clickhouse ;;
    *) die "Unknown option: $a (use --update, --sqlite or --clickhouse)." ;;
  esac
done

[ "$(id -u)" -eq 0 ] || [ -n "${FLOWSCOPE_ALLOW_NONROOT:-}" ] || die "Run as root."
[ "$MODE" = "install" ] || [ -d "$OPT/dist/src" ] || die "FlowScope is not installed in $OPT; run without --update."

[ -z "${FLOWSCOPE_ADMIN_PASSWORD:-}" ] || [ "${#FLOWSCOPE_ADMIN_PASSWORD}" -ge 12 ] || die "FLOWSCOPE_ADMIN_PASSWORD must be at least 12 characters."

self="$0"
work="$(mktemp -d)"
cleanup() { rm -rf "$work"; case "$self" in /tmp/flowscope-install.*) rm -f "$self";; esac; }   # flowscope-ctl update runs a temporary copy of this script
trap cleanup EXIT

# ---------------------------------------------------------------- packages
need_pkgs=()
for c in curl tar xz gzip; do command -v "$c" >/dev/null 2>&1 || need_pkgs+=("$c"); done
[ -f /etc/ssl/certs/ca-certificates.crt ] || need_pkgs+=(ca-certificates)
if [ ${#need_pkgs[@]} -gt 0 ] && [ -z "${FLOWSCOPE_SKIP_APT:-}" ]; then
  say "Installing packages: ${need_pkgs[*]}"
  export DEBIAN_FRONTEND=noninteractive
  pkgs=()
  for p in "${need_pkgs[@]}"; do case "$p" in xz) pkgs+=(xz-utils);; *) pkgs+=("$p");; esac; done
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends "${pkgs[@]}"
fi

# ---------------------------------------------------------------- Node.js
node_ok() {
  command -v node >/dev/null 2>&1 || return 1
  node -e "const [a,b]=process.versions.node.split('.').map(Number); process.exit(a>$NODE_MAJOR||(a===$NODE_MAJOR&&b>=$NODE_MIN_MINOR)?0:1)"
}
if [ "${FLOWSCOPE_NODE:-}" = "system" ]; then
  node_ok || die "FLOWSCOPE_NODE=system but Node.js $NODE_MAJOR.$NODE_MIN_MINOR or newer was not found."
elif ! node_ok || [ -x "$NODE_DIR/bin/node" ]; then
  # Official Node.js build from nodejs.org, checked against its published SHA-256 list. Kept in $NODE_DIR, away from apt.
  case "$(uname -m)" in x86_64|amd64) arch=x64;; aarch64|arm64) arch=arm64;; armv7l) arch=armv7l;; *) die "Unsupported CPU: $(uname -m)";; esac
  base="https://nodejs.org/dist/latest-v${NODE_MAJOR}.x"
  say "Downloading Node.js ${NODE_MAJOR} (linux-$arch)"
  curl -fsSL "$base/SHASUMS256.txt" -o "$work/SHASUMS256.txt" || die "Could not reach nodejs.org. Install Node.js $NODE_MAJOR.$NODE_MIN_MINOR+ yourself and run again with FLOWSCOPE_NODE=system."
  file="$(grep -o "node-v[0-9.]*-linux-$arch\.tar\.xz" "$work/SHASUMS256.txt" | head -n1)"
  [ -n "$file" ] || die "No Node.js build for linux-$arch was found."
  curl -fsSL "$base/$file" -o "$work/$file"
  ( cd "$work" && grep " $file\$" SHASUMS256.txt | sha256sum -c - >/dev/null ) || die "Node.js download failed its checksum."
  rm -rf "$NODE_DIR.new"; mkdir -p "$NODE_DIR.new"
  tar -xJf "$work/$file" -C "$NODE_DIR.new" --strip-components=1
  rm -rf "$NODE_DIR"; mv "$NODE_DIR.new" "$NODE_DIR"
  export PATH="$NODE_DIR/bin:$PATH"
  ln -sf "$NODE_DIR/bin/node" "$BIN_DIR/node"; ln -sf "$NODE_DIR/bin/npm" "$BIN_DIR/npm"; ln -sf "$NODE_DIR/bin/npx" "$BIN_DIR/npx"
fi
export PATH="${NODE_DIR}/bin:$PATH"
node_ok || die "Node.js $NODE_MAJOR.$NODE_MIN_MINOR or newer is required (found $(node -v 2>/dev/null || echo none))."
NODE_BIN="$(command -v node)"
say "Using Node.js $(node -v) at $NODE_BIN"

# ---------------------------------------------------------------- source
src=""
ref="${FLOWSCOPE_REF:-main}"
if [ -n "${FLOWSCOPE_SRC:-}" ]; then
  if [ -d "$FLOWSCOPE_SRC" ]; then src="$FLOWSCOPE_SRC"
  elif [ -f "$FLOWSCOPE_SRC" ]; then
    mkdir -p "$work/src"; tar -xzf "$FLOWSCOPE_SRC" -C "$work/src" --strip-components=0
    # a GitHub tarball has one top-level folder; one made by flowscope-lxc.sh has none
    if [ ! -f "$work/src/package.json" ]; then top="$(find "$work/src" -mindepth 1 -maxdepth 1 -type d | head -n1)"; [ -n "$top" ] && src="$top"; else src="$work/src"; fi
  else die "FLOWSCOPE_SRC=$FLOWSCOPE_SRC does not exist."; fi
elif [ -n "${FLOWSCOPE_REPO:-}" ]; then
  say "Downloading $FLOWSCOPE_REPO@$ref from GitHub"
  auth=(); [ -n "${GITHUB_TOKEN:-}" ] && auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
  curl -fsSL "${auth[@]}" -H "Accept: application/vnd.github+json" "https://api.github.com/repos/$FLOWSCOPE_REPO/tarball/$ref" -o "$work/src.tgz" \
    || die "Could not download $FLOWSCOPE_REPO. A private repository needs GITHUB_TOKEN (read access to contents)."
  mkdir -p "$work/src"; tar -xzf "$work/src.tgz" -C "$work/src"
  src="$(find "$work/src" -mindepth 1 -maxdepth 1 -type d | head -n1)"
else
  die "No source given. Set FLOWSCOPE_SRC (a tarball or checkout) or FLOWSCOPE_REPO (owner/name)."
fi
# Which commit this is, for `flowscope version`: given by the caller, else asked of git, else read from the name of the GitHub tarball folder
# (owner-repo-<commit>). The build below runs on a copy with no .git folder, so it has to be settled here.
if [ -z "${FLOWSCOPE_REVISION:-}" ] && command -v git >/dev/null 2>&1 && [ -d "$src/.git" ]; then
  FLOWSCOPE_REVISION="$(git -C "$src" rev-parse HEAD 2>/dev/null || true)"
  [ -n "$FLOWSCOPE_REVISION" ] && [ -n "$(git -C "$src" status --porcelain --untracked-files=no 2>/dev/null)" ] && FLOWSCOPE_REVISION="$FLOWSCOPE_REVISION-dirty"
fi
if [ -z "${FLOWSCOPE_REVISION:-}" ] && [ -n "${FLOWSCOPE_REPO:-}" ]; then
  FLOWSCOPE_REVISION="$(basename "$src" | sed -n 's/.*-\([0-9a-f]\{7,40\}\)$/\1/p')"
fi
export FLOWSCOPE_REVISION="${FLOWSCOPE_REVISION:-unknown}"
[ -f "$src/package.json" ] && [ -f "$src/packaging/linux/flowscope.service" ] || die "$src does not look like a FlowScope checkout."
# shellcheck source=../linux/clickhouse-setup.sh
. "$src/packaging/linux/clickhouse-setup.sh"

# ---------------------------------------------------------------- storage: ClickHouse server
want_ch=0
case "${FLOWSCOPE_STORAGE:-}" in
  clickhouse) want_ch=1 ;;
  sqlite) want_ch=0 ;;
  "") [ "$MODE" = "install" ] && want_ch=1 ;;
  *) die "FLOWSCOPE_STORAGE must be clickhouse or sqlite." ;;
esac
if [ "$want_ch" = 1 ]; then
  ch_install_package
  ch_write_listen_config
  # Not in the template build: it runs on the build machine's CPU, so the answer would mean nothing. The first-boot service asks on the real one.
  if [ -z "${FLOWSCOPE_TEMPLATE_BUILD:-}" ] && ! ch_binary_works; then
    warn "$(ch_cpu_message) Using SQLite for now."
    systemctl disable --now clickhouse-server >/dev/null 2>&1 || true
    want_ch=0
  fi
fi

# ---------------------------------------------------------------- build
say "Building FlowScope"
build="$work/build"; mkdir -p "$build"
( cd "$src" && tar --exclude=./.git --exclude=./node_modules --exclude=./dist --exclude=./data -cf - . ) | tar -xf - -C "$build"
( cd "$build"
  npm install --no-audit --no-fund --loglevel=error
  node tools/build.mjs
  npm prune --omit=dev --no-audit --no-fund --loglevel=error )

# ---------------------------------------------------------------- install files
id flowscope >/dev/null 2>&1 || useradd --system --home-dir "$VAR" --shell /usr/sbin/nologin flowscope
install -d -m 755 "$ETC"
install -d -m 750 -o flowscope -g flowscope "$VAR"

if command -v systemctl >/dev/null 2>&1 && [ -z "${FLOWSCOPE_SKIP_SYSTEMD:-}" ] && systemctl is-active --quiet flowscope 2>/dev/null; then
  say "Stopping the running service"; systemctl stop flowscope
fi

# what is installed now, to say afterwards whether the update changed anything
old_ver=""
[ -f "$OPT/dist/src/cli.js" ] && old_ver="$("$NODE_BIN" --disable-warning=ExperimentalWarning "$OPT/dist/src/cli.js" version 2>/dev/null | head -n1 || true)"

new="$OPT.new"; rm -rf "$new"; mkdir -p "$new"
cp -a "$build/dist" "$build/package.json" "$build/node_modules" "$new/"
mkdir -p "$new/packaging"; cp -a "$build/packaging/." "$new/packaging/"
rm -rf "$OPT.prev"; [ -d "$OPT" ] && mv "$OPT" "$OPT.prev"
mv "$new" "$OPT"
say "Installed to $OPT (the previous version, if any, is in $OPT.prev)"

# ---------------------------------------------------------------- settings
first_pw=""
if [ ! -f "$ETC/flowscope.env" ]; then
  if [ -z "${FLOWSCOPE_TEMPLATE_BUILD:-}" ]; then
    first_pw="${FLOWSCOPE_ADMIN_PASSWORD:-$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 20)}"
    [ "${#first_pw}" -ge 12 ] || die "FLOWSCOPE_ADMIN_PASSWORD must be at least 12 characters."
    pwline="FLOWSCOPE_ADMIN_PASSWORD=$first_pw"
  else
    pwline="# FLOWSCOPE_ADMIN_PASSWORD=                # a first-boot service generated one for this container; see /root/flowscope-admin-password.txt"
  fi
  cat > "$ETC/flowscope.env" <<ENV
# One KEY=value per line. See the README for every setting. Restart after a change: systemctl restart flowscope
# Password of the "admin" account. It is only read the first time FlowScope starts; delete this line after you have signed in.
$pwline
# The web console. 443 on new installs; an install made before that keeps 8443 (this line is not added to an existing file).
FLOWSCOPE_HTTPS_PORT=443
# FLOWSCOPE_FLOW_PORTS=2055,4739
# FLOWSCOPE_TLS=off              # plain HTTP on 8080 behind your own reverse proxy
# FLOWSCOPE_PUBLIC_URL=https://flows.example.com
# FLOWSCOPE_CLICKHOUSE_URL=
ENV
fi
chmod 640 "$ETC/flowscope.env"; chown root:flowscope "$ETC/flowscope.env"

# A ClickHouse user for FlowScope with its own random password, kept only in the settings file. Not in the template build: there the
# first-boot service does this for each container, so no two containers share a password.
if [ "$want_ch" = 1 ] && [ -z "${FLOWSCOPE_TEMPLATE_BUILD:-}" ] && ! grep -Eq '^[[:space:]]*FLOWSCOPE_CLICKHOUSE_URL=.+' "$ETC/flowscope.env"; then
  ch_pw="$(ch_gen_password)"
  ch_write_user "$ch_pw"
  printf '\n# Storage: the ClickHouse server on this machine, set up by the installer. Remove this line and restart to use another server.\nFLOWSCOPE_CLICKHOUSE_URL=%s\n' "$(ch_url "$ch_pw")" >> "$ETC/flowscope.env"
fi

# ---------------------------------------------------------------- service
unit="$UNIT_DIR/flowscope.service"
install -d "$UNIT_DIR"
sed -e "s#^ExecStart=.*#ExecStart=$NODE_BIN --disable-warning=ExperimentalWarning $OPT/dist/src/cli.js start#" -e "s#^WorkingDirectory=.*#WorkingDirectory=$OPT#" \
    "$src/packaging/linux/flowscope.service" > "$unit"
chmod 644 "$unit"
# Inside an LXC container systemd cannot always set up the mount namespaces behind ProtectSystem, PrivateTmp and PrivateDevices
# (the service then fails with status 226/NAMESPACE). The container is already the isolation boundary, so those are switched off here
# and the remaining hardening (no new privileges, restricted address families, ...) stays. Every directive that makes systemd build a
# mount namespace has to be switched off, including ReadWritePaths=, or the service still fails to start.
virt="$(systemd-detect-virt --container 2>/dev/null || true)"
if [ "$virt" = "lxc" ] || [ "$virt" = "lxc-libvirt" ] || [ "$virt" = "openvz" ] || [ -n "${FLOWSCOPE_LXC:-}" ]; then
  d="$UNIT_DIR/flowscope.service.d"; mkdir -p "$d"
  cat > "$d/lxc.conf" <<'CONF'
# Written by the FlowScope installer: running inside an LXC container.
[Service]
ProtectSystem=no
ProtectHome=no
PrivateTmp=no
PrivateDevices=no
ProtectKernelTunables=no
ProtectKernelModules=no
ProtectControlGroups=no
# ReadWritePaths= alone makes systemd build a mount namespace, which is what fails inside a container without the Nesting feature.
ReadWritePaths=
CONF
  say "LXC container detected: relaxed the systemd mount sandboxing (drop-in $d/lxc.conf)"
fi

# ---------------------------------------------------------------- helper command
cat > "$BIN_DIR/flowscope-ctl" <<CTL
#!/bin/sh
# Small helper installed by FlowScope. Usage: flowscope-ctl status | doctor | logs | update [branch-or-tag] | reset-password <user> | version
case "\${1:-status}" in
  status) systemctl status flowscope --no-pager ;;
  doctor)
    # One screen of facts to read when the web console does not answer.
    echo "== service"; systemctl is-enabled flowscope 2>&1; systemctl is-active flowscope 2>&1
    p=\$(sed -n 's/^[[:space:]]*FLOWSCOPE_HTTPS_PORT=\\([0-9]*\\).*/\\1/p' $ETC/flowscope.env 2>/dev/null | tail -n1); p=\${p:-8443}
    echo "== listening (expect TCP \$p and UDP 2055, 4739)"; ss -H -ltun 2>/dev/null | grep -E ":(\$p|2055|4739)\\b" || echo "nothing is listening on the FlowScope ports"
    echo "== container type: \$(systemd-detect-virt 2>/dev/null || echo unknown)   (nesting must be on in the Proxmox container options if this is lxc)"
    echo "== last log lines"; journalctl -u flowscope --no-pager -n 25 2>&1
    echo "== first-boot service"; systemctl is-active flowscope-firstboot 2>&1 || true
    if [ -e $ETC/.clickhouse-unsupported ]; then
      echo "== clickhouse: not started, this CPU cannot run it (it dies with an illegal-instruction signal). FlowScope uses SQLite."
      echo "   A Proxmox container uses the host's CPU; give the host (or its VM: Hardware, Processors, Type = host) a newer CPU type to use ClickHouse."
    elif systemctl cat clickhouse-server >/dev/null 2>&1; then
      echo "== clickhouse (FlowScope storage)"; systemctl is-active clickhouse-server 2>&1
      systemctl show clickhouse-server -p ExecMainStatus -p Result 2>&1 | grep -q 'Result=signal' && echo "killed by a signal: if it is ILL, this CPU cannot run ClickHouse (see docs/deployment.md)"
      curl -fsS --max-time 3 http://127.0.0.1:8123/ping 2>&1 | head -c 40 || echo "ClickHouse does not answer on 127.0.0.1:8123 (journalctl -u clickhouse-server -n 50)"
    fi ;;
  logs) shift; exec journalctl -u flowscope --no-pager "\${@:--n 100}" ;;
  reset-password) shift; exec runuser -u flowscope -- env FLOWSCOPE_DATA_DIR=$VAR $NODE_BIN --disable-warning=ExperimentalWarning $OPT/dist/src/cli.js reset-password "\$@" ;;
  version) exec $NODE_BIN $OPT/dist/src/cli.js version ;;
  update)
    # Downloads the source from GitHub and installs it: the main branch unless a branch or tag is given (flowscope-ctl update my-branch, or
    # FLOWSCOPE_REF=my-branch in $ETC/update.env). A private repository needs GITHUB_TOKEN=... in $ETC/update.env (chmod 600).
    ref_arg="\${2:-}"
    if [ -f $ETC/update.env ]; then set -a; . $ETC/update.env; set +a; fi
    [ -z "\$ref_arg" ] || FLOWSCOPE_REF="\$ref_arg"
    t=\$(mktemp /tmp/flowscope-install.XXXXXX) || exit 1
    cp $OPT/packaging/proxmox/install.sh "\$t"
    exec env FLOWSCOPE_REPO="\${FLOWSCOPE_REPO:-jballanger0226/flowscope}" FLOWSCOPE_REF="\${FLOWSCOPE_REF:-main}" bash "\$t" --update ;;
  *) echo "usage: flowscope-ctl status | doctor | logs | update [branch-or-tag] | reset-password <user> | version" >&2; exit 2 ;;
esac
CTL
chmod 755 "$BIN_DIR/flowscope-ctl"

if command -v systemctl >/dev/null 2>&1 && [ -z "${FLOWSCOPE_SKIP_SYSTEMD:-}" ]; then
  systemctl daemon-reload
  if [ "$want_ch" = 1 ]; then
    systemctl enable clickhouse-server >/dev/null 2>&1 || true
    # a restart, not a start: the server may already be running from the package install, before it was told to listen on 127.0.0.1 only
    systemctl restart clickhouse-server
    say "Waiting for ClickHouse"
    ch_wait || warn "ClickHouse did not answer within 90 seconds. Look at: journalctl -u clickhouse-server -n 50   (FlowScope keeps trying for a minute, then uses SQLite for this run)"
  fi
  systemctl enable flowscope >/dev/null 2>&1 || true
  systemctl restart flowscope
  say "Waiting for FlowScope to answer"
  ok=0
  for _ in $(seq 1 30); do
    if FLOWSCOPE_DATA_DIR="$VAR" "$NODE_BIN" --disable-warning=ExperimentalWarning "$OPT/dist/src/cli.js" healthcheck >/dev/null 2>&1; then ok=1; break; fi
    sleep 2
  done
  if [ "$ok" = 1 ]; then say "FlowScope is running"; else warn "FlowScope did not answer within a minute. Look at: journalctl -u flowscope -n 50"; fi
fi

echo
if [ -n "$first_pw" ]; then
  echo "  Sign in as:  admin"
  echo "  Password:    $first_pw   (used once; change it after signing in)"
fi
if [ "$MODE" = "update" ]; then
  new_ver="$("$NODE_BIN" --disable-warning=ExperimentalWarning "$OPT/dist/src/cli.js" version 2>/dev/null | head -n1 || true)"
  if [ -n "${FLOWSCOPE_REPO:-}" ]; then from="$FLOWSCOPE_REPO@$ref"; else from="the source you gave"; fi
  echo "  Updated from: ${old_ver:-unknown}"
  echo "            to: ${new_ver:-unknown}   (source: $from)"
  if [ -n "$old_ver" ] && [ "$old_ver" = "$new_ver" ]; then
    echo "  This is the same build that was installed before. If you expected a newer one: the default source is the main branch;"
    echo "  to install a branch or tag, run:  flowscope-ctl update <branch-or-tag>"
  fi
  echo "  If something is wrong, the previous version is in $OPT.prev"
fi
webport="$(sed -n 's/^[[:space:]]*FLOWSCOPE_HTTPS_PORT=\([0-9]*\).*/\1/p' "$ETC/flowscope.env" 2>/dev/null | tail -n1)"; webport="${webport:-8443}"   # an install from before 443 became the default keeps 8443
echo "  Web console: https://$(hostname -I 2>/dev/null | awk '{print $1}'):$webport/   (self-signed certificate until you install your own)"
echo "  Send NetFlow v5/v9 or IPFIX to UDP 2055 or 4739 on this machine."
if grep -Eq '^[[:space:]]*FLOWSCOPE_CLICKHOUSE_URL=.+' "$ETC/flowscope.env" 2>/dev/null || { [ -n "${FLOWSCOPE_TEMPLATE_BUILD:-}" ] && [ "$want_ch" = 1 ]; }; then
  echo "  Storage:     ClickHouse (data in /var/lib/clickhouse; it is on the container's root disk, so the container backup covers it)."
else
  echo "  Storage:     SQLite (embedded, in /var/lib/flowscope). To use ClickHouse instead, see docs/deployment.md."
fi
