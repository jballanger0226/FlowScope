# shellcheck shell=sh
# Shared ClickHouse setup for FlowScope on Debian/Ubuntu-style Linux (a host, a VM, or a Proxmox LXC container).
# Sourced, never run directly, by packaging/linux/install.sh, packaging/proxmox/install.sh and the template's first-boot script.
# Plain POSIX sh, so the first-boot script (/bin/sh) can use it too. The caller defines say, warn and die.
#
# What it sets up: the official ClickHouse server package, listening on 127.0.0.1 only, and a database user "flowscope" with a random
# password that only FlowScope knows (it is written to the FlowScope settings file as FLOWSCOPE_CLICKHOUSE_URL).

CH_ETC="${FLOWSCOPE_CH_ETC:-/etc/clickhouse-server}"
CH_PORT=8123

ch_gen_password() { head -c 64 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24; }

# The server package from ClickHouse's own repository (the LTS line). Skipped when the server is already installed.
ch_install_package() {
  if command -v clickhouse-server >/dev/null 2>&1; then return 0; fi
  [ -z "${FLOWSCOPE_SKIP_APT:-}" ] || die "clickhouse-server is not installed and FLOWSCOPE_SKIP_APT is set. Install it first, or use FLOWSCOPE_STORAGE=sqlite."
  command -v apt-get >/dev/null 2>&1 || die "Installing ClickHouse automatically needs apt (Debian or Ubuntu). Install ClickHouse yourself and set FLOWSCOPE_CLICKHOUSE_URL, or use FLOWSCOPE_STORAGE=sqlite."
  say "Installing ClickHouse from packages.clickhouse.com"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends gnupg apt-transport-https ca-certificates curl
  curl -fsSL 'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key' | gpg --dearmor --yes -o /usr/share/keyrings/clickhouse-keyring.gpg \
    || die "Could not download the ClickHouse repository key. Check the network, or use FLOWSCOPE_STORAGE=sqlite."
  echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg arch=$(dpkg --print-architecture)] https://packages.clickhouse.com/deb lts main" > /etc/apt/sources.list.d/clickhouse.list
  apt-get update -qq
  apt-get install -y -qq clickhouse-server clickhouse-client
}

# Keeps the server on the loopback address: FlowScope runs on the same machine, nothing else should reach it.
ch_write_listen_config() {
  [ -d "$CH_ETC" ] || die "$CH_ETC not found: ClickHouse is not installed."
  mkdir -p "$CH_ETC/config.d"
  cat > "$CH_ETC/config.d/flowscope.xml" <<'XML'
<!-- Written by the FlowScope installer. -->
<clickhouse>
    <listen_host>127.0.0.1</listen_host>
</clickhouse>
XML
  chmod 644 "$CH_ETC/config.d/flowscope.xml"
}

# Creates (or replaces) the "flowscope" database user with the given password, usable from this machine only.
ch_write_user() {
  _pw="$1"
  [ -d "$CH_ETC" ] || die "$CH_ETC not found: ClickHouse is not installed."
  mkdir -p "$CH_ETC/users.d"
  _hex="$(printf '%s' "$_pw" | sha256sum | cut -d' ' -f1)"
  _f="$CH_ETC/users.d/flowscope.xml"
  ( umask 027
    cat > "$_f" <<XML
<!-- Written by the FlowScope installer. FlowScope connects as this user; the password is in its settings file. -->
<clickhouse>
    <users>
        <flowscope>
            <password_sha256_hex>$_hex</password_sha256_hex>
            <networks><ip>127.0.0.1</ip><ip>::1</ip></networks>
            <profile>default</profile>
            <quota>default</quota>
            <access_management>1</access_management>
        </flowscope>
    </users>
</clickhouse>
XML
  )
  if id clickhouse >/dev/null 2>&1; then chown clickhouse:clickhouse "$_f"; fi
  chmod 640 "$_f"
}

ch_url() { printf 'http://flowscope:%s@127.0.0.1:%s/flowscope' "$1" "$CH_PORT"; }

# Waits until the server answers its ping page.
ch_wait() {
  _n=0
  while [ "$_n" -lt 45 ]; do
    if curl -fsS --max-time 2 "http://127.0.0.1:$CH_PORT/ping" >/dev/null 2>&1; then return 0; fi
    _n=$((_n + 1)); sleep 2
  done
  return 1
}
