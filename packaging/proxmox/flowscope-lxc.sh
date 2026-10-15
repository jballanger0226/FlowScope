#!/usr/bin/env bash
# Creates a FlowScope LXC container on a Proxmox VE host, or updates one made by this script.
# Run it as root in a shell on the Proxmox host (Datacenter -> your node -> Shell), from a checkout of the repository:
#
#   git clone https://github.com/jballanger0226/flowscope && cd flowscope      (a private repository needs a token or a download of the zip)
#   packaging/proxmox/flowscope-lxc.sh                      create a container with the defaults
#   CTID=210 IP=192.168.10.50/24 GW=192.168.10.1 packaging/proxmox/flowscope-lxc.sh
#   packaging/proxmox/flowscope-lxc.sh update 210           put the current checkout into container 210
#
# Settings (environment variables):
#   CTID          container id                          (default: the next free id)
#   CT_HOSTNAME   container host name                   (default: flowscope)
#   IP            dhcp, or an address with prefix        (default: dhcp)         e.g. 192.168.10.50/24
#   GW            gateway, for a static IP
#   BRIDGE        network bridge                        (default: vmbr0)
#   VLAN          VLAN tag for the container's NIC      (default: none)
#   DNS           name server                           (default: the host's setting)
#   STORAGE       storage for the root disk             (default: local-lvm if it exists, else local)
#   TEMPLATE_STORAGE   storage that holds templates     (default: local)
#   DISK_GB       root disk size in GB                  (default: 32; flow records and ClickHouse need room, see the README)
#   CORES, MEMORY (MB), SWAP (MB)                       (default: 2, 4096, 512; ClickHouse is the default storage and wants the memory)
#   STORAGE_BACKEND  clickhouse or sqlite               (default: clickhouse, installed inside the container)
#
# Options (anywhere on the command line):
#   --sqlite      no ClickHouse: nothing about it is downloaded, flow records go into the embedded SQLite file. Smaller defaults:
#                 2048 MB memory and a 16 GB disk, unless you set MEMORY and DISK_GB.
#   --clickhouse  ClickHouse, the default
#   ADMIN_PASSWORD  password for "admin"                (default: generated and printed at the end)
#   TEMPLATE      a template file name such as debian-12-standard_12.12-1_amd64.tar.zst   (default: the newest Debian 12 one)
#   START_ON_BOOT 1 or 0                                (default: 1)
set -euo pipefail

say()  { printf '\033[1m==> %s\033[0m\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run as root on the Proxmox host."
command -v pct >/dev/null 2>&1 && command -v pveam >/dev/null 2>&1 || die "pct and pveam were not found. Run this on a Proxmox VE host, not inside a container."

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
[ -f "$repo/package.json" ] && [ -f "$here/install.sh" ] || die "Run this script from a checkout of the FlowScope repository (packaging/proxmox/flowscope-lxc.sh)."

rest=()
for a in "$@"; do
  case "$a" in
    --sqlite) STORAGE_BACKEND=sqlite ;;
    --clickhouse) STORAGE_BACKEND=clickhouse ;;
    *) rest+=("$a") ;;
  esac
done
set -- "${rest[@]+"${rest[@]}"}"
case "${STORAGE_BACKEND:-}" in ""|clickhouse|sqlite) ;; *) die "STORAGE_BACKEND must be clickhouse or sqlite." ;; esac

cmd="create"; [ "${1:-}" = "update" ] && { cmd="update"; shift; }

# the source of the repository, as a tarball with no top-level folder (the installer builds it inside the container)
make_tarball() {
  local out="$1"
  tar -C "$repo" --exclude=./.git --exclude=./node_modules --exclude=./dist --exclude=./data -czf "$out" .
}

push_and_install() {
  local id="$1" mode="$2" pw="${3:-}"
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  say "Packing the source"
  make_tarball "$tmp/flowscope-src.tgz"
  pct push "$id" "$tmp/flowscope-src.tgz" /root/flowscope-src.tgz
  pct push "$id" "$here/install.sh" /root/flowscope-install.sh --perms 755
  say "Installing inside container $id (downloads Node.js and the npm packages; takes a few minutes)"
  local env=(FLOWSCOPE_SRC=/root/flowscope-src.tgz)
  local rev; rev="$(git -C "$repo" rev-parse HEAD 2>/dev/null || true)"
  if [ -n "$rev" ]; then
    [ -n "$(git -C "$repo" status --porcelain --untracked-files=no 2>/dev/null)" ] && rev="$rev-dirty"
    env+=("FLOWSCOPE_REVISION=$rev")
  fi
  [ -n "$pw" ] && env+=("FLOWSCOPE_ADMIN_PASSWORD=$pw")
  [ -n "${STORAGE_BACKEND:-}" ] && env+=("FLOWSCOPE_STORAGE=$STORAGE_BACKEND")
  local args=(); [ "$mode" = update ] && args=(--update)
  pct exec "$id" -- env "${env[@]}" bash /root/flowscope-install.sh "${args[@]}"
  pct exec "$id" -- rm -f /root/flowscope-src.tgz
}

if [ "$cmd" = "update" ]; then
  id="${1:-${CTID:-}}"; [ -n "$id" ] || die "Usage: $0 update <CTID>"
  pct status "$id" >/dev/null 2>&1 || die "Container $id does not exist."
  [ "$(pct status "$id" | awk '{print $2}')" = running ] || pct start "$id"
  say "Taking a snapshot first, so the update can be undone (pct rollback $id pre-update)"
  pct delsnapshot "$id" pre-update >/dev/null 2>&1 || true
  pct snapshot "$id" pre-update --description "Before FlowScope update $(date -u +%F)" || echo "(snapshots are not supported on this storage; continuing without one)"
  push_and_install "$id" update
  exit 0
fi

# ---------------------------------------------------------------- create
CTID="${CTID:-$(pvesh get /cluster/nextid)}"
HOSTNAME_CT="${CT_HOSTNAME:-flowscope}"
IP="${IP:-dhcp}"; BRIDGE="${BRIDGE:-vmbr0}"; def_disk=32; def_mem=4096; [ "${STORAGE_BACKEND:-}" = sqlite ] && { def_disk=16; def_mem=2048; }
DISK_GB="${DISK_GB:-$def_disk}"; CORES="${CORES:-2}"; MEMORY="${MEMORY:-$def_mem}"; SWAP="${SWAP:-512}"
TEMPLATE_STORAGE="${TEMPLATE_STORAGE:-local}"; START_ON_BOOT="${START_ON_BOOT:-1}"
if [ -z "${STORAGE:-}" ]; then pvesm status --content rootdir 2>/dev/null | awk 'NR>1{print $1}' | grep -qx local-lvm && STORAGE=local-lvm || STORAGE=local; fi
pct status "$CTID" >/dev/null 2>&1 && die "Container id $CTID is already in use. Choose another with CTID=..."
[ "$IP" = dhcp ] || [ -n "${GW:-}" ] || die "A static IP needs a gateway: GW=..."

say "Looking for a Debian 12 template"
if [ -z "${TEMPLATE:-}" ]; then
  pveam update >/dev/null
  TEMPLATE="$(pveam available --section system | awk '{print $2}' | grep '^debian-12-standard' | sort -V | tail -n1)"
  [ -n "$TEMPLATE" ] || die "No Debian 12 template was listed by pveam. Set TEMPLATE=... to a template you already have."
fi
if ! pveam list "$TEMPLATE_STORAGE" | awk '{print $1}' | grep -q "/$TEMPLATE\$"; then
  say "Downloading $TEMPLATE to $TEMPLATE_STORAGE"
  pveam download "$TEMPLATE_STORAGE" "$TEMPLATE"
fi

net="name=eth0,bridge=$BRIDGE,firewall=0"
if [ "$IP" = dhcp ]; then net+=",ip=dhcp"; else net+=",ip=$IP,gw=$GW"; fi
[ -n "${VLAN:-}" ] && net+=",tag=$VLAN"
opts=(--hostname "$HOSTNAME_CT" --cores "$CORES" --memory "$MEMORY" --swap "$SWAP" --rootfs "$STORAGE:$DISK_GB"
      --net0 "$net" --unprivileged 1 --features nesting=1 --onboot "$START_ON_BOOT" --ostype debian --tags flowscope)
[ -n "${DNS:-}" ] && opts+=(--nameserver "$DNS")

say "Creating container $CTID ($HOSTNAME_CT) on $STORAGE"
pct create "$CTID" "$TEMPLATE_STORAGE:vztmpl/$TEMPLATE" "${opts[@]}"
pct start "$CTID"

say "Waiting for the container's network"
up=0
for _ in $(seq 1 40); do
  if pct exec "$CTID" -- sh -c 'getent hosts deb.debian.org >/dev/null 2>&1'; then up=1; break; fi
  sleep 2
done
[ "$up" = 1 ] || die "The container has no working network or DNS. Check the bridge ($BRIDGE), the gateway and the DNS setting, then: pct stop $CTID && pct destroy $CTID"

password="${ADMIN_PASSWORD:-}"
if [ -z "$password" ]; then password="$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 20)"; fi
push_and_install "$CTID" install "$password"

addr="$(pct exec "$CTID" -- hostname -I 2>/dev/null | awk '{print $1}')"
cat <<DONE

FlowScope is installed in container $CTID.
  Web console:  https://${addr:-<container ip>}/             (self-signed certificate: the browser will warn once)
  Sign in:      admin / $password   (change it after signing in)
  Exporters:    send NetFlow v5/v9 or IPFIX to ${addr:-<container ip>} UDP 2055 or 4739
  Logs:         pct exec $CTID -- flowscope-ctl logs
  Update:       packaging/proxmox/flowscope-lxc.sh update $CTID     (from an updated checkout)
Back the container up with vzdump or Proxmox Backup Server; all FlowScope data is on its root disk (/var/lib/flowscope, and /var/lib/clickhouse for flow records).
DONE
