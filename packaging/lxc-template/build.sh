#!/usr/bin/env bash
# Builds the FlowScope Proxmox VE container template: a .tar.zst you upload in the Proxmox web interface.
#
#   packaging/lxc-template/build.sh                 -> template-out/debian-12-flowscope_<version>_amd64.tar.zst (+ .sha256)
#
# Needs a Linux machine (or WSL) with Docker and zstd, and internet access for the Debian packages and npm. It does not need Proxmox.
# GitHub Actions runs this for you (.github/workflows/lxc-template.yml); download its result from the Releases page instead if you prefer.
# Settings: OUT (output folder, default template-out), PLATFORM (default linux/amd64).
set -euo pipefail

say() { printf '\033[1m==> %s\033[0m\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "Docker is required."
command -v zstd   >/dev/null 2>&1 || die "zstd is required (apt install zstd)."

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo"
[ -f package.json ] || die "package.json not found in $repo"
version="$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' package.json | head -n1)"
[ -n "$version" ] || die "Could not read the version from package.json."
OUT="${OUT:-template-out}"; PLATFORM="${PLATFORM:-linux/amd64}"
case "$PLATFORM" in linux/amd64) arch=amd64;; linux/arm64) arch=arm64;; *) die "PLATFORM must be linux/amd64 or linux/arm64";; esac
name="debian-12-flowscope_${version}_${arch}.tar.zst"
mkdir -p "$OUT"

say "Building the root filesystem (Debian 12 + FlowScope $version, $PLATFORM)"
DOCKER_BUILDKIT=1 docker build --platform "$PLATFORM" -f packaging/lxc-template/Dockerfile \
  --output "type=tar,dest=$OUT/rootfs.tar" .

say "Compressing to $OUT/$name"
zstd -T0 -19 --force -q "$OUT/rootfs.tar" -o "$OUT/$name"
rm -f "$OUT/rootfs.tar"
( cd "$OUT" && sha256sum "$name" > "$name.sha256" )

say "Done: $OUT/$name ($(du -h "$OUT/$name" | cut -f1))"
echo "Upload it in Proxmox: Datacenter -> your node -> a storage with 'Container template' content -> CT Templates -> Upload."
echo "Then Create CT and choose it as the template. Directions: docs/deployment.md"
