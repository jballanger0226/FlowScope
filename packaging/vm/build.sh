#!/usr/bin/env bash
# Builds the FlowScope virtual machine appliance: Debian 12 + FlowScope (+ ClickHouse) on a bootable disk, as
#   vm-out/flowscope-vm_<version>_amd64.ova     for VMware ESXi / vCenter (also Workstation and Fusion)
#   vm-out/flowscope-vm_<version>_amd64.qcow2   for Nutanix AHV (Prism: Settings -> Image Configuration), and for KVM / Proxmox / OpenStack
#   STORAGE_BACKEND=sqlite packaging/vm/build.sh   -> flowscope-vm-sqlite_...  (no ClickHouse; flow records go in the embedded SQLite file)
#
# How: the same Docker build that makes the Proxmox template makes the root filesystem (Debian + Node.js + FlowScope + ClickHouse, with the
# first-boot service), then this script puts it on a GPT disk, adds a kernel, a boot loader for BIOS and UEFI, cloud-init and the guest
# agents (VMware Tools, QEMU guest agent), and converts the disk. It needs root (loop devices and chroot), Docker, and:
#   qemu-img (qemu-utils), sgdisk (gdisk), mkfs.vfat (dosfstools), mkfs.ext4 (e2fsprogs), node (for the OVA packer).
# GitHub Actions runs this (.github/workflows/vm-image.yml); the result is on the Releases page. Settings (environment variables):
#   OUT (default vm-out)   DISK_GB (default 20)   CPUS (default 2)   MEMORY_MB (default 4096)   STORAGE_BACKEND (clickhouse | sqlite)
set -euo pipefail

say() { printf '\033[1m==> %s\033[0m\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "Run as root (sudo $0): it needs loop devices and chroot."
for c in docker qemu-img sgdisk mkfs.vfat mkfs.ext4 losetup blkid node; do command -v "$c" >/dev/null 2>&1 || die "$c is required."; done

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
cd "$repo"
version="$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' package.json | head -n1)"
[ -n "$version" ] || die "Could not read the version from package.json."
rev="${GIT_SHA:-$(git rev-parse HEAD 2>/dev/null || true)}"; rev="${rev:-unknown}"
OUT="${OUT:-vm-out}"; DISK_GB="${DISK_GB:-20}"; CPUS="${CPUS:-2}"; MEMORY_MB="${MEMORY_MB:-4096}"
STORAGE_BACKEND="${STORAGE_BACKEND:-clickhouse}"
case "$STORAGE_BACKEND" in clickhouse) variant="";; sqlite) variant="-sqlite";; *) die "STORAGE_BACKEND must be clickhouse or sqlite";; esac
case "$DISK_GB" in ''|*[!0-9]*) die "DISK_GB must be a whole number of gigabytes";; esac
[ "$DISK_GB" -ge 8 ] || die "DISK_GB must be at least 8"
name="flowscope-vm${variant}_${version}_amd64"
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
work="$(mktemp -d "$OUT/work.XXXXXX")"
mnt="$work/mnt"; raw="$work/disk.raw"; loop=""

cleanup() {
  set +e
  if [ -d "$mnt" ]; then
    for m in dev/pts dev proc sys run boot/efi ""; do mountpoint -q "$mnt/$m" 2>/dev/null && umount -R -l "$mnt/$m" 2>/dev/null; done
  fi
  [ -n "$loop" ] && losetup -d "$loop" 2>/dev/null
  # never delete the work folder while anything is still mounted inside it (a bind-mounted /dev would be deleted with it)
  if grep -q " $work/" /proc/mounts 2>/dev/null; then echo "warning: something is still mounted under $work; leaving it for you to unmount and remove" >&2; else rm -rf --one-file-system "$work"; fi
}
trap cleanup EXIT

say "Building the root filesystem (Debian 12 + FlowScope $version, storage: $STORAGE_BACKEND)"
DOCKER_BUILDKIT=1 docker build --platform linux/amd64 --build-arg "STORAGE_BACKEND=$STORAGE_BACKEND" --build-arg TEMPLATE_KIND=vm --build-arg "GIT_SHA=$rev" \
  -f packaging/lxc-template/Dockerfile --output "type=tar,dest=$work/rootfs.tar" .

say "Making the disk ($DISK_GB GB, GPT: BIOS boot, EFI system, root)"
truncate -s "${DISK_GB}G" "$raw"
sgdisk --zap-all "$raw" >/dev/null
sgdisk -n 1:2048:+1M -t 1:EF02 -c 1:bios_grub \
       -n 2:0:+256M  -t 2:EF00 -c 2:esp \
       -n 3:0:0      -t 3:8300 -c 3:root "$raw" >/dev/null
loop="$(losetup --find --show --partscan "$raw")"
# the partition nodes can take a moment to appear
for _ in $(seq 1 20); do [ -b "${loop}p3" ] && break; udevadm settle 2>/dev/null || true; sleep 0.5; done
[ -b "${loop}p3" ] || die "The partitions of $loop did not appear (loop partition scanning is not available here)."
mkfs.vfat -F 32 -n ESP "${loop}p2" >/dev/null
mkfs.ext4 -q -L flowscope-root "${loop}p3"
mkdir -p "$mnt"
mount "${loop}p3" "$mnt"
mkdir -p "$mnt/boot/efi"; mount "${loop}p2" "$mnt/boot/efi"

say "Unpacking the root filesystem onto it"
tar -xpf "$work/rootfs.tar" -C "$mnt" --numeric-owner
rm -f "$work/rootfs.tar"
cp -a "$here/rootfs/." "$mnt/"
chmod 755 "$mnt"/usr/local/sbin/flowscope-vm-firstboot "$mnt"/usr/local/sbin/flowscope-issue

root_uuid="$(blkid -s UUID -o value "${loop}p3")"; esp_uuid="$(blkid -s UUID -o value "${loop}p2")"
cat > "$mnt/etc/fstab" <<FSTAB
# <file system>        <mount point>  <type>  <options>              <dump> <pass>
UUID=$root_uuid  /              ext4    errors=remount-ro,discard  0 1
UUID=$esp_uuid   /boot/efi      vfat    umask=0077,nofail          0 2
FSTAB
echo flowscope > "$mnt/etc/hostname"
printf '127.0.0.1\tlocalhost\n127.0.1.1\tflowscope\n' > "$mnt/etc/hosts"

say "Installing the kernel, boot loaders, cloud-init and guest agents"
for d in dev dev/pts proc sys; do mount --bind "/$d" "$mnt/$d"; done
cp /etc/resolv.conf "$mnt/etc/resolv.conf"
# no service may start inside the chroot
printf '#!/bin/sh\nexit 101\n' > "$mnt/usr/sbin/policy-rc.d"; chmod 755 "$mnt/usr/sbin/policy-rc.d"
chroot "$mnt" /usr/bin/env DEBIAN_FRONTEND=noninteractive LC_ALL=C.UTF-8 bash -euo pipefail -c '
  apt-get update
  # grub-pc-bin / grub-efi-amd64-bin are the boot loader files only; the installs below are done by hand, so no debconf question is asked
  apt-get install -y --no-install-recommends \
    linux-image-amd64 initramfs-tools grub2-common grub-pc-bin grub-efi-amd64-bin efibootmgr \
    cloud-init cloud-guest-utils open-vm-tools qemu-guest-agent \
    e2fsprogs dosfstools sudo
'
# BIOS and UEFI boot loaders: BIOS into the disk itself (the 1 MiB bios_grub partition), UEFI as the removable-media fallback path
# (EFI/BOOT/BOOTX64.EFI), which every firmware finds without any NVRAM entry, so the disk boots on whatever hypervisor it is attached to.
chroot "$mnt" grub-install --target=i386-pc --recheck --no-floppy "$loop"
chroot "$mnt" grub-install --target=x86_64-efi --efi-directory=/boot/efi --removable --no-nvram
chroot "$mnt" update-grub
grep -q "root=UUID=$root_uuid" "$mnt/boot/grub/grub.cfg" || die "grub.cfg does not boot from the root file system's UUID; the disk would not start."
grep -q "^[[:space:]]*linux[[:space:]]" "$mnt/boot/grub/grub.cfg" || die "grub.cfg has no kernel entry."
[ -f "$mnt/boot/efi/EFI/BOOT/BOOTX64.EFI" ] || die "The UEFI boot file was not written."

say "Switching on the appliance services"
for u in flowscope-vm-firstboot.service flowscope-issue.service cloud-init-local.service cloud-init.service cloud-config.service cloud-final.service open-vm-tools.service; do
  chroot "$mnt" systemctl enable "$u" || echo "note: could not enable $u"
done
# the services the base template enabled must still be on in the image
for u in flowscope.service flowscope-firstboot.service ssh.service; do
  chroot "$mnt" systemctl is-enabled "$u" >/dev/null || die "$u is not enabled in the image"
done
# cloud-init keeps its own state; the image must look never-booted to it
chroot "$mnt" cloud-init clean --logs 2>/dev/null || true

say "Cleaning up (nothing machine-specific may ship in the image)"
rm -f "$mnt/usr/sbin/policy-rc.d" "$mnt/etc/resolv.conf"
: > "$mnt/etc/machine-id"; rm -f "$mnt/var/lib/dbus/machine-id"
rm -f "$mnt"/etc/ssh/ssh_host_* "$mnt/root/.bash_history"
rm -rf "$mnt"/var/lib/apt/lists/* "$mnt"/var/cache/apt/* "$mnt"/tmp/* "$mnt"/var/tmp/*
find "$mnt/var/log" -type f -exec truncate -s 0 {} + 2>/dev/null || true
printf 'FlowScope virtual machine appliance for Debian 12, built from %s\n' "$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' "$mnt/opt/flowscope/package.json" | head -n1)" > "$mnt/etc/flowscope-template"
sync
# give the free space back to the (sparse) file so the converted disk is small
fstrim -v "$mnt" 2>/dev/null || true
fstrim -v "$mnt/boot/efi" 2>/dev/null || true
for m in dev/pts dev proc sys; do umount "$mnt/$m"; done
umount "$mnt/boot/efi"; umount "$mnt"
losetup -d "$loop"; loop=""

say "Converting the disk"
qemu-img convert -f raw -O qcow2 -c "$raw" "$OUT/$name.qcow2"
qemu-img convert -f raw -O vmdk -o subformat=streamOptimized "$raw" "$work/disk.vmdk"
say "Packing the OVA"
node "$here/make-ova.mjs" --vmdk "$work/disk.vmdk" --out "$OUT/$name.ova" --name "flowscope${variant}" --disk-gb "$DISK_GB" --cpus "$CPUS" --memory-mb "$MEMORY_MB" --version "$version"
( cd "$OUT" && sha256sum "$name.qcow2" "$name.ova" > "$name.sha256" )

say "Done:"
ls -lh "$OUT/$name".{qcow2,ova} | awk '{print "  " $5 "  " $9}'
echo "VMware: deploy the .ova (vSphere Client: right-click a host -> Deploy OVF Template). Nutanix AHV: upload the .qcow2 as a disk image (Prism: Settings -> Image Configuration). Directions: docs/deployment.md"
