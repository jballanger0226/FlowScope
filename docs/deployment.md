# Deploying FlowScope

FlowScope listens on three ports. Whatever you choose below, these have to be reachable from your browser and from your routers and switches.

| Port | Protocol | Purpose |
| --- | --- | --- |
| 8443 | TCP | Web console (HTTPS, self-signed certificate until you install your own) |
| 2055 | UDP | NetFlow v5 / v9 / IPFIX |
| 4739 | UDP | IPFIX |

Pick one of these:

1. [Docker or Docker Compose](#docker) — any machine with Docker, Podman or Docker Desktop.
2. [Proxmox VE, as a Debian LXC container](#proxmox-lxc) — works on every current Proxmox VE. **Recommended on Proxmox.**
3. [Proxmox VE 9.1 or newer, running the Docker image as an LXC "application container"](#proxmox-oci).
4. [A service on a plain Linux, macOS or Windows machine](#plain-service).

What has and has not been tested for each is in [verification.md](verification.md). The Proxmox paths have not been run on a real Proxmox host.

## Docker

### Build and run

```sh
git clone https://github.com/jballanger0226/flowscope && cd flowscope
docker build -t flowscope .
docker run -d --name flowscope --restart unless-stopped \
  -p 8443:8443 -p 2055:2055/udp -p 4739:4739/udp \
  -v flowscope-data:/data \
  -e FLOWSCOPE_ADMIN_PASSWORD='a-password-of-12-or-more-characters' \
  flowscope
```

Open `https://<docker host>:8443/` and sign in as `admin`. If you left `FLOWSCOPE_ADMIN_PASSWORD` out, a password is generated once and printed in `docker logs flowscope`. The variable is only read the first time, when the account is created.

### Compose

```sh
export FLOWSCOPE_ADMIN_PASSWORD='a-password-of-12-or-more-characters'   # optional, first start only
docker compose up -d                          # SQLite storage
docker compose --profile clickhouse up -d     # also start ClickHouse (needs CLICKHOUSE_PASSWORD set; see the README)
```

Everything FlowScope stores is in the `flowscope-data` volume (mounted at `/data`).

### Every exporter looks like the same device?

With the default bridge network, packets that come from the Docker host itself, or through some NAT and rootless setups, arrive with the bridge address as their source. Use host networking instead:

```sh
docker compose -f docker-compose.host.yml up -d
```

Ports are then set with `FLOWSCOPE_HTTPS_PORT` and `FLOWSCOPE_FLOW_PORTS` rather than a `ports:` list. Host networking is not available on Docker Desktop for Windows or macOS.

### Pulling a prebuilt image

`.github/workflows/image.yml` publishes `ghcr.io/jballanger0226/flowscope` (linux/amd64 and linux/arm64) on every push to `main` and on `v*` tags. A package published from a private repository is **private**. To pull it without logging in, make the package public (GitHub → your profile → Packages → flowscope → Package settings → Change visibility). Otherwise log in first:

```sh
echo "$GITHUB_TOKEN" | docker login ghcr.io -u <github user> --password-stdin     # a token with read:packages
docker pull ghcr.io/jballanger0226/flowscope:latest
```

### Data directory and user

The image starts as root only to make sure `/data` belongs to the unprivileged `node` user (uid 1000), then drops to it. That makes named volumes, new bind mounts and Proxmox mount points work without extra steps. If you prefer to never start as root, run with `--user 1000:1000` (or `user:` in compose) and make sure the data directory is already owned by that user.

### Behind your own TLS proxy

```sh
-e FLOWSCOPE_TLS=off -e FLOWSCOPE_TRUST_PROXY=1 -e FLOWSCOPE_PUBLIC_URL=https://flows.example.com
```

FlowScope then serves plain HTTP on 8080 (publish that instead of 8443). The UDP ports are unaffected and cannot go through an HTTP proxy.

### Upgrade

```sh
git pull && docker compose build && docker compose up -d      # or: docker pull ... && docker compose up -d
```

The data volume is kept. Back it up with, for example, `docker run --rm -v flowscope-data:/data -v "$PWD":/backup alpine tar czf /backup/flowscope-data.tgz -C /data .` (stop the container first for a consistent copy of the database).

## Proxmox LXC

This creates a small unprivileged Debian 12 container and installs FlowScope in it as a systemd service. It does not need Docker. Nothing in it needs a privileged container.

### Create

On the Proxmox host (web UI → your node → **Shell**, or SSH), as root:

```sh
git clone https://github.com/jballanger0226/flowscope && cd flowscope
packaging/proxmox/flowscope-lxc.sh
```

For a private repository, clone with a token (`git clone https://<user>:<token>@github.com/...`) or copy the repository to the host any other way. The script packs its own checkout and pushes it into the container, so the container itself never needs access to GitHub.

Defaults are 2 cores, 2 GB memory, 512 MB swap, a 16 GB disk, bridge `vmbr0`, DHCP, start on boot. Change them with environment variables:

```sh
CTID=210 CT_HOSTNAME=flowscope IP=192.168.10.50/24 GW=192.168.10.1 \
BRIDGE=vmbr0 VLAN=20 STORAGE=local-zfs DISK_GB=64 MEMORY=4096 \
ADMIN_PASSWORD='a-password-of-12-or-more-characters' \
packaging/proxmox/flowscope-lxc.sh
```

| Variable | Default | |
| --- | --- | --- |
| `CTID` | next free id | Container id |
| `CT_HOSTNAME` | `flowscope` | Host name |
| `IP`, `GW` | `dhcp` | Address with prefix (`192.168.10.50/24`) and gateway; a static address needs `GW` |
| `BRIDGE`, `VLAN` | `vmbr0`, none | Bridge and optional VLAN tag |
| `DNS` | the host's | Name server |
| `STORAGE` | `local-lvm` if present, else `local` | Where the root disk goes |
| `TEMPLATE_STORAGE` | `local` | Where the Debian template is kept |
| `TEMPLATE` | newest Debian 12 | A template file name you already have |
| `DISK_GB` | 16 | Root disk; flow records grow with traffic, so size it for your retention |
| `CORES`, `MEMORY`, `SWAP` | 2, 2048, 512 | |
| `ADMIN_PASSWORD` | generated | Printed at the end when generated |
| `START_ON_BOOT` | 1 | |

The script needs internet access from the container (Debian packages, Node.js from nodejs.org, npm packages). It prints the address, the `admin` password and the next steps when it is done. The container is tagged `flowscope`.

If the installer fails after the container exists, fix the cause and run `packaging/proxmox/flowscope-lxc.sh update <CTID>`; it is safe to repeat.

### Manage

```sh
pct exec <CTID> -- flowscope-ctl status
pct exec <CTID> -- flowscope-ctl logs -f
pct exec <CTID> -- flowscope-ctl reset-password admin
```

Settings are in `/etc/flowscope/flowscope.env` inside the container (see the README for the list); `systemctl restart flowscope` applies them. Data is in `/var/lib/flowscope` on the container's root disk.

### Update

From an updated checkout on the Proxmox host:

```sh
git pull
packaging/proxmox/flowscope-lxc.sh update <CTID>
```

This takes a snapshot named `pre-update` first (when the storage supports snapshots), installs the new version next to the old one, and restarts. To undo it: `pct rollback <CTID> pre-update`. The previous program files also stay in `/opt/flowscope.prev` inside the container.

### Back up

Everything is on the container's root disk, so a normal Proxmox backup job (**Datacenter → Backup**, or `vzdump <CTID>`, optionally to Proxmox Backup Server) covers it.

### Notes for LXC

* **Flow source address.** The container has its own address on your bridge, so exporters see it as a normal host and the source address of every flow is preserved.
* **systemd sandboxing.** The service unit is hardened, but some of those options fail inside an LXC container (service exits with status `226/NAMESPACE`). The installer adds a drop-in, `/etc/systemd/system/flowscope.service.d/lxc.conf`, that turns off the mount-namespace options when it detects a container. The container itself is the isolation boundary.
* **Unprivileged.** root inside the container is an unprivileged uid on the host. If you add your own bind mount to the container, mind the uid mapping.
* **Firewall.** The installer does not install a firewall. If you turn on the Proxmox firewall for the container, allow TCP 8443 and UDP 2055 and 4739.

## Proxmox OCI

Proxmox VE 9.1 and newer can create an LXC container from an OCI image ("application container"), so the Docker image can run there without Docker. This is the less proven path: it depends on Proxmox features that are new, and nothing here has been tried on a real host. If anything below does not match what you see, use the Debian LXC route above, which does not depend on it.

1. Make the image available from a registry Proxmox can reach. Either use the one published by `.github/workflows/image.yml` (`ghcr.io/jballanger0226/flowscope:latest`, which must be made public first; see above) or push your own build to a registry you control.
2. On the node: select a storage that holds container templates → **CT Templates** → **Pull from OCI Registry**; enter the image reference and the tag.
3. **Create CT**, and pick that template. Give it a network with its own address (bridge, DHCP or static).
4. Add a **mount point** for `/data` on persistent storage (Resources → Add → Mount Point, path `/data`). Without it the data is lost when the container is re-created.
5. Set environment variables in the container's **Options → Environment** (for example `FLOWSCOPE_ADMIN_PASSWORD`; see the README for the others). The image's default command is `start`, so no command needs to be set.
6. Start it, open `https://<container address>:8443/`.

The image's entrypoint takes care of ownership of `/data`: it starts as root (which is an unprivileged uid on the host for an unprivileged container), makes `/data` writable for the `node` user and drops to it. If the container keeps restarting with a permission error about `/data`, look at the log (Proxmox's task/console output, or `pct console`) first.

## Plain service

For a machine where you do not want containers:

| OS | How |
| --- | --- |
| Linux | `npm install && npm run build && sudo packaging/linux/install.sh` |
| macOS | `sudo packaging/macos/install.sh` |
| Windows | elevated PowerShell: `.\packaging\windows\install.ps1` |

These need Node.js 22.13 or newer. Details are in the README.

## After installing

1. Open the web console, sign in as `admin` and change the password (or create your own administrator).
2. **Exporters.** On each router or switch, send NetFlow v5/v9 or IPFIX to the FlowScope address, UDP 2055 or 4739. The log (`docker logs flowscope` or `flowscope-ctl logs`) shows `new exporter <address>` the first time each one is heard from.
3. **SNMP.** Add SNMP credential sets under Admin and the devices under SNMP devices to get interface names, speeds, VLANs, QoS policies and host tracking. Allow UDP 161 from FlowScope to the devices.
4. **HTTPS certificate.** Admin → HTTPS certificate replaces the self-signed one.
5. **Firewalls.** Allow TCP 8443 from your admin networks and UDP 2055/4739 from your exporters only. NetFlow is unauthenticated.
6. **Storage sizing.** Roughly allow for the retention you set times your flow rate; SQLite is fine for small and medium networks, and ClickHouse is the option for more (experimental).

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| All flows appear to come from one device, with the Docker bridge address | Use `docker-compose.host.yml`, or run FlowScope in an LXC container |
| No flows at all | Firewall in the way; exporter pointed at the wrong port; the log shows `new exporter <address>` when the first packet from a device arrives |
| Container exits with `EACCES` or `unable to open database file` on `/data` | The data directory is not writable. Run without `--user` so the entrypoint can fix ownership, or `chown 1000:1000` the directory |
| Service fails in an LXC with `status=226/NAMESPACE` | The sandboxing drop-in is missing; re-run the installer (`flowscope-lxc.sh update <CTID>`) |
| `pct create` fails with a template error | Run `pveam update`, or set `TEMPLATE=` to a template you already have under **CT Templates** |
| Container has no network during install | Check the bridge, gateway and DNS; the installer needs to reach deb.debian.org and nodejs.org |
| Forgot the admin password | Docker: `docker exec -it -u node flowscope node /app/dist/src/cli.js reset-password admin` (`-u node` keeps the database files owned by the right user). LXC: `pct exec <CTID> -- flowscope-ctl reset-password admin` |
