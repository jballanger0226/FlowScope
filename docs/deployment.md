# Deploying FlowScope

FlowScope listens on three ports. Whatever you choose below, these have to be reachable from your browser and from your routers and switches.

| Port | Protocol | Purpose |
| --- | --- | --- |
| 8443 | TCP | Web console (HTTPS, self-signed certificate until you install your own) |
| 2055 | UDP | NetFlow v5 / v9 / IPFIX |
| 4739 | UDP | IPFIX |

Pick one of these:

1. [Docker or Docker Compose](#docker) — any machine with Docker, Podman or Docker Desktop.
2. [Proxmox VE with a CT template, using only the web interface](#proxmox-ct-template-web-interface) — upload one file, click Create CT. **Recommended on Proxmox.**
3. [Proxmox VE from the command line](#proxmox-command-line-script) — one script on the Proxmox host that builds the same kind of container.
4. [Proxmox VE 9.1 or newer, running the Docker image as an LXC "application container"](#proxmox-oci).
5. [A service on a plain Linux, macOS or Windows machine](#plain-service).

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

## Proxmox CT template (web interface)

FlowScope is packaged as a Proxmox **container template**: a single `.tar.zst` file with Debian 12, Node.js and FlowScope already installed. You upload it to Proxmox like any other template and create the container with the normal **Create CT** wizard. No shell is needed on the Proxmox host, and the container does not need internet access to run.

### 1. Get the template file

Pick one:

* **From GitHub (easiest).** In the repository open **Releases** → **Proxmox template (latest main)** (or the newest `v*` release) and download `debian-12-flowscope_<version>_amd64.tar.zst`. The repository is private, so you have to be signed in to GitHub; a browser download is fine.
* **From a workflow run.** **Actions** → *Proxmox container template* → the newest run → **proxmox-ct-template** at the bottom. This downloads a `.zip`; unzip it and use the `.tar.zst` inside.
* **Build it yourself** on any Linux machine (or WSL) with Docker and `zstd`: `packaging/lxc-template/build.sh`. The file appears in `template-out/`. This needs no Proxmox and takes a few minutes.

Do not unpack the `.tar.zst`; Proxmox wants it as it is.

### 2. Upload it in Proxmox

1. In the web interface select your node, then a storage that can hold templates, for example **local** (left tree: *Datacenter → your node → local*).
2. Open **CT Templates** and click **Upload**.
3. Choose the file with **Select File…** and click **Upload**. It is about 100 to 150 MB.

If the storage has no **CT Templates** entry, enable it: *Datacenter → Storage →* the storage *→ Edit →* **Content** *→* add **Container template**.

The template can also be added with **Download from URL** (same page) when the file is reachable without signing in, for example from a public repository's release. A private repository's links need a login, so upload the file instead.

### 3. Create the container

Click **Create CT** (top right) and fill in the tabs:

| Tab | Setting |
| --- | --- |
| General | **Hostname** `flowscope`. Leave **Unprivileged container** ticked and **Nesting** ticked. Set a **Password** for the container's `root` user (and/or paste an SSH public key). |
| Template | **Storage** where you uploaded it, **Template** `debian-12-flowscope_…tar.zst`. |
| Disks | At least **16 GiB**. Flow records are stored here, so size it for your retention (the Storage and retention page in FlowScope has an estimator). |
| CPU | **2** cores. |
| Memory | **2048** MiB memory, **512** MiB swap. More helps with many exporters. |
| Network | Your bridge (usually `vmbr0`), a **VLAN Tag** if needed, **IPv4** *DHCP*, or *Static* with an address like `192.168.10.50/24` and the gateway. A fixed address is best, because your routers send flows to it. |
| DNS | Leave as *use host settings*, or set your own. |
| Confirm | Tick **Start after created** and click **Finish**. |

### 4. Sign in

1. Select the new container, open **Console**, and log in as `root` with the password you set in the wizard.
2. The welcome message shows what to do next. Read the generated password for FlowScope's `admin` account with:

   ```sh
   cat /root/flowscope-admin-password.txt
   ```

3. Find the container's address on its **Summary** tab (or run `hostname -I`) and open `https://<address>:8443/`. The browser warns about the self-signed certificate once; install your own under Admin → HTTPS certificate when you are ready.
4. Sign in as `admin`, change the password, then delete the file: `rm /root/flowscope-admin-password.txt`.

The password is generated for you; you can change it in FlowScope after signing in. If you ever lose it, run `flowscope-ctl reset-password admin` in the container's console for a new one-time password.

### If the web console does not answer (only SSH, port 22, is open)

FlowScope starts by itself when the container boots; there is nothing to run by hand. If TCP 8443 is closed, the service did not start, and the container's console tells you why:

```sh
flowscope-ctl doctor          # service state, listening ports, container type, last log lines
systemctl status flowscope    # the exact error, e.g. "status=226/NAMESPACE"
```

The common cause is **systemd's sandboxing needing a feature the container lacks**. Make sure the container has **Options → Features → Nesting** ticked (stop and start the container after changing it). Templates built before 2026-10-13 also had a bug that made the service fail even with the sandbox options switched off; the quick fix, run in the container's console, is:

```sh
mkdir -p /etc/systemd/system/flowscope.service.d
printf '[Service]\nProtectSystem=no\nProtectHome=no\nPrivateTmp=no\nPrivateDevices=no\nProtectKernelTunables=no\nProtectKernelModules=no\nProtectControlGroups=no\nReadWritePaths=\n' \
  > /etc/systemd/system/flowscope.service.d/lxc.conf
systemctl daemon-reload
systemctl restart flowscope
ss -ltn | grep 8443        # should now show a listener
```

If it still does not start, send the output of `systemctl status flowscope` and `journalctl -u flowscope -n 50` (an issue on GitHub is fine).

### 5. Finish up in the GUI

* **Start at boot:** container → **Options** → **Start at boot** → Yes.
* **Firewall:** if you enable the Proxmox firewall on the container, allow TCP 8443 and UDP 2055 and 4739 in.
* **Exporters:** send NetFlow v5/v9 or IPFIX from your routers and switches to the container's address, UDP 2055 or 4739. See [After installing](#after-installing).
* **Backups:** *Datacenter → Backup → Add*, select the container. All FlowScope data lives on its root disk, so a normal backup is complete.
* **More disk later:** container → **Resources** → *Root Disk* → **Volume Action** → **Resize**.

### Settings

Settings are in `/etc/flowscope/flowscope.env` inside the container (open **Console**, `nano /etc/flowscope/flowscope.env`, then `systemctl restart flowscope`). The README lists them all. Helpful commands in the console:

```sh
flowscope-ctl status                  # is it running?
flowscope-ctl logs                    # recent log; add -f to follow
flowscope-ctl reset-password admin    # prints a new one-time password for admin
flowscope-ctl update                  # see below
```

### Updating

Take a snapshot first: container → **Snapshots** → **Take Snapshot**. To undo an update later, select it and click **Rollback**.

Then, in the container's **Console**:

```sh
flowscope-ctl update
```

This downloads the current source from GitHub, builds it, swaps it in and restarts FlowScope; your data and settings are kept, and the previous version stays in `/opt/flowscope.prev`. The container needs internet access for this. Because the repository is private, give it a GitHub token (a fine-grained token with read access to the repository's **Contents**) once:

```sh
install -m 600 /dev/null /etc/flowscope/update.env
echo 'GITHUB_TOKEN=github_pat_xxxxxxxx' >> /etc/flowscope/update.env
```

`update.env` can also set `FLOWSCOPE_REF=` (a branch or tag; default `main`) and `FLOWSCOPE_REPO=owner/name` for a fork.

The alternative, with no internet access in the container, is to upload a newer template and create a new container from it, then move your exporters to it. Data is not carried over automatically in that case; use a Proxmox backup of the old container if you need to restore it.

### What is in the template

* Debian 12 with systemd, DHCP and `ifupdown` networking as Proxmox expects, and OpenSSH (key logins as root; Proxmox places the key you gave in the wizard).
* Node.js 22 and npm, FlowScope in `/opt/flowscope` running as a systemd service under its own user, data in `/var/lib/flowscope`.
* A first-boot service that makes the SSH host keys and the `admin` password for each container, so no two containers made from the same template share secrets.
* The template contains no password or key. The Proxmox wizard's password is the only credential for the container itself.

## Proxmox command line (script)

This does the same job as the template above from a shell on the Proxmox host: it downloads Proxmox's own Debian 12 template, creates an unprivileged container and installs FlowScope in it as a systemd service, building it from your checkout. It does not need Docker or a pre-built template file. Use the web-interface route above if you would rather not use a shell.

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

Proxmox VE 9.1 and newer can create an LXC container from an OCI image ("application container"), so the Docker image can run there without Docker. This is the less proven path: it depends on Proxmox features that are new, and nothing here has been tried on a real host. If anything below does not match what you see, use the CT template route above, which does not depend on it.

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

These need Node.js 22.13 or newer. Step-by-step Windows instructions, including how to avoid the `Could not read package.json` error you get when you run `npm` in the wrong folder after unzipping a download, are in the README under "Getting the files" and "Windows".

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
| Only port 22 is open on a new container | See *If the web console does not answer* above; start with `flowscope-ctl doctor` |
| Service fails in an LXC with `status=226/NAMESPACE` | The sandboxing drop-in is missing; re-run the installer (`flowscope-lxc.sh update <CTID>`, or `flowscope-ctl update` in the container) |
| The uploaded template is not listed under Create CT → Template | Check that it was uploaded to a storage with *Container template* content, and that the file name ends in `.tar.zst` (not `.zip`) |
| The container starts but there is no network | Check the bridge, VLAN tag, address and gateway on the Network tab (container → Network). Inside the console: `ip a`, `ip route` |
| `flowscope-ctl update` says it could not download | The repository is private: add `GITHUB_TOKEN` to `/etc/flowscope/update.env`; the container also needs internet access |
| `pct create` fails with a template error | Run `pveam update`, or set `TEMPLATE=` to a template you already have under **CT Templates** |
| Container has no network during install | Check the bridge, gateway and DNS; the installer needs to reach deb.debian.org and nodejs.org |
| `npm error ... Could not read package.json` (Windows or anywhere) | `npm` was run in the wrong folder, usually one level above the real project folder after unzipping. `cd` into the folder that contains `package.json` (README: "Getting the files") |
| Forgot the admin password | Docker: `docker exec -it -u node flowscope node /app/dist/src/cli.js reset-password admin` (`-u node` keeps the database files owned by the right user). LXC: `pct exec <CTID> -- flowscope-ctl reset-password admin` |
