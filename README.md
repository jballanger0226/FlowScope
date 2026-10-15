# FlowScope

A NetFlow / IPFIX collector with per-hop stream tracing, SNMP link and QoS monitoring, reports and an admin console.
One Node.js 22 process, one data folder. Runs on Linux, macOS, Windows and as a container.

* **Flow explorer**: search with tokens (`src:10.1.0.0/16 port:443 qos:changed dscp:46 vlan:140 exporter:...`), see every hop a stream took, and see where its DSCP marking was changed. Ports the exporter did not report (a switch that exports on input only shows "out —") are filled in from the other direction of the stream, the CDP/LLDP neighbour tables or host tracking, and marked "worked out". Each port lists its CDP/LLDP neighbours, and a neighbour that is one of your SNMP devices opens that device and port in Links & QoS. The Service column names well-known ports (0-1023) from a built-in list of the IANA-registered names (22 ssh, 119 nntp, 319 ptp-event, ...), with the port number in parentheses, "rtsp (554)", and the raw port numbers are in the address columns too; a port can be searched by number or by name (`port:119`, `port:nntp`, `app:ftp-data`, or just `nntp`). `ttl:expired` (or the **TTL expired only** button) lists streams whose TTL ran out before the destination. The list opens fast: the first page is built from the newest 2,000 flow records, with a warning that not everything has loaded, while the full answer for the whole time range loads in the background and replaces it (the Status column is filled in then). Results are paged, 100 to 2,000 rows per page, with Previous and Next. The time range defaults to the last 15 minutes; **Custom…** takes any whole number of minutes, hours or days (up to 800 days, and no further back than the data you keep). The same picker is on Flows by port and the Report builder.
* **Flows by port**: search for a network device (by name, address, role or the name of any of its ports; Enter takes the first match), pick one of its ports (or all of them), choose entering, leaving or either direction, and see its 25, 50, 100, 200 or 500 biggest flows by bytes, packets or recency. Flow explorer stays the place to search everything; this page answers "what is crossing this cable". It reads the raw flow records (the summarised tiers do not keep ports), so the time range is limited by raw retention. Selecting a row shows the stream's path hop by hop under the table, the same panel as in Flow explorer, and the choice is kept in the address. The port list narrows as you type (name, description, number or speed). Ports the device reports as down are left out to keep the list short; a note under the list says how many, with a button to show them, and searching for "down" shows them too. Every port in Links & QoS has an **All flows through this port** button. Devices that send flows but are not polled can be chosen by interface number.
* **Links & QoS**: SNMP interface utilisation, errors/discards and Cisco CBQoS per-class drops, with charts and the streams crossing a link. Each device shows what CDP and LLDP say is cabled to every port (a neighbour column in the interface table, and a Neighbours table), and a neighbour that is also an SNMP device opens in one click, on the port at the far end of the cable.
* **Reports**: group by L2/L3/L4 fields, filter, top-N with "other", export CSV or JSON.
* **Storage & retention**: raw, 1-minute, 1-hour and daily tiers with per-tier retention, size estimate, and a choice of ClickHouse (the default for the Docker, Linux and Proxmox installs, which set up a server) or embedded SQLite.
* **Devices**: add SNMP devices one at a time or by discovery, with several credential sets tried in turn. Each device has **SNMP diagnostics**: *Check what this device publishes* reports whether it serves interfaces, 64-bit counters, LLDP, CDP, the MAC table, ARP, VLANs and Cisco QoS, with the reason and a fix hint when something is missing (for example a firewall that needs the lldpd AgentX subagent to publish LLDP), and *Walk an OID* reads any part of the device's MIB, or all of it when the OID is left blank. A walk runs in the background with progress and a Cancel button, is read back 100 rows at a time with a filter box, and exports as text (like `snmpwalk`), JSON, CSV or XML. Both only read.
* **Admin**: HTTPS certificate (self-signed, upload PEM/PKCS#12, generate a CSR with ECDSA/RSA/Ed25519, roll back), start/stop collection, per-service authentication (local, RADIUS, LDAP, Active Directory, SAML for the web console), roles and users, SNMP credential sets, application logs.
* **Appearance**: light, dark or follow the operating system (System / Light / Dark switch at the top right and on the sign-in page; the choice is remembered in the browser).
* **Sign-in**: every page and API call needs a session. The signed-in user and role, and a Sign out button, are at the top right.
* Roles: **ro** (read-only), **snmp** (read-only plus device management), **admin**.

## Quick start

Needs Node.js 22.13 or newer. Run the commands from the folder that contains `package.json` (see [Getting the files](#getting-the-files-read-this-first-if-npm-says-it-cannot-find-packagejson) if you downloaded a ZIP). On Windows, follow the [Windows](#windows) steps.

```sh
npm install
npm run build
npm run demo          # simulated network, sign in as admin / flowscope-demo-admin at https://localhost:8443/
npm start             # real use
```

The certificate is self-signed until you install your own (Admin → HTTPS certificate), so the browser warns on first visit.
On first start the `admin` account is created. Set `FLOWSCOPE_ADMIN_PASSWORD` (12+ characters) beforehand, or read the generated password from the log.
Point your routers' NetFlow v5/v9 or IPFIX export at this host, UDP **2055** or **4739**.

### Getting the files (read this first if `npm` says it cannot find `package.json`)

Every `npm` command below must be run **inside the folder that directly contains `package.json`**. Check with `dir package.json` (Windows) or `ls package.json` (macOS/Linux); if it says the file is not found, you are in the wrong folder.

The usual cause is the downloaded ZIP: GitHub's **Code → Download ZIP** gives `flowscope-main.zip`, and Windows' **Extract All** puts a folder named after the zip around the folder that is already inside it, so you end up with `...\FlowScope-main\FlowScope-main\package.json`. Go one level down:

```powershell
cd "C:\Users\you\Downloads\FlowScope-main\FlowScope-main"     # adjust to your path; use dir to see what is inside
dir package.json                                                  # must list the file
```

Cloning with `git clone https://github.com/jballanger0226/flowscope` avoids this (it creates one folder), and is easier to update later with `git pull`.

### Windows

1. Install Node.js 22.13 or newer (the LTS installer from nodejs.org; tick the option that adds it to PATH), then open a **new** PowerShell window.
2. Get the files as above, and `cd` into the folder that contains `package.json`.
3. Build and try it:

   ```powershell
   npm install
   npm run build
   npm run demo        # simulated network; sign in as admin / flowscope-demo-admin at https://localhost:8443/  (stop with Ctrl+C)
   ```

4. To run it for real, as a service that starts at boot, open an **elevated** PowerShell (Run as administrator), `cd` to the same folder and run:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\packaging\windows\install.ps1
   ```

   This is needed (rather than just `.\packaging\windows\install.ps1`) when scripts are blocked, which is the default for files that came from a ZIP download. It copies the program to `C:\Program Files\FlowScope`, keeps data and the log in `C:\ProgramData\FlowScope`, and opens the firewall for TCP 8443 and UDP 2055/4739. Set `FLOWSCOPE_ADMIN_PASSWORD` in `C:\ProgramData\FlowScope\flowscope.env` before the first start, or read the generated password from `flowscope.log` in the same folder.

Windows Defender Firewall may also ask about Node.js the first time it runs by hand; allow it on the networks your exporters are on. The program can be run without installing it with `npm start`.

### Container

```sh
cp .env.example .env                          # then set CLICKHOUSE_PASSWORD in it (openssl rand -hex 16)
docker compose up -d                          # FlowScope and ClickHouse; data in the flowscope-data and clickhouse-data volumes
```

**Without ClickHouse** (embedded SQLite, one container, nothing more to download, no password to set): `docker compose -f docker-compose.sqlite.yml up -d`, or `docker-compose.host.sqlite.yml` for host networking.

or `docker build -t flowscope . && docker run -d -p 443:443 -p 2055:2055/udp -p 4739:4739/udp -v flowscope-data:/data flowscope`. A lone container has no ClickHouse server beside it, so it uses SQLite unless you pass `-e FLOWSCOPE_CLICKHOUSE_URL=...` for a server you run yourself.
The image has a health check (`flowscope healthcheck`), keeps everything in `/data`, and runs the server as the unprivileged `node` user (it starts as root only to make `/data` writable, then drops privileges; `--user 1000:1000` skips that).
Behind a TLS-terminating proxy set `FLOWSCOPE_TLS=off` (serves HTTP on 8080), `FLOWSCOPE_TRUST_PROXY=1` and `FLOWSCOPE_PUBLIC_URL`.
If every exporter shows up as the Docker bridge address, use `docker compose -f docker-compose.host.yml up -d`.

### Proxmox VE

Everything can be done in the Proxmox web interface, without a shell:

1. Download the template `debian-12-flowscope_<version>_amd64.tar.zst` from this repository's **Releases** page (built by GitHub Actions; or build it yourself with `packaging/lxc-template/build.sh`).
2. Proxmox: your node → a storage → **CT Templates** → **Upload**.
3. **Create CT**, choose that template (Debian 12, 2 cores, 4 GiB, 32 GiB disk is a good start; the template includes ClickHouse, which stores the flow records), start it, open **Console**, log in as `root`, and read the `admin` password from `/root/flowscope-admin-password.txt`.
4. Open `https://<container address>/`. Nothing needs to be started by hand. If the page does not load, run `flowscope-ctl doctor` in the console and see the troubleshooting part of the guide below (the container's **Nesting** option should be ticked).

### VMware ESXi, Nutanix AHV and Kubernetes

* **VMware ESXi / vSphere:** deploy the ready-made `flowscope-vm_<version>_amd64.ova` (Debian 12, FlowScope and ClickHouse, VMware Tools, cloud-init) with **Deploy OVF Template**.
* **Nutanix AHV:** upload `flowscope-vm_<version>_amd64.qcow2` in Prism (Image Configuration) and create a VM from it. The same image runs on KVM and OpenStack.
* **Kubernetes** (VMware Tanzu, Nutanix Kubernetes Platform, any cluster): `kubectl apply -k packaging/kubernetes`, or `packaging/kubernetes/clickhouse` for ClickHouse storage.

Both images are built by `.github/workflows/vm-image.yml` (releases page; `flowscope-vm-sqlite_*` leaves out ClickHouse). Steps and cluster notes, including why exporters need `externalTrafficPolicy: Local`: **[docs/deployment.md](docs/deployment.md)**.

A walkthrough of each wizard tab, updating, backups and troubleshooting: **[docs/deployment.md](docs/deployment.md)**. The same document covers the command-line alternative (`packaging/proxmox/flowscope-lxc.sh`, which creates the container for you) and running the Docker image directly as an OCI application container on Proxmox VE 9.1 and newer.

### As a service

| OS | How |
| --- | --- |
| Linux | `sudo packaging/linux/install.sh` (systemd unit, dedicated user, settings in `/etc/flowscope/flowscope.env`, data in `/var/lib/flowscope`; on Debian or Ubuntu it also installs ClickHouse, listening on 127.0.0.1 only; `sudo packaging/linux/install.sh --sqlite` skips ClickHouse entirely and uses SQLite) |
| VMware ESXi / vSphere | the OVA (Deploy OVF Template), see [docs/deployment.md](docs/deployment.md) |
| Nutanix AHV | the qcow2 image (Prism image service), see [docs/deployment.md](docs/deployment.md) |
| Kubernetes | `kubectl apply -k packaging/kubernetes` |
| Proxmox VE | CT template via the web interface (see above), or `packaging/proxmox/flowscope-lxc.sh` on the host; `packaging/proxmox/install.sh` is the installer both use. Without ClickHouse: the `debian-12-flowscope-sqlite_<version>_amd64.tar.zst` template, or `flowscope-lxc.sh --sqlite` |
| macOS | `sudo packaging/macos/install.sh` (launchd daemon, data in `/Library/Application Support/FlowScope`, log `/var/log/flowscope.log`) |
| Windows | elevated PowerShell: `.\packaging\windows\install.ps1` (scheduled task at boot as SYSTEM, firewall rules, settings in `%ProgramData%\FlowScope\flowscope.env`) |

## Settings

All settings are environment variables.

| Variable | Default | Meaning |
| --- | --- | --- |
| `FLOWSCOPE_DATA_DIR` | `/data` in a container; `/var/lib/flowscope` (root) or `~/.local/share/flowscope` on Linux; `~/Library/Application Support/FlowScope` on macOS; `%ProgramData%\FlowScope` on Windows | Everything FlowScope stores |
| `FLOWSCOPE_HTTPS_PORT` | `8443` (`443` in the container image and on Linux and Proxmox installs) | Web console and API (TLS). Ports below 1024 need a privilege: the Linux service unit and the container entrypoint grant `CAP_NET_BIND_SERVICE`; a run from source as an ordinary user should keep 8443 |
| `FLOWSCOPE_TLS` | `auto` | `off` serves plain HTTP only (behind a proxy) |
| `FLOWSCOPE_HTTP_PORT` | `0` (`8080` when TLS is off) | Plain HTTP listener |
| `FLOWSCOPE_BIND` | `0.0.0.0` | Web bind address |
| `FLOWSCOPE_FLOW_PORTS` | `2055,4739` | UDP ports for NetFlow v5/v9/IPFIX |
| `FLOWSCOPE_FLOW_BIND` | `0.0.0.0` | Flow listener address |
| `FLOWSCOPE_ADMIN_PASSWORD` | generated | Password for the first `admin` (first start only) |
| `FLOWSCOPE_MASTER_KEY` | key file in the data dir | Encrypts stored secrets (SNMP communities/passwords, RADIUS secret, bind passwords, private keys). Set it if you want the key outside the data folder. |
| `FLOWSCOPE_PUBLIC_URL` | | External URL, used for SAML callbacks |
| `FLOWSCOPE_TRUST_PROXY` | off | Number of reverse proxies in front of FlowScope (`1` for one). The client address is then taken from `X-Forwarded-For`, counting from the right |
| `FLOWSCOPE_CLICKHOUSE_URL` | set by the Docker compose files, the Linux and Proxmox installers and the Proxmox template | `http://user:pass@host:8123/database` (database defaults to `flowscope`). With no value, FlowScope uses SQLite. |
| `FLOWSCOPE_BACKEND` | | `sqlite` or `clickhouse`: which store a **new** install starts with. Empty: ClickHouse when `FLOWSCOPE_CLICKHOUSE_URL` is set, otherwise SQLite. |
| `FLOWSCOPE_CLICKHOUSE_WAIT` | `60` | Seconds to wait at start-up for ClickHouse to answer before falling back to SQLite for that run (ClickHouse is often still starting after a reboot or `docker compose up`) |
| `FLOWSCOPE_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `FLOWSCOPE_DEMO` | off | Same as `--demo`. The demo listens on 127.0.0.1 unless `FLOWSCOPE_BIND` is set (or it runs in a container), and keeps its data in a temporary folder that is removed when it stops |
| `FLOWSCOPE_KEEP_DATA_PERMS` | off | `1` stops FlowScope from removing group and other access from the data folder and `config.db` at start-up (Unix) |
| `FLOWSCOPE_SCRYPT_LOG2N` | `17` | Cost of new password hashes, as a power of two (4 to 18). The default takes about half a second and 128 MiB per hash, two at a time; lower it on very small machines |

Other commands: `flowscope reset-password <user>`, `flowscope healthcheck`, `flowscope version` (prints the version and the git revision it was built from; see [Which version is running](docs/deployment.md#which-version-is-running)).

## Storage

* **ClickHouse (default for Docker, Linux and Proxmox)**: a column store for higher volume and long retention. The Docker compose files start a ClickHouse container beside FlowScope. The Linux installer and the Proxmox installer and template put ClickHouse on the same machine (official package, listening on `127.0.0.1` only, a database user with its own random password that is kept only in `flowscope.env`). FlowScope talks to it over its HTTP interface, so there is no extra native dependency. The 1-minute tier is maintained by a materialized view; 1h/1d are filled when each hour/day closes. If ClickHouse cannot be reached at start-up FlowScope waits up to `FLOWSCOPE_CLICKHOUSE_WAIT` seconds, then falls back to SQLite for that run and says so in Storage. For an HTTPS ClickHouse with a private CA, start Node with `NODE_EXTRA_CA_CERTS=/path/ca.pem`.
* **SQLite**: one `ts.db` file in the data folder, nothing to run. Raw flows live in one table per day, so retention is a cheap drop. Rolled-up tiers (1m, 1h, 1d) are built from the raw rows exactly once, even when records arrive late. Good for small sites, up to a few thousand flows per second. It is also what FlowScope uses when no ClickHouse server is configured: `npm start`, Windows, macOS, and a lone container.

**Choosing at install time.** ClickHouse is the default everywhere; each platform has an explicit way to leave it out, and then nothing about ClickHouse is downloaded:

| | With ClickHouse (default) | Without (SQLite) |
| --- | --- | --- |
| Docker | `docker compose up -d` | `docker compose -f docker-compose.sqlite.yml up -d` (host networking: `docker-compose.host.sqlite.yml`) |
| Linux | `sudo packaging/linux/install.sh` | `sudo packaging/linux/install.sh --sqlite` |
| Proxmox, web interface | template `debian-12-flowscope_<version>_amd64.tar.zst` | template `debian-12-flowscope-sqlite_<version>_amd64.tar.zst` |
| Proxmox, command line | `packaging/proxmox/flowscope-lxc.sh` | `packaging/proxmox/flowscope-lxc.sh --sqlite` (also needs less: 2 GB memory and a 16 GB disk) |

**Which one a start-up uses.** A choice stored in the database (the Storage page) always wins. On a first start, FlowScope uses `FLOWSCOPE_BACKEND` if set; otherwise SQLite if the data folder already holds a SQLite store; otherwise ClickHouse when `FLOWSCOPE_CLICKHOUSE_URL` is set; otherwise SQLite. So **updating an existing install never moves it to ClickHouse or hides its data**. Switching is a choice under Storage (collection must be stopped; the new backend starts empty and old data is not migrated).

Tiers and defaults (days): raw 7, 1-minute 30, 1-hour 395, daily 1095, SNMP raw 30, SNMP hourly 395. The audit log is always kept.

## How the numbers are counted

A stream is a 5-tuple seen in both directions (ICMP ignores ports). When several routers export the same flow, every record is kept for the per-hop view, but bytes and packets are counted **once**, from the exporter that saw the stream first ("primary hop"). QoS is shown as changed when the DSCP differs between hops, or when an exporter reports a different post-policy DSCP (IPFIX `postIpClassOfService`) than it received.

## TTL expired flag

A stream is flagged when its TTL ran out before it reached its destination. Two kinds of evidence are used:

* **Exporter-reported TTL**: the exporter saw packets with a TTL of 1 or less that were not addressed to the router itself (IPFIX `minimumTTL`, IE 52, NetFlow v9 equivalent). Shown as **TTL expired**.
* **ICMP Time Exceeded** seen in the flow data (IPv4 type 11, IPv6 type 3, code 0). Shown as **TTL notice**: a router told the sender, but the flow it refers to may be a probe.

Traffic that is built to have a TTL of 1 is ignored: multicast, broadcast and link-local destinations (mDNS, SSDP, LLMNR, ...), IGMP, OSPF, EIGRP, PIM, VRRP, and UDP discovery or routing ports (NetBIOS, SSDP, WS-Discovery, mDNS, LLMNR, RIP/RIPng, DHCPv6, HSRP, GLBP), plus anything addressed to the exporter or to a router FlowScope knows. Limits: needs exporter-reported TTL, so it does not work with NetFlow v5; it is evaluated on raw flow records only (not on the 1-minute, hourly or daily rollups); traceroute probes are flagged because they do expire on purpose.

## SNMP

Reads standard MIB-II / IF-MIB (`ifDescr`, `ifName`, `ifAlias`, `ifHighSpeed`, `ifHC*Octets`, discards, errors, oper status), `ipAddrTable`, VLAN names from `Q-BRIDGE-MIB` (`dot1qVlanStaticName`) and Cisco `CISCO-VTP-MIB` (`vtpVlanName`), and per-class QoS from `CISCO-CLASS-BASED-QOS-MIB` (`cbQosPolicyDirection`, `cbQosIfIndex`, `cbQosConfigIndex`, `cbQosObjectsType`, `cbQosParentObjectsIndex`, `cbQosPolicyMapName`, plus class-map names, the 64-bit pre-policy packet/byte, post-policy byte and drop packet/byte counters, queueing bandwidth and current queue depth). SNMP v1, v2c and v3 (noAuthNoPriv, authNoPriv, authPriv) are supported through `net-snmp`. OIDs are listed in `src/snmp/oids.ts`. The Report builder can aggregate addresses to /32, /24, /16 or any prefix length from /0 to /32 (custom).

### Service policies (Cisco class-based QoS)

Both directions are read: the output policy that queues traffic on an interface and the input policy that marks or polices it. Input classes are listed with an `in` tag. Bandwidth guarantees use the MIB's units (percent, percent of remaining, kbps). Counters fall back from 64-bit to 32-bit when a device only implements the 32-bit ones, and per-VLAN policies are labelled with their VLAN. Control-plane policies are skipped because they do not belong to an interface. The poller re-reads the policy structure every hour so a policy attached later is picked up, and if a device returns nothing the reason is shown on the Links and QoS page (it is also stored in `devices.qos_note`) rather than the policy silently going missing.

### Ports, VLANs and finding hosts

For each switch FlowScope also reads which VLAN every port is in and, every five minutes (configurable), which MAC addresses are plugged into which port. This is what the VLAN column, the VLAN search, the "Hosts on this port" table and the "Find a host" box use, and it is how a multicast stream's source host is placed on a switch.

| What | Where it comes from |
| --- | --- |
| Access and voice VLAN | `CISCO-VLAN-MEMBERSHIP-MIB` (`vmVlan`, `vmVoiceVlanId`) |
| Trunk native VLAN and allowed VLANs | `CISCO-VTP-MIB` trunk table |
| Port VLAN on other vendors | `Q-BRIDGE-MIB` `dot1qPvid`, mapped through `dot1dBasePortIfIndex` |
| SVI / VLAN interfaces | the interface name (`Vlan140`, `Vl140`, `BDI140`, `irb.140`, `Vlan-interface140`) or ifType 53/135/136 |
| MAC address table | `Q-BRIDGE-MIB` `dot1qTpFdbPort`; on Cisco Catalyst, `BRIDGE-MIB` `dot1dTpFdbPort` read once per VLAN |
| IP to MAC | `ipNetToPhysicalTable` (IPv4 and IPv6), falling back to `ipNetToMediaTable`; read from every polled router or Layer 3 switch |
| Which ports are uplinks | LLDP (`lldpRem*`, with capability bits) and CDP (`cdpCache*`) |

How a host is placed: its MAC address comes from ARP (or, for a multicast source, from the flow records as a hint). It is then looked up in every switch's MAC table. A port that leads to another switch or router (LLDP/CDP says bridge or router, it is a routed port or SVI, or it has learned a large number of addresses) is an uplink and is never the answer. Of the remaining ports, the one with the fewest addresses wins. The answer carries a confidence: **high** when the switch reports LLDP/CDP neighbours and exactly one host port matches, **medium** when the switch reports no neighbours (so uplinks were judged by address count) or the MAC came from flow records, **low** when several host ports match. If the address was only seen on uplinks the answer is "not found on any polled switch" and the nearest uplink is named; nothing is guessed.

Things to know:

* **Cisco Catalyst switches keep one MAC table per VLAN.** To read them FlowScope uses the VLAN community (`community@vlan`) for SNMPv1/v2c, or the context `vlan-N` for SNMPv3. The SNMPv3 user must be allowed to use those contexts (`snmp-server group ... context vlan- match prefix` on IOS), and the device must accept VLAN-indexed communities. If the first three VLANs fail, FlowScope stops and says how many VLANs could not be read instead of waiting out a timeout for each.
* A switch has to be in the device list for its ports to be known; a host behind an unmanaged switch is shown on the uplink side as "not found" or on the nearest managed port with a lower confidence.
* The reads add SNMP load (one table walk per VLAN on Catalyst). Host tracking can be turned off or slowed down with `PUT /api/hosts/settings` (SNMP admin role; there is no screen for it yet) with `enabled`, `intervalSec` 60 to 86400 and `keepDays` 1 to 365. Addresses that disappear from a table are kept, marked as gone, for `keepDays`.
* Interfaces that are VLANs or SVIs are left out of "Needs attention" on Links and QoS, since they carry routed traffic for a whole subnet and not a physical link.

### Multicast streams

A multicast stream has one source and many receivers, and every switch and router on the distribution tree reports the same packets. The stream view therefore does not draw a path. It shows the source host, the group, and the devices that saw the stream as an unordered set (sorted by name), each with the interface it came in on and the interfaces it replicated to. No latency, loss or marking comparison is made between devices. The switch port the source is plugged into is looked up from the MAC tables as described above; it is marked on the matching device, and it is shown as unknown (not guessed from the flow data) when host tracking cannot place it.

## Security notes

* Passwords are hashed with scrypt; stored secrets are encrypted with AES-256-GCM; sessions use `SameSite=Strict` cookies and a CSRF header; the content-security-policy forbids inline scripts and external resources.
* Each service (web console, API, CLI) has its own authentication chain. A local **break-glass** administrator can always be allowed so a RADIUS/LDAP/SAML outage cannot lock everyone out; see Admin → Authentication.
* SAML is implemented in this project (no SAML library): SP-initiated login, HTTP-Redirect AuthnRequest, HTTP-POST response, enveloped signatures with exclusive canonicalisation only (RSA-SHA256/384/512, ECDSA), replay protection kept in memory (a restart just means signing in again). It is web-console only.
* Put the collector on a management network. Flow export is unauthenticated UDP by nature, and FlowScope does not yet limit what an unknown sender can make it store or keep in memory (templates, timestamps, exporter list). Allow the flow ports only from your exporters at the firewall. Rules for nftables, ufw, Docker (which bypasses ufw), Windows and Proxmox, the known gaps, and notes on the SNMP admin role, RADIUS, LDAP and SAML are in [docs/security.md](docs/security.md).

## Development

```sh
npm run typecheck
npm test                                          # builds, then runs all tests
FLOWSCOPE_TEST_CLICKHOUSE=http://127.0.0.1:8123 node --test dist/test/clickhouse.test.js   # needs a ClickHouse server
```

`src/` is the server, `web/` is the browser UI (TypeScript compiled with `tsc`, no bundler, no runtime dependencies), `test/` has unit, API and protocol tests. `src/sim/` contains the packet builders and SNMP agent used by the tests and the demo.

## What has and has not been verified

See [docs/verification.md](docs/verification.md). In short: developed and tested on Linux only. The Docker image was run against a stand-in base image; Windows, macOS and the Proxmox scripts have not been run on real systems.
