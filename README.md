# FlowScope

A NetFlow / IPFIX collector with per-hop stream tracing, SNMP link and QoS monitoring, reports and an admin console.
One Node.js 22 process, one data folder. Runs on Linux, macOS, Windows and as a container.

* **Overview** (the page FlowScope opens on): one place to see whether the network is healthy. The heading is a one-line verdict ("Everything looks healthy", or what is wrong, most serious first), followed by five tiles: SNMP devices answering, notices, flow exporters sending, traffic in the last hour, and data freshness (how long ago a flow and an SNMP poll last arrived, so a collector that has quietly stopped stands out). **Traffic** shows, in this order, the top applications by share of bytes, the largest flows, the top talkers (the hosts that sent the most), the busiest ports, a count of streams whose TTL ran out or whose DSCP marking changed (each opening Flow explorer with that search), and the flow exporters (sending, or quiet for more than 5 minutes). **Needs attention** lists every SNMP device that has stopped answering with how long it has been down, counted from its last successful poll (or from when it was added, if it never answered), then the highest-impact notices for devices that are answering, worst first (problems before warnings, routers and firewalls before switches). Each notice opens the device, tab, interface and section where it is explained. **Devices and system** shows device counts, the highest CPU, devices that restarted in the last hour, and, for administrators only, the latest errors and warnings from the application log. It refreshes every 30 seconds, and the flow searches behind it are reused for 30 seconds.
* **Flow explorer**: search with tokens (`src:10.1.0.0/16 port:443 qos:changed dscp:46 vlan:140 exporter:...`), see every hop a stream took, and see where its DSCP marking was changed. Ports the exporter did not report (a switch that exports on input only shows "out —") are filled in from the other direction of the stream, the CDP/LLDP neighbour tables or host tracking, and marked "worked out". Each port lists its CDP/LLDP neighbours, and a neighbour that is one of your SNMP devices opens that device and port in Links & QoS. The Service column names well-known ports (0-1023) from a built-in list of the IANA-registered names (22 ssh, 119 nntp, 319 ptp-event, ...), with the port number in parentheses, "rtsp (554)", and the raw port numbers are in the address columns too; a port can be searched by number or by name (`port:119`, `port:nntp`, `app:ftp-data`, or just `nntp`). `ttl:expired` (or the **TTL expired only** button) lists streams whose TTL ran out before the destination. The list opens fast: the first page is built from the newest 2,000 flow records, with a warning that not everything has loaded, while the full answer for the whole time range loads in the background and replaces it (the Status column is filled in then). Results are paged, 100 to 2,000 rows per page, with Previous and Next. The time range defaults to the last 15 minutes; **Custom…** takes any whole number of minutes, hours or days (up to 800 days, and no further back than the data you keep). The same picker is on Flows by port and the Report builder.
* **Flows by port**: search for a network device (by name, address, role or the name of any of its ports; Enter takes the first match), pick one of its ports (or all of them), choose entering, leaving or either direction, and see its 25, 50, 100, 200 or 500 biggest flows by bytes, packets or recency. Flow explorer stays the place to search everything; this page answers "what is crossing this cable". It reads the raw flow records (the summarised tiers do not keep ports), so the time range is limited by raw retention. Selecting a row shows the stream's path hop by hop under the table, the same panel as in Flow explorer, and the choice is kept in the address. The port list narrows as you type (name, description, number or speed). Ports that are up are listed first and ports the device reports as down last, marked "down": a port that is down now can still have flows from before it went down. Every port in Links & QoS has an **All flows through this port** button. Devices that send flows but are not polled can be chosen by interface number.
* **QoS re-marking, explained**: a stream whose DSCP changed is checked against the service policies read from the devices on its path (what each class matches and the "set" actions it applies). A change a policy sets is shown quietly as "re-marked by policy" (the flag stays, in blue); one that no policy explains, or that differs from what a policy sets, keeps the red flag with the reason (for example "no QoS policy is attached to Gi1/0/44", or a reset to CS0 on a port that does not trust the marking); a stream whose packets simply carry different markings is "mixed DSCP". AutoQoS marks through table maps, whose values the device does not publish: those count as configured marking but cannot be checked against the value. Devices with no QoS data leave the flag as it was.
* **Multicast**: for each router or Layer 3 switch, every multicast group it knows, with the interface it arrives on, the interfaces it is sent out of, the hosts that joined (IGMP), the rendezvous point and the rate, read from the device's own multicast table over SNMP. The same data completes a multicast stream's view (*Where this group should go*), which NetFlow alone cannot do because it only records the ingress interface. Hosts that joined are collected over time from the IGMP cache (the router keeps only the last reporter), so a VLAN with many receivers shows as a collapsible host list that fills in as hosts answer queries. The list has a **search box** (group, source host, or the switch and port a host is plugged into), **paging** and a **rows per page** choice. Cisco switches publish no IGMP snooping table over SNMP, so which *ports* a group goes to cannot be read; instead the last host to report each group is looked up in host tracking and shown with its switch and port, and so is each source.
* **Links & QoS**: SNMP interface utilisation, errors/discards and Cisco CBQoS per-class drops, with charts and the streams crossing a link. Each device shows what CDP and LLDP say is cabled to every port (a neighbour column in the interface table, and a Neighbours table), and a neighbour that is also an SNMP device opens in one click, on the port at the far end of the cable. **Aruba Instant access points** are recognised as access points (not switches) and add a Wi-Fi section: the AP's CPU, memory and uptime; each radio's channel, power, noise floor and how busy the channel is; the SSIDs on each radio (linked to their interfaces); and every wireless client with its name, operating system, MAC and IP address, SSID, signal-to-noise ratio, link rates, traffic and connect time. A wireless client's name, SSID and signal also appear in the host list of its SSID interface, and its IP address fills in when no polled router has it in ARP. This comes from Aruba's own MIB (AI-AP-MIB) and is read with the host tables every few minutes. **Ubiquiti UniFi** access points (SSIDs and channel use), **Ruckus** ZoneDirector/Unleashed (access points and WLANs) and **Cisco wireless controllers** (access points and clients) get a Wi-Fi section too, from their vendors' MIBs; these are not yet checked against real devices (see docs/verification.md), and what a vendor does not publish is shown as a dash.
* **Reports**: group by L2/L3/L4 fields, filter, top-N with "other", export CSV or JSON.
* **Storage & retention**: raw, 1-minute, 1-hour and daily tiers with per-tier retention, size estimate, and a choice of ClickHouse (the default for the Docker, Linux and Proxmox installs, which set up a server) or embedded SQLite.
* **More from Cisco devices** (read only from devices whose sysObjectID says Cisco): a **route lookup** from the CEF forwarding table, shown on each hop of a stream and flagging a flow that left an interface the table does not use; **DHCP snooping** leases, which place a host that has no MAC table entry and confirm one that has; **EIGRP** neighbours and **BFD** sessions; per-interface **queue drops, resets, storm control and port security** counters with warnings and graphs; **process CPU** (with the SNMP engine called out), **stack** member and port state, **ARP inspection** drops per VLAN, **NBAR2** applications per interface, and multicast load per interface. Each has a check in the SNMP diagnostics.
* **Devices**: add SNMP devices one at a time or by discovery, with several credential sets tried in turn. Each device has **SNMP diagnostics**: *Check what this device publishes* works out the device's vendor and role (switch, router, firewall, access point) and asks only for what it should publish, so a Cisco switch is never asked for Juniper MIBs. Results are grouped (basics, neighbours, hosts and VLANs, hardware, routing, link quality and queues, Wi-Fi) and cover interfaces, 64-bit counters, LLDP, CDP, the MAC table, ARP, VLANs, PoE, spanning tree, sensors, OSPF, BGP, multicast routing, vendor QoS, error counters and Wi-Fi controllers; an optional table that is empty shows as Not applicable. Network health → Neighbours and routing shows the ARP and neighbour cache read from the device, with the reason and a fix hint when something is missing (for example a firewall that needs the lldpd AgentX subagent to publish LLDP), and *Walk an OID* reads any part of the device's MIB, or all of it when the OID is left blank. A walk runs in the background with progress and a Cancel button, is read back 100 rows at a time with a filter box, and exports as text (like `snmpwalk`), JSON, CSV or XML. Both only read.
* **Admin**: HTTPS certificate (self-signed, upload PEM/PKCS#12, generate a CSR with ECDSA/RSA/Ed25519, get and renew one automatically over ACME, roll back), start/stop collection, per-service authentication (local, RADIUS, LDAP, Active Directory, SAML for the web console), roles and users, SNMP credential sets, application logs.
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

**Automatic certificate (ACME).** Admin → HTTPS certificate can get the certificate from an ACME CA and renew it by itself. It is a client written for FlowScope (RFC 8555, no extra package), so it works with Let's Encrypt, other public CAs, and internal CAs such as step-ca or Vault's PKI.

* *CA*: Let's Encrypt (or its staging CA for testing), or any ACME directory address. For a CA that requires it, give the external account key id and HMAC key. If the CA's own HTTPS certificate is not publicly trusted, paste its root certificate (used only to reach the CA).
* *HTTP-01*: the CA fetches a small file from this server over plain HTTP. This is the usual choice for an **internal CA**, which can reach the server on your network. FlowScope opens the port (80 by default) only while the check runs, or answers on the console's own HTTP port when that is the configured port. Opening port 80 needs the right to use low ports (`AmbientCapabilities=CAP_NET_BIND_SERVICE` on Linux). It is the only method that can certify an IP address, and only an internal CA will issue one.
* *DNS-01*: the CA looks for a TXT record under `_acme-challenge`. This works for a server that cannot be reached from the internet, and is the only way to get a wildcard certificate. **Cloudflare** records are added and removed automatically (an API token with Zone, DNS, Edit on that zone). With **manual** records, FlowScope shows the TXT records to add and waits until you choose Continue; it cannot renew by itself, so the page and the Application logs say when a renewal is due.
* *Public CAs only issue for public domain names you own.* They refuse `.local`, `.lan`, bare host names and IP addresses; for those, use an internal ACME CA. A server on a private network can still have a Let's Encrypt certificate for a real domain name if you use DNS-01.
* *Renewal*: checked every five minutes. A certificate is requested when none from the CA is in use, when the names change, and with 30 days left (or a third of the certificate's life, if that is shorter, so short-lived certificates renew in time). The new certificate is installed through the same staged / applied / previous slots, so Roll back still works. A failed request is retried after six hours and the reason is written to the Application logs; a certificate that is under seven days from expiry logs it as an error. A certificate you uploaded yourself is never replaced by the automatic renewal.
* The account key, the Cloudflare token and the external account HMAC key are stored encrypted with the server's master key, and are never sent back to the browser. A testing CA's certificate is staged but never applied.
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

Both directions are read: the output policy that queues traffic on an interface and the input policy that marks or polices it. Input classes are listed with an `in` tag. Bandwidth guarantees use the MIB's units (percent, percent of remaining, kbps). Counters fall back from 64-bit to 32-bit when a device only implements the 32-bit ones, and per-VLAN policies are labelled with their VLAN. Control-plane policies are skipped because they do not belong to an interface. The poller re-reads the policy structure every hour so a policy attached later is picked up, and if a device returns nothing the reason is shown on the Network health page (it is also stored in `devices.qos_note`) rather than the policy silently going missing.

Every device, switches and access points included, also reports its uptime, CPU, memory, swap, load and the fullest disks, read about once a minute from the first MIB it answers (Cisco process and memory pools, UCD-SNMP, HOST-RESOURCES). Network health shows them as tiles with a trend line and, below them, graphs of the history: a reading a minute is kept for three days and an hourly average and peak for the retention period of SNMP history, so a spike from last week is still visible. A drop in uptime is shown as a restart on the graphs.

CPU and memory also come from the vendors' own MIBs where the standard ones are empty (Juniper, Huawei, H3C and HPE Comware, HP ProCurve, FortiGate, Palo Alto), and firewalls show their session count and the history of it. The same page reads, every few minutes, the temperature, fan, power supply and voltage sensors (ENTITY-SENSOR-MIB, Cisco's version with its limits, CISCO-ENVMON-MIB, Juniper), the light levels and temperature of optics tied to their interface, the PoE budget, the spanning tree root and topology changes, OSPF neighbour and BGP peer states, and per interface the duplex, CRC/alignment/symbol errors, collisions and broadcast, multicast and unknown-protocol rates. Plain-language warnings flag half duplex on a fast link, errors still arriving and broadcast storms.

A device's page on Network health is split into tabs: **Overview** (a *Needs attention* list of everything outside its limits, each item with a button that opens the tab, and for a port the interface and its link quality section, where it is explained; a summary card per tab; then the resource tiles with their sparklines), **Interfaces** (the interface table, and the selected interface's queues, link quality and graphs), **Hardware** (on every device: the resource tiles with the history graphs of CPU, memory, disk, load, temperature and sessions, then sensors, optics, PoE, shown only when the device reports them), **Neighbours and routing** (spanning tree, OSPF, BGP, CDP and LLDP) and **Wi-Fi** (for access points). Inside an interface, **Traffic and queues**, **Link quality** and **Hosts and neighbours** are tabs of their own. Link quality lists every error and discard counter by type (input and output errors and discards, CRC, alignment, symbol, late and excessive collisions, collisions, carrier sense, frames too long, unknown protocol) with the change since the last read, and has graphs of errors, discards, broadcast, multicast and error types. These counters are read every few minutes and kept for three days as they were read, then as hourly averages. The light levels of optics are shown with their interface, in the interface table and its Link quality tab. Both the Traffic and queues and Link quality tabs of an interface also graph the device's CPU on the same time axis and crosshair, and say in a sentence whether the moments with queue drops, discards or errors coincide with a busy CPU (80% or more), so a drop caused by the device being overloaded can be told from one caused by the link. Drag across any line graph on Network health to zoom every graph of that group to the stretch you selected; "Show the full range" goes back. Each access point a device answers for gets the same tiles, sparklines and history graphs as any other device, kept per access point.

Queue statistics are read from Cisco's class-based QoS MIB first, then Juniper CoS (JUNIPER-COS-MIB) on Juniper devices, then the standard DIFFSERV-MIB. The OIDs for all of these were checked against the published MIB definitions, but only the Cisco QoS tables and the OPNsense (net-snmp) resource tables have been seen on real equipment; the others are covered by tests against synthetic tables, so report anything that reads wrongly on your hardware. Not supported: queue counters for Arista, Huawei and MikroTik (their MIBs could not be confirmed), and per-port PoE draw.

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
* An interface that holds a public IPv4 address shows its addresses in the **IP address** column of the interface table (routed ports and SVIs), with a small **public** tag beside each public one, and "(public)" in the selected interface's header. It is informational only: it never raises a notice or changes an interface's status, since edge routers and firewalls are meant to have one. Private, carrier-grade NAT (100.64.0.0/10), loopback, link-local, documentation, multicast and other reserved ranges do not count. The search box finds them with the word `public`, and also matches addresses. Only IPv4 addresses are read from the device (ipAddrTable).
* Interfaces that are VLANs or SVIs are left out of "Needs attention" on Network health, since they carry routed traffic for a whole subnet and not a physical link.

### Multicast streams

A multicast stream has one source and many receivers, and every switch and router on the distribution tree reports the same packets. The stream view therefore does not draw a path. It shows the source host, the group, and the devices that saw the stream as an unordered set (sorted by name), each with the interface it came in on and the interfaces it replicated to. No latency, loss or marking comparison is made between devices. The switch port the source is plugged into is looked up from the MAC tables as described above; it is marked on the matching device, and it is shown as unknown (not guessed from the flow data) when host tracking cannot place it.

**Where the group goes.** Flow records only show the interface a multicast packet arrived on: the router copies it to its receivers after that, so the outgoing interfaces are usually missing or only one of many is reported. FlowScope therefore also reads each router's own multicast table over SNMP, every two minutes (every hour from a device that has none), and shows it under the stream as *Where this group should go*: for each polled device that knows the group, the interfaces it is forwarded out of, which of them NetFlow also reported, and the hosts that joined on each (the last host to send an IGMP report). The same data is on its own page, **Multicast**: every group, source, incoming interface, outgoing interfaces, rate and rendezvous point of a device, with the hosts that joined on each interface and its PIM neighbours.

What is read, all read-only: the routes and their outgoing interface lists from `IPMROUTE-STD-MIB` (1.3.6.1.2.1.83), the measured rate and the route flags (prune, sparse, local, SPT and so on) from `CISCO-IPMROUTE-MIB` where the device has it, the IGMP cache from `IGMP-STD-MIB` (1.3.6.1.2.1.85), and the rendezvous point of each group, PIM interfaces, designated routers and neighbours from `PIM-MIB` (1.3.6.1.3.61). Without the Cisco table the page still works but shows no rate. A device that publishes none of it simply has no Multicast page entry.

The comparison flags what does not match: the stream arrives on a different interface than the route expects; NetFlow reports it leaving an interface the router does not forward to; a host joined on an interface the route does not forward to; a device sent flows for the group but has no route for it now. "NetFlow did not report this interface" is not a mismatch, since that is the normal case. A host that joined on the interface the stream arrives on is on the source's own segment and is shown as informational, not as a missing receiver. The state is a snapshot from when the router was last read, so for a stream that ended a while ago the receivers shown are the current ones; the page says so.

Limits: IPv4 only. Receivers that sit behind Layer 2 ports of a switch (IGMP snooping) are not visible on a device whose snooping table is not published (`dot1qTpGroupTable` was empty on the Catalyst 9300 stack this was built against), so those show up only as the VLAN interface the hosts are on. The IGMP cache gives the last host that reported, not every member of the group. **PIM mode** is read per interface from `PIM-MIB` (dense, sparse or sparse-dense) and per route from the route's protocol; a dense or sparse-dense interface is flagged because traffic is flooded and receivers behave differently there (a sparse-dense interface runs dense for groups with no rendezvous point). The **hardware model** of each device is read from `ENTITY-MIB` (`entPhysicalModelName` of the chassis and module rows, every six hours) and shown in the device header and in the incomplete-list notice. **PIM checks** under the summary: the two ends of a PIM link running different modes (a warning for dense against anything else, a note for sparse against sparse-dense; only when the neighbour is polled too), a mix of modes on one router, and groups running dense on a sparse-dense interface because no rendezvous point is known. The page also lists the **IGMP querier** of each interface (`IGMP-STD-MIB`, with a warning where hosts have joined but no querier is reported), the **rendezvous point mappings** the router knows (`pimRPSetTable`, and any group ranges it is a candidate RP for) with the device each address belongs to, and for every route its **RPF** information: the incoming interface and upstream neighbour, the unicast route that chose them and the count of packets dropped because they arrived on the wrong interface. The router counts those drops since the route was created, so a number means it happened, not that it is happening now. RPF is shown for each group as well as each source, and when the RPF neighbour is a device FlowScope polls too, the line links to that device's multicast table for the group and to the interface on each switch. Three problems are flagged on a route and on its collapsed group: packets dropped by the RPF check, a neighbour that does not list the link as a forwarding outgoing interface for the group, and multicast lost on the link (the neighbour sends clearly more out of its end than this router receives on its end, from the per-interface multicast counters). Where `pimRPSetTable` is empty, which it is on the Catalyst switches walked, the rendezvous points come from the per-group RP table (`pimRPTable`) and a down RP is flagged.


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
