# FlowScope

A NetFlow / IPFIX collector with per-hop stream tracing, SNMP link and QoS monitoring, reports and an admin console.
One Node.js 22 process, one data folder. Runs on Linux, macOS, Windows and as a container.

* **Flow explorer**: search with tokens (`src:10.1.0.0/16 port:443 qos:changed dscp:46 vlan:140 exporter:...`), see every hop a stream took, and see where its DSCP marking was changed. `ttl:expired` (or the **TTL expired only** button) lists streams whose TTL ran out before the destination.
* **Links & QoS**: SNMP interface utilisation, errors/discards and Cisco CBQoS per-class drops, with charts and the streams crossing a link.
* **Reports**: group by L2/L3/L4 fields, filter, top-N with "other", export CSV or JSON.
* **Storage & retention**: raw, 1-minute, 1-hour and daily tiers with per-tier retention, size estimate, and a choice of embedded SQLite (default) or ClickHouse (experimental).
* **Devices**: add SNMP devices one at a time or by discovery, with several credential sets tried in turn.
* **Admin**: HTTPS certificate (self-signed, upload PEM/PKCS#12, generate a CSR with ECDSA/RSA/Ed25519, roll back), start/stop collection, per-service authentication (local, RADIUS, LDAP, Active Directory, SAML for the web console), roles and users, SNMP credential sets, application logs.
* **Appearance**: light, dark or follow the operating system (System / Light / Dark switch at the top right and on the sign-in page; the choice is remembered in the browser).
* **Sign-in**: every page and API call needs a session. The signed-in user and role, and a Sign out button, are at the top right.
* Roles: **ro** (read-only), **snmp** (read-only plus device management), **admin**.

## Quick start

Needs Node.js 22.13 or newer.

```sh
npm install
npm run build
npm run demo          # simulated network, sign in as admin / flowscope-demo-admin at https://localhost:8443/
npm start             # real use
```

The certificate is self-signed until you install your own (Admin → HTTPS certificate), so the browser warns on first visit.
On first start the `admin` account is created. Set `FLOWSCOPE_ADMIN_PASSWORD` (12+ characters) beforehand, or read the generated password from the log.
Point your routers' NetFlow v5/v9 or IPFIX export at this host, UDP **2055** or **4739**.

### Container

```sh
docker compose up -d                          # SQLite storage, data in the flowscope-data volume
docker compose --profile clickhouse up -d     # also starts ClickHouse (see "ClickHouse" below)
```

or `docker build -t flowscope . && docker run -d -p 8443:8443 -p 2055:2055/udp -p 4739:4739/udp -v flowscope-data:/data flowscope`.
The image has a health check (`flowscope healthcheck`), keeps everything in `/data`, and runs the server as the unprivileged `node` user (it starts as root only to make `/data` writable, then drops privileges; `--user 1000:1000` skips that).
Behind a TLS-terminating proxy set `FLOWSCOPE_TLS=off` (serves HTTP on 8080), `FLOWSCOPE_TRUST_PROXY=1` and `FLOWSCOPE_PUBLIC_URL`.
If every exporter shows up as the Docker bridge address, use `docker compose -f docker-compose.host.yml up -d`.

### Proxmox VE

On the Proxmox host, from a checkout of this repository:

```sh
packaging/proxmox/flowscope-lxc.sh            # creates an unprivileged Debian 12 LXC container and installs FlowScope in it
packaging/proxmox/flowscope-lxc.sh update 210 # later: snapshot, then update container 210
```

Proxmox VE 9.1 and newer can also run the Docker image directly as an LXC application container. Both routes, with all options, are in **[docs/deployment.md](docs/deployment.md)**, together with Docker details, upgrades, backups and troubleshooting.

### As a service

| OS | How |
| --- | --- |
| Linux | `sudo packaging/linux/install.sh` (systemd unit, dedicated user, settings in `/etc/flowscope/flowscope.env`, data in `/var/lib/flowscope`) |
| Proxmox VE | `packaging/proxmox/flowscope-lxc.sh` on the host (see above); `packaging/proxmox/install.sh` is the installer it runs inside the container |
| macOS | `sudo packaging/macos/install.sh` (launchd daemon, data in `/Library/Application Support/FlowScope`, log `/var/log/flowscope.log`) |
| Windows | elevated PowerShell: `.\packaging\windows\install.ps1` (scheduled task at boot as SYSTEM, firewall rules, settings in `%ProgramData%\FlowScope\flowscope.env`) |

## Settings

All settings are environment variables.

| Variable | Default | Meaning |
| --- | --- | --- |
| `FLOWSCOPE_DATA_DIR` | `/data` in a container; `/var/lib/flowscope` (root) or `~/.local/share/flowscope` on Linux; `~/Library/Application Support/FlowScope` on macOS; `%ProgramData%\FlowScope` on Windows | Everything FlowScope stores |
| `FLOWSCOPE_HTTPS_PORT` | `8443` | Web console and API (TLS) |
| `FLOWSCOPE_TLS` | `auto` | `off` serves plain HTTP only (behind a proxy) |
| `FLOWSCOPE_HTTP_PORT` | `0` (`8080` when TLS is off) | Plain HTTP listener |
| `FLOWSCOPE_BIND` | `0.0.0.0` | Web bind address |
| `FLOWSCOPE_FLOW_PORTS` | `2055,4739` | UDP ports for NetFlow v5/v9/IPFIX |
| `FLOWSCOPE_FLOW_BIND` | `0.0.0.0` | Flow listener address |
| `FLOWSCOPE_ADMIN_PASSWORD` | generated | Password for the first `admin` (first start only) |
| `FLOWSCOPE_MASTER_KEY` | key file in the data dir | Encrypts stored secrets (SNMP communities/passwords, RADIUS secret, bind passwords, private keys). Set it if you want the key outside the data folder. |
| `FLOWSCOPE_PUBLIC_URL` | | External URL, used for SAML callbacks |
| `FLOWSCOPE_TRUST_PROXY` | off | Trust `X-Forwarded-*` from a reverse proxy |
| `FLOWSCOPE_CLICKHOUSE_URL` | | `http://user:pass@host:8123/database` (database defaults to `flowscope`) |
| `FLOWSCOPE_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `FLOWSCOPE_DEMO` | off | Same as `--demo` |

Other commands: `flowscope reset-password <user>`, `flowscope healthcheck`, `flowscope version`.

## Storage

* **SQLite (default)**: one `ts.db` file in the data folder. Raw flows live in one table per day, so retention is a cheap drop. Rolled-up tiers (1m, 1h, 1d) are built from the raw rows exactly once, even when records arrive late. Good for a few thousand flows per second.
* **ClickHouse (experimental)**: set `FLOWSCOPE_CLICKHOUSE_URL`, then choose it under Storage (collection must be stopped; the new backend starts empty and old data is not migrated). Uses ClickHouse's HTTP interface, so no extra native dependency. The 1-minute tier is maintained by a materialized view; 1h/1d are filled when each hour/day closes. If ClickHouse cannot be reached at start-up FlowScope falls back to SQLite and says so in Storage. For an HTTPS ClickHouse with a private CA, start Node with `NODE_EXTRA_CA_CERTS=/path/ca.pem`.

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
* Put the collector on a management network. Flow export is unauthenticated UDP by nature.

## Development

```sh
npm run typecheck
npm test                                          # builds, then runs all tests
FLOWSCOPE_TEST_CLICKHOUSE=http://127.0.0.1:8123 node --test dist/test/clickhouse.test.js   # needs a ClickHouse server
```

`src/` is the server, `web/` is the browser UI (TypeScript compiled with `tsc`, no bundler, no runtime dependencies), `test/` has unit, API and protocol tests. `src/sim/` contains the packet builders and SNMP agent used by the tests and the demo.

## What has and has not been verified

See [docs/verification.md](docs/verification.md). In short: developed and tested on Linux only. The Docker image was run against a stand-in base image; Windows, macOS and the Proxmox scripts have not been run on real systems.
