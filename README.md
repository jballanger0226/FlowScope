# FlowScope

A NetFlow / IPFIX collector with per-hop stream tracing, SNMP link and QoS monitoring, reports and an admin console.
One Node.js 22 process, one data folder. Runs on Linux, macOS, Windows and as a container.

* **Flow explorer**: search with tokens (`src:10.1.0.0/16 port:443 qos:changed dscp:46 vlan:140 exporter:...`), see every hop a stream took, and see where its DSCP marking was changed.
* **Links & QoS**: SNMP interface utilisation, errors/discards and Cisco CBQoS per-class drops, with charts and the streams crossing a link.
* **Reports**: group by L2/L3/L4 fields, filter, top-N with "other", export CSV or JSON.
* **Storage & retention**: raw, 1-minute, 1-hour and daily tiers with per-tier retention, size estimate, and a choice of embedded SQLite (default) or ClickHouse (experimental).
* **Devices**: add SNMP devices one at a time or by discovery, with several credential sets tried in turn.
* **Admin**: HTTPS certificate (self-signed, upload PEM/PKCS#12, generate a CSR with ECDSA/RSA/Ed25519, roll back), start/stop collection, per-service authentication (local, RADIUS, LDAP, Active Directory, SAML for the web console), roles and users, SNMP credential sets, application logs.
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
The image runs as a non-root user, has a health check (`flowscope healthcheck`), and keeps everything in `/data`.
Behind a TLS-terminating proxy set `FLOWSCOPE_TLS=off` (serves HTTP on 8080), `FLOWSCOPE_TRUST_PROXY=1` and `FLOWSCOPE_PUBLIC_URL`.

### As a service

| OS | How |
| --- | --- |
| Linux | `sudo packaging/linux/install.sh` (systemd unit, dedicated user, settings in `/etc/flowscope/flowscope.env`, data in `/var/lib/flowscope`) |
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

## SNMP

Reads standard MIB-II / IF-MIB (`ifDescr`, `ifName`, `ifAlias`, `ifHighSpeed`, `ifHC*Octets`, discards, errors, oper status), `ipAddrTable`, VLAN names from `Q-BRIDGE-MIB` (`dot1qVlanStaticName`) and Cisco `CISCO-VTP-MIB` (`vtpVlanName`), and per-class QoS from `CISCO-CLASS-BASED-QOS-MIB` (`cbQosPolicyDirection`, `cbQosIfIndex`, `cbQosConfigIndex`, `cbQosObjectsType`, `cbQosParentObjectsIndex`, `cbQosPolicyMapName`, plus class-map names, the 64-bit pre-policy packet/byte, post-policy byte and drop packet/byte counters, queueing bandwidth and current queue depth). SNMP v1, v2c and v3 (noAuthNoPriv, authNoPriv, authPriv) are supported through `net-snmp`. OIDs are listed in `src/snmp/oids.ts`.

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

See [docs/verification.md](docs/verification.md). In short: developed and tested on Linux only; Windows, macOS and the container image are written but have not been run.
