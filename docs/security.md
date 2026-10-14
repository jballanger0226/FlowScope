# Securing FlowScope

This page says what FlowScope exposes, what it does and does not protect against today, and what to configure around it. It comes from a code review of commit `e8b25a5` (October 2026). Where the application has a known gap, the gap is stated here so that your network can cover it.

## What listens where

| Port | Purpose | Who should reach it | Authentication |
| --- | --- | --- | --- |
| TCP 8443 (8080 with `FLOWSCOPE_TLS=off`) | Web console and API | Administrator networks only | Sign-in, roles, API tokens |
| UDP 2055 and 4739 (`FLOWSCOPE_FLOW_PORTS`) | NetFlow v5/v9 and IPFIX from your routers and switches | Exporter addresses only | None. NetFlow and IPFIX have no authentication |

FlowScope also connects out: UDP 161 to SNMP devices, UDP 1812 and 1813 to RADIUS, TCP 389 or 636 to LDAP and Active Directory, and TCP 8123 to ClickHouse (kept on the compose network or published on the loopback address only, never beyond it).

## The flow collector trusts what it receives

Anyone who can send UDP datagrams to the flow ports can:

* add false flow records, which then appear in the explorer, reports and stream traces as if a router had sent them;
* use up memory and disk with crafted packets. The decoder keeps NetFlow v9 and IPFIX templates and held data per sender without a cap, and flow timestamps are taken from the packet without a range check, so a packet can create storage tables for dates far in the past or future;
* fill the exporter list (limited to 5,000 senders), which also makes later, real exporters get ignored.

An exporter whose clock was never set reports dates in 1970 and has the timestamp effect by accident. On a new database that can stall storage for tens of seconds while the first rollup runs.

FlowScope does not limit these in the application yet, so the network has to. Follow the next section on every installation that is reachable from anything other than the exporters themselves.

## Limit who can send flows

1. **Allow the flow ports only from your exporters.** Use the address each device exports from. Set it to a loopback or management address on the device, so the list stays short and does not change when a link moves. Drop everything else.
2. **Put the collector on a management network** that only the exporters and administrators can reach. If the host has several addresses, set `FLOWSCOPE_FLOW_BIND` to the management one.
3. **Block forged source addresses** where the exporters connect (unicast reverse-path filtering or ingress filtering on those router interfaces). A source-address allow-list stops outsiders, but it does not stop a host that forges an exporter's address on a network that allows forging.
4. **Watch for unknown senders.** The log shows `new exporter <address>` the first time each address is heard. Treat an address that is not in your inventory as an alert.
5. **Set a memory limit** so that a flood restarts the service instead of exhausting the host: `MemoryMax=` in a systemd drop-in, or `mem_limit` (compose) or `--memory` (docker run). Pick a value above the normal usage you see in `systemctl status flowscope` or `docker stats`. The service restarts itself (`Restart=on-failure`, `restart: unless-stopped`), but flows sent in the meantime are lost.

### Linux host: nftables

Replace the example networks (192.0.2.0/24 exporters, 203.0.113.0/24 administrators) and add your IPv6 networks, or delete the IPv6 line to drop all IPv6 flow traffic:

```
table inet flowscope_filter {
  set exporters4 { type ipv4_addr; flags interval; elements = { 192.0.2.0/24, 198.51.100.10 } }
  set exporters6 { type ipv6_addr; flags interval; elements = { 2001:db8:10::/48 } }
  set admins4    { type ipv4_addr; flags interval; elements = { 203.0.113.0/24 } }
  chain input {
    type filter hook input priority 0; policy accept;
    udp dport { 2055, 4739 } ip saddr @exporters4 accept
    udp dport { 2055, 4739 } ip6 saddr @exporters6 accept
    udp dport { 2055, 4739 } drop
    tcp dport 8443 ip saddr @admins4 accept
    tcp dport 8443 drop
  }
}
```

Save it in `/etc/nftables.conf` (or a file that one includes) and load it with `sudo nft -f /etc/nftables.conf`. `nft -c -f <file>` checks the syntax without loading it. If you changed the ports with `FLOWSCOPE_FLOW_PORTS` or `FLOWSCOPE_HTTPS_PORT`, change them here too.

### Linux host: ufw

```sh
sudo ufw allow 22/tcp                       # first, so you do not lock yourself out of SSH
sudo ufw default deny incoming
sudo ufw allow from 192.0.2.0/24 to any port 2055,4739 proto udp
sudo ufw allow from 203.0.113.0/24 to any port 8443 proto tcp
sudo ufw enable
```

### Docker

Docker publishes container ports through its own firewall rules, which are evaluated before the rules that ufw and firewalld manage. A ufw rule does **not** restrict a published port such as `2055:2055/udp`. Use one of:

* **Host networking.** `docker compose -f docker-compose.host.yml up -d` (or the `.host.sqlite.yml` file). The container then uses the host's network and the host firewall above applies. Not available on Docker Desktop for Windows or macOS.
* **Rules in the `DOCKER-USER` chain**, which Docker leaves for your own rules. This matches the port the exporter sent to, so it works whatever host port you publish:

  ```sh
  sudo iptables -I DOCKER-USER -p udp -m conntrack --ctorigdstport 2055 ! -s 192.0.2.0/24 -j DROP
  sudo iptables -I DOCKER-USER -p udp -m conntrack --ctorigdstport 4739 ! -s 192.0.2.0/24 -j DROP
  sudo iptables -I DOCKER-USER -p tcp -m conntrack --ctorigdstport 8443 ! -s 203.0.113.0/24 -j DROP
  ```

  The chain exists once Docker has started, and the rules are lost on reboot unless your distribution saves them (for example with `iptables-persistent`).
* **Publish on one address.** `"192.0.2.10:2055:2055/udp"` in the `ports:` list limits which host address listens. It does not limit who may send to it, so combine it with one of the above.

### Windows

The installer opens the three ports to every address. Restrict them to your networks:

```powershell
Set-NetFirewallRule -DisplayName 'FlowScope flow export (UDP 2055)' -RemoteAddress 192.0.2.0/24
Set-NetFirewallRule -DisplayName 'FlowScope IPFIX (UDP 4739)'       -RemoteAddress 192.0.2.0/24
Set-NetFirewallRule -DisplayName 'FlowScope web (TCP 8443)'         -RemoteAddress 203.0.113.0/24
```

`-RemoteAddress` takes a comma-separated list of addresses and subnets.

### Proxmox and macOS

On Proxmox, enable the container firewall and allow the flow ports only from an IP set that holds your exporters, and TCP 8443 only from your administrator networks. On macOS, use the application firewall or `pf` the same way.

## Web console and API

* Reach TCP 8443 from administrator networks only.
* Behind a reverse proxy, set `FLOWSCOPE_TRUST_PROXY=1` only if the proxy **replaces** `X-Forwarded-For` with the address that connected to it (nginx: `proxy_set_header X-Forwarded-For $remote_addr;`). A proxy that appends to a header the client supplied lets the client choose the address that the sign-in throttle and the audit log record.
* To cut someone off, disable or delete the account; either stops their API tokens. A password reset (in the console or with `flowscope reset-password`) does not revoke API tokens. A token can create further tokens, including ones that never expire, so treat a token as a long-lived credential and give it the shortest lifetime that works.
* Make the data directory private. It holds password hashes, session data and logs, and the default permissions let other local users read the database. On the Linux service:

  ```sh
  sudo chmod 0700 /var/lib/flowscope
  sudo systemctl edit flowscope        # in the editor that opens, add the three lines below, save, then restart the service
  ```

  ```
  [Service]
  UMask=0077
  StateDirectoryMode=0700
  ```

  A named Docker volume lives under `/var/lib/docker`, which only root can enter. For a bind mount, set the same mode on the host directory.

## Roles

* **SNMP admin** is for people trusted to add, remove and maintain the list of SNMP targets, but not to administer FlowScope. It includes more than the target list: that role can test, add and run discovery against any address with any stored credential set, including "try other credentials". An SNMPv2c community string is sent in clear text to whatever address is entered, so anyone listening at that address can read it. To keep that harmless: store read-only communities (FlowScope only reads); use SNMPv3 with authentication and privacy where the devices support it; keep one credential set per site; and block outbound UDP 161 from the FlowScope host except to the networks that hold your devices. Credential tests are not written to the audit log; discovery runs are logged with the user and credential set name.
* **Admin** can change authentication, certificates and users. Keep at least one local administrator, with a long password, for break-glass use.

## RADIUS, LDAP and Active Directory, SAML

* **RADIUS.** FlowScope sends a Message-Authenticator with each Access-Request but does not yet require one in the reply. RADIUS over UDP is exposed to forged replies from anyone positioned between FlowScope and the server (BlastRADIUS, CVE-2024-3596). Keep that path on a network where no untrusted party can sit in the middle, apply your RADIUS vendor's BlastRADIUS update, and prefer LDAPS or SAML for the web console where you can. To find out whether your server already sends the attribute, capture a login and look for attribute 80 in the Access-Accept.
* **LDAP and Active Directory.** Use `ldaps://` and leave certificate verification on. The console also accepts `ldap://` and verification off, in which case passwords cross the network unprotected or go to an unverified server. Group mappings match on the group's common name (CN) only, so make sure nobody who can create groups in the directory can create one with the same CN as a mapped group.
* **SAML.** With SAML as the web sign-in, the local administrator cannot currently sign in through the web form, although the page offers it. Before you switch, keep the API service on local accounts (an administrator can then change the web provider back with `PUT /api/admin/aaa`), and test with a second browser session already signed in. Set `FLOWSCOPE_PUBLIC_URL`; without it the SAML URLs are built from the request's Host header.
