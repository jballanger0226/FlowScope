import type { ConfigDb } from '../db/configdb.js';
import type { AppLog } from '../logger.js';
import type { DeviceRow, DeviceService } from './devices.js';
import type { SnmpClient } from './client.js';
import { readAuthSessions, type AuthSession } from './authsessions.js';
import { readDhcpBindings, type DhcpBinding } from './dhcp_snooping.js';
import { readArp, readFdb, readNeighbors, readPortVlans, type Neighbor } from './ports.js';
import { apAsResources, recordResources } from './resource_history.js';
import type { WlanData } from './wlan.js';
import { readWlanFor } from './wlan_vendors.js';

/*
 * Host tracking: which switch port a host is plugged into.
 *
 * Every polled switch is asked for the MAC addresses it has learned on each port (its MAC address table), for its LLDP and CDP
 * neighbours, and every router or Layer 3 switch for its ARP table (which MAC address belongs to which IP address). The pieces are
 * joined here. A MAC address is normally learned on many switches, because the frame crosses all of them. The switch it is plugged
 * into is the one that learned it on a port that does NOT lead to another switch: LLDP/CDP says which ports are uplinks, and a
 * port that has learned a great many addresses is treated as one when no neighbour information exists.
 */

export interface HostOpts { enabled: boolean; intervalSec: number; keepDays: number }
export const HOST_DEFAULTS: HostOpts = { enabled: true, intervalSec: 300, keepDays: 14 };

export interface Attachment {
  devId: number; dev: string; ifIndex: number; ifName: string; vlan: number; macCount: number;
  /** The port is not an uplink to another switch or router. */
  edge: boolean; neighbor: string | null; neighborKind: string | null; portMode: string;
  lastSeen: number; since: number; active: boolean; mac: string;
}
export interface HostLocation {
  query: string; ip: string | null; macs: string[]; macSource: 'arp' | 'flow' | 'given' | 'none';
  attach: (Attachment & { confidence: 'high' | 'medium' | 'low' }) | null;
  /** Other places the address was seen: uplink ports, and other edge ports when it was seen on more than one. */
  others: (Attachment & { confidence: 'high' | 'medium' | 'low' })[];
  note: string;
}
/** What an access point knows about a wireless client. */
export interface WifiInfo { name: string; os: string; ssid: string; ap: string; radio: number | null; band: string; channel: string; snr: number; txRate: number; rxRate: number; txBytes: number; rxBytes: number; uptimeSec: number; readAt: number }
export interface PortHost { auth: { user: string; vlan: number; authenticated: boolean } | null; mac: string; vlan: number; ips: string[]; firstSeen: number; lastSeen: number; since: number; active: boolean; wifi: WifiInfo | null }

/** A port that has learned more than this many addresses is treated as leading to another switch when nothing else says otherwise. */
const UPLINK_MAC_COUNT = 30;
const LAG_EDGE_MAX = 8;
const LAG_NAME = /^(po|port-channel|ae|bond|lag|trk|bagg)\s*\d/i;

const shortName = (n: string) => n.toLowerCase().replace(/\..*$/, '').trim();

export class HostTracker {
  constructor(private cdb: ConfigDb, private devs: DeviceService, private log: AppLog, private opts: () => HostOpts = () => HOST_DEFAULTS) {}

  private get db() { return this.cdb.db; }
  private activeSince(now = Date.now()): number { return now - Math.max(120, this.opts().intervalSec) * 3 * 1000; }

  /** Reads one device and stores what it knows. Returns counts for the log and the device page. */
  async refresh(d: DeviceRow, c: SnmpClient): Promise<{ macs: number; arp: number; neighbors: number; wifiClients: number; note: string }> {
    const now = Date.now();
    const ifs = this.devs.interfaces(d.id).map(i => ({ index: i.ifIndex, name: i.name, descr: i.descr }));
    const ips = (this.db.prepare('SELECT if_index AS ifIndex FROM device_ips WHERE dev_id = ?').all(d.id) as unknown as { ifIndex: number }[]);
    const ports = await readPortVlans(c, ifs, ips);
    this.devs.applyPorts(d.id, ports);
    const notes: string[] = [];

    // neighbours first: they decide which ports are uplinks
    let nbs: Neighbor[] = [];
    try { nbs = await readNeighbors(c, ifs); } catch (e) { notes.push(`LLDP/CDP not read: ${(e as Error).message}`); }
    const known = new Set<string>();
    for (const r of this.devs.rows()) { known.add(shortName(r.name)); if (r.sys_name) known.add(shortName(r.sys_name)); }
    const knownIps = new Set(this.devs.allAddresses());
    for (const n of nbs) if (n.kind !== 'infra' && (known.has(shortName(n.name)) || (n.ip && knownIps.has(n.ip)))) n.kind = 'infra';

    let arpRows = 0;
    const arp: (Awaited<ReturnType<typeof readArp>>[number] & { vrf: string })[] = (await readArp(c).catch(e => { notes.push(`ARP not read: ${(e as Error).message}`); return []; })).map(a => ({ ...a, vrf: '' }));
    // The ARP table is not scoped by SNMP context (a read in a VRF's context returns every VRF's entries), so an entry's VRF is that of the interface it was learned on (an SVI in a VRF)
    const vrfOfIf = this.devs.vrfMaps(d.id).direct;
    for (const a of arp) a.vrf = vrfOfIf.get(a.ifIndex) ?? '';
    const vrfArp = arp.filter(a => a.vrf).length;

    const cisco = (d.sys_object_id ?? '').startsWith('1.3.6.1.4.1.9.');
    let binds: DhcpBinding[] = [];
    if (cisco) { try { binds = await readDhcpBindings(c); } catch (e) { notes.push(`DHCP snooping not read: ${(e as Error).message}`); } }
    // 802.1X / MAB sessions: the VLAN the authentication server gave each client, and its address
    let auth: AuthSession[] = [];
    if (cisco) { try { auth = await readAuthSessions(c); } catch (e) { notes.push(`Authentication sessions not read: ${(e as Error).message}`); } }
    const vlans = new Set<number>();
    for (const a of auth) if (a.vlan) vlans.add(a.vlan);
    for (const p of ports.values()) { if (p.mode === 'access' || p.mode === 'pvid') { if (p.vlan) vlans.add(p.vlan); if (p.voice) vlans.add(p.voice); } else if (p.mode === 'trunk' && p.vlan) vlans.add(p.vlan); }
    // Ports that authenticate users (802.1X, MAB) put each host in the VLAN the RADIUS server names, not the one configured on the port, so the MAC tables
    // of every VLAN the switch routes (it has an SVI for it) and every VLAN a lease was seen in are read too
    for (const p of ports.values()) if (p.mode === 'svi' && p.vlan) vlans.add(p.vlan);
    for (const b of binds) if (b.vlan) vlans.add(b.vlan);
    if (!vlans.size) vlans.add(1);
    let fdb: Awaited<ReturnType<typeof readFdb>>;
    try { fdb = await readFdb(c, { cisco, vlans: [...vlans], forVlan: v => c.forVlan(v) }); }
    catch (e) { fdb = { entries: [], method: 'none', vlansTried: 0, vlansFailed: 0 }; notes.push(`MAC table not read: ${(e as Error).message}`); }
    if (fdb.vlansFailed) notes.push(`${fdb.vlansFailed} of ${fdb.vlansTried + fdb.vlansFailed} VLANs could not be read through the VLAN community${fdb.vlansTried === 0 ? ' (the device does not accept VLAN-indexed access; for SNMPv3 the context vlan-N must be allowed)' : ''}`);

    // Aruba Instant APs publish their radios, SSIDs and clients (with name, IP address and signal) in a table of their own
    let wlan: WlanData | null = null;
    {
      try { wlan = await readWlanFor(c, ifs, d.sys_object_id ?? '', d.sys_descr ?? ''); } catch (e) { notes.push(`Wi-Fi tables not read: ${(e as Error).message}`); }
    }

    this.cdb.tx(() => {
      if (wlan) this.storeWlan(d.id, wlan, now);
      const up = this.db.prepare(`INSERT INTO fdb(dev_id, mac, vlan, if_index, first_seen, last_seen, since) VALUES (?,?,?,?,?,?,?)
        ON CONFLICT(dev_id, mac, vlan) DO UPDATE SET last_seen = excluded.last_seen, since = CASE WHEN fdb.if_index = excluded.if_index THEN fdb.since ELSE excluded.since END, if_index = excluded.if_index`);
      for (const e of fdb.entries) up.run(d.id, e.mac, e.vlan, e.ifIndex, now, now, now);
      // an authentication session names the port and VLAN of its client outright, which a MAC table that was not read for that VLAN cannot
      const seen = new Set(fdb.entries.map(e => `${e.mac}/${e.vlan}`));
      for (const a of auth) if (a.vlan && !seen.has(`${a.mac}/${a.vlan}`)) up.run(d.id, a.mac, a.vlan, a.ifIndex, now, now, now);
      const ua = this.db.prepare(`INSERT INTO arp(dev_id, ip, mac, if_index, last_seen, vrf) VALUES (?,?,?,?,?,?)
        ON CONFLICT(dev_id, ip, mac) DO UPDATE SET last_seen = excluded.last_seen, if_index = excluded.if_index, vrf = excluded.vrf`);
      for (const a of arp) { ua.run(d.id, a.ip, a.mac, a.ifIndex, now, a.vrf); arpRows++; }
      // a lease the switch has seen also tells which IP address a MAC address uses; the bindings of a device are replaced as a whole, since an ended lease is gone from the table
      this.db.prepare('DELETE FROM dhcp_bindings WHERE dev_id = ?').run(d.id);
      const ub = this.db.prepare('INSERT OR REPLACE INTO dhcp_bindings(dev_id, mac, vlan, ip, if_index, lease_sec, last_seen) VALUES (?,?,?,?,?,?,?)');
      for (const b of binds) { ub.run(d.id, b.mac, b.vlan, b.ip, b.ifIndex, b.leaseSec, now); ua.run(d.id, b.ip, b.mac, b.ifIndex, now, ''); }
      this.db.prepare('DELETE FROM auth_sessions WHERE dev_id = ?').run(d.id);
      const byVlanVrf = this.devs.vrfMaps(d.id).byVlan;
      const us = this.db.prepare('INSERT OR REPLACE INTO auth_sessions(dev_id, mac, if_index, vlan, ip, policy, profile, domain, last_seen) VALUES (?,?,?,?,?,?,?,?,?)');
      for (const a of auth) {
        us.run(d.id, a.mac, a.ifIndex, a.vlan, a.ip, a.user, a.vlanName, a.domain, now);
        if (a.ip) { const vl = a.vlan || ports.get(a.ifIndex)?.vlan || 0; ua.run(d.id, a.ip, a.mac, a.ifIndex, now, vl ? byVlanVrf.get(vl) ?? '' : ''); }
      }
      this.db.prepare('DELETE FROM neighbors WHERE dev_id = ?').run(d.id);
      const un = this.db.prepare('INSERT OR REPLACE INTO neighbors(dev_id, if_index, proto, rem_key, rem_name, rem_port, rem_ip, kind, caps, seen_at) VALUES (?,?,?,?,?,?,?,?,?,?)');
      for (const n of nbs) un.run(d.id, n.ifIndex, n.proto, n.key, n.name, n.port, n.ip, n.kind, n.caps.join(','), now);
      const parts = [`${fdb.entries.length} MAC addresses (${fdb.method})`, `${arpRows} ARP entries${vrfArp ? ` (${vrfArp} in VRFs)` : ''}`, ...(binds.length ? [`${binds.length} DHCP snooping bindings`] : []), ...(auth.length ? [`${auth.length} authentication sessions (${auth.filter(a => a.domain !== 'unknown').length} authenticated, ${auth.filter(a => a.vlan).length} with a VLAN from the server)`] : []), `${nbs.length} neighbours`, ...(wlan ? [`${wlan.clients.length} wireless clients`] : []), ...notes];
      this.db.prepare('UPDATE devices SET hosts_at = ?, hosts_note = ? WHERE id = ?').run(now, parts.join('; '), d.id);
    });
    return { macs: fdb.entries.length, arp: arpRows, neighbors: nbs.length, wifiClients: wlan?.clients.length ?? 0, note: notes.join('; ') };
  }

  /** Replaces what is stored for one access point with the latest read. */
  private storeWlan(devId: number, w: WlanData, now: number): void {
    for (const t of ['wlan_ap', 'wlan_radio', 'wlan_ssid', 'wlan_client']) this.db.prepare(`DELETE FROM ${t} WHERE dev_id = ?`).run(devId);
    const ia = this.db.prepare('INSERT INTO wlan_ap(dev_id, mac, name, ip, serial, model, cpu_pct, mem_free, mem_total, uptime_sec, role, read_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)');
    for (const a of w.aps) {
      ia.run(devId, a.mac, a.name, a.ip, a.serial, a.model, a.cpuPct, a.memFree, a.memTotal, a.uptimeSec, a.role, now);
      try { recordResources(this.db, devId, apAsResources(a, now), a.mac.toLowerCase()); } catch { /* history is a bonus */ }
    }
    const ir = this.db.prepare('INSERT OR REPLACE INTO wlan_radio(dev_id, ap_mac, idx, mac, channel, band, tx_power, noise_floor, util4, util64, clients, mode, up) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)');
    for (const r of w.radios) ir.run(devId, r.apMac, r.idx, r.mac, r.channel, r.band, r.txPower, r.noiseFloor, r.util4, r.util64, r.clients, r.mode, r.up ? 1 : 0);
    const is = this.db.prepare('INSERT OR REPLACE INTO wlan_ssid(dev_id, ap_mac, bssid, name, radio, ssid_id, clients, if_name) VALUES (?,?,?,?,?,?,?,?)');
    for (const s of w.ssids) is.run(devId, s.apMac, s.bssid, s.name, s.radio, s.ssidId, s.clients, s.ifName);
    const ic = this.db.prepare('INSERT OR REPLACE INTO wlan_client(dev_id, mac, ap_mac, ap_name, bssid, ssid, radio, ip, name, os, snr, tx_rate, rx_rate, tx_bytes, rx_bytes, uptime_sec, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)');
    for (const c of w.clients) ic.run(devId, c.mac, c.apMac, c.apName, c.bssid, c.ssid, c.radio, c.ip, c.name, c.os, c.snr, c.txRate, c.rxRate, c.txBytes, c.rxBytes, c.uptimeSec, now);
    // a device with these tables is an access point, whatever its description says (a controller keeps its own role)
    if (w.vendor !== 'cisco' && w.vendor !== 'ruckus') this.db.prepare("UPDATE devices SET role = 'ap' WHERE id = ?").run(devId);
  }

  /** The Wi-Fi state last read from one access point, or null when it has none. */
  wlanOf(devId: number): { readAt: number; aps: unknown[]; radios: unknown[]; ssids: unknown[]; clients: unknown[] } | null {
    const aps = this.db.prepare('SELECT mac, name, ip, serial, model, cpu_pct AS cpuPct, mem_free AS memFree, mem_total AS memTotal, uptime_sec AS uptimeSec, role, read_at AS readAt FROM wlan_ap WHERE dev_id = ? ORDER BY name').all(devId) as unknown as { readAt: number }[];
    if (!aps.length) return null;
    const radios = this.db.prepare('SELECT ap_mac AS apMac, idx, mac, channel, band, tx_power AS txPower, noise_floor AS noiseFloor, util4, util64, clients, mode, up FROM wlan_radio WHERE dev_id = ? ORDER BY ap_mac, idx').all(devId) as unknown as { up: number }[];
    const ssids = this.db.prepare('SELECT ap_mac AS apMac, bssid, name, radio, ssid_id AS ssidId, clients, if_name AS ifName FROM wlan_ssid WHERE dev_id = ? ORDER BY name, radio').all(devId);
    const clients = this.db.prepare('SELECT mac, ap_mac AS apMac, ap_name AS apName, bssid, ssid, radio, ip, name, os, snr, tx_rate AS txRate, rx_rate AS rxRate, tx_bytes AS txBytes, rx_bytes AS rxBytes, uptime_sec AS uptimeSec FROM wlan_client WHERE dev_id = ? ORDER BY name COLLATE NOCASE, mac').all(devId);
    return { readAt: aps[0].readAt, aps, radios: radios.map(r => ({ ...r, up: r.up === 1 })), ssids, clients };
  }

  /** True for devices that have Wi-Fi data, so the screens know to ask for it. */
  hasWlan(devId: number): boolean { return !!this.db.prepare('SELECT 1 FROM wlan_ap WHERE dev_id = ? LIMIT 1').get(devId); }

  /** What any access point knows about a MAC address, or null. */
  wifiFor(mac: string): WifiInfo | null {
    const r = this.db.prepare(`SELECT c.name, c.os, c.ssid, c.ap_name AS ap, c.radio, c.snr, c.tx_rate AS txRate, c.rx_rate AS rxRate, c.tx_bytes AS txBytes, c.rx_bytes AS rxBytes, c.uptime_sec AS uptimeSec, c.last_seen AS readAt, c.ip,
        r.channel, r.band FROM wlan_client c LEFT JOIN wlan_radio r ON r.dev_id = c.dev_id AND r.ap_mac = c.ap_mac AND r.idx = c.radio WHERE c.mac = ? ORDER BY c.last_seen DESC LIMIT 1`).get(mac) as unknown as (Omit<WifiInfo, 'channel' | 'band'> & { channel: string | null; band: string | null; ip: string }) | undefined;
    return r ? { name: r.name, os: r.os, ssid: r.ssid, ap: r.ap, radio: r.radio, band: r.band ?? '', channel: r.channel ?? '', snr: r.snr, txRate: r.txRate, rxRate: r.rxRate, txBytes: r.txBytes, rxBytes: r.rxBytes, uptimeSec: r.uptimeSec, readAt: r.readAt } : null;
  }

  /** Records why the last host-table read failed, so it shows on the device page. */
  fail(devId: number, message: string): void {
    this.db.prepare('UPDATE devices SET hosts_note = ? WHERE id = ?').run(`Last read failed: ${message}`, devId);
  }

  /** Forgets addresses not seen for `keepDays`. */
  purge(now = Date.now()): void {
    const lim = now - this.opts().keepDays * 86_400_000;
    this.db.prepare('DELETE FROM fdb WHERE last_seen < ?').run(lim);
    this.db.prepare('DELETE FROM arp WHERE last_seen < ?').run(lim);
    this.db.prepare('DELETE FROM dhcp_bindings WHERE last_seen < ?').run(lim);
    this.db.prepare('DELETE FROM auth_sessions WHERE last_seen < ?').run(lim);
    this.db.prepare('DELETE FROM wlan_client WHERE last_seen < ?').run(lim);
  }

  /* ---------------------------------------------------------------- queries */

  private ifName(devId: number, ifIndex: number): string {
    const r = (this.db.prepare('SELECT name FROM interfaces WHERE dev_id = ? AND if_index = ?').get(devId, ifIndex) ?? this.db.prepare('SELECT name FROM interface_names WHERE dev_id = ? AND if_index = ?').get(devId, ifIndex)) as { name: string } | undefined;
    return r?.name ?? `if${ifIndex}`;
  }

  /** Number of addresses currently learned on every port, keyed "device/ifIndex". */
  portCounts(): Map<string, number> {
    const rows = this.db.prepare('SELECT dev_id AS d, if_index AS i, COUNT(DISTINCT mac) AS n FROM fdb WHERE last_seen >= ? GROUP BY dev_id, if_index').all(this.activeSince()) as unknown as { d: number; i: number; n: number }[];
    return new Map(rows.map(r => [`${r.d}/${r.i}`, r.n]));
  }

  /** The VLANs hosts were really seen in on each port lately (the MAC table is per VLAN), most hosts first. A port with 802.1X is in the VLAN the RADIUS server gave, which differs from the configured one. */
  operatingVlans(devId: number): Map<number, { vlan: number; hosts: number }[]> {
    const rows = this.db.prepare('SELECT if_index AS i, vlan AS v, COUNT(DISTINCT mac) AS n FROM fdb WHERE dev_id = ? AND last_seen >= ? GROUP BY if_index, vlan ORDER BY n DESC, vlan').all(devId, this.activeSince()) as unknown as { i: number; v: number; n: number }[];
    const out = new Map<number, { vlan: number; hosts: number }[]>();
    for (const r of rows) { const a = out.get(r.i) ?? []; a.push({ vlan: r.v, hosts: r.n }); out.set(r.i, a); }
    return out;
  }

  neighborsOf(devId: number, ifIndex: number): { proto: string; name: string; port: string; ip: string; kind: string; caps: string }[] {
    return this.db.prepare('SELECT proto, rem_name AS name, rem_port AS port, rem_ip AS ip, kind, caps FROM neighbors WHERE dev_id = ? AND if_index = ? ORDER BY proto').all(devId, ifIndex) as unknown as { proto: string; name: string; port: string; ip: string; kind: string; caps: string }[];
  }

  /** Every neighbour a device reports, on any port. */
  neighborsOfDevice(devId: number): { ifIndex: number; proto: string; name: string; port: string; ip: string; kind: string; caps: string }[] {
    return this.db.prepare('SELECT if_index AS ifIndex, proto, rem_name AS name, rem_port AS port, rem_ip AS ip, kind, caps FROM neighbors WHERE dev_id = ? ORDER BY if_index, proto').all(devId) as unknown as { ifIndex: number; proto: string; name: string; port: string; ip: string; kind: string; caps: string }[];
  }

  /** Hosts learned on one port, with the IP addresses their MACs have in any ARP table. */
  /** The ARP and IPv6 neighbour cache last read from one device (a router or firewall holds the addresses of everything on its networks). */
  arpOf(devId: number, limit = 2000): { ip: string; mac: string; ifIndex: number; lastSeen: number; vrf: string }[] {
    return (this.db.prepare('SELECT ip, mac, if_index AS ifIndex, MAX(last_seen) AS lastSeen, vrf FROM arp WHERE dev_id = ? GROUP BY ip, mac, if_index, vrf ORDER BY vrf, if_index, ip LIMIT ?').all(devId, limit) as unknown as { ip: string; mac: string; ifIndex: number; lastSeen: number; vrf: string }[]);
  }

  portHosts(devId: number, ifIndex: number, limit = 200): PortHost[] {
    const since = this.activeSince();
    const rows = this.db.prepare('SELECT mac, vlan, first_seen AS firstSeen, last_seen AS lastSeen, since FROM fdb WHERE dev_id = ? AND if_index = ? ORDER BY last_seen DESC, mac LIMIT ?').all(devId, ifIndex, limit) as unknown as { mac: string; vlan: number; firstSeen: number; lastSeen: number; since: number }[];
    const arp = this.db.prepare('SELECT ip FROM arp WHERE mac = ? ORDER BY last_seen DESC LIMIT 4');
    const wip = this.db.prepare('SELECT ip FROM wlan_client WHERE mac = ? AND ip != \'\' ORDER BY last_seen DESC LIMIT 1');
    const au = this.db.prepare("SELECT policy AS user, vlan, domain NOT IN ('unknown', '') AS authenticated FROM auth_sessions WHERE dev_id = ? AND mac = ? AND if_index = ?");
    return rows.map(r => {
      const ips = [...new Set((arp.all(r.mac) as unknown as { ip: string }[]).map(x => x.ip))];
      // an access point knows its clients' addresses even when no polled router has them in its ARP table
      if (!ips.length) { const w = wip.get(r.mac) as { ip: string } | undefined; if (w) ips.push(w.ip); }
      return { ...r, ips, active: r.lastSeen >= since, wifi: this.wifiFor(r.mac), auth: ((): PortHost['auth'] => { const a = au.get(devId, r.mac, ifIndex) as { user: string; vlan: number; authenticated: number } | undefined; return a ? { ...a, authenticated: !!a.authenticated } : null; })() };
    });
  }

  /** MAC addresses for an IP address, newest first, from the ARP tables of every polled router or Layer 3 switch. */
  macsForIp(ip: string): string[] {
    const rows = this.db.prepare('SELECT mac, MAX(last_seen) AS t FROM arp WHERE ip = ? GROUP BY mac ORDER BY t DESC LIMIT 3').all(ip) as unknown as { mac: string }[];
    return rows.map(r => r.mac);
  }

  /** IP addresses a MAC address has had, newest first. */
  ipsForMac(mac: string): string[] {
    return [...new Set((this.db.prepare('SELECT ip, MAX(last_seen) AS t FROM arp WHERE mac = ? GROUP BY ip ORDER BY t DESC LIMIT 6').all(mac) as unknown as { ip: string }[]).map(r => r.ip))];
  }

  private classify(row: { dev_id: number; if_index: number; vlan: number; last_seen: number; since: number; mac: string }, hasNeighborData: Set<number>, since: number): Attachment {
    const dev = this.devs.row(row.dev_id);
    const nb = this.neighborsOf(row.dev_id, row.if_index);
    const infra = nb.find(n => n.kind === 'infra') ?? null;
    const first = infra ?? nb[0] ?? null;
    const itf = this.db.prepare('SELECT port_mode AS mode, if_type AS type, name FROM interfaces WHERE dev_id = ? AND if_index = ?').get(row.dev_id, row.if_index) as { mode: string; type: number; name: string } | undefined;
    const count = (this.db.prepare('SELECT COUNT(DISTINCT mac) AS n FROM fdb WHERE dev_id = ? AND if_index = ? AND last_seen >= ?').get(row.dev_id, row.if_index, since) as unknown as { n: number }).n;
    const lag = itf?.type === 161 || LAG_NAME.test(itf?.name ?? '');
    let edge: boolean;
    if (infra) edge = false;                                                   // LLDP/CDP says another switch or router is on the other end
    else if (itf?.mode === 'svi' || itf?.mode === 'routed') edge = false;      // learned on a VLAN interface, not a physical port
    else if (lag) edge = count <= LAG_EDGE_MAX;
    else if (hasNeighborData.has(row.dev_id)) edge = !(itf?.mode === 'trunk' && count > UPLINK_MAC_COUNT);
    else edge = count <= UPLINK_MAC_COUNT;                                     // nothing says what is on the other end: judge by how many addresses the port has learned
    return {
      devId: row.dev_id, dev: dev?.name ?? `device ${row.dev_id}`, ifIndex: row.if_index, ifName: this.ifName(row.dev_id, row.if_index), vlan: row.vlan, macCount: count, edge,
      neighbor: first ? `${first.name}${first.port ? ' ' + first.port : ''}` : null, neighborKind: first?.kind ?? null, portMode: itf?.mode ?? '',
      lastSeen: row.last_seen, since: row.since, active: row.last_seen >= since, mac: row.mac
    };
  }

  /**
   * Finds the switch port a host is on. `q` is an IP address or a MAC address. When the IP address is not in any ARP table, a MAC
   * address seen in the flow records can be passed as `macHint` (lower confidence, because it may belong to a router).
   */
  locate(q: string, macHint?: string | null): HostLocation {
    const query = q.trim().toLowerCase();
    const isMac = /^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$/.test(query);
    const ip = isMac ? null : query;
    let macs: string[] = []; let source: HostLocation['macSource'] = 'none';
    if (isMac) { macs = [query.replace(/-/g, ':')]; source = 'given'; }
    else { macs = this.macsForIp(query); if (macs.length) source = 'arp'; }
    if (!macs.length && macHint) { macs = [macHint.toLowerCase()]; source = 'flow'; }
    if (!macs.length) {
      const arpDevs = (this.db.prepare('SELECT COUNT(DISTINCT dev_id) AS n FROM arp').get() as unknown as { n: number }).n;
      return { query: q, ip, macs, macSource: 'none', attach: null, others: [], note: arpDevs ? `No ARP entry for ${q} was found on any polled router or Layer 3 switch, so its MAC address is not known. It may be on a subnet whose gateway is not in the device list, or it has not sent anything recently.` : 'No ARP tables have been read yet. A router or Layer 3 switch in the device list must answer the ARP / IP-MIB tables so an IP address can be matched to a MAC address.' };
    }
    const since = this.activeSince();
    const hasNb = new Set((this.db.prepare('SELECT DISTINCT dev_id FROM neighbors').all() as unknown as { dev_id: number }[]).map(r => r.dev_id));
    const rows = macs.flatMap(m => this.db.prepare('SELECT dev_id, mac, vlan, if_index, last_seen, since FROM fdb WHERE mac = ? ORDER BY last_seen DESC').all(m) as unknown as { dev_id: number; mac: string; vlan: number; if_index: number; last_seen: number; since: number }[]);
    if (!rows.length) {
      const b0 = this.bindingFor(macs);
      if (b0) {
        const where = `${b0.dev} ${b0.ifName} (VLAN ${b0.vlan}, ${b0.ip}${b0.leaseSec ? ', lease ' + Math.round(b0.leaseSec / 3600) + ' h' : ''})`;
        return { query: q, ip, macs, macSource: source, attach: { ...this.bindingAttach(b0), confidence: 'medium' }, others: [], note: `Placed from a DHCP snooping binding on ${where}. The address is not in the MAC table of any polled switch now, so this is where its lease was granted, not proof that it is still plugged in.` };
      }
      const polled = (this.db.prepare('SELECT COUNT(DISTINCT dev_id) AS n FROM fdb').get() as unknown as { n: number }).n;
      return { query: q, ip, macs, macSource: source, attach: null, others: [], note: polled ? `${macs[0]} is not in the MAC table of any polled switch. The host may be quiet, or plugged into a switch that is not in the device list.` : 'No MAC address tables have been read yet. Add the access switches under SNMP devices and wait a few minutes.' };
    }
    const all = rows.map(r => this.classify(r, hasNb, since));
    const edges = all.filter(a => a.edge && a.active).sort((a, b) => a.macCount - b.macCount || b.lastSeen - a.lastSeen);
    const stale = all.filter(a => a.edge && !a.active).sort((a, b) => b.lastSeen - a.lastSeen);
    const uplinks = all.filter(a => !a.edge);
    let attach: HostLocation['attach'] = null; let note = '';
    const pick = edges[0] ?? stale[0] ?? null;
    if (pick) {
      let conf: 'high' | 'medium' | 'low' = edges.length > 1 ? 'low' : hasNb.has(pick.devId) ? 'high' : 'medium';
      if (source === 'flow' && conf === 'high') conf = 'medium';
      attach = { ...pick, confidence: conf };
      if (!pick.active) note = `Last seen on this port ${new Date(pick.lastSeen).toLocaleString()}; the address is no longer in the MAC table.`;
      else if (edges.length > 1) note = `The address is on a non-uplink port of ${edges.length} switches (${edges.map(e => e.dev).join(', ')}). The port with the fewest addresses is shown. Check that LLDP or CDP is enabled so uplinks can be told apart.`;
      else if (!hasNb.has(pick.devId)) note = 'This switch reports no LLDP/CDP neighbours, so the port was judged to be a host port because it has learned few addresses.';
      else if (pick.neighborKind === 'phone' || pick.neighborKind === 'ap') note = `Behind a ${pick.neighborKind === 'phone' ? 'phone' : 'wireless access point'} (${pick.neighbor}).`;
    } else if (uplinks.length) {
      const best = uplinks.slice().sort((a, b) => a.macCount - b.macCount)[0];
      note = `The address was only seen on ports that lead to other switches or routers (nearest: ${best.dev} ${best.ifName}). The switch the host is plugged into is probably not in the device list.`;
    }
    // every other place gets a confidence too, so the console can offer them: a port that leads to another switch, one that is no longer in the MAC table, and one of several host ports are all low
    const conf = (a: Attachment): 'high' | 'medium' | 'low' => (a.edge && a.active && edges.length === 1 ? (hasNb.has(a.devId) && source !== 'flow' ? 'high' : 'medium') : 'low');
    const others = all.filter(a => a !== (attach ? pick : null)).slice(0, 12).map(a => ({ ...a, confidence: conf(a) }));
    // A DHCP snooping binding names the access port the client's lease request arrived on. It is checked against the MAC tables rather than trusted
    // over them: a host that moved keeps its binding until the lease ends, so the MAC table (fresher) wins when the two disagree.
    const bind = this.bindingFor(macs);
    if (bind) {
      const where = `${bind.dev} ${bind.ifName} (VLAN ${bind.vlan}, ${bind.ip}${bind.leaseSec ? ', lease ' + Math.round(bind.leaseSec / 3600) + ' h' : ''})`;
      if (attach && attach.devId === bind.devId && attach.ifIndex === bind.ifIndex) { attach = { ...attach, confidence: source === 'flow' ? 'medium' : 'high' }; note = (note ? note + ' ' : '') + 'Confirmed by a DHCP snooping binding.'; }
      else if (attach) note = (note ? note + ' ' : '') + `DHCP snooping on ${where} saw its lease on a different port than the MAC tables show now. If the host was moved, the binding stays until the lease ends.`;
      else {
        const a = this.bindingAttach(bind);
        attach = { ...a, confidence: 'medium' };
        note = `Placed from a DHCP snooping binding on ${where}. The address is not in the MAC table of any polled switch now, so this is where its lease was granted, not proof that it is still plugged in.`;
      }
    }
    return { query: q, ip, macs, macSource: source, attach, others, note };
  }

  /** The newest DHCP snooping binding for any of these MAC addresses. */
  private bindingFor(macs: string[]): { devId: number; dev: string; ifIndex: number; ifName: string; vlan: number; ip: string; leaseSec: number | null; lastSeen: number; mac: string } | null {
    for (const m of macs) {
      const r = this.db.prepare('SELECT dev_id AS devId, mac, vlan, ip, if_index AS ifIndex, lease_sec AS leaseSec, last_seen AS lastSeen FROM dhcp_bindings WHERE mac = ? ORDER BY last_seen DESC LIMIT 1').get(m) as unknown as { devId: number; mac: string; vlan: number; ip: string; ifIndex: number; leaseSec: number | null; lastSeen: number } | undefined;
      if (r) return { ...r, dev: this.devs.row(r.devId)?.name ?? `device ${r.devId}`, ifName: this.ifName(r.devId, r.ifIndex) };
    }
    return null;
  }

  private bindingAttach(b: { devId: number; dev: string; ifIndex: number; ifName: string; vlan: number; lastSeen: number; mac: string }): Attachment {
    const nb = this.neighborsOf(b.devId, b.ifIndex)[0] ?? null;
    const itf = this.db.prepare('SELECT port_mode AS mode FROM interfaces WHERE dev_id = ? AND if_index = ?').get(b.devId, b.ifIndex) as { mode: string } | undefined;
    const count = (this.db.prepare('SELECT COUNT(DISTINCT mac) AS n FROM fdb WHERE dev_id = ? AND if_index = ? AND last_seen >= ?').get(b.devId, b.ifIndex, this.activeSince()) as unknown as { n: number }).n;
    return { devId: b.devId, dev: b.dev, ifIndex: b.ifIndex, ifName: b.ifName, vlan: b.vlan, macCount: count, edge: true, neighbor: nb ? `${nb.name}${nb.port ? ' ' + nb.port : ''}` : null, neighborKind: nb?.kind ?? null, portMode: itf?.mode ?? '', lastSeen: b.lastSeen, since: b.lastSeen, active: false, mac: b.mac };
  }
}
