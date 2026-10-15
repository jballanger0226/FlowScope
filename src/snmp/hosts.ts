import type { ConfigDb } from '../db/configdb.js';
import type { AppLog } from '../logger.js';
import type { DeviceRow, DeviceService } from './devices.js';
import type { SnmpClient } from './client.js';
import { readArp, readFdb, readNeighbors, readPortVlans, type Neighbor } from './ports.js';

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
export interface PortHost { mac: string; vlan: number; ips: string[]; firstSeen: number; lastSeen: number; since: number; active: boolean }

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
  async refresh(d: DeviceRow, c: SnmpClient): Promise<{ macs: number; arp: number; neighbors: number; note: string }> {
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
    const arp = await readArp(c).catch(e => { notes.push(`ARP not read: ${(e as Error).message}`); return []; });

    const cisco = (d.sys_object_id ?? '').startsWith('1.3.6.1.4.1.9.');
    const vlans = new Set<number>();
    for (const p of ports.values()) { if (p.mode === 'access' || p.mode === 'pvid') { if (p.vlan) vlans.add(p.vlan); if (p.voice) vlans.add(p.voice); } else if (p.mode === 'trunk' && p.vlan) vlans.add(p.vlan); }
    if (!vlans.size) vlans.add(1);
    let fdb: Awaited<ReturnType<typeof readFdb>>;
    try { fdb = await readFdb(c, { cisco, vlans: [...vlans], forVlan: v => c.forVlan(v) }); }
    catch (e) { fdb = { entries: [], method: 'none', vlansTried: 0, vlansFailed: 0 }; notes.push(`MAC table not read: ${(e as Error).message}`); }
    if (fdb.vlansFailed) notes.push(`${fdb.vlansFailed} of ${fdb.vlansTried + fdb.vlansFailed} VLANs could not be read through the VLAN community${fdb.vlansTried === 0 ? ' (the device does not accept VLAN-indexed access; for SNMPv3 the context vlan-N must be allowed)' : ''}`);

    this.cdb.tx(() => {
      const up = this.db.prepare(`INSERT INTO fdb(dev_id, mac, vlan, if_index, first_seen, last_seen, since) VALUES (?,?,?,?,?,?,?)
        ON CONFLICT(dev_id, mac, vlan) DO UPDATE SET last_seen = excluded.last_seen, since = CASE WHEN fdb.if_index = excluded.if_index THEN fdb.since ELSE excluded.since END, if_index = excluded.if_index`);
      for (const e of fdb.entries) up.run(d.id, e.mac, e.vlan, e.ifIndex, now, now, now);
      const ua = this.db.prepare(`INSERT INTO arp(dev_id, ip, mac, if_index, last_seen) VALUES (?,?,?,?,?)
        ON CONFLICT(dev_id, ip, mac) DO UPDATE SET last_seen = excluded.last_seen, if_index = excluded.if_index`);
      for (const a of arp) { ua.run(d.id, a.ip, a.mac, a.ifIndex, now); arpRows++; }
      this.db.prepare('DELETE FROM neighbors WHERE dev_id = ?').run(d.id);
      const un = this.db.prepare('INSERT OR REPLACE INTO neighbors(dev_id, if_index, proto, rem_key, rem_name, rem_port, rem_ip, kind, caps, seen_at) VALUES (?,?,?,?,?,?,?,?,?,?)');
      for (const n of nbs) un.run(d.id, n.ifIndex, n.proto, n.key, n.name, n.port, n.ip, n.kind, n.caps.join(','), now);
      const parts = [`${fdb.entries.length} MAC addresses (${fdb.method})`, `${arpRows} ARP entries`, `${nbs.length} neighbours`, ...notes];
      this.db.prepare('UPDATE devices SET hosts_at = ?, hosts_note = ? WHERE id = ?').run(now, parts.join('; '), d.id);
    });
    return { macs: fdb.entries.length, arp: arpRows, neighbors: nbs.length, note: notes.join('; ') };
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
  }

  /* ---------------------------------------------------------------- queries */

  private ifName(devId: number, ifIndex: number): string {
    const r = this.db.prepare('SELECT name FROM interfaces WHERE dev_id = ? AND if_index = ?').get(devId, ifIndex) as { name: string } | undefined;
    return r?.name ?? `if${ifIndex}`;
  }

  /** Number of addresses currently learned on every port, keyed "device/ifIndex". */
  portCounts(): Map<string, number> {
    const rows = this.db.prepare('SELECT dev_id AS d, if_index AS i, COUNT(DISTINCT mac) AS n FROM fdb WHERE last_seen >= ? GROUP BY dev_id, if_index').all(this.activeSince()) as unknown as { d: number; i: number; n: number }[];
    return new Map(rows.map(r => [`${r.d}/${r.i}`, r.n]));
  }

  neighborsOf(devId: number, ifIndex: number): { proto: string; name: string; port: string; ip: string; kind: string; caps: string }[] {
    return this.db.prepare('SELECT proto, rem_name AS name, rem_port AS port, rem_ip AS ip, kind, caps FROM neighbors WHERE dev_id = ? AND if_index = ? ORDER BY proto').all(devId, ifIndex) as unknown as { proto: string; name: string; port: string; ip: string; kind: string; caps: string }[];
  }

  /** Every neighbour a device reports, on any port. */
  neighborsOfDevice(devId: number): { ifIndex: number; proto: string; name: string; port: string; ip: string; kind: string; caps: string }[] {
    return this.db.prepare('SELECT if_index AS ifIndex, proto, rem_name AS name, rem_port AS port, rem_ip AS ip, kind, caps FROM neighbors WHERE dev_id = ? ORDER BY if_index, proto').all(devId) as unknown as { ifIndex: number; proto: string; name: string; port: string; ip: string; kind: string; caps: string }[];
  }

  /** Hosts learned on one port, with the IP addresses their MACs have in any ARP table. */
  portHosts(devId: number, ifIndex: number, limit = 200): PortHost[] {
    const since = this.activeSince();
    const rows = this.db.prepare('SELECT mac, vlan, first_seen AS firstSeen, last_seen AS lastSeen, since FROM fdb WHERE dev_id = ? AND if_index = ? ORDER BY last_seen DESC, mac LIMIT ?').all(devId, ifIndex, limit) as unknown as { mac: string; vlan: number; firstSeen: number; lastSeen: number; since: number }[];
    const arp = this.db.prepare('SELECT ip FROM arp WHERE mac = ? ORDER BY last_seen DESC LIMIT 4');
    return rows.map(r => ({ ...r, ips: [...new Set((arp.all(r.mac) as unknown as { ip: string }[]).map(x => x.ip))], active: r.lastSeen >= since }));
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
    return { query: q, ip, macs, macSource: source, attach, others, note };
  }
}
