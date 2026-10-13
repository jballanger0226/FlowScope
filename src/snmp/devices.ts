import net from 'node:net';
import type { ConfigDb } from '../db/configdb.js';
import type { CredentialStore } from './creds.js';
import { SnmpClient, type SnmpTarget } from './client.js';
import { guessDscps, probe, type Probe } from './collect.js';
import type { TsStore } from '../store/types.js';
import type { AppLog } from '../logger.js';

export class DeviceError extends Error { constructor(m: string, readonly status = 400) { super(m); } }

export interface DeviceRow {
  id: number; name: string; ip: string; port: number; cred_id: number; interval_sec: number; polling: number; src: string; added_at: number;
  sys_name: string | null; sys_descr: string | null; sys_object_id: string | null; role: string | null; profile: string | null;
  last_poll: number | null; last_ok: number | null; last_error: string | null;
}
export interface DeviceView {
  id: number; name: string; ip: string; port: number; credId: number; credName: string; intervalSec: number; polling: boolean; source: string; addedAt: number;
  sysName: string; sysDescr: string; role: string; profile: string; lastPoll: number | null; lastOk: number | null; lastError: string | null;
  status: 'ok' | 'error' | 'paused' | 'pending'; interfaces: number; policies: number; classes: number; addresses: string[];
}
export interface InterfaceView {
  devId: number; ifIndex: number; name: string; descr: string; alias: string; speedMbps: number; oper: number; policy: string | null; direction: string | null;
  classes: { cls: string; queue: string | null; dscps: number[]; bw: string | null }[];
}

export function guessRole(descr: string, name: string): string {
  const t = (descr + ' ' + name).toLowerCase();
  if (/firewall|\basa\b|fortigate|pan-os|palo alto|checkpoint|sonicwall|srx/.test(t) || /(^|[-_])(fw|firewall)([-_]|\d|$)/.test(name.toLowerCase())) return 'firewall';
  if (/switch|catalyst|nexus|\bex\d|aruba|procurve|ruckus|(^|[-_])(sw|sw\d|access|dist)([-_]|\d|$)/.test(t)) return 'switch';
  if (/router|\bios\b|ios-xe|junos|mx\d|asr|isr|vyos|mikrotik|(^|[-_])(rtr|gw|edge|core)([-_]|\d|$)/.test(t)) return 'router';
  return 'device';
}

export function parseTargets(spec: string, max = 4096): string[] {
  const out = new Set<string>();
  const toN = (ip: string) => { const p = ip.split('.').map(Number); return ((p[0] * 256 + p[1]) * 256 + p[2]) * 256 + p[3]; };
  const toIp = (n: number) => [Math.floor(n / 16777216) % 256, Math.floor(n / 65536) % 256, Math.floor(n / 256) % 256, n % 256].join('.');
  for (const part of spec.split(/[\s,;]+/).filter(Boolean)) {
    let m: RegExpExecArray | null;
    if ((m = /^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/.exec(part))) {
      if (net.isIPv4(m[1]) === false) throw new DeviceError(`"${part}" is not a valid prefix`);
      const bits = Number(m[2]);
      if (bits < 12 || bits > 32) throw new DeviceError(`"${part}": use a prefix between /12 and /32 (up to ${max} addresses)`);
      const size = 2 ** (32 - bits); const base = Math.floor(toN(m[1]) / size) * size;
      if (size > max) throw new DeviceError(`"${part}" has ${size} addresses. The limit is ${max} per search.`);
      const lo = size > 2 ? base + 1 : base, hi = size > 2 ? base + size - 2 : base + size - 1;
      for (let n = lo; n <= hi; n++) out.add(toIp(n));
    } else if ((m = /^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$/.exec(part)) || (m = /^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$/.exec(part))) {
      let a: string, b: string;
      if (m[3] !== undefined) { a = m[1] + m[2]; b = m[1] + m[3]; } else { a = m[1]; b = m[2]; }
      if (!net.isIPv4(a) || !net.isIPv4(b)) throw new DeviceError(`"${part}" is not a valid range`);
      const lo = toN(a), hi = toN(b);
      if (hi < lo) throw new DeviceError(`"${part}": the range ends before it starts`);
      if (hi - lo + 1 > max) throw new DeviceError(`"${part}" has ${hi - lo + 1} addresses. The limit is ${max} per search.`);
      for (let n = lo; n <= hi; n++) out.add(toIp(n));
    } else if (net.isIP(part)) {
      out.add(part);
    } else throw new DeviceError(`"${part}" is not an address, range (10.0.0.1-10.0.0.50) or prefix (10.0.0.0/24)`);
    if (out.size > max) throw new DeviceError(`More than ${max} addresses. Narrow the search.`);
  }
  if (!out.size) throw new DeviceError('Enter an address, a range or a prefix');
  return [...out];
}

/** The SNMP device inventory: devices, their interfaces and QoS classes. Also resolves exporter IPs to device names. */
export class DeviceService {
  private lookup: { at: number; ipToDev: Map<string, number>; names: Map<number, string>; roles: Map<number, string>; ifNames: Map<string, string>; policies: Map<string, string> } | null = null;

  constructor(private cdb: ConfigDb, private creds: CredentialStore, private store: Pick<TsStore, 'deleteDevice'>, private log: AppLog, private timeoutMs = 3000) {}

  invalidate(): void { this.lookup = null; }

  private target(d: Pick<DeviceRow, 'ip' | 'port'>): SnmpTarget { return { host: d.ip, port: d.port, timeoutMs: this.timeoutMs, retries: 1 }; }

  /** Opens a session to a stored device. */
  open(d: DeviceRow): SnmpClient { return new SnmpClient(this.target(d), this.creds.resolve(d.cred_id)); }

  row(id: number): DeviceRow | undefined { return this.cdb.db.prepare('SELECT * FROM devices WHERE id = ?').get(id) as unknown as DeviceRow | undefined; }
  rows(): DeviceRow[] { return this.cdb.db.prepare('SELECT * FROM devices ORDER BY name').all() as unknown as DeviceRow[]; }

  list(): DeviceView[] {
    const creds = new Map(this.creds.list().map(c => [c.id, c.name]));
    const ifc = new Map((this.cdb.db.prepare('SELECT dev_id, COUNT(*) AS n, COUNT(DISTINCT policy) AS p FROM interfaces GROUP BY dev_id').all() as unknown as { dev_id: number; n: number; p: number }[]).map(r => [r.dev_id, r]));
    const cls = new Map((this.cdb.db.prepare('SELECT dev_id, COUNT(*) AS n FROM class_defs GROUP BY dev_id').all() as unknown as { dev_id: number; n: number }[]).map(r => [r.dev_id, r.n]));
    const addr = new Map<number, string[]>();
    for (const r of this.cdb.db.prepare('SELECT dev_id, ip FROM device_ips ORDER BY ip').all() as unknown as { dev_id: number; ip: string }[]) { const a = addr.get(r.dev_id); if (a) a.push(r.ip); else addr.set(r.dev_id, [r.ip]); }
    return this.rows().map(d => ({
      id: d.id, name: d.name, ip: d.ip, port: d.port, credId: d.cred_id, credName: creds.get(d.cred_id) ?? '(missing)', intervalSec: d.interval_sec, polling: d.polling === 1,
      source: d.src, addedAt: d.added_at, sysName: d.sys_name ?? '', sysDescr: d.sys_descr ?? '', role: d.role ?? 'device', profile: d.profile ?? 'generic',
      lastPoll: d.last_poll, lastOk: d.last_ok, lastError: d.last_error,
      status: d.polling !== 1 ? 'paused' : d.last_poll === null ? 'pending' : d.last_error ? 'error' : 'ok',
      interfaces: ifc.get(d.id)?.n ?? 0, policies: ifc.get(d.id)?.p ?? 0, classes: cls.get(d.id) ?? 0, addresses: addr.get(d.id) ?? []
    }));
  }

  interfaces(devId: number): InterfaceView[] {
    const ifs = this.cdb.db.prepare('SELECT * FROM interfaces WHERE dev_id = ? ORDER BY if_index').all(devId) as unknown as { dev_id: number; if_index: number; name: string; descr: string | null; alias: string | null; speed_mbps: number; oper_status: number; policy: string | null }[];
    const cls = this.cdb.db.prepare('SELECT * FROM class_defs WHERE dev_id = ? ORDER BY if_index, rowid').all(devId) as unknown as { if_index: number; cls: string; queue: string | null; dscps: string; bw: string | null }[];
    return ifs.map(i => ({
      devId, ifIndex: i.if_index, name: i.name, descr: i.descr ?? '', alias: i.alias ?? '', speedMbps: i.speed_mbps, oper: i.oper_status, policy: i.policy, direction: i.policy ? 'output' : null,
      classes: cls.filter(c => c.if_index === i.if_index).map(c => ({ cls: c.cls, queue: c.queue, dscps: JSON.parse(c.dscps) as number[], bw: c.bw }))
    }));
  }

  /** Applies a probe result: interfaces, addresses, VLAN names and QoS classes. Admin edits to class DSCP lists are kept. */
  private apply(id: number, p: Probe): void {
    this.cdb.tx(() => {
      const db = this.cdb.db;
      const seen = new Set<number>();
      const polByIf = new Map<number, { name: string }>();
      for (const q of p.qos) if (q.direction === 'output') polByIf.set(q.ifIndex, { name: q.policyName });
      for (const i of p.ifaces) {
        seen.add(i.index);
        db.prepare(`INSERT INTO interfaces(dev_id, if_index, name, descr, alias, speed_mbps, oper_status, policy) VALUES (?,?,?,?,?,?,?,?)
          ON CONFLICT(dev_id, if_index) DO UPDATE SET name=excluded.name, descr=excluded.descr, alias=excluded.alias, speed_mbps=excluded.speed_mbps, oper_status=excluded.oper_status, policy=excluded.policy`)
          .run(id, i.index, i.name, i.descr, i.alias, i.speedMbps, i.oper, polByIf.get(i.index)?.name ?? null);
      }
      for (const r of db.prepare('SELECT if_index FROM interfaces WHERE dev_id = ?').all(id) as unknown as { if_index: number }[]) {
        if (!seen.has(r.if_index)) { db.prepare('DELETE FROM interfaces WHERE dev_id = ? AND if_index = ?').run(id, r.if_index); db.prepare('DELETE FROM class_defs WHERE dev_id = ? AND if_index = ?').run(id, r.if_index); }
      }
      db.prepare('DELETE FROM device_ips WHERE dev_id = ?').run(id);
      for (const a of p.ips) db.prepare('INSERT OR REPLACE INTO device_ips(dev_id, ip, if_index) VALUES (?,?,?)').run(id, a.ip, a.ifIndex);
      const keep = new Set<string>();
      for (const q of p.qos) {
        if (q.direction !== 'output') continue;
        for (const c of q.classes) {
          const key = `${q.ifIndex}/${c.name}`; keep.add(key);
          const label = c.parentName && c.parentName !== 'class-default' ? `${c.parentName}/${c.name}` : c.name;
          void label;
          db.prepare(`INSERT INTO class_defs(dev_id, if_index, cls, queue, dscps, bw) VALUES (?,?,?,?,?,?)
            ON CONFLICT(dev_id, if_index, cls) DO UPDATE SET queue=excluded.queue, bw=excluded.bw`)
            .run(id, q.ifIndex, c.name, null, JSON.stringify(guessDscps(c.name)), c.bandwidth);
        }
      }
      for (const r of db.prepare('SELECT if_index, cls FROM class_defs WHERE dev_id = ?').all(id) as unknown as { if_index: number; cls: string }[]) {
        if (!keep.has(`${r.if_index}/${r.cls}`)) db.prepare('DELETE FROM class_defs WHERE dev_id = ? AND if_index = ? AND cls = ?').run(id, r.if_index, r.cls);
      }
      for (const v of p.vlans) {
        const ex = db.prepare('SELECT source FROM vlans WHERE id = ?').get(v.id) as { source: string } | undefined;
        if (!ex) db.prepare("INSERT INTO vlans(id, name, source) VALUES (?,?,'snmp')").run(v.id, v.name);
        else if (ex.source === 'snmp') db.prepare('UPDATE vlans SET name = ? WHERE id = ?').run(v.name, v.id);
      }
      db.prepare('UPDATE devices SET sys_name=?, sys_descr=?, sys_object_id=?, role=?, profile=? WHERE id=?')
        .run(p.info.sysName, p.info.sysDescr, p.info.sysObjectId, guessRole(p.info.sysDescr, p.info.sysName), p.profile, id);
    });
    this.invalidate();
  }

  /** Contacts a device with the given credential set and returns what it reports. Nothing is stored. */
  async test(ip: string, port: number, credId: number): Promise<Probe> {
    if (!net.isIP(ip)) throw new DeviceError('Enter an IP address');
    const c = new SnmpClient({ host: ip, port, timeoutMs: this.timeoutMs, retries: 1 }, this.creds.resolve(credId));
    try { return await probe(c); } catch (e) { throw new DeviceError((e as Error).message); } finally { c.close(); }
  }

  async add(o: { ip: string; name?: string; port?: number; credId?: number; intervalSec?: number; source?: string; probed?: Probe }): Promise<DeviceView> {
    const ip = o.ip.trim();
    if (!net.isIP(ip)) throw new DeviceError('Enter an IPv4 or IPv6 address');
    if (this.cdb.db.prepare('SELECT 1 FROM devices WHERE ip = ?').get(ip)) throw new DeviceError(`${ip} is already in the device list`, 409);
    const port = o.port ?? 161;
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new DeviceError('Port must be between 1 and 65535');
    const interval = o.intervalSec ?? 60;
    if (!Number.isInteger(interval) || interval < 10 || interval > 3600) throw new DeviceError('Polling interval must be between 10 and 3600 seconds');
    const credId = o.credId ?? this.creds.defaultId();
    if (credId === null || credId === undefined) throw new DeviceError('Create a credential set first, then add devices');
    const p = o.probed ?? await this.test(ip, port, credId);
    let name = (o.name || p.info.sysName || ip).trim().slice(0, 64);
    if (this.cdb.db.prepare('SELECT 1 FROM devices WHERE name = ?').get(name)) {
      if (o.name) throw new DeviceError(`A device named "${name}" already exists`, 409);
      name = `${name} (${ip})`;
    }
    const r = this.cdb.db.prepare('INSERT INTO devices(name, ip, port, cred_id, interval_sec, polling, src, added_at) VALUES (?,?,?,?,?,1,?,?)')
      .run(name, ip, port, credId, interval, o.source || 'Added by hand', Date.now());
    const id = Number(r.lastInsertRowid);
    this.apply(id, p);
    this.log.info('snmp', `Added device ${name} (${ip}): ${p.ifaces.length} interfaces, ${p.qos.reduce((a, q) => a + q.classes.length, 0)} QoS classes`);
    return this.list().find(d => d.id === id)!;
  }

  async rediscover(id: number): Promise<DeviceView> {
    const d = this.row(id);
    if (!d) throw new DeviceError('No such device', 404);
    const c = this.open(d);
    try { this.apply(id, await probe(c)); } catch (e) { throw new DeviceError((e as Error).message); } finally { c.close(); }
    return this.list().find(x => x.id === id)!;
  }

  update(id: number, patch: { name?: string; credId?: number; intervalSec?: number; port?: number }): DeviceView {
    const d = this.row(id);
    if (!d) throw new DeviceError('No such device', 404);
    const name = patch.name?.trim() ?? d.name;
    if (!name) throw new DeviceError('The name cannot be empty');
    if (name !== d.name && this.cdb.db.prepare('SELECT 1 FROM devices WHERE name = ? AND id != ?').get(name, id)) throw new DeviceError(`A device named "${name}" already exists`, 409);
    const interval = patch.intervalSec ?? d.interval_sec;
    if (!Number.isInteger(interval) || interval < 10 || interval > 3600) throw new DeviceError('Polling interval must be between 10 and 3600 seconds');
    const credId = patch.credId ?? d.cred_id;
    if (!this.cdb.db.prepare('SELECT 1 FROM snmp_credentials WHERE id = ?').get(credId)) throw new DeviceError('No such credential set');
    this.cdb.db.prepare('UPDATE devices SET name=?, cred_id=?, interval_sec=?, port=? WHERE id=?').run(name, credId, interval, patch.port ?? d.port, id);
    this.invalidate();
    return this.list().find(x => x.id === id)!;
  }

  setPolling(id: number, on: boolean): void {
    if (!this.row(id)) throw new DeviceError('No such device', 404);
    this.cdb.db.prepare('UPDATE devices SET polling = ? WHERE id = ?').run(on ? 1 : 0, id);
  }

  setClassDscps(id: number, ifIndex: number, cls: string, dscps: number[]): void {
    if (dscps.some(d => !Number.isInteger(d) || d < 0 || d > 63)) throw new DeviceError('DSCP values are 0 to 63');
    const r = this.cdb.db.prepare('UPDATE class_defs SET dscps = ? WHERE dev_id = ? AND if_index = ? AND cls = ?').run(JSON.stringify([...new Set(dscps)].sort((a, b) => a - b)), id, ifIndex, cls);
    if (!Number(r.changes)) throw new DeviceError('No such class', 404);
  }

  async remove(id: number): Promise<void> {
    const d = this.row(id);
    if (!d) throw new DeviceError('No such device', 404);
    this.cdb.tx(() => {
      for (const t of ['interfaces', 'class_defs', 'device_ips']) this.cdb.db.prepare(`DELETE FROM ${t} WHERE dev_id = ?`).run(id);
      this.cdb.db.prepare('UPDATE exporters SET device_id = NULL WHERE device_id = ?').run(id);
      this.cdb.db.prepare('DELETE FROM devices WHERE id = ?').run(id);
    });
    await this.store.deleteDevice(id);
    this.invalidate();
    this.log.info('snmp', `Removed device ${d.name} (${d.ip}) and its stored SNMP history`);
  }

  recordPoll(id: number, ok: boolean, error: string | null): void {
    const now = Date.now();
    this.cdb.db.prepare('UPDATE devices SET last_poll = ?, last_ok = CASE WHEN ? THEN ? ELSE last_ok END, last_error = ? WHERE id = ?').run(now, ok ? 1 : 0, now, error, id);
  }

  /* ---- names for the flow views ---- */

  private build() {
    if (this.lookup && Date.now() - this.lookup.at < 30_000) return this.lookup;
    const ipToDev = new Map<string, number>(); const names = new Map<number, string>(); const roles = new Map<number, string>();
    const ifNames = new Map<string, string>(); const policies = new Map<string, string>();
    for (const d of this.rows()) { names.set(d.id, d.name); roles.set(d.id, d.role ?? 'device'); ipToDev.set(d.ip, d.id); }
    for (const r of this.cdb.db.prepare('SELECT dev_id, ip FROM device_ips').all() as unknown as { dev_id: number; ip: string }[]) if (!ipToDev.has(r.ip)) ipToDev.set(r.ip, r.dev_id);
    for (const r of this.cdb.db.prepare('SELECT dev_id, if_index, name, policy FROM interfaces').all() as unknown as { dev_id: number; if_index: number; name: string; policy: string | null }[]) {
      ifNames.set(`${r.dev_id}/${r.if_index}`, r.name); if (r.policy) policies.set(`${r.dev_id}/${r.if_index}`, r.policy);
    }
    this.lookup = { at: Date.now(), ipToDev, names, roles, ifNames, policies };
    return this.lookup;
  }

  deviceIdForExporter(ip: string): number | null { return this.build().ipToDev.get(ip) ?? null; }
  deviceName(exporterIp: string): string { const l = this.build(); const id = l.ipToDev.get(exporterIp); return id === undefined ? exporterIp : l.names.get(id) ?? exporterIp; }
  deviceRole(exporterIp: string): string { const l = this.build(); const id = l.ipToDev.get(exporterIp); return id === undefined ? 'device' : l.roles.get(id) ?? 'device'; }
  ifName(exporterIp: string, ifIndex: number): string {
    const l = this.build(); const id = l.ipToDev.get(exporterIp);
    return (id !== undefined && l.ifNames.get(`${id}/${ifIndex}`)) || (ifIndex ? `if${ifIndex}` : '—');
  }
  policyOf(exporterIp: string, ifIndex: number): string | null { const l = this.build(); const id = l.ipToDev.get(exporterIp); return id === undefined ? null : l.policies.get(`${id}/${ifIndex}`) ?? null; }

  /** Exporter addresses of devices whose name or address contains the text. Exporter IPs that are not in the device list match on the address. */
  exporterIpsByName(text: string, knownExporters: Iterable<string> = []): string[] {
    const t = text.toLowerCase();
    const l = this.build();
    const out = new Set<string>();
    const ids = new Set<number>();
    for (const [id, name] of l.names) if (name.toLowerCase().includes(t)) ids.add(id);
    for (const [ip, id] of l.ipToDev) { if (ids.has(id) || ip.startsWith(t)) out.add(ip); }
    for (const ip of knownExporters) if (ip.startsWith(t) || ip === t) out.add(ip);
    return [...out];
  }
}
