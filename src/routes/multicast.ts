import type { App } from '../app.js';
import { HttpError } from '../server/http.js';
import type { FlowRecord } from '../collector/types.js';
import { int } from './util.js';
import { buildPlan, type Plan } from '../snmp/multicast_plan.js';

/** A multicast state older than this is shown as out of date */
const STALE_MS = 10 * 60_000;

/** The names of a device's interfaces, falling back to "if<number>". */
function namer(app: App, devId: number, mc?: { names?: Record<number, string> } | null): (ifIndex: number) => string {
  const m = new Map(app.devices.interfaces(devId).map(i => [i.ifIndex, i.name || i.descr] as const));
  return ix => m.get(ix) || app.devices.ifNameById(devId, ix) || mc?.names?.[ix] || `if${ix}`;
}

/** Where a multicast stream is expected to go, from the routers' own multicast state set beside what the exporters reported. */
export function multicastPlan(app: App, group: string, source: string, recs: FlowRecord[], firstSeen: number, lastSeen: number): Plan {
  const flows = new Map<number, { inIfs: number[]; outIfs: number[] }>();
  for (const r of recs) {
    const id = app.devices.deviceIdForExporter(r.exporter); if (id === null) continue;
    const e = flows.get(id) ?? { inIfs: [], outIfs: [] }; flows.set(id, e);
    if (r.inIf > 0 && !e.inIfs.includes(r.inIf)) e.inIfs.push(r.inIf);
    if (r.outIf > 0 && !e.outIfs.includes(r.outIf)) e.outIfs.push(r.outIf);
  }
  const devices = [];
  for (const d of app.devices.rows()) {
    const mc = app.devices.multicast(d.id); if (!mc) continue;
    devices.push({ devId: d.id, name: d.name, role: d.role ?? 'device', mc, ifName: namer(app, d.id, mc) });
  }
  return buildPlan({ group, source, firstSeen, lastSeen, now: Date.now(), devices, flows });
}

export function registerMulticast(app: App): void {
  const w = app.web;

  // Devices that publish multicast routing state, with the size of what was read.
  w.get('/api/multicast/devices', 'ro', c => {
    const now = Date.now();
    const list = [];
    for (const d of app.devices.rows()) {
      const m = app.devices.multicast(d.id); if (!m) continue;
      list.push({
        id: d.id, name: d.name, ip: d.ip, role: d.role ?? 'device', readAt: m.readAt, stale: now - m.readAt > STALE_MS, source: m.source,
        routes: m.routes.length, groups: new Set(m.routes.map(r => r.group)).size, receivers: m.receivers.length, forwarding: m.routes.filter(r => r.oifs.some(o => o.forwarding)).length, truncated: m.truncated
      });
    }
    c.json({ devices: list });
  });

  // One device's multicast routes with interface names, the hosts that joined each group, and PIM.
  w.get('/api/multicast/device', 'ro', c => {
    const id = int(c.query.get('id'), 0, 0, 1e9);
    const d = id ? app.devices.row(id) : null;
    if (!d) throw new HttpError(404, 'No such device');
    const m = app.devices.multicast(id);
    if (!m) throw new HttpError(404, 'This device has not published multicast routing state. It may not route multicast, or SNMP has not read it yet.');
    const name = namer(app, id, m);
    const ifs = new Map(app.devices.interfaces(id).map(i => [i.ifIndex, i.oper] as const)), downSet = new Set(m.down ?? []);
    const isDown = (ix: number): boolean => ifs.has(ix) ? ifs.get(ix) !== 1 : downSet.has(ix);
    const nbr = new Map(m.neighbors.map(n => [n.ifIndex, n.address]));
    const joins = new Map<string, typeof m.receivers>();
    for (const r of m.receivers) { const k = r.group + '|' + r.ifIndex; const a = joins.get(k) ?? []; a.push(r); joins.set(k, a); }
    const now = Date.now();
    // Where the hosts named in this device's state are plugged in. IGMP reports the VLAN interface and the last host that reported, not the switch port,
    // so a reporter or a source is looked up in host tracking (ARP, MAC tables, DHCP snooping).
    const ips = new Set<string>();
    for (const r of m.routes) if (r.source !== '0.0.0.0') ips.add(r.source);
    for (const r of m.receivers) if (r.lastReporter && !r.self) ips.add(r.lastReporter);
    const hosts: Record<string, { dev: string; port: string; vlan: number; confidence: string; neighbor: string | null } | null> = {};
    for (const ip of [...ips].slice(0, 800)) {
      const a = app.hosts.locate(ip).attach;
      hosts[ip] = a && a.edge ? { dev: a.dev, port: a.ifName, vlan: a.vlan, confidence: a.confidence, neighbor: a.neighbor } : null;
    }
    c.json({
      device: { id: d.id, name: d.name, ip: d.ip, role: d.role ?? 'device' }, readAt: m.readAt, stale: now - m.readAt > STALE_MS, source: m.source, truncated: m.truncated,
      routes: m.routes.map(r => ({
        group: r.group, source: r.source, sharedTree: r.source === '0.0.0.0', inIf: r.inIfIndex ? name(r.inIfIndex) : null, upstream: r.upstream, rp: r.rp, bps: r.bps, pkts: r.pkts, flags: r.flags, protocol: r.protocol, expirySec: r.expirySec,
        out: r.oifs.map(o => ({
          ifIndex: o.ifIndex, name: name(o.ifIndex), forwarding: o.forwarding, linkDown: isDown(o.ifIndex), loopback: /^(lo|loopback)\d+$/i.test(name(o.ifIndex)), pkts: o.pkts, neighbor: nbr.get(o.ifIndex) ?? null,
          joins: (joins.get(r.group + '|' + o.ifIndex) ?? []).map(j => ({ reporter: j.lastReporter, expirySec: j.expirySec, self: j.self }))
        }))
      })),
      hosts,
      load: (m.interfaces ?? []).filter(i => (i.inOctets ?? 0) > 0 || (i.outOctets ?? 0) > 0).map(i => ({ name: name(i.ifIndex), inBps: i.inBps, outBps: i.outBps, inOctets: i.inOctets, outOctets: i.outOctets, ttl: i.ttl, rateLimit: i.rateLimit }))
        .sort((a, b) => (b.inBps ?? 0) + (b.outBps ?? 0) - (a.inBps ?? 0) - (a.outBps ?? 0) || (b.inOctets ?? 0) + (b.outOctets ?? 0) - (a.inOctets ?? 0) - (a.outOctets ?? 0)),
      pim: { interfaces: m.pimInterfaces.map(p => ({ name: name(p.ifIndex), mode: p.mode, dr: p.dr })), neighbors: m.neighbors.map(n => ({ address: n.address, ifName: name(n.ifIndex) })) }
    });
  });
}
