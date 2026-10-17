import type { Multicast } from '../snmp/multicast.js';
import { lookupFib, type Fib } from '../snmp/fib.js';
import { rpfSignificant } from '../snmp/multicast.js';
import { multicastLoss, pimIssues, type PimPeer } from '../snmp/pimcheck.js';
import type { App } from '../app.js';
import { HttpError } from '../server/http.js';
import type { FlowRecord } from '../collector/types.js';
import { int } from './util.js';
import { modelText, type Entity } from '../snmp/entity.js';
import { igmpHint, vendorOf } from '../snmp/diagnose.js';
import { igmpFromFlows } from '../snmp/igmp_flows.js';
import { buildPlan, type Plan } from '../snmp/multicast_plan.js';
import { underlayMap } from '../snmp/underlay.js';

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

const RT_PROTO: Record<number, string> = { 2: 'connected', 3: 'static', 8: 'RIP', 9: 'IS-IS', 13: 'OSPF', 14: 'BGP', 16: 'EIGRP', 17: 'DVMRP' };
/** 255.255.255.0 as 24; an irregular mask is left as it is. */
function maskLen(mask: string): string {
  const n = mask.split('.').reduce((a, o) => a * 256 + Number(o), 0); let len = 0, x = n;
  while (len < 32 && x >= 2 ** 31) { len++; x = (x * 2) % 2 ** 32; }
  return x === 0 ? String(len) : mask;
}

export function registerMulticast(app: App): void {
  const w = app.web;

  // Devices that publish multicast routing state, with the size of what was read.
  w.get('/api/multicast/devices', 'ro', c => {
    const now = Date.now();
    const list = [];
    for (const d of app.devices.rows()) {
      const m = app.devices.multicast(d.id);
      const vrfs = app.devices.vrfs(d.id).map(v => ({ v, x: app.devices.vrfMulticast(d.id, v.name) })).filter((e): e is { v: typeof e.v; x: Multicast } => !!e.x)
        .map(({ v, x }) => ({ name: v.name, readAt: x.readAt, routes: x.routes.length, groups: new Set(x.routes.map(r => r.group)).size, forwarding: x.routes.filter(r => r.oifs.some(o => o.forwarding)).length }));
      if (!m && !vrfs.length) continue;
      list.push({
        id: d.id, name: d.name, ip: d.ip, role: d.role ?? 'device', readAt: m?.readAt ?? vrfs[0]!.readAt, stale: now - (m?.readAt ?? vrfs[0]!.readAt) > STALE_MS, source: m?.source ?? 'cisco',
        routes: m?.routes.length ?? 0, groups: m ? new Set(m.routes.map(r => r.group)).size : 0, receivers: m?.receivers.length ?? 0, forwarding: m ? m.routes.filter(r => r.oifs.some(o => o.forwarding)).length : 0, truncated: m?.truncated ?? false, vrfs
      });
    }
    c.json({ devices: list });
  });

  // One device's multicast routes with interface names, the hosts that joined each group, and PIM.
  w.get('/api/multicast/device', 'ro', async c => {
    const id = int(c.query.get('id'), 0, 0, 1e9);
    const d = id ? app.devices.row(id) : null;
    if (!d) throw new HttpError(404, 'No such device');
    const vrf = c.query.get('vrf') ?? '';
    if (vrf && !app.devices.vrfs(id).some(v => v.name === vrf)) throw new HttpError(404, 'This device has no such VRF');
    const m = vrf ? app.devices.vrfMulticast(id, vrf) : app.devices.multicast(id);
    if (!m) throw new HttpError(404, vrf ? `No multicast state has been read in VRF ${vrf}. Its SNMP context (vrf-${vrf}) may not be set up, or SNMP has not read it yet.` : 'This device has not published multicast routing state. It may not route multicast, or SNMP has not read it yet.');
    const name = namer(app, id, m);
    // SD-Access: which underlay group carries each overlay group, from what the VRFs state, and the reverse
    const vrfData = app.devices.vrfs(id).map(v => ({ name: v.name, mc: app.devices.vrfMulticast(id, v.name) })).filter((e): e is { name: string; mc: Multicast } => !!e.mc);
    const under = underlayMap(vrfData);
    const dflt = vrf ? app.devices.multicast(id) : m;
    const underInfo = (g: string): { group: string; sources: { source: string; pkts: number | null }[] } => ({ group: g, sources: (dflt?.routes ?? []).filter(x => x.group === g).map(x => ({ source: x.source, pkts: x.pkts })) });
    const ifs = new Map(app.devices.interfaces(id).map(i => [i.ifIndex, i.oper] as const)), downSet = new Set(m.down ?? []);
    const isDown = (ix: number): boolean => ifs.has(ix) ? ifs.get(ix) !== 1 : downSet.has(ix);
    const pimMode = new Map(m.pimInterfaces.map(p => [p.ifIndex, p.mode] as const));
    const nbr = new Map(m.neighbors.map(n => [n.ifIndex, n.address]));
    const joins = new Map<string, typeof m.receivers>();
    for (const r of m.receivers) { const k = r.group + '|' + r.ifIndex; const a = joins.get(k) ?? []; a.push(r); joins.set(k, a); }
    const now = Date.now();
    // the other polled devices, so the far end of each PIM link can be compared
    const ipsOf = new Map<number, Map<string, number>>();
    for (const r of app.cdb.db.prepare('SELECT dev_id, ip, if_index FROM device_ips').all() as unknown as { dev_id: number; ip: string; if_index: number | null }[]) { if (r.if_index === null) continue; const a = ipsOf.get(r.dev_id) ?? new Map<string, number>(); a.set(r.ip, r.if_index); ipsOf.set(r.dev_id, a); }
    const peerId = new Map<string, number>();
    for (const [devId, m2] of ipsOf) for (const ip of m2.keys()) peerId.set(ip, devId);
    const peers: PimPeer[] = [];
    for (const o of app.devices.rows()) { if (o.id === id || vrf) continue; const om = app.devices.multicast(o.id); const ips = ipsOf.get(o.id); if (om && ips) peers.push({ name: o.name, mc: om, ips, ifName: namer(app, o.id, om) }); }
    const own = new Set([d.ip, ...(ipsOf.get(id)?.keys() ?? [])]);
    const devByIp = new Map<string, string>();
    for (const o of app.devices.rows()) devByIp.set(o.ip, o.name);
    for (const [devId, m2] of ipsOf) { const n = app.devices.row(devId)?.name; if (n) for (const ip of m2.keys()) devByIp.set(ip, n); }
    const who = (ip: string | null): string | null => (ip ? (own.has(ip) ? 'this router' : devByIp.get(ip) ?? null) : null);
    const igmp = (m.igmpInterfaces ?? []).map(i => ({ ifIndex: i.ifIndex, name: name(i.ifIndex), querier: i.querier, who: who(i.querier), self: !!i.querier && (own.has(i.querier) || i.querierExpirySec === 0), version: i.version, intervalSec: i.queryIntervalSec, upSec: i.querierUpSec, expirySec: i.querierExpirySec, hosts: new Set(m.receivers.filter(r => r.ifIndex === i.ifIndex).map(r => r.lastReporter)).size }));
    const rps = {
      map: (m.rpSet ?? []).map(x => ({ range: `${x.group}/${maskLen(x.mask)}`, rp: x.rp, who: who(x.rp), self: own.has(x.rp), holdSec: x.holdSec, expirySec: x.expirySec })),
      // the RP in use per group, gathered by RP; this is what Catalyst switches publish when pimRPSetTable is empty
      inUse: [...(m.rpGroups ?? []).reduce((acc, g) => { const e = acc.get(g.rp) ?? { rp: g.rp, who: who(g.rp), self: own.has(g.rp), up: true, groups: [] as string[], sinceSec: g.sinceSec }; e.groups.push(g.group); if (!g.up) e.up = false; if (g.sinceSec !== null && (e.sinceSec === null || g.sinceSec > e.sinceSec)) e.sinceSec = g.sinceSec; acc.set(g.rp, e); return acc; }, new Map<string, { rp: string; who: string | null; self: boolean; up: boolean; groups: string[]; sinceSec: number | null }>()).values()],
      candidate: (m.candidateRps ?? []).map(x => ({ range: `${x.group}/${maskLen(x.mask)}`, rp: x.rp, self: own.has(x.rp) }))
    };
    // Where the hosts named in this device's state are plugged in. IGMP reports the VLAN interface and the last host that reported, not the switch port,
    // so a reporter or a source is looked up in host tracking (ARP, MAC tables, DHCP snooping).
    const ips = new Set<string>();
    for (const r of m.routes) if (r.source !== '0.0.0.0') ips.add(r.source);
    for (const r of m.receivers) if (r.lastReporter && !r.self) ips.add(r.lastReporter);
    type Mem = { ip: string; lastSeen: number | null; firstSeen: number | null; via: 'snmp' | 'netflow' | 'both'; recent?: boolean };
    const members = new Map<string, Mem[]>();
    for (const x of app.devices.mcastMembers(id, vrf)) { ips.add(x.ip); const k = x.group + '|' + x.ifIndex; const a = members.get(k) ?? []; a.push({ ip: x.ip, lastSeen: x.lastSeen, firstSeen: x.firstSeen, via: 'snmp' }); members.set(k, a); }
    // the same hosts as NetFlow saw them: version 1 and 2 reports name the group; a host in both is confirmed
    const nf = await igmpFromFlows(app, app.devices.exporterIpsForDevice(id), now);
    let unmatched = 0;
    if (nf) {
      const outIfs = new Set(m.routes.flatMap(r => r.oifs.map(o => o.ifIndex)));
      for (const [k, hostMap] of nf.members) {
        const [group, ifs] = [k.slice(0, k.indexOf('|')), Number(k.slice(k.indexOf('|') + 1))];
        const routed = m.routes.some(r => r.group === group), onOif = outIfs.has(ifs);
        if (!routed || !onOif) { unmatched += hostMap.size; continue; }
        const a = members.get(k) ?? []; members.set(k, a);
        for (const [host, info] of hostMap) { ips.add(host); const e = a.find(x => x.ip === host); if (e) { e.via = 'both'; e.recent = info.recent; } else a.push({ ip: host, lastSeen: null, firstSeen: null, via: 'netflow', recent: info.recent }); }
      }
    }
    const hosts: Record<string, { dev: string; devId: number; ifIndex: number; port: string; vlan: number; confidence: string; neighbor: string | null } | null> = {};
    for (const ip of [...ips].slice(0, 2500)) {
      const a = app.hosts.locate(ip).attach;
      hosts[ip] = a && a.edge ? { dev: a.dev, devId: a.devId, ifIndex: a.ifIndex, port: a.ifName, vlan: a.vlan, confidence: a.confidence, neighbor: a.neighbor } : null;
    }
    // the router on the other end of each route's RPF link, when it is polled too: its name and interface, and whether it forwards the group towards this router
    const lossIf = new Set(multicastLoss(m, peers).map(l => l.ifIndex));
    const peerRoutes = new Map<number, Map<string, Multicast['routes'][number]>>();
    const routesOf = (pid: number, pm: Multicast): Map<string, Multicast['routes'][number]> => { let x = peerRoutes.get(pid); if (!x) { x = new Map(pm.routes.map(r => [r.group + '|' + r.source, r] as const)); peerRoutes.set(pid, x); } return x; };
    const fib = app.devices.data<Fib>(id, vrf ? 'fib:' + vrf : 'fib');
    const ecmpPaths = (f: Fib | null, ip: string | null): number | null => { if (!f || !ip) return null; const e = lookupFib(f, ip); return e ? e.paths.filter(p => p.kind !== 'receive').length : null; };
    const rpfPeer = (r: Multicast['routes'][number]): { peer: { id: number; name: string; ifIndex: number; ifName: string; forwarding: boolean | null } | null; loss: boolean } => {
      const loss = r.inIfIndex !== null && lossIf.has(r.inIfIndex);
      const pid = r.upstream && !vrf ? peerId.get(r.upstream) : undefined, pm = pid ? app.devices.multicast(pid) : null, pif = pid && r.upstream ? ipsOf.get(pid)?.get(r.upstream) : undefined;
      if (!pid || !pm || pif === undefined) return { peer: null, loss };
      const pr = routesOf(pid, pm).get(r.group + '|' + r.source) ?? routesOf(pid, pm).get(r.group + '|0.0.0.0');
      const oif = pr?.oifs.find(o => o.ifIndex === pif);
      return { peer: { id: pid, name: app.devices.row(pid)?.name ?? '', ifIndex: pif, ifName: namer(app, pid, pm)(pif), forwarding: now - pm.readAt > STALE_MS ? null : oif ? oif.forwarding : false }, loss };
    };
    c.json({
      device: { id: d.id, name: d.name, ip: d.ip, role: d.role ?? 'device', model: modelText(app.devices.data<Entity>(id, 'entity')) }, vrf, vrfs: app.devices.vrfs(id).map(v => ({ name: v.name, routes: vrfData.find(x => x.name === v.name)?.mc.routes.length ?? null })), readAt: m.readAt, stale: now - m.readAt > STALE_MS, source: m.source, truncated: m.truncated,
      routes: m.routes.map(r => ({
        group: r.group, source: r.source, sharedTree: r.source === '0.0.0.0',
        // SD-Access: the underlay group an overlay group is carried in (read in a VRF), or the overlay groups an underlay group carries (read in the default VRF)
        underlay: vrf ? ((): ReturnType<typeof underInfo> & { exact: boolean } | null => { const own = r.oifs.find(o => o.underlay)?.underlay, g = own ?? under.forward.get(vrf + '|' + r.group); return g ? { ...underInfo(g), exact: !!own } : null; })() : null,
        overlay: !vrf && r.group.startsWith('232.') ? (under.reverse.get(r.group) ?? null) : null, rpf: r.inIfIndex || r.upstream || r.rpf ? { ...rpfPeer(r), inIf: r.inIfIndex ? name(r.inIfIndex) : null, inIfIndex: r.inIfIndex, neighbor: r.upstream, who: who(r.upstream), route: r.rpf ? `${r.rpf.prefix}/${maskLen(r.rpf.mask)}` : null, proto: r.rpf?.proto ? RT_PROTO[r.rpf.proto] ?? null : null, failures: r.rpfFail ?? null, failuresNew: r.rpfNew ?? null, failuresShare: r.rpfNew && r.pktsNew != null ? Math.round((r.rpfNew / (r.rpfNew + Math.max(0, r.pktsNew))) * 1000) / 10 : null, failuresMajor: rpfSignificant(r), paths: ecmpPaths(fib, r.source !== '0.0.0.0' ? r.source : r.rp) } : null, mode: r.protocol === 8 ? 'sparse' : r.protocol === 9 ? 'dense' : null, inIf: r.inIfIndex ? name(r.inIfIndex) : null, upstream: r.upstream, rp: r.rp, bps: r.bps, pkts: r.pkts, flags: r.flags, protocol: r.protocol, expirySec: r.expirySec,
        out: r.oifs.map(o => ({
          ifIndex: o.ifIndex, name: name(o.ifIndex), forwarding: o.forwarding, linkDown: isDown(o.ifIndex), loopback: /^(lo|loopback)\d+$/i.test(name(o.ifIndex)), pkts: o.pkts, neighbor: nbr.get(o.ifIndex) ?? null, pimMode: pimMode.get(o.ifIndex) ?? null,
          members: (members.get(r.group + '|' + o.ifIndex) ?? []).map(x => ({ ip: x.ip, via: x.via, ageSec: x.lastSeen !== null ? Math.max(0, Math.round((now - x.lastSeen) / 1000)) : x.recent ? 300 : 1800, sinceSec: x.firstSeen !== null ? Math.round((now - x.firstSeen) / 1000) : null, approx: x.lastSeen === null })),
          joins: (joins.get(r.group + '|' + o.ifIndex) ?? []).map(j => ({ reporter: j.lastReporter, expirySec: j.expirySec, self: j.self }))
        }))
      })),
      // wrong-interface drops per minute over the last day, one point per read
      rpfHistory: (vrf ? [] : app.devices.rpfHistory(id, now - 86_400_000)).map(p => ({ ts: p.ts, perMin: p.dt > 0 ? Math.round((p.drops * 60 / p.dt) * 10) / 10 : 0, routes: p.routes })),
      routeSource: m.routeSource ?? 'ipmroute',
      netflowIgmp: nf ? { reports: nf.reports, hosts: nf.hosts, v3Hosts: nf.v3Hosts, windowMin: nf.windowMin, unmatched } : null,
      igmp, rps,
      hosts, igmpHint: igmpHint(vendorOf(d.sys_object_id ?? '', d.sys_descr ?? '', (d.sys_object_id ?? '').startsWith('1.3.6.1.4.1.9.')), d.sys_descr ?? ''),
      load: (m.interfaces ?? []).filter(i => (i.inOctets ?? 0) > 0 || (i.outOctets ?? 0) > 0).map(i => ({ name: name(i.ifIndex), inBps: i.inBps, outBps: i.outBps, inOctets: i.inOctets, outOctets: i.outOctets, ttl: i.ttl, rateLimit: i.rateLimit }))
        .sort((a, b) => (b.inBps ?? 0) + (b.outBps ?? 0) - (a.inBps ?? 0) - (a.outBps ?? 0) || (b.inOctets ?? 0) + (b.outOctets ?? 0) - (a.inOctets ?? 0) - (a.outOctets ?? 0)),
      pimIssues: pimIssues(m, name, peers),
      pim: { interfaces: m.pimInterfaces.map(p => ({ name: name(p.ifIndex), mode: p.mode, dr: p.dr })), neighbors: m.neighbors.map(n => ({ address: n.address, ifName: name(n.ifIndex) })) }
    });
  });
}
