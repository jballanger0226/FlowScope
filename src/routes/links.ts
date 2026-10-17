import { rpfSignificant } from '../snmp/multicast.js';
import { contextOf } from '../snmp/vrf.js';
import { ifaceVrf } from '../snmp/vrfmap.js';
import { neighborViews } from '../analysis/path.js';
import { pathEnv } from './pathenv.js';
import type { App } from '../app.js';
import { HttpError } from '../server/http.js';
import { int, parseRange } from './util.js';
import type { ClassLatest, IfLatest } from '../store/types.js';
import { streamView } from './flows.js';
import { isVlanInterface } from '../snmp/ports.js';
import { DEFAULTS } from '../settings.js';
import { linkWarnings } from '../snmp/health.js';
import { modelText, type Entity } from '../snmp/entity.js';
import { authMethods, type AuthPort } from '../snmp/authsetup.js';
import type { Aaa } from '../snmp/aaa.js';
import type { ConfigState } from '../snmp/confighist.js';
import { daiReason, type Dai, type Nbar, type Processes, type Stack } from '../snmp/cisco_extra.js';

export const MIBS = [
  { name: 'IF-MIB · ifXTable, ifTable', what: 'Interface names, speed, status, each interface\'s own MAC address, 64-bit octet counters and discards.' },
  { name: 'IP-MIB · ipAddrTable', what: 'The addresses and subnet masks of each device, so flow exporters are matched to the right device and each interface shows its subnet.' },
  { name: 'HOST-RESOURCES-MIB · UCD-SNMP-MIB · CISCO-PROCESS-MIB · CISCO-MEMORY-POOL-MIB', what: 'Uptime, CPU, memory and disk use of each device, about once a minute, with history. Cisco uses its own process and memory pool tables, net-snmp devices (OPNsense, pfSense, Linux) the UCD-SNMP-MIB, and others HOST-RESOURCES-MIB.' },
  { name: 'JUNIPER-MIB · HUAWEI-ENTITY-EXTENT-MIB · HH3C-ENTITY-EXT-MIB · STATISTICS-MIB (HP ProCurve) · FORTINET-FORTIGATE-MIB · PAN-COMMON-MIB', what: 'CPU, memory and, on firewalls, the session count, for vendors whose devices do not publish them in the standard MIBs.' },
  { name: 'ENTITY-SENSOR-MIB · CISCO-ENTITY-SENSOR-MIB · CISCO-ENVMON-MIB · JUNIPER-MIB', what: 'Temperature, fan, power supply and voltage sensors, and the light levels and temperature of optics, read every few minutes. Cisco sensor thresholds decide when a reading is flagged.' },
  { name: 'POWER-ETHERNET-MIB', what: 'Power over Ethernet budget and use per power source, and how many ports are delivering power or in fault.' },
  { name: 'BRIDGE-MIB (spanning tree) · OSPF-MIB · BGP4-MIB', what: 'The spanning tree root, topology changes and blocking ports, OSPF neighbour states and BGP peer states.' },
  { name: 'EtherLike-MIB · IF-MIB (cast counters)', what: 'Duplex, CRC, alignment and symbol errors, collisions, and broadcast, multicast and unknown-protocol packets for each interface, to find bad cables, duplex mismatches and storms.' },
  { name: 'Q-BRIDGE-MIB · dot1qVlanStaticName', what: 'VLAN numbers and their names, so flows and interfaces can be searched by either.' },
  { name: 'CISCO-CLASS-BASED-QOS-MIB', what: 'Input and output service policies, per-class packets, bytes and drops, and queue depth (64-bit counters, or 32-bit where a device has no others). Used for devices that implement it.' },
  { name: 'JUNIPER-COS-MIB · DIFFSERV-MIB', what: 'Queue statistics per forwarding class on Juniper devices, and the standard DiffServ data path (classifier, meter, counter and drop elements) on devices that publish it. Cisco\'s MIB is tried first.' },
  { name: 'CISCO-VLAN-MEMBERSHIP-MIB · CISCO-VTP-MIB · Q-BRIDGE-MIB', what: 'The VLAN of each port: access and voice VLAN, trunk native and allowed VLANs, or the standard port VLAN id.' },
  { name: 'CISCO-CEF-MIB · CISCO-DHCP-SNOOPING-MIB', what: 'Cisco only. The forwarding table (checks which interface a flow should have left) and DHCP snooping leases (MAC, IP, VLAN and port of each client), read every few minutes.' },
  { name: 'CISCO-EIGRP-MIB · CISCO-IETF-BFD-MIB', what: 'Cisco only. EIGRP neighbours with retransmissions, and BFD sessions with their state and last failure.' },
  { name: 'CISCO-IF-EXTENSION-MIB · CISCO-PORT-STORM-CONTROL-MIB · CISCO-PORT-SECURITY-MIB', what: 'Cisco only. Per interface: output and input queue drops, resets, packets suppressed by storm control and port security violations.' },
  { name: 'CISCO-PROCESS-MIB · CISCO-STACKWISE-MIB · CISCO-DYNAMIC-ARP-INSPECTION-MIB · CISCO-NBAR-PROTOCOL-DISCOVERY-MIB', what: 'Cisco only. The busiest processes (including the SNMP engine), stack members and stack ports, ARP packets dropped per VLAN, and the applications NBAR2 recognised on each interface.' },
  { name: 'Aruba AI-AP-MIB (Instant access points)', what: 'Radios (channel, power, noise, how busy the channel is), SSIDs, and the wireless clients with their name, IP address, signal and traffic, read with the host tables.' },
  { name: 'BRIDGE-MIB · Q-BRIDGE-MIB · IP-MIB · LLDP-MIB · CISCO-CDP-MIB', what: 'MAC address tables, ARP, and LLDP/CDP neighbours every few minutes, to show which port a host is plugged into. Cisco switches are read one VLAN at a time.' }
];

interface Event { ts0: number; ts1: number; devId: number; dev: string; ifIndex: number; ifName: string; kind: 'drop' | 'util' | 'errors'; cls?: string; peak: number; text: string; severity: 'warn' | 'bad' }

/** Interfaces and QoS classes for every polled device, with the latest rates. The Network health page and the Overview both read this. */
/** The rate a priority class is limited to, from its configured bandwidth ("5000 kbps", "20%"). A share of what is left over has no fixed rate. */
export function limitBps(bw: string | null, speedMbps: number): number | null {
  const m = /^([\d.]+) (kbps|%)$/.exec((bw ?? '').trim().replace(/^([\d.]+)(%)$/, '$1 $2'));
  if (!m) return null;
  const v = Number(m[1]);
  if (!(v > 0)) return null;
  if (m[2] === 'kbps') return v * 1000;
  return speedMbps > 0 ? v / 100 * speedMbps * 1e6 : null;
}

export async function linkDevices(app: App, minutes: number) {
  const since = Date.now() - minutes * 60_000;
  const [ifl, cll] = await Promise.all([app.store.ifLatest(since), app.store.classLatest(since)]);
  const ifBy = new Map<string, IfLatest>(ifl.map(i => [`${i.dev}/${i.ifIndex}`, i]));
  const clBy = new Map<string, ClassLatest[]>();
  for (const k of cll) { const key = `${k.dev}/${k.ifIndex}`; const a = clBy.get(key); if (a) a.push(k); else clBy.set(key, [k]); }
  const al = app.settings.get('alerts');
  // multicast octets per interface (IPMROUTE-STD-MIB), read with the multicast tables
  const mcastLoad = new Map<number, Map<number, { inBps: number | null; outBps: number | null }>>();
  for (const dv of app.devices.list()) { const m = app.devices.multicast(dv.id); if (m?.interfaces?.length) mcastLoad.set(dv.id, new Map(m.interfaces.map(x => [x.ifIndex, x]))); }
  const counts = app.hosts.portCounts();
  const opVl = new Map(app.devices.list().map(d => [d.id, app.hosts.operatingVlans(d.id)] as const));
  const vmaps = new Map(app.devices.list().map(d => [d.id, app.devices.vrfMaps(d.id)] as const));
  const setups = new Map(app.devices.list().map(d => [d.id, new Map((app.devices.data<AuthPort[]>(d.id, 'authsetup') ?? []).map(p => [p.ifIndex, p]))] as const));
  const devices = app.devices.list().map(d => ({
    id: d.id, name: d.name, ip: d.ip, role: d.role, status: d.status, lastOk: d.lastOk, lastError: d.lastError, profile: d.profile,
    rpfNow: (() => { const g = (app.devices.multicast(d.id)?.routes ?? []).filter(rpfSignificant); return g.length ? { routes: g.length, drops: g.reduce((a, r) => a + (r.rpfNew ?? 0), 0), top: g.sort((a, b) => (b.rpfNew ?? 0) - (a.rpfNew ?? 0))[0]!.group } : null; })(),
    model: modelText(app.devices.data<Entity>(d.id, 'entity')), qosNote: d.qosNote, hostsAt: d.hostsAt, hostsNote: d.hostsNote, hasWlan: app.hosts.hasWlan(d.id), resources: d.resources,
    interfaces: app.devices.interfaces(d.id).map(i => {
      const mload = mcastLoad.get(d.id)?.get(i.ifIndex);
      const l = ifBy.get(`${d.id}/${i.ifIndex}`); const cls = clBy.get(`${d.id}/${i.ifIndex}`) ?? [];
      // VLAN and SVI interfaces carry routed traffic for a whole subnet and are never listed under "needs attention"
      const vlanIf = isVlanInterface(i);
      // an access port whose hosts sit in other VLANs than the configured one authenticates them (802.1X / MAB): the VLANs they are in are the ones in effect
      const seen = i.portMode === 'access' || i.portMode === 'pvid' ? (opVl.get(d.id)?.get(i.ifIndex) ?? []).filter(x => x.vlan !== i.voiceVlan) : [];
      const dynamic = seen.filter(x => x.vlan !== i.vlan).map(x => x.vlan);
      // how full the busiest strict-priority queue is, and how much of the link multicast takes (the larger of in and out)
      let prioPct: number | null = null;
      for (const def of i.classes) { if (!def.priority || def.cls.startsWith('in:')) continue; const lim = limitBps(def.bw, i.speedMbps); const k = cls.find(x => x.cls === def.cls); if (lim && k) prioPct = Math.max(prioPct ?? 0, 100 * k.sentBps / lim); }
      const mcastBps = mload ? Math.max(mload.inBps ?? 0, mload.outBps ?? 0) : null;
      const mcastPct = mcastBps !== null && i.speedMbps > 0 ? 100 * mcastBps / (i.speedMbps * 1e6) : null;
      return {
        ifIndex: i.ifIndex, name: i.name, alias: i.alias, mac: i.mac, addresses: i.addresses, speedMbps: i.speedMbps, oper: i.oper === 1 ? 'up' : i.oper === 2 ? 'down' : 'other', policy: i.policy, policyIn: i.policyIn,
        portMode: i.portMode, vlan: i.vlan || null, vlanName: i.vlan ? app.vlanName(i.vlan) : '', voiceVlan: i.voiceVlan || null, voiceVlanName: i.voiceVlan ? app.vlanName(i.voiceVlan) : '', vlanList: i.vlanList, ...(dynamic.length ? { opVlans: dynamic.map(v => ({ vlan: v, name: app.vlanName(v), hosts: seen.find(x => x.vlan === v)?.hosts ?? 0 })) } : {}),
        ...((): { authSetup: { methods: string; mode: string; open: boolean; control: string } } | Record<string, never> => { const a = setups.get(d.id)?.get(i.ifIndex); return a && (a.dot1x || a.mab) ? { authSetup: { methods: authMethods(a), mode: a.mode, open: a.open, control: a.control } } : {}; })(),
        isVlanIf: vlanIf, hosts: counts.get(`${d.id}/${i.ifIndex}`) ?? 0, ...((): { vrf: string; vrfVia: string } | Record<string, never> => { const vm = vmaps.get(d.id); const x = vm ? ifaceVrf(dynamic.length ? { ...i, vlan: dynamic[0]! } : i, vm.direct, vm.byVlan) : null; return x ? { vrf: x.vrf, vrfVia: x.via } : {}; })(),
        utilIn: l?.utilIn ?? null, utilOut: l?.utilOut ?? null, inBps: l?.inBps ?? null, outBps: l?.outBps ?? null, disc: l?.disc ?? 0, err: l?.err ?? 0,
        classes: i.classes.map(def => {
          const k = cls.find(x => x.cls === def.cls);
          const lim = def.priority && !def.cls.startsWith('in:') ? limitBps(def.bw, i.speedMbps) : null;
          return { priority: def.priority, limitBps: lim, limitPct: lim && k ? 100 * k.sentBps / lim : null, cls: def.cls, label: def.cls.replace(/^in:/, ''), dir: def.cls.startsWith('in:') ? 'in' : 'out', dscps: def.dscps, bw: def.bw, queue: def.queue, dropPct: k?.dropPct ?? null, dropPkts: k?.dropPkts ?? 0, dropBytes: k?.dropBytes ?? 0, sentBps: k?.sentBps ?? null, qdepth: k?.qdepth ?? null };
        }),
        worstDropPct: cls.length ? Math.max(...cls.map(x => x.dropPct)) : null,
        priorityPct: prioPct, mcastPct,
        flagged: !vlanIf && ((!!l && Math.max(l.utilIn, l.utilOut) >= al.util) || cls.some(x => x.dropPct >= al.drop) || (prioPct !== null && prioPct >= al.priority) || (mcastPct !== null && mcastPct >= al.mcast))
      };
    })
  }));
  return { devices, thresholds: al };
}

/** Sensors, PoE, spanning tree, routing neighbours and the link quality of each interface of one device, as last read. */
export function linkHealth(app: App, dev: number) {
  const ifs = new Map(app.devices.interfaces(dev).map(i => [i.ifIndex, i]));
  const extra = [...app.devices.ifExtra(dev)].map(([ifIndex, x]) => {
    const i = ifs.get(ifIndex);
    return { ifIndex, ...x, warnings: i ? linkWarnings(x, i.oper, i.speedMbps) : [] };
  });
  const dai = app.devices.data<Dai>(dev, 'dai');
  const extras = {
    procs: app.devices.data<Processes>(dev, 'procs'), stack: app.devices.data<Stack>(dev, 'stack'), nbar: app.devices.data<Nbar>(dev, 'nbar'), aaa: app.devices.data<Aaa>(dev, 'aaa'), config: app.devices.data<ConfigState>(dev, 'config'),
    dai: dai ? { ...dai, vlans: dai.vlans.map(v => ({ ...v, why: daiReason(v) })) } : null
  };
  return { health: app.devices.health(dev), ifExtra: extra, extras };
}

export function registerLinks(app: App): void {
  const w = app.web;
  const alerts = () => app.settings.get('alerts');

  // Interfaces and QoS classes for every polled device, with the latest rates
  w.get('/api/links', 'ro', async c => {
    const minutes = int(c.query.get('minutes'), 10, 1, 1440);
    const r = await linkDevices(app, minutes);
    c.json({ devices: r.devices, windowMinutes: minutes, thresholds: r.thresholds, mibs: MIBS });
  });

  // Sensors, PoE, spanning tree, routing neighbours and the link quality of each interface, as last read
  w.get('/api/links/health', 'ro', c => {
    const dev = int(c.query.get('dev'), 0, 0, 1e9);
    if (!app.devices.row(dev)) throw new HttpError(404, 'No such device');
    c.json(linkHealth(app, dev));
  });

  // Hosts learned on one port (from the switch's MAC address table, with IP addresses from ARP) and what LLDP/CDP says is at the other end
  w.get('/api/links/hosts', 'ro', c => {
    const dev = int(c.query.get('dev'), 0, 0, 1e9), ifx = int(c.query.get('if'), 0, 0, 1e9);
    const d = app.devices.row(dev);
    if (!d) throw new HttpError(404, 'No such device');
    const env = pathEnv(app);
    c.json({
      hosts: app.hosts.portHosts(dev, ifx, 300).map(h => ({ ...h, vlanName: h.vlan ? app.vlanName(h.vlan) : '', vrf: app.devices.vrfMaps(dev).byVlan.get(h.vlan) ?? '' })), neighbors: neighborViews(app.hosts.neighborsOf(dev, ifx).map(n => ({ ...n, ifIndex: ifx })), env, env.devices()),
      readAt: d.hosts_at, note: d.hosts_note ?? '', tracking: app.settings.get('hosts').enabled
    });
  });

  // The ARP cache of a device, as last read, with the interface each entry was learned on
  w.get('/api/links/arp', 'ro', c => {
    const dev = int(c.query.get('dev'), 0, 0, 1e9);
    const d = app.devices.row(dev);
    if (!d) throw new HttpError(404, 'No such device');
    const names = new Map(app.devices.interfaces(dev).map(i => [i.ifIndex, i.name]));
    const direct = app.devices.vrfMaps(dev).direct;
    c.json({ rows: app.hosts.arpOf(dev).map(r => ({ ...r, vrf: direct.get(r.ifIndex) ?? '', ifName: names.get(r.ifIndex) || app.devices.ifNameById(dev, r.ifIndex) || '' })), readAt: d.hosts_at });
  });

  // The VRFs of a device: their interfaces, the hosts in their ARP tables and their multicast state, each read in the VRF's own SNMP context
  w.get('/api/links/vrfs', 'ro', c => {
    const dev = int(c.query.get('dev'), 0, 0, 1e9);
    const d = app.devices.row(dev);
    if (!d) throw new HttpError(404, 'No such device');
    const mcNames = app.devices.multicast(dev)?.names ?? {};
    const nameOf = (ix: number): string => app.devices.interfaces(dev).find(i => i.ifIndex === ix)?.name || app.devices.ifNameById(dev, ix) || mcNames[ix] || `if${ix}`;
    const arp = app.hosts.arpOf(dev, 20_000), now = Date.now();
    const vm = app.devices.vrfMaps(dev);
    const ports = app.devices.interfaces(dev).flatMap(i => { const x = ifaceVrf(i, vm.direct, vm.byVlan); return x ? [{ ifIndex: i.ifIndex, name: i.name, vlan: i.vlan, vrf: x.vrf, via: x.via }] : []; });
    c.json({
      vrfs: app.devices.vrfs(dev).map(v => {
        const mc = app.devices.vrfMulticast(dev, v.name);
        const hosts = arp.filter(a => vm.direct.get(a.ifIndex) === v.name);
        return {
          name: v.name, context: contextOf(v.name),
          interfaces: v.ifIndexes.map(ix => ({ ifIndex: ix, name: mc?.names?.[ix] ?? nameOf(ix) })),
          // the access ports whose VLAN has its SVI in this VRF: the ports themselves have no VRF
          ports: ports.filter(p => p.vrf.split(', ').includes(v.name) && p.via === 'vlan').map(p => ({ ifIndex: p.ifIndex, name: p.name, vlan: p.vlan })),
          hosts: hosts.length, hostsReadAt: hosts.length ? Math.max(...hosts.map(h => h.lastSeen)) : null,
          multicast: mc ? { routes: mc.routes.length, groups: new Set(mc.routes.map(r => r.group)).size, forwarding: mc.routes.filter(r => r.oifs.some(o => o.forwarding)).length, readAt: mc.readAt, stale: now - mc.readAt > 10 * 60_000 } : null
        };
      })
    });
  });

  // Wi-Fi state of an access point: the AP itself, its radios, its SSIDs and the clients connected to it
  w.get('/api/links/wlan', 'ro', c => {
    const dev = int(c.query.get('dev'), 0, 0, 1e9);
    if (!app.devices.row(dev)) throw new HttpError(404, 'No such device');
    c.json(app.hosts.wlanOf(dev) ?? { readAt: null, aps: [], radios: [], ssids: [], clients: [] });
  });

  // Everything a device's CDP and LLDP tables say, by port, with the neighbours that are polled devices linked so the console can open them.
  w.get('/api/links/neighbors', 'ro', c => {
    const dev = int(c.query.get('dev'), 0, 0, 1e9);
    const d = app.devices.row(dev);
    if (!d) throw new HttpError(404, 'No such device');
    const env = pathEnv(app), devs = env.devices();
    const byPort = new Map<number, ReturnType<typeof app.hosts.neighborsOfDevice>>();
    for (const n of app.hosts.neighborsOfDevice(dev)) { const a = byPort.get(n.ifIndex) ?? []; a.push(n); byPort.set(n.ifIndex, a); }
    const ports = [...byPort].map(([ifIndex, rows]) => ({ ifIndex, ifName: env.ifName(dev, ifIndex), neighbors: neighborViews(rows, env, devs) }))
      .sort((a, b) => a.ifName.localeCompare(b.ifName, undefined, { numeric: true }));
    c.json({ ports, readAt: d.hosts_at, note: d.hosts_note ?? '', tracking: app.settings.get('hosts').enabled });
  });

  // Where is this host plugged in? q is an IP address or a MAC address.
  w.get('/api/hosts/locate', 'ro', c => {
    const q = (c.query.get('q') ?? '').trim().slice(0, 64);
    if (!q) throw new HttpError(400, 'Enter an IP address or a MAC address');
    c.json(app.hosts.locate(q));
  });

  w.get('/api/hosts/settings', 'ro', c => c.json({ ...app.settings.get('hosts'), defaults: DEFAULTS.hosts }));
  w.put('/api/hosts/settings', 'snmp', async c => {
    const b = await c.body<{ enabled?: boolean; intervalSec?: number; keepDays?: number }>(2000);
    const cur = app.settings.get('hosts');
    const interval = b.intervalSec === undefined ? cur.intervalSec : Math.floor(Number(b.intervalSec));
    const keep = b.keepDays === undefined ? cur.keepDays : Math.floor(Number(b.keepDays));
    if (!Number.isFinite(interval) || interval < 60 || interval > 86_400) throw new HttpError(400, 'The read interval must be between 60 seconds and 24 hours');
    if (!Number.isFinite(keep) || keep < 1 || keep > 365) throw new HttpError(400, 'Keep host records for 1 to 365 days');
    const next = { enabled: b.enabled === undefined ? cur.enabled : !!b.enabled, intervalSec: interval, keepDays: keep };
    app.settings.set('hosts', next);
    app.log.audit(c.user().username, `Host tracking ${next.enabled ? `on, every ${next.intervalSec} s, kept ${next.keepDays} days` : 'turned off'}`);
    c.json(next);
  });

  // Streams that left through one interface (found from the exporter and outgoing interface in the flow records)
  w.get('/api/links/streams', 'ro', async c => {
    const dev = int(c.query.get('dev'), 0, 0, 1e9), ifx = int(c.query.get('if'), 0, 0, 1e9);
    if (!app.devices.row(dev)) throw new HttpError(404, 'No such device');
    const range = parseRange(c.query, '1h');
    const page = await app.store.searchStreams({ range, conds: [{ kind: 'outif', ips: app.devices.exporterIpsForDevice(dev), ifIndex: ifx }], sort: 'bytes', dir: 'desc', limit: int(c.query.get('limit'), 8, 1, 50) });
    c.json({ rows: page.rows.map(r => streamView(app, r)), total: page.total });
  });

  // Time series for one interface: utilisation plus drop % and dropped bytes for each class
  w.get('/api/links/series', 'ro', async c => {
    const dev = int(c.query.get('dev'), 0, 0, 1e9), ifx = int(c.query.get('if'), 0, 0, 1e9);
    if (!app.devices.row(dev)) throw new HttpError(404, 'No such device');
    const range = parseRange(c.query, '6h');
    const points = int(c.query.get('points'), 120, 10, 600);
    const ret = app.settings.get('retention');
    const [u, k] = await Promise.all([app.store.ifSeries(dev, ifx, range, ret, points), app.store.classSeries(dev, ifx, range, ret, points)]);
    const defs = app.devices.interfaces(dev).find(i => i.ifIndex === ifx)?.classes ?? [];
    c.json({ range, util: u, classes: k.classes.map(cl => ({ ...cl, dscps: defs.find(d => d.cls === cl.cls)?.dscps ?? [], bw: defs.find(d => d.cls === cl.cls)?.bw ?? null })), step: u.step, tier: u.tier });
  });

  // History of one device's CPU, memory, swap, disk and load, and the moments it restarted
  w.get('/api/links/resources', 'ro', c => {
    const dev = int(c.query.get('dev'), 0, 0, 1e9);
    if (!app.devices.row(dev)) throw new HttpError(404, 'No such device');
    const range = parseRange(c.query, '6h');
    const points = int(c.query.get('points'), 120, 10, 600);
    const ap = (c.query.get('ap') ?? '').toLowerCase().slice(0, 40);
    c.json({ range, ...app.devices.resourceHistory(dev, range.from, range.to, points, /^[0-9a-f:.-]*$/.test(ap) ? ap : '') });
  });

  // History of one interface's error, discard, broadcast and multicast counters, as rates per second
  w.get('/api/links/quality', 'ro', c => {
    const dev = int(c.query.get('dev'), 0, 0, 1e9), ifx = int(c.query.get('if'), 0, 0, 1e9);
    if (!app.devices.row(dev)) throw new HttpError(404, 'No such device');
    const range = parseRange(c.query, '6h');
    const points = int(c.query.get('points'), 120, 10, 600);
    c.json({ range, ...app.devices.ifExtraHistory(dev, ifx, range.from, range.to, points) });
  });

  // Events: stretches where utilisation or drops were over the alert thresholds
  w.get('/api/links/events', 'ro', async c => {
    const range = parseRange(c.query, '24h');
    const al = alerts(); const ret = app.settings.get('retention');
    const out: Event[] = [];
    const maxIfs = 400;
    let scanned = 0;
    for (const d of app.devices.list()) {
      for (const i of app.devices.interfaces(d.id)) {
        if (isVlanInterface(i)) continue;
        if (scanned++ >= maxIfs) break;
        const [u, k] = await Promise.all([app.store.ifSeries(d.id, i.ifIndex, range, ret, 288), i.classes.length ? app.store.classSeries(d.id, i.ifIndex, range, ret, 288) : Promise.resolve(null)]);
        const merge = (pts: { ts: number; v: number }[], limit: number, step: number, mk: (peak: number) => Pick<Event, 'kind' | 'text' | 'cls'>) => {
          let cur: { a: number; b: number; peak: number } | null = null;
          const flush = () => { if (!cur) return; const m = mk(cur.peak); out.push({ ts0: cur.a, ts1: cur.b + step, devId: d.id, dev: d.name, ifIndex: i.ifIndex, ifName: i.name, peak: cur.peak, severity: cur.peak >= limit * 2.5 ? 'bad' : 'warn', ...m }); cur = null; };
          for (const p of pts) {
            if (p.v >= limit) { if (cur && p.ts - cur.b <= step * 1.5) { cur.b = p.ts; cur.peak = Math.max(cur.peak, p.v); } else { flush(); cur = { a: p.ts, b: p.ts, peak: p.v }; } }
          }
          flush();
        };
        merge(u.points.map(p => ({ ts: p.ts, v: Math.max(p.utilIn, p.utilOut) })), al.util, u.step, peak => ({ kind: 'util', text: `Utilisation reached ${peak.toFixed(0)}% on ${i.name}` }));
        for (const cl of k?.classes ?? []) {
          merge(cl.points.map(p => ({ ts: p.ts, v: p.dropPct })), al.drop, k!.step, peak => ({ kind: 'drop', cls: cl.cls, text: `Class ${cl.cls} dropped ${peak.toFixed(2)}% of packets on ${i.name}` }));
        }
        void u.points.length;
      }
    }
    out.sort((a, b) => b.ts1 - a.ts1);
    c.json({ events: out.slice(0, 500), range, thresholds: al, truncated: out.length > 500, scannedInterfaces: scanned });
  });
}
