/**
 * Multicast state read from a router or Layer 3 switch: which interface each (source, group) stream arrives on, which interfaces it is
 * forwarded out of, which receivers joined through IGMP, the rendezvous point and the PIM neighbours.
 *
 * NetFlow only records the interface a packet arrived on. A multicast packet is copied to its receivers after that point, so the flow
 * data rarely says where a group is going. The device's own multicast routing table does, and that is what is read here.
 *
 * Sources, all read-only:
 *  - IPMROUTE-STD-MIB  (1.3.6.1.2.1.83): routes and their outgoing interface list. Published by most routers.
 *  - CISCO-IPMROUTE-MIB (1.3.6.1.4.1.9.10.2): adds the current bit rate and the route flags. Optional.
 *  - IGMP-STD-MIB      (1.3.6.1.2.1.85): the hosts that joined each group on each interface.
 *  - PIM-MIB           (1.3.6.1.3.61): the rendezvous point of each group, PIM interfaces and neighbours.
 *
 * The column numbers and index layouts were checked against a full walk of a Catalyst 9300 stack running IOS XE 17.18.
 */
import { toBigInt, toNum, toStr, type SnmpClient, type SnmpValue } from './client.js';

export interface McOif {
  ifIndex: number;
  /** The route is forwarding out of this interface. False means it is pruned: the interface is in the list but no receiver wants the group. */
  forwarding: boolean;
  pkts: number | null;
}
export interface McRoute {
  group: string;
  /** The source address; 0.0.0.0 is a (*,G) route that is not tied to one sender. */
  source: string;
  inIfIndex: number | null;
  upstream: string | null;
  /** PIM sparse, dense, IGMP and so on, as the number in the MIB: 8 is PIM sparse mode, 9 is PIM dense mode */
  protocol: number | null;
  pkts: number | null;
  /** The rate the device measures for the route, in bits per second (checked: it matches the route's octets over its uptime). Only Cisco publishes it. */
  bps: number | null;
  expirySec: number | null;
  flags: string[];
  rp: string | null;
  oifs: McOif[];
  /** Reverse path forwarding. The incoming interface and upstream neighbour above are the RPF interface and neighbour; these say which unicast route chose them. */
  rpf?: { prefix: string; mask: string; proto: number | null } | null;
  /** Packets that arrived on an interface other than the RPF interface and were dropped (ipMRouteDifferentInIfPackets). A counter since the route was created. */
  rpfFail?: number | null;
  /** How much that counter grew since the previous read: drops happening now, as opposed to ones since the route was created. Null on the first read or when the counter restarted. */
  rpfNew?: number | null;
}
/** IGMP on one interface (IGMP-STD-MIB igmpInterfaceTable). The querier is the router that sends the membership queries on that segment. */
export interface McIgmpIf { ifIndex: number; querier: string | null; version: number | null; queryIntervalSec: number | null; querierUpSec: number | null; querierExpirySec: number | null }
/** A group range and the rendezvous point serving it (PIM-MIB pimRPSetTable). The MIB does not say whether the mapping was configured, learned from Auto-RP or from a bootstrap router. */
export interface McRpMap { group: string; mask: string; rp: string; holdSec: number | null; expirySec: number | null }
export interface McReceiver { group: string; ifIndex: number; lastReporter: string | null; expirySec: number | null; self: boolean }
export interface McPimIf { ifIndex: number; mode: 'dense' | 'sparse' | 'sparse-dense' | 'other'; dr: string | null }
export interface McNeighbor { address: string; ifIndex: number }
export interface McIfLoad {
  ifIndex: number;
  /** Octet totals as read, and the rate in bits per second since the previous read when there was one */
  inOctets: number | null; outOctets: number | null; inBps: number | null; outBps: number | null;
  /** Multicast boundary TTL threshold and rate limit (kbps) configured on the interface; 0 means none */
  ttl: number | null; rateLimit: number | null;
}

export interface Multicast {
  readAt: number;
  /** 'cisco' when the Cisco table (rates, flags) was available, otherwise 'standard' */
  source: 'cisco' | 'standard';
  routes: McRoute[];
  receivers: McReceiver[];
  pimInterfaces: McPimIf[];
  neighbors: McNeighbor[];
  /** 'pim' when the device publishes no IPMROUTE-STD-MIB (NX-OS) and the routes were taken from PIM-MIB: group, source and flags only, with no interfaces, no rates and no RPF. */
  routeSource?: 'ipmroute' | 'pim';
  igmpInterfaces?: McIgmpIf[];
  /** The rendezvous point each group is using and whether it is up (pimRPTable, index group.rp). The Catalyst 9300 and 3850 walks publish this and leave pimRPSetTable empty. */
  rpGroups?: { group: string; rp: string; up: boolean; sinceSec: number | null }[];
  rpSet?: McRpMap[];
  /** Group ranges this router is itself a candidate rendezvous point for */
  candidateRps?: { group: string; mask: string; rp: string }[];
  /** Multicast bytes in and out of each interface (IPMROUTE-STD-MIB). Absent in reads stored before it was collected */
  interfaces?: McIfLoad[];
  /** Names of the interfaces the tables mention, asked of the device by ifIndex. VLAN, tunnel and loopback interfaces are not in the stored interface list, so their names come from here. */
  names?: Record<number, string>;
  /** Interfaces the tables mention whose link is not up (ifOperStatus other than 1). A route can list a down interface as forwarding. */
  down?: number[];
  /** The tables held more rows than were kept */
  truncated: boolean;
}

export const MAX_ROUTES = 20_000;

const ROUTE = '1.3.6.1.2.1.83.1.1.2.1';
const NEXTHOP = '1.3.6.1.2.1.83.1.1.3.1';
const CROUTE = '1.3.6.1.4.1.9.10.2.1.1.2.1';
const MC_IF = '1.3.6.1.2.1.83.1.1.4.1';
const IGMP_CACHE = '1.3.6.1.2.1.85.1.2.1';
const PIM_IF = '1.3.6.1.3.61.1.1.2.1';
const PIM_NBR = '1.3.6.1.3.61.1.1.3.1';
const PIM_RP = '1.3.6.1.3.61.1.1.5.1';
const PIM_RPSET = '1.3.6.1.3.61.1.1.6.1';
const PIM_MROUTE = '1.3.6.1.3.61.1.1.4.1';
const IPIFSTATS = '1.3.6.1.2.1.4.31.3.1';
const PIM_CAND = '1.3.6.1.3.61.1.1.11.1';
const IGMP_IF = '1.3.6.1.2.1.85.1.1.1';

/** Cisco route flags in the order of their columns (12 to 18 and 25 to 27); 1 is true, 2 is false. */
const CFLAGS: [number, string][] = [[12, 'prune'], [13, 'sparse'], [14, 'connected'], [15, 'local'], [16, 'register'], [17, 'rp-tree'], [18, 'spt'], [25, 'join'], [26, 'msdp'], [27, 'proxy-join']];

const ip4 = (p: string[], at: number): string => p.slice(at, at + 4).join('.');
/** An IpAddress value: net-snmp hands back dotted text, but four raw bytes are accepted too. */
export const ipOf = (v: SnmpValue | undefined): string | null => {
  if (v === undefined || v === null) return null;
  const t = Buffer.isBuffer(v) ? (v.length === 4 ? [...v].join('.') : '') : String(v);
  return isIp(t) && t !== '0.0.0.0' ? t : null;
};
/** An IPv4 address as a number (NaN when it is not one). */
export const ipv4Int = (ip: string): number => { const p = ip.split('.'); return p.length === 4 && p.every(x => /^\d{1,3}$/.test(x) && Number(x) < 256) ? ((Number(p[0]) << 24) | (Number(p[1]) << 16) | (Number(p[2]) << 8) | Number(p[3])) >>> 0 : NaN; };
const num = (v: SnmpValue | undefined): number | null => (v === undefined || v === null ? null : toNum(v));
const EMPTY = new Map<string, SnmpValue>();
const col = (c: SnmpClient, oid: string) => c.column(oid, 50).catch(() => EMPTY);
const x32 = (a: string): number => a.split('.').reduce((t, o) => t * 256 + Number(o), 0);
const keyOf = (g: string, s: string) => g + '|' + s;
/** A TimeTicks value (hundredths of a second) as whole seconds. */
const secs = (v: SnmpValue | undefined): number | null => { const n = num(v); return n === null ? null : Math.round(n / 100); };
/** Whether a 4-part index looks like an IPv4 address; guards against indexes the table does not have */
const isIp = (s: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s);

/** Reads the multicast routing table. Returns null when the device publishes none of it. */
/** `cisco` says whether to ask for Cisco's rate and flag table; other vendors are never asked for it. */
export async function readMulticast(c: SnmpClient, now = Date.now(), cisco = true): Promise<Multicast | null> {
  const [up, inIf, expiry, pkts, proto] = await Promise.all([4, 5, 7, 8, 11].map(n => col(c, `${ROUTE}.${n}`)));
  const [rpfFail, rtProto, rtAddr, rtMask] = await Promise.all([9, 12, 13, 14].map(n => col(c, `${ROUTE}.${n}`)));
  const [nhState, nhPkts] = await Promise.all([6, 11].map(n => col(c, `${NEXTHOP}.${n}`)));
  const routes = new Map<string, McRoute>();
  let truncated = false;
  const add = (idx: string): McRoute | null => {
    const p = idx.split('.'); if (p.length < 12) return null;
    const group = ip4(p, 0), source = ip4(p, 4);
    if (!isIp(group) || !isIp(source)) return null;
    const k = keyOf(group, source);
    let r = routes.get(k);
    if (!r) {
      if (routes.size >= MAX_ROUTES) { truncated = true; return null; }
      r = { group, source, inIfIndex: null, upstream: null, protocol: null, pkts: null, bps: null, expirySec: null, flags: [], rp: null, oifs: [] };
      routes.set(k, r);
    }
    return r;
  };
  for (const [idx, v] of inIf) { const r = add(idx); if (r) r.inIfIndex = num(v); }
  for (const [idx, v] of up) { const r = add(idx); const s = ipOf(v); if (r && s) r.upstream = s; }
  for (const [idx, v] of expiry) { const r = routes.get(keyOf(ip4(idx.split('.'), 0), ip4(idx.split('.'), 4))); if (r) r.expirySec = secs(v); }
  for (const [idx, v] of pkts) { const r = routes.get(keyOf(ip4(idx.split('.'), 0), ip4(idx.split('.'), 4))); if (r) r.pkts = num(v); }
  for (const [idx, v] of proto) { const r = routes.get(keyOf(ip4(idx.split('.'), 0), ip4(idx.split('.'), 4))); if (r) r.protocol = num(v); }

  const byIdx = (idx: string): McRoute | undefined => { const p = idx.split('.'); return routes.get(keyOf(ip4(p, 0), ip4(p, 4))); };
  for (const [idx, v] of rpfFail) { const r = byIdx(idx); if (r) r.rpfFail = num(v); }
  for (const [idx, v] of rtAddr) {
    const r = byIdx(idx), a = ipOf(v), m = ipOf(rtMask.get(idx)); if (!r || !a) continue;
    r.rpf = { prefix: a, mask: m ?? '255.255.255.255', proto: num(rtProto.get(idx)) };
  }

  // outgoing interface list: index is group.source.mask.ifIndex.nextHopAddress
  for (const [idx, v] of nhState) {
    const p = idx.split('.'); if (p.length < 17) continue;
    const r = routes.get(keyOf(ip4(p, 0), ip4(p, 4))); if (!r) continue;
    const ifIndex = Number(p[12]); if (!Number.isFinite(ifIndex)) continue;
    r.oifs.push({ ifIndex, forwarding: num(v) === 2, pkts: num(nhPkts.get(idx)) });
  }
  for (const r of routes.values()) r.oifs.sort((a, b) => a.ifIndex - b.ifIndex);

  // Cisco adds the measured rate and the flags
  const bps = cisco ? await col(c, `${CROUTE}.19`) : EMPTY;
  let haveCisco = false;
  if (bps.size) {
    haveCisco = true;
    for (const [idx, v] of bps) { const p = idx.split('.'); const r = routes.get(keyOf(ip4(p, 0), ip4(p, 4))); if (r) r.bps = num(v); }
    const flagCols = await Promise.all(CFLAGS.map(([n]) => col(c, `${CROUTE}.${n}`)));
    CFLAGS.forEach(([, name], i) => {
      for (const [idx, v] of flagCols[i]!) { const p = idx.split('.'); const r = routes.get(keyOf(ip4(p, 0), ip4(p, 4))); if (r && num(v) === 1) r.flags.push(name); }
    });
  }

  // NX-OS publishes no IPMROUTE-STD-MIB. PIM-MIB still lists each (S,G) and (*,G) with its flags, indexed group.source.mask.
  let routeSource: 'ipmroute' | 'pim' = 'ipmroute';
  if (!routes.size) {
    const fl = await col(c, `${PIM_MROUTE}.5`);
    // the flags are a BITS value (rpt, spt); a (*,G) route is the shared tree and the rest are source trees, which is what the walk shows
    for (const idx of fl.keys()) { const r = add(idx); if (!r) continue; r.protocol = 8; r.flags = [r.source === '0.0.0.0' ? 'rpt' : 'spt']; }
    if (routes.size) routeSource = 'pim';
  }

  // the rendezvous point of each group: PIM-MIB pimRPTable is indexed group.rpAddress
  const [rpCol, rpSince] = await Promise.all([3, 5].map(n => col(c, `${PIM_RP}.${n}`)));
  const rpOf = new Map<string, string>();
  const rpGroups: NonNullable<Multicast['rpGroups']> = [];
  for (const [idx, v] of rpCol) {
    const p = idx.split('.'); if (p.length < 8) continue;
    rpOf.set(ip4(p, 0), ip4(p, 4));
    rpGroups.push({ group: ip4(p, 0), rp: ip4(p, 4), up: num(v) === 1, sinceSec: secs(rpSince.get(idx)) });
  }
  for (const r of routes.values()) r.rp = rpOf.get(r.group) ?? null;

  // IGMP: who joined which group on which interface. Indexed group.ifIndex
  const [igSelf, igRep, igExp] = await Promise.all([3, 4, 6].map(n => col(c, `${IGMP_CACHE}.${n}`)));
  const receivers: McReceiver[] = [];
  for (const [idx, v] of igRep) {
    const p = idx.split('.'); if (p.length < 5) continue;
    receivers.push({ group: ip4(p, 0), ifIndex: Number(p[4]), lastReporter: ipOf(v), expirySec: secs(igExp.get(idx)), self: num(igSelf.get(idx)) === 1 });
  }
  receivers.sort((a, b) => a.group.localeCompare(b.group, undefined, { numeric: true }) || a.ifIndex - b.ifIndex);

  const [pMode, pDr, pStatus] = await Promise.all([4, 5, 7].map(n => col(c, `${PIM_IF}.${n}`)));
  const MODES: Record<number, McPimIf['mode']> = { 1: 'dense', 2: 'sparse', 3: 'sparse-dense' };
  const pimInterfaces: McPimIf[] = [...pMode].map(([idx, v]) => {
    return { ifIndex: Number(idx), mode: MODES[num(v) ?? 0] ?? 'other', dr: ipOf(pDr.get(idx)) };
  }).filter(x => Number.isFinite(x.ifIndex) && (!pStatus.size || num(pStatus.get(String(x.ifIndex))) === 1));
  const nbrIf = await col(c, `${PIM_NBR}.2`);
  const neighbors: McNeighbor[] = [...nbrIf].map(([idx, v]) => ({ address: idx, ifIndex: num(v) ?? 0 })).filter(n => isIp(n.address));

  const igmpInterfaces = await readIgmpInterfaces(c);
  // the rendezvous point mappings: pimRPSetTable is indexed component.group.mask.rp
  const rpSet: McRpMap[] = [];
  const [hold, expiry2] = await Promise.all([4, 5].map(n => col(c, `${PIM_RPSET}.${n}`)));
  for (const k of new Set([...hold.keys(), ...expiry2.keys()])) {
    const p = k.split('.'); if (p.length < 13) continue;
    const g = ip4(p, 1), m = ip4(p, 5), rp = ip4(p, 9);
    if (isIp(g) && isIp(rp)) rpSet.push({ group: g, mask: m, rp, holdSec: num(hold.get(k)), expirySec: secs(expiry2.get(k)) });
  }
  rpSet.sort((a, b) => a.group.localeCompare(b.group, undefined, { numeric: true }) || a.rp.localeCompare(b.rp, undefined, { numeric: true }));
  const candidateRps: { group: string; mask: string; rp: string }[] = [];
  for (const [idx, v] of await col(c, `${PIM_CAND}.3`)) { const p = idx.split('.'); const rp = ipOf(v); if (p.length >= 8 && rp) candidateRps.push({ group: ip4(p, 0), mask: ip4(p, 4), rp }); }

  // per-interface multicast bytes: HC counters when the device has them
  const [hcIn, hcOut, lIn, lOut, ttl, lim] = await Promise.all([7, 8, 5, 6, 2, 4].map(n => col(c, `${MC_IF}.${n}`)));
  const big = (v: SnmpValue | undefined): number | null => { if (v === undefined || v === null) return null; const b = toBigInt(v); return b === null ? null : Number(b); };
  const interfaces: McIfLoad[] = [];
  for (const k of new Set([...hcIn.keys(), ...lIn.keys()])) {
    const ifIndex = Number(k); if (!Number.isInteger(ifIndex) || ifIndex <= 0) continue;
    interfaces.push({ ifIndex, inOctets: big(hcIn.get(k)) ?? big(lIn.get(k)), outOctets: big(hcOut.get(k)) ?? big(lOut.get(k)), inBps: null, outBps: null, ttl: num(ttl.get(k)), rateLimit: num(lim.get(k)) });
  }
  // without the multicast interface table (NX-OS), the IP counters count multicast octets per interface: HC in 37, HC out 41, indexed 1.ifIndex for IPv4
  if (!interfaces.length) {
    const [mIn, mOut] = await Promise.all([37, 41].map(n => col(c, `${IPIFSTATS}.${n}`)));
    for (const [k, v] of mIn) {
      const p = k.split('.'); if (p[0] !== '1') continue;
      const ifIndex = Number(p[1]), i = big(v), o = big(mOut.get(k));
      if (Number.isInteger(ifIndex) && ifIndex > 0 && ((i ?? 0) > 0 || (o ?? 0) > 0)) interfaces.push({ ifIndex, inOctets: i, outOctets: o, inBps: null, outBps: null, ttl: null, rateLimit: null });
    }
  }
  interfaces.sort((a, b) => a.ifIndex - b.ifIndex);

  // no per-group RP table: the RP of a group is the one whose range covers it most closely
  const covers = (r: McRpMap, g: string): boolean => { const size = 2 ** 32 - x32(r.mask), start = x32(r.group) - (x32(r.group) % size); return size < 2 ** 32 && x32(g) >= start && x32(g) < start + size; };
  for (const r of routes.values()) if (!r.rp) { const best = rpSet.filter(x => covers(x, r.group)).sort((a, b) => x32(b.mask) - x32(a.mask))[0]; if (best) r.rp = best.rp; }
  if (!routes.size && !receivers.length) return null;
  const names = await interfaceNames(c, [...routes.values()].flatMap(r => [r.inIfIndex ?? 0, ...r.oifs.map(o => o.ifIndex)]).concat(receivers.map(r => r.ifIndex), pimInterfaces.map(p => p.ifIndex), neighbors.map(n => n.ifIndex), interfaces.map(i => i.ifIndex)));
  const used = [...routes.values()].flatMap(r => r.oifs.map(o => o.ifIndex)).concat(receivers.map(r => r.ifIndex));
  const down = await interfacesDown(c, used);
  const list = [...routes.values()].sort((a, b) => a.group.localeCompare(b.group, undefined, { numeric: true }) || a.source.localeCompare(b.source, undefined, { numeric: true }));
  return { readAt: now, source: haveCisco ? 'cisco' : 'standard', routes: list, receivers, pimInterfaces, neighbors, routeSource, igmpInterfaces, rpGroups, rpSet, candidateRps, interfaces, names, down, truncated };
}

/** The last host to report each group on each interface (igmpCacheLastReporter), read on its own so it can be sampled often. */
export async function readIgmpReporters(c: SnmpClient): Promise<{ group: string; ifIndex: number; reporter: string }[]> {
  const rep = await col(c, `${IGMP_CACHE}.4`);
  const out: { group: string; ifIndex: number; reporter: string }[] = [];
  for (const [idx, v] of rep) {
    const p = idx.split('.'); if (p.length < 5) continue;
    const r = ipOf(v); if (!r || r === '0.0.0.0') continue;
    out.push({ group: ip4(p, 0), ifIndex: Number(p[4]), reporter: r });
  }
  return out;
}

/** ifName (or ifDescr) of each interface the multicast tables refer to, read with a few GETs. A device that will not answer just gives no names. */
export async function interfaceNames(c: SnmpClient, ifIndexes: number[]): Promise<Record<number, string>> {
  const want = [...new Set(ifIndexes.filter(n => Number.isInteger(n) && n > 0))].slice(0, 400);
  const out: Record<number, string> = {};
  if (!want.length || typeof c.get !== 'function') return out;
  for (const col of ['1.3.6.1.2.1.31.1.1.1.1', '1.3.6.1.2.1.2.2.1.2']) {
    const todo = want.filter(n => !out[n]);
    for (let i = 0; i < todo.length; i += 40) {
      try {
        const r = await c.get(todo.slice(i, i + 40).map(n => `${col}.${n}`));
        for (const [oid, vb] of r) { const n = Number(oid.slice(col.length + 1)); const s = vb.value === null || vb.value === undefined ? '' : toStr(vb.value as SnmpValue); if (n && s) out[n] = s; }
      } catch { break; }
    }
    if (want.every(n => out[n])) break;
  }
  return out;
}

/** Which of these interfaces are not up, read as ifOperStatus. An interface the device does not answer for is not reported. */
export async function interfacesDown(c: SnmpClient, ifIndexes: number[]): Promise<number[]> {
  const want = [...new Set(ifIndexes.filter(n => Number.isInteger(n) && n > 0))].slice(0, 400);
  const col = '1.3.6.1.2.1.2.2.1.8', out: number[] = [];
  if (!want.length || typeof c.get !== 'function') return out;
  for (let i = 0; i < want.length; i += 40) {
    try {
      const r = await c.get(want.slice(i, i + 40).map(n => `${col}.${n}`));
      for (const [oid, vb] of r) { const v = toNum(vb.value as SnmpValue); if (v !== null && v !== 1) out.push(Number(oid.slice(col.length + 1))); }
    } catch { break; }
  }
  return out;
}

/** What a device's multicast state says about one group: the routes for it and the interfaces its receivers sit behind. */
export interface GroupExpectation {
  group: string;
  /** The route that matches the stream's source, or the (*,G) route when the source has none of its own */
  route: McRoute | null;
  /** Interfaces the route forwards out of, which are where the traffic is expected to leave */
  expectedOut: number[];
  /** Interfaces in the list that are pruned */
  pruned: number[];
  /** Interfaces where a host reported the group through IGMP */
  joined: McReceiver[];
}

/** Picks the route a stream follows: the (S,G) route for its source, otherwise (*,G). */
export function expectationFor(m: Multicast, group: string, source: string): GroupExpectation {
  const routes = m.routes.filter(r => r.group === group);
  const route = routes.find(r => r.source === source) ?? routes.find(r => r.source === '0.0.0.0') ?? null;
  return {
    group, route,
    expectedOut: route ? route.oifs.filter(o => o.forwarding).map(o => o.ifIndex) : [],
    pruned: route ? route.oifs.filter(o => !o.forwarding).map(o => o.ifIndex) : [],
    joined: m.receivers.filter(r => r.group === group)
  };
}

/** How the interfaces NetFlow saw compare with the interfaces the device says it forwards to. */
export interface Comparison {
  /** In the device's list and also reported by NetFlow */
  confirmed: number[];
  /** In the device's list but never reported by NetFlow. Expected, since NetFlow records the ingress side */
  notSeen: number[];
  /** Reported by NetFlow as an outgoing interface but missing from the device's list */
  unexpected: number[];
  /** The interface the stream arrived on according to NetFlow differs from the route's incoming interface */
  inMismatch: { flow: number; route: number } | null;
}

export function compareOut(e: GroupExpectation, flowIn: number | null, flowOut: number[]): Comparison {
  const exp = new Set(e.expectedOut), seen = new Set(flowOut.filter(x => x > 0));
  const inRoute = e.route?.inIfIndex ?? null;
  return {
    confirmed: [...exp].filter(x => seen.has(x)).sort((a, b) => a - b),
    notSeen: [...exp].filter(x => !seen.has(x)).sort((a, b) => a - b),
    unexpected: [...seen].filter(x => !exp.has(x)).sort((a, b) => a - b),
    inMismatch: flowIn && inRoute && flowIn !== inRoute ? { flow: flowIn, route: inRoute } : null
  };
}

/** Fills in the bits per second of each interface from the previous read. A counter that went backwards, or an interval that is too long to mean anything, gives no figure. */
export function withLoadRates(m: Multicast, prev: Multicast | null): Multicast {
  if (!prev) return m;
  const dt = (m.readAt - prev.readAt) / 1000;
  if (dt <= 0 || dt > 3600) return m;
  // growth of each route's wrong-interface counter since the previous read
  const was = new Map(prev.routes.map(r => [r.group + '|' + r.source, r.rpfFail] as const));
  for (const r of m.routes) { const b = was.get(r.group + '|' + r.source); r.rpfNew = r.rpfFail == null || b == null || r.rpfFail < b ? null : r.rpfFail - b; }
  if (!m.interfaces || !prev.interfaces) return m;
  const old = new Map(prev.interfaces.map(i => [i.ifIndex, i]));
  const rate = (a: number | null, b: number | null | undefined) => (a === null || b === null || b === undefined || a < b ? null : Math.round(((a - b) * 8) / dt));
  for (const i of m.interfaces) { const o = old.get(i.ifIndex); if (o) { i.inBps = rate(i.inOctets, o.inOctets); i.outBps = rate(i.outOctets, o.outOctets); } }
  return m;
}

/** IGMP per interface: the querier, the version and the query timers. Indexed by ifIndex. */
export async function readIgmpInterfaces(c: SnmpClient): Promise<McIgmpIf[]> {
  const [interval, version, querier, upTime, expiry, status] = await Promise.all([2, 4, 5, 7, 8, 3].map(n => col(c, `${IGMP_IF}.${n}`)));
  const out: McIgmpIf[] = [];
  for (const k of new Set([...querier.keys(), ...version.keys()])) {
    const ifIndex = Number(k); if (!Number.isInteger(ifIndex) || ifIndex <= 0) continue;
    if (status.size && num(status.get(k)) !== 1) continue; // 2 is notInService: configured but not running
    const q = ipOf(querier.get(k));
    out.push({ ifIndex, querier: q && q !== '0.0.0.0' ? q : null, version: num(version.get(k)), queryIntervalSec: num(interval.get(k)), querierUpSec: secs(upTime.get(k)), querierExpirySec: secs(expiry.get(k)) });
  }
  return out.sort((a, b) => a.ifIndex - b.ifIndex);
}
