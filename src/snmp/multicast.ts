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
import { toNum, type SnmpClient, type SnmpValue } from './client.js';

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
}
export interface McReceiver { group: string; ifIndex: number; lastReporter: string | null; expirySec: number | null; self: boolean }
export interface McPimIf { ifIndex: number; mode: 'dense' | 'sparse' | 'sparse-dense' | 'other'; dr: string | null }
export interface McNeighbor { address: string; ifIndex: number }
export interface Multicast {
  readAt: number;
  /** 'cisco' when the Cisco table (rates, flags) was available, otherwise 'standard' */
  source: 'cisco' | 'standard';
  routes: McRoute[];
  receivers: McReceiver[];
  pimInterfaces: McPimIf[];
  neighbors: McNeighbor[];
  /** The tables held more rows than were kept */
  truncated: boolean;
}

export const MAX_ROUTES = 20_000;

const ROUTE = '1.3.6.1.2.1.83.1.1.2.1';
const NEXTHOP = '1.3.6.1.2.1.83.1.1.3.1';
const CROUTE = '1.3.6.1.4.1.9.10.2.1.1.2.1';
const IGMP_CACHE = '1.3.6.1.2.1.85.1.2.1';
const PIM_IF = '1.3.6.1.3.61.1.1.2.1';
const PIM_NBR = '1.3.6.1.3.61.1.1.3.1';
const PIM_RP = '1.3.6.1.3.61.1.1.5.1';

/** Cisco route flags in the order of their columns (12 to 18 and 25 to 27); 1 is true, 2 is false. */
const CFLAGS: [number, string][] = [[12, 'prune'], [13, 'sparse'], [14, 'connected'], [15, 'local'], [16, 'register'], [17, 'rp-tree'], [18, 'spt'], [25, 'join'], [26, 'msdp'], [27, 'proxy-join']];

const ip4 = (p: string[], at: number): string => p.slice(at, at + 4).join('.');
/** An IpAddress value: net-snmp hands back dotted text, but four raw bytes are accepted too. */
const ipOf = (v: SnmpValue | undefined): string | null => {
  if (v === undefined || v === null) return null;
  const t = Buffer.isBuffer(v) ? (v.length === 4 ? [...v].join('.') : '') : String(v);
  return isIp(t) && t !== '0.0.0.0' ? t : null;
};
const num = (v: SnmpValue | undefined): number | null => (v === undefined || v === null ? null : toNum(v));
const EMPTY = new Map<string, SnmpValue>();
const col = (c: SnmpClient, oid: string) => c.column(oid, 50).catch(() => EMPTY);
const keyOf = (g: string, s: string) => g + '|' + s;
/** A TimeTicks value (hundredths of a second) as whole seconds. */
const secs = (v: SnmpValue | undefined): number | null => { const n = num(v); return n === null ? null : Math.round(n / 100); };
/** Whether a 4-part index looks like an IPv4 address; guards against indexes the table does not have */
const isIp = (s: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s);

/** Reads the multicast routing table. Returns null when the device publishes none of it. */
export async function readMulticast(c: SnmpClient, now = Date.now()): Promise<Multicast | null> {
  const [up, inIf, expiry, pkts, proto] = await Promise.all([4, 5, 7, 8, 11].map(n => col(c, `${ROUTE}.${n}`)));
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

  // outgoing interface list: index is group.source.mask.ifIndex.nextHopAddress
  for (const [idx, v] of nhState) {
    const p = idx.split('.'); if (p.length < 17) continue;
    const r = routes.get(keyOf(ip4(p, 0), ip4(p, 4))); if (!r) continue;
    const ifIndex = Number(p[12]); if (!Number.isFinite(ifIndex)) continue;
    r.oifs.push({ ifIndex, forwarding: num(v) === 2, pkts: num(nhPkts.get(idx)) });
  }
  for (const r of routes.values()) r.oifs.sort((a, b) => a.ifIndex - b.ifIndex);

  // Cisco adds the measured rate and the flags
  const bps = await col(c, `${CROUTE}.19`);
  let cisco = false;
  if (bps.size) {
    cisco = true;
    for (const [idx, v] of bps) { const p = idx.split('.'); const r = routes.get(keyOf(ip4(p, 0), ip4(p, 4))); if (r) r.bps = num(v); }
    const flagCols = await Promise.all(CFLAGS.map(([n]) => col(c, `${CROUTE}.${n}`)));
    CFLAGS.forEach(([, name], i) => {
      for (const [idx, v] of flagCols[i]!) { const p = idx.split('.'); const r = routes.get(keyOf(ip4(p, 0), ip4(p, 4))); if (r && num(v) === 1) r.flags.push(name); }
    });
  }

  // the rendezvous point of each group: PIM-MIB pimRPTable is indexed group.rpAddress
  const rpCol = await col(c, `${PIM_RP}.3`);
  const rpOf = new Map<string, string>();
  for (const [idx] of rpCol) { const p = idx.split('.'); if (p.length >= 8) rpOf.set(ip4(p, 0), ip4(p, 4)); }
  for (const r of routes.values()) r.rp = rpOf.get(r.group) ?? null;

  // IGMP: who joined which group on which interface. Indexed group.ifIndex
  const [igSelf, igRep, igExp] = await Promise.all([3, 4, 6].map(n => col(c, `${IGMP_CACHE}.${n}`)));
  const receivers: McReceiver[] = [];
  for (const [idx, v] of igRep) {
    const p = idx.split('.'); if (p.length < 5) continue;
    receivers.push({ group: ip4(p, 0), ifIndex: Number(p[4]), lastReporter: ipOf(v), expirySec: secs(igExp.get(idx)), self: num(igSelf.get(idx)) === 1 });
  }
  receivers.sort((a, b) => a.group.localeCompare(b.group, undefined, { numeric: true }) || a.ifIndex - b.ifIndex);

  const [pMode, pDr] = await Promise.all([4, 5].map(n => col(c, `${PIM_IF}.${n}`)));
  const MODES: Record<number, McPimIf['mode']> = { 1: 'dense', 2: 'sparse', 3: 'sparse-dense' };
  const pimInterfaces: McPimIf[] = [...pMode].map(([idx, v]) => {
    return { ifIndex: Number(idx), mode: MODES[num(v) ?? 0] ?? 'other', dr: ipOf(pDr.get(idx)) };
  }).filter(x => Number.isFinite(x.ifIndex));
  const nbrIf = await col(c, `${PIM_NBR}.2`);
  const neighbors: McNeighbor[] = [...nbrIf].map(([idx, v]) => ({ address: idx, ifIndex: num(v) ?? 0 })).filter(n => isIp(n.address));

  if (!routes.size && !receivers.length) return null;
  const list = [...routes.values()].sort((a, b) => a.group.localeCompare(b.group, undefined, { numeric: true }) || a.source.localeCompare(b.source, undefined, { numeric: true }));
  return { readAt: now, source: cisco ? 'cisco' : 'standard', routes: list, receivers, pimInterfaces, neighbors, truncated };
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
