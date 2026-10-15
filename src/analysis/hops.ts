import type { FlowRecord } from '../collector/types.js';
import { appName, dscpName, protoName, service } from '../query/apps.js';
import { ttlEvidence } from './ttl.js';

export interface HopContext {
  deviceName(exporterIp: string): string;
  deviceRole(exporterIp: string): string;
  ifName(exporterIp: string, ifIndex: number): string;
  /** Egress queue statistics from SNMP for the hop's outgoing interface in the time window. */
  classDrops?(exporterIp: string, outIf: number, from: number, to: number, dscp: number): { cls: string; dropPct: number; dropPkts: number }[];
  /** Policy name attached to the outgoing interface, if known. */
  policyOf?(exporterIp: string, outIf: number): string | null;
  vlanName?(id: number): string;
  slowLinkMs?: number;
  /** Addresses of our own routers; traffic addressed to them is never reported as TTL-expired. */
  localIps?: ReadonlySet<string>;
}

/** An IPv4 group (224.0.0.0/4) or an IPv6 multicast address (ff00::/8). */
export function isMulticast(ip: string): boolean {
  if (ip.includes(':')) return /^ff/i.test(ip);
  const o = Number(ip.split('.')[0]);
  return o >= 224 && o <= 239;
}

export type ObsKind = 'loss' | 'slow' | 'remark' | 'qdrop' | 'nat' | 'path' | 'ttl' | 'info';
export interface Observation { kind: ObsKind; text: string; severity: 'info' | 'warn' | 'bad' }

/** What CDP / LLDP says is at the other end of a port, and which polled device that is when it is one of ours. */
export interface NeighborView {
  /** Both protocols when the device reports itself over CDP and LLDP. */
  protos: ('cdp' | 'lldp')[];
  name: string; port: string; ip: string; kind: string; caps: string[];
  /** The SNMP target this neighbour is, and the port on it that the cable ends in, so the console can open them. */
  device: { id: number; name: string } | null;
  devicePort: { ifIndex: number; name: string } | null;
}
/** Where a port name on a hop came from: the flow record itself, or filled in because the exporter did not report it. */
export type PortSource = 'flow' | 'reverse' | 'neighbor' | 'host';

/** A class that dropped at least this share of its packets in some poll is flagged on the stream. Below it the drops are only mentioned. */
const DROP_FLAG_PCT = 0.1;

export interface HopView {
  n: number;
  exporter: string;
  dev: string;
  role: string;
  inIf: string; outIf: string;
  /** SNMP ifIndex of the in and out interfaces as reported by the exporter; 0 when it did not say. */
  inIfIndex: number; outIfIndex: number;
  /** Set by the path enrichment (path.ts): the polled device for this exporter, how a missing port was worked out, and what is cabled to each port. */
  devId?: number | null; inFrom?: PortSource; outFrom?: PortSource;
  inNeighbors?: NeighborView[]; outNeighbors?: NeighborView[];
  /** Details this exporter does not send at all (MAC addresses, VLAN, TTL), so a blank means "not exported" and not "lost". Set by the route from the exporter's templates. */
  notExported?: string[];
  /** Every interface the traffic left through, busiest first. More than one on a multicast stream means the device replicated it. */
  outIfs: string[];
  /** Set on a multicast stream when SNMP data says the source host is plugged into this device: the port it is on, and whether the flow's ingress interface agrees. */
  sourcePort?: string | null; sourceConfirmed?: boolean;
  frameSrc: string | null; frameDst: string | null;
  vlan: number | null; vlanName: string;
  ttl: number | null;
  /** The TTL ran out at this hop ('ttl'), or this hop exported an ICMP Time Exceeded message ('icmp'). */
  ttlExpired: 'ttl' | 'icmp' | null;
  dscpIn: number; dscpOut: number | null;
  dscpInS: string; dscpOutS: string;
  qosChanged: boolean;
  pkts: number; bytes: number;
  firstSeen: number; lastSeen: number;
  linkMs: number | null; cumMs: number | null;
  policy: string | null;
  obs: Observation[];
}

/** One DSCP value seen on the packets of one direction of a stream. */
export interface MarkingValue { dscp: number; name: string; pkts: number; bytes: number; where: string[] }
export interface Marking { direction: 'forward' | 'reverse'; values: MarkingValue[] }

export interface StreamDetail {
  skey: string;
  initiator: { ip: string; port: number };
  responder: { ip: string; port: number };
  proto: number; protoName: string; app: string; appPort: number | null;
  t0: number; t1: number;
  forward: HopView[];
  reverse: HopView[];
  qosChanged: boolean;
  /** Directions whose packets carry more than one DSCP value (marking differs between records, even where no hop re-marks it). */
  marking: Marking[];
  /** The stream ran out of TTL before reaching its destination (or an ICMP Time Exceeded message was seen for it). */
  ttlExpired: boolean;
  totals: { fwdBytes: number; revBytes: number; fwdPkts: number; revPkts: number };
  note: string | null;
  /** Present for a multicast stream: one source, many receivers, so the devices are branches of a tree, not a path. */
  multicast: { group: string; source: string } | null;
}

interface Agg {
  exporter: string; recs: FlowRecord[]; pkts: number; bytes: number; t0: number; t1: number;
  ttl: number | null; tosIn: number; tosOut: number | null; inIf: number; outIf: number;
  macS: string | null; macD: string | null; vlan: number | null; nat: FlowRecord | null; multiPath: boolean; outIfs: number[];
  ttlLow: number | null; ttlWhy: 'ttl' | 'icmp' | null;
}

/**
 * A switch that exports on both input and output reports each packet twice, once from each monitor, and each half knows only one port:
 * the input monitor has the ingress interface and no egress (0), the output monitor the reverse. They are the same packets, so they are
 * one hop with one in port and one out port, and the packets and bytes are counted once. Records that carry both ports are left as they are.
 */
function halves(rs: FlowRecord[]): { inOnly: FlowRecord[]; outOnly: FlowRecord[] } | null {
  if (rs.some(r => r.inIf && r.outIf)) return null;
  const inOnly = rs.filter(r => r.inIf && !r.outIf), outOnly = rs.filter(r => !r.inIf && r.outIf);
  return inOnly.length && outOnly.length ? { inOnly, outOnly } : null;
}

function busiest(rs: FlowRecord[], key: (r: FlowRecord) => number): number {
  const by = new Map<number, number>();
  for (const r of rs) by.set(key(r), (by.get(key(r)) ?? 0) + r.bytes);
  let best = 0, bb = -1;
  for (const [k, b] of by) if (b > bb) { best = k; bb = b; }
  return best;
}

function aggregate(recs: FlowRecord[], local: ReadonlySet<string>, multicast = false): Agg[] {
  const by = new Map<string, FlowRecord[]>();
  for (const r of recs) { const a = by.get(r.exporter); if (a) a.push(r); else by.set(r.exporter, [r]); }
  const out: Agg[] = [];
  for (const [exporter, rs] of by) {
    let pkts = 0, bytes = 0, t0 = Infinity, t1 = 0, ttl: number | null = null;
    const ifBytes = new Map<string, number>();
    let nat: FlowRecord | null = null;
    let ttlLow: number | null = null, ttlWhy: 'ttl' | 'icmp' | null = null;
    for (const r of rs) {
      const ev = ttlEvidence(r, local);
      if (ev === 'ttl') { ttlWhy = 'ttl'; ttlLow = ttlLow === null ? r.ttlMin : Math.min(ttlLow, r.ttlMin as number); } else if (ev === 'icmp' && ttlWhy === null) ttlWhy = 'icmp';
      pkts += r.pkts; bytes += r.bytes; t0 = Math.min(t0, r.ts0); t1 = Math.max(t1, r.ts1);
      if (r.ttlMax !== null) ttl = ttl === null ? r.ttlMax : Math.max(ttl, r.ttlMax);
      const k = r.inIf + '>' + r.outIf; ifBytes.set(k, (ifBytes.get(k) ?? 0) + r.bytes);
      if (r.natSrcIp || r.natDstIp) nat = r;
    }
    let ii: number, oo: number;
    let main: FlowRecord;
    let outIfs: number[];
    let multiPath: boolean;
    const hv = halves(rs);
    if (hv) {
      // one pair, and the larger of the two halves as the count (they cover the same packets; the smaller one may just have been cut at the edge of the window)
      ii = busiest(hv.inOnly, r => r.inIf); oo = busiest(hv.outOnly, r => r.outIf);
      const sum = (a: FlowRecord[], k: 'pkts' | 'bytes') => a.reduce((t, r) => t + r[k], 0);
      // a multicast switch replicates, so its output side is larger than its input and the input side is the stream
      if (multicast || sum(hv.inOnly, 'bytes') >= sum(hv.outOnly, 'bytes')) { pkts = sum(hv.inOnly, 'pkts'); bytes = sum(hv.inOnly, 'bytes'); } else { pkts = sum(hv.outOnly, 'pkts'); bytes = sum(hv.outOnly, 'bytes'); }
      main = hv.inOnly.find(r => r.inIf === ii) ?? rs[0];
      // the MAC addresses and VLAN come from whichever half carries them
      if (main.srcMac === null || main.dstMac === null || main.vlan === null) {
        const pick = <T,>(f: (r: FlowRecord) => T | null): T | null => { for (const r of [main, ...hv.inOnly, ...hv.outOnly]) { const v = f(r); if (v !== null) return v; } return null; };
        main = { ...main, srcMac: pick(r => r.srcMac), dstMac: pick(r => r.dstMac), vlan: pick(r => r.vlan) };
      }
      const outBytes = new Map<number, number>();
      for (const r of hv.outOnly) outBytes.set(r.outIf, (outBytes.get(r.outIf) ?? 0) + r.bytes);
      outIfs = [...outBytes].sort((a, b) => b[1] - a[1]).map(([k]) => k);
      multiPath = new Set(hv.inOnly.map(r => r.inIf)).size > 1 || outBytes.size > 1;
    } else {
      let best = '', bb = -1;
      for (const [k, b] of ifBytes) if (b > bb) { best = k; bb = b; }
      [ii, oo] = best.split('>').map(Number);
      main = rs.find(r => r.inIf === ii && r.outIf === oo) ?? rs[0];
      outIfs = [...ifBytes].sort((a, b) => b[1] - a[1]).map(([k]) => Number(k.split('>')[1]));
      multiPath = ifBytes.size > 1;
    }
    const post = rs.find(r => r.postTos !== null && r.postTos !== undefined);
    out.push({
      exporter, recs: rs, pkts, bytes, t0, t1, ttl, tosIn: main.tos >> 2, tosOut: post && post.postTos !== null ? post.postTos >> 2 : null,
      inIf: ii, outIf: oo, macS: main.srcMac, macD: main.dstMac, vlan: main.vlan, nat, multiPath, ttlLow, ttlWhy, outIfs
    });
  }
  return out;
}

function order(a: Agg[]): Agg[] {
  const haveTtl = a.every(x => x.ttl !== null);
  return a.slice().sort((x, y) => {
    if (haveTtl && x.ttl !== y.ttl) return (y.ttl as number) - (x.ttl as number);
    return x.t0 - y.t0;
  });
}

function buildHops(recs: FlowRecord[], ctx: HopContext, multicast = false): HopView[] {
  if (!recs.length) return [];
  // Multicast is one source and many receivers. Every device on the distribution tree sees the same packets, so they are not in series:
  // there is no previous hop to compare with (loss, latency, DSCP change) and the TTL does not give an order across branches.
  const aggs = multicast
    ? aggregate(recs, ctx.localIps ?? new Set(), true).sort((x, y) => ctx.deviceName(x.exporter).localeCompare(ctx.deviceName(y.exporter)))
    : order(aggregate(recs, ctx.localIps ?? new Set()));
  const dest = recs[0].dstIp;
  const slow = ctx.slowLinkMs ?? 30;
  const hops: HopView[] = [];
  let cum = 0;
  aggs.forEach((a, i) => {
    const prev = i > 0 && !multicast ? aggs[i - 1] : null;
    const prevHop = i > 0 && !multicast ? hops[i - 1] : null;
    const obs: Observation[] = [];
    let linkMs: number | null = null;
    if (prev) {
      // Estimate from first-packet timestamps of the two exporters. Needs synchronised clocks, so only trust small non-negative values.
      const d = a.t0 - prev.t0;
      if (d >= 0 && d < 5000) { linkMs = d; cum += d; }
      else if (d < 0 && d > -50) { linkMs = 0; }
    }
    const cumMs = multicast ? null : i === 0 ? 0 : (linkMs === null ? null : cum);
    const dev = ctx.deviceName(a.exporter);
    const dscpOut = a.tosOut;
    const qosChanged = dscpOut !== null && dscpOut !== a.tosIn;
    if (qosChanged) obs.push({ kind: 'remark', severity: 'warn', text: `DSCP re-marked ${dscpName(a.tosIn)} → ${dscpName(dscpOut as number)} by the egress policy` });
    if (prevHop) {
      const before = prevHop.dscpOut ?? prevHop.dscpIn;
      if (before !== a.tosIn) obs.push({ kind: 'remark', severity: 'warn', text: `DSCP arrived as ${dscpName(a.tosIn)}; previous hop sent ${dscpName(before)}` });
    }
    if (linkMs !== null && linkMs >= slow) obs.push({ kind: 'slow', severity: 'warn', text: `Slow link: about ${linkMs.toFixed(0)} ms from ${prevHop!.dev}` });
    if (prev && a.recs.every(r => r.sampling <= 1) && prev.recs.every(r => r.sampling <= 1) && prev.pkts > 20) {
      const lost = prev.pkts - a.pkts;
      const pct = (100 * lost) / prev.pkts;
      if (lost > 0 && pct >= 1) obs.push({ kind: 'loss', severity: pct >= 5 ? 'bad' : 'warn', text: `${pct.toFixed(1)}% fewer packets than ${prevHop!.dev} (${lost} of ${prev.pkts}); loss on the link between them or at ${prevHop!.dev} egress` });
    }
    if (a.nat) {
      const r = a.nat;
      const to = `${r.natSrcIp ?? r.srcIp}${r.natSport ? ':' + r.natSport : ''} → ${r.natDstIp ?? r.dstIp}${r.natDport ? ':' + r.natDport : ''}`;
      obs.push({ kind: 'nat', severity: 'info', text: `NAT applied: ${to}` });
    }
    if (a.ttlWhy === 'ttl') obs.push({ kind: 'ttl', severity: 'bad', text: `TTL expired at ${dev}: packets arrived with TTL ${a.ttlLow} and could not be forwarded, so they did not reach ${dest}` });
    else if (a.ttlWhy === 'icmp') obs.push({ kind: 'ttl', severity: 'bad', text: `${dev} exported an ICMP Time Exceeded message: a router reported that a packet's TTL ran out on its way to ${dest}` });
    if (a.multiPath && multicast) obs.push({ kind: 'path', severity: 'info', text: `Replicated to ${new Set(a.outIfs).size} interfaces: ${a.outIfs.slice(0, 6).map(x => ctx.ifName(a.exporter, x)).join(', ')}${a.outIfs.length > 6 ? ', …' : ''}` });
    else if (a.multiPath) obs.push({ kind: 'path', severity: 'info', text: 'Traffic used more than one interface pair on this device (load sharing or a path change)' });
    const drops = ctx.classDrops?.(a.exporter, a.outIf, a.t0 - 120_000, a.t1 + 120_000, dscpOut ?? a.tosIn) ?? [];
    for (const d of drops) {
      if (d.dropPkts <= 0) continue;
      // The counters belong to the whole class on the port, over the whole life of the stream, not to this stream alone. A huge count at a tiny rate
      // (a busy class-default over many hours) is not a problem for the stream, so it is noted but not flagged.
      const peak = d.dropPct < 0.01 ? '<0.01%' : d.dropPct.toFixed(2) + '%';
      const where = `${ctx.ifName(a.exporter, a.outIf)}: class ${d.cls}`;
      if (d.dropPct >= DROP_FLAG_PCT) obs.push({ kind: 'qdrop', severity: d.dropPct >= 1 ? 'bad' : 'warn', text: `Egress queue drops on ${where} dropped ${peak} at worst (${d.dropPkts.toLocaleString()} packets in all) around this time` });
      else obs.push({ kind: 'qdrop', severity: 'info', text: `Egress queue on ${where} dropped ${d.dropPkts.toLocaleString()} packets over the life of this stream, at worst ${peak} of the class in any one poll. These counts are for the whole class on the port, not just this stream, and the rate is too low to matter.` });
    }
    hops.push({
      n: i + 1, exporter: a.exporter, dev, role: ctx.deviceRole(a.exporter),
      inIf: ctx.ifName(a.exporter, a.inIf), outIf: ctx.ifName(a.exporter, a.outIf), inIfIndex: a.inIf, outIfIndex: a.outIf, outIfs: [...new Set(a.outIfs)].filter(x => x).map(x => ctx.ifName(a.exporter, x)),
      frameSrc: a.macS, frameDst: a.macD, vlan: a.vlan, vlanName: a.vlan && ctx.vlanName ? ctx.vlanName(a.vlan) : '',
      ttl: a.ttl, ttlExpired: a.ttlWhy, dscpIn: a.tosIn, dscpOut, dscpInS: dscpName(a.tosIn), dscpOutS: dscpOut === null ? 'not reported' : dscpName(dscpOut), qosChanged,
      pkts: a.pkts, bytes: a.bytes, firstSeen: a.t0, lastSeen: a.t1, linkMs, cumMs,
      policy: ctx.policyOf?.(a.exporter, a.outIf) ?? null, obs
    });
  });
  return hops;
}

/** The DSCP values seen in one direction. Packets are counted once per DSCP at the exporter that saw the most of them, since two exporters see the same packets. */
function markingOf(recs: FlowRecord[], direction: 'forward' | 'reverse', ctx: HopContext): Marking | null {
  const by = new Map<number, { per: Map<string, { pkts: number; bytes: number }>; where: Set<string> }>();
  for (const r of recs) {
    const d = r.tos >> 2;
    const e = by.get(d) ?? { per: new Map(), where: new Set<string>() }; by.set(d, e);
    const x = e.per.get(r.exporter) ?? { pkts: 0, bytes: 0 }; x.pkts += r.pkts; x.bytes += r.bytes; e.per.set(r.exporter, x);
    e.where.add(`${ctx.deviceName(r.exporter)} ${ctx.ifName(r.exporter, r.inIf)} → ${ctx.ifName(r.exporter, r.outIf)}`);
  }
  if (by.size < 2) return null;
  const values = [...by].map(([dscp, e]) => ({ dscp, name: dscpName(dscp), pkts: Math.max(...[...e.per.values()].map(v => v.pkts)), bytes: Math.max(...[...e.per.values()].map(v => v.bytes)), where: [...e.where].slice(0, 6) }))
    .sort((a, b) => b.pkts - a.pkts);
  return { direction, values };
}

/** Works out the path a stream took from the flow records reported by each exporter. */
export function analyzeStream(skey: string, recs: (FlowRecord & { primary?: boolean })[], ctx: HopContext): StreamDetail | null {
  if (!recs.length) return null;
  // the initiator is the source of the earliest record
  const first = recs.slice().sort((a, b) => a.ts0 - b.ts0)[0];
  const fwdRecs = recs.filter(r => r.srcIp === first.srcIp && r.sport === first.sport);
  const revRecs = recs.filter(r => !(r.srcIp === first.srcIp && r.sport === first.sport));
  const mcast = isMulticast(first.dstIp);
  const forward = buildHops(fwdRecs, ctx, mcast);
  const reverse = buildHops(revRecs, ctx, mcast);
  const sum = (rs: (FlowRecord & { primary?: boolean })[], k: 'bytes' | 'pkts') => rs.filter(r => r.primary !== false).reduce((a, r) => a + r[k], 0);
  let note: string | null = null;
  if (mcast) note = null;
  else if (!reverse.length) note = 'Only one direction was exported. Check that the exporters report both ingress and egress traffic.';
  else if (reverse.length !== forward.length) note = 'The forward and reverse paths do not cross the same devices. The route may be asymmetric.';
  const all = [...forward, ...reverse];
  const marking = [markingOf(fwdRecs, 'forward', ctx), markingOf(revRecs, 'reverse', ctx)].filter((m): m is Marking => m !== null);
  return {
    skey, initiator: { ip: first.srcIp, port: first.sport }, responder: { ip: first.dstIp, port: first.dport },
    proto: first.proto, protoName: protoName(first.proto), app: appName(first.proto, first.sport, first.dport), appPort: service(first.proto, first.sport, first.dport).port,
    t0: Math.min(...recs.map(r => r.ts0)), t1: Math.max(...recs.map(r => r.ts1)),
    forward, reverse, qosChanged: all.some(h => h.qosChanged || h.obs.some(o => o.kind === 'remark')) || marking.length > 0, marking,
    ttlExpired: all.some(h => h.ttlExpired !== null),
    totals: { fwdBytes: sum(fwdRecs, 'bytes'), revBytes: sum(revRecs, 'bytes'), fwdPkts: sum(fwdRecs, 'pkts'), revPkts: sum(revRecs, 'pkts') },
    note, multicast: mcast ? { group: first.dstIp, source: first.srcIp } : null
  };
}
