import type { FlowRecord } from '../collector/types.js';
import { appName, dscpName, protoName } from '../query/apps.js';

export interface HopContext {
  deviceName(exporterIp: string): string;
  deviceRole(exporterIp: string): string;
  ifName(exporterIp: string, ifIndex: number): string;
  /** Egress queue statistics from SNMP for the hop's outgoing interface in the time window. */
  classDrops?(exporterIp: string, outIf: number, from: number, to: number): { cls: string; dropPct: number; dropPkts: number }[];
  /** Policy name attached to the outgoing interface, if known. */
  policyOf?(exporterIp: string, outIf: number): string | null;
  vlanName?(id: number): string;
  slowLinkMs?: number;
}

export type ObsKind = 'loss' | 'slow' | 'remark' | 'qdrop' | 'nat' | 'path' | 'info';
export interface Observation { kind: ObsKind; text: string; severity: 'info' | 'warn' | 'bad' }

export interface HopView {
  n: number;
  exporter: string;
  dev: string;
  role: string;
  inIf: string; outIf: string;
  frameSrc: string | null; frameDst: string | null;
  vlan: number | null; vlanName: string;
  ttl: number | null;
  dscpIn: number; dscpOut: number | null;
  dscpInS: string; dscpOutS: string;
  qosChanged: boolean;
  pkts: number; bytes: number;
  firstSeen: number; lastSeen: number;
  linkMs: number | null; cumMs: number | null;
  policy: string | null;
  obs: Observation[];
}

export interface StreamDetail {
  skey: string;
  initiator: { ip: string; port: number };
  responder: { ip: string; port: number };
  proto: number; protoName: string; app: string;
  t0: number; t1: number;
  forward: HopView[];
  reverse: HopView[];
  qosChanged: boolean;
  totals: { fwdBytes: number; revBytes: number; fwdPkts: number; revPkts: number };
  note: string | null;
}

interface Agg {
  exporter: string; recs: FlowRecord[]; pkts: number; bytes: number; t0: number; t1: number;
  ttl: number | null; tosIn: number; tosOut: number | null; inIf: number; outIf: number;
  macS: string | null; macD: string | null; vlan: number | null; nat: FlowRecord | null; multiPath: boolean;
}

function aggregate(recs: FlowRecord[]): Agg[] {
  const by = new Map<string, FlowRecord[]>();
  for (const r of recs) { const a = by.get(r.exporter); if (a) a.push(r); else by.set(r.exporter, [r]); }
  const out: Agg[] = [];
  for (const [exporter, rs] of by) {
    let pkts = 0, bytes = 0, t0 = Infinity, t1 = 0, ttl: number | null = null;
    const ifBytes = new Map<string, number>();
    let nat: FlowRecord | null = null;
    for (const r of rs) {
      pkts += r.pkts; bytes += r.bytes; t0 = Math.min(t0, r.ts0); t1 = Math.max(t1, r.ts1);
      if (r.ttlMax !== null) ttl = ttl === null ? r.ttlMax : Math.max(ttl, r.ttlMax);
      const k = r.inIf + '>' + r.outIf; ifBytes.set(k, (ifBytes.get(k) ?? 0) + r.bytes);
      if (r.natSrcIp || r.natDstIp) nat = r;
    }
    let best = '', bb = -1;
    for (const [k, b] of ifBytes) if (b > bb) { best = k; bb = b; }
    const [ii, oo] = best.split('>').map(Number);
    const main = rs.find(r => r.inIf === ii && r.outIf === oo) ?? rs[0];
    const post = rs.find(r => r.postTos !== null && r.postTos !== undefined);
    out.push({
      exporter, recs: rs, pkts, bytes, t0, t1, ttl, tosIn: main.tos >> 2, tosOut: post && post.postTos !== null ? post.postTos >> 2 : null,
      inIf: ii, outIf: oo, macS: main.srcMac, macD: main.dstMac, vlan: main.vlan, nat, multiPath: ifBytes.size > 1
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

function buildHops(recs: FlowRecord[], ctx: HopContext): HopView[] {
  if (!recs.length) return [];
  const aggs = order(aggregate(recs));
  const slow = ctx.slowLinkMs ?? 30;
  const hops: HopView[] = [];
  let cum = 0;
  aggs.forEach((a, i) => {
    const prev = i > 0 ? aggs[i - 1] : null;
    const prevHop = i > 0 ? hops[i - 1] : null;
    const obs: Observation[] = [];
    let linkMs: number | null = null;
    if (prev) {
      // Estimate from first-packet timestamps of the two exporters. Needs synchronised clocks, so only trust small non-negative values.
      const d = a.t0 - prev.t0;
      if (d >= 0 && d < 5000) { linkMs = d; cum += d; }
      else if (d < 0 && d > -50) { linkMs = 0; }
    }
    const cumMs = i === 0 ? 0 : (linkMs === null ? null : cum);
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
    if (a.multiPath) obs.push({ kind: 'path', severity: 'info', text: 'Traffic used more than one interface pair on this device (load sharing or a path change)' });
    const drops = ctx.classDrops?.(a.exporter, a.outIf, a.t0 - 120_000, a.t1 + 120_000) ?? [];
    for (const d of drops) {
      if (d.dropPkts > 0) obs.push({ kind: 'qdrop', severity: d.dropPct >= 1 ? 'bad' : 'warn', text: `Egress queue drops on ${ctx.ifName(a.exporter, a.outIf)}: class ${d.cls} dropped ${d.dropPct.toFixed(2)}% (${d.dropPkts} packets) around this time` });
    }
    hops.push({
      n: i + 1, exporter: a.exporter, dev, role: ctx.deviceRole(a.exporter),
      inIf: ctx.ifName(a.exporter, a.inIf), outIf: ctx.ifName(a.exporter, a.outIf),
      frameSrc: a.macS, frameDst: a.macD, vlan: a.vlan, vlanName: a.vlan && ctx.vlanName ? ctx.vlanName(a.vlan) : '',
      ttl: a.ttl, dscpIn: a.tosIn, dscpOut, dscpInS: dscpName(a.tosIn), dscpOutS: dscpOut === null ? 'not reported' : dscpName(dscpOut), qosChanged,
      pkts: a.pkts, bytes: a.bytes, firstSeen: a.t0, lastSeen: a.t1, linkMs, cumMs,
      policy: ctx.policyOf?.(a.exporter, a.outIf) ?? null, obs
    });
  });
  return hops;
}

/** Works out the path a stream took from the flow records reported by each exporter. */
export function analyzeStream(skey: string, recs: (FlowRecord & { primary?: boolean })[], ctx: HopContext): StreamDetail | null {
  if (!recs.length) return null;
  // the initiator is the source of the earliest record
  const first = recs.slice().sort((a, b) => a.ts0 - b.ts0)[0];
  const fwdRecs = recs.filter(r => r.srcIp === first.srcIp && r.sport === first.sport);
  const revRecs = recs.filter(r => !(r.srcIp === first.srcIp && r.sport === first.sport));
  const forward = buildHops(fwdRecs, ctx);
  const reverse = buildHops(revRecs, ctx);
  const sum = (rs: (FlowRecord & { primary?: boolean })[], k: 'bytes' | 'pkts') => rs.filter(r => r.primary !== false).reduce((a, r) => a + r[k], 0);
  let note: string | null = null;
  if (!reverse.length) note = 'Only one direction was exported. Check that the exporters report both ingress and egress traffic.';
  else if (reverse.length !== forward.length) note = 'The forward and reverse paths do not cross the same devices. The route may be asymmetric.';
  const all = [...forward, ...reverse];
  return {
    skey, initiator: { ip: first.srcIp, port: first.sport }, responder: { ip: first.dstIp, port: first.dport },
    proto: first.proto, protoName: protoName(first.proto), app: appName(first.proto, first.sport, first.dport),
    t0: Math.min(...recs.map(r => r.ts0)), t1: Math.max(...recs.map(r => r.ts1)),
    forward, reverse, qosChanged: all.some(h => h.qosChanged || h.obs.some(o => o.kind === 'remark')),
    totals: { fwdBytes: sum(fwdRecs, 'bytes'), revBytes: sum(revRecs, 'bytes'), fwdPkts: sum(fwdRecs, 'pkts'), revPkts: sum(revRecs, 'pkts') },
    note
  };
}
