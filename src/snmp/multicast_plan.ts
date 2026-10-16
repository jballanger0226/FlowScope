import { compareOut, expectationFor, type Multicast } from './multicast.js';

/**
 * "Where should this stream go": for one multicast stream, what each router says about the group (route, outgoing interfaces, who joined)
 * set beside what NetFlow saw. NetFlow records the interface a packet arrived on, so the outgoing list comes from the router itself.
 */

export type Level = 'ok' | 'info' | 'warn';
export interface PlanOut { ifIndex: number; name: string; state: 'forwarding' | 'pruned'; seenInFlow: boolean; joins: { reporter: string | null; expirySec: number | null; self: boolean }[]; neighbor: string | null; pkts: number | null }
export interface PlanDevice {
  devId: number; name: string; role: string;
  /** The device sent flow records for this stream */
  exported: boolean;
  readAt: number;
  /** The multicast state is older than a few polls, so it may not match what the network is doing now */
  stale: boolean;
  route: null | { source: string; inIf: string | null; inIfIndex: number | null; upstream: string | null; rp: string | null; bps: number | null; flags: string[]; protocol: number | null; expirySec: number | null; sharedTree: boolean };
  outgoing: PlanOut[];
  /** Hosts that joined the group on an interface the route does not forward to */
  strayJoins: { ifIndex: number; name: string; reporter: string | null }[];
  flow: { inIf: string | null; outIfs: string[] } | null;
  findings: { level: Level; text: string }[];
}
export interface Plan {
  group: string; source: string;
  devices: PlanDevice[];
  /** Interfaces (across the devices) the group is forwarded out of, and the hosts known to have joined */
  forwardingTo: number; joinedHosts: number;
  level: Level;
}

export interface PlanInput {
  group: string; source: string;
  /** Streams t0 and t1 */
  firstSeen: number; lastSeen: number;
  now: number;
  /** One entry per polled device that has multicast state */
  devices: { devId: number; name: string; role: string; mc: Multicast; ifName: (ifIndex: number) => string }[];
  /** What each exporter's flow records said, keyed by device id */
  flows: Map<number, { inIfs: number[]; outIfs: number[] }>;
}

const STALE_MS = 10 * 60_000;

export function buildPlan(inp: PlanInput): Plan {
  const out: PlanDevice[] = [];
  for (const d of inp.devices) {
    const e = expectationFor(d.mc, inp.group, inp.source);
    const fl = inp.flows.get(d.devId) ?? null;
    if (!e.route && !fl) continue;                      // a device that neither knows the group nor reported it is not part of this stream
    const nbr = new Map(d.mc.neighbors.map(n => [n.ifIndex, n.address]));
    const flowOut = fl?.outIfs ?? [];
    const flowIn = fl ? fl.inIfs[0] ?? null : null;
    const cmp = e.route ? compareOut(e, flowIn, flowOut) : null;
    const dev: PlanDevice = {
      devId: d.devId, name: d.name, role: d.role, exported: !!fl, readAt: d.mc.readAt, stale: inp.now - d.mc.readAt > STALE_MS,
      route: e.route ? {
        source: e.route.source, inIf: e.route.inIfIndex ? d.ifName(e.route.inIfIndex) : null, inIfIndex: e.route.inIfIndex, upstream: e.route.upstream, rp: e.route.rp,
        bps: e.route.bps, flags: e.route.flags, protocol: e.route.protocol, expirySec: e.route.expirySec, sharedTree: e.route.source === '0.0.0.0'
      } : null,
      outgoing: e.route ? e.route.oifs.map(o => ({
        ifIndex: o.ifIndex, name: d.ifName(o.ifIndex), state: o.forwarding ? 'forwarding' as const : 'pruned' as const, seenInFlow: flowOut.includes(o.ifIndex),
        joins: e.joined.filter(j => j.ifIndex === o.ifIndex).map(j => ({ reporter: j.lastReporter, expirySec: j.expirySec, self: j.self })), neighbor: nbr.get(o.ifIndex) ?? null, pkts: o.pkts
      })) : [],
      strayJoins: [], flow: fl ? { inIf: flowIn ? d.ifName(flowIn) : null, outIfs: [...new Set(flowOut)].filter(x => x > 0).map(d.ifName) } : null, findings: []
    };
    const inList = new Set(e.route?.oifs.map(o => o.ifIndex) ?? []);
    // a host on the interface the stream arrives on is on the source's own segment: it gets the packets at Layer 2 and the router never forwards them back out
    const inIfx = e.route?.inIfIndex ?? -1;
    const local = e.joined.filter(j => j.ifIndex === inIfx && !j.self);
    dev.strayJoins = e.joined.filter(j => !inList.has(j.ifIndex) && j.ifIndex !== inIfx).map(j => ({ ifIndex: j.ifIndex, name: d.ifName(j.ifIndex), reporter: j.lastReporter }));

    const f = dev.findings;
    if (!e.route) f.push({ level: 'warn', text: `${d.name} sent flow records for this stream but has no multicast route for ${inp.group} now. The route may have timed out since the flows were recorded, or the stream is routed in a different VRF.` });
    else {
      if (cmp?.inMismatch) f.push({ level: 'warn', text: `NetFlow shows the stream arriving on ${d.ifName(cmp.inMismatch.flow)}, but the multicast route expects it on ${d.ifName(cmp.inMismatch.route)}. The packets may be taking an unexpected path or failing the reverse-path check.` });
      if (cmp?.unexpected.length) f.push({ level: 'warn', text: `NetFlow reports the stream leaving ${cmp.unexpected.map(d.ifName).join(', ')}, which ${cmp.unexpected.length === 1 ? 'is' : 'are'} not in the router's list of forwarding interfaces. The receivers may have left since, or the flows are from an earlier route.` });
      const fwd = dev.outgoing.filter(o => o.state === 'forwarding');
      if (!fwd.length) f.push({ level: 'info', text: `${d.name} has a route for this stream but is forwarding it nowhere: no downstream receiver or PIM neighbour has asked for ${inp.group}${dev.outgoing.length ? ', and every interface in the list is pruned' : ''}. The traffic ends at this device.` });
      for (const s of dev.strayJoins) f.push({ level: 'warn', text: `A host${s.reporter ? ' (' + s.reporter + ')' : ''} joined ${inp.group} on ${s.name}, but the route does not forward there. That receiver is not getting this stream.` });
      if (local.length) f.push({ level: 'info', text: `${local.length} host${local.length === 1 ? '' : 's'} on ${d.ifName(inIfx)} (${local.slice(0, 3).map(j => j.lastReporter ?? '?').join(', ')}${local.length > 3 ? ', …' : ''}) joined the group on the segment the stream arrives on. They receive it directly from the switch, not through routing, so the router does not forward it back out of that interface.` });
      if (fwd.length && !f.some(x => x.level === 'warn')) f.push({ level: 'ok', text: `Forwarding to ${fwd.length} interface${fwd.length === 1 ? '' : 's'}${cmp && cmp.confirmed.length ? `; NetFlow also reported ${cmp.confirmed.length} of them` : ''}. ${cmp && cmp.notSeen.length && !cmp.confirmed.length ? 'NetFlow reports the ingress side, so the outgoing interfaces come from the router.' : ''}`.trim() });
      if (e.route.source === '0.0.0.0' && inp.source !== '0.0.0.0') f.push({ level: 'info', text: `This source has no (S,G) route of its own on ${d.name}; the shared (*,G) tree is used.` });
    }
    if (dev.stale) f.push({ level: 'info', text: `The multicast state of ${d.name} was read ${Math.round((inp.now - d.mc.readAt) / 60000)} minutes ago, so it may be out of date.` });
    if (e.route && inp.lastSeen < d.mc.readAt - STALE_MS) f.push({ level: 'info', text: `This stream was last seen before the router state was read, so the receivers shown are the ones now and may differ from the ones at the time of the flows.` });
    out.push(dev);
  }
  out.sort((a, b) => Number(b.exported) - Number(a.exported) || Number(!!b.route) - Number(!!a.route) || a.name.localeCompare(b.name));
  const level: Level = out.some(d => d.findings.some(f => f.level === 'warn')) ? 'warn' : out.length ? 'ok' : 'info';
  const joined = new Set<string>();
  for (const d of out) for (const o of d.outgoing) for (const j of o.joins) if (!j.self) joined.add(`${d.devId}/${o.ifIndex}/${j.reporter ?? ''}`);
  return { group: inp.group, source: inp.source, devices: out, forwardingTo: out.reduce((n, d) => n + d.outgoing.filter(o => o.state === 'forwarding').length, 0), joinedHosts: joined.size, level };
}
