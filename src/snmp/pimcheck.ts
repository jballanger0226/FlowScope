import type { Multicast } from './multicast.js';

/** One finding about the PIM setup of a device. `warn` can stop traffic, `info` is worth knowing. */
export interface PimIssue { level: 'warn' | 'info'; kind: 'rp-down' | 'mismatch' | 'link-loss' | 'mixed' | 'no-rp' | 'no-querier' | 'rpf' | 'rp-unknown'; text: string }

/** A device FlowScope also polls, so the far end of a PIM link can be looked up. `ips` maps each of its addresses to the interface it sits on. */
export interface PimPeer { name: string; mc: Multicast; ips: Map<string, number>; ifName: (ix: number) => string }

const known = (m: string | undefined): m is 'dense' | 'sparse' | 'sparse-dense' => m === 'dense' || m === 'sparse' || m === 'sparse-dense';

/** Multicast that one end of a PIM link sends and the other end does not receive. Both ends count multicast per interface, so on a routed link the two rates should agree. */
export interface McLoss { ifIndex: number; peer: string; peerIf: string; inBps: number; outBps: number }
export function multicastLoss(mc: Multicast, peers: PimPeer[]): McLoss[] {
  const out: McLoss[] = [];
  for (const n of mc.neighbors) {
    const peer = peers.find(p => p.ips.has(n.address)); if (!peer) continue;
    const theirIf = peer.ips.get(n.address)!;
    const ours = mc.interfaces?.find(i => i.ifIndex === n.ifIndex)?.inBps, theirs = peer.mc.interfaces?.find(i => i.ifIndex === theirIf)?.outBps;
    if (ours == null || theirs == null) continue;
    // the two reads are not taken at the same moment, so small differences are ignored
    if (theirs >= 500_000 && theirs - ours >= 250_000 && ours < theirs * 0.9 && !out.some(o => o.ifIndex === n.ifIndex)) out.push({ ifIndex: n.ifIndex, peer: peer.name, peerIf: peer.ifName(theirIf), inBps: ours, outBps: theirs });
  }
  return out;
}
const mbps = (b: number): string => (b >= 1e9 ? (b / 1e9).toFixed(2) + ' Gbps' : b >= 1e6 ? (b / 1e6).toFixed(1) + ' Mbps' : Math.round(b / 1e3) + ' kbps');

/**
 * Checks that explain why multicast is flooded, missing or half working:
 *  - the two ends of a PIM link run different modes (dense against sparse breaks forwarding: one side floods and waits for prunes,
 *    the other sends joins to a rendezvous point and expects them to be answered; sparse against sparse-dense only differs for groups with no RP);
 *  - one router runs a mix of modes on its routed interfaces;
 *  - a group runs dense on a router that is sparse-dense because it has no rendezvous point.
 * The far end of a link can only be checked when that device is polled too; otherwise it is left out rather than guessed.
 */
export function pimIssues(mc: Multicast, ifName: (ix: number) => string, peers: PimPeer[]): PimIssue[] {
  const out: PimIssue[] = [];
  const mine = new Map(mc.pimInterfaces.map(p => [p.ifIndex, p.mode] as const));

  for (const n of mc.neighbors) {
    const my = mine.get(n.ifIndex);
    const peer = peers.find(p => p.ips.has(n.address));
    if (!peer || !known(my)) continue;
    const theirIf = peer.ips.get(n.address)!;
    const their = peer.mc.pimInterfaces.find(p => p.ifIndex === theirIf)?.mode;
    if (!known(their) || their === my) continue;
    const dense = my === 'dense' || their === 'dense';
    out.push({
      level: dense ? 'warn' : 'info', kind: 'mismatch',
      text: dense
        ? `${ifName(n.ifIndex)} runs PIM ${my}, but ${peer.name} runs ${their} on ${peer.ifName(theirIf)}. Dense mode floods and waits for prunes, sparse mode sends joins to the rendezvous point, so the two ends do not agree on what to forward.`
        : `${ifName(n.ifIndex)} runs PIM ${my}, but ${peer.name} runs ${their} on ${peer.ifName(theirIf)}. This only differs for groups that have no rendezvous point, which the sparse-dense side runs dense.`
    });
  }

  for (const l of multicastLoss(mc, peers)) out.push({ level: 'warn', kind: 'link-loss', text: `Multicast is lost between ${l.peer} ${l.peerIf} and ${ifName(l.ifIndex)}: ${l.peer} sends ${mbps(l.outBps)} out of it and this router receives ${mbps(l.inBps)}. Look at errors, discards and multicast limits on both interfaces.` });

  // loopbacks are the router's own addresses, so only interfaces that carry traffic count towards a mix
  const modes = new Set(mc.pimInterfaces.filter(p => !/^(lo|loopback)\d+$/i.test(ifName(p.ifIndex))).map(p => p.mode).filter(known));
  if (modes.size > 1) {
    const by = new Map<string, string[]>();
    for (const p of mc.pimInterfaces) if (known(p.mode) && !/^(lo|loopback)\d+$/i.test(ifName(p.ifIndex))) by.set(p.mode, [...(by.get(p.mode) ?? []), ifName(p.ifIndex)]);
    out.push({ level: 'info', kind: 'mixed', text: `This router runs more than one PIM mode: ${[...by].map(([m, l]) => `${m} on ${l.length > 3 ? l.slice(0, 3).join(', ') + ` and ${l.length - 3} more` : l.join(', ')}`).join('; ')}.` });
  }

  if (mc.pimInterfaces.some(p => p.mode === 'sparse-dense')) {
    const sd = new Set(mc.pimInterfaces.filter(p => p.mode === 'sparse-dense').map(p => p.ifIndex));
    // 224.0.1.39 and .40 are Auto-RP itself and are meant to run dense
    const dense = [...new Set(mc.routes.filter(r => r.protocol === 9 && !r.rp && !/^224\.0\.1\.(39|40)$/.test(r.group) && ((r.inIfIndex !== null && sd.has(r.inIfIndex)) || r.oifs.some(o => sd.has(o.ifIndex)))).map(r => r.group))];
    if (dense.length) out.push({ level: 'warn', kind: 'no-rp', text: `${dense.length === 1 ? 'A group runs' : dense.length + ' groups run'} dense on a sparse-dense interface because no rendezvous point is known for ${dense.length === 1 ? 'it' : 'them'}: ${dense.slice(0, 5).join(', ')}${dense.length > 5 ? ` and ${dense.length - 5} more` : ''}. Check that the RP is reachable and its group range covers ${dense.length === 1 ? 'it' : 'them'}.` });
  }

  // an interface with joined hosts and no IGMP querier: nothing refreshes the memberships, so they time out and the group stops
  const noQuerier = (mc.igmpInterfaces ?? []).filter(i => !i.querier && mc.receivers.some(r => r.ifIndex === i.ifIndex)).map(i => ifName(i.ifIndex));
  if (noQuerier.length) out.push({ level: 'warn', kind: 'no-querier', text: `No IGMP querier is reported on ${noQuerier.slice(0, 4).join(', ')}${noQuerier.length > 4 ? ` and ${noQuerier.length - 4} more` : ''}, which has hosts that joined. Without a querier, memberships are not refreshed and groups stop after the timeout.` });

  // packets that arrived on a different interface than the one the route accepts the group on (ipMRouteDifferentInIfPackets). The counter runs since the
  // route was created, so only growth between two reads means it is happening now; a small total on an old route is usually a path change or an equal-cost path.
  const growing = mc.routes.filter(r => (r.rpfNew ?? 0) > 0).sort((a, b) => (b.rpfNew ?? 0) - (a.rpfNew ?? 0));
  const before = mc.routes.filter(r => (r.rpfFail ?? 0) > 0 && !(r.rpfNew ?? 0)).sort((a, b) => (b.rpfFail ?? 0) - (a.rpfFail ?? 0));
  const nm = (r: Multicast['routes'][number]): string => (r.source === '0.0.0.0' ? r.group : r.source + ', ' + r.group);
  const n = (v: number): string => v.toLocaleString('en-US');
  if (growing.length) out.push({ level: 'warn', kind: 'rpf', text: `${growing.length} route${growing.length === 1 ? ' is' : 's are'} dropping packets that arrive on the wrong interface right now (RPF check), most on ${nm(growing[0]!)} (${n(growing[0]!.rpfNew!)} since the last read). Traffic is coming in on an interface other than the one the route accepts it on. This happens when two equal-cost paths both deliver the group, or when the unicast route to the source has changed.` });
  else if (before.length) out.push({ level: 'info', kind: 'rpf', text: `${before.length} route${before.length === 1 ? ' has' : 's have'} dropped some packets that arrived on the wrong interface since ${before.length === 1 ? 'it was' : 'they were'} created, most on ${nm(before[0]!)} (${n(before[0]!.rpfFail!)}). None is growing between reads, so this is history, not a current problem.` });

  // sparse mode with no rendezvous point mapped at all
  if (mc.rpSet && !mc.rpSet.length && !(mc.rpGroups ?? []).length && !(mc.candidateRps ?? []).length && mc.pimInterfaces.some(p => p.mode === 'sparse') && !mc.routes.some(r => r.rp)) out.push({ level: 'info', kind: 'rp-unknown', text: 'PIM sparse mode is on, but this router lists no rendezvous point. That is normal when only source-specific multicast is used. Otherwise check the RP configuration.' });
  return out;
}
