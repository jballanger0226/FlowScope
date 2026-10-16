import type { Multicast } from './multicast.js';

/** One finding about the PIM setup of a device. `warn` can stop traffic, `info` is worth knowing. */
export interface PimIssue { level: 'warn' | 'info'; kind: 'mismatch' | 'mixed' | 'no-rp'; text: string }

/** A device FlowScope also polls, so the far end of a PIM link can be looked up. `ips` maps each of its addresses to the interface it sits on. */
export interface PimPeer { name: string; mc: Multicast; ips: Map<string, number>; ifName: (ix: number) => string }

const known = (m: string | undefined): m is 'dense' | 'sparse' | 'sparse-dense' => m === 'dense' || m === 'sparse' || m === 'sparse-dense';

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
  return out;
}
