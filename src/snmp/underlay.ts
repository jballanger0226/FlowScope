import type { Multicast } from './multicast.js';

/** One overlay group in one VRF and the underlay group (232.x) it is carried in. */
export interface OverlayGroup { vrf: string; group: string }

/**
 * SD-Access carries each overlay multicast group (in a VRF) in an underlay SSM group in the default VRF. The switch states the pairing on the routes it
 * encapsulates itself: the LISP outgoing interface's next-hop is the underlay group. Every other source of the same overlay group uses the same
 * underlay group, so a group is paired once any of its routes names it. A group this switch only receives has no pairing here.
 */
export function underlayMap(vrfs: { name: string; mc: Multicast }[]): { forward: Map<string, string>; reverse: Map<string, OverlayGroup[]> } {
  const forward = new Map<string, string>(), reverse = new Map<string, OverlayGroup[]>();
  for (const v of vrfs) for (const r of v.mc.routes) for (const o of r.oifs) {
    if (!o.underlay) continue;
    const k = v.name + '|' + r.group;
    if (forward.has(k)) continue;
    forward.set(k, o.underlay);
    const a = reverse.get(o.underlay) ?? []; a.push({ vrf: v.name, group: r.group }); reverse.set(o.underlay, a);
  }
  return { forward, reverse };
}
