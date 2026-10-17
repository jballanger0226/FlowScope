import type { Vrf } from './vrf.js';

/**
 * A switch port has no VRF of its own: the VRF belongs to the SVI of the VLAN the port is in (`vrf forwarding X` on interface VlanN), so a port and the
 * hosts plugged into it are in that VRF. These helpers work that out. The default VRF is the empty string.
 */

/** VLAN number → VRF, from the VRF's VLAN interfaces (Vl3035, Vlan3035). */
export function vlanVrfMap(vrfs: Vrf[], nameOf: (ifIndex: number) => string): Map<number, string> {
  const out = new Map<number, string>();
  for (const v of vrfs) for (const ix of v.ifIndexes) { const m = /^(?:vl|vlan)\s*(\d+)$/i.exec(nameOf(ix).trim()); if (m) out.set(Number(m[1]), v.name); }
  return out;
}

/** The VLAN numbers in an allowed list like "10,20-30" ('all' is every VLAN the map knows). */
function listVlans(list: string, known: Iterable<number>): number[] {
  if (!list) return [];
  if (list === 'all') return [...known];
  const out: number[] = [];
  for (const p of list.split(',')) { const [lo, hi] = p.split('-').map(Number); if (lo === undefined || !Number.isFinite(lo)) continue; const to = hi === undefined || !Number.isFinite(hi) ? lo : hi; if (to - lo > 4096) continue; for (let v = lo; v <= to; v++) out.push(v); }
  return out;
}

export interface IfVrf {
  /** The VRF name(s), comma separated when a port reaches more than one; '' is the default VRF */
  vrf: string;
  /** 'interface' when the interface itself is in the VRF (an SVI or a routed port), 'vlan' when its VLAN's SVI is, 'vlans' for a trunk carrying VLANs of several */
  via: 'interface' | 'vlan' | 'vlans';
}

/** The VRF of an interface, or null when none of what it connects to is in a VRF (it is in the default VRF). */
export function ifaceVrf(i: { ifIndex: number; portMode: string; vlan: number; voiceVlan: number; vlanList: string }, direct: Map<number, string>, byVlan: Map<number, string>): IfVrf | null {
  const d = direct.get(i.ifIndex);
  if (d) return { vrf: d, via: 'interface' };
  if (i.portMode === 'trunk') {
    const v = [...new Set(listVlans(i.vlanList, byVlan.keys()).map(x => byVlan.get(x)).filter((x): x is string => !!x))].sort();
    return v.length ? { vrf: v.join(', '), via: 'vlans' } : null;
  }
  if (i.portMode === 'svi' || i.portMode === 'routed') return null;
  const v = [...new Set([i.vlan, i.voiceVlan].map(x => (x ? byVlan.get(x) : undefined)).filter((x): x is string => !!x))];
  return v.length ? { vrf: v.join(', '), via: 'vlan' } : null;
}
