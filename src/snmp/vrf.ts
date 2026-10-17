import type { SnmpClient } from './client.js';

/** A VRF on a device, and the interfaces that belong to it. */
export interface Vrf { name: string; ifIndexes: number[] }

/** device_data kind that holds the multicast state read in one VRF's SNMP context */
export const VRF_MC = 'mcast:';

/** The SNMP context a VRF is read in. A VRF named MEDIA is read as `vrf-MEDIA`, which is how the context is configured on the switch (snmp-server context vrf-MEDIA, snmp context vrf-MEDIA under the VRF). */
export const CONTEXT_PREFIX = 'vrf-';
export const contextOf = (vrf: string): string => CONTEXT_PREFIX + vrf;

/** MPLS-L3VPN-STD-MIB mplsL3VpnIfConfRowStatus, indexed length.name.ifIndex: which interface is in which VRF. */
const IF_CONF = '1.3.6.1.2.1.10.166.11.1.2.1.1.2';

/** Splits the index `3.80.67.73.433` into the VRF name (PCI) and the interface. Null when it is not shaped like that. */
export function parseVrfIndex(idx: string): { name: string; ifIndex: number } | null {
  const p = idx.split('.').map(Number);
  const n = p[0]!;
  if (!Number.isInteger(n) || n < 1 || n > 32 || p.length !== n + 2 || p.some(x => !Number.isInteger(x) || x < 0)) return null;
  const chars = p.slice(1, 1 + n);
  if (chars.some(x => x < 33 || x > 126)) return null;
  return { name: String.fromCharCode(...chars), ifIndex: p[n + 1]! };
}

/** The VRFs a device has, or null when it publishes none (not a Cisco with VRFs, or no MPLS-L3VPN-STD-MIB). */
export async function readVrfs(c: SnmpClient): Promise<Vrf[] | null> {
  const col = await c.column(IF_CONF, 50).catch(() => new Map<string, unknown>());
  const by = new Map<string, Set<number>>();
  for (const idx of col.keys()) { const x = parseVrfIndex(idx); if (!x) continue; const s = by.get(x.name) ?? new Set<number>(); s.add(x.ifIndex); by.set(x.name, s); }
  if (!by.size) return null;
  return [...by].map(([name, s]) => ({ name, ifIndexes: [...s].sort((a, b) => a - b) })).sort((a, b) => a.name.localeCompare(b.name));
}
