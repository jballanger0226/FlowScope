/**
 * The SNMP contexts a device has configured, for the walk form. CISCO-CONTEXT-MAPPING-MIB cContextMappingTable (.1.3.6.1.4.1.9.9.468.1.1.1) is indexed by the
 * context name (length, then one sub-identifier per character) and its column .2 names the VRF the context belongs to. Where the device has no such table the
 * standard SNMP-VIEW-BASED-ACM-MIB vacmContextName column (.1.3.6.1.6.3.16.1.1.1.1) lists them. The default context (empty name) is not listed.
 *
 * Checked against a Catalyst 9300 walk: seven contexts, vrf-PCI, vrf-USER, vrf-GUEST and so on, each mapped to its VRF.
 */
import { toStr, type SnmpClient, type SnmpValue } from './client.js';

export interface SnmpContext { name: string; vrf: string }
const EMPTY = new Map<string, SnmpValue>();

/** The text an index spells: a length followed by that many character codes. */
export function nameFromIndex(index: string): string | null {
  const p = index.split('.').map(Number);
  if (p.some(n => !Number.isInteger(n) || n < 0 || n > 255) || p.length < 2 || p[0] !== p.length - 1) return null;
  return String.fromCharCode(...p.slice(1));
}

export async function readContexts(c: SnmpClient): Promise<SnmpContext[]> {
  const col = (oid: string) => c.column(oid, 50).catch(() => EMPTY);
  const out = new Map<string, SnmpContext>();
  for (const [k, v] of await col('1.3.6.1.4.1.9.9.468.1.1.1.2')) { const n = nameFromIndex(k); if (n) out.set(n, { name: n, vrf: toStr(v) }); }
  if (!out.size) for (const k of (await col('1.3.6.1.6.3.16.1.1.1.1')).keys()) { const n = nameFromIndex(k); if (n) out.set(n, { name: n, vrf: '' }); }
  return [...out.values()].sort((a, b) => a.name.localeCompare(b.name));
}
