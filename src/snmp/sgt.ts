/**
 * Security group tags (TrustSec) of hosts, from CISCO-TRUSTSEC-POLICY-MIB ctspIpSgtTable (1.3.6.1.4.1.9.9.713.1.4.1.1): the tag a switch applies to each
 * IP address, which on an SD-Access edge is the one its authentication session was given. Index is <VRF name as length.chars>.<address type 1>.<4>.<four
 * address bytes>.<prefix length>; col 5 is the tag (ctspIpSgtValue), col 6 where it came from (3 localAuthenticated, 5 internal). The names of the tags
 * are in CISCO-TRUSTSEC-MIB ctsEnvSecurityGroupName (1.3.6.1.4.1.9.9.730.1.4.16.1.4.<tag>).
 *
 * Checked against a full walk of a Catalyst 9300 stack acting as an SD-Access edge (116 bindings, 34 of them localAuthenticated: 10.135.159.203 in VRF DEVICE
 * is tag 74, named DEVICE_CAMERA), and against `show authentication sessions interface Te1/0/7 details` (SGT Value: 74).
 */
import { toNum, type SnmpClient, type SnmpValue } from './client.js';

export interface IpSgt { vrf: string; ip: string; sgt: number; source: string }
export interface SgtData { bindings: IpSgt[]; names: Map<number, string> }

const T = '1.3.6.1.4.1.9.9.713.1.4.1.1', NAMES = '1.3.6.1.4.1.9.9.730.1.4.16.1.4';
const EMPTY = new Map<string, SnmpValue>();
const SOURCE: Record<number, string> = { 1: 'cli', 2: 'learned', 3: 'authenticated', 4: 'sxp', 5: 'internal' };

/** Splits an index like `6.68.69.86.73.67.69.1.4.10.135.159.203.32` into VRF DEVICE and address 10.135.159.203/32 (the default VRF is the zero-length name). */
export function parseSgtIndex(idx: string): { vrf: string; ip: string; prefix: number } | null {
  const p = idx.split('.').map(Number);
  if (p.some(x => !Number.isInteger(x) || x < 0)) return null;
  const n = p[0]!;
  if (n > 32 || p.length !== n + 8 || p[n + 1] !== 1 || p[n + 2] !== 4) return null;
  const name = p.slice(1, 1 + n);
  if (name.some(x => x < 33 || x > 126)) return null;
  const a = p.slice(n + 3, n + 7);
  if (a.some(x => x > 255)) return null;
  return { vrf: String.fromCharCode(...name), ip: a.join('.'), prefix: p[n + 7]! };
}

export async function readSgt(c: SnmpClient): Promise<SgtData> {
  const [val, src, names] = await Promise.all([5, 6].map(n => c.column(`${T}.${n}`, 50).catch(() => EMPTY)).concat(c.column(NAMES, 50).catch(() => EMPTY)));
  const bindings: IpSgt[] = [];
  for (const [idx, v] of val!) {
    const x = parseSgtIndex(idx); const sgt = toNum(v);
    if (!x || x.prefix !== 32 || sgt === null) continue;   // host bindings only; a subnet binding does not say which host
    bindings.push({ vrf: x.vrf, ip: x.ip, sgt, source: SOURCE[toNum(src!.get(idx) ?? null) ?? 0] ?? 'other' });
  }
  const nm = new Map<number, string>();
  for (const [idx, v] of names!) { const k = Number(idx); const t = Buffer.isBuffer(v) ? v.toString('utf8') : String(v ?? ''); if (Number.isInteger(k) && t) nm.set(k, t.replace(/[^\x20-\x7e]/g, '')); }
  return { bindings, names: nm };
}
