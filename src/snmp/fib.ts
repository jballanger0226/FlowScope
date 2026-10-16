/**
 * The IPv4 forwarding table of a Cisco router or Layer 3 switch, read from CISCO-CEF-MIB (1.3.6.1.4.1.9.9.492). With it a stream's path can be
 * checked against what the device would do with the destination now: which prefix matches, and which next hop and interface it uses.
 *
 * Layout, checked against a full walk of a Catalyst 9300 stack (IOS XE 17.18, 4,955 IPv4 prefixes, 9,381 paths):
 *  - cefPathTable          .1.1.5.1.<col>.<ent>.1.4.<a.b.c.d>.<prefixLen>.<path>   col 2 path type
 *  - cefFESelectionTable   .1.3.1.1.<col>.<ent>.8.1.1.4.<a.b.c.d>.<prefixLen>.<n>  col 6 egress interface, 7 next hop type, 8 next hop address, 11 weight
 * The selection row carries the resolved egress (a recursive path such as a default route is already resolved there).
 */
import { toNum, type SnmpClient, type SnmpValue } from './client.js';
import { ipOf, ipv4Int } from './multicast.js';

export type FibKind = 'attached' | 'recursive' | 'connected' | 'receive' | 'adjacency' | 'special' | 'other';
export interface FibPath { ifIndex: number; nextHop: string | null; weight: number; kind: FibKind }
export interface FibEntry { prefix: string; len: number; paths: FibPath[] }
export interface Fib { readAt: number; entries: FibEntry[]; truncated: boolean }

export const MAX_FIB = 80_000;
const PATH_TYPE = '1.3.6.1.4.1.9.9.492.1.1.5.1.2';
const SEL = { ifIndex: '1.3.6.1.4.1.9.9.492.1.3.1.1.6', nextHop: '1.3.6.1.4.1.9.9.492.1.3.1.1.8', weight: '1.3.6.1.4.1.9.9.492.1.3.1.1.11' };
/** cefPathType values as the walk shows them: 1 receive, 2 connectedPrefix, 5 attachedNexthop, 6 recursiveNexthop, 7 adjacencyPrefix, 8 specialPrefix */
const KINDS: Record<number, FibKind> = { 1: 'receive', 2: 'connected', 5: 'attached', 6: 'recursive', 7: 'adjacency', 8: 'special' };

const EMPTY = new Map<string, SnmpValue>();
const col = (c: SnmpClient, oid: string) => c.column(oid, 50).catch(() => EMPTY);

/** "10.1.2.0/24/3" from the part of an index that starts at the address type: 1.4.<a.b.c.d>.<len>.<n> */
function parseAt(p: string[], at: number): { prefix: string; len: number; n: number } | null {
  if (p[at] !== '1' || p[at + 1] !== '4') return null;
  const a = p.slice(at + 2, at + 6), len = Number(p[at + 6]), n = Number(p[at + 7]);
  if (a.length !== 4 || !Number.isInteger(len) || len < 0 || len > 32 || !Number.isInteger(n)) return null;
  return { prefix: a.join('.'), len, n };
}

/** Reads the IPv4 forwarding table. Returns null when the device does not publish CISCO-CEF-MIB. */
export async function readFib(c: SnmpClient, now = Date.now()): Promise<Fib | null> {
  const [ifs, nhs, wts, types] = await Promise.all([col(c, SEL.ifIndex), col(c, SEL.nextHop), col(c, SEL.weight), col(c, PATH_TYPE)]);
  if (!ifs.size) return null;
  const kind = new Map<string, FibKind>();
  for (const [idx, v] of types) { const r = parseAt(idx.split('.'), 1); if (r) kind.set(`${r.prefix}/${r.len}/${r.n}`, KINDS[toNum(v) ?? 0] ?? 'other'); }
  const byPrefix = new Map<string, FibEntry>();
  let truncated = false;
  for (const [idx, v] of ifs) {
    const r = parseAt(idx.split('.'), 3); if (!r) continue;
    const key = `${r.prefix}/${r.len}`;
    let e = byPrefix.get(key);
    if (!e) { if (byPrefix.size >= MAX_FIB) { truncated = true; continue; } e = { prefix: r.prefix, len: r.len, paths: [] }; byPrefix.set(key, e); }
    e.paths.push({ ifIndex: toNum(v) ?? 0, nextHop: ipOf(nhs.get(idx)), weight: toNum(wts.get(idx) ?? null) ?? 1, kind: kind.get(`${key}/${r.n}`) ?? 'other' });
  }
  if (!byPrefix.size) return null;
  return { readAt: now, entries: [...byPrefix.values()].sort((a, b) => ipv4Int(a.prefix) - ipv4Int(b.prefix) || a.len - b.len), truncated };
}

const MASKS: number[] = Array.from({ length: 33 }, (_, n) => (n === 0 ? 0 : (0xffffffff << (32 - n)) >>> 0));
const index = new WeakMap<Fib, Map<number, Map<number, FibEntry>>>();

/** The longest-prefix match for an IPv4 address, or null when nothing matches (or the table was cut off before the address's prefix). */
export function lookupFib(f: Fib, ip: string): FibEntry | null {
  const n = ipv4Int(ip); if (Number.isNaN(n)) return null;
  let idx = index.get(f);
  if (!idx) {
    idx = new Map();
    for (const e of f.entries) { let m = idx.get(e.len); if (!m) { m = new Map(); idx.set(e.len, m); } m.set((ipv4Int(e.prefix) & MASKS[e.len]!) >>> 0, e); }
    index.set(f, idx);
  }
  for (let len = 32; len >= 0; len--) { const m = idx.get(len); const e = m?.get((n & MASKS[len]!) >>> 0); if (e) return e; }
  return null;
}
