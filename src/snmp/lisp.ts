/**
 * LISP / SD-Access fabric state of an edge or border node, from LISP-MIB (RFC 7052, 1.3.6.1.2.1.220):
 *   - the map cache (.6 EIDs, .7 their RLOCs): the remote endpoints this node has resolved because a local host sent to them, and the fabric node (RLOC) each is behind;
 *   - the mapping database (.4): the local endpoints this node registered with the map server;
 *   - per-instance (VN) features and statistics (.1, .3) and the state of the map servers (.12) and map resolvers (.13).
 *
 * Index of an EID: <L>.<L bytes>.<prefix length>, where the bytes are an LCAF instance-ID address: [L, 64, 3 (AFI 16387), length, 2 (type instance ID),
 * instance ID in three bytes, AFI two bytes (1 IPv4, 6 MAC), the address]. An RLOC follows as <8>.<8>.0.1.4.<four bytes>.<32>. The first byte repeating the length is
 * how the Catalyst encodes it; the layout is the one in the walk below.
 *
 * Checked against a full walk of a Catalyst 9300 SD-Access edge: 7 instances (4097 default, 4099 BRANCH ... 4104 GUEST), 266 map cache entries (106 active),
 * 232 registered EIDs (IPv4 /32 and MAC /48), 164 map servers and 162 map resolvers, all up. The packet and byte counters of the cache are zero on that switch
 * (forwarding is in hardware), so they are kept only when a device fills them in. The cache expiry time is not read: its units are not settled by the walk.
 */
import { toNum, toStr, type SnmpClient, type SnmpValue } from './client.js';

export interface LispCacheEntry { iid: number; kind: 'ip' | 'mac'; eid: string; prefix: number; active: boolean; authoritative: boolean; ageSec: number | null; rlocs: { rloc: string; priority: number; weight: number; up: boolean }[]; bytes: number; pkts: number }
export interface LispRegistered { iid: number; kind: 'ip' | 'mac'; eid: string; prefix: number; ageSec: number | null }
export interface LispInstance { iid: number; vrf: string; cacheSize: number; cacheLimit: number; etr: boolean; itr: boolean; pitr: boolean; petr: boolean; mapServer: boolean; mapResolver: boolean; requestsOut: number; repliesIn: number; registersOut: number; newRequests: number | null; newReplies: number | null }
export interface LispHistoryPoint { t: number; cache: number; added: number; removed: number }
export interface Lisp {
  readAt: number; instances: LispInstance[]; cache: LispCacheEntry[]; registered: LispRegistered[]; cacheTotal: number; truncated: boolean;
  mapServers: { total: number; down: string[] }; mapResolvers: { total: number; down: string[] };
  history: LispHistoryPoint[]; problems: string[]; level: 'ok' | 'warn' | 'bad';
}

const L = '1.3.6.1.2.1.220.1';
const EMPTY = new Map<string, SnmpValue>();
const MAX_KEPT = 4000, HISTORY = 288;

export interface EidIndex { iid: number; kind: 'ip' | 'mac'; eid: string; prefix: number; rest: number[] }
/** Splits the index of an EID row (and whatever follows it, such as an RLOC) into its parts. */
export function parseEidIndex(idx: string): EidIndex | null {
  const p = idx.split('.').map(Number);
  if (p.some(x => !Number.isInteger(x) || x < 0)) return null;
  const len = p[0]!;
  if (!(len >= 12) || p.length < len + 2) return null;
  const b = p.slice(1, 1 + len);
  if (b[1] !== 64 || b[2] !== 3 || b[4] !== 2) return null;
  const iid = (b[5]! << 16) | (b[6]! << 8) | b[7]!;
  const afi = (b[8]! << 8) | b[9]!, addr = b.slice(10);
  const prefix = p[1 + len]!;
  const rest = p.slice(2 + len);
  if (afi === 1 && addr.length === 4) return { iid, kind: 'ip', eid: addr.join('.'), prefix, rest };
  if (afi === 6 && addr.length === 6) return { iid, kind: 'mac', eid: addr.map(x => x.toString(16).padStart(2, '0')).join(':'), prefix, rest };
  return null;
}
/** The address of an IPv4 RLOC from what follows an EID in an index: <8>.<8>.0.1.4.a.b.c.d.<32>. */
export function rlocOf(rest: number[]): string | null { return rest.length >= 9 && rest[0] === 8 && rest[3] === 1 ? rest.slice(5, 9).join('.') : null; }

const key = (e: { iid: number; eid: string; prefix: number }) => `${e.iid}/${e.eid}/${e.prefix}`;

export async function readLisp(c: SnmpClient, prev: Lisp | null, now = Date.now()): Promise<Lisp | null> {
  const col = (base: string, i: number) => c.column(`${L}.${base}.${i}`, 50).catch(() => EMPTY);
  const [cState, cAuth, cTs, cOct, cPkt] = await Promise.all([5, 6, 3, 9, 10].map(i => col('6.1', i)));
  const [db, dbTs] = await Promise.all([col('4.1', 3), col('4.1', 5)]);
  if (!cState!.size && !db!.size) return null;
  const [rPrio, rWeight, rState] = await Promise.all([3, 4, 7].map(i => col('7.1', i)));
  const [fItr, fEtr, fPitr, fPetr, fMs, fMr, fSize, fLimit] = await Promise.all([3, 4, 5, 6, 7, 8, 9, 10].map(i => col('1.1', i)));
  const [sReqOut, sRepIn, sRegOut] = await Promise.all([2, 3, 6].map(i => col('3.1', i)));
  const [iidVrf, ms, mr] = await Promise.all([c.column(`${L}.2.1.1`, 50).catch(() => EMPTY), col('12.1', 3), col('13.1', 3)]);
  let up = 0;
  try { const g = await c.get(['1.3.6.1.2.1.1.3.0']); up = toNum((g.get('1.3.6.1.2.1.1.3.0')?.value ?? null) as SnmpValue) ?? 0; } catch { /* the age of an entry is left out */ }
  const age = (ts: SnmpValue | undefined): number | null => { const t = ts === undefined ? null : toNum(ts); return t === null || !up ? null : Math.max(0, Math.round((up - t) / 100)); };

  const rlocs = new Map<string, LispCacheEntry['rlocs']>();
  for (const [idx, v] of rState!) {
    const e = parseEidIndex(idx); const r = e ? rlocOf(e.rest) : null; if (!e || !r) continue;
    const k = key(e); const a = rlocs.get(k) ?? [];
    a.push({ rloc: r, priority: toNum(rPrio!.get(idx) ?? null) ?? 0, weight: toNum(rWeight!.get(idx) ?? null) ?? 0, up: toNum(v) === 1 }); rlocs.set(k, a);
  }
  const all: LispCacheEntry[] = [];
  for (const [idx, st] of cState!) {
    const e = parseEidIndex(idx); if (!e) continue;
    const r = (rlocs.get(key(e)) ?? []).sort((a, b) => a.priority - b.priority || b.weight - a.weight);
    all.push({ iid: e.iid, kind: e.kind, eid: e.eid, prefix: e.prefix, active: toNum(st) === 1, authoritative: toNum(cAuth!.get(idx) ?? null) === 1, ageSec: age(cTs!.get(idx)), rlocs: r, bytes: toNum(cOct!.get(idx) ?? null) ?? 0, pkts: toNum(cPkt!.get(idx) ?? null) ?? 0 });
  }
  const registered: LispRegistered[] = [];
  for (const [idx] of db!) { const e = parseEidIndex(idx); if (e) registered.push({ iid: e.iid, kind: e.kind, eid: e.eid, prefix: e.prefix, ageSec: age(dbTs!.get(idx)) }); }

  const vrfName = (iid: number): string => { const n = toStr(iidVrf.get(String(iid)) ?? null).trim(); return n === 'default' ? '' : n; };
  const byIid = new Map<number, LispInstance>();
  const inst = (iid: number): LispInstance => { let x = byIid.get(iid); if (!x) { x = { iid, vrf: vrfName(iid), cacheSize: 0, cacheLimit: 0, etr: false, itr: false, pitr: false, petr: false, mapServer: false, mapResolver: false, requestsOut: 0, repliesIn: 0, registersOut: 0, newRequests: null, newReplies: null }; byIid.set(iid, x); } return x; };
  const on = (m: Map<string, SnmpValue>, k: string) => toNum(m.get(k) ?? null) === 1;
  for (const [k, sz] of fSize!) {
    const iid = Number(k.split('.')[0]); if (!Number.isInteger(iid)) continue;
    const x = inst(iid); x.cacheSize += toNum(sz) ?? 0; x.cacheLimit = Math.max(x.cacheLimit, toNum(fLimit!.get(k) ?? null) ?? 0);
    x.itr ||= on(fItr!, k); x.etr ||= on(fEtr!, k); x.pitr ||= on(fPitr!, k); x.petr ||= on(fPetr!, k); x.mapServer ||= on(fMs!, k); x.mapResolver ||= on(fMr!, k);
  }
  for (const [k, v] of sReqOut!) { const iid = Number(k.split('.')[0]); if (Number.isInteger(iid)) { const x = inst(iid); x.requestsOut += toNum(v) ?? 0; x.repliesIn += toNum(sRepIn!.get(k) ?? null) ?? 0; x.registersOut += toNum(sRegOut!.get(k) ?? null) ?? 0; } }
  for (const x of byIid.values()) {
    const o = prev?.instances.find(y => y.iid === x.iid);
    if (o && x.requestsOut >= o.requestsOut) { x.newRequests = x.requestsOut - o.requestsOut; x.newReplies = x.repliesIn - o.repliesIn; }
  }

  // churn: what entered and left the map cache since the last read
  const seen = new Set(all.map(key)); const before = prev ? new Set(prev.cache.map(key)) : null;
  let added = 0, removed = 0;
  if (before && !prev!.truncated && all.length <= MAX_KEPT) { for (const k of seen) if (!before.has(k)) added++; for (const k of before) if (!seen.has(k)) removed++; }
  const history = [...(prev?.history ?? []), { t: now, cache: all.length, added, removed }].slice(-HISTORY);

  const down = (m: Map<string, SnmpValue>): string[] => [...m].filter(([, v]) => toNum(v) !== 1).map(([k]) => { const e = parseEidIndex(k); return e ? e.eid : k; });
  const problems: string[] = []; let level: Lisp['level'] = 'ok';
  const bump = (l: 'warn' | 'bad', t: string) => { problems.push(t); if (l === 'bad' || level !== 'bad') level = l; };
  const dms = down(ms), dmr = down(mr);
  if (dms.length) bump(ms.size && dms.length === ms.size ? 'bad' : 'warn', `${dms.length} of ${ms.size} map servers are not up (${dms.slice(0, 3).join(', ')}${dms.length > 3 ? ', …' : ''}). Endpoints cannot register through them.`);
  if (dmr.length) bump(mr.size && dmr.length === mr.size ? 'bad' : 'warn', `${dmr.length} of ${mr.size} map resolvers are not up (${dmr.slice(0, 3).join(', ')}${dmr.length > 3 ? ', …' : ''}). Remote endpoints cannot be resolved through them.`);
  for (const x of byIid.values()) {
    if (x.cacheLimit && x.cacheSize >= 0.8 * x.cacheLimit) bump('warn', `Map cache of instance ${x.iid}${x.vrf ? ' (' + x.vrf + ')' : ''} is ${Math.round(100 * x.cacheSize / x.cacheLimit)}% full (${x.cacheSize} of ${x.cacheLimit}).`);
    if ((x.newRequests ?? 0) >= 5 && (x.newReplies ?? 0) === 0) bump('warn', `Instance ${x.iid}${x.vrf ? ' (' + x.vrf + ')' : ''} sent ${x.newRequests} map requests since the last read and got no reply.`);
  }
  const last = history[history.length - 1]!, base = prev?.cache.length ?? 0;
  if (removed >= 20 && removed >= 0.25 * base) bump('warn', `The map cache lost ${removed} of ${base} entries since the last read. A cache that empties at once means it was cleared or the control plane restarted; remote endpoints then need resolving again.`);
  const grew = history.length >= 12 ? history[history.length - 12]!.cache : null;
  if (grew !== null && last.cache >= 1000 && last.cache >= 1.5 * grew) bump('warn', `The map cache grew from ${grew} to ${last.cache} entries in the last hour.`);
  return { readAt: now, instances: [...byIid.values()].sort((a, b) => a.iid - b.iid), cache: all.slice(0, MAX_KEPT), registered: registered.slice(0, MAX_KEPT), cacheTotal: all.length, truncated: all.length > MAX_KEPT, mapServers: { total: ms.size, down: dms }, mapResolvers: { total: mr.size, down: dmr }, history, problems, level };
}
