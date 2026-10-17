/**
 * Joins what a fabric node says about LISP (src/snmp/lisp.ts) with what FlowScope knows about the hosts on its ports:
 *   - the registration check: hosts seen on this node's ports whose IPv4 address is not in its mapping database (nothing can reach them through the fabric), and registered
 *     addresses that are no longer on any port (a stale registration, or a silent host);
 *   - the endpoints the node is sending to: map cache entries in use, the fabric node (RLOC) each is behind, and who the host is.
 */
import type { Lisp, LispCacheEntry } from '../snmp/lisp.js';

export interface FabricHost { ip: string; vrf: string; mac: string; ifIndex: number; lastSeen: number; auth: boolean; user: string }
export interface Missing { ip: string; vrf: string; mac: string; ifIndex: number; authenticated: boolean; user: string }
export interface Stale { iid: number; vrf: string; ip: string; ageSec: number | null }
export interface Registration { registeredHosts: number; matched: number; missing: Missing[]; stale: Stale[]; macEids: number; instancesChecked: number }

/** A registration younger than this is not called stale: the host may simply not have been seen on the port yet. */
export const STALE_AFTER_SEC = 900;

export function registrationCheck(l: Lisp, hosts: FabricHost[], own: Set<string>): Registration {
  const vrfOf = new Map(l.instances.map(i => [i.iid, i.vrf]));
  const reg = new Map<string, { iid: number; ageSec: number | null }>();
  for (const r of l.registered) if (r.kind === 'ip' && r.prefix === 32) reg.set(`${vrfOf.get(r.iid) ?? ''}/${r.eid}`, { iid: r.iid, ageSec: r.ageSec });
  const seen = new Set<string>(); const missing: Missing[] = []; let matched = 0;
  for (const h of hosts) {
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(h.ip) || own.has(h.ip)) continue;
    const k = `${h.vrf}/${h.ip}`; if (seen.has(k)) continue; seen.add(k);
    if (reg.has(k)) matched++; else missing.push({ ip: h.ip, vrf: h.vrf, mac: h.mac, ifIndex: h.ifIndex, authenticated: h.auth, user: h.user });
  }
  const stale: Stale[] = [];
  for (const [k, r] of reg) {
    const ip = k.slice(k.indexOf('/') + 1);
    if (seen.has(k) || own.has(ip) || (r.ageSec ?? 0) < STALE_AFTER_SEC) continue;
    stale.push({ iid: r.iid, vrf: vrfOf.get(r.iid) ?? '', ip, ageSec: r.ageSec });
  }
  missing.sort((a, b) => Number(b.authenticated) - Number(a.authenticated) || a.vrf.localeCompare(b.vrf) || a.ip.localeCompare(b.ip, undefined, { numeric: true }));
  stale.sort((a, b) => (b.ageSec ?? 0) - (a.ageSec ?? 0));
  return { registeredHosts: reg.size, matched, missing, stale, macEids: l.registered.filter(r => r.kind === 'mac').length, instancesChecked: new Set(l.registered.map(r => r.iid)).size };
}

export interface Conversation { iid: number; vrf: string; ip: string; ageSec: number | null; rloc: string | null; rlocName: string; viaBorder: boolean; mac: string; user: string; sgt: { value: number; name: string } | null; bytes: number | null; flows: number | null }
export interface Who { mac: string; user: string; sgt: { value: number; name: string } | null }

/** The map cache entries that are in use (active), newest first. An entry with no RLOC is a negative entry: the node forwards that traffic to the border. */
export function conversations(l: Lisp, who: (ip: string) => Who | null, rlocName: (rloc: string) => string, traffic: Map<string, { bytes: number; flows: number }> | null, limit = 300): Conversation[] {
  const vrfOf = new Map(l.instances.map(i => [i.iid, i.vrf]));
  const act = l.cache.filter((e: LispCacheEntry) => e.active && e.kind === 'ip' && e.prefix === 32);
  return act.map(e => {
    const w = who(e.eid); const r = e.rlocs[0]; const t = traffic?.get(e.eid);
    return { iid: e.iid, vrf: vrfOf.get(e.iid) ?? '', ip: e.eid, ageSec: e.ageSec, rloc: r?.rloc ?? null, rlocName: r ? rlocName(r.rloc) : '', viaBorder: !r, mac: w?.mac ?? '', user: w?.user ?? '', sgt: w?.sgt ?? null, bytes: traffic ? t?.bytes ?? 0 : null, flows: traffic ? t?.flows ?? 0 : null };
  }).sort((a, b) => (b.bytes ?? 0) - (a.bytes ?? 0) || (a.ageSec ?? 1e12) - (b.ageSec ?? 1e12)).slice(0, limit);
}

/** How the endpoints are spread over the fabric nodes: for each RLOC, how many active entries are behind it. */
export function byRloc(l: Lisp, rlocName: (rloc: string) => string): { rloc: string; name: string; active: number; total: number }[] {
  const m = new Map<string, { rloc: string; name: string; active: number; total: number }>();
  for (const e of l.cache) { const r = e.rlocs[0]?.rloc; if (!r) continue; const x = m.get(r) ?? { rloc: r, name: rlocName(r), active: 0, total: 0 }; x.total++; if (e.active) x.active++; m.set(r, x); }
  return [...m.values()].sort((a, b) => b.active - a.active || b.total - a.total);
}
