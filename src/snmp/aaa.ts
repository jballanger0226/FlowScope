/**
 * RADIUS and TACACS+ server health, from CISCO-AAA-SERVER-MIB (1.3.6.1.4.1.9.10.56). When an authentication server is slow or unreachable, 802.1X and MAB
 * clients fail or fall back to the critical VLAN, which looks like a network fault. This table counts the requests, timeouts and failures per server.
 *
 * Config table 1.1.2.1 (col 3 address, 4 authentication port, 5 accounting port, 7 priority) and statistics 1.2.1.1 (col 1 authentication requests, 2 timeouts,
 * 7 successes, 8 failures, 6 last response time in ms, 9/10 authorization requests/timeouts, 17/18 accounting requests/timeouts, 22 accounting response time,
 * 25 state 1 up, 26 seconds in this state, 27 seconds in the previous state, 28 total seconds dead, 29 times marked dead). The index is <server>.<priority>.
 *
 * Checked against a full walk of a Catalyst 9300 SD-Access edge: server 1.0 is TACACS+ on port 49 (no traffic), server 2.1 is RADIUS 10.254.185.251:1812
 * with 24115 authentication requests, 77 timeouts, 12 failures, a last response time of 925 ms and 2 dead periods.
 */
import { toNum, toStr, type SnmpClient, type SnmpValue } from './client.js';

export interface AaaServer {
  key: string; address: string; kind: 'radius' | 'tacacs'; port: number; acctPort: number; priority: number; up: boolean; stateSec: number; deadCount: number; deadSec: number;
  authReq: number; authTimeouts: number; authFail: number; authMs: number; acctReq: number; acctTimeouts: number; acctMs: number; authorReq: number; authorTimeouts: number;
  /** Changes since the previous read (null on the first read) */
  newReq: number | null; newTimeouts: number | null; newFail: number | null; newDead: number | null;
  level: 'ok' | 'warn' | 'bad'; problems: string[];
}
export interface Aaa { readAt: number; dtSec: number; servers: AaaServer[] }

const CFG = '1.3.6.1.4.1.9.10.56.1.1.2.1', ST = '1.3.6.1.4.1.9.10.56.1.2.1.1';
const EMPTY = new Map<string, SnmpValue>();
const SLOW_MS = 750;

const n = (m: Map<string, SnmpValue>, k: string): number => { const v = m.get(k); return v === undefined || v === null ? 0 : toNum(v) ?? 0; };

/** Turns the counters into per-server findings. `prev` is the previous read, used to say what happened since. */
export function readAaa(c: SnmpClient, prev: Aaa | null, now = Date.now()): Promise<Aaa | null> {
  return (async () => {
    const col = (base: string, i: number) => c.column(`${base}.${i}`, 50).catch(() => EMPTY);
    const [addr, port, acctPort, prio] = await Promise.all([3, 4, 5, 7].map(i => col(CFG, i)));
    if (!addr.size) return null;
    const cols = await Promise.all([1, 2, 6, 7, 8, 9, 10, 17, 18, 22, 25, 26, 28, 29].map(i => col(ST, i)));
    const [req, tmo, ms, , fail, aReq, aTmo, cReq, cTmo, cMs, state, dur, deadSec, dead] = cols;
    const dt = prev ? Math.max(0, (now - prev.readAt) / 1000) : 0;
    const servers: AaaServer[] = [];
    for (const [k, a] of addr) {
      const address = toStr(a).trim() || (Buffer.isBuffer(a) && a.length === 4 ? [...a].join('.') : '');
      if (!address || address === '0.0.0.0') continue;
      const p = n(port!, k);
      const s: AaaServer = {
        key: k, address, kind: p === 49 ? 'tacacs' : 'radius', port: p, acctPort: n(acctPort!, k), priority: n(prio!, k), up: n(state!, k) === 1, stateSec: n(dur!, k), deadCount: n(dead!, k), deadSec: n(deadSec!, k),
        authReq: n(req!, k), authTimeouts: n(tmo!, k), authFail: n(fail!, k), authMs: n(ms!, k), acctReq: n(cReq!, k), acctTimeouts: n(cTmo!, k), acctMs: n(cMs!, k), authorReq: n(aReq!, k), authorTimeouts: n(aTmo!, k),
        newReq: null, newTimeouts: null, newFail: null, newDead: null, level: 'ok', problems: []
      };
      const old = prev?.servers.find(x => x.key === k);
      // a counter that went down means the device restarted: no difference is claimed
      if (old && s.authReq >= old.authReq) {
        s.newReq = s.authReq - old.authReq + (s.acctReq - old.acctReq); s.newTimeouts = s.authTimeouts - old.authTimeouts + (s.acctTimeouts - old.acctTimeouts);
        s.newFail = s.authFail - old.authFail; s.newDead = s.deadCount - old.deadCount;
      }
      const label = `${s.kind === 'tacacs' ? 'TACACS+' : 'RADIUS'} server ${s.address}`;
      const used = s.authReq + s.acctReq + s.authorReq > 0;
      if (!s.up) { s.level = 'bad'; s.problems.push(`${label} is marked dead${s.stateSec ? ` (for ${s.stateSec < 120 ? s.stateSec + ' s' : Math.round(s.stateSec / 60) + ' min'})` : ''}. 802.1X and MAB clients cannot authenticate against it.`); }
      if ((s.newDead ?? 0) > 0) { s.level = s.level === 'bad' ? 'bad' : 'warn'; s.problems.push(`${label} was marked dead ${s.newDead} time${s.newDead === 1 ? '' : 's'} since the last read.`); }
      if ((s.newTimeouts ?? 0) > 0 && s.up) { s.level = 'warn'; s.problems.push(`${label} did not answer ${s.newTimeouts} request${s.newTimeouts === 1 ? '' : 's'} since the last read.`); }
      if (used && s.up && s.authReq >= 100 && s.authTimeouts / s.authReq >= 0.01 && s.level === 'ok') { s.level = 'warn'; s.problems.push(`${label} has not answered ${((s.authTimeouts / s.authReq) * 100).toFixed(1)}% of ${s.authReq} authentication requests since the counters started.`); }
      if (used && s.up && s.authMs >= SLOW_MS && s.level === 'ok') { s.level = 'warn'; s.problems.push(`${label} took ${s.authMs} ms to answer its last authentication request (over ${SLOW_MS} ms is slow).`); }
      servers.push(s);
    }
    servers.sort((a, b) => a.priority - b.priority || a.address.localeCompare(b.address));
    return { readAt: now, dtSec: dt, servers };
  })();
}
