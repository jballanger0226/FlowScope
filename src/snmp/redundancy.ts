/**
 * Supervisor / unit redundancy from CISCO-RF-MIB (.1.3.6.1.4.1.9.9.176.1). Scalars: .1.1 unit id, .1.2 unit state (14 active, 9 standby hot, 2 disabled, ...),
 * .1.3 peer unit id, .1.4 peer unit state, .1.6 duplex (1 true: the pair is running redundantly), .1.8 last switchover reason (2 none, 3 not known, 7 active unit removed, ...),
 * .1.9 time since the last failover (ticks), .2.14 configured mode (1 non-redundant, 8 hot standby / SSO), .2.16 operational mode, .2.15 the configured mode as text.
 *
 * Checked against seven Catalyst walks: a dual-supervisor 9606R and a 9300 stack are active + standby hot, running SSO; a single-supervisor 9606R is configured
 * for SSO but operates non-redundant with the peer disabled; single-member stacks and fixed 9500s show peer disabled and the "configured" mode is not meaningful.
 * Whether a missing peer is a fault is a question for the caller: it knows how many supervisors the chassis holds.
 */
import { toNum, type SnmpClient } from './client.js';

type Level = 'ok' | 'warn' | 'bad' | 'off';
export interface Redundancy {
  readAt: number; unitState: string; peerState: string; peerId: number | null;
  /** The pair is running redundantly now (cRFStatusDuplexMode true) */ duplex: boolean;
  configured: string; operating: string; configuredSso: boolean; operatingSso: boolean;
  lastSwitchover: string | null; sinceFailoverSec: number | null; level: Level; problems: string[];
}
const RF = '1.3.6.1.4.1.9.9.176.1';
const UNIT: Record<number, string> = { 0: 'not known', 1: 'not known', 2: 'disabled', 3: 'initialization', 4: 'negotiation', 5: 'standby cold', 6: 'standby config', 7: 'standby file', 8: 'standby bulk', 9: 'standby hot', 10: 'active fast', 11: 'active drain', 12: 'active preconfig', 13: 'active postconfig', 14: 'active', 15: 'active extra load', 16: 'active handback', 17: 'standby hot-handback' };
const MODE: Record<number, string> = { 1: 'non-redundant', 2: 'warm standby (RPR)', 3: 'warm standby', 4: 'cold standby', 5: 'cold standby (RPR+)', 6: 'RPR', 7: 'RPR+', 8: 'SSO (hot standby)', 9: 'NSF with SSO', 10: 'SSO with ISSU' };
/** Only the codes seen on real devices (2 none, 3 not known, 7 active unit removed) are named; the rest are shown as their number. */
const SWACT_NAMES: Record<number, string> = { 3: 'not known', 7: 'active unit removed' };

export async function readRedundancy(c: SnmpClient, now = Date.now()): Promise<Redundancy | null> {
  const o = (s: string) => `${RF}.${s}.0`;
  const names = { id: o('1.1'), state: o('1.2'), peerId: o('1.3'), peer: o('1.4'), duplex: o('1.6'), swact: o('1.8'), fail: o('1.9'), cfg: o('2.14'), oper: o('2.16') };
  let m;
  try { m = await c.get(Object.values(names)); } catch { return null; }
  const g = (k: keyof typeof names) => m.get(names[k])?.value ?? null;
  const st = toNum(g('state'));
  if (st === null) return null;
  const peer = toNum(g('peer')), cfg = toNum(g('cfg')), op = toNum(g('oper')), sw = toNum(g('swact')), ft = toNum(g('fail'));
  const duplex = toNum(g('duplex')) === 1;
  const r: Redundancy = {
    readAt: now, unitState: UNIT[st] ?? `state ${st}`, peerState: peer === null ? 'not known' : UNIT[peer] ?? `state ${peer}`, peerId: toNum(g('peerId')), duplex,
    configured: cfg === null ? 'not known' : MODE[cfg] ?? `mode ${cfg}`, operating: op === null ? 'not known' : MODE[op] ?? `mode ${op}`,
    configuredSso: cfg !== null && cfg >= 8, operatingSso: op !== null && op >= 8,
    lastSwitchover: sw === null || sw === 2 ? null : SWACT_NAMES[sw] ?? `reason ${sw}`, sinceFailoverSec: ft !== null && ft > 0 ? Math.floor(ft / 100) : null, level: 'ok', problems: []
  };
  return r;
}

/**
 * Judges the pair. `supervisors` is how many supervisor (or stack member) slots are populated, when known: a chassis with one supervisor cannot be redundant and is
 * only worth a note, while one with two that is not running redundantly has lost its standby.
 */
export function judgeRedundancy(r: Redundancy, supervisors: number | null): Redundancy {
  const problems: string[] = [];
  let level: Level = 'ok';
  const raise = (l: Level) => { if ((l === 'bad' && level !== 'bad') || (l === 'warn' && level === 'ok')) level = l; };
  if (r.unitState !== 'active') { problems.push(`This unit is ${r.unitState}, not active.`); raise('warn'); }
  if (r.configuredSso && !r.duplex) {
    if (supervisors !== null && supervisors <= 1) problems.push('Configured for SSO redundancy but there is only one supervisor, so it runs without a standby.');
    else { problems.push(`Configured for SSO redundancy but running ${r.operating}: the standby is ${r.peerState}. A failure of the active unit now stops the device instead of switching over.`); raise('warn'); }
  }
  if (r.lastSwitchover && r.sinceFailoverSec !== null && r.sinceFailoverSec < 86_400) { problems.push(`Switched over to this unit in the last day (${r.lastSwitchover}).`); raise('warn'); }
  return { ...r, level, problems };
}

/**
 * How many supervisors a chassis has, from the modules ENTITY-MIB lists. A switch stack has no supervisor redundancy to speak of (the members back each other up through
 * StackWise, not CISCO-RF-MIB), so a stack counts as one; StackWise Virtual and chassis switches count their supervisor modules. Null when nothing says.
 */
export function supervisorCount(modelsAndDescr: string[], stackMembers: number, svl: boolean): number | null {
  if (stackMembers > 1 && !svl) return 1;
  const n = modelsAndDescr.filter(t => /supervisor|\bsup[-\d]|-sup/i.test(t)).length;
  return n || null;
}
