/**
 * Whether the running configuration has been saved, and what changed it last, from CISCO-CONFIG-MAN-MIB (1.3.6.1.4.1.9.9.43.1.1). The three scalars are
 * sysUpTime ticks: .1 running config last changed, .2 running config last saved to startup, .3 startup config last changed. Changes the running config has
 * that startup does not are lost at the next reload. The history table (.6.1) lists the last few events: col 2 time, 3 command source (1 command line,
 * 2 SNMP), 4 source and 5 destination (1 erase, 2 the command's source (a read such as "show running-config"), 3 running, 4 startup), 6 terminal type
 * (3 console, 4 terminal, 5 virtual), 8 user.
 *
 * Checked against a full walk of a Catalyst 9300 SD-Access edge: running changed at 955997 ticks, saved at 954085 (19 s earlier), sysUpTime 956460. All 10
 * events in the history were reads of the running config by the DNA Center user.
 */
import { toNum, toStr, type SnmpClient, type SnmpValue } from './client.js';

export interface ConfigEvent { at: number; what: string; user: string; via: string }
export interface ConfigState { readAt: number; changedAt: number | null; savedAt: number | null; unsaved: boolean; unsavedSec: number; events: ConfigEvent[] }

const B = '1.3.6.1.4.1.9.9.43.1.1', HIST = `${B}.6.1`, UP = '1.3.6.1.2.1.1.3.0';
const EMPTY = new Map<string, SnmpValue>();
const WHAT: Record<number, string> = { 1: 'erased', 3: 'changed', 4: 'saved' };
const VIA: Record<number, string> = { 3: 'console', 4: 'terminal', 5: 'remote session' };

export async function readConfigState(c: SnmpClient, now = Date.now()): Promise<ConfigState | null> {
  let g: Map<string, { value: SnmpValue }>;
  try { g = await c.get([`${B}.1.0`, `${B}.2.0`, `${B}.3.0`, UP]) as never; } catch { return null; }
  const t = (oid: string): number | null => { const v = g.get(oid)?.value; return v === undefined || v === null ? null : toNum(v); };
  const up = t(UP), changed = t(`${B}.1.0`), saved = t(`${B}.2.0`);
  if (up === null || changed === null) return null;
  const abs = (ticks: number | null): number | null => (ticks === null ? null : now - Math.max(0, up - ticks) * 10);
  // saved is zero on a device that has not saved since it started; running unchanged since boot has changed 0 ticks, which is not a change
  const unsaved = changed > 0 && (saved === null || saved < changed);
  const col = (i: number) => c.column(`${HIST}.${i}`, 20).catch(() => EMPTY);
  const [time, , dst, via, , user] = await Promise.all([2, 3, 5, 6, 7, 8].map(col));
  const events: ConfigEvent[] = [];
  for (const [k, tv] of time) {
    const d = toNum(dst.get(k) ?? null) ?? 0; const what = WHAT[d]; if (!what) continue;   // reads of the configuration are not changes
    const tk = toNum(tv); if (tk === null) continue;
    events.push({ at: abs(tk) ?? now, what, user: toStr(user.get(k) ?? null).trim(), via: VIA[toNum(via.get(k) ?? null) ?? 0] ?? '' });
  }
  events.sort((a, b) => b.at - a.at);
  return { readAt: now, changedAt: abs(changed), savedAt: saved ? abs(saved) : null, unsaved, unsavedSec: unsaved ? Math.max(0, (up - changed) / 100) : 0, events: events.slice(0, 5) };
}
