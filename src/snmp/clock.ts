/**
 * Clock synchronisation. NTPv4-MIB (.1.3.6.1.2.1.197) is the standard source; CISCO-NTP-MIB (.1.3.6.1.4.1.9.9.168) adds reachability per source.
 * ntpEntStatusCurrentMode .1.2.1 (1 not running, 2 not synchronized, 3 none configured, 4 sync to local, 5 sync to refclock, 6 sync to remote server, 7 unknown),
 * stratum .1.2.2, active source id .1.2.3, offset .1.2.5 and dispersion .1.2.7 as text ("11.0546 ms"); associations .1.3.1.1: .5 address (InetAddress, 4 bytes for IPv4),
 * .3 reference id text, .6 offset, .7 stratum, .8 jitter, .9 delay, .10 dispersion as text. cntpPeersReach .9.9.168.1.2.1.1.21 is the reach register (255 = the last eight polls all answered).
 *
 * Checked against seven Catalyst walks: all synchronised to a remote server at stratum 2 with two or three sources, offsets 11 ms on one of them. The mode names and the
 * reach register are from the MIBs; no walk had an unsynchronised device.
 */
import { toNum, toStr, type SnmpClient, type SnmpValue } from './client.js';

type Level = 'ok' | 'warn' | 'bad' | 'off';
export interface NtpSource { id: number; address: string; stratum: number | null; offsetMs: number | null; jitterMs: number | null; delayMs: number | null; reach: number | null; refId: string; active: boolean; level: Level }
export interface Ntp { readAt: number; mode: string; synced: boolean; stratum: number | null; offsetMs: number | null; dispersionMs: number | null; sources: NtpSource[]; level: Level; problems: string[] }
const NTP = '1.3.6.1.2.1.197.1', CNTP = '1.3.6.1.4.1.9.9.168.1.2.1.1';
const MODE: Record<number, string> = { 1: 'not running', 2: 'not synchronised', 3: 'no source configured', 4: 'running on its own clock', 5: 'synchronised to a reference clock', 6: 'synchronised to a server', 7: 'unknown' };
const EMPTY = new Map<string, SnmpValue>();

/** "11.054 ms", "0.97 ms", "4.660" or "-3.2 ms" as milliseconds. */
export function msOf(v: SnmpValue | undefined): number | null {
  if (v === undefined || v === null) return null;
  const m = /^\s*(-?\d+(?:\.\d+)?)\s*(ms|s|us)?/i.exec(toStr(v)); if (!m) return null;
  const n = Number(m[1]), u = (m[2] ?? 'ms').toLowerCase();
  return u === 's' ? n * 1000 : u === 'us' ? n / 1000 : n;
}
const addrOf = (v: SnmpValue | undefined): string => {
  if (Buffer.isBuffer(v) && v.length === 4) return [...v].join('.');
  if (Buffer.isBuffer(v) && v.length === 16) { const w: string[] = []; for (let i = 0; i < 16; i += 2) w.push(v.readUInt16BE(i).toString(16)); return w.join(':'); }
  return typeof v === 'string' ? v : '';
};

export async function readNtp(c: SnmpClient, now = Date.now(), cisco = true): Promise<Ntp | null> {
  const col = (o: string) => c.column(o, 50).catch(() => EMPTY);
  let m;
  try { m = await c.get([`${NTP}.2.1.0`, `${NTP}.2.2.0`, `${NTP}.2.3.0`, `${NTP}.2.5.0`, `${NTP}.2.7.0`]); } catch { return null; }
  const g = (n: number) => m.get(`${NTP}.2.${n}.0`)?.value ?? null;
  const modeN = toNum(g(1));
  if (modeN === null) return null;
  const [addr, stratum, offset, jitter, delay, ref, reach] = await Promise.all([`${NTP}.3.1.1.5`, `${NTP}.3.1.1.7`, `${NTP}.3.1.1.6`, `${NTP}.3.1.1.8`, `${NTP}.3.1.1.9`, `${NTP}.3.1.1.3`, `${CNTP}.21`].map(o => (!cisco && o.startsWith('1.3.6.1.4.1.9.') ? Promise.resolve(EMPTY) : col(o))));
  const activeId = toNum(g(3));
  const sources: NtpSource[] = [];
  for (const [k, a] of addr) {
    const id = Number(k), rc = toNum(reach.get(k) ?? null), off = msOf(offset.get(k)), st = toNum(stratum.get(k) ?? null);
    let level: Level = 'ok';
    if (rc !== null && rc === 0) level = 'bad'; else if (rc !== null && rc < 255 && rc !== 0) level = 'warn';
    if (off !== null && Math.abs(off) >= 1000) level = 'bad'; else if (off !== null && Math.abs(off) >= 100 && level === 'ok') level = 'warn';
    sources.push({ id, address: addrOf(a), stratum: st, offsetMs: off, jitterMs: msOf(jitter.get(k)), delayMs: msOf(delay.get(k)), reach: rc, refId: toStr(ref.get(k) ?? null), active: activeId === id, level });
  }
  sources.sort((x, y) => Number(y.active) - Number(x.active) || x.address.localeCompare(y.address, undefined, { numeric: true }));
  const synced = modeN === 5 || modeN === 6 || modeN === 4;
  const problems: string[] = [];
  let level: Level = 'ok';
  const raise = (l: Level) => { if ((l === 'bad' && level !== 'bad') || (l === 'warn' && level === 'ok')) level = l; };
  const offsetMs = msOf(g(5)), stratumN = toNum(g(2));
  if (modeN === 3) { problems.push('No time source is configured, so this device keeps its own, drifting, clock. Logs and flow timestamps will not line up with other devices.'); raise('warn'); }
  else if (modeN === 1 || modeN === 2 || modeN === 7) { problems.push(`The clock is ${MODE[modeN]}. Logs and flow timestamps will not line up with other devices.`); raise('bad'); }
  else if (modeN === 4) { problems.push('Running on its own clock; no external time source is in use.'); raise('warn'); }
  if (synced && offsetMs !== null && Math.abs(offsetMs) >= 100) { problems.push(`The clock is ${Math.abs(offsetMs).toFixed(0)} ms ${offsetMs > 0 ? 'ahead of' : 'behind'} its time source.`); raise(Math.abs(offsetMs) >= 1000 ? 'bad' : 'warn'); }
  if (synced && stratumN !== null && stratumN >= 8) { problems.push(`Stratum ${stratumN} is far from a reference clock.`); raise('warn'); }
  const bad = sources.filter(s => s.level === 'bad' && s.reach === 0);
  if (bad.length) { problems.push(`${bad.length === 1 ? 'A time source does' : `${bad.length} time sources do`} not answer: ${bad.map(s => s.address).join(', ')}.`); raise(bad.length === sources.length ? 'bad' : 'warn'); }
  if (synced && sources.length === 1) problems.push('Only one time source is configured; there is nothing to fall back on if it fails.');
  return { readAt: now, mode: MODE[modeN] ?? `mode ${modeN}`, synced: modeN === 5 || modeN === 6, stratum: stratumN, offsetMs, dispersionMs: msOf(g(7)), sources, level, problems };
}
