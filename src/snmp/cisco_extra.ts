/**
 * Cisco-only tables that explain why a device or a network behaves the way it does. Each reader is checked against a walk of a Catalyst 9300 stack.
 *   - Processes (CISCO-PROCESS-MIB): which process is using the CPU, including the SNMP engine, which tells whether polling itself is the load.
 *   - Stack (CISCO-STACKWISE-MIB): member state and stack-port health. One broken ring link leaves the stack running with no redundancy.
 *   - Dynamic ARP inspection (CISCO-DYNAMIC-ARP-INSPECTION-MIB): per VLAN, ARP packets forwarded and dropped, and why.
 *   - NBAR2 (CISCO-NBAR-PROTOCOL-DISCOVERY-MIB): per interface, the application protocols the device recognised and their rate.
 */
import { toBigInt, toNum, toStr, type SnmpClient, type SnmpValue } from './client.js';
import { macText } from './collect.js';

type Level = 'ok' | 'warn' | 'bad' | 'off';
const EMPTY = new Map<string, SnmpValue>();
const col = (c: SnmpClient, oid: string, maxRep = 50) => c.column(oid, maxRep).catch(() => EMPTY);
const num = (v: SnmpValue | undefined): number | null => (v === undefined || v === null ? null : toNum(v));

/* ------------------------------------------------------------------ processes */

export interface ProcessCpu { name: string; pid: number; five: number; one: number; fiveMin: number }
export interface Processes { readAt: number; top: ProcessCpu[]; /** Share of CPU used by the SNMP engine over five seconds, when the device lists it */ snmpFive: number | null; snmpOne: number | null }

/** The busiest processes by their one-minute CPU share. The same process runs on each stack member or CPU, so rows with the same name are merged and the busiest one is shown: adding them would give a share of more than one CPU. */
export async function readProcesses(c: SnmpClient, now = Date.now()): Promise<Processes | null> {
  const [name, five, one, fiveMin] = await Promise.all([
    col(c, '1.3.6.1.4.1.9.9.109.1.2.1.1.2'), col(c, '1.3.6.1.4.1.9.9.109.1.2.2.1.5'), col(c, '1.3.6.1.4.1.9.9.109.1.2.2.1.6'), col(c, '1.3.6.1.4.1.9.9.109.1.2.2.1.7')]);
  if (!name.size) return null;
  const by = new Map<string, ProcessCpu>();
  for (const [k, v] of name) {
    const nm = toStr(v).trim(); if (!nm) continue;
    const p = by.get(nm) ?? { name: nm, pid: Number(k.split('.').pop()) || 0, five: 0, one: 0, fiveMin: 0 };
    p.five = Math.max(p.five, num(five.get(k)) ?? 0); p.one = Math.max(p.one, num(one.get(k)) ?? 0); p.fiveMin = Math.max(p.fiveMin, num(fiveMin.get(k)) ?? 0);
    by.set(nm, p);
  }
  const all = [...by.values()];
  const snmp = all.filter(p => /snmp/i.test(p.name));
  const top = all.filter(p => p.one > 0 || p.five > 0).sort((a, b) => b.one - a.one || b.five - a.five).slice(0, 8);
  return { readAt: now, top, snmpFive: snmp.length ? Math.max(...snmp.map(p => p.five)) : null, snmpOne: snmp.length ? Math.max(...snmp.map(p => p.one)) : null };
}

/* ------------------------------------------------------------------ stack */

export interface StackMember { index: number; number: number | null; role: string; state: string; level: Level; mac: string }
export interface StackPort { ifIndex: number; status: string; level: Level; neighbor: number | null }
export interface Stack { readAt: number; members: StackMember[]; ports: StackPort[]; /** Plain-language problems, empty when the stack is whole */ problems: string[] }
const ROLE: Record<number, string> = { 1: 'master', 2: 'member', 3: 'not a member', 4: 'standby' };
const SW_STATE: Record<number, [string, Level]> = { 1: ['waiting', 'warn'], 2: ['progressing', 'warn'], 3: ['added', 'warn'], 4: ['ready', 'ok'], 5: ['SDM template mismatch', 'bad'], 6: ['version mismatch', 'bad'], 7: ['feature mismatch', 'bad'], 8: ['new master initialising', 'warn'], 9: ['provisioned', 'off'], 10: ['invalid', 'bad'], 11: ['removed', 'bad'] };
const PORT_STATE: Record<number, [string, Level]> = { 1: ['up', 'ok'], 2: ['down', 'bad'], 3: ['forced down', 'warn'] };

export async function readStack(c: SnmpClient, now = Date.now()): Promise<Stack | null> {
  const [cur, role, state, mac, pst, nbr] = await Promise.all([
    col(c, '1.3.6.1.4.1.9.9.500.1.2.1.1.1'), col(c, '1.3.6.1.4.1.9.9.500.1.2.1.1.3'), col(c, '1.3.6.1.4.1.9.9.500.1.2.1.1.6'), col(c, '1.3.6.1.4.1.9.9.500.1.2.1.1.7'),
    col(c, '1.3.6.1.4.1.9.9.500.1.2.2.1.1'), col(c, '1.3.6.1.4.1.9.9.500.1.2.2.1.2')]);
  if (!state.size) return null;
  const members: StackMember[] = [];
  for (const [k, v] of state) {
    const [st, level] = SW_STATE[num(v) ?? 0] ?? ['unknown', 'off' as Level];
    members.push({ index: Number(k), number: num(cur.get(k)), role: ROLE[num(role.get(k)) ?? 0] ?? 'unknown', state: st, level, mac: macText(mac.get(k)) });
  }
  members.sort((a, b) => (a.number ?? a.index) - (b.number ?? b.index));
  const ports: StackPort[] = [];
  for (const [k, v] of pst) { const [st, level] = PORT_STATE[num(v) ?? 0] ?? ['unknown', 'off' as Level]; ports.push({ ifIndex: Number(k), status: st, level, neighbor: num(nbr.get(k)) }); }
  ports.sort((a, b) => a.ifIndex - b.ifIndex);
  const problems: string[] = [];
  const downP = ports.filter(p => p.level !== 'ok');
  if (downP.length) problems.push(`${downP.length} stack port${downP.length === 1 ? ' is' : 's are'} not up. The stack ring is broken, so traffic between members has no second path and a further failure would split the stack.`);
  for (const m of members) if (m.level === 'bad' || m.level === 'warn') problems.push(`Stack member ${m.number ?? m.index} is ${m.state}.`);
  if (!members.some(m => m.role === 'master')) problems.push('No stack member reports itself as the master.');
  return { readAt: now, members, ports, problems };
}

/* ------------------------------------------------------------------ dynamic ARP inspection */

export interface DaiVlan { vlan: number; forwarded: number; dropped: number; dhcpDenied: number; aclDenied: number; srcMac: number; dstMac: number; ip: number; invalid: number; /** Packets dropped since the previous read, when there was one */ droppedNow: number | null }
export interface Dai { readAt: number; vlans: DaiVlan[]; /** Seconds between this read and the previous one */ dtSec: number | null }
const DAI = '1.3.6.1.4.1.9.9.374.1.4.1.1';
const DAI_COLS = { forwarded: 2, dropped: 3, aclDenied: 6, dhcpDenied: 7, srcMac: 8, dstMac: 9, ip: 10, invalid: 12 } as const;

/** Only VLANs that have had ARP packets dropped are listed. The table has a row for every possible VLAN, so the busy ones are read in detail. */
export async function readDai(c: SnmpClient, prev: Dai | null, now = Date.now()): Promise<Dai | null> {
  const dropped = await col(c, `${DAI}.${DAI_COLS.dropped}`, 100);
  if (!dropped.size) return null;
  const busy = [...dropped].filter(([, v]) => (num(v) ?? 0) > 0).map(([k]) => k).slice(0, 60);
  const vlans: DaiVlan[] = [];
  for (const k of busy) {
    const oids = (Object.keys(DAI_COLS) as (keyof typeof DAI_COLS)[]).map(n => `${DAI}.${DAI_COLS[n]}.${k}`);
    let got: Map<string, { value: SnmpValue }>;
    try { got = await c.get(oids) as unknown as Map<string, { value: SnmpValue }>; } catch { continue; }
    const g = (n: keyof typeof DAI_COLS) => { const x = got.get(`${DAI}.${DAI_COLS[n]}.${k}`)?.value; const b = x === undefined || x === null ? null : toBigInt(x); return b === null ? 0 : Number(b); };
    const d: DaiVlan = { vlan: Number(k), forwarded: g('forwarded'), dropped: g('dropped'), dhcpDenied: g('dhcpDenied'), aclDenied: g('aclDenied'), srcMac: g('srcMac'), dstMac: g('dstMac'), ip: g('ip'), invalid: g('invalid'), droppedNow: null };
    const p = prev?.vlans.find(x => x.vlan === d.vlan);
    // a VLAN that was not listed before had nothing dropped then
    if (prev) d.droppedNow = p ? (d.dropped >= p.dropped ? d.dropped - p.dropped : null) : d.dropped;
    vlans.push(d);
  }
  vlans.sort((a, b) => (b.droppedNow ?? 0) - (a.droppedNow ?? 0) || b.dropped - a.dropped);
  return { readAt: now, vlans, dtSec: prev && now > prev.readAt ? Math.round((now - prev.readAt) / 1000) : null };
}

/** Why a VLAN drops ARP packets, in the words of someone fixing it */
export function daiReason(v: DaiVlan): string {
  const parts: string[] = [];
  if (v.dhcpDenied) parts.push(`${v.dhcpDenied.toLocaleString('en-US')} had no matching DHCP snooping binding (a host with a static address, or a lease the switch has not seen)`);
  if (v.aclDenied) parts.push(`${v.aclDenied.toLocaleString('en-US')} were denied by an ARP ACL`);
  if (v.srcMac) parts.push(`${v.srcMac.toLocaleString('en-US')} had a source MAC that did not match the Ethernet header`);
  if (v.dstMac) parts.push(`${v.dstMac.toLocaleString('en-US')} had a destination MAC that did not match`);
  if (v.ip) parts.push(`${v.ip.toLocaleString('en-US')} carried an invalid IP address`);
  if (v.invalid) parts.push(`${v.invalid.toLocaleString('en-US')} had invalid protocol data`);
  return parts.join('; ');
}

/* ------------------------------------------------------------------ NBAR2 */

/** `inBps`/`outBps` come from the byte counters between two reads (null on the first read of a protocol): the device's own rate column was not in bits per second on the Catalyst 9300 it was checked on. */
export interface NbarProto { name: string; inBps: number | null; outBps: number | null; inBytes: number; outBytes: number }
export interface Nbar { readAt: number; /** Per interface: the protocols with the most traffic */ interfaces: Record<number, NbarProto[]> }
const NB = '1.3.6.1.4.1.9.9.244.1.2.1.1';

/** Application protocols NBAR2 recognised, per interface (indexed ifIndex.protocolId). Only the busiest few of each interface are kept. */
export async function readNbar(c: SnmpClient, now = Date.now(), prev: Nbar | null = null): Promise<Nbar | null> {
  const [name, inB, outB] = await Promise.all([col(c, `${NB}.2`, 50), col(c, `${NB}.9`, 50), col(c, `${NB}.10`, 50)]);
  if (!name.size) return null;
  const by = new Map<number, NbarProto[]>();
  const big = (m: Map<string, SnmpValue>, k: string) => { const v = m.get(k); const b = v === undefined || v === null ? null : toBigInt(v); return b === null ? 0 : Number(b); };
  for (const [k, v] of name) {
    const ifx = Number(k.split('.')[0]); if (!Number.isInteger(ifx) || ifx <= 0) continue;
    const p: NbarProto = { name: toStr(v), inBps: null, outBps: null, inBytes: big(inB, k), outBytes: big(outB, k) };
    if (!p.name || (!p.inBytes && !p.outBytes)) continue;
    const was = prev?.interfaces[ifx]?.find(x => x.name === p.name), dt = prev ? (now - prev.readAt) / 1000 : 0;
    if (was && dt >= 5) { if (p.inBytes >= was.inBytes) p.inBps = Math.round((p.inBytes - was.inBytes) * 8 / dt); if (p.outBytes >= was.outBytes) p.outBps = Math.round((p.outBytes - was.outBytes) * 8 / dt); }
    (by.get(ifx) ?? by.set(ifx, []).get(ifx)!).push(p);
  }
  const interfaces: Record<number, NbarProto[]> = {};
  for (const [ifx, list] of by) interfaces[ifx] = list.sort((a, b) => (b.inBps ?? 0) + (b.outBps ?? 0) - ((a.inBps ?? 0) + (a.outBps ?? 0)) || b.inBytes + b.outBytes - (a.inBytes + a.outBytes)).slice(0, 8);
  return Object.keys(interfaces).length ? { readAt: now, interfaces } : null;
}
