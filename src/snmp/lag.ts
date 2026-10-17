/**
 * Port-channels (EtherChannel) from IEEE8023-LAG-MIB (.1.2.840.10006.300.43), which Cisco publishes for LACP. Aggregators are indexed by the ifIndex of the Port-channel:
 * .1.1.1.2 MAC address (all zero for an unused slot), .1.1.1.6 admin key, .1.1.1.7 oper key. Ports: .1.2.1.1.4 actor admin key (0 for a port not in a channel), .1.2.1.1.12
 * selected aggregator, .1.2.1.1.13 attached aggregator (0 = not bundled), .1.2.1.1.21 actor oper state and .23 partner oper state (BITS: lacpActivity, lacpTimeout,
 * aggregation, synchronization, collecting, distributing, defaulted, expired), .1.2.1.1.24 aggregate (true) or individual.
 *
 * The channel's configured members are the lower layers of the aggregator in IF-MIB ifStackStatus (.1.3.6.1.2.1.31.1.2.1.3, index higher.lower), which also lists a
 * member port that is down; LACP lists only the ports that joined.
 *
 * Checked against two Catalyst 9500X/9600 walks: 24 channels with 61 member ports on one and 9 channels with 18 on the other, every member collecting and distributing.
 * Five ports on the first are LACP ports with key 0, all down, and three unused aggregators have a zero MAC. PAgP (CISCO-PAGP-MIB) is "off" on every port of the walks,
 * so only LACP is read; a PAgP or static ("on") channel is not listed.
 */
import { toNum, type SnmpClient, type SnmpValue } from './client.js';

type Level = 'ok' | 'warn' | 'bad' | 'off';
export interface LagMember { ifIndex: number; bundled: boolean; collecting: boolean; distributing: boolean; partnerInSync: boolean; defaulted: boolean; expired: boolean; level: Level; why: string }
export interface Channel { ifIndex: number; key: number; partnerMac: string; members: LagMember[]; level: Level; problems: string[] }
const AGG = '1.2.840.10006.300.43.1.1.1.1', PORT = '1.2.840.10006.300.43.1.2.1.1';
const EMPTY = new Map<string, SnmpValue>();
const macOf = (b: SnmpValue | undefined): string => (Buffer.isBuffer(b) && b.length === 6 ? [...b].map(x => x.toString(16).padStart(2, '0')).join(':') : '');
// LACP state bits, first bit of the first byte first
const BIT = { timeout: 0x40, sync: 0x10, collecting: 0x08, distributing: 0x04, defaulted: 0x02, expired: 0x01 } as const;
const has = (v: SnmpValue | undefined, bit: number): boolean => Buffer.isBuffer(v) && v.length > 0 && (v[0]! & bit) !== 0;

export async function readLag(c: SnmpClient): Promise<Channel[]> {
  const col = (o: string) => c.column(o, 50).catch(() => EMPTY);
  const [mac, okey, pAdmin, pSel, pAtt, pActor, pPartner, stack] = await Promise.all([`${AGG}.2`, `${AGG}.7`, `${PORT}.4`, `${PORT}.12`, `${PORT}.13`, `${PORT}.21`, `${PORT}.23`, '1.3.6.1.2.1.31.1.2.1.3'].map(col));
  const used = (k: string) => { const m = macOf(mac!.get(k)); return m !== '' && m !== '00:00:00:00:00:00'; };
  const byAgg = new Map<number, Channel>();
  const chan = (id: number): Channel | null => {
    if (!used(String(id))) return null;
    let ch = byAgg.get(id);
    if (!ch) { ch = { ifIndex: id, key: toNum(okey!.get(String(id)) ?? null) ?? 0, partnerMac: '', members: [], level: 'ok', problems: [] }; byAgg.set(id, ch); }
    return ch;
  };
  for (const k of mac!.keys()) { const id = Number(k); if (Number.isInteger(id) && used(k)) chan(id); }
  for (const [k] of pAdmin!) {
    const port = Number(k); if (!Number.isInteger(port)) continue;
    const att = toNum(pAtt!.get(k) ?? null) ?? 0, sel = toNum(pSel!.get(k) ?? null) ?? 0, agg = att || sel;
    if (!agg) continue;
    const ch = chan(agg); if (!ch) continue;
    const a = pActor!.get(k), p = pPartner!.get(k);
    const m: LagMember = {
      ifIndex: port, bundled: att === agg, collecting: has(a, BIT.collecting), distributing: has(a, BIT.distributing), partnerInSync: has(p, BIT.sync),
      defaulted: has(a, BIT.defaulted), expired: has(a, BIT.expired), level: 'ok', why: ''
    };
    if (!m.bundled) { m.level = 'warn'; m.why = 'selected for the channel but not yet bundled'; }
    else if (m.expired) { m.level = 'bad'; m.why = 'the LACP partner stopped sending (expired)'; }
    else if (m.defaulted) { m.level = 'warn'; m.why = 'no LACP partner has been heard, so the port runs on defaults'; }
    else if (!m.partnerInSync) { m.level = 'warn'; m.why = 'the partner is not in sync'; }
    else if (!m.collecting || !m.distributing) { m.level = 'warn'; m.why = `bundled but not ${!m.collecting && !m.distributing ? 'collecting or distributing' : !m.collecting ? 'collecting' : 'distributing'}`; }
    ch.members.push(m);
  }
  // configured members that LACP does not list: the port is down, or never joined
  for (const k of stack!.keys()) {
    const [hi, lo] = k.split('.').map(Number); if (hi === undefined || !lo) continue;
    const ch = byAgg.get(hi); if (!ch || ch.members.some(m => m.ifIndex === lo)) continue;
    ch.members.push({ ifIndex: lo, bundled: false, collecting: false, distributing: false, partnerInSync: false, defaulted: false, expired: false, level: 'warn', why: 'configured in the channel but not bundled: the port is down or not running LACP' });
  }
  const out = [...byAgg.values()];
  for (const ch of out) {
    ch.members.sort((a, b) => a.ifIndex - b.ifIndex);
    const ok = ch.members.filter(m => m.level === 'ok').length;
    if (!ch.members.length) { ch.level = 'bad'; ch.problems.push('No member port is attached: every port of this channel is down or not bundled.'); }
    else {
      const bad = ch.members.filter(m => m.level !== 'ok');
      if (!ok) { ch.level = 'bad'; ch.problems.push('No member is carrying traffic.'); }
      else if (bad.length) { ch.level = 'warn'; ch.problems.push(`${bad.length} of ${ch.members.length} members ${bad.length === 1 ? 'is' : 'are'} not carrying traffic.`); }
      else if (ch.members.length === 1) ch.problems.push('Only one member port is in this channel, so it has no second link to fall back on.');
    }
  }
  return out.sort((a, b) => a.ifIndex - b.ifIndex);
}
