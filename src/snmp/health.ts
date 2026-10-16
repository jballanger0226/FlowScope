/**
 * Hardware and protocol health read from standard and vendor MIBs: sensors (temperature, fans, power, optics), PoE budget, spanning tree,
 * OSPF and BGP neighbours, and per-interface link quality (EtherLike-MIB, IF-MIB cast counters).
 *
 * The OIDs were checked against the published MIB definitions. None of it has been run against real hardware from every vendor here, so each
 * reader treats a missing table as "not published" and never fails the poll.
 */
import { toBigInt, toNum, toStr, type SnmpClient, type SnmpValue } from './client.js';
import { ipOf } from './multicast.js';

export type SensorKind = 'temperature' | 'fan' | 'power' | 'voltage' | 'current' | 'optic' | 'humidity' | 'status' | 'other';
export type Level = 'ok' | 'warn' | 'bad' | 'off';
export interface Sensor {
  id: string; kind: SensorKind; name: string; value: number | null; unit: string; state: Level; stateText: string;
  /** An optic's reading: 'tx' and 'rx' light levels, 'temp' for the module temperature */
  optic?: 'tx' | 'rx' | 'temp' | 'other';
  /** The interface an optic belongs to, filled in from the device's interface list when served */
  ifIndex?: number;
}
export interface Poe { group: number; budgetW: number | null; usedW: number | null; usedPct: number | null; status: 'on' | 'off' | 'faulty' | 'unknown'; portsDelivering: number; portsFault: number; portsTotal: number }
export interface Stp { rootId: string; isRoot: boolean; rootPort: number; rootCost: number; topChanges: number | null; sinceChangeSec: number | null; blockingPorts: number; ports: number }
export interface OspfNeighbor { id: string; address: string; state: string; level: Level }
export interface BgpPeer { address: string; as: number | null; state: string; level: Level; admin: string; upSec: number | null; updatesIn: number | null; updatesOut: number | null }
/** An EIGRP neighbour (CISCO-EIGRP-MIB). The table lists only neighbours that have formed, so a lost one is absent, not shown down. */
export interface EigrpPeer { as: number; address: string; ifIndex: number; holdSec: number | null; upText: string; srttMs: number | null; retrans: number | null; retries: number | null; level: Level }
/** A BFD session (CISCO-IETF-BFD-MIB): the fast failure detector that routing protocols are often tied to. */
export interface BfdSession { id: number; /** The neighbour when it can be worked out, otherwise this device's own address */ address: string; local?: string; peerKnown?: boolean; ifIndex: number | null; state: string; level: Level; upSec: number | null; upCount: number | null; diag: string | null; detectMs: number | null }
/** `eigrp` and `bfd` are absent from health stored before they were read */
export interface Health { readAt: number; sensors: Sensor[]; poe: Poe[]; stp: Stp | null; ospf: OspfNeighbor[]; bgp: BgpPeer[]; bgpLocalAs: number | null; eigrp?: EigrpPeer[]; bfd?: BfdSession[] }
export const EMPTY_HEALTH = (readAt: number): Health => ({ readAt, sensors: [], poe: [], stp: null, ospf: [], bgp: [], bgpLocalAs: null, eigrp: [], bfd: [] });

const num = (v: SnmpValue | undefined): number | null => (v === undefined || v === null ? null : toNum(v));
const EMPTY = new Map<string, SnmpValue>();
type Cols = (o: string) => Promise<Map<string, SnmpValue>>;
const colsOf = (c: SnmpClient): Cols => (o: string) => c.column(o).catch(() => EMPTY);

/* ------------------------------------------------------------------ sensors */

const ENTITY = { name: '1.3.6.1.2.1.47.1.1.1.1.7', descr: '1.3.6.1.2.1.47.1.1.1.1.2' };
const ESENS = { type: '1.3.6.1.2.1.99.1.1.1.1', scale: '1.3.6.1.2.1.99.1.1.1.2', prec: '1.3.6.1.2.1.99.1.1.1.3', value: '1.3.6.1.2.1.99.1.1.1.4', oper: '1.3.6.1.2.1.99.1.1.1.5' };
const CSENS = { type: '1.3.6.1.4.1.9.9.91.1.1.1.1.1', scale: '1.3.6.1.4.1.9.9.91.1.1.1.1.2', prec: '1.3.6.1.4.1.9.9.91.1.1.1.1.3', value: '1.3.6.1.4.1.9.9.91.1.1.1.1.4', oper: '1.3.6.1.4.1.9.9.91.1.1.1.1.5',
  thrSeverity: '1.3.6.1.4.1.9.9.91.1.2.1.1.2', thrRelation: '1.3.6.1.4.1.9.9.91.1.2.1.1.3', thrValue: '1.3.6.1.4.1.9.9.91.1.2.1.1.4' };
const ENVMON = { tempDescr: '1.3.6.1.4.1.9.9.13.1.3.1.2', tempValue: '1.3.6.1.4.1.9.9.13.1.3.1.3', tempValue1: '1.3.6.1.4.1.9.9.13.1.3.1.7', tempState: '1.3.6.1.4.1.9.9.13.1.3.1.6',
  fanDescr: '1.3.6.1.4.1.9.9.13.1.4.1.2', fanState: '1.3.6.1.4.1.9.9.13.1.4.1.3', supDescr: '1.3.6.1.4.1.9.9.13.1.5.1.2', supState: '1.3.6.1.4.1.9.9.13.1.5.1.3',
  voltDescr: '1.3.6.1.4.1.9.9.13.1.2.1.2', voltValue: '1.3.6.1.4.1.9.9.13.1.2.1.3', voltState: '1.3.6.1.4.1.9.9.13.1.2.1.7' };
const JNX = { descr: '1.3.6.1.4.1.2636.3.1.13.1.5', state: '1.3.6.1.4.1.2636.3.1.13.1.6', temp: '1.3.6.1.4.1.2636.3.1.13.1.7' };
const HW_TEMP = '1.3.6.1.4.1.2011.5.25.31.1.1.1.1.11', H3C_TEMP = '1.3.6.1.4.1.25506.2.6.1.1.1.1.12';

const UNIT: Record<number, [SensorKind, string]> = { 3: ['voltage', 'V'], 4: ['voltage', 'V'], 5: ['current', 'A'], 6: ['power', 'W'], 7: ['other', 'Hz'], 8: ['temperature', '°C'], 9: ['humidity', '%'], 10: ['fan', 'RPM'], 11: ['other', 'CFM'], 12: ['status', ''], 14: ['optic', 'dBm'], 15: ['other', 'dB'] };

/** The value of a sensor row in its base unit: the raw number with its decimal places (precision) and its SI prefix (scale) applied. */
export function sensorValue(raw: number, scale: number, precision: number): number {
  const exp = (scale - 9) * 3 - precision;
  return Number((raw * Math.pow(10, exp)).toFixed(3));
}

const OPTIC_NAME = /transceiver|\bsfp|\bxfp|qsfp|optic|module (temperature|transmit|receive|bias)|(transmit|receive|tx|rx)\s*(power|lane)|lane \d|(ethernet|gigabit)\S*\d/i;

function classify(typeNum: number, name: string): { kind: SensorKind; optic?: Sensor['optic'] } {
  const [kind] = UNIT[typeNum] ?? ['other', ''];
  const n = name.toLowerCase();
  if (kind === 'optic' || (kind === 'temperature' && OPTIC_NAME.test(name)) || (kind === 'power' && /transmit|receive|\btx\b|\brx\b/.test(n) && OPTIC_NAME.test(name))) {
    const optic = kind === 'temperature' ? 'temp' : /transmit|\btx\b/.test(n) ? 'tx' : /receive|\brx\b/.test(n) ? 'rx' : 'other';
    return { kind: 'optic', optic };
  }
  if (kind === 'other' && /fan/.test(n)) return { kind: 'fan' };
  if (kind === 'status' && /fan/.test(n)) return { kind: 'fan' };
  if (kind === 'status' && /power|psu|supply|\bpem\b/.test(n)) return { kind: 'power' };
  return { kind };
}

/** A threshold crossed by a sensor value: CISCO-ENTITY-SENSOR-MIB severity minor(10) is a warning, major(20) and critical(30) are bad. */
export function thresholdLevel(value: number, thresholds: { severity: number; relation: number; value: number }[]): Level {
  let level: Level = 'ok';
  for (const t of thresholds) {
    const hit = t.relation === 1 ? value < t.value : t.relation === 2 ? value <= t.value : t.relation === 3 ? value > t.value : t.relation === 4 ? value >= t.value : t.relation === 5 ? value === t.value : t.relation === 6 ? value !== t.value : false;
    if (!hit) continue;
    const l: Level = t.severity >= 20 ? 'bad' : 'warn';
    if (l === 'bad') return 'bad';
    level = 'warn';
  }
  return level;
}

async function entityNames(col: Cols): Promise<Map<string, string>> {
  const [name, descr] = await Promise.all([col(ENTITY.name), col(ENTITY.descr)]);
  const out = new Map<string, string>();
  for (const [k, v] of descr) out.set(k, toStr(v));
  for (const [k, v] of name) { const s = toStr(v); if (s) out.set(k, s); }
  return out;
}

async function entitySensors(col: Cols, tabs: typeof ESENS, names: Map<string, string>, withThresholds: boolean, idPrefix: string): Promise<Sensor[]> {
  const [type, scale, prec, value, oper] = await Promise.all([col(tabs.type), col(tabs.scale), col(tabs.prec), col(tabs.value), col(tabs.oper)]);
  if (!type.size) return [];
  const thr = new Map<string, { severity: number; relation: number; value: number }[]>();
  if (withThresholds) {
    const [sev, rel, tv] = await Promise.all([col(CSENS.thrSeverity), col(CSENS.thrRelation), col(CSENS.thrValue)]);
    for (const [k, v] of sev) {
      const ent = k.split('.')[0];
      const relation = num(rel.get(k)), tval = num(tv.get(k)), severity = num(v);
      if (relation === null || tval === null || severity === null) continue;
      (thr.get(ent) ?? thr.set(ent, []).get(ent)!).push({ severity, relation, value: tval });
    }
  }
  const out: Sensor[] = [];
  for (const [k, tv] of type) {
    const t = num(tv); if (t === null || !UNIT[t] || t === 2 || t === 1) continue;
    const name = names.get(k) || `sensor ${k}`;
    const st = num(oper.get(k)) ?? 1;
    const sc = num(scale.get(k)) ?? 9, pr = num(prec.get(k)) ?? 0, raw = num(value.get(k));
    const cls = classify(t, name);
    const unit = UNIT[t][1];
    let v: number | null = raw === null ? null : sensorValue(raw, sc, pr);
    let state: Level = 'ok', text = 'ok';
    if (st === 2) { state = 'off'; text = 'not available'; v = null; }
    else if (st === 3) { state = 'bad'; text = 'not operating'; }
    else if (t === 12) { state = v === 1 ? 'ok' : 'bad'; text = v === 1 ? 'ok' : 'fault'; }
    else if (v !== null && thr.has(k)) {
      // thresholds are in the same scale as the sensor's own value
      const tl = thresholdLevel(v, thr.get(k)!.map(x => ({ ...x, value: sensorValue(x.value, sc, pr) })));
      state = tl; text = tl === 'ok' ? 'ok' : tl === 'warn' ? 'over a minor limit' : 'over a major limit';
    }
    out.push({ id: `${idPrefix}:${k}`, kind: cls.kind, name, value: t === 12 ? null : v, unit, state, stateText: text, ...(cls.optic ? { optic: cls.optic } : {}) });
  }
  return out;
}

const ENVMON_STATE: Record<number, [Level, string]> = { 1: ['ok', 'normal'], 2: ['warn', 'warning'], 3: ['bad', 'critical'], 4: ['bad', 'shutdown'], 5: ['off', 'not present'], 6: ['bad', 'not functioning'] };

async function envmonSensors(col: Cols): Promise<Sensor[]> {
  const [td, tv, tv1, ts, fd, fs, sd, ss, vd, vv, vs] = await Promise.all([col(ENVMON.tempDescr), col(ENVMON.tempValue), col(ENVMON.tempValue1), col(ENVMON.tempState), col(ENVMON.fanDescr), col(ENVMON.fanState),
    col(ENVMON.supDescr), col(ENVMON.supState), col(ENVMON.voltDescr), col(ENVMON.voltValue), col(ENVMON.voltState)]);
  const out: Sensor[] = [];
  const lv = (n: number | null): [Level, string] => ENVMON_STATE[n ?? 0] ?? ['off', 'unknown'];
  for (const [k, d] of td) { const [state, stateText] = lv(num(ts.get(k))); out.push({ id: `envT:${k}`, kind: 'temperature', name: toStr(d), value: num(tv1.get(k)) ?? num(tv.get(k)), unit: '°C', state, stateText }); }
  for (const [k, d] of fd) { const [state, stateText] = lv(num(fs.get(k))); out.push({ id: `envF:${k}`, kind: 'fan', name: toStr(d), value: null, unit: '', state, stateText }); }
  for (const [k, d] of sd) { const [state, stateText] = lv(num(ss.get(k))); out.push({ id: `envS:${k}`, kind: 'power', name: toStr(d), value: null, unit: '', state, stateText }); }
  for (const [k, d] of vd) { const [state, stateText] = lv(num(vs.get(k))); const mv = num(vv.get(k)); out.push({ id: `envV:${k}`, kind: 'voltage', name: toStr(d), value: mv === null ? null : mv / 1000, unit: 'V', state, stateText }); }
  return out;
}

const JNX_STATE: Record<number, [Level, string]> = { 1: ['off', 'unknown'], 2: ['ok', 'running'], 3: ['ok', 'ready'], 4: ['warn', 'reset'], 5: ['ok', 'running at full speed'], 6: ['bad', 'down'], 7: ['ok', 'standby'] };

async function juniperSensors(col: Cols): Promise<Sensor[]> {
  const [descr, state, temp] = await Promise.all([col(JNX.descr), col(JNX.state), col(JNX.temp)]);
  const out: Sensor[] = [];
  for (const [k, d] of descr) {
    const name = toStr(d), t = num(temp.get(k)), st = JNX_STATE[num(state.get(k)) ?? 1] ?? ['off', 'unknown'];
    if (t !== null && t > 0) out.push({ id: `jnxT:${k}`, kind: 'temperature', name, value: t, unit: '°C', state: st[0] === 'bad' ? 'bad' : 'ok', stateText: st[1] });
    if (/power|\bpem\b|\bpsu\b/i.test(name)) out.push({ id: `jnxP:${k}`, kind: 'power', name, value: null, unit: '', state: st[0], stateText: st[1] });
    else if (/fan/i.test(name)) out.push({ id: `jnxF:${k}`, kind: 'fan', name, value: null, unit: '', state: st[0], stateText: st[1] });
  }
  return out;
}

async function tempColumn(col: Cols, oid: string, names: Map<string, string>, id: string): Promise<Sensor[]> {
  const t = await col(oid);
  const out: Sensor[] = [];
  for (const [k, v] of t) { const n = num(v); if (n !== null && n > 0 && n < 200) out.push({ id: `${id}:${k}`, kind: 'temperature', name: names.get(k) || `board ${k}`, value: n, unit: '°C', state: 'ok', stateText: 'ok' }); }
  return out;
}

/** Temperature, fan, power, voltage and optic sensors: ENTITY-SENSOR-MIB first (Cisco's own version where there are thresholds), then the vendor MIBs of devices that do not publish it. */
export async function readSensors(c: SnmpClient, objectId = ''): Promise<Sensor[]> {
  const col = colsOf(c);
  const names = await entityNames(col);
  const cisco = objectId.startsWith('1.3.6.1.4.1.9.');
  let sensors: Sensor[] = [];
  if (cisco) sensors = await entitySensors(col, CSENS as unknown as typeof ESENS, names, true, 'cisco');
  if (!sensors.length) sensors = await entitySensors(col, ESENS, names, false, 'ent');
  // Cisco's sensor MIB is also tried on a device of unknown make, but not on one known to be another vendor's
  const otherVendor = /^1\.3\.6\.1\.4\.1\.(2636|2011|25506|11|12356|25461|30065|8072|14823|41112|25053|14988)\./.test(objectId);
  if (!sensors.length && !cisco && !otherVendor) sensors = await entitySensors(col, CSENS as unknown as typeof ESENS, names, true, 'cisco');
  // Cisco's older MIB covers fans and supplies on boxes whose ENTITY-SENSOR has temperatures and optics only
  if (cisco && !sensors.some(s => s.kind === 'fan' || s.kind === 'power')) sensors = [...sensors, ...(await envmonSensors(col)).filter(s => !(sensors.some(x => x.kind === 'temperature') && s.kind === 'temperature'))];
  if (!sensors.length) {
    if (objectId.startsWith('1.3.6.1.4.1.2636.')) sensors = await juniperSensors(col);
    else if (objectId.startsWith('1.3.6.1.4.1.2011.')) sensors = await tempColumn(col, HW_TEMP, names, 'hw');
    else if (objectId.startsWith('1.3.6.1.4.1.25506.')) sensors = await tempColumn(col, H3C_TEMP, names, 'h3c');
  }
  const order: Record<SensorKind, number> = { temperature: 0, fan: 1, power: 2, voltage: 3, current: 4, humidity: 5, status: 6, optic: 7, other: 8 };
  return sensors.sort((a, b) => order[a.kind] - order[b.kind] || a.name.localeCompare(b.name, undefined, { numeric: true }));
}

/** The hottest chassis temperature, leaving out optics (a warm transceiver is its own story). */
export function hottest(sensors: Sensor[]): number | null {
  const t = sensors.filter(s => s.kind === 'temperature' && s.state !== 'off' && s.value !== null).map(s => s.value as number);
  return t.length ? Math.max(...t) : null;
}

/** Links optic sensors to interfaces by the interface name being at the start of the sensor name ("TenGigabitEthernet1/1/1 Transmit Power Sensor"). */
export function linkOptics(sensors: Sensor[], ifaces: { index: number; name: string; descr: string }[]): Sensor[] {
  const byLen = [...ifaces].sort((a, b) => Math.max(b.name.length, b.descr.length) - Math.max(a.name.length, a.descr.length));
  return sensors.map(s => {
    if (s.kind !== 'optic') return s;
    const n = s.name.toLowerCase();
    const hit = byLen.find(i => [i.descr, i.name].some(x => x && n.startsWith(x.toLowerCase()) && !/\d/.test(n.charAt(x.length) || ' ')));
    return hit ? { ...s, ifIndex: hit.index } : s;
  });
}

/* ------------------------------------------------------------------ PoE (POWER-ETHERNET-MIB, RFC 3621) */

const PETH = { power: '1.3.6.1.2.1.105.1.3.1.1.2', oper: '1.3.6.1.2.1.105.1.3.1.1.3', used: '1.3.6.1.2.1.105.1.3.1.1.4', portStatus: '1.3.6.1.2.1.105.1.1.1.6' };

export async function readPoe(c: SnmpClient): Promise<Poe[]> {
  const col = colsOf(c);
  const [power, oper, used, ports] = await Promise.all([col(PETH.power), col(PETH.oper), col(PETH.used), col(PETH.portStatus)]);
  const groups = new Set<string>([...power.keys(), ...oper.keys()]);
  const out: Poe[] = [];
  for (const g of [...groups].sort((a, b) => Number(a) - Number(b))) {
    const mine = [...ports].filter(([k]) => k.split('.')[0] === g).map(([, v]) => num(v));
    const budget = num(power.get(g)), usedW = num(used.get(g)), st = num(oper.get(g));
    out.push({
      group: Number(g), budgetW: budget, usedW, usedPct: budget && budget > 0 && usedW !== null ? Math.round((usedW / budget) * 1000) / 10 : null,
      status: st === 1 ? 'on' : st === 2 ? 'off' : st === 3 ? 'faulty' : 'unknown',
      portsDelivering: mine.filter(x => x === 3).length, portsFault: mine.filter(x => x === 4 || x === 6).length, portsTotal: mine.length
    });
  }
  return out;
}

/* ------------------------------------------------------------------ spanning tree (BRIDGE-MIB) */

const STP = { addr: '1.3.6.1.2.1.17.1.1.0', since: '1.3.6.1.2.1.17.2.3.0', changes: '1.3.6.1.2.1.17.2.4.0', root: '1.3.6.1.2.1.17.2.5.0', cost: '1.3.6.1.2.1.17.2.6.0', rootPort: '1.3.6.1.2.1.17.2.7.0', portState: '1.3.6.1.2.1.17.2.15.1.3' };

const bridgeId = (b: SnmpValue | undefined): string => (Buffer.isBuffer(b) && b.length === 8 ? `${b.readUInt16BE(0)}/${[...b.subarray(2)].map(x => x.toString(16).padStart(2, '0')).join(':')}` : '');

export async function readStp(c: SnmpClient): Promise<Stp | null> {
  let m: Map<string, { value: SnmpValue }>;
  try { m = await c.get([STP.addr, STP.since, STP.changes, STP.root, STP.cost, STP.rootPort]); } catch { return null; }
  const rootRaw = m.get(STP.root)?.value;
  const rootId = bridgeId(rootRaw);
  if (!rootId) return null;
  const addr = m.get(STP.addr)?.value;
  const myMac = Buffer.isBuffer(addr) && addr.length === 6 ? [...addr].map(x => x.toString(16).padStart(2, '0')).join(':') : '';
  const states = await colsOf(c)(STP.portState);
  const st = [...states.values()].map(num);
  const since = num(m.get(STP.since)?.value);
  return {
    rootId, isRoot: !!myMac && rootId.endsWith('/' + myMac), rootPort: num(m.get(STP.rootPort)?.value) ?? 0, rootCost: num(m.get(STP.cost)?.value) ?? 0,
    topChanges: num(m.get(STP.changes)?.value), sinceChangeSec: since === null ? null : Math.floor(since / 100),
    blockingPorts: st.filter(x => x === 2).length, ports: st.length
  };
}

/* ------------------------------------------------------------------ OSPF-MIB and BGP4-MIB */

const OSPF = { rtr: '1.3.6.1.2.1.14.10.1.3', state: '1.3.6.1.2.1.14.10.1.6' };
const OSPF_STATE: Record<number, [string, Level]> = { 1: ['down', 'bad'], 2: ['attempt', 'warn'], 3: ['init', 'warn'], 4: ['two-way', 'ok'], 5: ['exstart', 'warn'], 6: ['exchange', 'warn'], 7: ['loading', 'warn'], 8: ['full', 'ok'] };

export async function readOspf(c: SnmpClient): Promise<OspfNeighbor[]> {
  const col = colsOf(c);
  const [state, rtr] = await Promise.all([col(OSPF.state), col(OSPF.rtr)]);
  const out: OspfNeighbor[] = [];
  for (const [k, v] of state) {
    const [st, level] = OSPF_STATE[num(v) ?? 0] ?? ['unknown', 'off' as Level];
    const parts = k.split('.');
    out.push({ id: toStr(rtr.get(k) ?? null) || '', address: parts.slice(0, 4).join('.'), state: st, level });
  }
  return out.sort((a, b) => a.address.localeCompare(b.address, undefined, { numeric: true }));
}

const BGP = { state: '1.3.6.1.2.1.15.3.1.2', admin: '1.3.6.1.2.1.15.3.1.3', as: '1.3.6.1.2.1.15.3.1.9', inUp: '1.3.6.1.2.1.15.3.1.10', outUp: '1.3.6.1.2.1.15.3.1.11', time: '1.3.6.1.2.1.15.3.1.16', local: '1.3.6.1.2.1.15.2.0' };
const BGP_STATE: Record<number, [string, Level]> = { 1: ['idle', 'bad'], 2: ['connect', 'warn'], 3: ['active', 'warn'], 4: ['open sent', 'warn'], 5: ['open confirm', 'warn'], 6: ['established', 'ok'] };

export async function readBgp(c: SnmpClient): Promise<{ peers: BgpPeer[]; localAs: number | null }> {
  const col = colsOf(c);
  const [state, admin, as, inUp, outUp, time] = await Promise.all([col(BGP.state), col(BGP.admin), col(BGP.as), col(BGP.inUp), col(BGP.outUp), col(BGP.time)]);
  const peers: BgpPeer[] = [];
  for (const [k, v] of state) {
    const [st, level] = BGP_STATE[num(v) ?? 0] ?? ['unknown', 'off' as Level];
    const a = num(admin.get(k));
    peers.push({ address: k, as: num(as.get(k)), state: st, level: a === 1 && level !== 'ok' ? 'off' : level, admin: a === 1 ? 'stop' : 'start', upSec: level === 'ok' ? num(time.get(k)) : null, updatesIn: num(inUp.get(k)), updatesOut: num(outUp.get(k)) });
  }
  let localAs: number | null = null;
  if (peers.length) { try { localAs = num((await c.get([BGP.local])).get(BGP.local)?.value); } catch { /* optional */ } }
  return { peers: peers.sort((a, b) => a.address.localeCompare(b.address, undefined, { numeric: true })), localAs };
}

/* ------------------------------------------------------------------ CISCO-EIGRP-MIB and CISCO-IETF-BFD-MIB */

const EIGRP = '1.3.6.1.4.1.9.9.449.1.4.1.1';
/** Peer rows are indexed vrf.as.handle; columns 3 address, 4 ifIndex, 5 hold time (s), 6 uptime as text like "3w1d", 7 smooth round trip (ms), 12 retransmissions, 13 retries of the current packet. */
export async function readEigrp(c: SnmpClient): Promise<EigrpPeer[]> {
  const col = colsOf(c);
  const [addr, ifx, hold, up, srtt, retrans, retries] = await Promise.all([3, 4, 5, 6, 7, 12, 13].map(n => col(`${EIGRP}.${n}`)));
  const out: EigrpPeer[] = [];
  for (const [k, v] of addr) {
    const p = k.split('.'); if (p.length < 3) continue;
    const a = ipOf(v); if (!a) continue;
    const r = num(retries.get(k));
    out.push({ as: Number(p[1]), address: a, ifIndex: num(ifx.get(k)) ?? 0, holdSec: num(hold.get(k)), upText: toStr(up.get(k) ?? null) || '', srttMs: num(srtt.get(k)), retrans: num(retrans.get(k)), retries: r, level: r !== null && r > 0 ? 'warn' : 'ok' });
  }
  return out.sort((a, b) => a.as - b.as || a.address.localeCompare(b.address, undefined, { numeric: true }));
}

const BFD = '1.3.6.1.4.1.9.10.137.1';
const BFD_STATE: Record<number, [string, Level]> = { 1: ['admin down', 'off'], 2: ['down', 'bad'], 3: ['init', 'warn'], 4: ['up', 'ok'] };
const BFD_DIAG: Record<number, string> = { 1: 'control detection time expired', 2: 'echo function failed', 3: 'neighbour signalled session down', 4: 'forwarding plane reset', 5: 'path down', 6: 'concatenated path down', 7: 'administratively down', 8: 'reverse concatenated path down' };
const IP_ADDR = '1.3.6.1.2.1.4.20.1';

/** The other end of a point-to-point subnet: a /30 has two usable addresses, a /31 two. Anything wider has no single answer. */
export function p2pPeer(local: string, mask: string | null): string | null {
  const l = local.split('.').map(Number), m = (mask ?? '').split('.').map(Number);
  if (l.length !== 4 || m.length !== 4 || l.some(x => !(x >= 0 && x <= 255)) || m.some(x => !(x >= 0 && x <= 255))) return null;
  const ln = ((l[0]! << 24) | (l[1]! << 16) | (l[2]! << 8) | l[3]!) >>> 0, mn = ((m[0]! << 24) | (m[1]! << 16) | (m[2]! << 8) | m[3]!) >>> 0;
  const host = ~mn >>> 0;
  let peer: number;
  if (host === 1) peer = (ln ^ 1) >>> 0;                           // /31
  else if (host === 3 && (ln & 3) !== 0 && (ln & 3) !== 3) peer = (ln & 3) === 1 ? ln + 1 : ln - 1;   // /30
  else return null;
  return [peer >>> 24, (peer >>> 16) & 255, (peer >>> 8) & 255, peer & 255].join('.');
}

/**
 * ciscoBfdSessAddr is this device's own address on the session, and ciscoBfdSessInterface is not the interface the neighbour is on (checked against `show bfd neighbors`
 * of a Catalyst 9300 stack). The interface comes from the interface that owns that address (IP-MIB), and the neighbour is the other end of its /30 or /31.
 * One session is listed once for each client that registered it (for example a routing protocol and a static route), so sessions with the same address and
 * discriminators are shown once.
 */
export async function readBfd(c: SnmpClient): Promise<BfdSession[]> {
  const col = colsOf(c);
  const [state, addr, txi, mult, upTime, upCount, diag, ld, rd, ipIf, ipMask] = await Promise.all([
    col(`${BFD}.2.1.6`), col(`${BFD}.2.1.14`), col(`${BFD}.2.1.15`), col(`${BFD}.2.1.18`), col(`${BFD}.3.1.3`), col(`${BFD}.3.1.6`), col(`${BFD}.3.1.5`), col(`${BFD}.2.1.3`), col(`${BFD}.2.1.4`),
    col(`${IP_ADDR}.2`), col(`${IP_ADDR}.3`)]);
  const seen = new Map<string, BfdSession>();
  for (const [k, v] of state) {
    const [st, level] = BFD_STATE[num(v) ?? 0] ?? ['unknown', 'off' as Level];
    const local = ipOf(addr.get(k) ?? null); if (!local) continue;
    const tx = num(txi.get(k)), m = num(mult.get(k)), d = num(diag.get(k)), ut = num(upTime.get(k));
    const peer = p2pPeer(local, ipOf(ipMask.get(local) ?? null));
    const s: BfdSession = { id: Number(k), address: peer ?? local, local, peerKnown: !!peer, ifIndex: num(ipIf.get(local)) || null, state: st, level, upSec: level === 'ok' && ut !== null ? Math.round(ut / 100) : null, upCount: num(upCount.get(k)),
      diag: d ? BFD_DIAG[d] ?? null : null, detectMs: tx !== null && m !== null ? Math.round((tx * m) / 1000) : null };
    const key = `${local}|${num(ld.get(k))}|${num(rd.get(k))}`;
    const have = seen.get(key);
    if (!have || (s.level !== 'ok' && have.level === 'ok') || (s.level === have.level && (s.upSec ?? 0) > (have.upSec ?? 0))) seen.set(key, s);
  }
  return [...seen.values()].sort((a, b) => a.address.localeCompare(b.address, undefined, { numeric: true }) || a.id - b.id);
}

/* ------------------------------------------------------------------ everything slow, in one read */

export async function readHealth(c: SnmpClient, objectId = '', now = Date.now()): Promise<Health | null> {
  const h = EMPTY_HEALTH(now);
  const tasks: Promise<unknown>[] = [
    readSensors(c, objectId).then(x => { h.sensors = x; }), readPoe(c).then(x => { h.poe = x; }), readStp(c).then(x => { h.stp = x; }),
    readOspf(c).then(x => { h.ospf = x; }), readBgp(c).then(x => { h.bgp = x.peers; h.bgpLocalAs = x.localAs; })
  ];
  // vendor-specific MIBs are only asked of the vendor that publishes them
  if (objectId.startsWith('1.3.6.1.4.1.9.')) tasks.push(readEigrp(c).then(x => { h.eigrp = x; }), readBfd(c).then(x => { h.bfd = x; }));
  await Promise.all(tasks.map(t => t.catch(() => undefined)));
  return h.sensors.length || h.poe.length || h.stp || h.ospf.length || h.bgp.length || h.eigrp?.length || h.bfd?.length ? h : null;
}

/* ------------------------------------------------------------------ interface link quality (EtherLike-MIB, IF-MIB) */

const DOT3 = { align: '1.3.6.1.2.1.10.7.2.1.2', fcs: '1.3.6.1.2.1.10.7.2.1.3', single: '1.3.6.1.2.1.10.7.2.1.4', multi: '1.3.6.1.2.1.10.7.2.1.5', late: '1.3.6.1.2.1.10.7.2.1.8', excessive: '1.3.6.1.2.1.10.7.2.1.9', carrier: '1.3.6.1.2.1.10.7.2.1.11', tooLong: '1.3.6.1.2.1.10.7.2.1.13', symbol: '1.3.6.1.2.1.10.7.2.1.18', duplex: '1.3.6.1.2.1.10.7.2.1.19' };
const IFX = { admin: '1.3.6.1.2.1.2.2.1.7', unknown: '1.3.6.1.2.1.2.2.1.15', inMc: '1.3.6.1.2.1.31.1.1.1.2', inBc: '1.3.6.1.2.1.31.1.1.1.3', outMc: '1.3.6.1.2.1.31.1.1.1.4', outBc: '1.3.6.1.2.1.31.1.1.1.5', hcInMc: '1.3.6.1.2.1.31.1.1.1.8', hcInBc: '1.3.6.1.2.1.31.1.1.1.9', hcOutMc: '1.3.6.1.2.1.31.1.1.1.12', hcOutBc: '1.3.6.1.2.1.31.1.1.1.13', inDisc: '1.3.6.1.2.1.2.2.1.13', inErr: '1.3.6.1.2.1.2.2.1.14', outDisc: '1.3.6.1.2.1.2.2.1.19', outErr: '1.3.6.1.2.1.2.2.1.20' };

const CISCO_IF = { inQ: '1.3.6.1.4.1.9.9.276.1.1.1.1.10', outQ: '1.3.6.1.4.1.9.9.276.1.1.1.1.11', resets: '1.3.6.1.4.1.9.9.276.1.1.2.1.1', reason: '1.3.6.1.4.1.9.9.276.1.1.2.1.3' };
/** cpscSuppressedPacket, indexed ifIndex.trafficType (broadcast, multicast, unicast, all) */
const CISCO_STORM = '1.3.6.1.4.1.9.9.362.1.2.1.1.3';
/** cpsIfViolationCount, indexed ifIndex */
const CISCO_PSEC = '1.3.6.1.4.1.9.9.315.1.2.1.1.9';
/** The packets storm control has suppressed on an interface, of every traffic type together. Absent when the interface has no storm control rows. */
function stormTotal(m: Map<string, SnmpValue>, ifIndex: string): number | undefined {
  let sum: number | undefined;
  for (const [k, v] of m) { if (!k.startsWith(ifIndex + '.')) continue; const b = toBigInt(v); if (b !== null) sum = (sum ?? 0) + Number(b); }
  return sum;
}

export const EXTRA_COUNTERS = ['fcs', 'align', 'symbol', 'late', 'excessive', 'collisions', 'carrier', 'tooLong', 'unknown', 'inMc', 'inBc', 'outMc', 'outBc', 'inErr', 'outErr', 'inDisc', 'outDisc', 'outQDrops', 'inQDrops', 'resets', 'storm', 'portSec'] as const;
export type ExtraCounter = (typeof EXTRA_COUNTERS)[number];
export interface IfExtra {
  duplex: 'full' | 'half' | 'unknown' | null;
  /** ifAdminStatus: 1 up, 2 down, 3 testing */
  admin: number | null;
  /** Why the interface last changed state, as the device words it (CISCO-IF-EXTENSION-MIB) */
  reason?: string | null;
  /** Counter totals as last read; a counter the device does not publish is absent */
  totals: Partial<Record<ExtraCounter, number>>;
  /** What each counter went up by since the previous read, and how many seconds that was */
  delta: Partial<Record<ExtraCounter, number>> | null; dtSec: number | null;
  readAt: number;
}

/** Reads the extra interface counters of every interface in one pass. A counter the device does not publish is left out of that interface's totals. */
export async function readIfExtra(c: SnmpClient, now = Date.now(), cisco = false): Promise<Map<number, IfExtra>> {
  const col = colsOf(c);
  // Cisco only: queue drops and resets (CISCO-IF-EXTENSION-MIB), storm control suppression and port security violations. Each table may be absent.
  const cx = cisco ? await Promise.all([col(CISCO_IF.inQ), col(CISCO_IF.outQ), col(CISCO_IF.resets), col(CISCO_IF.reason), col(CISCO_STORM), col(CISCO_PSEC)]) : null;
  const [align, fcs, single, multi, late, exc, carrier, tooLong, symbol, duplex, admin, unknown, inMc, inBc, outMc, outBc, hInMc, hInBc, hOutMc, hOutBc, inErr, outErr, inDisc, outDisc] = await Promise.all([
    col(DOT3.align), col(DOT3.fcs), col(DOT3.single), col(DOT3.multi), col(DOT3.late), col(DOT3.excessive), col(DOT3.carrier), col(DOT3.tooLong), col(DOT3.symbol), col(DOT3.duplex),
    col(IFX.admin), col(IFX.unknown), col(IFX.inMc), col(IFX.inBc), col(IFX.outMc), col(IFX.outBc), col(IFX.hcInMc), col(IFX.hcInBc), col(IFX.hcOutMc), col(IFX.hcOutBc),
    col(IFX.inErr), col(IFX.outErr), col(IFX.inDisc), col(IFX.outDisc)
  ]);
  const keys = new Set<string>([...admin.keys(), ...fcs.keys(), ...duplex.keys(), ...inBc.keys(), ...hInBc.keys()]);
  const n = (m: Map<string, SnmpValue>, k: string): number | undefined => { const v = m.get(k); if (v === undefined || v === null) return undefined; const b = toBigInt(v); return b === null ? undefined : Number(b); };
  const out = new Map<number, IfExtra>();
  for (const k of keys) {
    const idx = Number(k); if (!Number.isInteger(idx) || idx <= 0) continue;
    const totals: Partial<Record<ExtraCounter, number>> = {};
    const put = (name: ExtraCounter, v: number | undefined) => { if (v !== undefined) totals[name] = v; };
    put('fcs', n(fcs, k)); put('align', n(align, k)); put('symbol', n(symbol, k)); put('late', n(late, k)); put('excessive', n(exc, k)); put('carrier', n(carrier, k)); put('tooLong', n(tooLong, k));
    const s = n(single, k), m = n(multi, k); if (s !== undefined || m !== undefined) totals.collisions = (s ?? 0) + (m ?? 0);
    put('unknown', n(unknown, k));
    put('inMc', n(hInMc, k) ?? n(inMc, k)); put('inBc', n(hInBc, k) ?? n(inBc, k)); put('outMc', n(hOutMc, k) ?? n(outMc, k)); put('outBc', n(hOutBc, k) ?? n(outBc, k));
    put('inErr', n(inErr, k)); put('outErr', n(outErr, k)); put('inDisc', n(inDisc, k)); put('outDisc', n(outDisc, k));
    if (cx) { put('inQDrops', n(cx[0], k)); put('outQDrops', n(cx[1], k)); put('resets', n(cx[2], k)); put('storm', stormTotal(cx[4], k)); put('portSec', n(cx[5], k)); }
    const d = n(duplex, k);
    out.set(idx, { reason: cx ? toStr(cx[3].get(k) ?? null) || null : undefined, duplex: d === 3 ? 'full' : d === 2 ? 'half' : d === 1 ? 'unknown' : null, admin: n(admin, k) ?? null, totals, delta: null, dtSec: null, readAt: now });
  }
  return out;
}

/** What each counter went up by since the previous read. A counter that went backwards (device restart or a wrap) gives no figure for that interval. */
export function diffExtra(prev: IfExtra | undefined, cur: IfExtra): IfExtra {
  if (!prev || cur.readAt <= prev.readAt) return cur;
  const dt = (cur.readAt - prev.readAt) / 1000;
  if (dt > 3600) return cur;
  const delta: Partial<Record<ExtraCounter, number>> = {};
  for (const k of EXTRA_COUNTERS) {
    const a = prev.totals[k], b = cur.totals[k];
    if (a === undefined || b === undefined || b < a) continue;
    delta[k] = b - a;
  }
  return { ...cur, delta, dtSec: Math.round(dt) };
}

/** Plain-language problems with a link, from its latest read. Half duplex on a fast link, errors still arriving, and broadcast or multicast storms. */
export function linkWarnings(x: IfExtra, oper: number, speedMbps: number): { level: Level; text: string }[] {
  const out: { level: Level; text: string }[] = [];
  if (oper === 1 && x.duplex === 'half' && speedMbps >= 1000) out.push({ level: 'bad', text: 'Half duplex on a gigabit or faster link. Almost always a duplex mismatch or a bad cable.' });
  else if (oper === 1 && x.duplex === 'half') out.push({ level: 'warn', text: 'Half duplex. If the other end is full duplex, expect errors and slow transfers.' });
  const d = x.delta;
  if (d && x.dtSec) {
    const bad = (d.fcs ?? 0) + (d.align ?? 0) + (d.symbol ?? 0);
    if (bad > 0) out.push({ level: bad >= 100 ? 'bad' : 'warn', text: `${bad} frame errors (CRC, alignment or symbol) arrived in the last ${x.dtSec < 120 ? x.dtSec + ' seconds' : Math.round(x.dtSec / 60) + ' minutes'}. Check the cable, the optic and the duplex setting.` });
    const late = (d.late ?? 0) + (d.excessive ?? 0);
    if (late > 0) out.push({ level: 'bad', text: `${late} late or excessive collisions in the last interval. That only happens on half duplex links, so check for a duplex mismatch.` });
    const bc = ((d.inBc ?? 0) + (d.outBc ?? 0)) / x.dtSec, mc = ((d.inMc ?? 0) + (d.outMc ?? 0)) / x.dtSec;
    if (bc >= 1000) out.push({ level: bc >= 5000 ? 'bad' : 'warn', text: `${Math.round(bc).toLocaleString('en-US')} broadcast packets per second. A sustained rate like this usually means a loop or a misbehaving host.` });
    if (mc >= 5000) out.push({ level: 'warn', text: `${Math.round(mc).toLocaleString('en-US')} multicast packets per second.` });
    const span = x.dtSec < 120 ? x.dtSec + ' seconds' : Math.round(x.dtSec / 60) + ' minutes';
    if ((d.outQDrops ?? 0) > 0) out.push({ level: 'warn', text: `${d.outQDrops!.toLocaleString('en-US')} packets were dropped from this port's output queue in the last ${span}. The port is congested: traffic is arriving faster than it can be sent.` });
    if ((d.inQDrops ?? 0) > 0) out.push({ level: 'warn', text: `${d.inQDrops!.toLocaleString('en-US')} packets were dropped from the input queue in the last ${span}. The device could not keep up with what this port received.` });
    if ((d.storm ?? 0) > 0) out.push({ level: 'warn', text: `Storm control suppressed ${d.storm!.toLocaleString('en-US')} packets in the last ${span}. Broadcast, multicast or unicast traffic on this port went over its configured limit.` });
    if ((d.portSec ?? 0) > 0) out.push({ level: 'warn', text: `${d.portSec!.toLocaleString('en-US')} port security violation${d.portSec === 1 ? '' : 's'} in the last ${span}. A device with an unexpected MAC address sent traffic on this port.` });
    if ((d.resets ?? 0) > 0) out.push({ level: 'warn', text: `This interface was reset ${d.resets} time${d.resets === 1 ? '' : 's'} in the last ${span}${x.reason ? ` (last state change: ${x.reason})` : ''}.` });
  }
  return out;
}
