/**
 * Hardware and protocol health read from standard and vendor MIBs: sensors (temperature, fans, power, optics), PoE budget, spanning tree,
 * OSPF and BGP neighbours, and per-interface link quality (EtherLike-MIB, IF-MIB cast counters).
 *
 * The OIDs were checked against the published MIB definitions. None of it has been run against real hardware from every vendor here, so each
 * reader treats a missing table as "not published" and never fails the poll.
 */
import { toBigInt, toNum, toStr, type SnmpClient, type SnmpValue } from './client.js';

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
export interface Health { readAt: number; sensors: Sensor[]; poe: Poe[]; stp: Stp | null; ospf: OspfNeighbor[]; bgp: BgpPeer[]; bgpLocalAs: number | null }
export const EMPTY_HEALTH = (readAt: number): Health => ({ readAt, sensors: [], poe: [], stp: null, ospf: [], bgp: [], bgpLocalAs: null });

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
  if (!sensors.length && !cisco) sensors = await entitySensors(col, CSENS as unknown as typeof ESENS, names, true, 'cisco');
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

/* ------------------------------------------------------------------ everything slow, in one read */

export async function readHealth(c: SnmpClient, objectId = '', now = Date.now()): Promise<Health | null> {
  const h = EMPTY_HEALTH(now);
  const tasks: Promise<unknown>[] = [
    readSensors(c, objectId).then(x => { h.sensors = x; }), readPoe(c).then(x => { h.poe = x; }), readStp(c).then(x => { h.stp = x; }),
    readOspf(c).then(x => { h.ospf = x; }), readBgp(c).then(x => { h.bgp = x.peers; h.bgpLocalAs = x.localAs; })
  ];
  await Promise.all(tasks.map(t => t.catch(() => undefined)));
  return h.sensors.length || h.poe.length || h.stp || h.ospf.length || h.bgp.length ? h : null;
}

/* ------------------------------------------------------------------ interface link quality (EtherLike-MIB, IF-MIB) */

const DOT3 = { align: '1.3.6.1.2.1.10.7.2.1.2', fcs: '1.3.6.1.2.1.10.7.2.1.3', single: '1.3.6.1.2.1.10.7.2.1.4', multi: '1.3.6.1.2.1.10.7.2.1.5', late: '1.3.6.1.2.1.10.7.2.1.8', excessive: '1.3.6.1.2.1.10.7.2.1.9', carrier: '1.3.6.1.2.1.10.7.2.1.11', tooLong: '1.3.6.1.2.1.10.7.2.1.13', symbol: '1.3.6.1.2.1.10.7.2.1.18', duplex: '1.3.6.1.2.1.10.7.2.1.19' };
const IFX = { admin: '1.3.6.1.2.1.2.2.1.7', unknown: '1.3.6.1.2.1.2.2.1.15', inMc: '1.3.6.1.2.1.31.1.1.1.2', inBc: '1.3.6.1.2.1.31.1.1.1.3', outMc: '1.3.6.1.2.1.31.1.1.1.4', outBc: '1.3.6.1.2.1.31.1.1.1.5', hcInMc: '1.3.6.1.2.1.31.1.1.1.8', hcInBc: '1.3.6.1.2.1.31.1.1.1.9', hcOutMc: '1.3.6.1.2.1.31.1.1.1.12', hcOutBc: '1.3.6.1.2.1.31.1.1.1.13', inDisc: '1.3.6.1.2.1.2.2.1.13', inErr: '1.3.6.1.2.1.2.2.1.14', outDisc: '1.3.6.1.2.1.2.2.1.19', outErr: '1.3.6.1.2.1.2.2.1.20' };

export const EXTRA_COUNTERS = ['fcs', 'align', 'symbol', 'late', 'excessive', 'collisions', 'carrier', 'tooLong', 'unknown', 'inMc', 'inBc', 'outMc', 'outBc', 'inErr', 'outErr', 'inDisc', 'outDisc'] as const;
export type ExtraCounter = (typeof EXTRA_COUNTERS)[number];
export interface IfExtra {
  duplex: 'full' | 'half' | 'unknown' | null;
  /** ifAdminStatus: 1 up, 2 down, 3 testing */
  admin: number | null;
  /** Counter totals as last read; a counter the device does not publish is absent */
  totals: Partial<Record<ExtraCounter, number>>;
  /** What each counter went up by since the previous read, and how many seconds that was */
  delta: Partial<Record<ExtraCounter, number>> | null; dtSec: number | null;
  readAt: number;
}

/** Reads the extra interface counters of every interface in one pass. A counter the device does not publish is left out of that interface's totals. */
export async function readIfExtra(c: SnmpClient, now = Date.now()): Promise<Map<number, IfExtra>> {
  const col = colsOf(c);
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
    const d = n(duplex, k);
    out.set(idx, { duplex: d === 3 ? 'full' : d === 2 ? 'half' : d === 1 ? 'unknown' : null, admin: n(admin, k) ?? null, totals, delta: null, dtSec: null, readAt: now });
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
  }
  return out;
}
