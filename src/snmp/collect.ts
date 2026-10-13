import { SnmpClient, toBigInt, toNum, toStr, type SnmpValue } from './client.js';
import { OID, CBQOS_OBJ, IF_TYPE_IGNORED } from './oids.js';

export interface DeviceInfo { sysName: string; sysDescr: string; sysObjectId: string; uptimeSec: number }
export interface IfaceInfo { index: number; name: string; descr: string; alias: string; speedMbps: number; oper: number; type: number }
export interface QosClass { name: string; objIdx: number; queueObjIdx: number | null; parentName: string | null; bandwidth: string | null }
export interface QosPolicy { policyIdx: number; ifIndex: number; direction: 'input' | 'output'; policyName: string; classes: QosClass[] }
export interface Probe { info: DeviceInfo; ifaces: IfaceInfo[]; ips: { ip: string; ifIndex: number }[]; vlans: { id: number; name: string }[]; qos: QosPolicy[]; profile: string }

export async function readInfo(c: SnmpClient): Promise<DeviceInfo> {
  const m = await c.get([OID.sysName, OID.sysDescr, OID.sysObjectID, OID.sysUpTime]);
  if (!m.size) throw new Error('The device answered but returned no system data');
  const up = toNum(m.get(OID.sysUpTime)?.value ?? null);
  return {
    sysName: toStr(m.get(OID.sysName)?.value ?? null), sysDescr: toStr(m.get(OID.sysDescr)?.value ?? null),
    sysObjectId: toStr(m.get(OID.sysObjectID)?.value ?? null), uptimeSec: up === null ? 0 : Math.floor(up / 100)
  };
}

const num = (v: SnmpValue | undefined, d = 0): number => (v === undefined ? d : toNum(v) ?? d);

export async function readInterfaces(c: SnmpClient): Promise<IfaceInfo[]> {
  const [descr, type, speed, oper, name, high, alias] = await Promise.all([
    c.column(OID.ifDescr), c.column(OID.ifType), c.column(OID.ifSpeed), c.column(OID.ifOperStatus),
    c.column(OID.ifName).catch(() => new Map<string, SnmpValue>()), c.column(OID.ifHighSpeed).catch(() => new Map<string, SnmpValue>()), c.column(OID.ifAlias).catch(() => new Map<string, SnmpValue>())
  ]);
  const out: IfaceInfo[] = [];
  for (const [k, d] of descr) {
    const idx = Number(k);
    if (!Number.isInteger(idx)) continue;
    const t = num(type.get(k));
    if (IF_TYPE_IGNORED.has(t) && !toStr(alias.get(k) ?? null)) continue;
    const hs = num(high.get(k)), sp = num(speed.get(k));
    out.push({ index: idx, name: toStr(name.get(k) ?? null) || toStr(d), descr: toStr(d), alias: toStr(alias.get(k) ?? null), speedMbps: hs > 0 ? hs : Math.round(sp / 1e6), oper: num(oper.get(k), 4), type: t });
  }
  return out.sort((a, b) => a.index - b.index);
}

export async function readIps(c: SnmpClient): Promise<{ ip: string; ifIndex: number }[]> {
  const m = await c.column(OID.ipAdEntIfIndex).catch(() => new Map<string, SnmpValue>());
  return [...m].map(([ip, v]) => ({ ip, ifIndex: num(v) })).filter(x => /^\d+\.\d+\.\d+\.\d+$/.test(x.ip));
}

export async function readVlans(c: SnmpClient): Promise<{ id: number; name: string }[]> {
  const out = new Map<number, string>();
  const q = await c.column(OID.dot1qVlanStaticName).catch(() => new Map<string, SnmpValue>());
  for (const [k, v] of q) { const id = Number(k); if (id >= 1 && id <= 4094) out.set(id, toStr(v)); }
  if (!out.size) {
    const vtp = await c.column(OID.vtpVlanName).catch(() => new Map<string, SnmpValue>());
    for (const [k, v] of vtp) { const id = Number(k.split('.').pop()); if (id >= 1 && id <= 4094) out.set(id, toStr(v)); }
  }
  return [...out].map(([id, name]) => ({ id, name })).filter(v => v.name).sort((a, b) => a.id - b.id);
}

/** Reads the Cisco class-based QoS structure: which policy is attached where, and which classes it has. Returns [] when the MIB is not supported. */
export async function readQosStructure(c: SnmpClient): Promise<QosPolicy[]> {
  const pol = await c.column(OID.cbQosIfIndex).catch(() => new Map<string, SnmpValue>());
  if (!pol.size) return [];
  const dir = await c.column(OID.cbQosPolicyDirection);
  const [cfgIdx, objType, parent, pmName, cmName, qBw, qUnits] = await Promise.all([
    c.column(OID.cbQosConfigIndex), c.column(OID.cbQosObjectsType), c.column(OID.cbQosParentObjectsIndex),
    c.column(OID.cbQosPolicyMapName), c.column(OID.cbQosCMName), c.column(OID.cbQosQueueingCfgBandwidth).catch(() => new Map<string, SnmpValue>()),
    c.column(OID.cbQosQueueingCfgBandwidthUnits).catch(() => new Map<string, SnmpValue>())
  ]);
  const out: QosPolicy[] = [];
  for (const [pk, ifv] of pol) {
    const policyIdx = Number(pk);
    const direction = num(dir.get(pk)) === 1 ? 'input' : 'output';
    const objs: { idx: number; cfg: string; type: number; parent: number }[] = [];
    for (const [k, t] of objType) {
      const [p, o] = k.split('.');
      if (Number(p) !== policyIdx) continue;
      objs.push({ idx: Number(o), cfg: String(num(cfgIdx.get(k))), type: num(t), parent: num(parent.get(k)) });
    }
    const pmap = objs.find(o => o.type === CBQOS_OBJ.policymap);
    const byIdx = new Map(objs.map(o => [o.idx, o]));
    const classes: QosClass[] = [];
    for (const o of objs.filter(x => x.type === CBQOS_OBJ.classmap)) {
      const name = toStr(cmName.get(o.cfg) ?? null) || `class-${o.idx}`;
      const q = objs.find(x => x.type === CBQOS_OBJ.queueing && x.parent === o.idx) ?? null;
      let bw: string | null = null;
      if (q) {
        const b = num(qBw.get(q.cfg), -1), u = num(qUnits.get(q.cfg), 0);
        if (b > 0) bw = u === 3 ? `${b}%` : u === 2 ? `${b}% remaining` : `${b} kbps`;
      }
      const par = byIdx.get(o.parent);
      const parentName = par && par.type === CBQOS_OBJ.classmap ? toStr(cmName.get(par.cfg) ?? null) : null;
      classes.push({ name, objIdx: o.idx, queueObjIdx: q ? q.idx : null, parentName, bandwidth: bw });
    }
    out.push({ policyIdx, ifIndex: num(ifv), direction, policyName: pmap ? toStr(pmName.get(pmap.cfg) ?? null) : '', classes });
  }
  return out;
}

export async function probe(c: SnmpClient): Promise<Probe> {
  const info = await readInfo(c);
  const [ifaces, ips, vlans, qos] = await Promise.all([
    readInterfaces(c), readIps(c).catch(() => []), readVlans(c).catch(() => []), readQosStructure(c).catch(() => [] as QosPolicy[])
  ]);
  const profile = qos.length ? 'cisco-cbqos' : 'generic';
  return { info, ifaces, ips, vlans, qos, profile };
}

export interface IfCounters { inOct: bigint; outOct: bigint; inDisc: bigint; outDisc: bigint; inErr: bigint; outErr: bigint; oper: number; speedMbps: number; hc: boolean }

export async function pollIfCounters(c: SnmpClient): Promise<Map<number, IfCounters>> {
  const empty = new Map<string, SnmpValue>();
  const [hin, hout, in32, out32, ind, outd, ine, oute, oper, high, speed] = await Promise.all([
    c.column(OID.ifHCInOctets).catch(() => empty), c.column(OID.ifHCOutOctets).catch(() => empty),
    c.column(OID.ifInOctets32).catch(() => empty), c.column(OID.ifOutOctets32).catch(() => empty),
    c.column(OID.ifInDiscards).catch(() => empty), c.column(OID.ifOutDiscards).catch(() => empty),
    c.column(OID.ifInErrors).catch(() => empty), c.column(OID.ifOutErrors).catch(() => empty),
    c.column(OID.ifOperStatus).catch(() => empty), c.column(OID.ifHighSpeed).catch(() => empty), c.column(OID.ifSpeed).catch(() => empty)
  ]);
  const out = new Map<number, IfCounters>();
  const big = (m: Map<string, SnmpValue>, k: string) => (m.has(k) ? toBigInt(m.get(k)!) ?? 0n : 0n);
  const keys = new Set([...oper.keys()]);
  for (const k of keys) {
    const idx = Number(k);
    if (!Number.isInteger(idx)) continue;
    const hc = hin.has(k);
    const hs = num(high.get(k));
    out.set(idx, {
      inOct: hc ? big(hin, k) : big(in32, k), outOct: hc ? big(hout, k) : big(out32, k),
      inDisc: big(ind, k), outDisc: big(outd, k), inErr: big(ine, k), outErr: big(oute, k), oper: num(oper.get(k), 4),
      speedMbps: hs > 0 ? hs : Math.round(num(speed.get(k)) / 1e6), hc
    });
  }
  return out;
}

export interface ClassCounters { pre: bigint; preB: bigint; postB: bigint; drop: bigint; dropB: bigint }
export interface QosCounters { classes: Map<string, ClassCounters>; queueDepth: Map<string, number> }

/** Reads class counters keyed "policyIdx.objIdx". Queue depth is keyed by the class's queueing object (see QosClass.queueObjIdx). */
export async function pollQosCounters(c: SnmpClient): Promise<QosCounters> {
  const empty = new Map<string, SnmpValue>();
  const [pre, preB, postB, drop, dropB, qd] = await Promise.all([
    c.column(OID.cbQosCMPrePolicyPkt64), c.column(OID.cbQosCMPrePolicyByte64), c.column(OID.cbQosCMPostPolicyByte64),
    c.column(OID.cbQosCMDropPkt64), c.column(OID.cbQosCMDropByte64), c.column(OID.cbQosQueueingCurrentQDepth).catch(() => empty)
  ]);
  const classes = new Map<string, ClassCounters>();
  const b = (m: Map<string, SnmpValue>, k: string) => (m.has(k) ? toBigInt(m.get(k)!) ?? 0n : 0n);
  for (const k of pre.keys()) classes.set(k, { pre: b(pre, k), preB: b(preB, k), postB: b(postB, k), drop: b(drop, k), dropB: b(dropB, k) });
  const queueDepth = new Map<string, number>();
  for (const [k, v] of qd) queueDepth.set(k, num(v));
  return { classes, queueDepth };
}

/** Counter difference with wraparound for 32-bit counters. Returns null when the counter went backwards on a 64-bit counter (device reset). */
export function delta(cur: bigint, prev: bigint, wide: boolean): bigint | null {
  if (cur >= prev) return cur - prev;
  if (wide) return null;
  return cur + 4294967296n - prev;
}

/** Guess which DSCP values a class carries from its name. Admins can correct the mapping. */
export function guessDscps(name: string): number[] {
  const n = name.toLowerCase();
  if (/voice|\bef\b|rtp|priority/.test(n)) return [46];
  if (/video|af4|interactive/.test(n)) return [34, 36, 38];
  if (/signal|cs3|call/.test(n)) return [24];
  if (/critical|af3|business|transactional/.test(n)) return [26, 28, 30];
  if (/mission|af2/.test(n)) return [18, 20, 22];
  if (/scaven|cs1|bulk-low/.test(n)) return [8];
  if (/bulk|af1/.test(n)) return [10, 12, 14];
  if (/network|routing|cs6|control/.test(n)) return [48];
  if (/default/.test(n)) return [0];
  return [];
}
