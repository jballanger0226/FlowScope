import { SnmpClient, toBigInt, toNum, toStr, type SnmpValue } from './client.js';
import { OID, CBQOS_OBJ, IF_TYPE_IGNORED } from './oids.js';
import { readPortVlans, type PortVlan } from './ports.js';

export interface DeviceInfo { sysName: string; sysDescr: string; sysObjectId: string; uptimeSec: number }
export interface IfaceInfo { index: number; name: string; descr: string; alias: string; speedMbps: number; oper: number; type: number }
export interface QosClass { name: string; objIdx: number; queueObjIdx: number | null; parentName: string | null; bandwidth: string | null }
/** cbQosIfType: 1 main interface, 2 sub-interface, 5 control plane, 6 one VLAN of a trunk (cbQosVlanIndex), 7 EVC, 8 tunnel, 9 wireless. */
export interface QosPolicy { policyIdx: number; ifIndex: number; direction: 'input' | 'output'; policyName: string; classes: QosClass[]; ifType: number; vlan: number; parentPolicyIdx: number }
export interface Probe {
  info: DeviceInfo; ifaces: IfaceInfo[]; ips: { ip: string; ifIndex: number }[]; vlans: { id: number; name: string }[]; qos: QosPolicy[]; profile: string;
  /** Why no QoS data could be read, or a short summary of what was found. */
  qosNote: string; ports: Map<number, PortVlan>;
}

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

/** Bandwidth units of cbQosQueueingCfgBandwidthUnits (QueueingBandwidthUnits in CISCO-CLASS-BASED-QOS-MIB). */
export function bandwidthText(b: number, unit: number): string | null {
  if (!(b > 0)) return null;
  switch (unit) {
    case 1: return `${b} kbps`;
    case 2: return `${b}%`;
    case 3: return `${b}% remaining`;
    case 4: return `${b} (ratio of remaining)`;
    case 5: return `${b / 10}%`;
    case 6: return `${b / 10000}%`;
    default: return `${b}`;
  }
}

/** Reads the Cisco class-based QoS structure: which policy is attached where (both directions), and which classes it has. Returns [] when the MIB is not supported. */
export async function readQosStructure(c: SnmpClient): Promise<QosPolicy[]> {
  const empty = () => new Map<string, SnmpValue>();
  const pol = await c.column(OID.cbQosPolicyDirection);
  if (!pol.size) return [];
  const [ifIdx, ifType, vlanIdx, parentIdx] = await Promise.all([
    c.column(OID.cbQosIfIndex).catch(empty), c.column(OID.cbQosIfType).catch(empty), c.column(OID.cbQosVlanIndex).catch(empty), c.column(OID.cbQosParentPolicyIndex).catch(empty)
  ]);
  const [cfgIdx, objType, parent, pmName, cmName, qBw, qUnits] = await Promise.all([
    c.column(OID.cbQosConfigIndex), c.column(OID.cbQosObjectsType), c.column(OID.cbQosParentObjectsIndex),
    c.column(OID.cbQosPolicyMapName), c.column(OID.cbQosCMName), c.column(OID.cbQosQueueingCfgBandwidth).catch(empty),
    c.column(OID.cbQosQueueingCfgBandwidthUnits).catch(empty)
  ]);
  // group the objects by policy once, instead of scanning the whole table for every policy
  const byPolicy = new Map<number, { idx: number; cfg: string; type: number; parent: number }[]>();
  for (const [k, t] of objType) {
    const [p, o] = k.split('.');
    const a = byPolicy.get(Number(p)) ?? []; byPolicy.set(Number(p), a);
    a.push({ idx: Number(o), cfg: String(num(cfgIdx.get(k))), type: num(t), parent: num(parent.get(k)) });
  }
  const out: QosPolicy[] = [];
  for (const [pk, dv] of pol) {
    const policyIdx = Number(pk);
    const direction = num(dv) === 1 ? 'input' : 'output';
    const objs = byPolicy.get(policyIdx) ?? [];
    const pmap = objs.find(o => o.type === CBQOS_OBJ.policymap);
    const byIdx = new Map(objs.map(o => [o.idx, o]));
    const nameOf = (o: { cfg: string; idx: number }) => toStr(cmName.get(o.cfg) ?? null) || `class-${o.idx}`;
    // a hierarchical policy (for example a port shaper with a queueing child policy) can have the same class name at two levels
    const path = (o: { parent: number; cfg: string; idx: number }): string[] => {
      const names = [nameOf(o)];
      for (let p = byIdx.get(o.parent), n = 0; p && n < 8; p = byIdx.get(p.parent), n++) if (p.type === CBQOS_OBJ.classmap) names.unshift(nameOf(p));
      return names;
    };
    const maps = objs.filter(x => x.type === CBQOS_OBJ.classmap);
    const count = new Map<string, number>();
    for (const o of maps) count.set(nameOf(o), (count.get(nameOf(o)) ?? 0) + 1);
    const classes: QosClass[] = [];
    for (const o of maps) {
      const name = (count.get(nameOf(o)) ?? 0) > 1 ? path(o).join('/') : nameOf(o);
      const q = objs.find(x => x.type === CBQOS_OBJ.queueing && x.parent === o.idx) ?? null;
      const bw = q ? bandwidthText(num(qBw.get(q.cfg), -1), num(qUnits.get(q.cfg), 0)) : null;
      const par = byIdx.get(o.parent);
      const parentName = par && par.type === CBQOS_OBJ.classmap ? nameOf(par) : null;
      classes.push({ name, objIdx: o.idx, queueObjIdx: q ? q.idx : null, parentName, bandwidth: bw });
    }
    out.push({
      policyIdx, ifIndex: num(ifIdx.get(pk)), direction, policyName: pmap ? toStr(pmName.get(pmap.cfg) ?? null) : '', classes,
      ifType: num(ifType.get(pk), 1), vlan: num(vlanIdx.get(pk)), parentPolicyIdx: num(parentIdx.get(pk))
    });
  }
  return out;
}

/** Name shown for a policy on an interface; a policy bound to one VLAN of a trunk says which. */
export function policyText(p: Pick<QosPolicy, 'policyName' | 'vlan'>): string { return (p.policyName || 'unnamed policy') + (p.vlan > 0 ? ` (VLAN ${p.vlan})` : ''); }
/**
 * Class name as stored with the statistics. Output classes keep their plain name; classes of an input policy are prefixed "in:" so
 * the same class name in both directions stays two series. The screens strip the prefix and show an "in" tag.
 */
export function classLabel(p: Pick<QosPolicy, 'direction' | 'vlan'>, name: string): string { return (p.direction === 'input' ? 'in:' : '') + name + (p.vlan > 0 ? ` (VLAN ${p.vlan})` : ''); }
/** Policies that belong to an interface, as opposed to the control plane or an entry without a usable ifIndex. */
export const perInterface = (p: Pick<QosPolicy, 'ifType' | 'ifIndex'>): boolean => p.ifType !== 5 && p.ifIndex > 0;

/** A plain-language summary of what the QoS tables returned, kept so an admin can see why a policy is missing. */
export function qosSummary(policies: QosPolicy[], ifaces: Pick<IfaceInfo, 'index'>[]): string {
  if (!policies.length) return 'The device returned no service policies (cbQosServicePolicyTable is empty). Either no policy is attached, or it does not publish CISCO-CLASS-BASED-QOS-MIB.';
  const known = new Set(ifaces.map(i => i.index));
  const inp = policies.filter(p => p.direction === 'input').length, outp = policies.length - inp;
  const parts = [`${policies.length} service polic${policies.length === 1 ? 'y' : 'ies'} found (${outp} output, ${inp} input)`];
  const cp = policies.filter(p => p.ifType === 5).length; if (cp) parts.push(`${cp} on the control plane (not shown per interface)`);
  const vp = policies.filter(p => p.ifType === 6 || p.vlan > 0).length; if (vp) parts.push(`${vp} attached to one VLAN of a trunk (shown on the port)`);
  const orphan = policies.filter(p => p.ifType !== 5 && p.ifIndex > 0 && !known.has(p.ifIndex));
  if (orphan.length) parts.push(`${orphan.length} attached to interfaces missing from the interface list (ifIndex ${[...new Set(orphan.map(p => p.ifIndex))].slice(0, 6).join(', ')})`);
  const noCls = policies.filter(p => !p.classes.length).length; if (noCls) parts.push(`${noCls} with no class statistics`);
  return parts.join('; ') + '.';
}

export async function probe(c: SnmpClient): Promise<Probe> {
  const info = await readInfo(c);
  const [ifaces, ips, vlans] = await Promise.all([readInterfaces(c), readIps(c).catch(() => []), readVlans(c).catch(() => [])]);
  // A failure here is kept as a note instead of being hidden, so "no policy" can be told apart from "the device did not answer in time"
  let qos: QosPolicy[] = []; let qosNote: string;
  try { qos = await readQosStructure(c); qosNote = qosSummary(qos, ifaces); } catch (e) { qosNote = `The QoS tables could not be read: ${(e as Error).message}`; }
  const ports = await readPortVlans(c, ifaces, ips).catch(() => new Map<number, PortVlan>());
  const profile = qos.length ? 'cisco-cbqos' : 'generic';
  return { info, ifaces, ips, vlans, qos, profile, qosNote, ports };
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
export interface QosCounters { classes: Map<string, ClassCounters>; queueDepth: Map<string, number>; /** false when only the 32-bit counters exist */ wide: boolean }

/** Reads class counters keyed "policyIdx.objIdx". Queue depth is keyed by the class's queueing object (see QosClass.queueObjIdx). Falls back to the 32-bit counters on devices without the 64-bit ones. */
export async function pollQosCounters(c: SnmpClient): Promise<QosCounters> {
  const empty = new Map<string, SnmpValue>();
  const rd = (o: string) => c.column(o).catch(() => empty);
  let [pre, preB, postB, drop, dropB] = await Promise.all([rd(OID.cbQosCMPrePolicyPkt64), rd(OID.cbQosCMPrePolicyByte64), rd(OID.cbQosCMPostPolicyByte64), rd(OID.cbQosCMDropPkt64), rd(OID.cbQosCMDropByte64)]);
  const qd = await rd(OID.cbQosQueueingCurrentQDepth);
  let wide = true;
  if (!pre.size) {
    wide = false;
    [pre, preB, postB, drop, dropB] = await Promise.all([rd(OID.cbQosCMPrePolicyPkt32), rd(OID.cbQosCMPrePolicyByte32), rd(OID.cbQosCMPostPolicyByte32), rd(OID.cbQosCMDropPkt32), rd(OID.cbQosCMDropByte32)]);
  }
  const classes = new Map<string, ClassCounters>();
  const b = (m: Map<string, SnmpValue>, k: string) => (m.has(k) ? toBigInt(m.get(k)!) ?? 0n : 0n);
  for (const k of pre.keys()) classes.set(k, { pre: b(pre, k), preB: b(preB, k), postB: b(postB, k), drop: b(drop, k), dropB: b(dropB, k) });
  const queueDepth = new Map<string, number>();
  for (const [k, v] of qd) queueDepth.set(k, num(v));
  return { classes, queueDepth, wide };
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
