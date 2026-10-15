/**
 * Queue and class statistics from MIBs other than Cisco's class-based QoS MIB, in the same shape so the rest of FlowScope (graphs, drop events,
 * class table) treats them alike.
 *
 *  - Juniper CoS (JUNIPER-COS-MIB jnxCosIfqStatsTable, .1.3.6.1.4.1.2636.3.15.1): one row per interface and forwarding class. The table is marked
 *    deprecated in the MIB, and Junos does not publish tail-drop bytes, so dropped bytes only count RED drops.
 *  - DIFFSERV-MIB (RFC 3289): walks each interface's data path through classifiers and meters to the counter and drop elements. It is only
 *    as good as the device's implementation of that MIB, which few devices have, so it is the last resort.
 *
 * The OIDs and indexes were checked against the published MIB definitions; neither reader has run against real hardware here.
 */
import { toBigInt, toNum, toStr, type SnmpClient, type SnmpValue } from './client.js';
import type { ClassCounters, QosCounters, QosPolicy } from './collect.js';

const EMPTY = new Map<string, SnmpValue>();
const col = (c: SnmpClient, o: string) => c.column(o).catch(() => EMPTY);
const big = (m: Map<string, SnmpValue>, k: string): bigint => { const v = m.get(k); return v === undefined || v === null ? 0n : toBigInt(v) ?? 0n; };

export interface QosSource {
  id: string;
  /** Reads which policies (or queue sets) exist on which interfaces, and their classes. [] when the device does not publish this MIB. */
  read(c: SnmpClient): Promise<QosPolicy[]>;
  /** Reads the current counters of the classes in `policies`, keyed "policyIdx.objIdx". */
  poll(c: SnmpClient, policies: QosPolicy[]): Promise<QosCounters>;
  /** One line for the device's QoS note when this source found something. */
  note: string;
}

/* ------------------------------------------------------------------ Juniper */

const JQ = {
  qedPkts: '1.3.6.1.4.1.2636.3.15.1.1.3', qedBytes: '1.3.6.1.4.1.2636.3.15.1.1.5', txedBytes: '1.3.6.1.4.1.2636.3.15.1.1.9',
  tailDropPkts: '1.3.6.1.4.1.2636.3.15.1.1.11', redDropPkts: '1.3.6.1.4.1.2636.3.15.1.1.13', redDropBytes: '1.3.6.1.4.1.2636.3.15.1.1.23'
};

/** Splits a jnxCosIfqStatsTable row index into the ifIndex and the forwarding class name (an octet string index, with or without its length). */
export function juniperIndex(suffix: string): { ifIndex: number; fc: string } | null {
  const parts = suffix.split('.').map(Number);
  if (parts.length < 2 || parts.some(n => !Number.isInteger(n) || n < 0)) return null;
  const [ifIndex, ...rest] = parts;
  const chars = rest.length > 1 && rest[0] === rest.length - 1 ? rest.slice(1) : rest;
  if (!chars.length || chars.some(n => n > 255)) return null;
  return { ifIndex, fc: String.fromCharCode(...chars) };
}

export const juniperSource: QosSource = {
  id: 'juniper-cos',
  note: 'Junos CoS queues (JUNIPER-COS-MIB). Dropped bytes count RED drops only, because Junos does not publish bytes lost to tail drop.',
  async read(c) {
    const qed = await col(c, JQ.qedPkts);
    if (!qed.size) return [];
    const byIf = new Map<number, { fc: string; ref: string }[]>();
    for (const [k, v] of qed) {
      const ix = juniperIndex(k); if (!ix) continue;
      // forwarding classes that never carried a packet are left out; one that starts to is picked up at the next hourly re-read
      if (big(new Map([[k, v]]), k) === 0n) continue;
      (byIf.get(ix.ifIndex) ?? byIf.set(ix.ifIndex, []).get(ix.ifIndex)!).push({ fc: ix.fc, ref: k });
    }
    const out: QosPolicy[] = [];
    for (const [ifIndex, fcs] of byIf) {
      out.push({
        policyIdx: ifIndex, ifIndex, direction: 'output', policyName: 'CoS queues', ifType: 1, vlan: 0, parentPolicyIdx: 0,
        classes: fcs.sort((a, b) => a.fc.localeCompare(b.fc)).map((f, i) => ({ name: f.fc, objIdx: i + 1, queueObjIdx: null, parentName: null, bandwidth: null, matched: [], sets: null, ref: f.ref }))
      });
    }
    return out;
  },
  async poll(c, policies) {
    const [qed, qedB, txB, tail, red, redB] = await Promise.all([col(c, JQ.qedPkts), col(c, JQ.qedBytes), col(c, JQ.txedBytes), col(c, JQ.tailDropPkts), col(c, JQ.redDropPkts), col(c, JQ.redDropBytes)]);
    const classes = new Map<string, ClassCounters>();
    for (const p of policies) for (const k of p.classes) {
      const r = (k as { ref?: string }).ref; if (!r || !qed.has(r)) continue;
      classes.set(`${p.policyIdx}.${k.objIdx}`, { pre: big(qed, r), preB: big(qedB, r), postB: big(txB, r), drop: big(tail, r) + big(red, r), dropB: big(redB, r) });
    }
    return { classes, queueDepth: new Map(), wide: true };
  }
};

/* ------------------------------------------------------------------ DIFFSERV-MIB (RFC 3289) */

const DS = {
  dataPathStart: '1.3.6.1.2.1.97.1.1.1.1.2',
  clfrElementNext: '1.3.6.1.2.1.97.1.2.4.1.3',
  meterSucceed: '1.3.6.1.2.1.97.1.3.2.1.2', meterFail: '1.3.6.1.2.1.97.1.3.2.1.3',
  countOctets: '1.3.6.1.2.1.97.1.5.5.1.2', countPkts: '1.3.6.1.2.1.97.1.5.5.1.3',
  dropOctets: '1.3.6.1.2.1.97.1.6.2.1.7', dropPkts: '1.3.6.1.2.1.97.1.6.2.1.8',
  qNext: '1.3.6.1.2.1.97.1.7.2.1.2'
};
/** Entry prefixes of the tables a row pointer can name, so a pointer can be turned into "which table, which row". */
const DS_ENTRY: [string, string][] = [
  ['clfr', '1.3.6.1.2.1.97.1.2.2.1'], ['element', '1.3.6.1.2.1.97.1.2.4.1'], ['meter', '1.3.6.1.2.1.97.1.3.2.1'], ['count', '1.3.6.1.2.1.97.1.5.5.1'],
  ['drop', '1.3.6.1.2.1.97.1.6.2.1'], ['queue', '1.3.6.1.2.1.97.1.7.2.1'], ['scheduler', '1.3.6.1.2.1.97.1.8.2.1']
];

/** What a row pointer points at: the table and the row index, or null for "nothing" (0.0) and for tables we do not follow. */
export function diffservPointer(v: SnmpValue | undefined): { table: string; row: string } | null {
  const s = toStr(v ?? null).replace(/^\./, '');
  if (!s || s === '0.0') return null;
  for (const [table, prefix] of DS_ENTRY) {
    if (s.startsWith(prefix + '.')) {
      const rest = s.slice(prefix.length + 1).split('.');
      rest.shift();                          // the column the pointer happens to name
      return rest.length ? { table, row: rest.join('.') } : null;
    }
  }
  return null;
}

interface DsPath { counts: string[]; drops: string[]; /** Whether a counter element comes before the first drop element on the path */ countFirst: boolean | null }

/** Follows the chain of functional elements after a classifier element, collecting the counter and drop rows it passes. */
function follow(p: { table: string; row: string } | null, maps: { meterOk: Map<string, SnmpValue>; meterFail: Map<string, SnmpValue>; qNext: Map<string, SnmpValue> }, out: DsPath, seen = new Set<string>(), depth = 0): void {
  if (!p || depth > 12) return;
  const id = `${p.table}:${p.row}`;
  if (seen.has(id)) return;
  seen.add(id);
  if (p.table === 'count') { out.counts.push(p.row); out.countFirst ??= true; }
  else if (p.table === 'drop') { out.drops.push(p.row); out.countFirst ??= false; }
  else if (p.table === 'meter') { follow(diffservPointer(maps.meterOk.get(p.row)), maps, out, seen, depth + 1); follow(diffservPointer(maps.meterFail.get(p.row)), maps, out, seen, depth + 1); }
  else if (p.table === 'queue') follow(diffservPointer(maps.qNext.get(p.row)), maps, out, seen, depth + 1);
}

export const diffservSource: QosSource = {
  id: 'diffserv',
  note: 'DIFFSERV-MIB (RFC 3289). Classes are named by their classifier and element numbers, since the MIB carries no names.',
  async read(c) {
    const start = await col(c, DS.dataPathStart);
    if (!start.size) return [];
    const [elemNext, meterOk, meterFail, qNext] = await Promise.all([col(c, DS.clfrElementNext), col(c, DS.meterSucceed), col(c, DS.meterFail), col(c, DS.qNext)]);
    const maps = { meterOk, meterFail, qNext };
    const out: QosPolicy[] = [];
    let pid = 0;
    for (const [k, sp] of start) {
      const [ifx, dir] = k.split('.').map(Number);
      const first = diffservPointer(sp);
      if (!first || !Number.isInteger(ifx) || ifx <= 0) continue;
      const classes: QosPolicy['classes'] = [];
      if (first.table === 'clfr') {
        for (const [ek, nx] of [...elemNext].filter(([e]) => e.startsWith(first.row + '.')).sort(([a], [b]) => a.localeCompare(b, undefined, { numeric: true }))) {
          const path: DsPath = { counts: [], drops: [], countFirst: null };
          follow(diffservPointer(nx), maps, path);
          if (!path.counts.length && !path.drops.length) continue;
          classes.push({ name: `class ${ek}`, objIdx: classes.length + 1, queueObjIdx: null, parentName: null, bandwidth: null, matched: [], sets: null, ref: `c:${path.counts.join(',')}|d:${path.drops.join(',')}|f:${path.countFirst === false ? 0 : 1}` } as QosPolicy['classes'][number]);
        }
      }
      if (classes.length) out.push({ policyIdx: ++pid, ifIndex: ifx, direction: dir === 1 ? 'input' : 'output', policyName: 'DiffServ data path', classes, ifType: 1, vlan: 0, parentPolicyIdx: 0 });
    }
    return out;
  },
  async poll(c, policies) {
    const [cOct, cPkt, dOct, dPkt] = await Promise.all([col(c, DS.countOctets), col(c, DS.countPkts), col(c, DS.dropOctets), col(c, DS.dropPkts)]);
    const classes = new Map<string, ClassCounters>();
    const sum = (m: Map<string, SnmpValue>, ids: string[]) => ids.reduce((a, i) => a + big(m, i), 0n);
    for (const p of policies) for (const k of p.classes) {
      const r = (k as { ref?: string }).ref; if (!r) continue;
      const m = /^c:([^|]*)\|d:([^|]*)\|f:([01])$/.exec(r); if (!m) continue;
      const counts = m[1] ? m[1].split(',') : [], drops = m[2] ? m[2].split(',') : [];
      const dropP = sum(dPkt, drops), dropB = sum(dOct, drops);
      const seenP = sum(cPkt, counts), seenB = sum(cOct, counts);
      // a counter ahead of the dropper counts everything that entered the class; one behind it counts only what got through
      const dropperFirst = m[3] === '0';
      classes.set(`${p.policyIdx}.${k.objIdx}`, dropperFirst
        ? { pre: seenP + dropP, preB: seenB + dropB, postB: seenB, drop: dropP, dropB }
        : { pre: seenP, preB: seenB, postB: seenB > dropB ? seenB - dropB : 0n, drop: dropP, dropB });
    }
    return { classes, queueDepth: new Map(), wide: true };
  }
};

void toNum;
