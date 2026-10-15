import test from 'node:test';
import assert from 'node:assert/strict';
import { matchedDscps, readQosStructure, setActions } from '../src/snmp/collect.js';
import { OID } from '../src/snmp/oids.js';
import { analyzeStream, explainRemark, type PolicyView } from '../src/analysis/hops.js';
import type { FlowRecord } from '../src/collector/types.js';
import type { SnmpValue, SnmpClient } from '../src/snmp/client.js';

test('class match statements are read as the DSCP values the device lists', () => {
  assert.deepEqual(matchedDscps('Match  dscp af41 (34) af42 (36) af43 (38)'), [34, 36, 38]);
  assert.deepEqual(matchedDscps('Match  dscp cs2 (16) cs3 (24) cs6 (48) cs7 (56)'), [16, 24, 48, 56]);
  assert.deepEqual(matchedDscps('Match cos  5 '), [], 'a CoS match is not a DSCP match');
  assert.deepEqual(matchedDscps('Match any '), []);
});

test('set actions: a value is read, a zero is a table map, bits count from the most significant', () => {
  const f = (cfg: string, hex: number[]) => new Map<string, SnmpValue>([[cfg, Buffer.from(hex)]]);
  const v = (cfg: string, n: number) => new Map<string, SnmpValue>([[cfg, n]]);
  const none = new Map<string, SnmpValue>();
  assert.deepEqual(setActions(['1'], f('1', [0x80, 0, 0, 0]), v('1', 46), none, none), { dscp: 46, cos: null, precedence: null, table: false });
  assert.deepEqual(setActions(['1'], f('1', [0x80, 0, 0, 0]), v('1', 0), none, none), { dscp: null, cos: null, precedence: null, table: true }, 'set dscp with value 0: a table map, as AutoQoS does');
  assert.deepEqual(setActions(['1'], f('1', [0x04, 0, 0, 0]), none, none, v('1', 5)), { dscp: null, cos: 5, precedence: null, table: false });
  assert.equal(setActions([], none, none, none, none), null);
});

/** The two policies of Gi1/0/44 of a Catalyst 3850 with AutoQoS, as the device publishes them (CISCO-CLASS-BASED-QOS-MIB). */
function autoqos(): SnmpClient {
  const t: Record<string, Record<string, SnmpValue>> = {};
  const put = (oid: string, key: string, v: SnmpValue) => { (t[oid] ??= {})[key] = v; };
  put(OID.cbQosPolicyDirection, '816', 1); put(OID.cbQosIfIndex, '816', 10144); put(OID.cbQosIfType, '816', 1);
  put(OID.cbQosPolicyDirection, '818', 2); put(OID.cbQosIfIndex, '818', 10144); put(OID.cbQosIfType, '818', 1);
  const obj = (p: string, o: number, cfg: number, type: number, parent: number) => { put(OID.cbQosConfigIndex, `${p}.${o}`, cfg); put(OID.cbQosObjectsType, `${p}.${o}`, type); put(OID.cbQosParentObjectsIndex, `${p}.${o}`, parent); };
  // input: Trust-Dscp, one class (class-default) that matches anything and sets DSCP through a table map (value 0, feature bit ipDscp)
  obj('816', 1, 19172164, 1, 0); obj('816', 65536, 1593, 2, 1); obj('816', 65537, 1594, 3, 65536); obj('816', 65538, 2001743028, 8, 65536);
  put(OID.cbQosPolicyMapName, '19172164', 'AutoQos-4.0-Trust-Dscp-Input-Policy'); put(OID.cbQosCMName, '1593', 'class-default');
  put(OID.cbQosMatchStmtName, '1594', 'Match any ');
  put(OID.cbQosSetCfgFeature, '2001743028', Buffer.from([0x80, 0, 0, 0])); put(OID.cbQosSetCfgIpDSCPValue, '2001743028', 0);
  // output: a priority queue class matching cs4, cs5 and ef, and class-default
  obj('818', 1, 36168835, 1, 0); obj('818', 65536, 387987483, 2, 1); obj('818', 65537, 617310497, 3, 65536); obj('818', 524288, 1593, 2, 1); obj('818', 524289, 1594, 3, 524288);
  put(OID.cbQosPolicyMapName, '36168835', 'AutoQos-4.0-Output-Policy'); put(OID.cbQosCMName, '387987483', 'AutoQos-4.0-Output-Priority-Queue');
  put(OID.cbQosMatchStmtName, '617310497', 'Match  dscp cs4 (32) cs5 (40) ef (46)');
  return { async column(oid: string) { return new Map(Object.entries(t[oid] ?? {})); } } as unknown as SnmpClient;
}

test('a service policy is read with what its classes match and how they mark', async () => {
  const pols = await readQosStructure(autoqos());
  const inp = pols.find(p => p.direction === 'input')!, out = pols.find(p => p.direction === 'output')!;
  assert.equal(inp.policyName, 'AutoQos-4.0-Trust-Dscp-Input-Policy');
  assert.deepEqual(inp.classes.map(c => [c.name, c.matched, c.sets]), [['class-default', [], { dscp: null, cos: null, precedence: null, table: true }]]);
  assert.deepEqual(out.classes.map(c => [c.name, c.matched, c.sets]), [['AutoQos-4.0-Output-Priority-Queue', [32, 40, 46], null], ['class-default', [], null]]);
});

const view = (over: Partial<PolicyView>): PolicyView => ({ device: 'sw', ifName: 'Gi1/0/44', dir: 'in', policy: null, deviceHasQos: true, classes: [], ...over });

test('explainRemark: configured value, table map, a different value, no policy, and no data', () => {
  const set = (dscp: number | null, table = false) => ({ dscp, cos: null, precedence: null, table });
  const ok = explainRemark(0, 48, [view({ policy: 'P', classes: [{ cls: 'class-default', matches: [], sets: set(48) }] })]);
  assert.equal(ok.kind, 'policy'); assert.match(ok.text, /sets DSCP CS6/);
  const tm = explainRemark(0, 48, [view({ policy: 'AutoQos-Trust', classes: [{ cls: 'class-default', matches: [], sets: set(null, true) }] })]);
  assert.equal(tm.kind, 'policy'); assert.match(tm.text, /table map/);
  const wrong = explainRemark(0, 48, [view({ policy: 'P', classes: [{ cls: 'voice', matches: [46], sets: set(46) }] })]);
  assert.equal(wrong.kind, 'unexplained'); assert.match(wrong.text, /sets DSCP EF.*seen as CS6/);
  const none = explainRemark(46, 0, [view({ policy: null }), view({ dir: 'out', policy: 'Out', classes: [{ cls: 'class-default', matches: [], sets: null }] })]);
  assert.equal(none.kind, 'unexplained'); assert.match(none.text, /no QoS policy is attached to Gi1\/0\/44/); assert.match(none.text, /policy Out \(Gi1\/0\/44\) has no class that marks/); assert.match(none.text, /reset to CS0/);
  assert.equal(explainRemark(0, 48, [null, view({ deviceHasQos: false })]).kind, 'unknown');
});

const rec = (over: Partial<FlowRecord>): FlowRecord => ({
  ts0: 1_000_000, ts1: 1_030_000, exporter: 'sw', inIf: 1, outIf: 2, srcIp: '10.0.0.1', dstIp: '10.0.0.2', proto: 17, sport: 4500, dport: 4500, flags: 0, tos: 0, postTos: null,
  ttlMin: null, ttlMax: null, bytes: 1000, pkts: 10, srcMac: null, dstMac: null, vlan: null, natSrcIp: null, natDstIp: null, natSport: null, natDport: null, nextHop: null, sampling: 1, ...over
});
const ctx = (policyAt?: (ip: string, i: number, d: 'in' | 'out') => PolicyView | null) => ({ deviceName: (ip: string) => ip, deviceRole: () => 'switch', ifName: (_: string, i: number) => `if${i}`, policyAt });

test('a re-marked stream: expected when a policy marks it, flagged when nothing configured does', () => {
  const recs = [rec({ tos: 0, postTos: 48 << 2 })];
  const policy = analyzeStream('k', recs, ctx((_ip, _i, dir) => view({ dir, policy: dir === 'out' ? 'Out' : null, classes: dir === 'out' ? [{ cls: 'class-default', matches: [], sets: { dscp: 48, cos: null, precedence: null, table: false } }] : [] })))!;
  assert.equal(policy.forward[0].qosChanged, true, 'the flag is still there');
  assert.equal(policy.qosChanged, true);
  assert.equal(policy.qosVerdict?.kind, 'policy');
  const ob = policy.forward[0].obs.find(o => o.kind === 'remark')!;
  assert.equal(ob.severity, 'info'); assert.match(ob.text, /Expected: .*sets DSCP CS6/);
  const gap = analyzeStream('k', recs, ctx((_ip, _i, dir) => view({ dir, policy: null })))!;
  assert.equal(gap.qosVerdict?.kind, 'unexplained');
  assert.equal(gap.forward[0].obs.find(o => o.kind === 'remark')!.severity, 'warn');
  const blind = analyzeStream('k', recs, ctx())!;
  assert.equal(blind.qosVerdict?.kind, 'unknown');
  assert.equal(blind.forward[0].obs.find(o => o.kind === 'remark')!.severity, 'warn', 'without policy data the flag stays as loud as before');
});

test('a change between two hops is checked against the earlier hop\'s policies only when it did not report its output marking', () => {
  const recs = [rec({ exporter: 'a', tos: 46 << 2 }), rec({ exporter: 'b', tos: 0, ts0: 1_000_020 })];
  const hasSet = (dscp: number) => (_ip: string, _i: number, dir: 'in' | 'out') => view({ dir, policy: 'P', classes: [{ cls: 'c', matches: [46], sets: { dscp, cos: null, precedence: null, table: false } }] });
  assert.equal(analyzeStream('k', recs, ctx(hasSet(0)))!.qosVerdict?.kind, 'policy');
  const reported = [rec({ exporter: 'a', tos: 46 << 2, postTos: 46 << 2 }), rec({ exporter: 'b', tos: 0, ts0: 1_000_020 })];
  const d = analyzeStream('k', reported, ctx(hasSet(0)))!;
  assert.equal(d.qosVerdict?.kind, 'unexplained', 'a changed after a device that reported its output marking happened somewhere else');
  assert.match(d.forward[1].obs.find(o => o.kind === 'remark')!.text, /between them/);
});
