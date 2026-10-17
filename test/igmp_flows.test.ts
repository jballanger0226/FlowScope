import test from 'node:test';
import assert from 'node:assert/strict';
import { igmpFromFlows } from '../src/snmp/igmp_flows.js';
import type { App } from '../src/app.js';

type Spec = { range: { from: number; to: number }; dims: string[]; conds: { kind: string; protos?: number[]; m?: { lo: number; hi: number }[]; ips?: string[] }[] };
function fakeApp(rows: (s: Spec) => { dims: Record<string, string | number>; flows: number }[], seen: Spec[] = []): App {
  return { store: { report: async (s: Spec) => { seen.push(s); return { rows: rows(s), totalRows: 0, totals: { bytes: 0, pkts: 0, flows: 0 }, other: {} }; } } } as unknown as App;
}

test('version 2 reports name the host and group, version 3 reports only the host', async () => {
  const seen: Spec[] = [];
  const now = 1_000_000_000_000;
  const app = fakeApp(s => {
    if (s.dims.length === 1) return [{ dims: { srcIp: '10.1.4.150' }, flows: 4 }, { dims: { srcIp: '10.1.4.151' }, flows: 2 }];
    const wide = s.range.to - s.range.from > 10 * 60_000;
    return [{ dims: { inIf: '10.255.1.1#9', srcIp: '10.1.4.20', dstIp: '239.1.1.1' }, flows: 3 }, ...(wide ? [{ dims: { inIf: '10.255.1.1#9', srcIp: '10.1.4.21', dstIp: '239.1.1.1' }, flows: 1 }] : [])];
  }, seen);
  const r = (await igmpFromFlows(app, ['10.255.1.1'], now))!;
  assert.deepEqual([...r.members.get('239.1.1.1|9')!], [['10.1.4.20', { recent: true }], ['10.1.4.21', { recent: false }]], 'recent means seen in the last 5 minutes');
  assert.equal(r.reports, 4); assert.equal(r.hosts, 2); assert.equal(r.v3Hosts, 2);
  // protocol 2 only, from the device's own exporter, groups start after the 224.0.0.0/24 control range
  for (const s of seen) { assert.deepEqual(s.conds.find(c => c.kind === 'proto')!.protos, [2]); assert.deepEqual(s.conds.find(c => c.kind === 'exporter')!.ips, ['10.255.1.1']); }
  const groupQuery = seen.find(s => s.dims.includes('dstIp'))!.conds.find(c => c.kind === 'dst')!.m![0]!;
  assert.equal(groupQuery.lo, 224 * 2 ** 24 + 1 * 256); assert.equal(groupQuery.hi, 239 * 2 ** 24 + 0xffffff);
});

test('no exporter, or a store that cannot answer, gives nothing rather than an error', async () => {
  assert.equal(await igmpFromFlows(fakeApp(() => []), []), null);
  assert.equal(await igmpFromFlows({ store: { report: async () => { throw new Error('no raw tier'); } } } as unknown as App, ['10.0.0.1']), null);
  const empty = (await igmpFromFlows(fakeApp(() => []), ['10.0.0.1']))!;
  assert.equal(empty.reports, 0); assert.equal(empty.v3Hosts, 0); assert.equal(empty.members.size, 0);
});
