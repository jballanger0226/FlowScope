import test from 'node:test';
import assert from 'node:assert/strict';
import { pimIssues, type PimPeer } from '../src/snmp/pimcheck.js';
import type { Multicast, McPimIf } from '../src/snmp/multicast.js';

const mc = (pim: McPimIf[], extra: Partial<Multicast> = {}): Multicast => ({ readAt: 1, source: 'standard', routes: [], receivers: [], pimInterfaces: pim, neighbors: [], interfaces: [], truncated: false, ...extra }) as Multicast;
const nm = (ix: number): string => (ix === 99 ? 'Loopback0' : 'Eth' + ix);
const peer = (mode: McPimIf['mode']): PimPeer => ({ name: 'leaf', mc: mc([{ ifIndex: 5, mode, dr: null }]), ips: new Map([['10.0.0.2', 5]]), ifName: nm });

test('dense against sparse on a link is a warning, sparse against sparse-dense only a note, equal modes nothing', () => {
  const me = mc([{ ifIndex: 1, mode: 'sparse', dr: null }], { neighbors: [{ address: '10.0.0.2', ifIndex: 1 }] });
  const a = pimIssues(me, nm, [peer('dense')]);
  assert.equal(a.length, 1); assert.equal(a[0]!.level, 'warn'); assert.match(a[0]!.text, /Eth1 runs PIM sparse, but leaf runs dense on Eth5/);
  assert.equal(pimIssues(me, nm, [peer('sparse-dense')])[0]!.level, 'info');
  assert.deepEqual(pimIssues(me, nm, [peer('sparse')]), []);
  assert.deepEqual(pimIssues(me, nm, []), [], 'a neighbour that is not polled is not guessed at');
});

test('mixed modes are noted but a loopback does not count', () => {
  assert.deepEqual(pimIssues(mc([{ ifIndex: 1, mode: 'sparse', dr: null }, { ifIndex: 99, mode: 'dense', dr: null }]), nm, []), []);
  const x = pimIssues(mc([{ ifIndex: 1, mode: 'sparse', dr: null }, { ifIndex: 2, mode: 'dense', dr: null }]), nm, []);
  assert.equal(x.length, 1); assert.equal(x[0]!.kind, 'mixed'); assert.equal(x[0]!.level, 'info');
});

test('a dense group on a sparse-dense interface with no RP is a warning, Auto-RP groups are not', () => {
  const r = (group: string, rp: string | null) => ({ group, source: '0.0.0.0', inIfIndex: 1, upstream: null, protocol: 9, pkts: null, bps: null, expirySec: null, flags: [], rp, oifs: [] });
  const x = pimIssues(mc([{ ifIndex: 1, mode: 'sparse-dense', dr: null }], { routes: [r('239.1.1.1', null), r('224.0.1.40', null), r('239.2.2.2', '10.0.0.9')] as never }), nm, []);
  assert.equal(x.length, 1); assert.equal(x[0]!.kind, 'no-rp'); assert.match(x[0]!.text, /239\.1\.1\.1/); assert.ok(!/224\.0\.1\.40|239\.2\.2\.2/.test(x[0]!.text));
});
