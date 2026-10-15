import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cards, issues, type OvInput } from '../web/views/overview_logic.js';

const ifc = (ifIndex: number, name: string, extra: object = {}) => ({ ifIndex, name, alias: '', oper: 'up', isVlanIf: false, flagged: false, utilIn: null, utilOut: null, worstDropPct: null, ...extra });
const base = (): OvInput => ({
  dev: { status: 'ok', lastError: null, hasWlan: false, resources: { cpuPct: 10, memPct: 40, swapPct: null, disks: [] }, interfaces: [ifc(1, 'Gi1'), ifc(2, 'Gi2')] },
  health: null, wlan: null, neighbours: 2, arp: 5, hasHardware: true, thresholds: { util: 90, drop: 1 },
});

test('a healthy device has no issues and every card is ok', () => {
  const i = base(); const all = issues(i);
  assert.equal(all.length, 0);
  assert.ok(cards(i, all).every(c => c.level === 'ok'));
});

test('problems on one interface become one item that opens its quality section', () => {
  const i = base();
  i.health = { ifExtra: [{ ifIndex: 2, warnings: [{ level: 'bad', text: 'Half duplex' }, { level: 'warn', text: '5 frame errors' }] }],
    health: { sensors: [{ kind: 'optic', name: 'Gi2 Rx', state: 'warn', stateText: 'over a limit', ifIndex: 2 }], poe: [], stp: null, ospf: [], bgp: [] } };
  const all = issues(i);
  assert.equal(all.length, 1);
  assert.equal(all[0]!.level, 'bad');
  assert.deepEqual(all[0]!.target, { tab: 'interfaces', ifIndex: 2, section: 'quality' });
  assert.match(all[0]!.title, /3 link problems/);
});

test('hardware and routing problems point at their own tabs, worst first', () => {
  const i = base();
  i.health = { ifExtra: [], health: { sensors: [{ kind: 'temperature', name: 'CPU temp', state: 'warn', stateText: 'high' }], poe: [], stp: null, ospf: [], bgp: [{ address: '10.0.0.1', as: 65001, state: 'idle', level: 'bad' }] } };
  const all = issues(i);
  assert.deepEqual(all.map(x => x.target?.tab), ['network', 'hardware']);
  const cs = cards(i, all);
  assert.equal(cs.find(c => c.tab === 'network')!.level, 'bad');
  assert.equal(cs.find(c => c.tab === 'hardware')!.level, 'warn');
});

test('high CPU is listed without a link, since the graphs are on the Overview', () => {
  const i = base(); i.dev.resources!.cpuPct = 97;
  const all = issues(i);
  assert.equal(all[0]!.level, 'bad'); assert.equal(all[0]!.target, undefined);
});
