import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildNotices, downDevices, exporterSummary, impact, EXPORTER_STALE_MS, type DeviceState, type NoticeInput } from '../src/overview.js';
import type { OvInput } from '../web/views/overview_logic.js';

const NOW = Date.UTC(2026, 9, 15, 17, 0, 0);
const MIN = 60_000, HOUR = 3600_000;
const dev = (over: Partial<DeviceState> = {}): DeviceState => ({ id: 1, name: 'sw-1', ip: '10.0.0.1', role: 'switch', status: 'ok', lastOk: NOW - MIN, lastError: null, addedAt: NOW - 30 * 24 * HOUR, ...over });

const ifc = (ifIndex: number, name: string, extra: object = {}) => ({ ifIndex, name, alias: '', oper: 'up', isVlanIf: false, flagged: false, utilIn: null, utilOut: null, worstDropPct: null, ...extra });
const ov = (over: Partial<OvInput['dev']> = {}): OvInput => ({
  dev: { status: 'ok', lastError: null, hasWlan: false, resources: { cpuPct: 10, memPct: 40, swapPct: null, disks: [] }, interfaces: [ifc(1, 'Gi1'), ifc(2, 'Gi2')], ...over },
  health: null, wlan: null, neighbours: null, arp: null, hasHardware: false, thresholds: { util: 90, drop: 1 }
});

test('a device that failed its last poll is down since its last successful poll', () => {
  const [d] = downDevices([dev({ status: 'error', lastOk: NOW - 3 * HOUR - 12 * MIN, lastError: 'Request timed out' })], NOW);
  assert.equal(d!.downMs, 3 * HOUR + 12 * MIN);
  assert.equal(d!.since, NOW - 3 * HOUR - 12 * MIN);
  assert.equal(d!.neverReached, false);
  assert.equal(d!.lastError, 'Request timed out');
});

test('a device that never answered counts from when it was added, and says so', () => {
  const [d] = downDevices([dev({ status: 'error', lastOk: null, addedAt: NOW - 2 * HOUR })], NOW);
  assert.equal(d!.neverReached, true);
  assert.equal(d!.downMs, 2 * HOUR);
});

test('only devices that failed are listed, longest outage first', () => {
  const list = downDevices([
    dev({ id: 1, name: 'ok', status: 'ok' }), dev({ id: 2, name: 'paused', status: 'paused' }), dev({ id: 3, name: 'new', status: 'pending', lastOk: null }),
    dev({ id: 4, name: 'short', status: 'error', lastOk: NOW - 5 * MIN }), dev({ id: 5, name: 'long', status: 'error', lastOk: NOW - 2 * 24 * HOUR })
  ], NOW);
  assert.deepEqual(list.map(d => d.name), ['long', 'short']);
});

test('the clock running slightly behind never gives a negative duration', () => {
  assert.equal(downDevices([dev({ status: 'error', lastOk: NOW + 5000 })], NOW)[0]!.downMs, 0);
});

test('an unreachable device outranks any warning, and its stale readings are not listed', () => {
  const bad = ov({ resources: { cpuPct: 99, memPct: 10, swapPct: null, disks: [] } });
  const inputs: NoticeInput[] = [
    { dev: dev({ id: 1, name: 'sw-1' }), ov: bad },
    { dev: dev({ id: 2, name: 'sw-2', status: 'error', lastOk: NOW - HOUR }), ov: bad }
  ];
  const n = buildNotices(inputs, NOW);
  assert.equal(n[0]!.kind, 'device-down');
  assert.equal(n[0]!.dev, 'sw-2');
  assert.deepEqual(n[0]!.target, { tab: 'overview' });
  // the down device contributed one notice; its old CPU reading did not
  assert.equal(n.filter(x => x.dev === 'sw-2').length, 1);
  assert.equal(n.filter(x => x.dev === 'sw-1').length, 1);
});

test('problems come before warnings, and a router outranks a switch at the same level', () => {
  const warn = ov({ resources: { cpuPct: 88, memPct: 10, swapPct: null, disks: [] } });      // CPU 88%: warning
  const bad = ov({ resources: { cpuPct: 97, memPct: 10, swapPct: null, disks: [] } });       // CPU 97%: problem
  const n = buildNotices([
    { dev: dev({ id: 1, name: 'access-sw', role: 'switch' }), ov: bad },
    { dev: dev({ id: 2, name: 'core-rtr', role: 'router' }), ov: bad },
    { dev: dev({ id: 3, name: 'warn-rtr', role: 'router' }), ov: warn }
  ], NOW);
  assert.deepEqual(n.map(x => x.dev), ['core-rtr', 'access-sw', 'warn-rtr']);
  assert.deepEqual(n.map(x => x.level), ['bad', 'bad', 'warn']);
});

test('notices carry the tab, interface and section to open', () => {
  const o = ov(); o.dev.interfaces = [ifc(1, 'Gi1'), ifc(2, 'Gi2', { flagged: true, utilIn: 95, utilOut: 20 })];
  const [n] = buildNotices([{ dev: dev(), ov: o }], NOW);
  assert.equal(n!.kind, 'issue');
  assert.deepEqual(n!.target, { tab: 'interfaces', ifIndex: 2, section: 'traffic' });
  assert.equal(n!.devId, 1);
});

test('paused and not-yet-polled devices raise no notices, and a healthy network raises none', () => {
  const bad = ov({ resources: { cpuPct: 99, memPct: 10, swapPct: null, disks: [] } });
  assert.deepEqual(buildNotices([{ dev: dev({ status: 'paused' }), ov: bad }, { dev: dev({ id: 2, name: 'b', status: 'pending' }), ov: bad }], NOW), []);
  assert.deepEqual(buildNotices([{ dev: dev(), ov: ov() }, { dev: dev({ id: 2, name: 'c' }), ov: null }], NOW), []);
});

test('ranking is stable: equal notices sort by device then title', () => {
  const o = ov({ resources: { cpuPct: 97, memPct: 10, swapPct: null, disks: [] } });
  const n = buildNotices([{ dev: dev({ id: 2, name: 'b-sw' }), ov: o }, { dev: dev({ id: 1, name: 'a-sw' }), ov: o }], NOW);
  assert.deepEqual(n.map(x => x.dev), ['a-sw', 'b-sw']);
});

test('impact: level dominates, then unreachable, then device role', () => {
  assert.ok(impact({ level: 'bad', kind: 'issue' }, 'device') > impact({ level: 'warn', kind: 'device-down' }, 'router'));
  assert.ok(impact({ level: 'bad', kind: 'device-down' }, 'device') > impact({ level: 'bad', kind: 'issue' }, 'router'));
  assert.ok(impact({ level: 'warn', kind: 'issue' }, 'firewall') > impact({ level: 'warn', kind: 'issue' }, 'switch'));
});

test('exporters: the ones silent for more than five minutes are called out, longest silence first', () => {
  const e = (ip: string, ago: number) => ({ ip, name: ip, devId: null, version: 'v9', records: 10, lastSeen: NOW - ago, lastError: null });
  const s = exporterSummary([e('a', 10_000), e('b', EXPORTER_STALE_MS), e('c', EXPORTER_STALE_MS + 1), e('d', HOUR)], NOW);
  assert.equal(s.total, 4); assert.equal(s.active, 2);
  assert.deepEqual(s.silent.map(x => x.ip), ['d', 'c']);
  assert.equal(s.silent[0]!.silentMs, HOUR);
  assert.deepEqual(exporterSummary([], NOW), { total: 0, active: 0, silent: [] });
});
