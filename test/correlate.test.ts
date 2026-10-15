import { test } from 'node:test';
import assert from 'node:assert/strict';
import { correlate, verdict } from '../web/views/correlate.js';

const cpu = (vals: number[]) => vals.map((v, i) => ({ ts: i * 60_000, cpu: v, cpuMax: v }));

test('drops at moments of high CPU are counted and flagged as likely related', () => {
  const pts = cpu([10, 12, 95, 97, 11, 10, 9, 13, 96, 10]);
  const c = correlate([2 * 60_000, 3 * 60_000, 8 * 60_000], pts, 80, 60_000);
  assert.equal(c.moments, 3); assert.equal(c.high, 3); assert.equal(c.peak, 97);
  assert.ok(c.avgOther! < 15);
  assert.equal(verdict(c, 80).level, 'warn');
});

test('drops while the CPU is idle are reported as probably not CPU', () => {
  const pts = cpu([10, 12, 90, 11, 10, 9, 13, 10]);
  const c = correlate([4 * 60_000, 5 * 60_000], pts, 80, 60_000);
  assert.equal(c.high, 0);
  assert.equal(verdict(c, 80).level, 'ok');
});

test('no moments, or no CPU history near them, says so rather than guessing', () => {
  assert.match(verdict(correlate([], cpu([10]), 80, 60_000), 80).text, /No drops/);
  const far = correlate([10 * 3600_000], cpu([10, 20]), 80, 60_000);
  assert.equal(far.withData, 0);
  assert.match(verdict(far, 80).text, /no CPU history/i);
});

test('a CPU that is always high does not count as a link', () => {
  const c = correlate([60_000, 120_000], cpu([95, 96, 97, 95, 96]), 80, 60_000);
  assert.equal(verdict(c, 80).level, 'info');
});
