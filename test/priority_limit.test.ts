import test from 'node:test';
import assert from 'node:assert/strict';
import { limitBps } from '../src/routes/links.js';

test('priority queue limit: kbps as configured, a percentage of the line speed, nothing for a share of what is left', () => {
  assert.equal(limitBps('5000 kbps', 1000), 5_000_000);
  assert.equal(limitBps('20%', 1000), 200_000_000);
  assert.equal(limitBps('10%', 10_000), 1_000_000_000);
  assert.equal(limitBps('10% remaining', 1000), null);
  assert.equal(limitBps('remainder', 1000), null);
  assert.equal(limitBps(null, 1000), null);
  assert.equal(limitBps('20%', 0), null, 'a percentage of an unknown speed has no rate');
});
