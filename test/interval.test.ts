import test from 'node:test';
import assert from 'node:assert/strict';
import { guardedInterval } from '../src/interval.js';

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

test('a slow job is not started again while it is still running', async () => {
  let started = 0, active = 0, maxActive = 0;
  const t = guardedInterval(10, async () => { started++; active++; maxActive = Math.max(maxActive, active); await sleep(55); active--; }, () => undefined);
  await sleep(160); clearInterval(t); await sleep(70);
  assert.equal(maxActive, 1);
  assert.ok(started >= 2 && started <= 3, 'ran ' + started + ' times in 160 ms with a 55 ms job');
});

test('a failing job is reported and runs again on a later tick', async () => {
  const errors: string[] = []; let n = 0;
  const t = guardedInterval(10, async () => { n++; throw new Error('boom ' + n); }, e => errors.push((e as Error).message));
  await sleep(80); clearInterval(t);
  assert.ok(n >= 3); assert.equal(errors[0], 'boom 1'); assert.equal(errors.length, n);
});

test('a job that throws synchronously is also reported', async () => {
  const errors: string[] = [];
  const t = guardedInterval(10, () => { throw new Error('sync'); }, e => errors.push((e as Error).message));
  await sleep(40); clearInterval(t);
  assert.ok(errors.length >= 2); assert.equal(errors[0], 'sync');
});
