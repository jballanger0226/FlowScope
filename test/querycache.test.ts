import test from 'node:test';
import assert from 'node:assert/strict';
import { QueryCache, SwitchableStore } from '../src/store/switchable.js';
import type { StreamQuery, StreamPage, TsStore } from '../src/store/types.js';

test('identical requests share one run, and the result is reused until it expires', async () => {
  let t = 1_000_000; const c = new QueryCache(5000, 24, () => t);
  let runs = 0;
  const job = async () => { runs++; await new Promise(r => setTimeout(r, 10)); return { rows: [runs] }; };
  const [a, b] = await Promise.all([c.run('k', job), c.run('k', job)]);
  assert.equal(runs, 1); assert.deepEqual(a, b);
  a.rows.push(99);                                   // callers get their own copy
  assert.deepEqual((await c.run('k', job)).rows, [1]);
  t += 4999; await c.run('k', job); assert.equal(runs, 1);
  t += 2; assert.deepEqual((await c.run('k', job)).rows, [2]); assert.equal(runs, 2);
  assert.equal((await c.run('other', job)).rows[0], 3);
});

test('a failed run is not remembered', async () => {
  const c = new QueryCache(5000, 24, () => 1);
  let n = 0;
  await assert.rejects(() => c.run('k', async () => { n++; throw new Error('boom'); }), /boom/);
  assert.equal(await c.run('k', async () => { n++; return 'ok'; }), 'ok'); assert.equal(n, 2);
});

test('the cache stays small', async () => {
  const c = new QueryCache(5000, 3, () => 1);
  for (let i = 0; i < 10; i++) await c.run('k' + i, async () => i);
  let runs = 0;
  await c.run('k0', async () => { runs++; return 0; }); assert.equal(runs, 1);   // long gone
  await c.run('k9', async () => { runs++; return 9; }); assert.equal(runs, 1);   // still there
});

test('live ranges that differ by a second share an answer; fixed ranges and other queries do not', async () => {
  const now = Date.now();
  let runs = 0;
  const inner = { kind: 'sqlite', searchStreams: async (q: StreamQuery): Promise<StreamPage> => { runs++; return { rows: [], total: q.limit, truncated: false } as unknown as StreamPage; }, deleteDevice: async () => undefined, close: async () => undefined } as unknown as TsStore;
  const s = new SwitchableStore(inner);
  const base: StreamQuery = { range: { from: now - 3_600_000, to: now }, conds: [], sort: 'time', dir: 'desc', limit: 200, localIps: [] };
  // pin the bucket so the test does not straddle a 5 s boundary
  const edge = Math.floor(now / 5000) * 5000 + 100;
  const q = (dt: number, over: Partial<StreamQuery> = {}): StreamQuery => ({ ...base, range: { from: edge - 3_600_000 + dt, to: edge + dt }, ...over });
  await s.searchStreams(q(0)); await s.searchStreams(q(900)); assert.equal(runs, 1);
  await s.searchStreams(q(0, { limit: 300 })); assert.equal(runs, 2);
  await s.searchStreams(q(0, { sort: 'bytes' })); assert.equal(runs, 3);
  // a range far from now is exact: one millisecond apart is a different question
  const old = { from: now - 9 * 86400_000, to: now - 8 * 86400_000 };
  await s.searchStreams({ ...base, range: old }); await s.searchStreams({ ...base, range: { ...old, to: old.to + 1 } }); assert.equal(runs, 5);
  await s.searchStreams({ ...base, range: old }); assert.equal(runs, 5);
  await s.deleteDevice(1);     // clears what was remembered
  await s.searchStreams({ ...base, range: old }); assert.equal(runs, 6);
});
