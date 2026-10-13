import test from 'node:test';
import assert from 'node:assert/strict';
import { openClickHouse } from '../src/store/clickhouse.js';
import { scenarios, rec, q, RET, type Mk } from './scenarios.js';

/** Runs the shared store scenarios against a real ClickHouse server. Set FLOWSCOPE_TEST_CLICKHOUSE=http://host:8123 to enable. */
const url = process.env.FLOWSCOPE_TEST_CLICKHOUSE;
const log = { info() {}, warn() {}, error() {}, debug() {} } as any;

if (!url) {
  test('clickhouse store scenarios', { skip: 'set FLOWSCOPE_TEST_CLICKHOUSE to run' }, () => undefined);
} else {
  let n = 0;
  const mk: Mk = async () => {
    const db = `fs_test_${process.pid}_${Date.now()}_${n++}`;
    const base = url.replace(/\/+$/, '');
    const s = await openClickHouse(`${base}/${db}`, log);
    return {
      s: s as any,
      done: async () => { await fetch(`${base}/?query=${encodeURIComponent('DROP DATABASE IF EXISTS ' + db + ' SYNC')}`, { method: 'POST' }); }
    };
  };
  scenarios('clickhouse', mk);

  test('clickhouse: sql-injection-shaped input is treated as data', async () => {
    const t = await mk();
    try {
      await t.s.insertFlows([rec({ exporter: "x'; DROP TABLE flow_raw; --" })]);
      const r = await t.s.searchStreams(q([{ kind: 'exporter', ips: ["x'; DROP TABLE flow_raw; --"] }, { kind: 'mac', text: "\\' or 1=1 --" }]));
      assert.equal(r.total, 0);
      const r2 = await t.s.searchStreams(q([{ kind: 'exporter', ips: ["x'; DROP TABLE flow_raw; --"] }]));
      assert.equal(r2.total, 1);
      assert.equal((await t.s.stats()).rawRows, 1);
    } finally { await t.done(); }
  });
}
