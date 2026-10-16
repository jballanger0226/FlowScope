import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import type { SnmpClient, SnmpValue } from '../src/snmp/client.js';
import { diffExtra, linkWarnings, readIfExtra } from '../src/snmp/health.js';

/** Rows from a real walk of a Catalyst 9300 stack: CISCO-IF-EXTENSION-MIB queue drops and resets, storm control and port security counts for five interfaces. */
const FIX = JSON.parse(fs.readFileSync(path.join(import.meta.dirname, '..', '..', 'test', 'fixtures', 'ifextra-c9300.json'), 'utf8')) as Record<string, SnmpValue>;
const IF = (n: number) => `1.3.6.1.2.1.2.2.1.7.${n}`;
function agent(rows: Record<string, SnmpValue>, asked: string[] = []): SnmpClient {
  const all: Record<string, SnmpValue> = { ...rows };
  for (const n of [1, 9, 14, 234, 560]) all[IF(n)] = 1;
  return { column: async (col: string) => {
    asked.push(col);
    const m = new Map<string, SnmpValue>();
    for (const [o, v] of Object.entries(all)) if (o.startsWith(col + '.')) m.set(o.slice(col.length + 1), v);
    return m;
  } } as unknown as SnmpClient;
}

test('a Cisco device gives output queue drops, resets and port security violations per interface', async () => {
  const m = await readIfExtra(agent(FIX), 1000, true);
  const busy = m.get(560)!;
  assert.equal(busy.totals.outQDrops, 1479195824); assert.equal(busy.totals.inQDrops, 0); assert.equal(busy.totals.resets, 2);
  assert.equal(busy.reason, 'up');
  assert.equal(m.get(14)!.totals.portSec, 4); assert.equal(m.get(234)!.totals.portSec, 15);
});

test('a device that is not Cisco is not asked for the Cisco tables', async () => {
  const asked: string[] = [];
  const m = await readIfExtra(agent(FIX, asked), 1000, false);
  assert.ok(!asked.some(c => c.startsWith('1.3.6.1.4.1.9.')));
  assert.equal(m.get(560)!.totals.outQDrops, undefined);
});

test('storm control counts are added up over the traffic types of an interface', async () => {
  const rows = { ...FIX, '1.3.6.1.4.1.9.9.362.1.2.1.1.3.9.1': 100, '1.3.6.1.4.1.9.9.362.1.2.1.1.3.9.2': 50, '1.3.6.1.4.1.9.9.362.1.2.1.1.3.9.3': 0, '1.3.6.1.4.1.9.9.362.1.2.1.1.3.90.1': 7 };
  const m = await readIfExtra(agent(rows), 1000, true);
  assert.equal(m.get(9)!.totals.storm, 150, 'interface 90 does not leak into interface 9');
});

test('growth in the new counters turns into plain-language warnings, and no growth stays quiet', async () => {
  const a = (await readIfExtra(agent(FIX), 1000, true)).get(560)!;
  const rows = { ...FIX, '1.3.6.1.4.1.9.9.276.1.1.1.1.11.560': 1479195824 + 500, '1.3.6.1.4.1.9.9.315.1.2.1.1.9.560': 3, '1.3.6.1.4.1.9.9.276.1.1.2.1.1.560': 3, '1.3.6.1.4.1.9.9.362.1.2.1.1.3.560.1': 40 };
  const b = diffExtra(a, (await readIfExtra(agent(rows), 61_000, true)).get(560)!);
  assert.equal(b.delta!.outQDrops, 500);
  const w = linkWarnings(b, 1, 10000).map(x => x.text).join('\n');
  assert.match(w, /500 packets were dropped from this port's output queue/);
  assert.match(w, /Storm control suppressed 40 packets/);
  assert.match(w, /3 port security violations/);
  assert.match(w, /reset 1 time/);
  const quiet = diffExtra(a, (await readIfExtra(agent(FIX), 61_000, true)).get(560)!);
  assert.deepEqual(linkWarnings(quiet, 1, 10000), []);
});
