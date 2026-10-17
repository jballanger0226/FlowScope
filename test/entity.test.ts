import test from 'node:test';
import assert from 'node:assert/strict';
import { readEntity, modelText } from '../src/snmp/entity.js';
import type { SnmpClient, SnmpValue } from '../src/snmp/client.js';

const ENT = '1.3.6.1.2.1.47.1.1.1.1';
const rows: Record<string, SnmpValue> = {
  // a two-member stack, one module in member 1, a fan and a port that must be ignored
  [`${ENT}.5.1000`]: 3, [`${ENT}.5.2000`]: 3, [`${ENT}.5.1010`]: 9, [`${ENT}.5.1100`]: 7, [`${ENT}.5.1200`]: 10,
  [`${ENT}.13.1000`]: 'C9300-48UXM', [`${ENT}.13.2000`]: 'C9300-48UXM', [`${ENT}.13.1010`]: 'C9300-NM-8X',
  [`${ENT}.7.1000`]: 'Switch 1', [`${ENT}.7.2000`]: 'Switch 2', [`${ENT}.11.1000`]: 'FOC1', [`${ENT}.11.2000`]: 'FOC2',
  [`${ENT}.13.1100`]: 'FAN-SHOULD-NOT-BE-ASKED'
};
const client = (r: Record<string, SnmpValue>, asked: string[] = []): SnmpClient => ({
  column: async (col: string) => { const m = new Map<string, SnmpValue>(); for (const [o, v] of Object.entries(r)) if (o.startsWith(col + '.')) m.set(o.slice(col.length + 1), v); return m; },
  get: async (oids: string[]) => { asked.push(...oids); const m = new Map<string, { oid: string; type: number; value: SnmpValue }>(); for (const o of oids) if (o in r) m.set(o, { oid: o, type: 4, value: r[o]! }); return m; }
}) as unknown as SnmpClient;

test('the hardware model comes from the chassis and module rows of ENTITY-MIB only', async () => {
  const asked: string[] = [];
  const e = await readEntity(client(rows, asked), 1000);
  assert.deepEqual(e!.chassis.map(c => [c.name, c.model, c.serial]), [['Switch 1', 'C9300-48UXM', 'FOC1'], ['Switch 2', 'C9300-48UXM', 'FOC2']]);
  assert.deepEqual(e!.modules.map(m => m.model), ['C9300-NM-8X']);
  assert.ok(!asked.some(o => o.endsWith('.1100') || o.endsWith('.1200')), 'fans and ports are never asked for');
  assert.equal(modelText(e), '2 × C9300-48UXM');
  assert.equal(modelText({ readAt: 0, chassis: [{ index: 1, name: '', model: 'A', descr: '', serial: '', sw: '' }, { index: 2, name: '', model: 'B', descr: '', serial: '', sw: '' }], modules: [] }), 'A + B');
  assert.equal(modelText(null), '');
});

test('a device without ENTITY-MIB gives no model', async () => {
  assert.equal(await readEntity(client({}), 1), null);
  assert.equal(await readEntity({ column: async () => { throw new Error('noSuchName'); } } as unknown as SnmpClient, 1), null);
});
