import test from 'node:test';
import assert from 'node:assert/strict';
import type { SnmpValue } from '../src/snmp/client.js';
import { readAaa } from '../src/snmp/aaa.js';
import { readAuthSetup, authMethods } from '../src/snmp/authsetup.js';
import { readConfigState } from '../src/snmp/confighist.js';

const fake = (tables: Record<string, Record<string, SnmpValue>>, scalars: Record<string, SnmpValue> = {}) => ({
  column: async (oid: string) => new Map(Object.entries(tables[oid] ?? {})),
  get: async (oids: string[]) => new Map(oids.filter(o => o in scalars).map(o => [o, { oid: o, value: scalars[o]! }]))
}) as never;

const CFG = '1.3.6.1.4.1.9.10.56.1.1.2.1', ST = '1.3.6.1.4.1.9.10.56.1.2.1.1';
// values as the Catalyst 9300 returned them: server 1.0 is TACACS+ with no traffic, server 2.1 is RADIUS with some timeouts and a slow last answer
const aaaTables = (over: Record<string, SnmpValue> = {}): Record<string, Record<string, SnmpValue>> => ({
  [`${CFG}.3`]: { '1.0': '10.254.185.15', '2.1': '10.254.185.251' }, [`${CFG}.4`]: { '1.0': 49, '2.1': 1812 }, [`${CFG}.5`]: { '1.0': 49, '2.1': 1813 }, [`${CFG}.7`]: { '1.0': 0, '2.1': 1 },
  [`${ST}.1`]: { '1.0': 0, '2.1': 24115 }, [`${ST}.2`]: { '1.0': 0, '2.1': 77 }, [`${ST}.6`]: { '1.0': 0, '2.1': 925 }, [`${ST}.8`]: { '1.0': 0, '2.1': 12 },
  [`${ST}.17`]: { '1.0': 0, '2.1': 3507 }, [`${ST}.18`]: { '1.0': 0, '2.1': 67 }, [`${ST}.25`]: { '1.0': 1, '2.1': 1 }, [`${ST}.26`]: { '1.0': 956724, '2.1': 956450 }, [`${ST}.29`]: { '1.0': 0, '2.1': over.dead ?? 2 }
});

test('RADIUS health: servers, their type from the port, and a slow last answer is called out', async () => {
  const a = await readAaa(fake(aaaTables()), null, 1000);
  assert.equal(a!.servers.length, 2);
  const [tac, rad] = a!.servers;
  assert.deepEqual([tac!.address, tac!.kind, tac!.port], ['10.254.185.15', 'tacacs', 49]);
  assert.deepEqual([rad!.address, rad!.kind, rad!.authReq, rad!.authTimeouts, rad!.authFail, rad!.authMs, rad!.deadCount, rad!.up], ['10.254.185.251', 'radius', 24115, 77, 12, 925, 2, true]);
  assert.equal(tac!.level, 'ok');            // an unused server is not a problem
  assert.equal(rad!.level, 'warn'); assert.match(rad!.problems.join(' '), /925 ms/);
  assert.equal(rad!.newTimeouts, null);       // nothing to compare with on the first read
});

test('RADIUS health: new timeouts and a new dead period since the last read are reported, a counter reset is not', async () => {
  const first = await readAaa(fake(aaaTables()), null, 1000);
  const t = aaaTables({ dead: 3 }); t[`${ST}.2`] = { '1.0': 0, '2.1': 80 }; t[`${ST}.1`] = { '1.0': 0, '2.1': 24200 }; t[`${ST}.6`] = { '1.0': 0, '2.1': 40 };
  const next = await readAaa(fake(t), first, 61_000);
  const rad = next!.servers[1]!;
  assert.deepEqual([rad.newTimeouts, rad.newDead, rad.newReq], [3, 1, 85]);
  assert.equal(rad.level, 'warn'); assert.match(rad.problems.join(' '), /dead 1 time/);
  const reset = aaaTables(); reset[`${ST}.1`] = { '1.0': 0, '2.1': 5 };
  assert.equal((await readAaa(fake(reset), next, 121_000))!.servers[1]!.newReq, null);
  const down = aaaTables(); down[`${ST}.25`] = { '1.0': 1, '2.1': 2 };
  const d = (await readAaa(fake(down), null, 1))!.servers[1]!; assert.equal(d.level, 'bad'); assert.equal(d.up, false);
});

test('port authentication setup: 802.1X from the PAE capability bit, MAB from the MAB table, host mode and open access from the framework table', async () => {
  const CAF = '1.3.6.1.4.1.9.9.656.1.2.1.1';
  const r = await readAuthSetup(fake({
    [`${CAF}.3`]: { '99': 3, '120': 3 }, [`${CAF}.4`]: { '99': 1, '120': 2 }, [`${CAF}.5`]: { '99': 2, '120': 2 }, [`${CAF}.6`]: { '99': 2, '120': 2 },
    '1.3.6.1.4.1.9.9.220.1.1.1.10': { '99': Buffer.from([0x80]), '120': Buffer.from([0x80]) }, '1.3.6.1.4.1.9.9.654.1.1.1.1.1': { '99': 1, '120': 2 }
  }));
  assert.deepEqual(r.map(p => [p.ifIndex, p.dot1x, p.mab, p.mode, p.control, p.open]), [[99, true, true, 'multi-auth', 'auto', true], [120, true, false, 'multi-auth', 'auto', false]]);
  assert.equal(authMethods(r[0]!), '802.1X + MAB'); assert.equal(authMethods(r[1]!), '802.1X only');
  assert.equal(authMethods({ dot1x: false, mab: true }), 'MAB only');
});

test('configuration state: changed after the last save is unsaved, and only writes are listed as changes', async () => {
  const B = '1.3.6.1.4.1.9.9.43.1.1', H = `${B}.6.1`;
  const sc = { [`${B}.1.0`]: 955997, [`${B}.2.0`]: 954085, [`${B}.3.0`]: 916365, '1.3.6.1.2.1.1.3.0': 956460 };
  const hist = { [`${H}.2`]: { '737': 942755, '746': 954085 }, [`${H}.5`]: { '737': 2, '746': 4 }, [`${H}.6`]: { '737': 5, '746': 5 }, [`${H}.8`]: { '737': Buffer.from('dna-gopher'), '746': Buffer.from('admin') } };
  const now = 10_000_000;
  const s = await readConfigState(fake(hist, sc), now);
  assert.equal(s!.unsaved, true);
  assert.equal(Math.round(s!.unsavedSec * 10) / 10, 4.6);            // (956460 - 955997) ticks of 10 ms
  assert.equal(s!.changedAt, now - 4630); assert.equal(s!.savedAt, now - 23750);
  assert.deepEqual(s!.events.map(e => [e.what, e.user, e.via]), [['saved', 'admin', 'remote session']]);   // the read of the running config (737) is not a change
  const saved = await readConfigState(fake({}, { ...sc, [`${B}.2.0`]: 956000 }), now);
  assert.equal(saved!.unsaved, false);
  assert.equal(await readConfigState({ get: async () => { throw new Error('x'); } } as never, now), null);
});
