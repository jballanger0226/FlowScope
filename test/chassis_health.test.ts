import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { SnmpClient, SnmpValue } from '../src/snmp/client.js';
import { readLag } from '../src/snmp/lag.js';
import { readUdld } from '../src/snmp/udld.js';
import { readStack } from '../src/snmp/cisco_extra.js';
import { judgeRedundancy, supervisorCount, type Redundancy } from '../src/snmp/redundancy.js';

const mk = (cc: Record<string, [string, SnmpValue][]>) => ({ column: async (oid: string) => new Map(cc[oid] ?? []) }) as unknown as SnmpClient;
const mac = Buffer.from('d0854354a502', 'hex'), zero = Buffer.alloc(6);

test('port-channels: members that LACP does not bundle or that stopped collecting are flagged, unused aggregators ignored', async () => {
  const A = '1.2.840.10006.300.43.1.1.1.1', P = '1.2.840.10006.300.43.1.2.1.1';
  const ok = Buffer.from([0xbc]), lame = Buffer.from([0xa0]); // activity+aggregation+sync+collecting+distributing, and no collecting/distributing
  const r = await readLag(mk({
    [`${A}.2`]: [['100', mac], ['101', mac], ['102', zero]], [`${A}.7`]: [['100', 1], ['101', 2]],
    [`${P}.4`]: [['1', 1], ['2', 1], ['3', 2]], [`${P}.12`]: [['1', 100], ['2', 100], ['3', 101]], [`${P}.13`]: [['1', 100], ['2', 100], ['3', 101]],
    [`${P}.21`]: [['1', ok], ['2', ok], ['3', lame]], [`${P}.23`]: [['1', ok], ['2', ok], ['3', ok]],
    '1.3.6.1.2.1.31.1.2.1.3': [['100.1', 1], ['100.2', 1], ['100.4', 1], ['101.3', 1]]
  }));
  assert.deepEqual(r.map(c => [c.ifIndex, c.level, c.members.length]), [[100, 'warn', 3], [101, 'bad', 1]]);
  assert.equal(r[0]!.members.find(m => m.ifIndex === 4)!.bundled, false); // configured but LACP never listed it
});

test('UDLD: only ports running it are listed; an unknown state is a fault', async () => {
  const T = '1.3.6.1.4.1.9.9.118.1.2.1.1';
  const r = await readUdld(mk({ [`${T}.5`]: [['1', 3], ['2', 2], ['3', 1], ['4', 1]], [`${T}.2`]: [['1', 3], ['2', 3], ['3', 2], ['4', 9]] }));
  assert.deepEqual(r.map(p => [p.ifIndex, p.mode, p.level]), [[1, 'aggressive', 'ok'], [3, 'enabled', 'off'], [4, 'enabled', 'bad']]);
});

test('StackWise Virtual: the stack links are front-panel ports and a down bundle is a problem', async () => {
  const S = '1.3.6.1.4.1.9.9.500.1.2';
  const mkS = (bundle: number) => mk({
    [`${S}.1.1.6`]: [['1', 4], ['2', 4]], [`${S}.1.1.1`]: [['1', 1], ['2', 2]], [`${S}.1.1.3`]: [['1', 1], ['2', 4]],
    [`${S}.4.1.1`]: [['1.1.500', Buffer.from('Te1/0/1')]], [`${S}.4.1.2`]: [['1.1.500', 1]], [`${S}.4.1.3`]: [['1.1.500', Buffer.from('Te2/0/1')]], [`${S}.4.1.4`]: [['1.1.500', 2]],
    [`${S}.3.1.2`]: [['1.1', bundle], ['2.1', 1]]
  });
  const up = await readStack(mkS(1));
  assert.equal(up!.svl, true); assert.equal(up!.ports[0]!.ifIndex, 500); assert.equal(up!.ports[0]!.neighborName, 'Te2/0/1'); assert.deepEqual(up!.problems, []);
  assert.match((await readStack(mkS(2)))!.problems[0]!, /StackWise Virtual link bundle/);
});

test('redundancy: a lost standby matters with two supervisors and is only a note with one; stacks do not count', () => {
  const r: Redundancy = { readAt: 0, unitState: 'active', peerState: 'disabled', peerId: null, duplex: false, configured: 'SSO', operating: 'non-redundant', configuredSso: true, operatingSso: false, lastSwitchover: null, sinceFailoverSec: null, level: 'ok', problems: [] };
  assert.equal(judgeRedundancy(r, 2).level, 'warn');
  assert.equal(judgeRedundancy(r, 1).level, 'ok');
  assert.equal(supervisorCount(['C9300-24T', 'C9300-24T'], 2, false), 1);
  assert.equal(supervisorCount(['C9600-SUP-1 Supervisor 1 Module', 'C9600-SUP-1 Supervisor 1 Module'], 0, false), 2);
});
