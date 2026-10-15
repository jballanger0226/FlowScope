import test from 'node:test';
import assert from 'node:assert/strict';
import { runChecks, cleanOid, formatValue } from '../src/snmp/diagnose.js';
import { OID } from '../src/snmp/oids.js';
import type { SnmpValue } from '../src/snmp/client.js';

/** A device made of whole columns: the walker returns the rows registered under each OID, or an empty table. */
function fake(tables: Record<string, Record<string, SnmpValue>>, fail: string[] = []) {
  return { column: async (oid: string) => { if (fail.includes(oid)) throw new Error('No response from the device (timeout).'); return new Map(Object.entries(tables[oid] ?? {})); } };
}
const byId = (cs: Awaited<ReturnType<typeof runChecks>>) => Object.fromEntries(cs.map(c => [c.id, c]));

test('a firewall that publishes no LLDP is reported as missing, with the AgentX hint', async () => {
  const c = byId(await runChecks(fake({ [OID.ifName]: { '1': 'igb0', '2': 'igb1' }, [OID.ifHCInOctets]: { '1': 5, '2': 6 } }), { role: 'router', cisco: false }));
  assert.equal(c.interfaces.state, 'ok'); assert.equal(c.interfaces.count, 2);
  assert.equal(c.lldp.state, 'fail');
  assert.match(c.lldp.hint ?? '', /AgentX/);
  assert.match(c.lldp.hint ?? '', /\.1\.0\.8802/);
  assert.equal(c.cdp.state, 'na');
  assert.equal(c.mac.state, 'na');          // a router is not expected to have a MAC table
  assert.equal(c.arp.state, 'warn');        // but a router is expected to have an ARP cache
});

test('LLDP published with no neighbours is a warning, with neighbours it is ok and counts ports', async () => {
  const f = { role: 'device', cisco: false };
  const published = byId(await runChecks(fake({ [OID.ifName]: { '1': 'a' }, [OID.lldpLocPortId]: { '1': 'igb0' } }), f));
  assert.equal(published.lldp.state, 'warn');
  const seen = byId(await runChecks(fake({ [OID.ifName]: { '1': 'a' }, [OID.lldpLocPortId]: { '1': 'x' }, [OID.lldpRemChassisId]: { '0.1.1': 'aa', '0.1.2': 'bb', '0.3.1': 'cc' } }), f));
  assert.equal(seen.lldp.state, 'ok'); assert.equal(seen.lldp.count, 3);
  assert.match(seen.lldp.detail, /3 neighbours on 2 ports/);
});

test('MAC table: a switch without one fails, a Cisco switch is excused because its tables are per VLAN', async () => {
  const base = { [OID.ifName]: { '1': 'Gi1/0/1' } };
  assert.equal(byId(await runChecks(fake(base), { role: 'switch', cisco: false })).mac.state, 'fail');
  const cisco = byId(await runChecks(fake(base), { role: 'switch', cisco: true }));
  assert.equal(cisco.mac.state, 'na'); assert.match(cisco.mac.detail, /per VLAN/);
  assert.equal(byId(await runChecks(fake({ ...base, [OID.dot1dTpFdbPort]: { '1.2.3.4.5.6': 1 } }), { role: 'switch', cisco: false })).mac.state, 'ok');
});

test('only 32-bit counters is a warning; a timeout is quoted in the detail', async () => {
  const c = byId(await runChecks(fake({ [OID.ifName]: { '1': 'a' }, [OID.ifInOctets32]: { '1': 1 } }, [OID.lldpLocPortId]), { role: 'switch', cisco: false }));
  assert.equal(c.counters.state, 'warn');
  assert.equal(c.lldp.state, 'fail'); assert.match(c.lldp.detail, /timeout/);
});

test('cleanOid accepts numeric OIDs and refuses everything else', () => {
  assert.equal(cleanOid('1.0.8802.1.1.2.1.4'), '1.0.8802.1.1.2.1.4');
  assert.equal(cleanOid(' .1.3.6.1.2.1.1 '), '1.3.6.1.2.1.1');
  for (const bad of ['', '1', 'sysDescr', '1.3.6.1.2.1.1.x', '1..3', '3.1.2', '1.3.6.1.99999999999', '1.3.6.1.2.1;rm', '1.3.6.1.2.1.1\n.2']) assert.equal(cleanOid(bad), null, bad);
  assert.equal(cleanOid('1.' + Array(70).fill('1').join('.')), null);
});

test('formatValue prints text as text and binary as hex', () => {
  assert.deepEqual(formatValue(4, Buffer.from('OPNsense\0')), { type: 'OctetString', text: 'OPNsense' });
  assert.deepEqual(formatValue(4, Buffer.from([0x00, 0x1b, 0x21, 0xab, 0xcd, 0xef])), { type: 'OctetString', text: 'hex 00:1b:21:ab:cd:ef' });
  assert.deepEqual(formatValue(4, Buffer.alloc(0)), { type: 'OctetString', text: '' });
  assert.deepEqual(formatValue(70, 12345678901234567890n), { type: 'Counter64', text: '12345678901234567890' });
  assert.deepEqual(formatValue(2, 7), { type: 'Integer', text: '7' });
  assert.equal(formatValue(99, 1).type, 'type 99');
});
