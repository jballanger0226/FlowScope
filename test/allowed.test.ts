import test from 'node:test';
import assert from 'node:assert/strict';
import { TargetPolicy } from '../src/snmp/allowed.js';
import { Discovery } from '../src/snmp/discovery.js';

test('an empty list allows every address', () => {
  const p = new TargetPolicy('  ');
  assert.equal(p.open, true); assert.equal(p.allows('203.0.113.9'), true); assert.equal(p.allows('2001:db8::1'), true);
});

test('prefixes and single addresses, IPv4 and IPv6', () => {
  const p = new TargetPolicy('10.20.0.0/16, 192.0.2.10\n2001:db8:1::/48;198.51.100.0/24');
  assert.deepEqual(p.entries, ['10.20.0.0/16', '192.0.2.10', '2001:db8:1::/48', '198.51.100.0/24']);
  for (const ip of ['10.20.0.1', '10.20.255.254', '192.0.2.10', '198.51.100.77', '2001:db8:1::5', '::ffff:10.20.3.4']) assert.equal(p.allows(ip), true, ip);
  for (const ip of ['10.21.0.1', '192.0.2.11', '2001:db8:2::1', '127.0.0.1', 'not-an-ip', '']) assert.equal(p.allows(ip), false, ip);
});

test('bad entries are refused with the entry named', () => {
  for (const bad of ['10.0.0.0/33', 'router1', '10.0.0.0/x', '2001:db8::/129', '10.0.0.0/8/9']) assert.throws(() => new TargetPolicy(bad), new RegExp(bad.replace(/[/.]/g, '.')), bad);
});

test('discovery refuses a search that reaches outside the allowed networks before sending anything', () => {
  const p = new TargetPolicy('10.20.0.0/24');
  let probed = 0;
  const devs = { list: () => [] } as never;
  const creds = { defaultId: () => 1, list: () => [{ id: 1, name: 'ro' }], resolve: () => { probed++; throw new Error('should not be used'); } } as never;
  // (an allowed search starts a background scan and is covered by the discovery tests in snmp.test.ts)
  const log = { info() { /* quiet */ } } as never;
  const d = new Discovery(devs, creds, log, { timeoutMs: 50 });
  assert.throws(() => d.start('10.20.0.250-10.20.1.5', 'u', 1, false, ip => p.allows(ip)), /10\.20\.1\.0 is outside the networks you may scan/);
  assert.throws(() => d.start('192.0.2.0/30', 'u', 1, false, ip => p.allows(ip)), /outside/);
  assert.equal(probed, 0, 'nothing was sent for the refused searches');
});
