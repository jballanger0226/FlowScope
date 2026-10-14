import test from 'node:test';
import assert from 'node:assert/strict';
import { clientAddress } from '../src/server/http.js';
import { loadConfig } from '../src/config.js';

test('without a proxy the forwarded header is ignored', () => {
  assert.equal(clientAddress('203.0.113.5', '1.2.3.4', 0), '203.0.113.5');
  assert.equal(clientAddress('::ffff:203.0.113.5', undefined, 0), '203.0.113.5');
});

test('behind one proxy the client is the last entry, so a header the client sent cannot pick the address', () => {
  // the proxy appends what it saw; the client tried to pose as 10.0.0.1
  assert.equal(clientAddress('::ffff:10.9.9.9', '10.0.0.1, 198.51.100.7', 1), '198.51.100.7');
  assert.equal(clientAddress('10.9.9.9', '198.51.100.7', 1), '198.51.100.7');
  // several header lines are joined
  assert.equal(clientAddress('10.9.9.9', ['10.0.0.1', '198.51.100.7'], 1), '198.51.100.7');
  assert.equal(clientAddress('10.9.9.9', '2001:db8::7', 1), '2001:db8::7');
});

test('behind two proxies the client is the second entry from the right', () => {
  assert.equal(clientAddress('10.9.9.9', '10.0.0.1, 198.51.100.7, 172.16.0.2', 2), '198.51.100.7');
  // fewer entries than proxies: the first one is the best information there is
  assert.equal(clientAddress('10.9.9.9', '198.51.100.7', 2), '198.51.100.7');
});

test('a missing or unusable header falls back to the proxy address', () => {
  assert.equal(clientAddress('10.9.9.9', undefined, 1), '10.9.9.9');
  assert.equal(clientAddress('10.9.9.9', '', 1), '10.9.9.9');
  assert.equal(clientAddress('10.9.9.9', 'unknown', 1), '10.9.9.9');
  assert.equal(clientAddress('10.9.9.9', '<script>alert(1)</script>', 1), '10.9.9.9');
});

test('FLOWSCOPE_TRUST_PROXY: 1 keeps meaning one proxy, a number sets the count', () => {
  const n = (v?: string) => loadConfig(v === undefined ? {} : { FLOWSCOPE_TRUST_PROXY: v }).trustProxy;
  assert.equal(n(), 0); assert.equal(n('0'), 0); assert.equal(n('1'), 1); assert.equal(n('2'), 2); assert.equal(n('yes'), 0);
});
