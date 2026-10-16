import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ipv4ToInt, isPublicIPv4, publicAddresses } from '../web/views/ip_scope.js';

test('private, shared, loopback, link-local and other reserved ranges are not public, at both ends of each range', () => {
  for (const ip of ['0.1.2.3', '10.0.0.0', '10.255.255.255', '100.64.0.1', '100.127.255.254', '127.0.0.1', '169.254.1.1', '172.16.0.1', '172.31.255.255',
    '192.0.0.8', '192.0.2.5', '192.168.0.1', '192.168.255.255', '198.18.0.1', '198.19.255.255', '198.51.100.7', '203.0.113.9', '224.0.0.5', '239.255.255.250', '240.0.0.1', '255.255.255.255']) {
    assert.equal(isPublicIPv4(ip), false, ip);
  }
});

test('addresses just outside the reserved ranges are public', () => {
  for (const ip of ['1.1.1.1', '8.8.8.8', '9.255.255.255', '11.0.0.0', '100.63.255.255', '100.128.0.0', '126.255.255.255', '128.0.0.1', '169.253.0.1', '169.255.0.1',
    '172.15.255.255', '172.32.0.0', '192.0.1.1', '192.167.255.255', '192.169.0.0', '198.17.255.255', '198.20.0.0', '203.0.112.255', '203.0.114.0', '223.255.255.255']) {
    assert.equal(isPublicIPv4(ip), true, ip);
  }
});

test('a /prefix after the address is ignored, and anything that is not a dotted IPv4 address is not public', () => {
  assert.equal(isPublicIPv4('8.8.8.8/30'), true);
  assert.equal(isPublicIPv4('192.168.1.1/24'), false);
  for (const bad of ['', 'abc', '256.1.1.1', '1.2.3', '1.2.3.4.5', '2001:db8::1', '2606:4700::1111', ' ']) assert.equal(isPublicIPv4(bad), false, bad);
  assert.equal(ipv4ToInt('1.2.3.4'), 16909060);
  assert.equal(ipv4ToInt('300.1.1.1'), null);
});

test('publicAddresses keeps only the public ones, in order, as given', () => {
  assert.deepEqual(publicAddresses(['10.0.0.1/24', '203.0.114.2/30', '192.168.1.1/24', '8.8.4.4/32']), ['203.0.114.2/30', '8.8.4.4/32']);
  assert.deepEqual(publicAddresses([]), []);
  assert.deepEqual(publicAddresses(undefined), []);
});
