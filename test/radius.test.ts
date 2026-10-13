import test from 'node:test';
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import { authenticate, account, RadiusError } from '../src/auth/radius.js';
import { mockRadius as mockServer } from './helpers.js';

test('RADIUS PAP accept, reject, long password, attributes', async () => {
  const s = await mockServer('sh4red', { alice: { pw: 'correct horse battery staple', filter: 'flowscope-admin', klass: 'grp=netops' }, bob: { pw: 'p' } });
  try {
    const o = { servers: [{ host: '127.0.0.1', port: s.port }], secret: 'sh4red', timeoutMs: 800, retries: 0, nasId: 'flowscope' };
    const a = await authenticate(o, 'alice', 'correct horse battery staple');
    assert.equal(a.accepted, true); assert.deepEqual(a.filterIds, ['flowscope-admin']); assert.deepEqual(a.classes, ['grp=netops']); assert.equal(a.replyMessage, 'Welcome');
    assert.equal((await authenticate(o, 'alice', 'wrong')).accepted, false);
    assert.equal((await authenticate(o, 'nobody', 'x')).accepted, false);
    assert.equal((await authenticate(o, 'alice', '')).accepted, false);
    assert.ok(s.seen.every(x => x.msgAuthOk), 'requests carry a valid Message-Authenticator');
    const long = 'x'.repeat(64);
    const s2 = await mockServer('sh4red', { carol: { pw: long } });
    try { assert.equal((await authenticate({ ...o, servers: [{ host: '127.0.0.1', port: s2.port }] }, 'carol', long)).accepted, true); } finally { s2.close(); }
  } finally { s.close(); }
});

test('RADIUS: wrong shared secret is detected, failover to second server, timeout, accounting', async () => {
  const bad = await mockServer('sh4red', { alice: { pw: 'pw' } }, { badSecretReply: true });
  const good = await mockServer('sh4red', { alice: { pw: 'pw' } });
  try {
    const base = { secret: 'sh4red', timeoutMs: 500, retries: 0 };
    await assert.rejects(() => authenticate({ ...base, servers: [{ host: '127.0.0.1', port: bad.port }] }, 'alice', 'pw'), /shared secret/);
    // first server silent (nothing listening), second answers
    const dead = dgram.createSocket('udp4'); await new Promise<void>(r => dead.bind(0, '127.0.0.1', () => r())); const deadPort = dead.address().port;
    const r = await authenticate({ ...base, servers: [{ host: '127.0.0.1', port: deadPort }, { host: '127.0.0.1', port: good.port }] }, 'alice', 'pw');
    assert.equal(r.accepted, true); assert.equal(r.server, `127.0.0.1:${good.port}`);
    await assert.rejects(() => authenticate({ ...base, servers: [{ host: '127.0.0.1', port: deadPort }] }, 'alice', 'pw'), (e: Error) => e instanceof RadiusError && e.kind === 'timeout');
    dead.close();
    await account({ ...base, servers: [{ host: '127.0.0.1', port: good.port }] }, 'alice', 'sess-1', 'start');
    await account({ ...base, servers: [{ host: '127.0.0.1', port: good.port }] }, 'alice', 'sess-1', 'stop', 42);
    assert.deepEqual(good.seen.filter(x => x.code === 4).map(x => x.acctStatus), [1, 2]);
  } finally { bad.close(); good.close(); }
});
