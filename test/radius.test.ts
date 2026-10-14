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

test('RADIUS: Message-Authenticator is the first attribute of a request', async () => {
  const s = await mockServer('sh4red', { alice: { pw: 'pw' } });
  try {
    await authenticate({ servers: [{ host: '127.0.0.1', port: s.port }], secret: 'sh4red', timeoutMs: 800, retries: 0 }, 'alice', 'pw');
    assert.equal(s.seen.length, 1);
    assert.equal(s.seen[0].maFirst, true); assert.equal(s.seen[0].msgAuthOk, true);
  } finally { s.close(); }
});

test('RADIUS: replies without Message-Authenticator are refused when it is required, and reported either way', async () => {
  const none = await mockServer('sh4red', { alice: { pw: 'pw' } }, { replyMa: false });
  const has = await mockServer('sh4red', { alice: { pw: 'pw' } });
  try {
    const base = { secret: 'sh4red', timeoutMs: 400, retries: 0 };
    const o = (port: number, requireMa: boolean) => ({ ...base, servers: [{ host: '127.0.0.1', port }], requireMa });
    await assert.rejects(() => authenticate(o(none.port, true), 'alice', 'pw'), (e: Error) => e instanceof RadiusError && e.kind === 'protocol' && /Message-Authenticator/.test(e.message));
    const lax = await authenticate(o(none.port, false), 'alice', 'pw');
    assert.equal(lax.accepted, true); assert.equal(lax.messageAuth, false);
    const strict = await authenticate(o(has.port, true), 'alice', 'pw');
    assert.equal(strict.accepted, true); assert.equal(strict.messageAuth, true);
    // rejections are protected too
    const rej = await authenticate(o(has.port, true), 'alice', 'wrong');
    assert.equal(rej.accepted, false); assert.equal(rej.messageAuth, true);
    await assert.rejects(() => authenticate(o(none.port, true), 'alice', 'wrong'), /Message-Authenticator/);
    // accounting replies carry none and are not affected
    await account(o(none.port, true), 'alice', 's1', 'start');
  } finally { none.close(); has.close(); }
});

test('RADIUS: forged or mismatched replies do not cancel a sign-in', async () => {
  const s = await mockServer('sh4red', { alice: { pw: 'pw' } }, { junkFirst: true });
  try {
    const o = { servers: [{ host: '127.0.0.1', port: s.port }], secret: 'sh4red', timeoutMs: 800, retries: 0, requireMa: true };
    const r = await authenticate(o, 'alice', 'pw');
    assert.equal(r.accepted, true);
    assert.equal((await authenticate(o, 'alice', 'wrong')).accepted, false);
  } finally { s.close(); }
});

test('RADIUS: only forged replies end as an error, not as a success', async () => {
  const sock = dgram.createSocket('udp4');
  await new Promise<void>(r => sock.bind(0, '127.0.0.1', () => r()));
  sock.on('message', (m, rinfo) => {
    // an Access-Accept signed with a guessed secret
    const h = Buffer.alloc(20); h[0] = 2; h[1] = m[1]; h.writeUInt16BE(20, 2);
    sock.send(h, rinfo.port, rinfo.address);
  });
  try {
    const o = { servers: [{ host: '127.0.0.1', port: sock.address().port }], secret: 'sh4red', timeoutMs: 400, retries: 0 };
    await assert.rejects(() => authenticate(o, 'alice', 'pw'), /shared secret/);
  } finally { sock.close(); }
});
