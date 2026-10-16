import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import dgram from 'node:dgram';
import { App } from '../src/app.js';
import { loadConfig } from '../src/config.js';

const freePort = () => new Promise<number>(res => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = (s.address() as net.AddressInfo).port; s.close(() => res(p)); }); });
const freeUdp = () => new Promise<number>(res => { const s = dgram.createSocket('udp4'); s.bind(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); }); });

const ADMIN_PW = 'admin-test-passphrase-1';

async function call(base: string, cookie: string, url: string) {
  const r = await fetch(base + url, { headers: cookie ? { cookie } : {} });
  const text = await r.text();
  return { status: r.status, json: (() => { try { return JSON.parse(text); } catch { return null; } })() as any, text };
}
async function login(base: string, user: string, pass: string): Promise<{ cookie: string; csrf: string }> {
  const r = await fetch(base + '/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: user, password: pass }) });
  assert.equal(r.status, 200, `login ${user}`);
  const m = /fs_sid=([^;]*)/.exec(r.headers.get('set-cookie') ?? '');
  return { cookie: 'fs_sid=' + (m?.[1] ?? ''), csrf: (await r.json() as { csrf: string }).csrf };
}

/** Boots an app on free ports with an admin account, runs `fn`, and cleans up. */
async function withApp(fn: (app: App, base: string, admin: { cookie: string; csrf: string }) => Promise<void>): Promise<void> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-ov-'));
  const httpPort = await freePort(), flowPort = await freeUdp();
  const cfg = loadConfig({ FLOWSCOPE_TLS: 'off', FLOWSCOPE_HTTP_PORT: String(httpPort), FLOWSCOPE_FLOW_PORTS: String(flowPort), FLOWSCOPE_BIND: '127.0.0.1', FLOWSCOPE_FLOW_BIND: '127.0.0.1', FLOWSCOPE_LOG_LEVEL: 'warn', FLOWSCOPE_DEMO: '' } as NodeJS.ProcessEnv);
  cfg.dataDir = dir;
  process.env.FLOWSCOPE_ADMIN_PASSWORD = ADMIN_PW;
  const app = await App.create(cfg);
  app.log.quiet = true;
  await app.start();
  const base = `http://127.0.0.1:${httpPort}`;
  try {
    assert.equal((await call(base, '', '/api/overview')).status, 401, 'sign-in is required');
    await fn(app, base, await login(base, 'admin', ADMIN_PW));
  } finally {
    await app.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
}


const send = (base: string, who: { cookie: string; csrf: string }, method: string, url: string, body?: unknown) =>
  fetch(base + url, { method, headers: { 'content-type': 'application/json', cookie: who.cookie, 'x-csrf-token': who.csrf }, body: body === undefined ? undefined : JSON.stringify(body) }).then(async r => { const t = await r.text(); return { status: r.status, json: (() => { try { return JSON.parse(t); } catch { return null; } })() as any }; });

const good = { enabled: true, preset: 'custom', directoryUrl: 'https://ca.corp.example/directory', email: 'ops@corp.example', tosAgreed: false, names: 'flowscope.corp.example, 10.0.0.5', challenge: 'http-01', httpPort: 80,
  dnsProvider: 'manual', dnsWaitSec: 30, cloudflareToken: 'cf-secret-token', eabKid: 'kid-1', eabHmac: 'hmac-secret-value', caPem: '', keyType: 'ecdsa-p256', autoRenew: true, renewDays: 30 };

test('ACME admin API: settings are saved, secrets are never returned, bad input is explained, and only administrators can use it', { timeout: 60_000 }, async () => {
  await withApp(async (app, base, admin) => {
    const r0 = await send(base, admin, 'GET', '/api/admin/acme');
    assert.equal(r0.status, 200);
    assert.equal(r0.json.config.enabled, false);
    assert.equal(r0.json.account.registered, false);

    const r1 = await send(base, admin, 'PUT', '/api/admin/acme', good);
    assert.equal(r1.status, 200, JSON.stringify(r1.json));
    assert.deepEqual(r1.json.config.names, ['flowscope.corp.example', '10.0.0.5']);
    assert.equal(r1.json.config.cloudflareTokenSet, true); assert.equal(r1.json.config.eabHmacSet, true);
    assert.ok(!JSON.stringify(r1.json).includes('cf-secret-token') && !JSON.stringify(r1.json).includes('hmac-secret-value'), 'secrets are not returned');
    const stored = app.cdb.db.prepare("SELECT value FROM settings WHERE key = 'acme'").get() as { value: string };
    assert.ok(!stored.value.includes('cf-secret-token') && !stored.value.includes('hmac-secret-value'), 'secrets are not stored in the clear');

    // leaving a secret out keeps it; null removes it
    const r2 = await send(base, admin, 'PUT', '/api/admin/acme', { ...good, cloudflareToken: undefined, eabHmac: null });
    assert.equal(r2.json.config.cloudflareTokenSet, true); assert.equal(r2.json.config.eabHmacSet, false);

    for (const [patch, text] of [
      [{ names: '' }, /at least one name/], [{ directoryUrl: 'http://ca.corp.example/directory' }, /https/], [{ preset: 'nonsense' }, /preset must be one of/],
      [{ challenge: 'tls-alpn-01' }, /challenge must be one of/], [{ email: 'not an email' }, /e-mail/], [{ caPem: 'junk' }, /root certificate/],
      [{ preset: 'letsencrypt', names: 'host.local', tosAgreed: true }, /public domain names/], [{ preset: 'letsencrypt', names: 'a.example.com', tosAgreed: false }, /terms of service/]
    ] as [object, RegExp][]) {
      const r = await send(base, admin, 'PUT', '/api/admin/acme', { ...good, ...patch });
      assert.equal(r.status, 400, JSON.stringify(patch)); assert.match(r.json.error ?? r.json.message ?? JSON.stringify(r.json), text);
    }
    // a bad save changed nothing
    assert.deepEqual((await send(base, admin, 'GET', '/api/admin/acme')).json.config.names, ['flowscope.corp.example', '10.0.0.5']);

    // with HTTPS switched off there is no certificate to manage
    const r3 = await send(base, admin, 'POST', '/api/admin/acme/issue');
    assert.equal(r3.status, 400); assert.match(JSON.stringify(r3.json), /switched off/);
    assert.equal((await send(base, admin, 'POST', '/api/admin/acme/cancel')).status, 200);

    // a read-only user cannot see or change any of it
    const mk = await send(base, admin, 'POST', '/api/admin/users', { username: 'viewer', password: 'Lorem-ipsum-ro-1', role: 'ro', mustChange: false });
    assert.equal(mk.status, 201, JSON.stringify(mk.json));
    const ro = await login(base, 'viewer', 'Lorem-ipsum-ro-1');
    for (const [m, u] of [['GET', '/api/admin/acme'], ['PUT', '/api/admin/acme'], ['POST', '/api/admin/acme/issue'], ['POST', '/api/admin/acme/continue'], ['POST', '/api/admin/acme/cancel']] as const) assert.equal((await send(base, ro, m, u, m === 'PUT' ? good : undefined)).status, 403, `${m} ${u}`);
  });
});

test('ACME challenges are answered on the console\'s plain-HTTP listener without signing in, only while a token is open', { timeout: 60_000 }, async () => {
  await withApp(async (app, base) => {
    const tokens = (app.acme as unknown as { tokens: Map<string, string> }).tokens;
    const url = '/.well-known/acme-challenge/abc_DEF-1';
    const body = async (u: string) => (await fetch(base + u)).text();
    assert.notEqual(await body(url), 'abc_DEF-1.thumbprint', 'nothing is served while no challenge is open');
    tokens.set('abc_DEF-1', 'abc_DEF-1.thumbprint');
    const r = await fetch(base + url);
    assert.equal(r.status, 200); assert.equal(await r.text(), 'abc_DEF-1.thumbprint');
    assert.match(r.headers.get('content-type') ?? '', /text\/plain/);
    // a token that is not open is not answered, and the token list cannot be reached by other paths
    assert.notEqual(await body('/.well-known/acme-challenge/other'), 'abc_DEF-1.thumbprint');
    assert.notEqual(await body('/.well-known/acme-challenge/abc_DEF-1/extra'), 'abc_DEF-1.thumbprint');
    assert.notEqual(await body('/.well-known/acme-challenge/abc_DEF-1?x=1&y'), '', 'a query string does not break the lookup');
    tokens.clear();
    assert.notEqual(await body(url), 'abc_DEF-1.thumbprint');
  });
});
