import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import crypto from 'node:crypto';
import { ConfigDb } from '../src/db/configdb.js';
import { Settings } from '../src/settings.js';
import { Secrets } from '../src/secrets.js';
import { AppLog } from '../src/logger.js';
import { CertManager } from '../src/tls/manager.js';
import { AcmeService, resolveConfig, type AcmeConfig, type AcmeDeps } from '../src/tls/acme_service.js';
import { MockAcme } from './acme_mock.js';

const freePort = () => new Promise<number>(res => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = (s.address() as net.AddressInfo).port; s.close(() => res(p)); }); });
const DAY = 86400_000;

interface Rig { ca: MockAcme; svc: AcmeService; settings: Settings; certs: CertManager; installs: { chain: string; key: string; apply: boolean }[]; applied: number; logs: string[]; deps: AcmeDeps; httpPort: number; active: { notBefore: number; notAfter: number; fingerprint: string; selfSigned: boolean } | null | 'real' }

async function rig(fn: (r: Rig) => Promise<void>, extra: Partial<AcmeDeps> = {}): Promise<void> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-acme-'));
  const ca = new MockAcme(); await ca.start();
  const cdb = new ConfigDb(dir), settings = new Settings(cdb), secrets = new Secrets(dir), log = new AppLog(cdb, settings, 'info'); log.quiet = true;
  const certs = new CertManager(cdb, secrets, log);
  const httpPort = await freePort(); ca.httpPort = httpPort;
  const logs: string[] = [];
  for (const k of ['info', 'warn', 'error'] as const) { const orig = log[k].bind(log); (log as any)[k] = (s: string, m: string, u?: string) => { logs.push(`${k}: ${m}`); orig(s, m, u); }; }
  const r = { ca, settings, certs, installs: [] as Rig['installs'], applied: 0, logs, httpPort, active: 'real' } as Rig;
  r.deps = {
    settings, secrets, log, bind: '127.0.0.1', httpPort: () => undefined, directoryOverride: undefined, pollMs: 10, maxPolls: 200, cloudflareBase: ca.cloudflare,
    install: async (chain, key, apply) => { r.installs.push({ chain, key, apply }); await certs.stagePem({ certPem: chain, keyPem: key }); if (apply) { certs.apply(); r.applied++; } },
    active: () => { if (r.active !== 'real') return r.active; const a = certs.status().active; return a ? { notBefore: a.notBefore, notAfter: a.notAfter, fingerprint: a.fingerprint, selfSigned: a.selfSigned } : null; },
    ...extra
  };
  r.svc = new AcmeService(r.deps);
  try { await fn(r); } finally { await ca.stop(); log.close(); cdb.close(); fs.rmSync(dir, { recursive: true, force: true }); }
}

const base = (r: Rig, over: Partial<Parameters<AcmeService['configure']>[0]> = {}): Parameters<AcmeService['configure']>[0] =>
  ({ enabled: true, preset: 'custom', directoryUrl: r.ca.directory, email: 'ops@example.test', names: ['localhost'], challenge: 'http-01', httpPort: r.httpPort, keyType: 'ecdsa-p256', autoRenew: true, renewDays: 30, ...over });

test('HTTP-01 with an internal CA: registers, answers the challenge on a temporary port, installs the certificate', { timeout: 30_000 }, async () => {
  await rig(async r => {
    r.svc.configure(base(r));
    await r.svc.issue();
    assert.equal(r.ca.newAccounts, 1);
    assert.equal(r.installs.length, 1);
    assert.equal(r.installs[0]!.apply, true);
    const leaf = new crypto.X509Certificate(r.installs[0]!.chain);
    assert.ok(leaf.checkHost('localhost'), 'the certificate covers the name');
    assert.ok(leaf.checkPrivateKey(crypto.createPrivateKey(r.installs[0]!.key)), 'the key belongs to the certificate');
    const st = r.svc.status();
    assert.equal(st.state.lastError, null);
    assert.equal(st.managed, true, 'the certificate in use is the one from the CA');
    assert.equal(st.account.registered, true);
    assert.equal(r.certs.status().active?.chainLength, 1, 'the CA certificate came with it');
    assert.match(r.certs.status().active!.issuer, /Test ACME CA/);
    // the temporary listener is gone and the token cannot be fetched any more
    await new Promise(res => setTimeout(res, 50));
    await assert.rejects(fetch(`http://127.0.0.1:${r.httpPort}/.well-known/acme-challenge/x`));
    assert.equal(r.svc.challengeBody('anything'), undefined);
  });
});

test('an IP address can be certified with HTTP-01 and ends up in the certificate', { timeout: 30_000 }, async () => {
  await rig(async r => {
    r.svc.configure(base(r, { names: ['127.0.0.1', 'localhost'] }));
    await r.svc.issue();
    const leaf = new crypto.X509Certificate(r.installs[0]!.chain);
    assert.ok(leaf.checkIP('127.0.0.1'));
    assert.ok(leaf.checkHost('localhost'));
  });
});

test('the account is registered once and reused; a different CA gets its own account', { timeout: 30_000 }, async () => {
  await rig(async r => {
    r.svc.configure(base(r));
    await r.svc.issue(); await r.svc.issue();
    assert.equal(r.ca.newAccounts, 1);
    const second = new MockAcme(); await second.start(); second.httpPort = r.httpPort;
    try {
      r.svc.configure(base(r, { directoryUrl: second.directory }));
      await r.svc.issue();
      assert.equal(second.newAccounts, 1);
    } finally { await second.stop(); }
  });
});

test('a CA that has forgotten the account gets a new one registered', { timeout: 30_000 }, async () => {
  await rig(async r => {
    r.svc.configure(base(r));
    await r.svc.issue();
    (r.ca as any).accounts.clear();
    await r.svc.issue();
    assert.equal(r.ca.newAccounts, 2);
    assert.equal(r.installs.length, 2);
  });
});

test('a stale nonce is refreshed and the request repeated', { timeout: 30_000 }, async () => {
  await rig(async r => {
    r.svc.configure(base(r));
    r.ca.badNonceOnce = true;
    await r.svc.issue();
    assert.equal(r.installs.length, 1);
  });
});

test('external account binding: needed by the CA, so a missing or wrong key is explained and the right one works', { timeout: 30_000 }, async () => {
  await rig(async r => {
    r.ca.requireEab = { kid: 'kid-123', hmac: crypto.randomBytes(32) };
    r.svc.configure(base(r));
    await assert.rejects(r.svc.issue(), /external account/i);
    r.svc.configure(base(r, { eabKid: 'kid-123', eabHmac: crypto.randomBytes(32).toString('base64url') }));
    await assert.rejects(r.svc.issue(), /external account binding failed/i);
    r.svc.configure(base(r, { eabKid: 'kid-123', eabHmac: r.ca.requireEab.hmac.toString('base64url') }));
    await r.svc.issue();
    assert.equal(r.installs.length, 1);
    assert.equal(r.svc.status().config.eabHmacSet, true);
    assert.ok(!JSON.stringify(r.svc.status()).includes(r.ca.requireEab.hmac.toString('base64url')), 'the secret is never returned');
  });
});

test('DNS-01 with Cloudflare: adds the TXT records, waits, cleans up, and handles a wildcard', { timeout: 30_000 }, async () => {
  await rig(async r => {
    r.svc.configure(base(r, { names: ['*.example.test', 'example.test'], challenge: 'dns-01', dns: { provider: 'cloudflare', waitSec: 0 }, cloudflareToken: 'cf-token' }));
    await r.svc.issue();
    const leaf = new crypto.X509Certificate(r.installs[0]!.chain);
    assert.ok(leaf.checkHost('example.test'));
    assert.ok(leaf.checkHost('www.example.test'), 'the wildcard covers other names');
    assert.equal(r.ca.cfRecords.size, 0, 'the TXT records were removed again');
    assert.ok(r.ca.cfCalls.some(c => c.startsWith('POST /zones/zone1/dns_records')));
    assert.equal(r.svc.status().config.cloudflareTokenSet, true);
    assert.ok(!JSON.stringify(r.svc.status()).includes('cf-token'));
  });
});

test('DNS-01 with Cloudflare: a wrong token or an unknown zone is explained, and no record is left behind', { timeout: 30_000 }, async () => {
  await rig(async r => {
    r.svc.configure(base(r, { names: ['example.test'], challenge: 'dns-01', dns: { provider: 'cloudflare', waitSec: 0 }, cloudflareToken: 'wrong' }));
    await assert.rejects(r.svc.issue(), /did not accept the API token/);
    r.svc.configure(base(r, { names: ['other.invalid'], challenge: 'dns-01', dns: { provider: 'cloudflare', waitSec: 0 }, cloudflareToken: 'cf-token' }));
    await assert.rejects(r.svc.issue(), /no zone for other.invalid/);
    assert.equal(r.ca.cfRecords.size, 0);
  });
});

test('DNS-01 with manual records: shows what to add, waits, then finishes when asked to continue', { timeout: 30_000 }, async () => {
  await rig(async r => {
    r.svc.configure(base(r, { names: ['flow.example.test'], challenge: 'dns-01', dns: { provider: 'manual', waitSec: 0 } }));
    await r.svc.issue();
    const st = r.svc.status();
    assert.equal(r.installs.length, 0);
    assert.deepEqual(st.pending!.records.map(x => x.name), ['_acme-challenge.flow.example.test']);
    assert.match(st.pending!.records[0]!.value, /^[A-Za-z0-9_-]{43}$/, 'a SHA-256 digest, base64url');
    await assert.rejects(r.svc.issue(), /waiting for DNS records/);
    r.ca.txt.set('_acme-challenge.flow.example.test', new Set([st.pending!.records[0]!.value]));
    await r.svc.proceed();
    assert.equal(r.installs.length, 1);
    assert.equal(r.svc.status().pending, null);
    assert.equal(r.svc.status().running, false);
  });
});

test('DNS-01 with manual records: continuing before the records exist fails with the CA\'s reason and a retry is possible; cancel clears the request', { timeout: 30_000 }, async () => {
  await rig(async r => {
    r.svc.configure(base(r, { names: ['flow.example.test'], challenge: 'dns-01', dns: { provider: 'manual', waitSec: 0 } }));
    await r.svc.issue();
    await assert.rejects(r.svc.proceed(), /could not verify flow.example.test.*No TXT record/s);
    const st = r.svc.status();
    assert.match(st.state.lastError!, /No TXT record/);
    assert.ok(st.state.nextAttemptAt! > Date.now(), 'automatic retries wait');
    assert.equal(st.running, false); assert.equal(st.pending, null);
    await r.svc.issue(); assert.ok(r.svc.status().pending);
    r.svc.cancel();
    assert.equal(r.svc.status().pending, null); assert.equal(r.svc.status().running, false);
  });
});

test('a failed HTTP-01 check reports what the CA saw, and a busy port is explained', { timeout: 30_000 }, async () => {
  await rig(async r => {
    r.svc.configure(base(r));
    r.ca.httpPort = await freePort();   // the CA looks somewhere nobody is listening
    await assert.rejects(r.svc.issue(), /could not verify localhost.*Could not connect/s);
    const blocker = net.createServer(); await new Promise<void>(res => blocker.listen(r.httpPort, '127.0.0.1', () => res()));
    try { await assert.rejects(r.svc.issue(), /Port \d+ is already used by another program/); } finally { blocker.close(); }
  });
});

test('when the console\'s own HTTP port is the one configured, no second listener is opened', { timeout: 30_000 }, async () => {
  await rig(async r => {
    // stand in for the console: serve the token the service has open on the configured port
    const svc = r.svc;
    const own = (await import('node:http')).createServer((q, s) => { const m = /acme-challenge\/([\w-]+)/.exec(q.url || ''); const b = m ? svc.challengeBody(m[1]!) : undefined; s.writeHead(b === undefined ? 404 : 200); s.end(b); });
    await new Promise<void>(res => own.listen(r.httpPort, '127.0.0.1', () => res()));
    r.deps.httpPort = () => r.httpPort;
    try { svc.configure(base(r)); await svc.issue(); assert.equal(r.installs.length, 1); } finally { own.close(); }
  });
});

test('a testing CA (Let\'s Encrypt staging) gets its certificate staged but never applied', { timeout: 30_000 }, async () => {
  await rig(async r => {
    r.deps.directoryOverride = r.ca.directory;
    r.svc.configure(base(r, { preset: 'letsencrypt-staging', tosAgreed: true, names: ['example.test'], challenge: 'dns-01', dns: { provider: 'cloudflare', waitSec: 0 }, cloudflareToken: 'cf-token' }));
    await r.svc.issue();
    assert.equal(r.installs[0]!.apply, false);
    assert.equal(r.applied, 0);
    const st = r.svc.status();
    assert.equal(st.managed, false);
    assert.match(st.state.note!, /not applied/);
    assert.ok(r.certs.status().staged, 'it is staged for inspection');
    assert.equal(r.certs.status().active, null);
  });
});

test('settings are checked before anything is sent', () => {
  const ok: AcmeConfig = { enabled: true, preset: 'letsencrypt', directoryUrl: '', email: '', tosAgreed: true, names: ['flow.example.com'], challenge: 'http-01', httpPort: 80, dns: { provider: 'manual', cloudflareTokenEnc: '', waitSec: 30 }, eabKid: '', eabHmacEnc: '', caPem: '', keyType: 'ecdsa-p256', autoRenew: true, renewDays: 30 };
  assert.equal(resolveConfig(ok).trusted, true);
  assert.equal(resolveConfig({ ...ok, preset: 'letsencrypt-staging' }).trusted, false);
  assert.throws(() => resolveConfig({ ...ok, names: [] }), /at least one name/);
  assert.throws(() => resolveConfig({ ...ok, tosAgreed: false }), /terms of service/);
  assert.throws(() => resolveConfig({ ...ok, names: ['flowscope.local'] }), /public domain names you own/);
  assert.throws(() => resolveConfig({ ...ok, names: ['flowscope'] }), /public domain names you own/);
  assert.throws(() => resolveConfig({ ...ok, names: ['10.0.0.5'] }), /IP addresses/);
  assert.throws(() => resolveConfig({ ...ok, names: ['*.example.com'] }), /only be verified with DNS-01/);
  assert.throws(() => resolveConfig({ ...ok, challenge: 'dns-01', dns: { ...ok.dns, provider: 'cloudflare' }, names: ['a.example.com'] }), /Cloudflare API token/);
  assert.throws(() => resolveConfig({ ...ok, preset: 'custom', directoryUrl: '' }), /address of the ACME directory/);
  assert.throws(() => resolveConfig({ ...ok, preset: 'custom', directoryUrl: 'http://ca.corp.example/directory' }), /must be an https/);
  assert.doesNotThrow(() => resolveConfig({ ...ok, preset: 'custom', directoryUrl: 'http://127.0.0.1:9000/directory', names: ['flowscope.corp.lan', '10.0.0.5'] }));
  assert.throws(() => resolveConfig({ ...ok, preset: 'custom', directoryUrl: 'https://ca.corp.example/directory', caPem: 'not a certificate' }), /root certificate/);
  assert.throws(() => resolveConfig({ ...ok, preset: 'custom', directoryUrl: 'https://ca.corp.example/directory', challenge: 'dns-01', names: ['10.0.0.5'] }), /IP address can only/);
});

test('renewal: first request, a renewal window of a third of the life, changed names, backoff, and manual DNS that cannot renew by itself', { timeout: 30_000 }, async () => {
  await rig(async r => {
    const now = Date.now();
    r.svc.configure(base(r));
    // 1. a self-signed certificate is in use: ask the CA
    r.active = { notBefore: now - DAY, notAfter: now + 800 * DAY, fingerprint: 'self', selfSigned: true };
    assert.equal(await r.svc.tick(now), true);
    const fp = r.svc.status().state.fingerprint!; assert.ok(fp);
    // 2. the certificate is ours and young: nothing to do
    r.active = { notBefore: now - DAY, notAfter: now + 89 * DAY, fingerprint: fp, selfSigned: false };
    assert.equal(await r.svc.tick(now), false);
    // 3. inside the window (30 days left of 90): renew
    r.active = { notBefore: now - 60 * DAY, notAfter: now + 29 * DAY, fingerprint: fp, selfSigned: false };
    assert.equal(await r.svc.tick(now), true);
    // 4. a short-lived certificate (6 days) renews when a third is left, not when 30 days are
    const cur = (): string => r.svc.status().state.fingerprint!;   // every renewal replaces the certificate, so its fingerprint changes
    const short = { notBefore: now - 4 * DAY, notAfter: now + 2 * DAY, fingerprint: cur(), selfSigned: false };
    r.active = { ...short, notAfter: now + 3 * DAY, notBefore: now - 3 * DAY };   // 3 of 6 days left: not yet
    assert.equal(await r.svc.tick(now), false);
    r.active = short;                                                              // 2 of 6 days left: now
    assert.equal(await r.svc.tick(now), true);
    // 5. someone else's certificate is left alone
    r.active = { notBefore: now - 60 * DAY, notAfter: now + 5 * DAY, fingerprint: 'uploaded-by-hand', selfSigned: false };
    assert.equal(await r.svc.tick(now), false);
    // 6. the names changed
    const fp2 = cur();
    r.active = { notBefore: now - DAY, notAfter: now + 89 * DAY, fingerprint: fp2, selfSigned: false };
    r.svc.configure(base(r, { names: ['localhost', '127.0.0.1'] }));
    assert.equal(await r.svc.tick(now), true);
    // 7. a failure backs off for hours, then tries again
    r.active = { notBefore: now - DAY, notAfter: now + 800 * DAY, fingerprint: 'self', selfSigned: true };
    r.ca.httpPort = await freePort();
    assert.equal(await r.svc.tick(now), false);                                    // ran and failed
    assert.ok(r.svc.status().state.lastError);
    r.ca.httpPort = r.httpPort;
    assert.equal(await r.svc.tick(now + 3600_000), false, 'still backing off after an hour');
    assert.equal(await r.svc.tick(now + 7 * 3600_000), true, 'tries again after six hours');
    // 8. switched off, or auto-renew off
    r.active = { notBefore: now - DAY, notAfter: now + 800 * DAY, fingerprint: 'self', selfSigned: true };
    r.svc.configure(base(r, { autoRenew: false })); assert.equal(await r.svc.tick(now + 99 * DAY), false);
    r.svc.configure({ ...base(r), enabled: false }); assert.equal(await r.svc.tick(now + 99 * DAY), false);
    // 9. manual DNS cannot renew by itself; it says so
    r.svc.configure(base(r, { names: ['flow.example.test'], challenge: 'dns-01', dns: { provider: 'manual', waitSec: 0 }, autoRenew: true }));
    assert.equal(await r.svc.tick(now + 99 * DAY), false);
    assert.match(r.svc.status().state.note!, /manual records cannot renew by itself/);
  });
});

test('the real certificate manager can roll the new certificate back', { timeout: 30_000 }, async () => {
  await rig(async r => {
    await r.certs.makeSelfSigned(['localhost']);
    const selfFp = r.certs.status().active!.fingerprint;
    r.svc.configure(base(r));
    assert.equal(await r.svc.tick(), true, 'the self-signed certificate is replaced');
    assert.notEqual(r.certs.status().active!.fingerprint, selfFp);
    assert.equal(r.certs.status().previous!.fingerprint, selfFp);
  });
});
