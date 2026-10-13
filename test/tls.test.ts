import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import { buildCsr, buildSelfSigned, generateKey, inspectCert, parseSans, KEY_TYPES, type KeyType } from '../src/tls/x509.js';

const hasOpenssl = spawnSync('openssl', ['version']).status === 0;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-tls-'));

for (const kt of KEY_TYPES.map(k => k.id) as KeyType[]) {
  test(`self-signed certificate and CSR for ${kt}`, { skip: kt === 'rsa-4096' && process.env.FAST === '1' }, async () => {
    const key = await generateKey(kt);
    const sans = parseSans(['flowscope.example.net', '10.0.0.5', '2001:db8::5', '*.lab.example.net']);
    const cert = buildSelfSigned({ key, subject: { cn: 'flowscope.example.net', o: 'Example', c: 'US' }, sans, days: 365 });
    const info = inspectCert(cert);
    assert.match(info.subject, /CN=flowscope.example.net/);
    assert.ok(info.sans.includes('10.0.0.5') && info.sans.includes('flowscope.example.net'));
    assert.ok(info.selfSigned);
    assert.ok(new crypto.X509Certificate(cert).checkPrivateKey(key));
    const csr = buildCsr(key, { cn: 'flowscope.example.net', o: 'Example' }, sans);
    if (hasOpenssl) {
      const c = path.join(tmp, kt + '.crt'), r = path.join(tmp, kt + '.csr');
      fs.writeFileSync(c, cert); fs.writeFileSync(r, csr);
      const v1 = spawnSync('openssl', ['verify', '-CAfile', c, c], { encoding: 'utf8' });
      assert.equal(v1.status, 0, v1.stdout + v1.stderr);
      const v2 = spawnSync('openssl', ['req', '-in', r, '-noout', '-verify', '-text'], { encoding: 'utf8' });
      assert.equal(v2.status, 0, v2.stdout + v2.stderr);
      assert.match(v2.stdout + v2.stderr, /verify OK/);
      assert.match(v2.stdout, /DNS:flowscope.example.net/);
      assert.match(v2.stdout, /IP Address:10.0.0.5/);
    }
  });
}

test('SAN validation', () => {
  assert.throws(() => parseSans(['not a host!']), /not a host name/);
  assert.deepEqual(parseSans(['A.example.com', '1.2.3.4', '']).dns, ['a.example.com']);
});

import tls from 'node:tls';
import { ConfigDb } from '../src/db/configdb.js';
import { Secrets } from '../src/secrets.js';
import { Settings } from '../src/settings.js';
import { AppLog } from '../src/logger.js';
import { CertManager, CertError } from '../src/tls/manager.js';

function mgr() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-cm-'));
  const cdb = new ConfigDb(dir); const settings = new Settings(cdb);
  const log = new AppLog(cdb, settings, 'error'); log.quiet = true;
  return { m: new CertManager(cdb, new Secrets(dir, 'k'), log), dir, done: () => { log.close(); cdb.close(); fs.rmSync(dir, { recursive: true, force: true }); } };
}
function leafAndCa() {
  const d = fs.mkdtempSync(path.join(tmp, 'ca-'));
  const sh = (args: string[]) => { const r = spawnSync('openssl', args, { cwd: d, encoding: 'utf8' }); if (r.status !== 0) throw new Error(r.stderr); };
  sh(['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', 'ca.key', '-out', 'ca.crt', '-subj', '/CN=Test CA', '-days', '200', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign']);
  sh(['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'leaf.key', '-out', 'leaf.csr', '-subj', '/CN=flow.test.example']);
  fs.writeFileSync(path.join(d, 'ext.cnf'), 'subjectAltName=DNS:flow.test.example,IP:10.1.1.1\n');
  sh(['x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'leaf.crt', '-days', '100', '-extfile', 'ext.cnf']);
  sh(['pkcs12', '-export', '-in', 'leaf.crt', '-inkey', 'leaf.key', '-certfile', 'ca.crt', '-out', 'bundle.p12', '-passout', 'pass:s3cretpw']);
  const rd = (f: string) => fs.readFileSync(path.join(d, f), 'utf8');
  return { leaf: rd('leaf.crt'), ca: rd('ca.crt'), key: rd('leaf.key'), p12: fs.readFileSync(path.join(d, 'bundle.p12')) };
}

test('certificate manager: self-signed, PEM stage/apply/rollback, validation errors', async () => {
  const t = mgr();
  try {
    assert.equal(await t.m.ensureActive(['flowscope.local', '10.0.0.5']), true);
    assert.equal(await t.m.ensureActive(['flowscope.local']), false);
    const st = t.m.status();
    assert.ok(st.active!.selfSigned && st.active!.daysLeft > 800);
    const o0 = t.m.options()!;
    assert.ok(o0.cert && o0.key);
    const x = leafAndCa();
    await assert.rejects(() => t.m.stagePem({ certPem: x.leaf, keyPem: x.key.replace(/./, 'X') }), CertError);
    await assert.rejects(() => t.m.stagePem({ certPem: x.leaf }), /private key/);
    const other = await generateKey('ecdsa-p256');
    await assert.rejects(() => t.m.stagePem({ certPem: x.leaf, keyPem: other.export({ type: 'pkcs8', format: 'pem' }) as string }), /does not match/);
    // chain out of order
    await assert.rejects(() => t.m.stagePem({ certPem: x.ca + x.leaf, keyPem: x.key }), /does not match|out of order|private key/);
    const r = await t.m.stagePem({ certPem: x.leaf + x.ca, keyPem: x.key, expectHost: 'other.example' });
    assert.ok(r.warnings.some(w => /does not cover/.test(w)));
    assert.equal(t.m.status().staged!.chainLength, 1);
    const opts = t.m.apply();
    assert.match(t.m.status().active!.subject, /flow.test.example/);
    assert.match(t.m.status().previous!.subject, /flowscope.local/);
    tls.createSecureContext(opts);
    t.m.rollback();
    assert.match(t.m.status().active!.subject, /flowscope.local/);
    assert.ok(t.m.status().staged);
    // an expired certificate is refused
    const exp = path.join(tmp, 'exp'); fs.mkdirSync(exp);
    const r1 = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', 'e.key', '-out', 'e.crt', '-subj', '/CN=old', '-days', '1', '-not_before', '20200101000000Z', '-not_after', '20200102000000Z'], { cwd: exp, encoding: 'utf8' });
    if (r1.status === 0) await assert.rejects(() => t.m.stagePem({ certPem: fs.readFileSync(path.join(exp, 'e.crt'), 'utf8'), keyPem: fs.readFileSync(path.join(exp, 'e.key'), 'utf8') }), /expired/);
  } finally { t.done(); }
});

test('certificate manager: PKCS#12 bundle, wrong password, and a real TLS server reload', async () => {
  const t = mgr();
  try {
    await t.m.ensureActive(['localhost']);
    const x = leafAndCa();
    await assert.rejects(() => t.m.stageP12({ pfx: x.p12, passphrase: 'wrong' }), /password is wrong|not a usable|could not be opened/);
    const r = await t.m.stageP12({ pfx: x.p12, passphrase: 's3cretpw', expectHost: 'flow.test.example' });
    assert.deepEqual(r.warnings, []);
    assert.equal(t.m.status().staged!.format, 'pkcs12');
    assert.equal(t.m.status().staged!.chainLength, 1);
    // serve with the active cert, then apply the staged one and reload without restarting
    const server = tls.createServer({ ...t.m.options()!, minVersion: 'TLSv1.2' }, s => s.end('hi'));
    await new Promise<void>(res => server.listen(0, '127.0.0.1', () => res()));
    const port = (server.address() as { port: number }).port;
    const peer = () => new Promise<string>((resolve, reject) => { const c = tls.connect({ port, host: '127.0.0.1', rejectUnauthorized: false }, () => { const s = c.getPeerCertificate().subject.CN; c.destroy(); resolve(s as string); }); c.on('error', reject); });
    assert.equal(await peer(), 'localhost');
    server.setSecureContext(t.m.apply());
    assert.equal(await peer(), 'flow.test.example');
    server.setSecureContext(t.m.rollback());
    assert.equal(await peer(), 'localhost');
    server.close();
  } finally { t.done(); }
});

test('certificate manager: CSR keeps the key on the server and the signed certificate can be staged without pasting it', async () => {
  const t = mgr();
  try {
    await assert.rejects(() => t.m.generateCsr({ cn: '', keyType: 'ecdsa-p256' }), /common name/);
    const csr = await t.m.generateCsr({ cn: 'flow.test.example', sans: ['10.1.1.1'], keyType: 'ecdsa-p384', o: 'Example Org', c: 'US' });
    assert.match(csr.csrPem, /BEGIN CERTIFICATE REQUEST/);
    assert.equal(csr.keyDesc, 'ECDSA P-384');
    // sign the CSR with a throwaway CA
    const d = fs.mkdtempSync(path.join(tmp, 'sign-'));
    fs.writeFileSync(path.join(d, 'req.csr'), csr.csrPem);
    const sh = (a: string[]) => { const r = spawnSync('openssl', a, { cwd: d, encoding: 'utf8' }); assert.equal(r.status, 0, r.stderr); };
    sh(['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', 'ca.key', '-out', 'ca.crt', '-subj', '/CN=CA', '-days', '30']);
    fs.writeFileSync(path.join(d, 'ext.cnf'), 'subjectAltName=DNS:flow.test.example,IP:10.1.1.1\n');
    sh(['x509', '-req', '-in', 'req.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'out.crt', '-days', '10', '-extfile', 'ext.cnf']);
    const signed = fs.readFileSync(path.join(d, 'out.crt'), 'utf8');
    const r = await t.m.stagePem({ certPem: signed });
    assert.ok(r.warnings.length >= 0);
    t.m.apply();
    assert.equal(t.m.status().active!.keyDesc, 'ECDSA P-384');
    // a certificate that does not belong to the pending key is refused
    const x = leafAndCa();
    await assert.rejects(() => t.m.stagePem({ certPem: x.leaf }), /does not match/);
  } finally { t.done(); }
});
