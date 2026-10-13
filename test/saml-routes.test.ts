import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import dgram from 'node:dgram';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { App } from '../src/app.js';
import { SamlState } from '../src/auth/saml/saml.js';
import { loadConfig } from '../src/config.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const saml = JSON.parse(fs.readFileSync(path.join(here, '..', '..', 'test', 'fixtures', 'saml.json'), 'utf8')) as { acs: string; sp: string; idp: string; req: string; rsaCert: string; cases: Record<string, { xml: string }> };
const freePort = () => new Promise<number>(res => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = (s.address() as net.AddressInfo).port; s.close(() => res(p)); }); });
const freeUdp = () => new Promise<number>(res => { const s = dgram.createSocket('udp4'); s.bind(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); }); });

test('SAML sign-in through the HTTP server', { timeout: 60_000 }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-saml-'));
  const httpPort = await freePort(), flowPort = await freeUdp();
  const cfg = loadConfig({ FLOWSCOPE_TLS: 'off', FLOWSCOPE_HTTP_PORT: String(httpPort), FLOWSCOPE_FLOW_PORTS: String(flowPort), FLOWSCOPE_BIND: '127.0.0.1', FLOWSCOPE_FLOW_BIND: '127.0.0.1', FLOWSCOPE_LOG_LEVEL: 'error', FLOWSCOPE_MASTER_KEY: 'test-key', FLOWSCOPE_PUBLIC_URL: 'https://fs.example.com' });
  cfg.dataDir = dir;
  process.env.FLOWSCOPE_ADMIN_PASSWORD = 'admin-test-passphrase-1';
  const app = await App.create(cfg);
  await app.start();
  const base = `http://127.0.0.1:${httpPort}`;
  try {
    // not turned on yet
    assert.equal((await fetch(base + '/api/auth/saml/login', { redirect: 'manual' })).status, 404);
    const a = structuredClone(app.settings.get('aaa'));
    a.services.web = 'saml';
    a.saml = { ...a.saml, idpEntity: saml.idp, idpSso: 'https://idp.example.com/sso', idpCert: saml.rsaCert, nameAttr: 'email', groupAttr: 'groups', sp: saml.sp };
    a.map.saml = { admin: 'netadmins', snmp: '', ro: 'staff' };
    app.settings.set('aaa', a);

    const login = await fetch(base + '/api/auth/saml/login', { redirect: 'manual' });
    assert.equal(login.status, 302);
    const loc = new URL(login.headers.get('location')!);
    assert.equal(loc.origin + loc.pathname, 'https://idp.example.com/sso');
    const req = zlib.inflateRawSync(Buffer.from(loc.searchParams.get('SAMLRequest')!, 'base64')).toString();
    assert.match(req, new RegExp(`AssertionConsumerServiceURL="${saml.acs}"`));
    assert.match(req, new RegExp(`<saml:Issuer>${saml.sp}</saml:Issuer>`));

    const acs = (xml: string) => fetch(base + '/api/auth/saml/acs', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ SAMLResponse: Buffer.from(xml).toString('base64') }).toString(), redirect: 'manual' });

    // a response to a request this server never made
    let r = await acs(saml.cases.rsa_assertion.xml);
    assert.equal(r.status, 401); assert.match(await r.text(), /not for this server|request that was not made here/);
    // unsigned
    app.saml.adopt(saml.req);
    r = await acs(saml.cases.unsigned.xml);
    assert.equal(r.status, 401); assert.match(await r.text(), /not signed/);
    // good
    r = await acs(saml.cases.rsa_assertion.xml);
    assert.equal(r.status, 302, await r.clone().text());
    const cookie = /fs_sid=([^;]+)/.exec(r.headers.get('set-cookie') || '')?.[1];
    assert.ok(cookie);
    const me = await (await fetch(base + '/api/auth/me', { headers: { cookie: 'fs_sid=' + cookie } })).json() as { username: string; role: string; source: string };
    assert.equal(me.username, 'jacob@example.com'); assert.equal(me.role, 'admin'); assert.equal(me.source, 'saml');
    // replay of the same response
    app.saml.adopt(saml.req);
    r = await acs(saml.cases.rsa_assertion.xml);
    assert.equal(r.status, 401); assert.match(await r.text(), /already used/);
    // metadata is public and carries the ACS URL
    const md = await (await fetch(base + '/api/auth/saml/metadata')).text();
    assert.match(md, /Location="https:\/\/fs\.example\.com\/api\/auth\/saml\/acs"/);
    // unmapped groups are refused
    a.map.saml = { admin: 'nobody', snmp: '', ro: '' }; a.def.saml = 'deny'; app.settings.set('aaa', a);
    app.saml = new SamlState(); app.saml.adopt(saml.req);
    r = await acs(saml.cases.rsa_response.xml);
    assert.equal(r.status, 403); assert.match(await r.text(), /none of your groups maps/);
  } finally {
    await app.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
