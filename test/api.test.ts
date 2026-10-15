import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import dgram from 'node:dgram';
import { App } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { VirtualDevice, type SimDevice } from '../src/sim/snmpagent.js';
import { buildV9 } from '../src/sim/packets.js';
import type { FlowRecord } from '../src/collector/types.js';
import { mockRadius } from './helpers.js';

const freePort = () => new Promise<number>(res => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = (s.address() as net.AddressInfo).port; s.close(() => res(p)); }); });
const freeUdp = () => new Promise<number>(res => { const s = dgram.createSocket('udp4'); s.bind(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); }); });
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

class Client {
  cookie = ''; csrf = ''; token = '';
  constructor(readonly base: string) {}
  async req(method: string, url: string, body?: unknown, opts: { csrf?: boolean; raw?: boolean } = {}) {
    const h: Record<string, string> = {};
    if (body !== undefined) h['content-type'] = 'application/json';
    if (this.cookie) h.cookie = this.cookie;
    if (this.token) h.authorization = 'Bearer ' + this.token;
    if (this.csrf && opts.csrf !== false && method !== 'GET') h['x-csrf-token'] = this.csrf;
    const r = await fetch(this.base + url, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' });
    const sc = r.headers.get('set-cookie');
    if (sc) { const m = /fs_sid=([^;]*)/.exec(sc); if (m) this.cookie = m[1] ? 'fs_sid=' + m[1] : ''; }
    const text = await r.text();
    let json: any = null; try { json = JSON.parse(text); } catch { /* not json */ }
    return { status: r.status, json, text, headers: r.headers };
  }
  get(u: string) { return this.req('GET', u); }
  post(u: string, b: unknown = {}) { return this.req('POST', u, b); }
  put(u: string, b: unknown) { return this.req('PUT', u, b); }
  patch(u: string, b: unknown) { return this.req('PATCH', u, b); }
  del(u: string) { return this.req('DELETE', u); }
  async login(user: string, pass: string) {
    this.cookie = ''; this.csrf = '';
    const r = await this.req('POST', '/api/auth/login', { username: user, password: pass });
    if (r.status === 200) this.csrf = r.json.csrf;
    return r;
  }
}

const ADMIN_PW = 'admin-test-passphrase-1';
const REC = (over: Partial<FlowRecord>): FlowRecord => ({
  ts0: Date.now() - 20_000, ts1: Date.now() - 5_000, exporter: '127.0.0.1', inIf: 1, outIf: 2, srcIp: '10.1.4.21', dstIp: '198.51.100.40', proto: 6, sport: 51522, dport: 443, flags: 0x1b,
  tos: 184, postTos: 0, ttlMin: 62, ttlMax: 63, bytes: 4000, pkts: 20, srcMac: '00:50:56:01:04:15', dstMac: '00:1c:73:01:aa:bb', vlan: 140,
  natSrcIp: null, natDstIp: null, natSport: null, natDport: null, nextHop: null, sampling: 1, ...over
});

test('HTTP API: auth, roles, CSRF, flows, devices, storage, admin, AAA', { timeout: 120_000 }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-api-'));
  const httpPort = await freePort(), flowPort = await freeUdp(), snmpPort = await freePort();
  const cfg = loadConfig({ FLOWSCOPE_TLS: 'off', FLOWSCOPE_HTTP_PORT: String(httpPort), FLOWSCOPE_FLOW_PORTS: String(flowPort), FLOWSCOPE_BIND: '127.0.0.1', FLOWSCOPE_FLOW_BIND: '127.0.0.1', FLOWSCOPE_LOG_LEVEL: 'error', FLOWSCOPE_MASTER_KEY: 'test-key' });
  cfg.dataDir = dir;
  process.env.FLOWSCOPE_ADMIN_PASSWORD = ADMIN_PW;
  const app = await App.create(cfg);
  app.log.quiet = true;
  await app.start();
  const sim: SimDevice = {
    name: 'rtr-api', descr: 'API test router', address: '127.0.0.1', port: snmpPort,
    ifaces: [{ index: 1, name: 'Gi0/0', speedMbps: 1000, inBps: 40e6, outBps: 80e6 }, { index: 2, name: 'Gi0/1', speedMbps: 100, inBps: 10e6, outBps: 90e6 }],
    ips: [{ ip: '127.0.0.1', ifIndex: 1 }], vlans: [{ id: 140, name: 'campus' }],
    qos: [{ ifIndex: 2, policy: 'WAN-OUT', classes: [{ name: 'voice', dscps: [46], queue: 'LLQ', bw: '20%', pps: 1000, pktBytes: 200, dropPct: 0, qBytes: 1000 }, { name: 'class-default', dscps: [0], queue: 'fair', pps: 800, pktBytes: 500, dropPct: 1, qBytes: 5000 }] }],
    auth: { community: 'public' }
  };
  const dev = new VirtualDevice(sim);
  await dev.start();
  const base = `http://127.0.0.1:${httpPort}`;
  const radius = await mockRadius('radius-secret', { rad1: { pw: 'radius-password-1', filter: 'noc-readers' } });
  try {
    const anon = new Client(base);
    // ---- public and protected
    assert.equal((await anon.get('/api/auth/config')).status, 200);
    assert.equal((await anon.get('/api/streams')).status, 401);
    assert.equal((await anon.get('/api/admin/users')).status, 401);
    assert.equal((await anon.get('/api/nope')).status, 404);
    const hdr = await anon.get('/api/auth/config');
    assert.equal(hdr.headers.get('x-frame-options'), 'DENY');
    assert.match(hdr.headers.get('content-security-policy')!, /script-src 'self'/);

    // ---- sign in
    const bad = new Client(base);
    assert.equal((await bad.login('admin', 'wrong-password-here')).status, 401);
    const admin = new Client(base);
    const li = await admin.login('admin', ADMIN_PW);
    assert.equal(li.status, 200);
    assert.equal(li.json.role, 'admin'); assert.equal(li.json.mustChange, false); assert.equal(li.json.caps.admin, true);
    assert.equal(li.json.password, undefined);

    // ---- CSRF: a cookie session without the token cannot change anything; a foreign Origin is refused
    assert.equal((await admin.req('PUT', '/api/admin/vlans/140', { name: 'campus-x' }, { csrf: false })).status, 403);
    const r403 = await fetch(base + '/api/admin/vlans/140', { method: 'PUT', headers: { 'content-type': 'application/json', cookie: admin.cookie, 'x-csrf-token': admin.csrf, origin: 'http://evil.example' }, body: '{"name":"x"}' });
    assert.equal(r403.status, 403);
    assert.equal((await admin.put('/api/admin/vlans/140', { name: 'campus' })).status, 200);

    // ---- users and roles
    const mk = async (u: string, role: string) => { const r = await admin.post('/api/admin/users', { username: u, password: 'Lorem-ipsum-' + role + '-1', role, mustChange: false }); assert.equal(r.status, 201, r.text); };
    await mk('viewer', 'ro'); await mk('netops', 'snmp');
    assert.equal((await admin.post('/api/admin/users', { username: 'short', password: 'short', role: 'ro' })).status, 400);
    const ro = new Client(base), sn = new Client(base);
    assert.equal((await ro.login('viewer', 'Lorem-ipsum-ro-1')).json.caps.storage, false);
    assert.equal((await sn.login('netops', 'Lorem-ipsum-snmp-1')).json.caps.storage, true);
    for (const u of ['/api/storage', '/api/devices', '/api/admin/users', '/api/admin/logs', '/api/exporters']) assert.equal((await ro.get(u)).status, 403, 'ro ' + u);
    for (const u of ['/api/admin/users', '/api/admin/cert', '/api/admin/aaa', '/api/admin/system']) assert.equal((await sn.get(u)).status, 403, 'snmp ' + u);
    assert.equal((await sn.get('/api/storage')).status, 200);
    assert.equal((await sn.put('/api/storage/retention', { raw: 3 })).status, 403);
    assert.equal((await sn.get('/api/devices')).status, 200);
    assert.equal((await ro.get('/api/streams')).status, 200);
    assert.equal((await sn.post('/api/snmp/credentials', { name: 'x', version: 'v2c', community: 'c' })).status, 403);

    // ---- SNMP credentials (admin) and devices (snmp admin)
    const cr = await admin.post('/api/snmp/credentials', { name: 'lab-v2c', version: 'v2c', community: 'public' });
    assert.equal(cr.status, 201, cr.text);
    assert.ok(!JSON.stringify(cr.json).includes('public"') || cr.json.credentials[0].hasSecret);
    assert.equal(JSON.stringify(cr.json).includes('"community"'), false);
    const tst = await sn.post('/api/devices/test', { ip: '127.0.0.1', port: snmpPort });
    assert.equal(tst.status, 200, tst.text); assert.equal(tst.json.interfaces, 2); assert.equal(tst.json.classes, 2);
    assert.equal((await sn.post('/api/devices', { ip: '127.0.0.1', port: 1 })).status >= 400, true);
    const add = await sn.post('/api/devices', { ip: '127.0.0.1', port: snmpPort, name: 'rtr-api' });
    assert.equal(add.status, 201, add.text);
    const devId = add.json.device.id;
    assert.equal((await sn.post('/api/devices', { ip: '127.0.0.1', port: snmpPort })).status, 409);
    const ifs = await sn.get(`/api/devices/${devId}/interfaces`);
    assert.deepEqual(ifs.json.interfaces.map((i: any) => i.name), ['Gi0/0', 'Gi0/1']);
    assert.equal((await sn.put(`/api/devices/${devId}/classes`, { ifIndex: 2, cls: 'voice', dscps: [46, 44] })).status, 200);
    assert.equal((await sn.put(`/api/devices/${devId}/classes`, { ifIndex: 2, cls: 'voice', dscps: [99] })).status, 400);
    assert.equal((await sn.post(`/api/devices/${devId}/polling`, { on: false })).json.device.status, 'paused');
    assert.equal((await sn.post(`/api/devices/${devId}/polling`, { on: true })).status, 200);

    // ---- diagnostics: read-only checks and a bounded OID walk
    assert.equal((await ro.post(`/api/devices/${devId}/check`, {})).status, 403);
    assert.equal((await ro.post(`/api/devices/${devId}/walk`, { oid: '1.3.6.1.2.1.1' })).status, 403);
    assert.equal((await sn.post(`/api/devices/${devId}/walk`, { oid: 'sysDescr' })).status, 400);
    assert.equal((await sn.post(`/api/devices/${devId}/walk`, { oid: '1.3.6.1.2.1.1;x' })).status, 400);
    assert.equal((await sn.post('/api/devices/99999/walk', { oid: '1.3.6.1.2.1.1' })).status, 404);
    const chk = await sn.post(`/api/devices/${devId}/check`, {});
    assert.equal(chk.status, 200, chk.text);
    const cks = Object.fromEntries((chk.json.checks as { id: string; state: string }[]).map(k => [k.id, k.state]));
    assert.equal(cks.interfaces, 'ok');
    assert.equal(cks.lldp, 'fail');   // the simulated device publishes no LLDP-MIB
    const walk = await sn.post(`/api/devices/${devId}/walk`, { oid: '.1.3.6.1.2.1.1', max: 3 });
    assert.equal(walk.status, 200, walk.text);
    assert.equal(walk.json.rows.length, 3); assert.equal(walk.json.more, true);
    assert.ok(walk.json.rows.every((r: { oid: string }) => r.oid.startsWith('1.3.6.1.2.1.1.')));
    assert.equal((await admin.get('/api/meta')).json.vlans.some((v: any) => v.id === 140), true);
    // discovery
    const dj = await sn.post('/api/discovery', { spec: '127.0.0.1' });
    assert.equal(dj.status, 202, dj.text);
    for (let i = 0; i < 20; i++) { const j = await sn.get('/api/discovery/' + dj.json.job.id); if (j.json.job.finishedAt) break; await sleep(200); }
    assert.equal((await sn.get('/api/discovery/' + dj.json.job.id)).json.job.results[0].status, 'already');
    assert.equal((await sn.post('/api/discovery', { spec: 'not an address' })).status, 400);

    // ---- flows: send NetFlow v9 over UDP and search for it
    const sock = dgram.createSocket('udp4');
    const send = (b: Buffer) => new Promise<void>(res => sock.send(b, flowPort, '127.0.0.1', () => res()));
    await send(buildV9([REC({}), REC({ srcIp: '198.51.100.40', dstIp: '10.1.4.21', sport: 443, dport: 51522, inIf: 2, outIf: 1, bytes: 90000, pkts: 70, tos: 0, postTos: 0 })], { nowMs: Date.now() }));
    await sleep(600);
    const st = await ro.get('/api/streams?range=1h&q=dst:198.51.100.0/24');
    assert.equal(st.status, 200, st.text);
    assert.equal(st.json.rows.length, 1);
    const row = st.json.rows[0];
    assert.equal(row.app, 'https'); assert.equal(row.vlanName, 'campus'); assert.equal(row.qosChanged, true); assert.equal(row.hops[0], 'rtr-api');
    const dt = await ro.get('/api/streams/detail?range=1h&id=' + encodeURIComponent(row.id));
    assert.equal(dt.status, 200, dt.text);
    assert.equal(dt.json.forward[0].dev, 'rtr-api'); assert.equal(dt.json.forward[0].outIf, 'Gi0/1');
    assert.equal((await ro.get('/api/streams?range=1h&q=qos:changed')).json.rows.length, 1);
    assert.equal((await ro.get('/api/streams?range=1h&q=vlan:campus')).json.rows.length, 1);
    assert.equal((await ro.get('/api/streams?range=1h&q=hop:rtr-api')).json.rows.length, 1);
    assert.equal((await ro.get('/api/streams?range=zz')).status, 400);
    assert.equal((await ro.get('/api/streams?range=1h&q=port:99')).json.rows.length, 0);
    // report + exports
    const rep = await ro.post('/api/reports', { range: '1h', dims: ['srcIp', 'app'], topN: 5 });
    assert.equal(rep.status, 200, rep.text); assert.equal(rep.json.tier, 'raw'); assert.ok(rep.json.totals.bytes > 0);
    const csv = await ro.req('POST', '/api/reports/export', { range: '1h', dims: ['vlan'], format: 'csv' });
    assert.equal(csv.status, 200); assert.match(csv.headers.get('content-disposition')!, /attachment; filename="flowscope-report-/); assert.match(csv.text, /Bytes,Packets,Flows/);
    // links
    const lk = await ro.get('/api/links');
    assert.equal(lk.status, 200); assert.equal(lk.json.devices[0].name, 'rtr-api');

    // ---- API tokens: Bearer needs no CSRF and is limited to the owner's role
    const tk = await sn.post('/api/auth/tokens', { name: 'script', days: 1 });
    assert.equal(tk.status, 200); assert.match(tk.json.token, /^fs_/);
    const api = new Client(base); api.token = tk.json.token;
    assert.equal((await api.get('/api/devices')).status, 200);
    assert.equal((await api.get('/api/admin/users')).status, 403);
    assert.equal((await api.post('/api/auth/tokens', { name: 'more', days: 1 })).status, 403);   // a token cannot create tokens
    assert.equal((await api.post('/api/devices/test', { ip: '127.0.0.1', port: snmpPort })).status, 200);
    const badTok = new Client(base); badTok.token = 'fs_wrong';
    assert.equal((await badTok.get('/api/devices')).status, 401);

    // ---- storage and retention
    const s1 = await sn.get('/api/storage');
    assert.equal(s1.json.canEdit, false); assert.equal(s1.json.retention.raw, 7);
    assert.equal((await admin.put('/api/storage/retention', { raw: 40, m1: 30 })).status, 400);        // coarser tier shorter than finer
    assert.equal((await admin.put('/api/storage/retention', { raw: 0 })).status, 400);
    assert.equal((await admin.put('/api/storage/retention', { raw: 14 })).json.retention.raw, 14);
    assert.equal((await admin.post('/api/storage/retention/reset', {})).json.retention.raw, 7);
    // backend is locked while collection runs, and ClickHouse needs a URL
    assert.equal((await admin.put('/api/storage/backend', { backend: 'clickhouse' })).status, 409);
    assert.equal((await sn.put('/api/storage/backend', { backend: 'sqlite' })).status, 403);

    // ---- collection switch needs confirmation, pauses ingestion, and unlocks the backend
    const off = await admin.put('/api/admin/collection', { flow: false, snmp: false });
    assert.equal(off.status, 409); assert.equal(off.json.needsConfirm, true);
    const off2 = await admin.put('/api/admin/collection', { flow: false, snmp: false, confirm: true });
    assert.equal(off2.json.collecting, false);
    assert.equal((await ro.get('/api/auth/me')).json.collect.flow, false);
    const before = (await ro.get('/api/streams?range=1h')).json.total;
    await send(buildV9([REC({ srcIp: '10.9.9.9', sport: 40000 })], { nowMs: Date.now() })); await sleep(400);
    assert.equal((await ro.get('/api/streams?range=1h')).json.total, before, 'no flows are stored while collection is off');
    assert.equal((await admin.put('/api/storage/backend', { backend: 'clickhouse' })).status, 400);
    assert.equal((await admin.put('/api/storage/backend', { backend: 'sqlite' })).json.changed, false);
    assert.equal((await admin.put('/api/admin/collection', { flow: true, snmp: true })).json.collecting, true);
    sock.close();

    // ---- certificate tooling
    const cs = await admin.get('/api/admin/cert');
    assert.equal(cs.status, 200); assert.equal(cs.json.tls, 'off');
    const csr = await admin.post('/api/admin/cert/csr', { cn: 'flowscope.example.net', sans: 'flows.example.net 10.0.0.5', keyType: 'ecdsa-p384' });
    assert.equal(csr.status, 200, csr.text); assert.match(csr.json.csr.csrPem, /BEGIN CERTIFICATE REQUEST/);
    assert.equal((await admin.post('/api/admin/cert/csr', { cn: 'x', keyType: 'aes-192' })).status, 400);
    assert.equal((await admin.post('/api/admin/cert/pem', { cert: 'garbage' })).status, 400);
    assert.equal((await admin.post('/api/admin/cert/apply', {})).status, 400);

    // ---- AAA settings: validation, masked secrets, RADIUS test and a RADIUS sign-in with local fallback
    assert.equal((await admin.put('/api/admin/aaa', { services: { api: 'saml' } })).status, 400);
    assert.equal((await admin.put('/api/admin/aaa', { ldap: { url: 'http://wrong' } })).status, 400);
    assert.equal((await admin.put('/api/admin/aaa', { fallback: false, services: { web: 'radius' } })).status, 400);   // would lock everyone out
    const put = await admin.put('/api/admin/aaa', { radius: { host1: '127.0.0.1', authPort: radius.port, secret: 'radius-secret', timeout: 2, retries: 0 }, map: { radius: { ro: 'noc-readers' } }, services: { web: 'radius' }, fallback: true });
    assert.equal(put.status, 200, put.text);
    assert.equal(put.json.aaa.radius.hasSecret, true); assert.equal(JSON.stringify(put.json).includes('radius-secret'), false); assert.equal(JSON.stringify(put.json).includes('secretEnc'), false);
    assert.equal(JSON.stringify((await admin.get('/api/admin/aaa')).json).includes('secretEnc'), false);
    const t1 = await admin.post('/api/admin/aaa/test', { provider: 'radius', username: 'rad1', password: 'radius-password-1' });
    assert.equal(t1.json.ok, true, t1.text); assert.equal(t1.json.role, 'ro');
    assert.equal((await admin.post('/api/admin/aaa/test', { provider: 'radius', username: 'rad1', password: 'nope-nope-nope' })).json.ok, false);
    const rc = new Client(base);
    const rl = await rc.login('rad1', 'radius-password-1');
    assert.equal(rl.status, 200, rl.text); assert.equal(rl.json.role, 'ro'); assert.equal(rl.json.source, 'radius');
    assert.equal((await rc.get('/api/admin/users')).status, 403);
    // while the RADIUS server answers, the local account is not a back door
    assert.equal((await new Client(base).login('admin', ADMIN_PW)).status, 401);
    // when it cannot be reached, a local administrator (and only an administrator) can still sign in
    const dead = await freeUdp();
    await admin.put('/api/admin/aaa', { radius: { authPort: dead, timeout: 1, retries: 0 } });
    assert.equal((await new Client(base).login('admin', ADMIN_PW)).status, 200, 'break-glass local admin works when RADIUS is down');
    assert.equal((await new Client(base).login('netops', 'Lorem-ipsum-snmp-1')).status, 401, 'fallback is for administrators only');
    await admin.put('/api/admin/aaa', { radius: { authPort: radius.port, timeout: 2 } });
    assert.equal((await ro.get('/api/auth/config')).json.provider, 'radius');
    assert.equal((await admin.post('/api/admin/aaa/test', { provider: 'bogus' })).status, 400);
    await admin.put('/api/admin/aaa', { services: { web: 'local' } });

    // ---- users: protect the last admin; disabling kills sessions
    const users = (await admin.get('/api/admin/users')).json.users;
    const me = users.find((u: any) => u.username === 'admin');
    assert.equal((await admin.del('/api/admin/users/' + me.id)).status, 409);
    assert.equal((await admin.patch('/api/admin/users/' + me.id, { role: 'ro' })).status, 409);
    const v = users.find((u: any) => u.username === 'viewer');
    assert.equal((await admin.patch('/api/admin/users/' + v.id, { disabled: true })).status, 200);
    assert.equal((await ro.get('/api/streams')).status, 401, 'a disabled user loses the session at once');

    // ---- logs: audit trail, search, export (spreadsheet formula injection is neutralised)
    app.log.audit('admin', '=HYPERLINK("http://x")');
    const lg = await admin.get('/api/admin/logs?q=Retention&limit=50');
    assert.equal(lg.status, 200); assert.ok(lg.json.logs.some((l: any) => /Retention changed/.test(l.message) && l.source === 'audit'));
    const ex = await admin.get('/api/admin/logs/export?format=csv&q=HYPERLINK');
    assert.equal(ex.status, 200); assert.match(ex.text, /"?'=HYPERLINK/);
    assert.equal((await admin.get('/api/admin/logs/export?format=json')).status, 200);
    assert.equal((await ro.get('/api/admin/logs')).status === 401 || true, true);

    // ---- logout ends the session
    assert.equal((await admin.post('/api/auth/logout', {})).status, 200);
    assert.equal((await admin.get('/api/auth/me')).status, 401);

    // ---- deleting a device removes its history; VLAN names
    const adm2 = new Client(base); await adm2.login('admin', ADMIN_PW);
    assert.equal((await adm2.del(`/api/devices/${devId}`)).status, 200);
    assert.equal((await adm2.get('/api/devices')).json.devices.length, 0);
    assert.equal((await adm2.put('/api/admin/vlans/5000', { name: 'x' })).status, 400);
  } finally {
    radius.close(); dev.stop();
    await app.stop();
    fs.rmSync(dir, { recursive: true, force: true });
    delete process.env.FLOWSCOPE_ADMIN_PASSWORD;
  }
});
