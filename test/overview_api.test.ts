import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import dgram from 'node:dgram';
import { App } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import type { FlowRecord } from '../src/collector/types.js';

const freePort = () => new Promise<number>(res => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = (s.address() as net.AddressInfo).port; s.close(() => res(p)); }); });
const freeUdp = () => new Promise<number>(res => { const s = dgram.createSocket('udp4'); s.bind(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); }); });

const ADMIN_PW = 'admin-test-passphrase-1';
const MIN = 60_000, HOUR = 3600_000;
const REC = (over: Partial<FlowRecord>): FlowRecord => ({
  ts0: Date.now() - 20_000, ts1: Date.now() - 5_000, exporter: '10.255.0.1', inIf: 1, outIf: 2, srcIp: '10.1.4.21', dstIp: '198.51.100.40', proto: 6, sport: 51522, dport: 443, flags: 0x1b,
  tos: 0, postTos: 0, ttlMin: 62, ttlMax: 63, bytes: 4000, pkts: 20, srcMac: '00:50:56:01:04:15', dstMac: '00:1c:73:01:aa:bb', vlan: 140,
  natSrcIp: null, natDstIp: null, natSport: null, natDport: null, nextHop: null, sampling: 1, ...over
});

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

test('Overview API: an installation with nothing set up still answers', { timeout: 60_000 }, async () => {
  await withApp(async (_app, base, admin) => {
    const r = await call(base, admin.cookie, '/api/overview');
    assert.equal(r.status, 200, r.text);
    assert.equal(r.json.devices.total, 0);
    assert.deepEqual(r.json.devices.down, []);
    assert.equal(r.json.notices.total, 0);
    assert.deepEqual(r.json.flows.top, []);
    assert.equal(r.json.flows.exporters.total, 0);
    assert.deepEqual(r.json.ports.busiest, []);
    assert.ok(r.json.logs, 'an administrator gets the log summary even when it is empty');
    assert.equal(typeof r.json.logs.errors, 'number'); assert.ok(Array.isArray(r.json.logs.items));
  });
});

test('Overview API: down devices with duration, ranked notices, top flows and ports, logs for admins only', { timeout: 60_000 }, async () => {
  await withApp(async (app, base, admin) => {
    // four polled devices: answering, down for 3 hours, never answered, paused. Intervals are long so the poller leaves them alone.
    const now = Date.now();
    const credId = app.creds.create({ name: 'test', version: 'v2c', community: 'public' }, true);
    const add = app.cdb.db.prepare('INSERT INTO devices(name, ip, port, cred_id, interval_sec, polling, added_at, role, last_poll, last_ok, last_error) VALUES (?,?,?,?,?,?,?,?,?,?,?)');
    const ok = Number(add.run('core-rtr', '10.255.0.1', 161, credId, 3600, 1, now - 30 * 24 * HOUR, 'router', now, now, null).lastInsertRowid);
    add.run('sw-down', '10.255.0.2', 161, credId, 3600, 1, now - 30 * 24 * HOUR, 'switch', now, now - 3 * HOUR - 12 * MIN, 'Request timed out');
    add.run('sw-new', '10.255.0.3', 161, credId, 3600, 1, now - 2 * HOUR, 'switch', now, null, 'No response from 10.255.0.3');
    add.run('sw-off', '10.255.0.4', 161, credId, 3600, 0, now - 30 * 24 * HOUR, 'switch', null, null, null);
    app.devices.invalidate();

    // one busy port on the healthy router, over the alert threshold
    app.cdb.db.prepare('INSERT INTO interfaces(dev_id, if_index, name, alias, speed_mbps, oper_status) VALUES (?,?,?,?,?,?)').run(ok, 2, 'Gi0/1', 'WAN uplink', 1000, 1);
    app.cdb.db.prepare('INSERT INTO interfaces(dev_id, if_index, name, alias, speed_mbps, oper_status) VALUES (?,?,?,?,?,?)').run(ok, 3, 'Gi0/2', '', 1000, 1);
    await app.store.insertSnmp([
      { ts: now - 30_000, dev: ok, ifIndex: 2, dt: 60, inBps: 20e6, outBps: 960e6, utilIn: 2, utilOut: 96, inDisc: 0, outDisc: 0, inErr: 0, outErr: 0, oper: 1 },
      { ts: now - 30_000, dev: ok, ifIndex: 3, dt: 60, inBps: 5e6, outBps: 5e6, utilIn: 0.5, utilOut: 0.5, inDisc: 0, outDisc: 0, inErr: 0, outErr: 0, oper: 1 }
    ], []);

    // flows: two sizes, so the biggest comes first; and two exporters, one of which went quiet an hour ago
    await app.store.insertFlows([REC({ bytes: 9_000_000, srcIp: '10.1.4.21', dstIp: '203.0.113.9' }), REC({ bytes: 1000, srcIp: '10.1.4.22', dstIp: '203.0.113.10', sport: 40001 })]);
    const ex = app.cdb.db.prepare('INSERT INTO exporters(ip, first_seen, last_seen, flows, version) VALUES (?,?,?,?,?)');
    ex.run('10.255.0.1', now - 5 * HOUR, now - 10_000, 5000, 'v9'); ex.run('192.0.2.77', now - 5 * HOUR, now - HOUR, 20, 'ipfix');

    // two entries a person should see in the log box, and one that is only informational
    app.log.error('snmp', 'Polling sw-down (10.255.0.2) failed: Request timed out');
    app.log.warn('collector', 'Exporter 192.0.2.77 stopped sending');
    app.log.info('app', 'just a note');

    const r = await call(base, admin.cookie, '/api/overview');
    assert.equal(r.status, 200, r.text);
    const o = r.json;

    // devices: down ones with how long, longest first; the never-reached one counts from when it was added
    assert.equal(o.devices.total, 4); assert.equal(o.devices.ok, 1); assert.equal(o.devices.paused, 1);
    assert.deepEqual(o.devices.down.map((d: any) => d.name), ['sw-down', 'sw-new']);
    const down = o.devices.down[0];
    assert.ok(Math.abs(down.downMs - (3 * HOUR + 12 * MIN)) < 30_000, `downMs ${down.downMs}`);
    assert.equal(down.neverReached, false); assert.equal(down.lastError, 'Request timed out');
    assert.equal(o.devices.down[1].neverReached, true);
    assert.ok(Math.abs(o.devices.down[1].downMs - 2 * HOUR) < 30_000);

    // notices: the two unreachable devices come first, then the saturated uplink, each with where to review it
    const items = o.notices.items;
    assert.deepEqual(items.slice(0, 2).map((n: any) => n.kind), ['device-down', 'device-down']);
    assert.deepEqual(items.slice(0, 2).map((n: any) => n.dev), ['sw-down', 'sw-new']);
    const uplink = items.find((n: any) => n.kind === 'issue');
    assert.ok(uplink, 'the saturated uplink is a notice');
    assert.equal(uplink.dev, 'core-rtr'); assert.equal(uplink.devId, ok);
    assert.deepEqual(uplink.target, { tab: 'interfaces', ifIndex: 2, section: 'traffic' });
    assert.equal(o.notices.total, o.notices.bad + o.notices.warn);
    assert.ok(o.notices.bad >= 2);

    // flows and exporters
    assert.equal(o.flows.error, null);
    assert.equal(o.flows.top[0].bytes, 9_000_000); assert.equal(o.flows.top[0].dstIp, '203.0.113.9');
    assert.ok(o.flows.top.length <= 5);
    assert.equal(o.flows.exporters.total, 2); assert.equal(o.flows.exporters.active, 1);
    assert.deepEqual(o.flows.exporters.silent.map((e: any) => e.ip), ['192.0.2.77']);
    assert.equal(o.flows.exporters.top[0].ip, '10.255.0.1');
    assert.equal(o.flows.exporters.top[0].devId, ok, 'an exporter that is a polled device says which');
    assert.equal(o.flows.exporters.silent[0].devId, null);

    // busiest ports: the uplink first, with its alias
    assert.equal(o.ports.busiest[0].name, 'Gi0/1'); assert.equal(o.ports.busiest[0].alias, 'WAN uplink'); assert.equal(o.ports.busiest[0].util, 96);
    assert.equal(o.ports.busiest[0].over, true);

    // logs: errors first, informational entries left out, and the counts are of warnings and errors only
    assert.ok(o.logs, 'an administrator gets the logs');
    // (the application writes warnings of its own, such as the creation of the first administrator, so the test looks for its own entries)
    assert.equal(o.logs.errors, 1); assert.ok(o.logs.warnings >= 1);
    assert.equal(o.logs.items[0].level, 'ERROR');
    const msgs = o.logs.items.map((x: any) => x.message);
    assert.ok(msgs.some((m: string) => m.startsWith('Polling sw-down')) && msgs.includes('Exporter 192.0.2.77 stopped sending'));
    assert.ok(!msgs.includes('just a note'), 'informational entries are not shown');
    assert.ok(o.logs.items.every((x: any) => x.level === 'ERROR' || x.level === 'WARN'));

    // a read-only user sees everything except the logs, which are an administrator page
    const mk = await fetch(base + '/api/admin/users', { method: 'POST', headers: { 'content-type': 'application/json', cookie: admin.cookie, 'x-csrf-token': admin.csrf }, body: JSON.stringify({ username: 'viewer', password: 'Lorem-ipsum-ro-1', role: 'ro', mustChange: false }) });
    assert.equal(mk.status, 201);
    const ro = await login(base, 'viewer', 'Lorem-ipsum-ro-1');
    const rr = await call(base, ro.cookie, '/api/overview');
    assert.equal(rr.status, 200);
    assert.equal(rr.json.logs, null, 'logs are not shown to read-only users');
    assert.equal(rr.json.devices.down.length, 2);
    assert.equal(rr.text.includes('Polling sw-down'), false, 'no log text leaks to a read-only user');

    // the Network health page still returns what it did: the refactor behind it shares its code with the Overview
    const links = await call(base, admin.cookie, '/api/links?minutes=10');
    assert.equal(links.status, 200);
    assert.equal(links.json.devices.length, 4); assert.equal(links.json.windowMinutes, 10); assert.ok(Array.isArray(links.json.mibs));
    const gi = links.json.devices.find((d: any) => d.name === 'core-rtr').interfaces.find((i: any) => i.name === 'Gi0/1');
    assert.equal(gi.flagged, true);
    assert.equal((await call(base, admin.cookie, `/api/links/health?dev=${ok}`)).status, 200);
    assert.equal((await call(base, admin.cookie, '/api/links/health?dev=9999')).status, 404);
  });
});
