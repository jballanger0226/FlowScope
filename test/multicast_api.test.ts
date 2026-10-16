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
import { readMulticast } from '../src/snmp/multicast.js';
import { skeyOf } from '../src/store/util.js';
import type { SnmpClient, SnmpValue } from '../src/snmp/client.js';

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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-mc-'));
  const httpPort = await freePort(), flowPort = await freeUdp();
  const cfg = loadConfig({ FLOWSCOPE_TLS: 'off', FLOWSCOPE_HTTP_PORT: String(httpPort), FLOWSCOPE_FLOW_PORTS: String(flowPort), FLOWSCOPE_BIND: '127.0.0.1', FLOWSCOPE_FLOW_BIND: '127.0.0.1', FLOWSCOPE_LOG_LEVEL: 'warn', FLOWSCOPE_DEMO: '' } as NodeJS.ProcessEnv);
  cfg.dataDir = dir;
  process.env.FLOWSCOPE_ADMIN_PASSWORD = ADMIN_PW;
  const app = await App.create(cfg);
  app.log.quiet = true;
  await app.start();
  const base = `http://127.0.0.1:${httpPort}`;
  try {
    assert.equal((await call(base, '', '/api/multicast/devices')).status, 401, 'sign-in is required');
    await fn(app, base, await login(base, 'admin', ADMIN_PW));
  } finally {
    await app.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
}


const FIX = JSON.parse(fs.readFileSync(path.join(import.meta.dirname, '..', '..', 'test', 'fixtures', 'mcast-c9300.json'), 'utf8')) as Record<string, SnmpValue>;
const agent = { column: async (col: string) => { const m = new Map<string, SnmpValue>(); for (const [o, v] of Object.entries(FIX)) if (o.startsWith(col + '.')) m.set(o.slice(col.length + 1), v); return m; } } as unknown as SnmpClient;

test('Multicast API: device list, one device\'s routes with names, and the plan on a multicast stream', { timeout: 60_000 }, async () => {
  await withApp(async (app, base, admin) => {
    const now = Date.now();
    const credId = app.creds.create({ name: 'test', version: 'v2c', community: 'public' }, true);
    const add = app.cdb.db.prepare('INSERT INTO devices(name, ip, port, cred_id, interval_sec, polling, added_at, role, last_poll, last_ok, last_error) VALUES (?,?,?,?,?,?,?,?,?,?,?)');
    const sw = Number(add.run('core-sw', '10.255.0.1', 161, credId, 3600, 1, now - HOUR, 'switch', now, now, null).lastInsertRowid);
    const plain = Number(add.run('access-sw', '10.255.0.2', 161, credId, 3600, 1, now - HOUR, 'switch', now, now, null).lastInsertRowid);
    app.devices.invalidate();
    const ifr = app.cdb.db.prepare('INSERT INTO interfaces(dev_id, if_index, name, alias, speed_mbps, oper_status) VALUES (?,?,?,?,?,?)');
    for (const [ix, nm] of [[735, 'Vl735'], [104, 'Vl104'], [107, 'Vl107'], [110, 'Vl110'], [427, 'Te1/1/1']] as [number, string][]) ifr.run(sw, ix, nm, '', 1000, 1);
    app.devices.saveMulticast(sw, (await readMulticast(agent, now))!);

    const list = await call(base, admin.cookie, '/api/multicast/devices');
    assert.equal(list.status, 200, list.text);
    assert.equal(list.json.devices.length, 1, 'only a device with multicast state is listed');
    assert.equal(list.json.devices[0].name, 'core-sw');
    assert.equal(list.json.devices[0].routes, 25);
    assert.equal(list.json.devices[0].stale, false);

    const dev = await call(base, admin.cookie, '/api/multicast/device?id=' + sw);
    assert.equal(dev.status, 200, dev.text);
    const r = dev.json.routes.find((x: any) => x.group === '224.0.1.129' && x.source === '10.13.192.136');
    assert.equal(r.inIf, 'Vl735');
    assert.deepEqual(r.out.map((o: any) => o.name), ['Vl104', 'Vl107', 'Vl110', 'Te1/1/1']);
    assert.ok(r.out.every((o: any) => o.forwarding));
    assert.equal(dev.json.pim.neighbors.length, 2);
    // every route source is looked up for the plugged-in port (null when host tracking has not seen it)
    assert.equal(typeof dev.json.hosts, 'object');
    assert.ok('10.13.192.136' in dev.json.hosts, 'the source of a route has an entry');
    assert.ok(!('0.0.0.0' in dev.json.hosts), 'wildcard sources are not looked up');
    assert.equal((await call(base, admin.cookie, '/api/multicast/device?id=' + plain)).status, 404, 'a device with no multicast state');
    assert.equal((await call(base, admin.cookie, '/api/multicast/device?id=99999')).status, 404);

    // a multicast stream through core-sw: the flow records show only the ingress side and one egress
    const rec = REC({ exporter: '10.255.0.1', srcIp: '10.13.192.136', dstIp: '224.0.1.129', proto: 17, sport: 319, dport: 319, inIf: 735, outIf: 104, srcMac: null, dstMac: '01:00:5e:00:01:81', vlan: 735 });
    await app.store.insertFlows([rec]);
    const d = await call(base, admin.cookie, '/api/streams/detail?id=' + encodeURIComponent(skeyOf(rec)) + '&range=1h');
    assert.equal(d.status, 200, d.text);
    assert.ok(d.json.multicast, 'recognised as multicast');
    const plan = d.json.plan;
    assert.equal(plan.group, '224.0.1.129');
    assert.equal(plan.devices.length, 1);
    assert.equal(plan.devices[0].name, 'core-sw');
    assert.equal(plan.devices[0].exported, true);
    assert.deepEqual(plan.devices[0].outgoing.map((o: any) => [o.name, o.seenInFlow]), [['Vl104', true], ['Vl107', false], ['Vl110', false], ['Te1/1/1', false]]);
    assert.equal(plan.forwardingTo, 4);
    assert.equal(plan.level, 'ok');

    // an ordinary unicast stream has no plan
    const u = REC({ srcIp: '10.1.4.21', dstIp: '198.51.100.40' });
    await app.store.insertFlows([u]);
    const ud = await call(base, admin.cookie, '/api/streams/detail?id=' + encodeURIComponent(skeyOf(u)) + '&range=1h');
    assert.equal(ud.status, 200, ud.text);
    assert.equal(ud.json.plan, null);
  });
});

test('Multicast members: reporters are collected over time and cleared when they leave', { timeout: 60_000 }, async () => {
  await withApp(async (app, base, admin) => {
    const now = Date.now(), MIN = 60_000;
    const credId = app.creds.create({ name: 'test', version: 'v2c', community: 'public' }, true);
    const sw = Number(app.cdb.db.prepare('INSERT INTO devices(name, ip, port, cred_id, interval_sec, polling, added_at, role, last_poll, last_ok, last_error) VALUES (?,?,?,?,?,?,?,?,?,?,?)').run('core-sw', '10.255.0.1', 161, credId, 3600, 1, now - HOUR, 'switch', now, now, null).lastInsertRowid);
    app.devices.invalidate();
    app.devices.saveMulticast(sw, (await readMulticast(agent, now))!);
    const G = '224.0.1.129', V = 104;
    const ips = () => app.devices.mcastMembers(sw).map(m => m.ip).sort();
    app.devices.noteIgmp(sw, [{ group: G, ifIndex: V, reporter: '10.1.1.1' }], now - 20 * MIN);
    app.devices.noteIgmp(sw, [{ group: G, ifIndex: V, reporter: '10.1.1.2' }], now - 10 * MIN);
    assert.deepEqual(ips(), ['10.1.1.1', '10.1.1.2'], 'each reporter is kept, not just the last one');
    const dev = await call(base, admin.cookie, '/api/multicast/device?id=' + sw);
    const out = dev.json.routes.find((x: any) => x.group === G && x.out.some((o: any) => o.ifIndex === V)).out.find((o: any) => o.ifIndex === V);
    assert.deepEqual(out.members.map((m: any) => m.ip).sort(), ['10.1.1.1', '10.1.1.2']);
    assert.ok(dev.json.hosts['10.1.1.1'] !== undefined, 'members are looked up in host tracking');
    // a host not heard from for 30 minutes and not on the network is dropped; the one that just reported stays
    app.devices.noteIgmp(sw, [{ group: G, ifIndex: V, reporter: '10.1.1.2' }], now + 25 * MIN);
    assert.deepEqual(ips(), ['10.1.1.2']);
    // a quiet host that host tracking still sees is kept
    app.devices.noteIgmp(sw, [{ group: G, ifIndex: V, reporter: '10.1.1.3' }], now + 26 * MIN);
    app.cdb.db.prepare('INSERT INTO arp(dev_id, ip, mac, if_index, last_seen) VALUES (?,?,?,?,?)').run(sw, '10.1.1.2', 'aa:bb:cc:00:00:02', V, now + 70 * MIN);
    app.devices.noteIgmp(sw, [{ group: G, ifIndex: V, reporter: '10.1.1.3' }], now + 80 * MIN);
    assert.deepEqual(ips(), ['10.1.1.2', '10.1.1.3'], 'still on the network, so still counted');
    // nothing from 12 hours, or the group gone from the cache, clears them
    app.devices.noteIgmp(sw, [], now + 81 * MIN);
    assert.deepEqual(ips(), [], 'the group is no longer in the router\'s cache');
  });
});
