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
import type { FlowRecord } from '../src/collector/types.js';

const freePort = () => new Promise<number>(res => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = (s.address() as net.AddressInfo).port; s.close(() => res(p)); }); });
const freeUdp = () => new Promise<number>(res => { const s = dgram.createSocket('udp4'); s.bind(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); }); });
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

class Client {
  cookie = ''; csrf = '';
  constructor(readonly base: string) {}
  async req(method: string, url: string, body?: unknown) {
    const h: Record<string, string> = {};
    if (body !== undefined) h['content-type'] = 'application/json';
    if (this.cookie) h.cookie = this.cookie;
    if (this.csrf && method !== 'GET') h['x-csrf-token'] = this.csrf;
    const r = await fetch(this.base + url, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' });
    const sc = r.headers.get('set-cookie');
    if (sc) { const m = /fs_sid=([^;]*)/.exec(sc); if (m) this.cookie = m[1] ? 'fs_sid=' + m[1] : ''; }
    const text = await r.text();
    let json: any = null; try { json = JSON.parse(text); } catch { /* not json */ }
    return { status: r.status, json, text };
  }
  get(u: string) { return this.req('GET', u); }
  post(u: string, b: unknown = {}) { return this.req('POST', u, b); }
  put(u: string, b: unknown) { return this.req('PUT', u, b); }
  async login(user: string, pass: string) { const r = await this.req('POST', '/api/auth/login', { username: user, password: pass }); if (r.status === 200) this.csrf = r.json.csrf; return r; }
}

const MAC_A = '00:50:56:01:04:15', MAC_PHONE = '00:50:56:01:08:15';
const rec = (over: Partial<FlowRecord>): FlowRecord => ({
  ts0: Date.now() - 120_000, ts1: Date.now() - 60_000, exporter: '127.0.0.1', inIf: 1, outIf: 3, srcIp: '10.1.4.21', dstIp: '198.51.100.40', proto: 6, sport: 51522, dport: 443, flags: 0x1b,
  tos: 0, postTos: null, ttlMin: 62, ttlMax: 63, bytes: 4000, pkts: 20, srcMac: MAC_A, dstMac: '00:1c:73:01:aa:bb', vlan: 140,
  natSrcIp: null, natDstIp: null, natSport: null, natDport: null, nextHop: null, sampling: 1, ...over
});

test('HTTP API: VLAN columns, SVIs left out of needs-attention, host tracking, multicast detail, report prefixes', { timeout: 120_000 }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-apisw-'));
  const httpPort = await freePort(), flowPort = await freeUdp(), snmpPort = await freePort();
  const cfg = loadConfig({ FLOWSCOPE_TLS: 'off', FLOWSCOPE_HTTP_PORT: String(httpPort), FLOWSCOPE_FLOW_PORTS: String(flowPort), FLOWSCOPE_BIND: '127.0.0.1', FLOWSCOPE_FLOW_BIND: '127.0.0.1', FLOWSCOPE_LOG_LEVEL: 'error', FLOWSCOPE_MASTER_KEY: 'test-key' });
  cfg.dataDir = dir;
  process.env.FLOWSCOPE_ADMIN_PASSWORD = 'admin-test-passphrase-1';
  const app = await App.create(cfg);
  app.log.quiet = true;
  await app.start();
  const iface = (index: number, name: string, speedMbps: number, outBps: number) => ({ index, name, speedMbps, inBps: outBps / 4, outBps });
  const sim: SimDevice = {
    name: 'acc-sw-01', descr: 'Cisco IOS XE Catalyst 9300X', objectId: '1.3.6.1.4.1.9.1.2000', address: '127.0.0.1', port: snmpPort,
    // the SVI and the uplink are both nearly full; only the uplink is a link worth looking at
    ifaces: [iface(1, 'Gi1/0/1', 1000, 2e6), iface(2, 'Gi1/0/2', 1000, 2e6), iface(3, 'Te1/1/1', 10000, 9.6e9), iface(4, 'Vl140', 10000, 9.8e9)],
    ips: [{ ip: '127.0.0.1', ifIndex: 4 }], vlans: [{ id: 140, name: 'CAMPUS-USERS' }, { id: 160, name: 'CAMPUS-VOICE' }], qos: [],
    ports: [{ ifIndex: 1, mode: 'access', vlan: 140, voice: 160 }, { ifIndex: 2, mode: 'access', vlan: 150 }, { ifIndex: 3, mode: 'trunk', vlan: 1, allowed: [140, 150, 160] }],
    fdb: [{ mac: MAC_A, vlan: 140, ifIndex: 1 }, { mac: MAC_PHONE, vlan: 160, ifIndex: 1 }],
    arp: [{ ip: '10.1.4.21', mac: MAC_A, ifIndex: 4 }],
    lldp: [{ ifIndex: 3, name: 'core-rtr-01', port: 'Te0/0/0', caps: 0x28 }, { ifIndex: 1, name: 'SEP0050', port: 'Port 1', caps: 0x04 }],
    auth: { community: 'public' }
  };
  const dev = new VirtualDevice(sim);
  await dev.start();
  const base = `http://127.0.0.1:${httpPort}`;
  try {
    const admin = new Client(base);
    assert.equal((await admin.login('admin', 'admin-test-passphrase-1')).status, 200);
    assert.equal((await admin.post('/api/admin/users', { username: 'viewer', password: 'Lorem-ipsum-ro-1', role: 'ro', mustChange: false })).status, 201);
    const ro = new Client(base); assert.equal((await ro.login('viewer', 'Lorem-ipsum-ro-1')).status, 200);
    assert.equal((await admin.post('/api/snmp/credentials', { name: 'lab-v2c', version: 'v2c', community: 'public' })).status, 201);
    const add = await admin.post('/api/devices', { ip: '127.0.0.1', port: snmpPort, name: 'acc-sw-01' });
    assert.equal(add.status, 201, add.text);
    const devId = add.json.device.id;

    app.settings.set('alerts', { util: 60, drop: 1, mcast: 50, priority: 80 });
    // rates need two polls a little apart
    await app.poller.pollNow(devId); await sleep(2200); await app.poller.pollNow(devId);

    // host tables are read on demand (and on a schedule) ...
    assert.equal((await ro.post(`/api/devices/${devId}/read-hosts`)).status, 403, 'a read-only user cannot trigger a read');
    const rh = await admin.post(`/api/devices/${devId}/read-hosts`);
    assert.equal(rh.status, 200, rh.text);
    assert.equal(rh.json.macs, 2); assert.equal(rh.json.arp, 1);

    const lk = await ro.get('/api/links');
    assert.equal(lk.status, 200, lk.text);
    const d = lk.json.devices.find((x: any) => x.name === 'acc-sw-01');
    const by = (n: string) => d.interfaces.find((i: any) => i.name === n);
    // VLAN of each port
    assert.deepEqual([by('Gi1/0/1').portMode, by('Gi1/0/1').vlan, by('Gi1/0/1').vlanName, by('Gi1/0/1').voiceVlan, by('Gi1/0/1').voiceVlanName], ['access', 140, 'CAMPUS-USERS', 160, 'CAMPUS-VOICE']);
    assert.deepEqual([by('Gi1/0/2').vlan, by('Gi1/0/2').vlanName], [150, '']);
    assert.deepEqual([by('Te1/1/1').portMode, by('Te1/1/1').vlan, by('Te1/1/1').vlanList], ['trunk', 1, '140,150,160']);
    assert.deepEqual([by('Vl140').portMode, by('Vl140').vlan, by('Vl140').isVlanIf], ['svi', 140, true]);
    assert.equal(by('Gi1/0/1').hosts, 2);
    // Needs attention: the busy uplink is flagged, the equally busy SVI is not
    assert.ok(by('Vl140').utilOut > 70, 'the SVI really is busy: ' + by('Vl140').utilOut);
    assert.ok(by('Te1/1/1').utilOut > 70, 'util ' + by('Te1/1/1').utilOut);
    assert.equal(by('Te1/1/1').flagged, true);
    assert.equal(by('Vl140').flagged, false);

    // hosts on a port, and a locator
    const ph = await ro.get(`/api/links/hosts?dev=${devId}&if=1`);
    assert.equal(ph.status, 200, ph.text);
    assert.deepEqual(ph.json.hosts.map((h: any) => h.mac).sort(), [MAC_A, MAC_PHONE]);
    assert.deepEqual(ph.json.hosts.find((h: any) => h.mac === MAC_A).ips, ['10.1.4.21']);
    assert.equal(ph.json.hosts.find((h: any) => h.mac === MAC_A).vlanName, 'CAMPUS-USERS');
    assert.equal(ph.json.neighbors[0].kind, 'phone');
    assert.equal((await ro.get('/api/links/hosts?dev=999&if=1')).status, 404);
    const loc = await ro.get('/api/hosts/locate?q=10.1.4.21');
    assert.equal(loc.json.attach.dev, 'acc-sw-01'); assert.equal(loc.json.attach.ifName, 'Gi1/0/1'); assert.equal(loc.json.attach.confidence, 'high');
    assert.equal((await ro.get('/api/hosts/locate?q=')).status, 400);
    assert.equal((await ro.get('/api/hosts/locate?q=10.99.99.99')).json.attach, null);

    // host tracking settings: validated, and only an SNMP admin or above may change them
    assert.equal((await ro.get('/api/hosts/settings')).json.intervalSec, 300);
    assert.equal((await ro.put('/api/hosts/settings', { intervalSec: 120 })).status, 403);
    assert.equal((await admin.put('/api/hosts/settings', { intervalSec: 5 })).status, 400);
    assert.equal((await admin.put('/api/hosts/settings', { keepDays: 0 })).status, 400);
    assert.equal((await admin.put('/api/hosts/settings', { intervalSec: 120, keepDays: 30 })).json.intervalSec, 120);

    await app.store.insertFlows([rec({})]);
    // multicast: three exporters-worth of the same group; the source is located from the MAC table, not guessed from the flows
    const t = Date.now();
    await app.store.insertFlows([
      rec({ srcIp: '10.1.4.21', dstIp: '239.10.20.30', proto: 17, sport: 40500, dport: 5004, inIf: 1, outIf: 3, ts0: t - 300_000, ts1: t - 60_000, dstMac: '01:00:5e:0a:14:1e' }),
      rec({ srcIp: '10.1.4.21', dstIp: '239.10.20.30', proto: 17, sport: 40500, dport: 5004, inIf: 1, outIf: 2, ts0: t - 300_000, ts1: t - 60_000, dstMac: '01:00:5e:0a:14:1e' })
    ]);
    const sid = '10.1.4.21|40500|239.10.20.30|5004|17';
    const det = await ro.get('/api/streams/detail?id=' + encodeURIComponent(sid) + '&range=24h');
    assert.equal(det.status, 200, det.text);
    assert.deepEqual([det.json.multicast.group, det.json.multicast.source], ['239.10.20.30', '10.1.4.21']);
    assert.equal(det.json.multicast.location.attach.ifName, 'Gi1/0/1');
    assert.equal(det.json.forward.length, 1);
    assert.equal(det.json.forward[0].sourcePort, 'Gi1/0/1');
    assert.equal(det.json.forward[0].sourceConfirmed, true, 'the flow record entered on the same port the MAC table says the host is on');
    assert.deepEqual([...det.json.forward[0].outIfs].sort(), ['Gi1/0/2', 'Te1/1/1']);
    assert.equal(det.json.reverse.length, 0); assert.equal(det.json.note, null);
    // a unicast stream has no multicast block
    const uni = await ro.get('/api/streams/detail?id=' + encodeURIComponent('10.1.4.21|51522|198.51.100.40|443|6') + '&range=24h');
    assert.equal(uni.json.multicast, null);

    // report prefixes: any length from /0 to /32
    await app.store.insertFlows([
      rec({ srcIp: '10.1.4.21', sport: 1, bytes: 1000 }), rec({ srcIp: '10.1.15.9', sport: 2, bytes: 2000 }), rec({ srcIp: '10.1.16.9', sport: 3, bytes: 4000 }), rec({ srcIp: '10.1.4.130', sport: 4, bytes: 8000 }),
      rec({ srcIp: '192.0.2.1', sport: 5, bytes: 16000, dstIp: '203.0.113.7' })
    ]);
    const groups = async (prefix: number) => {
      const r = await ro.post('/api/reports', { range: '1h', dims: ['srcIp'], prefix, topN: 50, f3: 'proto:tcp dst:198.51.100.40 port:443' });
      assert.equal(r.status, 200, r.text);
      return Object.fromEntries(r.json.rows.map((x: any) => [x.dims.srcIp, x.bytes]));
    };
    assert.deepEqual(await groups(20), { '10.1.0.0/20': 15000, '10.1.16.0/20': 4000 });      // 10.1.4.x and 10.1.15.x share a /20, 10.1.16.x does not
    assert.deepEqual(await groups(27), { '10.1.4.0/27': 5000, '10.1.4.128/27': 8000, '10.1.15.0/27': 2000, '10.1.16.0/27': 4000 });
    assert.deepEqual(await groups(0), { '0.0.0.0/0': 19000 });
    assert.equal((await groups(32))['10.1.4.130'], 8000);
    assert.deepEqual(Object.keys(await groups(24)).sort(), ['10.1.15.0/24', '10.1.16.0/24', '10.1.4.0/24'], '/24: 10.1.4.x, 10.1.15.x, 10.1.16.x');
  } finally {
    dev.stop();
    await app.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
