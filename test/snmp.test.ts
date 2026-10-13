import test from 'node:test';
import assert from 'node:assert/strict';
import { VirtualDevice, type SimDevice } from '../src/sim/snmpagent.js';
import { SnmpClient } from '../src/snmp/client.js';
import { probe, pollIfCounters, pollQosCounters, delta, guessDscps } from '../src/snmp/collect.js';

function spec(port: number, over: Partial<SimDevice> = {}): SimDevice {
  return {
    name: 'rtr-test', descr: 'Test router', address: '127.0.0.1', port,
    ifaces: [
      { index: 1, name: 'Gi0/0', alias: 'to core', speedMbps: 1000, inBps: 40e6, outBps: 80e6 },
      { index: 2, name: 'Gi0/1', alias: 'uplink', speedMbps: 100, inBps: 10e6, outBps: 90e6, discPct: 2 }
    ],
    ips: [{ ip: '10.255.0.1', ifIndex: 1 }, { ip: '192.0.2.1', ifIndex: 2 }],
    vlans: [{ id: 140, name: 'campus' }, { id: 150, name: 'servers' }],
    qos: [{ ifIndex: 2, policy: 'WAN-OUT', classes: [
      { name: 'voice', dscps: [46], queue: 'LLQ', bw: '20%', pps: 1000, pktBytes: 200, dropPct: 0, qBytes: 1000 },
      { name: 'bulk', dscps: [10], queue: 'CBWFQ', bw: '10%', pps: 5000, pktBytes: 1000, dropPct: 4, qBytes: 90000 },
      { name: 'class-default', dscps: [0], queue: 'fair', pps: 800, pktBytes: 500, dropPct: 1, qBytes: 5000 }
    ] }],
    auth: { community: 'public', user: { name: 'poller', level: 'authPriv', authProto: 'sha256', authKey: 'authpass123', privProto: 'aes', privKey: 'privpass123' } },
    ...over
  };
}

test('virtual device: v2c probe reads system, interfaces, ips, vlans and CBQoS structure', async () => {
  const d = new VirtualDevice(spec(36161));
  await d.start();
  const c = new SnmpClient({ host: '127.0.0.1', port: 36161, timeoutMs: 1500, retries: 0 }, { version: 'v2c', community: 'public' });
  try {
    const p = await probe(c);
    assert.equal(p.info.sysName, 'rtr-test');
    assert.deepEqual(p.ifaces.map(i => [i.index, i.name, i.speedMbps, i.alias]), [[1, 'Gi0/0', 1000, 'to core'], [2, 'Gi0/1', 100, 'uplink']]);
    assert.deepEqual(p.ips.map(i => i.ip).sort(), ['10.255.0.1', '192.0.2.1']);
    assert.deepEqual(p.vlans, [{ id: 140, name: 'campus' }, { id: 150, name: 'servers' }]);
    assert.equal(p.profile, 'cisco-cbqos');
    assert.equal(p.qos.length, 1);
    assert.equal(p.qos[0].ifIndex, 2);
    assert.equal(p.qos[0].direction, 'output');
    assert.equal(p.qos[0].policyName, 'WAN-OUT');
    assert.deepEqual(p.qos[0].classes.map(x => [x.name, x.bandwidth]), [['voice', '20%'], ['bulk', '10%'], ['class-default', null]]);
    // counters move
    const a = await pollIfCounters(c); const qa = await pollQosCounters(c);
    await new Promise(r => setTimeout(r, 2100));
    const b = await pollIfCounters(c); const qb = await pollQosCounters(c);
    const dOut = delta(b.get(2)!.outOct, a.get(2)!.outOct, true)!;
    assert.ok(dOut > 0n);
    const bps = Number(dOut) * 8 / 2.1;
    assert.ok(bps > 60e6 && bps < 120e6, 'out bps ' + bps);
    assert.equal(a.get(2)!.hc, true);
    const bulkKey = `${p.qos[0].policyIdx}.${p.qos[0].classes[1].objIdx}`;
    const dd = qb.classes.get(bulkKey)!.drop - qa.classes.get(bulkKey)!.drop, dp = qb.classes.get(bulkKey)!.pre - qa.classes.get(bulkKey)!.pre;
    assert.ok(dp > 0n);
    const pct = Number(dd) * 100 / Number(dp);
    assert.ok(Math.abs(pct - 4) < 0.5, 'drop pct ' + pct);
    assert.ok(qb.queueDepth.get(`${p.qos[0].policyIdx}.${p.qos[0].classes[1].queueObjIdx}`)! > 0);
  } finally { c.close(); d.stop(); }
});

test('SNMPv3 authPriv works, wrong credentials fail with a clear error', async () => {
  const d = new VirtualDevice(spec(36162));
  await d.start();
  const good = new SnmpClient({ host: '127.0.0.1', port: 36162, timeoutMs: 2000, retries: 0 }, { version: 'v3', username: 'poller', level: 'authPriv', authProto: 'SHA-256', authKey: 'authpass123', privProto: 'AES-128', privKey: 'privpass123' });
  const bad = new SnmpClient({ host: '127.0.0.1', port: 36162, timeoutMs: 800, retries: 0 }, { version: 'v2c', community: 'wrong' });
  const badV3 = new SnmpClient({ host: '127.0.0.1', port: 36162, timeoutMs: 1500, retries: 0 }, { version: 'v3', username: 'poller', level: 'authPriv', authProto: 'SHA-256', authKey: 'WRONGWRONG1', privProto: 'AES-128', privKey: 'privpass123' });
  try {
    const p = await probe(good);
    assert.equal(p.info.sysName, 'rtr-test');
    await assert.rejects(() => probe(bad), /timeout|No response/i);
    await assert.rejects(() => probe(badV3));
  } finally { good.close(); bad.close(); badV3.close(); d.stop(); }
});

test('counter delta and dscp guess', () => {
  assert.equal(delta(10n, 5n, false), 5n);
  assert.equal(delta(5n, 4294967290n, false), 11n);
  assert.equal(delta(5n, 100n, true), null);
  assert.deepEqual(guessDscps('voice'), [46]);
  assert.deepEqual(guessDscps('class-default'), [0]);
});

import { ConfigDb } from '../src/db/configdb.js';
import { Secrets } from '../src/secrets.js';
import { Settings } from '../src/settings.js';
import { AppLog } from '../src/logger.js';
import { CredentialStore, CredError } from '../src/snmp/creds.js';
import { DeviceService, DeviceError, parseTargets } from '../src/snmp/devices.js';
import { Poller } from '../src/snmp/poller.js';
import { Discovery } from '../src/snmp/discovery.js';
import { SqliteStore } from '../src/store/sqlite.js';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

async function env() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-snmp-'));
  const cdb = new ConfigDb(dir);
  const secrets = new Secrets(dir, 'test-key');
  const settings = new Settings(cdb);
  const log = new AppLog(cdb, settings, 'error'); log.quiet = true;
  const creds = new CredentialStore(cdb, secrets, settings);
  const store = await SqliteStore.open(path.join(dir, 'ts'));
  const devs = new DeviceService(cdb, creds, store, log, 1500);
  return { dir, cdb, creds, store, devs, log, done: async () => { await store.close(); log.close(); cdb.close(); fs.rmSync(dir, { recursive: true, force: true }); } };
}

test('target parsing', () => {
  assert.equal(parseTargets('10.0.0.0/30').length, 2);
  assert.deepEqual(parseTargets('10.0.0.5-10.0.0.7'), ['10.0.0.5', '10.0.0.6', '10.0.0.7']);
  assert.deepEqual(parseTargets('10.0.0.5-7, 10.0.1.1'), ['10.0.0.5', '10.0.0.6', '10.0.0.7', '10.0.1.1']);
  assert.throws(() => parseTargets('10.0.0.0/8'), DeviceError);
  assert.throws(() => parseTargets('banana'), DeviceError);
  assert.throws(() => parseTargets('10.0.0.9-10.0.0.1'), DeviceError);
});

test('credentials: encrypted at rest, default handling, in-use protection', async () => {
  const e = await env();
  try {
    const a = e.creds.create({ name: 'lab-v2c', version: 'v2c', community: 'sekret-community' });
    assert.equal(e.creds.defaultId(), a);
    const raw = JSON.stringify(e.cdb.db.prepare('SELECT * FROM snmp_credentials').all());
    assert.ok(!raw.includes('sekret-community'));
    assert.equal(e.creds.resolve(a).community, 'sekret-community');
    assert.throws(() => e.creds.create({ name: 'bad', version: 'v3', username: 'u', level: 'authPriv', authKey: 'short', privKey: 'privprivpriv' }), CredError);
    assert.throws(() => e.creds.create({ name: 'bad2', version: 'v3', username: 'u', level: 'authPriv', authKey: 'longenough1', authProto: 'SHA-256', privKey: 'privprivpriv', privProto: 'AES-192' }), /Unsupported privacy/);
    const b = e.creds.create({ name: 'prod-v3', version: 'v3', username: 'poller', level: 'authPriv', authKey: 'authpass123', privKey: 'privpass123' });
    e.creds.update(b, { name: 'prod-v3', version: 'v3', username: 'poller2', level: 'authPriv' });
    assert.equal(e.creds.resolve(b).authKey, 'authpass123');
    assert.equal(e.creds.resolve(b).username, 'poller2');
    assert.throws(() => e.creds.remove(a), /default/);
    e.creds.setDefault(b);
    e.creds.remove(a);
    assert.equal(e.creds.list().length, 1);
  } finally { await e.done(); }
});

test('devices: add, list, re-discover, polling, remove; poller stores rates; discovery finds and adds', async () => {
  const e = await env();
  const d1 = new VirtualDevice(spec(36171, { name: 'edge-rtr-01' }));
  const d2 = new VirtualDevice(spec(36172, { name: 'dist-sw-02', address: '127.0.0.2', ips: [{ ip: '10.255.0.2', ifIndex: 1 }], qos: [], descr: 'Cisco switch' }));
  await d1.start(); await d2.start();
  try {
    const cid = e.creds.create({ name: 'lab', version: 'v2c', community: 'public' });
    await assert.rejects(() => e.devs.add({ ip: '127.0.0.1', port: 36999, credId: cid }), /No response|timeout/i);
    const dv = await e.devs.add({ ip: '127.0.0.1', port: 36171, credId: cid });
    assert.equal(dv.name, 'edge-rtr-01'); assert.equal(dv.interfaces, 2); assert.equal(dv.classes, 3); assert.equal(dv.profile, 'cisco-cbqos');
    assert.equal(dv.role, 'router');
    await assert.rejects(() => e.devs.add({ ip: '127.0.0.1', port: 36171, credId: cid }), /already/);
    const ifs = e.devs.interfaces(dv.id);
    assert.equal(ifs[1].policy, 'WAN-OUT');
    assert.deepEqual(ifs[1].classes.map(c => [c.cls, c.dscps]), [['voice', [46]], ['bulk', [10, 12, 14]], ['class-default', [0]]]);
    e.devs.setClassDscps(dv.id, 2, 'bulk', [10]);
    await e.devs.rediscover(dv.id);
    assert.deepEqual(e.devs.interfaces(dv.id)[1].classes[1].dscps, [10], 'admin edit is kept across re-discovery');
    assert.equal(e.cdb.db.prepare('SELECT name FROM vlans WHERE id = 140').get()!.name, 'campus');
    assert.equal(e.devs.deviceName('10.255.0.1'), 'edge-rtr-01');
    assert.equal(e.devs.ifName('10.255.0.1', 2), 'Gi0/1');
    assert.equal(e.devs.policyOf('10.255.0.1', 2), 'WAN-OUT');
    assert.deepEqual(e.devs.exporterIpsByName('edge').sort(), ['10.255.0.1', '127.0.0.1', '192.0.2.1']);

    // poller: two polls produce rates
    const poller = new Poller(e.devs, e.store, e.log, { isEnabled: () => true });
    await poller.pollNow(dv.id);
    await new Promise(r => setTimeout(r, 2200));
    await poller.pollNow(dv.id);
    const view = e.devs.list()[0];
    assert.equal(view.status, 'ok');
    const lat = await e.store.ifLatest(Date.now() - 60_000);
    const up = lat.find(x => x.ifIndex === 2)!;
    assert.ok(up.outBps > 60e6 && up.outBps < 120e6, 'outBps ' + up.outBps);
    assert.ok(up.utilOut > 60 && up.utilOut < 120 || up.utilOut === 100, 'util ' + up.utilOut);
    const cl = await e.store.classLatest(Date.now() - 60_000);
    const bulk = cl.find(x => x.cls === 'bulk')!;
    assert.ok(Math.abs(bulk.dropPct - 4) < 0.6, 'bulk drop ' + bulk.dropPct);
    // polling toggle & failure recording
    e.devs.setPolling(dv.id, false);
    assert.equal(e.devs.list()[0].status, 'paused');
    d1.stop();
    e.devs.setPolling(dv.id, true);
    await poller.pollNow(dv.id);
    assert.equal(e.devs.list()[0].status, 'error');

    // discovery
    const disc = new Discovery(e.devs, e.creds, e.log, { timeoutMs: 600, port: 36172, concurrency: 4 });
    const job = disc.start('127.0.0.1-127.0.0.3', 'tester', cid);
    for (let i = 0; i < 40 && !disc.get(job.id)!.finishedAt; i++) await new Promise(r => setTimeout(r, 100));
    const res = disc.get(job.id)!;
    assert.ok(res.finishedAt);
    assert.deepEqual(res.results.map(r => [r.ip, r.status]), [['127.0.0.1', 'already'], ['127.0.0.2', 'found']]);
    assert.equal(res.results[1].sysName, 'dist-sw-02');
    const add = await disc.addFound(job.id, ['127.0.0.2', '127.0.0.3'], 'tester');
    assert.equal(add.added.length, 1); assert.equal(add.added[0].name, 'dist-sw-02'); assert.equal(add.added[0].role, 'switch');
    assert.equal(add.failed.length, 1);
    assert.equal(e.devs.list().length, 2);

    // remove
    await e.devs.remove(dv.id);
    assert.equal(e.devs.list().length, 1);
    assert.equal((await e.store.ifLatest(Date.now() - 60_000)).length, 0);
    assert.equal(e.cdb.db.prepare('SELECT COUNT(*) AS n FROM interfaces WHERE dev_id = ?').get(dv.id)!.n, 0);
    poller.stop();
  } finally { d1.stop(); d2.stop(); await e.done(); }
});
