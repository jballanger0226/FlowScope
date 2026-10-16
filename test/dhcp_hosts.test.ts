import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { SnmpValue } from '../src/snmp/client.js';
import { OID } from '../src/snmp/oids.js';
import { HostTracker } from '../src/snmp/hosts.js';
import { ConfigDb } from '../src/db/configdb.js';
import { Secrets } from '../src/secrets.js';
import { Settings } from '../src/settings.js';
import { AppLog } from '../src/logger.js';
import { CredentialStore } from '../src/snmp/creds.js';
import { DeviceService } from '../src/snmp/devices.js';
import { SqliteStore } from '../src/store/sqlite.js';

/**
 * Host placement with DHCP snooping bindings, against a fake switch that answers whole columns. The cases: a host that is in no MAC table (placed from its
 * lease), one the MAC table agrees with (confirmed), and one that has moved (the fresher MAC table wins and the binding is only mentioned).
 */
const mac = (s: string) => Buffer.from(s.split(':').map(x => parseInt(x, 16)));
const dotted = (m: string) => m.split(':').map(x => parseInt(x, 16)).join('.');
const MAC_A = '00:50:56:01:04:15', MAC_D = '00:50:56:01:04:33', MAC_NEW = '00:50:56:0a:0b:0c';
const BIND = '1.3.6.1.4.1.9.9.380.1.4.1.1';

function switchTables(): Record<string, Record<string, SnmpValue>> {
  const arpIdx = (ip: string) => `4.1.4.${ip}`;
  const bind = (m: string, vlan: number, ip: string, ifIndex: number, lease: number) => ({ idx: `${vlan}.${dotted(m)}`, ip: Buffer.from(ip.split('.').map(Number)), ifIndex, lease });
  const bs = [bind(MAC_NEW, 140, '10.1.4.77', 2, 86400), bind(MAC_A, 140, '10.1.4.21', 1, 3600), bind(MAC_D, 140, '10.1.4.33', 1, 7200)];
  return {
    [OID.ipNetToPhysicalPhysAddress]: { [arpIdx('10.1.4.21')]: mac(MAC_A), [arpIdx('10.1.4.33')]: mac(MAC_D) },
    [OID.dot1qTpFdbPort]: { [`140.${dotted(MAC_A)}`]: 1, [`140.${dotted(MAC_D)}`]: 2 },
    [OID.dot1qTpFdbStatus]: { [`140.${dotted(MAC_A)}`]: 3, [`140.${dotted(MAC_D)}`]: 3 },
    [`${BIND}.4`]: Object.fromEntries(bs.map(b => [b.idx, b.ip])), [`${BIND}.5`]: Object.fromEntries(bs.map(b => [b.idx, b.ifIndex])),
    [`${BIND}.6`]: Object.fromEntries(bs.map(b => [b.idx, b.lease])), [`${BIND}.7`]: Object.fromEntries(bs.map(b => [b.idx, 1]))
  };
}
const fakeClient = (tables: Record<string, Record<string, SnmpValue>>) => ({
  column: async (oid: string) => new Map(Object.entries(tables[oid] ?? {})),
  get: async () => new Map(),
  close() { /* nothing to close */ }
}) as never;

async function env() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-dhcp-'));
  const cdb = new ConfigDb(dir);
  const secrets = new Secrets(dir, 'test-key');
  const settings = new Settings(cdb);
  const log = new AppLog(cdb, settings, 'error'); log.quiet = true;
  const creds = new CredentialStore(cdb, secrets, settings);
  const store = await SqliteStore.open(path.join(dir, 'ts'));
  const devs = new DeviceService(cdb, creds, store, log, 1500);
  return { cdb, creds, devs, log, done: async () => { await store.close(); log.close(); cdb.close(); fs.rmSync(dir, { recursive: true, force: true }); } };
}

function addSwitch(e: Awaited<ReturnType<typeof env>>, name: string, objectId: string): number {
  const cid = e.creds.create({ name: 'lab-' + name, version: 'v2c', community: 'public' });
  const r = e.cdb.db.prepare('INSERT INTO devices(name, ip, cred_id, added_at, sys_object_id, role) VALUES (?,?,?,?,?,?)').run(name, name === 'acc-sw-01' ? '10.1.0.2' : '10.1.0.3', cid, Date.now(), objectId, 'switch');
  const id = Number(r.lastInsertRowid);
  const ins = e.cdb.db.prepare('INSERT INTO interfaces(dev_id, if_index, name, descr, speed_mbps, oper_status) VALUES (?,?,?,?,?,?)');
  ins.run(id, 1, 'Gi1/0/1', 'Gi1/0/1', 1000, 1); ins.run(id, 2, 'Gi1/0/2', 'Gi1/0/2', 1000, 1);
  return id;
}

test('DHCP snooping bindings place a host with no MAC table entry, confirm one that has it, and never override a moved one', async () => {
  const e = await env();
  try {
    const id = addSwitch(e, 'acc-sw-01', '1.3.6.1.4.1.9.1.2000');
    const tracker = new HostTracker(e.cdb, e.devs, e.log);
    const r = await tracker.refresh(e.devs.row(id)!, fakeClient(switchTables()));
    assert.equal(r.macs, 2); assert.equal(r.arp, 2);
    assert.equal((e.cdb.db.prepare('SELECT COUNT(*) AS n FROM arp').get() as { n: number }).n, 3, 'the lease of the host with no ARP entry gives an address too');
    assert.equal((e.cdb.db.prepare('SELECT COUNT(*) AS n FROM dhcp_bindings').get() as { n: number }).n, 3);
    assert.match(String((e.cdb.db.prepare('SELECT hosts_note AS n FROM devices WHERE id = ?').get(id) as { n: string }).n), /3 DHCP snooping bindings/);

    const fresh = tracker.locate('10.1.4.77');
    assert.equal(fresh.attach?.ifName, 'Gi1/0/2'); assert.equal(fresh.attach?.confidence, 'medium'); assert.equal(fresh.attach?.vlan, 140);
    assert.match(fresh.note, /DHCP snooping binding/); assert.match(fresh.note, /not proof that it is still plugged in/);

    const same = tracker.locate('10.1.4.21');
    assert.equal(same.attach?.ifName, 'Gi1/0/1'); assert.equal(same.attach?.confidence, 'high'); assert.match(same.note, /Confirmed by a DHCP snooping binding/);

    const moved = tracker.locate('10.1.4.33');
    assert.equal(moved.attach?.ifName, 'Gi1/0/2', 'the fresher MAC table wins');
    assert.match(moved.note, /different port than the MAC tables show now/);

    // an ended lease is gone from the table, so the next read removes it
    const t = switchTables();
    for (const k of Object.keys(t)) if (k.startsWith(BIND)) for (const idx of Object.keys(t[k]!)) if (idx.endsWith(dotted(MAC_NEW))) delete t[k]![idx];
    await tracker.refresh(e.devs.row(id)!, fakeClient(t));
    assert.equal((e.cdb.db.prepare('SELECT COUNT(*) AS n FROM dhcp_bindings').get() as { n: number }).n, 2);
  } finally { await e.done(); }
});

test('a device that is not Cisco is not asked for DHCP snooping, and its bindings table stays empty', async () => {
  const e = await env();
  try {
    const id = addSwitch(e, 'other-sw-01', '1.3.6.1.4.1.2636.1.1');
    const asked: string[] = [];
    const tables = switchTables();
    const cl = { column: async (oid: string) => { asked.push(oid); return new Map(Object.entries(tables[oid] ?? {})); }, get: async () => new Map(), close() { /* nothing */ } } as never;
    await new HostTracker(e.cdb, e.devs, e.log).refresh(e.devs.row(id)!, cl);
    assert.ok(!asked.some(o => o.startsWith(BIND)));
    assert.equal((e.cdb.db.prepare('SELECT COUNT(*) AS n FROM dhcp_bindings').get() as { n: number }).n, 0);
  } finally { await e.done(); }
});
