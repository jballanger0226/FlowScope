import type { App } from './app.js';
import { apAsResources, recordResources } from './snmp/resource_history.js';
import { recordIfExtra } from './snmp/iface_history.js';
import { diffExtra, EMPTY_HEALTH, EXTRA_COUNTERS, hottest, type ExtraCounter, type Health, type IfExtra, type Sensor } from './snmp/health.js';
import type { FlowRecord } from './collector/types.js';
import type { ClsPoint, IfPoint } from './store/types.js';
import { dscpName } from './query/apps.js';
import type { Resources } from './snmp/resources.js';

/** Demo mode: a small simulated network (eight devices, the traffic between them and SNMP history) written straight into
 *  the real stores, so every screen has realistic data without any exporters. Nothing here talks to the network. */

type Role = 'switch' | 'router' | 'firewall' | 'ap';
// interface: [name, description, speed Mbps, output policy, out util %, in util %]
type Ifc = [string, string, number, string | null, number, number];
interface Dev { name: string; ip: string; role: Role; descr: string; secs: number; ifs: Ifc[]; mac: string }

/** A plausible, slowly moving uptime / CPU / memory / disk reading for a demo device, so the resource panels have something to show. */
function demoResources(d: Dev, now: number): Resources {
  const k = [...d.name].reduce((a, c) => a + c.charCodeAt(0), 0);
  const wave = (period: number, phase = 0) => (Math.sin((now / 1000 + k * 37 + phase) / period) + 1) / 2;
  const base = { switch: [6, 14, 38, 20, 4], router: [10, 24, 44, 24, 8], firewall: [14, 34, 58, 20, 16], ap: [9, 30, 52, 18, 1] }[d.role];
  // now and then a short burst, so the history has something worth looking at; the firewall also has a slow memory leak that is reset by its restart
  const burst = wave(1700, 11) > 0.96 ? 30 + wave(90) * 25 : 0;
  const cpu = Math.min(99, Math.round(base[0] + wave(500) * base[1] + burst));
  const memTotal = base[4] * 1024 ** 3;
  const memPct = Math.round((base[2] + wave(2400, 5) * base[3]) * 10) / 10;
  const up = (3 + (k % 40)) * 86400 + 5 * 3600 + (k % 59) * 60;
  // the first switch restarted 20 hours ago, which the history marks
  const restartAt = d.name === 'dist-sw-01' ? DEMO_BOOT - 20 * 3600_000 : 0;
  const uptimeSec = restartAt && now >= restartAt ? Math.floor((now - restartAt) / 1000) : up + Math.floor((now - DEMO_BOOT) / 1000);
  const sessions = d.role === 'firewall' ? Math.round(5200 + wave(900, 3) * 4800 + burst * 60) : null;
  return {
    uptimeSec, tempC: hottest(demoHealth(d, now).sensors), sessions, sessionsMax: d.role === 'firewall' ? 64000 : null, cpuPct: cpu, cores: d.role === 'firewall' ? 8 : d.role === 'router' ? 4 : null,
    load: d.role === 'firewall' ? [Math.round(cpu / 12) / 10, Math.round(cpu / 14) / 10, Math.round(cpu / 16) / 10] : null,
    memPct, memTotal, memUsed: Math.round(memTotal * memPct / 100), swapPct: d.role === 'firewall' ? 1.2 : null,
    disks: d.role === 'firewall' ? [{ name: '/', usedPct: 18.4, totalBytes: 120 * 1024 ** 3, usedBytes: Math.round(120 * 1024 ** 3 * 0.184) }, { name: '/var/log', usedPct: 41.0, totalBytes: 20 * 1024 ** 3, usedBytes: Math.round(20 * 1024 ** 3 * 0.41) }] : [],
    source: d.role === 'firewall' ? 'UCD-SNMP-MIB + HOST-RESOURCES-MIB' : 'CISCO-PROCESS-MIB + CISCO-MEMORY-POOL-MIB', readAt: now
  };
}
const DEMO_BOOT = Date.now();

/** Two access points answering for one device, each with its own slowly moving CPU and memory, so the Wi-Fi view has per-AP readings and history. */
function demoAps(now: number): { mac: string; name: string; ip: string; serial: string; model: string; cpuPct: number; memFree: number; memTotal: number; uptimeSec: number; role: string }[] {
  return [['ap-4f-01', '00:1c:73:aa:04:01', 'AP-515', 11, 2, 31], ['ap-4f-02', '00:1c:73:aa:04:02', 'AP-535', 23, 5, 47]].map(([name, mac, model, phase, days, memBase], i) => {
    const wave = (period: number, ph = 0) => (Math.sin((now / 1000 + (phase as number) * 97 + ph) / period) + 1) / 2;
    const burst = wave(1900, 7) > 0.95 ? 28 + wave(80) * 20 : 0;
    const total = 1024 * 1024 * 1024;
    return { mac: mac as string, name: name as string, ip: `10.1.7.${40 + i}`, serial: `DEMO${phase}AP${i}`, model: model as string, cpuPct: Math.min(99, Math.round(8 + wave(600) * 22 + burst)),
      memTotal: total, memFree: Math.round(total * (1 - ((memBase as number) + wave(2600, 3) * 14) / 100)), uptimeSec: (days as number) * 86400 + Math.floor((now - DEMO_BOOT) / 1000), role: i === 0 ? 'primary' : 'member' };
  });
}
function seedWlan(app: App, devId: number, now: number, history = false): void {
  const db = app.cdb.db;
  const aps = demoAps(now);
  db.prepare('DELETE FROM wlan_ap WHERE dev_id = ?').run(devId); db.prepare('DELETE FROM wlan_radio WHERE dev_id = ?').run(devId);
  for (const a of aps) {
    db.prepare('INSERT INTO wlan_ap(dev_id, mac, name, ip, serial, model, cpu_pct, mem_free, mem_total, uptime_sec, role, read_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)').run(devId, a.mac, a.name, a.ip, a.serial, a.model, a.cpuPct, a.memFree, a.memTotal, a.uptimeSec, a.role, now);
    [['2.4 GHz', '6', 14, 31], ['5 GHz', '44', 17, 22]].forEach(([band, ch, tx, busy], idx) => db.prepare('INSERT OR REPLACE INTO wlan_radio(dev_id, ap_mac, idx, mac, channel, band, tx_power, noise_floor, util4, util64, clients, mode, up) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)')
      .run(devId, a.mac, idx, a.mac, ch, band, tx, -92, busy, (busy as number) - 3, 4 + idx * 3, 'ap', 1));
    try { recordResources(db, devId, apAsResources(a, now), a.mac); } catch { /* demo history is a bonus */ }
  }
  if (history) app.cdb.tx(() => { for (let t = now - 14 * 86400_000; t < now - 60_000; t += t < now - 3 * 86400_000 ? 300_000 : 60_000) for (const a of demoAps(t)) recordResources(db, devId, apAsResources(a, t), a.mac); });
}

/** Sensors, PoE, spanning tree and routing neighbours for a demo device, drifting slowly with the time. */
function demoHealth(d: Dev, now: number): Health {
  const k = [...d.name].reduce((a, c) => a + c.charCodeAt(0), 0);
  const wave = (period: number, phase = 0) => (Math.sin((now / 1000 + k * 53 + phase) / period) + 1) / 2;
  const h = EMPTY_HEALTH(now);
  const S = (kind: Sensor['kind'], name: string, value: number | null, unit: string, state: Sensor['state'] = 'ok', stateText = 'ok', extra: Partial<Sensor> = {}): void => { h.sensors.push({ id: `demo:${h.sensors.length}`, kind, name, value, unit, state, stateText, ...extra }); };
  const base = d.role === 'firewall' ? 44 : d.role === 'router' ? 41 : 36;
  const t = Math.round((base + wave(3000) * 9 + (d.name === 'dc-leaf-07' ? 22 : 0)) * 10) / 10;
  S('temperature', d.role === 'switch' ? 'Switch 1 - Mainboard Temperature' : 'Chassis inlet temperature', t, '°C', t >= 65 ? 'warn' : 'ok', t >= 65 ? 'over a minor limit' : 'ok');
  S('temperature', d.role === 'switch' ? 'Switch 1 - ASIC Temperature' : 'CPU package temperature', Math.round((t + 11) * 10) / 10, '°C');
  S('fan', 'Fan tray 1', 4200 + Math.round(wave(700) * 900), 'RPM'); S('fan', 'Fan tray 2', 4100 + Math.round(wave(800, 4) * 900), 'RPM');
  S('power', 'Power supply A', null, '', 'ok', 'ok');
  if (d.name === 'dc-leaf-11') S('power', 'Power supply B', null, '', 'bad', 'not functioning'); else S('power', 'Power supply B', null, '', 'ok', 'ok');
  S('voltage', '12 V rail', 12.02, 'V');
  // 10 G ports carry optics: the second uplink of the distribution switch has a weak receive level
  for (const i of d.ifs.filter(x => x[2] >= 10000 && !/^V/i.test(x[0]))) {
    const weak = d.name === 'dist-sw-01' && i[0] === 'Te1/0/2';
    S('optic', `${i[0]} Transmit Power`, -2.1 + Math.round(wave(900, k) * 4) / 10, 'dBm', 'ok', 'ok', { optic: 'tx' });
    S('optic', `${i[0]} Receive Power`, weak ? -14.6 : -5.3 + Math.round(wave(1100, k) * 6) / 10, 'dBm', weak ? 'warn' : 'ok', weak ? 'over a minor limit' : 'ok', { optic: 'rx' });
    S('optic', `${i[0]} Module Temperature`, 34 + Math.round(wave(1500) * 50) / 10, '°C', 'ok', 'ok', { optic: 'temp' });
  }
  if (d.name === 'dist-sw-01') {
    h.poe = [{ group: 1, budgetW: 740, usedW: 205 + Math.round(wave(600) * 40), usedPct: 0, status: 'on', portsDelivering: 3, portsFault: 0, portsTotal: 24 }];
    h.poe[0].usedPct = Math.round((h.poe[0].usedW! / 740) * 1000) / 10;
    h.stp = { rootId: '32768/00:1c:73:00:00:11', isRoot: false, rootPort: 3, rootCost: 4, topChanges: 17, sinceChangeSec: 3 * 86400 + 7200, blockingPorts: 1, ports: 12 };
  } else if (d.name === 'dc-spine-01') h.stp = { rootId: '4096/' + d.mac, isRoot: true, rootPort: 0, rootCost: 0, topChanges: 4, sinceChangeSec: 9 * 86400, blockingPorts: 0, ports: 8 };
  else if (d.role === 'switch') h.stp = { rootId: '4096/00:1c:73:00:01:01', isRoot: false, rootPort: 1, rootCost: 4, topChanges: 6, sinceChangeSec: 5 * 86400, blockingPorts: 0, ports: 6 };
  if (d.name === 'core-rtr-01') h.ospf = [{ id: '10.255.0.2', address: '10.0.0.2', state: 'full', level: 'ok' }, { id: '10.255.0.5', address: '10.0.0.6', state: 'full', level: 'ok' }, { id: '10.255.0.9', address: '10.0.0.10', state: 'full', level: 'ok' }];
  if (d.name === 'core-rtr-01') {
    h.eigrp = [{ as: 1971, address: '10.0.0.14', ifIndex: 2, holdSec: 13, upText: '3w1d', srttMs: 1, retrans: 15, retries: 0, level: 'ok' }, { as: 1971, address: '10.0.0.18', ifIndex: 3, holdSec: 11, upText: '5d02h', srttMs: 4, retrans: 212, retries: 2, level: 'warn' }];
    h.bfd = [{ id: 393217, address: '10.0.0.14', ifIndex: 2, state: 'up', level: 'ok', upSec: 21 * 86400, upCount: 1, diag: null, detectMs: 1500 }, { id: 393219, address: '10.0.0.18', ifIndex: 3, state: 'up', level: 'ok', upSec: 5 * 86400, upCount: 3, diag: 'control detection time expired', detectMs: 1500 }];
  }
  if (d.name === 'wan-rtr-01') {
    h.ospf = [{ id: '10.255.0.1', address: '10.0.0.9', state: 'full', level: 'ok' }];
    h.bgpLocalAs = 65010;
    h.bgp = [
      { address: '203.0.113.1', as: 64500, state: 'established', level: 'ok', admin: 'start', upSec: 12 * 86400, updatesIn: 912_440, updatesOut: 4_120 },
      { address: '198.51.100.1', as: 64501, state: 'active', level: 'warn', admin: 'start', upSec: null, updatesIn: 88_120, updatesOut: 3_904 }
    ];
  }
  return h;
}

/** How fast each link quality counter grows (per second) at time t. One port has a duplex mismatch and one carries bursts of broadcast; busy ports drop packets now and then. */
function exRates(d: Dev, i: Ifc, t: number): Record<ExtraCounter, number> {
  const mismatch = d.name === 'dist-sw-01' && i[0] === 'Gi1/0/16', storm = d.name === 'dist-sw-01' && i[0] === 'Gi1/0/24';
  const k = [...(d.name + i[0])].reduce((a, c) => a + c.charCodeAt(0), 0);
  const sec = t / 1000;
  const wave = (period: number, ph = 0) => (Math.sin((sec + ph + k * 31) / period) + 1) / 2;
  const mc = (i[2] >= 10000 ? 40 : 3) * (0.7 + 0.6 * wave(3000));
  const bc = storm ? (wave(2400, 5) > 0.88 ? 2400 + 600 * wave(120) : 60 + 30 * wave(300)) : 2 * (0.6 + 0.8 * wave(1800));
  const fcs = mismatch ? 0.9 * (0.3 + wave(900, 3)) : wave(7000) > 0.985 ? 0.08 : 0;
  const align = mismatch ? 0.25 * (0.3 + wave(900, 9)) : 0, late = mismatch ? 0.06 * (0.3 + wave(900, 5)) : 0;
  const busy = Math.max(0, i[4] - 38);
  const outDisc = busy ? busy * 0.12 * (0.2 + wave(700)) : wave(9000) > 0.99 ? 0.02 : 0;
  return {
    fcs, align, symbol: 0, late, excessive: 0, collisions: mismatch ? 0.4 * (0.3 + wave(900, 7)) : 0, carrier: 0, tooLong: 0, unknown: 0.002 * (1 + wave(4000)),
    inMc: mc, inBc: bc, outMc: 2 * (0.7 + 0.6 * wave(2500)), outBc: storm ? bc * 0.3 : 1 * (0.6 + 0.8 * wave(2100)),
    inErr: fcs + align, outErr: mismatch ? late : 0, inDisc: wave(11000) > 0.99 ? 0.01 : 0, outDisc,
    outQDrops: busy ? outDisc * 0.8 : 0, inQDrops: 0, resets: 0, storm: storm && bc > 1000 ? bc * 0.05 : 0, portSec: 0
  };
}
const EXACC = new Map<string, { t: number; v: Record<string, number> }>();

/** Link quality counters that grow with time, so the change between two reads is a rate. Each counter is the sum of its rate so far, so the history has ups and downs. */
function demoIfExtra(d: Dev, ifIndex: (name: string) => number | undefined, now: number): Map<number, IfExtra> {
  const out = new Map<number, IfExtra>();
  for (const i of d.ifs) {
    const ix = ifIndex(i[0]); if (ix === undefined || /^V/i.test(i[0])) continue;
    const key = d.name + '|' + i[0];
    let st = EXACC.get(key);
    if (!st) {
      // counters have been running for a few days, not since 1970
      const r = exRates(d, i, now), v: Record<string, number> = {};
      for (const c of EXTRA_COUNTERS) v[c] = r[c] * 4 * 86400 + ix * 7;
      st = { t: now, v }; EXACC.set(key, st);
    }
    // step through the time since the last call, in steps of at most a minute, so a burst is not averaged away
    for (let t = st.t; t < now; t += 60_000) { const e = Math.min(now, t + 60_000), r = exRates(d, i, (t + e) / 2); for (const c of EXTRA_COUNTERS) st.v[c] += r[c] * (e - t) / 1000; }
    st.t = Math.max(st.t, now);
    const totals: Partial<Record<ExtraCounter, number>> = {};
    for (const c of EXTRA_COUNTERS) totals[c] = Math.round(st.v[c]);
    const mismatch = d.name === 'dist-sw-01' && i[0] === 'Gi1/0/16';
    out.set(ix, { duplex: mismatch ? 'half' : 'full', admin: 1, delta: null, dtSec: null, readAt: now, totals });
  }
  return out;
}

const DEVS: Dev[] = [
  { name: 'wifi-ctl-01', ip: '10.255.0.30', role: 'ap', descr: 'Wireless access points, floor 4', secs: 60, mac: '00:1c:73:00:00:30', ifs: [['Gi0', 'Uplink to dist-sw-01', 1000, null, 9, 6]] },
  { name: 'dist-sw-01', ip: '10.255.0.2', role: 'switch', descr: 'Distribution switch', secs: 60, mac: '00:1c:73:00:00:02', ifs: [
    ['Vl140', 'VLAN 140 CAMPUS-USERS (SVI)', 10000, null, 12, 9], ['Vl150', 'VLAN 150 CAMPUS-WIFI (SVI)', 10000, null, 7, 6],
    ['Te1/0/1', 'Uplink to core-rtr-01', 10000, 'CORE-OUT', 31, 28], ['Te1/0/2', 'Uplink to core-rtr-01 (DC path)', 10000, 'CORE-OUT', 22, 35],
    ['Gi1/0/12', 'Desk 4-21 (PC and phone)', 1000, null, 4, 2], ['Gi1/0/14', 'Desk 4-33', 1000, null, 3, 1], ['Gi1/0/15', 'Lab bench 60', 1000, null, 2, 1],
    ['Gi1/0/16', 'Printer room', 1000, null, 1, 1], ['Gi1/0/20', 'Wireless AP, floor 4', 1000, null, 9, 6], ['Gi1/0/24', 'Meeting room 4B (video)', 1000, null, 6, 1]] },
  { name: 'core-rtr-01', ip: '10.255.0.1', role: 'router', descr: 'Core router', secs: 60, mac: '00:1c:73:00:00:01', ifs: [
    ['Te0/0/0', 'Downlink to dist-sw-01', 10000, 'CORE-OUT', 38, 33], ['Te0/0/1', 'Link to DC fabric', 10000, 'CORE-OUT', 44, 41],
    ['Te0/0/2', 'Link to fw-edge-01', 10000, 'CORE-OUT', 27, 30], ['Te0/0/3', 'Link to wan-rtr-01', 1000, 'WAN-OUT', 71, 64], ['Lo0', 'Loopback', 0, null, 0, 0]] },
  { name: 'fw-edge-01', ip: '10.255.0.5', role: 'firewall', descr: 'Edge firewall', secs: 60, mac: '00:1c:73:00:00:05', ifs: [
    ['Eth1/1', 'Inside, to core-rtr-01', 10000, null, 27, 30], ['Eth1/2', 'Outside, to ISP', 1000, 'FW-OUT', 58, 49]] },
  { name: 'dc-leaf-07', ip: '10.255.1.7', role: 'switch', descr: 'Data center leaf', secs: 60, mac: '00:1c:73:00:01:07', ifs: [
    ['Vl310', 'VLAN 310 DC-APPS (SVI)', 10000, null, 40, 36], ['Eth1/49', 'Uplink to core-rtr-01', 40000, 'DC-FABRIC-OUT', 52, 47], ['Eth1/52', 'Uplink to dc-spine-01', 40000, 'DC-FABRIC-OUT', 61, 58],
    ['Eth1/10', 'db-prod-05', 10000, null, 12, 14], ['Eth1/11', 'app-prod-12', 10000, null, 8, 9], ['Eth1/12', 'media-enc-30 (multicast source)', 10000, null, 18, 2]] },
  { name: 'dc-leaf-11', ip: '10.255.1.11', role: 'switch', descr: 'Data center leaf', secs: 60, mac: '00:1c:73:00:01:0b', ifs: [
    ['Eth1/49', 'Uplink to dc-spine-01', 40000, 'DC-FABRIC-OUT', 33, 36], ['Vl320', 'VLAN 320 DC-DATABASE (SVI)', 10000, null, 22, 25],
    ['Eth1/10', 'queue-svc-30', 10000, null, 6, 7], ['Eth1/20', 'Multicast receivers', 10000, null, 9, 1]] },
  { name: 'dc-spine-01', ip: '10.255.1.1', role: 'switch', descr: 'Data center spine', secs: 60, mac: '00:1c:73:00:01:01', ifs: [
    ['Eth1/7', 'Downlink to dc-leaf-07', 40000, 'DC-FABRIC-OUT', 59, 62], ['Eth1/9', 'Downlink to dc-leaf-11', 40000, 'DC-FABRIC-OUT', 35, 33]] },
  { name: 'wan-rtr-01', ip: '10.255.0.9', role: 'router', descr: 'WAN aggregation router', secs: 60, mac: '00:1c:73:00:00:09', ifs: [
    ['Tu100', 'Tunnel to br-rtr-02', 1000, 'WAN-OUT', 66, 72], ['Gi0/0/0', 'Link to core-rtr-01', 1000, 'WAN-OUT', 64, 71]] },
  { name: 'br-rtr-02', ip: '10.255.2.2', role: 'router', descr: 'Branch router', secs: 300, mac: '00:1c:73:00:02:02', ifs: [
    ['Gi0/0/1', 'Branch LAN, VLAN 200 BRANCH-LAN', 1000, null, 28, 31], ['Tu100', 'WAN tunnel to wan-rtr-01', 200, 'WAN-OUT', 94, 61]] }
];

// class: [name, queue, matched DSCP values, guarantee]
const POLICIES: Record<string, [string, string, number[], string][]> = {
  'CORE-OUT': [['VOICE', 'Q0 · strict priority', [46], '10%'], ['VIDEO', 'Q1', [34], '25%'], ['CRITICAL', 'Q2', [18], '30%'], ['BULK', 'Q3', [10], '5%'], ['DEFAULT', 'Q4 · class-default', [], 'remainder']],
  'WAN-OUT': [['VOICE', 'Q0 · strict priority', [46], '20%'], ['VIDEO', 'Q1', [34], '25%'], ['SIGNALING', 'Q2', [24], '5%'], ['CRITICAL', 'Q3', [18], '30%'], ['BULK', 'Q4', [10], '5%'], ['DEFAULT', 'Q5 · class-default', [], 'remainder']],
  'DC-FABRIC-OUT': [['REPLICATION', 'Q1', [26], '30%'], ['CRITICAL', 'Q2', [18], '30%'], ['BULK', 'Q3', [10], '10%'], ['DEFAULT', 'Q4 · class-default', [], 'remainder']],
  'FW-OUT': [['VOICE', 'Q0 · strict priority', [46], '10%'], ['CRITICAL', 'Q1', [18], '40%'], ['DEFAULT', 'Q2 · class-default', [], 'remainder']]
};
const SHARE: Record<string, number> = { VOICE: 0.03, VIDEO: 0.08, SIGNALING: 0.01, CRITICAL: 0.35, REPLICATION: 0.3, BULK: 0.12, DEFAULT: 0.25 };
/** A voice queue running close to its priority limit (dist side of the WAN) */
const HOT_SHARE: Record<string, number> = { 'wan-rtr-01|Gi0/0/0|VOICE': 0.44 };
const OVERRIDE: Record<string, { drop: number; depth: number; mode: 'burst' | 'ramp' }> = {
  'dc-leaf-07|Eth1/49|BULK': { drop: 2.4, depth: 212, mode: 'burst' },
  'core-rtr-01|Te0/0/3|DEFAULT': { drop: 1.2, depth: 96, mode: 'ramp' },
  'br-rtr-02|Tu100|CRITICAL': { drop: 0.3, depth: 148, mode: 'burst' },
  'br-rtr-02|Tu100|DEFAULT': { drop: 0.6, depth: 74, mode: 'burst' }
};
const VLANS: [number, string][] = [[140, 'CAMPUS-USERS'], [150, 'CAMPUS-WIFI'], [160, 'CAMPUS-VOICE'], [200, 'BRANCH-LAN'], [310, 'DC-APPS'], [320, 'DC-DATABASE']];

// Switch port settings that SNMP would report: "dev|interface" -> mode, VLAN (access or native), voice VLAN and the VLANs a trunk allows
const PORTINFO: Record<string, { mode: 'access' | 'trunk' | 'routed'; vlan: number; voice?: number; list?: string }> = {
  'dist-sw-01|Te1/0/1': { mode: 'trunk', vlan: 1, list: '140,150,160' }, 'dist-sw-01|Te1/0/2': { mode: 'trunk', vlan: 1, list: '140,150,160' },
  'dist-sw-01|Gi1/0/12': { mode: 'access', vlan: 140, voice: 160 }, 'dist-sw-01|Gi1/0/14': { mode: 'access', vlan: 140 }, 'dist-sw-01|Gi1/0/15': { mode: 'access', vlan: 140 },
  'dist-sw-01|Gi1/0/16': { mode: 'access', vlan: 140 }, 'dist-sw-01|Gi1/0/20': { mode: 'access', vlan: 150 }, 'dist-sw-01|Gi1/0/24': { mode: 'access', vlan: 140 },
  'dc-leaf-07|Eth1/49': { mode: 'trunk', vlan: 1, list: '310,320' }, 'dc-leaf-07|Eth1/52': { mode: 'trunk', vlan: 1, list: '310,320' },
  'dc-leaf-07|Eth1/10': { mode: 'access', vlan: 310 }, 'dc-leaf-07|Eth1/11': { mode: 'access', vlan: 310 }, 'dc-leaf-07|Eth1/12': { mode: 'access', vlan: 310 },
  'dc-leaf-11|Eth1/49': { mode: 'trunk', vlan: 1, list: '310,320' }, 'dc-leaf-11|Eth1/10': { mode: 'access', vlan: 320 }, 'dc-leaf-11|Eth1/20': { mode: 'access', vlan: 320 },
  'dc-spine-01|Eth1/7': { mode: 'routed', vlan: 0 }, 'dc-spine-01|Eth1/9': { mode: 'routed', vlan: 0 }
};
/** Input service policies (class names carry the "in:" prefix the collector uses). */
const POLICY_IN: Record<string, string> = { 'dist-sw-01|Gi1/0/12': 'ACCESS-IN', 'dist-sw-01|Gi1/0/24': 'ACCESS-IN' };
const IN_POLICIES: Record<string, [string, number[], string][]> = { 'ACCESS-IN': [['VOICE-MARK', [46], 'police 1 Mbps'], ['VIDEO-MARK', [34], 'police 20 Mbps'], ['class-default', [], 'remainder']] };

// Hosts plugged in to switch ports: the MAC address tables, ARP and LLDP data that host tracking reads
const HOSTS: { ip: string; dev: string; port: string; vlan: number; l3: string; name?: string }[] = [
  { ip: '10.1.4.21', dev: 'dist-sw-01', port: 'Gi1/0/12', vlan: 140, l3: 'dist-sw-01' }, { ip: '10.1.8.21', dev: 'dist-sw-01', port: 'Gi1/0/12', vlan: 160, l3: 'dist-sw-01', name: 'SEP00505601080015' },
  { ip: '10.1.4.33', dev: 'dist-sw-01', port: 'Gi1/0/14', vlan: 140, l3: 'dist-sw-01' }, { ip: '10.1.4.60', dev: 'dist-sw-01', port: 'Gi1/0/15', vlan: 140, l3: 'dist-sw-01' },
  { ip: '10.1.4.50', dev: 'dist-sw-01', port: 'Gi1/0/16', vlan: 140, l3: 'dist-sw-01' }, { ip: '10.1.7.88', dev: 'dist-sw-01', port: 'Gi1/0/20', vlan: 150, l3: 'dist-sw-01' },
  { ip: '10.1.7.19', dev: 'dist-sw-01', port: 'Gi1/0/20', vlan: 150, l3: 'dist-sw-01' },
  { ip: '10.9.0.5', dev: 'dc-leaf-07', port: 'Eth1/10', vlan: 310, l3: 'dc-leaf-07' }, { ip: '10.9.0.12', dev: 'dc-leaf-07', port: 'Eth1/11', vlan: 310, l3: 'dc-leaf-07' },
  { ip: '10.9.0.30', dev: 'dc-leaf-07', port: 'Eth1/12', vlan: 310, l3: 'dc-leaf-07' }, { ip: '10.9.2.30', dev: 'dc-leaf-11', port: 'Eth1/10', vlan: 320, l3: 'dc-leaf-11' }
];
// LLDP / CDP neighbours: "dev|interface" -> [protocol, remote name, remote port, kind, capabilities]
const NEIGHBORS: Record<string, [string, string, string, string, string]> = {
  'dist-sw-01|Te1/0/1': ['lldp', 'core-rtr-01', 'Te0/0/0', 'infra', 'bridge,router'], 'dist-sw-01|Te1/0/2': ['lldp', 'core-rtr-01', 'Te0/0/4', 'infra', 'bridge,router'],
  'dist-sw-01|Gi1/0/12': ['lldp', 'SEP00505601080015', 'Port 1', 'phone', 'telephone'], 'dist-sw-01|Gi1/0/20': ['lldp', 'ap-4f-02', 'Gi0', 'ap', 'wlan-ap'],
  'dc-leaf-07|Eth1/49': ['lldp', 'core-rtr-01', 'Te0/0/1', 'infra', 'bridge,router'], 'dc-leaf-07|Eth1/52': ['lldp', 'dc-spine-01', 'Eth1/7', 'infra', 'bridge,router'],
  'dc-leaf-11|Eth1/49': ['lldp', 'dc-spine-01', 'Eth1/9', 'infra', 'bridge,router'],
  'dc-spine-01|Eth1/7': ['lldp', 'dc-leaf-07', 'Eth1/52', 'infra', 'bridge,router'], 'dc-spine-01|Eth1/9': ['lldp', 'dc-leaf-11', 'Eth1/49', 'infra', 'bridge,router']
};
// Addresses a switch has learned through an uplink rather than on a host port: [learning switch, uplink, host IP]
const LEARNED_VIA: [string, string, string][] = [['dc-leaf-07', 'Eth1/52', '10.9.2.30'], ['dc-leaf-11', 'Eth1/49', '10.9.0.30'], ['dc-leaf-11', 'Eth1/49', '10.9.0.5'], ['dc-leaf-11', 'Eth1/49', '10.9.0.12']];

// path hop: [device, ingress interface ('@v' = the VLAN's SVI), egress interface, link latency in ms from the previous hop]
type Hop = [string, string, string, number];
const PATHS: Record<string, Hop[]> = {
  A: [['dist-sw-01', '@v', 'Te1/0/1', 0], ['core-rtr-01', 'Te0/0/0', 'Te0/0/2', 0.4], ['fw-edge-01', 'Eth1/1', 'Eth1/2', 0.3]],
  B: [['dist-sw-01', '@v', 'Te1/0/2', 0], ['core-rtr-01', 'Te0/0/0', 'Te0/0/1', 0.4], ['dc-leaf-07', 'Eth1/49', 'Vl310', 0.6]],
  C: [['br-rtr-02', 'Gi0/0/1', 'Tu100', 0], ['wan-rtr-01', 'Tu100', 'Gi0/0/0', 18.2], ['core-rtr-01', 'Te0/0/3', 'Te0/0/1', 0.5], ['dc-leaf-07', 'Eth1/49', 'Vl310', 0.6]],
  D: [['dc-leaf-07', 'Vl310', 'Eth1/52', 0], ['dc-spine-01', 'Eth1/7', 'Eth1/9', 0.2], ['dc-leaf-11', 'Eth1/49', 'Vl320', 0.2]],
  E: [['dc-leaf-07', 'Vl310', 'Eth1/49', 0], ['core-rtr-01', 'Te0/0/1', 'Te0/0/2', 0.6], ['fw-edge-01', 'Eth1/1', 'Eth1/2', 0.3]],
  F: [['dist-sw-01', '@v', 'Te1/0/1', 0], ['core-rtr-01', 'Te0/0/0', 'Lo0', 0.4]],
  // multicast: the same stream seen on both branches of the tree (dc-leaf-07 replicates it to two uplinks)
  M1: [['dc-leaf-07', 'Eth1/12', 'Eth1/49', 0], ['core-rtr-01', 'Te0/0/1', 'Te0/0/0', 0.6], ['dist-sw-01', 'Te1/0/2', 'Gi1/0/24', 0.4]],
  M2: [['dc-leaf-07', 'Eth1/12', 'Eth1/52', 0], ['dc-spine-01', 'Eth1/7', 'Eth1/9', 0.2], ['dc-leaf-11', 'Eth1/49', 'Eth1/20', 0.2]],
  G: [['br-rtr-02', 'Gi0/0/1', 'Tu100', 0], ['wan-rtr-01', 'Tu100', 'Gi0/0/0', 18.2], ['core-rtr-01', 'Te0/0/3', 'Te0/0/2', 0.5], ['fw-edge-01', 'Eth1/1', 'Eth1/2', 0.3]]
};

const TCP = 6, UDP = 17, ICMP = 1;
const FL: Record<string, number> = { FIN: 1, SYN: 2, RST: 4, PSH: 8, ACK: 16 };
const flagBits = (s: string) => s.split(' ').filter(Boolean).reduce((a, f) => a | (FL[f] ?? 0), 0);

interface Spec {
  src: string; dst: string; proto: number; sport: number; dport: number; vlan: number; fB: number; rB: number; fP: number; rP: number; path: string; rev: boolean;
  agoMin: number; durSec: number; flags: string; dscp: number; dscpR?: number;
  /** First-seen TTL at the first hop is ttl0 - 1. A small value makes the traffic run out of TTL along the path. */
  ttl0?: number;
  /** Only the first n hops of the path are seen (the stream does not get any further). */
  hops?: number;
  loss?: [number, number, 'i' | 'r']; slow?: [number, number]; remark?: [number, number, 'i' | 'r' | 'b'];
}
const SAMPLE: Spec[] = [
  { src: '10.1.4.21', dst: '198.51.100.40', proto: TCP, sport: 51522, dport: 443, vlan: 140, fB: 184200, rB: 3320000, fP: 1200, rP: 2650, path: 'A', rev: false, agoMin: 1, durSec: 42, flags: 'SYN ACK PSH FIN', dscp: 0 },
  { src: '10.1.4.33', dst: '192.0.2.53', proto: UDP, sport: 49311, dport: 53, vlan: 140, fB: 1450, rB: 3920, fP: 22, rP: 22, path: 'A', rev: false, agoMin: 1, durSec: 1, flags: '', dscp: 0 },
  { src: '10.1.4.21', dst: '10.9.0.5', proto: TCP, sport: 50002, dport: 5432, vlan: 140, fB: 922000, rB: 14800000, fP: 1800, rP: 11000, path: 'B', rev: false, agoMin: 2, durSec: 311, flags: 'SYN ACK PSH', dscp: 18, remark: [1, 0, 'i'] },
  { src: '10.1.7.88', dst: '10.9.0.12', proto: TCP, sport: 61004, dport: 445, vlan: 150, fB: 2100000, rB: 88400000, fP: 2300, rP: 62000, path: 'B', rev: false, agoMin: 3, durSec: 129, flags: 'SYN ACK PSH FIN', dscp: 10, loss: [2, 2.4, 'r'], remark: [1, 0, 'r'] },
  { src: '10.20.3.14', dst: '10.9.0.12', proto: TCP, sport: 55871, dport: 443, vlan: 200, fB: 312000, rB: 4820000, fP: 380, rP: 3600, path: 'C', rev: false, agoMin: 4, durSec: 87, flags: 'SYN ACK PSH FIN', dscp: 0, slow: [1, 38] },
  { src: '10.20.3.14', dst: '10.9.0.5', proto: TCP, sport: 55872, dport: 5432, vlan: 200, fB: 640000, rB: 9800000, fP: 900, rP: 7400, path: 'C', rev: false, agoMin: 4, durSec: 203, flags: 'SYN ACK PSH', dscp: 18, slow: [1, 38] },
  { src: '10.9.0.5', dst: '10.9.2.30', proto: TCP, sport: 40123, dport: 9092, vlan: 310, fB: 412000000, rB: 9100000, fP: 310000, rP: 98000, path: 'D', rev: false, agoMin: 1, durSec: 3540, flags: 'SYN ACK PSH', dscp: 26 },
  { src: '10.9.2.30', dst: '10.9.0.5', proto: TCP, sport: 40890, dport: 5432, vlan: 320, fB: 5200000, rB: 61000000, fP: 6100, rP: 47000, path: 'D', rev: true, agoMin: 2, durSec: 640, flags: 'SYN ACK PSH', dscp: 18 },
  { src: '10.9.0.12', dst: '198.51.100.77', proto: TCP, sport: 44312, dport: 443, vlan: 310, fB: 96000, rB: 1900000, fP: 420, rP: 1500, path: 'E', rev: false, agoMin: 7, durSec: 18, flags: 'SYN ACK PSH FIN', dscp: 0 },
  { src: '10.1.4.60', dst: '10.9.0.20', proto: TCP, sport: 50220, dport: 22, vlan: 140, fB: 48000, rB: 310000, fP: 520, rP: 640, path: 'B', rev: false, agoMin: 3, durSec: 1280, flags: 'SYN ACK PSH', dscp: 16 },
  { src: '10.1.4.60', dst: '10.255.0.1', proto: ICMP, sport: 0, dport: 0, vlan: 140, fB: 4000, rB: 4000, fP: 50, rP: 50, path: 'F', rev: false, agoMin: 6, durSec: 49, flags: '', dscp: 0 },
  { src: '10.1.9.15', dst: '192.0.2.123', proto: UDP, sport: 123, dport: 123, vlan: 140, fB: 380, rB: 380, fP: 5, rP: 5, path: 'A', rev: false, agoMin: 9, durSec: 256, flags: '', dscp: 0 },
  { src: '10.1.7.19', dst: '198.51.100.200', proto: TCP, sport: 52311, dport: 443, vlan: 150, fB: 88000, rB: 2400000, fP: 610, rP: 1900, path: 'A', rev: false, agoMin: 5, durSec: 33, flags: 'SYN ACK PSH FIN', dscp: 0 },
  { src: '10.1.7.19', dst: '198.51.100.201', proto: TCP, sport: 52312, dport: 443, vlan: 150, fB: 64000, rB: 1100000, fP: 420, rP: 980, path: 'A', rev: false, agoMin: 5, durSec: 31, flags: 'SYN ACK PSH FIN', dscp: 0 },
  { src: '10.20.5.7', dst: '10.9.0.30', proto: UDP, sport: 5060, dport: 5060, vlan: 200, fB: 52000, rB: 48000, fP: 160, rP: 150, path: 'C', rev: false, agoMin: 2, durSec: 415, flags: '', dscp: 24, slow: [1, 38], remark: [1, 0, 'i'] },
  { src: '10.9.0.30', dst: '10.20.5.7', proto: UDP, sport: 16384, dport: 16390, vlan: 310, fB: 9200000, rB: 9100000, fP: 46000, rP: 45500, path: 'C', rev: true, agoMin: 2, durSec: 414, flags: '', dscp: 46, loss: [2, 1.2, 'i'], slow: [1, 38], remark: [2, 0, 'i'] },
  { src: '10.1.4.33', dst: '10.9.0.8', proto: TCP, sport: 49800, dport: 3389, vlan: 140, fB: 2200000, rB: 41000000, fP: 9100, rP: 33000, path: 'B', rev: false, agoMin: 8, durSec: 1860, flags: 'SYN ACK PSH', dscp: 34, remark: [1, 18, 'i'] },
  { src: '10.9.0.9', dst: '10.9.2.40', proto: UDP, sport: 51234, dport: 514, vlan: 310, fB: 830000, rB: 0, fP: 2100, rP: 0, path: 'D', rev: false, agoMin: 2, durSec: 3590, flags: '', dscp: 0 },
  { src: '10.1.4.77', dst: '198.51.100.5', proto: TCP, sport: 50910, dport: 80, vlan: 140, fB: 22000, rB: 640000, fP: 160, rP: 540, path: 'A', rev: false, agoMin: 10, durSec: 12, flags: 'SYN ACK PSH FIN', dscp: 0 },
  { src: '10.1.7.88', dst: '198.51.100.40', proto: TCP, sport: 53500, dport: 443, vlan: 150, fB: 310000, rB: 5200000, fP: 980, rP: 4100, path: 'A', rev: false, agoMin: 12, durSec: 64, flags: 'SYN ACK PSH FIN', dscp: 0 },
  { src: '10.1.4.21', dst: '10.9.0.5', proto: TCP, sport: 50003, dport: 5432, vlan: 140, fB: 410000, rB: 6200000, fP: 820, rP: 5200, path: 'B', rev: false, agoMin: 15, durSec: 188, flags: 'SYN ACK PSH', dscp: 18 },
  { src: '10.9.0.5', dst: '10.1.4.21', proto: TCP, sport: 38211, dport: 8080, vlan: 310, fB: 18000, rB: 92000, fP: 60, rP: 110, path: 'B', rev: true, agoMin: 16, durSec: 22, flags: 'SYN ACK PSH FIN', dscp: 0 },
  { src: '10.1.4.90', dst: '10.9.0.12', proto: TCP, sport: 49002, dport: 443, vlan: 140, fB: 71000, rB: 1300000, fP: 300, rP: 1100, path: 'B', rev: false, agoMin: 130, durSec: 51, flags: 'SYN ACK PSH FIN', dscp: 0 },
  { src: '10.1.9.4', dst: '192.0.2.88', proto: UDP, sport: 51000, dport: 443, vlan: 140, fB: 2400000, rB: 38000000, fP: 2100, rP: 31000, path: 'A', rev: false, agoMin: 300, durSec: 92, flags: '', dscp: 0 },
  { src: '10.20.3.40', dst: '198.51.100.40', proto: TCP, sport: 56001, dport: 443, vlan: 200, fB: 140000, rB: 2300000, fP: 420, rP: 1800, path: 'G', rev: false, agoMin: 9, durSec: 60, flags: 'SYN ACK PSH FIN', dscp: 0 },
  // TTL: traffic that runs out of TTL before the destination, and look-alikes that must not be flagged
  { src: '10.1.4.60', dst: '198.51.100.40', proto: UDP, sport: 40001, dport: 33434, vlan: 140, fB: 180, rB: 0, fP: 3, rP: 0, path: 'A', rev: false, agoMin: 2, durSec: 1, flags: '', dscp: 0, ttl0: 4 },
  { src: '10.20.3.88', dst: '10.9.0.12', proto: TCP, sport: 52044, dport: 443, vlan: 200, fB: 3600, rB: 0, fP: 60, rP: 0, path: 'C', rev: false, agoMin: 3, durSec: 30, flags: 'SYN', dscp: 0, ttl0: 3, hops: 2 },
  { src: '10.255.0.1', dst: '10.1.4.77', proto: ICMP, sport: 0, dport: 2816, vlan: 140, fB: 336, rB: 0, fP: 3, rP: 0, path: 'F', rev: true, agoMin: 2, durSec: 1, flags: '', dscp: 0, ttl0: 65 },
  { src: '10.1.4.50', dst: '224.0.0.251', proto: UDP, sport: 5353, dport: 5353, vlan: 140, fB: 2400, rB: 0, fP: 24, rP: 0, path: 'F', rev: false, agoMin: 4, durSec: 120, flags: '', dscp: 0, ttl0: 2, hops: 1 },
  { src: '10.1.4.52', dst: '239.255.255.250', proto: UDP, sport: 51900, dport: 1900, vlan: 140, fB: 1300, rB: 0, fP: 6, rP: 0, path: 'F', rev: false, agoMin: 3, durSec: 60, flags: '', dscp: 0, ttl0: 2, hops: 1 },
  { src: '10.1.4.61', dst: '10.255.0.1', proto: TCP, sport: 50881, dport: 22, vlan: 140, fB: 5200, rB: 0, fP: 44, rP: 0, path: 'F', rev: false, agoMin: 4, durSec: 90, flags: 'SYN ACK PSH', dscp: 16, ttl0: 2 },
  // multicast video from media-enc-30: every device on the tree reports the same packets; the source host is on dc-leaf-07 Eth1/12
  { src: '10.9.0.30', dst: '239.10.20.30', proto: UDP, sport: 40500, dport: 5004, vlan: 310, fB: 84000000, rB: 0, fP: 64000, rP: 0, path: 'M1', rev: false, agoMin: 12, durSec: 540, flags: '', dscp: 34, ttl0: 16 },
  { src: '10.9.0.30', dst: '239.10.20.30', proto: UDP, sport: 40500, dport: 5004, vlan: 310, fB: 84000000, rB: 0, fP: 64000, rP: 0, path: 'M2', rev: false, agoMin: 12, durSec: 540, flags: '', dscp: 34, ttl0: 16 },
  { src: '10.20.3.14', dst: '10.9.0.12', proto: TCP, sport: 55880, dport: 445, vlan: 200, fB: 1100000, rB: 22000000, fP: 1400, rP: 16000, path: 'C', rev: false, agoMin: 11, durSec: 95, flags: 'SYN ACK PSH FIN', dscp: 10, slow: [1, 38] }
];

/** Small deterministic random generator so a demo looks the same each time it is seeded. */
function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => { s = (s + 0x6D2B79F5) >>> 0; let t = s; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}

function hostMac(ip: string): string {
  const p = ip.split('.').map(Number);
  return ['00', '50', '56', ...p.slice(1).map(n => n.toString(16).padStart(2, '0'))].join(':');
}

class Net {
  ids = new Map<string, number>();            // device name -> id
  ifIdx = new Map<string, number>();          // "dev|ifname" -> ifIndex
  byName = new Map(DEVS.map(d => [d.name, d]));
  idx(dev: string, ifn: string): number { return this.ifIdx.get(dev + '|' + ifn) ?? 0; }
}

function makeRecords(net: Net, sp: Spec, startMs: number, r: () => number): FlowRecord[] {
  const out: FlowRecord[] = [];
  const base = PATHS[sp.path].slice(0, sp.hops ?? undefined);
  const ttl0 = sp.ttl0 ?? (sp.dport === 445 || sp.dport === 3389 ? 128 : 64);
  const mkDir = (fwd: boolean) => {
    const natural = sp.rev ? !fwd : fwd;
    const hops = natural ? base.map(h => ({ dev: h[0], inn: h[1], out: h[2], ms: h[3] })) : base.slice().reverse().map((h, i, a) => ({ dev: h[0], inn: h[2], out: i === a.length - 1 ? '@v' : h[1], ms: h[3] }));
    // in the reverse direction the ingress of the first hop is the egress of the last natural hop; the link delay stays attached to each device
    const src = fwd ? sp.src : sp.dst, dst = fwd ? sp.dst : sp.src, sport = fwd ? sp.sport : sp.dport, dport = fwd ? sp.dport : sp.sport;
    let pkts = fwd ? sp.fP : sp.rP, bytes = fwd ? sp.fB : sp.rB;
    if (!pkts) return;
    let dscp = fwd ? sp.dscp : sp.dscpR ?? (sp.dscp === 0 ? 0 : sp.dscp);
    const dirTag = fwd ? 'i' : 'r';
    let t = startMs + (fwd ? 0 : 3);
    let prevMac = hostMac(src);
    const ratio = bytes / pkts;
    hops.forEach((h, i) => {
      const dev = net.byName.get(h.dev)!;
      let ms = h.ms;
      if (sp.slow && sp.slow[0] === i) ms = sp.slow[1];
      if (i > 0) t += Math.round(ms);
      if (sp.loss && sp.loss[2] === dirTag && sp.loss[0] === i) { const keep = 1 - sp.loss[1] / 100; pkts = Math.max(1, Math.round(pkts * keep)); bytes = Math.round(pkts * ratio); }
      const inName = h.inn === '@v' ? 'Vl' + sp.vlan : h.inn, outName = h.out === '@v' ? 'Vl' + sp.vlan : h.out;
      const inIf = net.idx(h.dev, inName) || net.idx(h.dev, h.inn);
      const outIf = net.idx(h.dev, outName) || net.idx(h.dev, h.out);
      let post: number | null = null;
      if (sp.remark && (sp.remark[2] === 'b' || sp.remark[2] === dirTag) && sp.remark[0] === i) post = sp.remark[1];
      out.push({
        ts0: t, ts1: t + sp.durSec * 1000, exporter: dev.ip, inIf, outIf, srcIp: src, dstIp: dst, proto: sp.proto, sport, dport,
        flags: sp.proto === TCP ? flagBits(sp.flags) : 0, tos: dscp << 2, postTos: post === null ? null : post << 2,
        ttlMin: sp.proto === ICMP && sp.ttl0 === undefined ? null : Math.max(0, ttl0 - i - 1), ttlMax: sp.proto === ICMP && sp.ttl0 === undefined ? null : Math.max(0, ttl0 - i - 1),
        bytes, pkts, srcMac: i === 0 ? hostMac(src) : prevMac, dstMac: dev.mac, vlan: sp.vlan, natSrcIp: null, natDstIp: null, natSport: null, natDport: null, nextHop: null, sampling: 1
      });
      prevMac = dev.mac;
      if (post !== null) dscp = post;
    });
  };
  mkDir(true); mkDir(false);
  void r;
  return out;
}

// templates for background traffic: [src subnet prefix, dst prefix, proto, dport, vlan, path, dscp, bytes scale]
const BG: { s: string; d: string; proto: number; dport: number; vlan: number; path: string; rev?: boolean; dscp: number; scale: number }[] = [
  { s: '10.1.4.', d: '198.51.100.', proto: TCP, dport: 443, vlan: 140, path: 'A', dscp: 0, scale: 3e6 },
  { s: '10.1.7.', d: '198.51.100.', proto: TCP, dport: 443, vlan: 150, path: 'A', dscp: 0, scale: 2e6 },
  { s: '10.1.4.', d: '10.9.0.', proto: TCP, dport: 5432, vlan: 140, path: 'B', dscp: 18, scale: 8e6 },
  { s: '10.1.7.', d: '10.9.0.', proto: TCP, dport: 445, vlan: 150, path: 'B', dscp: 10, scale: 3e7 },
  { s: '10.1.4.', d: '192.0.2.', proto: UDP, dport: 53, vlan: 140, path: 'A', dscp: 0, scale: 3e3 },
  { s: '10.20.3.', d: '10.9.0.', proto: TCP, dport: 443, vlan: 200, path: 'C', dscp: 0, scale: 4e6 },
  { s: '10.20.3.', d: '10.9.0.', proto: TCP, dport: 445, vlan: 200, path: 'C', dscp: 10, scale: 1e7 },
  { s: '10.9.0.', d: '10.9.2.', proto: TCP, dport: 9092, vlan: 310, path: 'D', dscp: 26, scale: 1e8 },
  { s: '10.9.2.', d: '10.9.0.', proto: TCP, dport: 5432, vlan: 320, path: 'D', rev: true, dscp: 18, scale: 2e7 },
  { s: '10.9.0.', d: '198.51.100.', proto: TCP, dport: 443, vlan: 310, path: 'E', dscp: 0, scale: 2e6 },
  { s: '10.1.4.', d: '10.9.0.', proto: TCP, dport: 22, vlan: 140, path: 'B', dscp: 16, scale: 4e5 },
  { s: '10.1.4.', d: '10.9.0.', proto: TCP, dport: 3389, vlan: 140, path: 'B', dscp: 34, scale: 2e7 },
  { s: '10.20.5.', d: '10.9.0.', proto: UDP, dport: 5060, vlan: 200, path: 'C', dscp: 24, scale: 5e4 }
];

function backgroundSpec(r: () => number, agoMin: number): Spec {
  const t = BG[Math.floor(r() * BG.length)];
  const rbytes = Math.round(t.scale * (0.05 + r() * 1.4));
  const fbytes = Math.round(rbytes * (0.04 + r() * 0.12));
  const mtu = t.proto === UDP ? 180 : 700;
  return {
    src: t.s + (2 + Math.floor(r() * 90)), dst: t.d + (3 + Math.floor(r() * 60)), proto: t.proto, sport: 32768 + Math.floor(r() * 28000), dport: t.dport, vlan: t.vlan,
    fB: fbytes, rB: rbytes, fP: Math.max(1, Math.round(fbytes / 160)), rP: Math.max(1, Math.round(rbytes / mtu)), path: t.path, rev: !!t.rev,
    agoMin, durSec: 1 + Math.floor(r() * 400), flags: t.proto === TCP ? 'SYN ACK PSH FIN' : '', dscp: t.dscp
  };
}

/* ------------------------------------------------------------------ SNMP model */

function diurnal(ms: number): number { return 0.78 + 0.22 * Math.sin(2 * Math.PI * ((ms % 86400000) / 86400000 - 0.30)); }

class SnmpModel {
  private r = rng(42);
  constructor(private net: Net, private app: App) {}

  point(now: number, dt: number, onlyDevs?: Set<string>): { ifs: IfPoint[]; cls: ClsPoint[] } {
    const ifs: IfPoint[] = [], cls: ClsPoint[] = [];
    for (const d of DEVS) {
      if (onlyDevs && !onlyDevs.has(d.name)) continue;
      const dev = this.net.ids.get(d.name)!;
      for (const [name, , speed, policy, outU, inU] of d.ifs) {
        const ifIndex = this.net.idx(d.name, name);
        const k = diurnal(now) * (1 + (this.r() - 0.5) * 0.16);
        const outUtil = Math.min(99.5, outU * k), inUtil = Math.min(99.5, inU * k);
        const outBps = speed * 1e6 * outUtil / 100, inBps = speed * 1e6 * inUtil / 100;
        let discPkts = 0;
        if (policy) {
          const defs = POLICIES[policy];
          const shareOf = (c: string) => HOT_SHARE[`${d.name}|${name}|${c}`] ?? SHARE[c] ?? 0.1;
          const total = defs.reduce((a, c) => a + shareOf(c[0]), 0);
          for (const [cname] of defs) {
            const key = `${d.name}|${name}|${cname}`;
            const o = OVERRIDE[key];
            const classBps = outBps * shareOf(cname) / total;
            const preBytes = classBps * dt / 8, avg = cname === 'VOICE' ? 200 : 600;
            const prePkts = preBytes / avg;
            let pct = 0, depth = Math.round(5 + this.r() * 20);
            if (o) {
              if (o.mode === 'ramp') { const age = (Date.now() - now) / 60000; pct = age > 120 ? 0.1 + this.r() * 0.2 : o.drop * (1 - age / 120) * (0.7 + this.r() * 0.6) + 0.05; depth = Math.round(o.depth * (0.4 + (pct / o.drop) * 0.6)); }
              else { const spike = this.r() < 0.28; pct = spike ? o.drop * (0.6 + this.r() * 0.9) : 0.02 + this.r() * 0.08; depth = Math.round(spike ? o.depth * (0.7 + this.r() * 0.5) : 10 + this.r() * 30); }
            }
            const dropPkts = Math.round(prePkts * pct / 100), dropBytes = Math.round(preBytes * pct / 100);
            discPkts += dropPkts;
            cls.push({ ts: now, dev, ifIndex, cls: cname, dt, prePkts: Math.round(prePkts), preBytes: Math.round(preBytes), postBytes: Math.round(preBytes - dropBytes), dropPkts, dropBytes, qdepth: depth });
          }
        }
        const polIn = POLICY_IN[`${d.name}|${name}`];
        if (polIn) {
          const defs = IN_POLICIES[polIn];
          for (const [cname] of defs) {
            const share = cname === 'VOICE-MARK' ? 0.1 : cname === 'VIDEO-MARK' ? 0.25 : 0.65;
            const preBytes = inBps * share * dt / 8, prePkts = preBytes / 500;
            const pct = cname === 'VIDEO-MARK' && this.r() < 0.1 ? 0.5 : 0;   // policer drops, now and then
            const dropBytes = Math.round(preBytes * pct / 100);
            cls.push({ ts: now, dev, ifIndex, cls: 'in:' + cname, dt, prePkts: Math.round(prePkts), preBytes: Math.round(preBytes), postBytes: Math.round(preBytes - dropBytes), dropPkts: Math.round(prePkts * pct / 100), dropBytes, qdepth: 0 });
          }
        }
        ifs.push({ ts: now, dev, ifIndex, dt, inBps, outBps, utilIn: inUtil, utilOut: outUtil, inDisc: 0, outDisc: discPkts, inErr: 0, outErr: 0, oper: 1 });
      }
    }
    return { ifs, cls };
  }
}

/* ------------------------------------------------------------------ seeding */

export const DEMO_LOGINS = [
  { user: 'admin', role: 'Admin', password: 'flowscope-demo-admin' },
  { user: 'netops', role: 'SNMP admin', password: 'flowscope-demo-snmp' },
  { user: 'viewer', role: 'Read only', password: 'flowscope-demo-ro' }
];

function seedConfig(app: App, net: Net): void {
  const db = app.cdb.db;
  if (!app.creds.list().length) app.creds.create({ name: 'demo-snmpv3', version: 'v3', username: 'demo', level: 'authPriv', authProto: 'SHA-256', authKey: 'demo-auth-key-1', privProto: 'AES-128', privKey: 'demo-priv-key-1' }, true);
  const cred = app.creds.defaultId()!;
  const now = Date.now();
  for (const d of DEVS) {
    let row = db.prepare('SELECT id FROM devices WHERE ip = ?').get(d.ip) as { id: number } | undefined;
    if (!row) {
      const hasPol = d.ifs.some(i => i[3]);
      const r = db.prepare(`INSERT INTO devices(name, ip, port, cred_id, interval_sec, polling, src, added_at, sys_name, sys_descr, sys_object_id, role, profile, last_poll, last_ok)
        VALUES (?,?,161,?,?,1,'Demo network',?,?,?,?,?,?,?,?)`)
        .run(d.name, d.ip, cred, d.secs, now - 14 * 86400000, d.name, d.descr + ' (simulated)', '1.3.6.1.4.1.9.1.0', d.role, hasPol ? 'cisco-cbqos' : 'generic', now, now);
      row = { id: Number(r.lastInsertRowid) };
      // interfaces are written below, for new and existing demo databases alike
      db.prepare('INSERT OR REPLACE INTO device_ips(dev_id, ip, if_index) VALUES (?,?,NULL)').run(row.id, d.ip);
      db.prepare('INSERT OR REPLACE INTO exporters(ip, name, device_id, first_seen, last_seen, flows, version) VALUES (?,?,?,?,?,0,?)').run(d.ip, d.name, row.id, now - 14 * 86400000, now, d.name === 'fw-edge-01' ? 'IPFIX' : 'v9');
    }
    net.ids.set(d.name, row.id);
    // interfaces: every row is inserted if missing, so a demo database made by an earlier version gains the new ports
    d.ifs.forEach((ifc, i) => {
      const ifx = i + 1, key = `${d.name}|${ifc[0]}`, pi = PORTINFO[key];
      const svi = /^Vl(\d+)$/.exec(ifc[0]);
      const ifType = svi ? 53 : ifc[0].startsWith('Lo') ? 24 : ifc[0].startsWith('Tu') ? 131 : 6;
      const mode = svi ? 'svi' : pi?.mode ?? '', vlan = svi ? Number(svi[1]) : pi?.vlan ?? 0;
      db.prepare('INSERT OR IGNORE INTO interfaces(dev_id, if_index, name, descr, alias, speed_mbps, oper_status, policy) VALUES (?,?,?,?,?,?,?,?)').run(row!.id, ifx, ifc[0], ifc[1], ifc[1], ifc[2], 1, ifc[3]);
      db.prepare('UPDATE interfaces SET if_type = ?, port_mode = ?, vlan = ?, voice_vlan = ?, vlan_list = ?, policy_in = ? WHERE dev_id = ? AND if_index = ?').run(ifType, mode, vlan, pi?.voice ?? 0, pi?.list ?? '', POLICY_IN[key] ?? null, row!.id, ifx);
      if (ifc[3]) for (const c of POLICIES[ifc[3]]) db.prepare('INSERT OR IGNORE INTO class_defs(dev_id, if_index, cls, queue, dscps, bw, priority) VALUES (?,?,?,?,?,?,?)').run(row!.id, ifx, c[0], c[1], JSON.stringify(c[2]), c[3], c[1].includes('strict priority') ? 1 : 0);
      if (POLICY_IN[key]) for (const c of IN_POLICIES[POLICY_IN[key]]) db.prepare('INSERT OR IGNORE INTO class_defs(dev_id, if_index, cls, queue, dscps, bw) VALUES (?,?,?,?,?,?)').run(row!.id, ifx, 'in:' + c[0], '', JSON.stringify(c[1]), c[2]);
    });
    const ifs = db.prepare('SELECT if_index, name FROM interfaces WHERE dev_id = ?').all(row.id) as unknown as { if_index: number; name: string }[];
    for (const i of ifs) net.ifIdx.set(d.name + '|' + i.name, i.if_index);
    // every interface answers with the device's MAC address in the demo, so a MAC seen in a stream can be named
    db.prepare("UPDATE interfaces SET mac = ? WHERE dev_id = ? AND mac = ''").run(d.mac, row.id);
    app.devices.saveResources(row.id, demoResources(d, Date.now()));
    const nowMs = Date.now();
    // two weeks of link quality history too: a read every three minutes for three days, one every quarter of an hour before that
    {
      const prev = new Map<number, IfExtra>();
      app.cdb.tx(() => {
        for (let t = nowMs - 14 * 86400_000; t < nowMs - 5 * 60_000; t += t < nowMs - 3 * 86400_000 ? 900_000 : 180_000) {
          for (const [ix, x] of demoIfExtra(d, n => net.ifIdx.get(d.name + '|' + n), t)) { const df = diffExtra(prev.get(ix), x); prev.set(ix, x); recordIfExtra(db, row!.id, ix, df); }
        }
      });
    }
    seedHealth(app, row.id, d, net, true);
    // two weeks of history: a reading a minute for the last three days, one every five minutes before that
    if (d.role === 'ap') seedWlan(app, row.id, nowMs, true);
    app.cdb.tx(() => { for (let t = nowMs - 14 * 86400_000; t < nowMs - 60_000; t += t < nowMs - 3 * 86400_000 ? 300_000 : 60_000) recordResources(db, row.id, demoResources(d, t)); });
  }
  seedHosts(app, net);
  for (const [id, name] of VLANS) db.prepare("INSERT OR IGNORE INTO vlans(id, name, source) VALUES (?,?,'manual')").run(id, name);
  app.devices.invalidate();
  const have = new Set(app.auth.listUsers().map(u => u.username));
  for (const u of DEMO_LOGINS.slice(1)) if (!have.has(u.user)) app.auth.createUser('demo', { username: u.user, password: u.password, role: u.role === 'SNMP admin' ? 'snmp' : 'ro', mustChange: false });
}

/** Writes (and keeps fresh) what host tracking would have read from the switches: MAC address tables, ARP and LLDP neighbours. */
/** Writes the demo device's current health and link quality. At seeding it writes two reads a minute apart, so rates show at once. */
function seedHealth(app: App, id: number, d: Dev, net: Net, twice = false): void {
  const ifIdx = (name: string) => net.ifIdx.get(d.name + '|' + name);
  const now = Date.now();
  if (twice) app.devices.saveIfExtra(id, demoIfExtra(d, ifIdx, now - 60_000));
  app.devices.saveIfExtra(id, demoIfExtra(d, ifIdx, now));
  const h = demoHealth(d, now);
  app.devices.saveHealth(id, h.sensors.length || h.poe.length || h.stp || h.ospf.length || h.bgp.length || h.eigrp?.length || h.bfd?.length ? h : null);
  // Cisco extras: busiest processes on the switches and routers, a stack, ARP inspection drops and application statistics
  const MODELS: Record<string, string> = { 'dist-sw-01': 'C9300-48UXM', 'dc-spine-01': 'C9300-48UXM', 'dc-leaf-07': 'N9K-C93180YC-FX3', 'dc-leaf-11': 'N9K-C93180YC-FX3', 'core-rtr-01': 'ASR1001-X', 'wan-rtr-01': 'ISR4451-X/K9', 'br-rtr-02': 'ISR4331/K9' };
  if (MODELS[d.name]) app.devices.saveData(id, 'entity', { readAt: now, chassis: Array.from({ length: d.name === 'dc-spine-01' ? 3 : 1 }, (_, i) => ({ index: i + 1, name: 'Switch ' + (i + 1), model: MODELS[d.name]!, descr: '', serial: 'FDO2' + (1000 + i), sw: '' })), modules: [] }, now);
  if (d.role === 'switch' || d.role === 'router') {
    const wob = Math.round(((Math.sin(now / 600_000 + id) + 1) / 2) * 3);
    app.devices.saveData(id, 'procs', { readAt: now, top: [{ name: 'linux_iosd-imag', pid: 7813, five: 9 + wob, one: 8, fiveMin: 7 }, { name: 'fed main event', pid: 6121, five: 6, one: 5, fiveMin: 5 }, { name: 'SNMP ENGINE', pid: 4172, five: 3 + wob, one: 4, fiveMin: 3 }, { name: 'IP Input', pid: 220, five: 1, one: 1, fiveMin: 1 }], snmpFive: 3 + wob, snmpOne: 4 }, now);
  }
  if (d.name === 'dc-leaf-07') {
    // the far end of the spine's downlink, running dense where the spine runs sparse
    const up = ifIdx('Eth1/52') ?? 0;
    // the same streams as the spine sees them, sent up the link; every thirteenth is not forwarded towards the spine
    const leafRoutes = [] as any[];
    for (let g = 0; g < 130; g++) {
      const gi = Math.floor(g / 5), group = `239.${10 + (gi % 4)}.${20 + Math.floor(gi / 4)}.${30 + (gi % 7)}`;
      leafRoutes.push({ group, source: `10.9.0.${30 + (g % 9)}`, inIfIndex: ifIdx('Eth1/12') ?? 0, upstream: null, protocol: 9, pkts: 90_000 * (g + 1), bps: 400_000 + g * 37_000, expirySec: 180, flags: [], rp: null, oifs: [{ ifIndex: up, forwarding: g % 13 !== 0, pkts: 80_000 * (g + 1) }] });
    }
    // VLAN 310 has its SVI in a VRF, so the access ports in it (Eth1/10-12) and the hosts on them are in that VRF although the ports themselves have no VRF
    app.devices.saveData(id, 'vrfs', [{ name: 'APPS', ifIndexes: [ifIdx('Vl310') ?? 0] }], now);
    app.cdb.db.prepare('UPDATE device_ips SET if_index = ? WHERE dev_id = ? AND ip = ?').run(up, id, d.ip);
    app.devices.saveMulticast(id, { readAt: now, source: 'standard', routes: leafRoutes, receivers: [], pimInterfaces: [{ ifIndex: up, mode: 'dense', dr: '10.255.1.7' }], neighbors: [{ address: '10.255.1.1', ifIndex: up }], interfaces: [{ ifIndex: up, inOctets: null, outOctets: null, inBps: 800_000_000, outBps: 30_000_000_000, ttl: null, rateLimit: null }], truncated: false });
  }
  if (d.name === 'dc-spine-01') {
    // a day of wrong-interface drops: quiet, a burst in the early morning, then a smaller one that is still going
    if (!app.devices.rpfHistory(id, now - 86_400_000).length) {
      for (let t = now - 86_400_000; t < now - 120_000; t += 120_000) { const h = (now - t) / 3_600_000; app.devices.noteRpf(id, t, 120, h > 15 && h < 17 ? 900 + Math.round(Math.sin(t / 7e5) * 300) : h < 2 ? 160 : 0, h > 15 && h < 17 ? 9 : h < 2 ? 4 : 0); }
    }
    app.devices.noteRpf(id, now, 60, 160, 4);
    // multicast state: video and market-data groups from a handful of encoders, receivers on both downlinks
    const e7 = ifIdx('Eth1/7') ?? 0, e9 = ifIdx('Eth1/9') ?? 0;
    const routes = [] as any[]; const receivers = [] as any[];
    for (let g = 0; g < 130; g++) {
      const gi = Math.floor(g / 5), group = `239.${10 + (gi % 4)}.${20 + Math.floor(gi / 4)}.${30 + (gi % 7)}`; const src = `10.9.0.${30 + (g % 9)}`;
      routes.push({ group, source: src, inIfIndex: e7, upstream: '10.255.1.7', protocol: g % 11 === 0 ? 9 : 8, pkts: 90_000 * (g + 1), bps: 400_000 + g * 37_000, expirySec: 180, flags: ['sparse'], rp: g % 11 === 0 ? null : '10.255.0.1', rpf: { prefix: src.replace(/\.\d+$/, '.0'), mask: '255.255.255.0', proto: 13 }, rpfFail: g % 17 === 0 ? 120 * (g + 1) : 0, rpfNew: g % 34 === 0 ? 40 : 0,
        oifs: [{ ifIndex: e9, forwarding: g % 5 !== 0, pkts: 80_000 * (g + 1) }] });
      if (g % 3 === 0) receivers.push({ group, ifIndex: e9, lastReporter: `10.1.4.${20 + (g % 40)}`, expirySec: 200, self: false });
    }
    app.devices.saveMulticast(id, { readAt: now, source: 'cisco', routes, receivers, pimInterfaces: [{ ifIndex: e7, mode: 'sparse', dr: '10.255.1.1' }, { ifIndex: e9, mode: 'sparse-dense', dr: '10.255.1.1' }], neighbors: [{ address: '10.255.1.7', ifIndex: e7 }], igmpInterfaces: [{ ifIndex: e9, querier: '10.255.1.11', version: 2, queryIntervalSec: 125, querierUpSec: 5 * 86400, querierExpirySec: 240 }, { ifIndex: e7, querier: null, version: 2, queryIntervalSec: 125, querierUpSec: null, querierExpirySec: null }], rpGroups: [...new Set(routes.map((r: any) => r.group))].map((g: any, i: number) => ({ group: g, rp: i % 9 === 0 ? '10.255.1.7' : '10.255.0.1', up: true, sinceSec: 86400 })), rpSet: [], candidateRps: [], truncated: false, interfaces: [{ ifIndex: e9, inOctets: 91_000_000_000, outOctets: 1_820_000_000_000, inBps: 1_200_000_000, outBps: 24_000_000_000, ttl: null, rateLimit: null }, { ifIndex: e7, inOctets: 1_900_000_000_000, outOctets: 70_000_000_000, inBps: 25_000_000_000, outBps: 900_000_000, ttl: null, rateLimit: null }] });
    // hosts collected over time from the IGMP cache: several per group on the downlink
    for (const r of receivers) app.devices.noteIgmp(id, Array.from({ length: 6 }, (_, k) => ({ group: r.group, ifIndex: r.ifIndex, reporter: `10.1.4.${20 + ((Number(r.group.split('.')[3]) + k * 7) % 40)}` })), now, false);
    // an SD-Access style overlay VRF: one stream sent into the fabric (underlay group 232.0.2.19) and two arriving from it
    const lisp = 9001; const mrt = (group: string, source: string, inIfIndex: number, oifs: any[], pkts: number, bps: number) => ({ group, source, inIfIndex, upstream: null, protocol: 8, pkts, bps, expirySec: 180, flags: ['sparse'], rp: null, rpf: null, oifs });
    const vm = { readAt: now, source: 'cisco', receivers: [{ group: '239.202.29.2', ifIndex: e9, lastReporter: '10.133.47.77', expirySec: 200, self: false }], pimInterfaces: [], neighbors: [], names: { [lisp]: 'LISP0.4102' }, truncated: false,
      routes: [mrt('239.202.29.2', '10.133.47.240', e9, [{ ifIndex: lisp, forwarding: true, pkts: 185_142, underlay: '232.0.2.19' }], 185_142, 2_400_000),
        mrt('239.202.29.2', '10.245.201.253', lisp, [{ ifIndex: e9, forwarding: true, pkts: 90_000 }], 90_000, 1_100_000),
        mrt('239.202.29.2', '10.245.84.248', lisp, [{ ifIndex: e9, forwarding: true, pkts: 88_000 }], 88_000, 1_000_000)] };
    app.devices.saveData(id, 'vrfs', [{ name: 'MEDIA', ifIndexes: [e9, lisp] }], now);
    app.devices.saveVrfMulticast(id, 'MEDIA', vm as any);
    app.devices.noteIgmp(id, [{ group: '239.202.29.2', ifIndex: e9, reporter: '10.133.47.77' }], now, false, 'MEDIA');
    // the underlay side: the same stream as a (local RLOC, 232.0.2.19) route in the default VRF
    routes.push(mrt('232.0.2.19', '10.255.1.1', e7, [{ ifIndex: e7, forwarding: true, pkts: 185_142 }], 185_142, 2_400_000), mrt('232.0.2.19', '10.255.1.7', e7, [{ ifIndex: e9, forwarding: true, pkts: 90_000 }], 90_000, 1_100_000));
    const m0 = app.devices.multicast(id)!; m0.routes = routes; app.devices.saveMulticast(id, m0);
  }
  if (d.name === 'dc-spine-01') {
    const m = (n: number, role: string) => ({ index: n * 1000, number: n, role, state: 'ready', level: 'ok', mac: `00:1c:73:01:0${n}:00` });
    app.devices.saveData(id, 'stack', { readAt: now, members: [m(1, 'master'), m(2, 'standby'), m(3, 'member')], ports: [88, 89, 191, 192, 272, 273].map((ifIndex, i) => ({ ifIndex, status: 'up', level: 'ok', neighbor: ((i + 1) % 3 + 1) * 1000 })), problems: [] }, now);
  }
  if (d.name === 'dist-sw-01') seedFabric(app, id, net, now);
  if (d.name === 'dist-sw-01') {
    app.devices.saveData(id, 'dai', { readAt: now, dtSec: 300, vlans: [{ vlan: 140, forwarded: 290_344, dropped: 555_705, dhcpDenied: 555_705, aclDenied: 0, srcMac: 0, dstMac: 0, ip: 0, invalid: 0, droppedNow: 41 }] }, now);
    const gi = ifIdx('Gi1/0/12');
    if (gi) app.devices.saveData(id, 'nbar', { readAt: now, interfaces: { [gi]: [
      { name: 'ms-office-365', inBps: 2_400_000, outBps: 640_000, inBytes: 9_100_000_000, outBytes: 2_300_000_000 }, { name: 'ssl', inBps: 1_100_000, outBps: 300_000, inBytes: 4_800_000_000, outBytes: 1_200_000_000 },
      { name: 'dns', inBps: 12_000, outBps: 9_000, inBytes: 180_000_000, outBytes: 90_000_000 }, { name: 'ntp', inBps: 120, outBps: 120, inBytes: 4_000_000, outBytes: 4_000_000 }] } }, now);
  }
}

/** What an SD-Access edge node adds: RADIUS servers, per-port authentication setup, configuration state and the LISP map cache. */
function seedFabric(app: App, id: number, net: Net, now: number): void {
  const srv = (key: string, address: string, kind: 'radius' | 'tacacs', port: number, priority: number, o: Record<string, unknown>) => ({ key, address, kind, port, priority, up: true, stateSec: 956450, deadCount: 0, authReq: 0, authTimeouts: 0, authFail: 0, authMs: 0, acctReq: 0, acctTimeouts: 0, newReq: null, newTimeouts: null, newFail: null, newDead: null, level: 'ok', problems: [] as string[], ...o });
  app.devices.saveData(id, 'aaa', { readAt: now, dtSec: 60, servers: [
    srv('1.0', '10.254.185.15', 'tacacs', 49, 0, {}),
    srv('2.1', '10.254.185.251', 'radius', 1812, 1, { authReq: 24115, authTimeouts: 77, authFail: 12, authMs: 925, acctReq: 3507, acctTimeouts: 67, deadCount: 2, newReq: 38, newTimeouts: 1, level: 'warn', problems: ['RADIUS server 10.254.185.251 did not answer 1 request since the last read.'] })] }, now);
  app.devices.saveData(id, 'config', { readAt: now, changedAt: now - 4_600, savedAt: now - 23_700, unsaved: true, unsavedSec: 4.6, events: [{ at: now - 86_400_000, what: 'saved', user: 'netops', via: 'remote session' }] }, now);
  const ports = ['Gi1/0/12', 'Gi1/0/14', 'Gi1/0/15', 'Gi1/0/16', 'Gi1/0/20', 'Gi1/0/24'].map(n => net.ifIdx.get('dist-sw-01|' + n)).filter((x): x is number => !!x);
  app.devices.saveData(id, 'authsetup', ports.map(ifIndex => ({ ifIndex, dot1x: true, mab: true, mode: 'multi-auth', control: 'auto', open: ifIndex !== ports[5], reauth: false })), now);
  // LISP: endpoints the node resolved, what it registered, and a day of cache movement
  const rl = ['10.255.1.7', '10.255.1.11', '10.255.0.1'];
  const hostsIn = ['10.9.0.5', '10.9.0.12', '10.9.0.30', '10.9.2.30'];
  const entries = [...hostsIn.map((ip, i) => ({ iid: 4097, kind: 'ip', eid: ip, prefix: 32, active: true, authoritative: true, ageSec: 240 + i * 610, rlocs: [{ rloc: rl[i < 3 ? 0 : 1]!, priority: 10, weight: 10, up: true }], bytes: 0, pkts: 0 })),
    ...Array.from({ length: 12 }, (_, i) => ({ iid: 4097, kind: 'ip', eid: `10.1.${20 + i}.${40 + i * 3}`, prefix: 32, active: i < 5, authoritative: true, ageSec: 900 + i * 700, rlocs: [{ rloc: rl[i % 2]!, priority: 10, weight: 10, up: true }], bytes: 0, pkts: 0 })),
    { iid: 4097, kind: 'ip', eid: '10.133.0.0', prefix: 16, active: true, authoritative: true, ageSec: 5000, rlocs: [], bytes: 0, pkts: 0 }];
  const regs = [...['10.1.4.21', '10.1.8.21', '10.1.4.33', '10.1.4.60', '10.1.7.88', '10.1.7.19'].map(eid => ({ iid: 4097, kind: 'ip', eid, prefix: 32, ageSec: 52_000 })), { iid: 4097, kind: 'ip', eid: '10.1.4.99', prefix: 32, ageSec: 7_300 }];
  const history = Array.from({ length: 288 }, (_, i) => { const t = now - (287 - i) * 300_000; const cache = 150 + Math.round(18 * Math.sin(i / 20) + (i > 200 && i < 206 ? -60 + (i - 200) * 10 : 0)); return { t, cache, added: i % 7 === 0 ? 6 : 1, removed: i === 201 ? 58 : i % 9 === 0 ? 4 : 0 }; });
  history[history.length - 1] = { t: now, cache: entries.length, added: 3, removed: 1 };
  app.devices.saveData(id, 'lisp', { readAt: now, instances: [{ iid: 4097, vrf: '', cacheSize: entries.length, cacheLimit: 40448, etr: true, itr: false, pitr: true, petr: false, mapServer: false, mapResolver: false, requestsOut: 5424, repliesIn: 4081, registersOut: 282, newRequests: 12, newReplies: 12 }],
    cache: entries, registered: regs, cacheTotal: entries.length, truncated: false, mapServers: { total: 2, down: [] }, mapResolvers: { total: 2, down: [] }, history, problems: [], level: 'ok' }, now);
}

function seedHosts(app: App, net: Net): void {
  const db = app.cdb.db; const now = Date.now(), first = now - 6 * 3600_000;
  const fdb = db.prepare(`INSERT INTO fdb(dev_id, mac, vlan, if_index, first_seen, last_seen, since) VALUES (?,?,?,?,?,?,?)
    ON CONFLICT(dev_id, mac, vlan) DO UPDATE SET last_seen = excluded.last_seen, if_index = excluded.if_index`);
  const arp = db.prepare(`INSERT INTO arp(dev_id, ip, mac, if_index, last_seen) VALUES (?,?,?,?,?) ON CONFLICT(dev_id, ip, mac) DO UPDATE SET last_seen = excluded.last_seen`);
  // the hosts of the demo overlay VRF, read from its own ARP table
  { const sp = net.ids.get('dc-spine-01'); if (sp) for (const [ip, m] of [['10.133.47.77', '00:50:56:aa:00:01'], ['10.133.47.240', '00:50:56:aa:00:02'], ['10.133.47.241', '00:50:56:aa:00:03']] as const) db.prepare('INSERT OR REPLACE INTO arp(dev_id, ip, mac, if_index, last_seen, vrf) VALUES (?,?,?,?,?,?)').run(sp, ip, m, net.idx('dc-spine-01', 'Eth1/9'), now, 'MEDIA'); }
  const nb = db.prepare(`INSERT OR REPLACE INTO neighbors(dev_id, if_index, proto, rem_key, rem_name, rem_port, rem_ip, kind, caps, seen_at) VALUES (?,?,?,?,?,?,?,?,?,?)`);
  const ix = (dev: string, port: string) => net.idx(dev, port);
  app.cdb.tx(() => {
    for (const x of HOSTS) {
      const mac = hostMac(x.ip);
      fdb.run(net.ids.get(x.dev)!, mac, x.vlan, ix(x.dev, x.port), first, now, first);
      arp.run(net.ids.get(x.l3)!, x.ip, mac, ix(x.l3, 'Vl' + x.vlan), now);
    }
    // 802.1X / MAB sessions and security group tags on the edge switch: one host in a VLAN the server assigned, one that did not authenticate
    { const sw = net.ids.get('dist-sw-01')!;
      const sess = db.prepare('INSERT OR REPLACE INTO auth_sessions(dev_id, mac, if_index, vlan, ip, policy, profile, last_seen, domain, status) VALUES (?,?,?,?,?,?,?,?,?,?)');
      const sgt = db.prepare('INSERT OR REPLACE INTO ip_sgt(dev_id, vrf, ip, sgt, source, last_seen) VALUES (?,?,?,?,?,?)');
      db.prepare('INSERT OR REPLACE INTO sgt_names(dev_id, sgt, name) VALUES (?,?,?)').run(sw, 10, 'EMPLOYEES'); db.prepare('INSERT OR REPLACE INTO sgt_names(dev_id, sgt, name) VALUES (?,?,?)').run(sw, 74, 'DEVICE_CAMERA'); db.prepare('INSERT OR REPLACE INTO sgt_names(dev_id, sgt, name) VALUES (?,?,?)').run(sw, 30, 'DC_SERVERS');
      const g12 = ix('dist-sw-01', 'Gi1/0/12'), g14 = ix('dist-sw-01', 'Gi1/0/14'), g15 = ix('dist-sw-01', 'Gi1/0/15'), g16 = ix('dist-sw-01', 'Gi1/0/16');
      const m = hostMac;
      sess.run(sw, m('10.1.4.21'), g12, 140, '10.1.4.21', 'jdoe', 'CAMPUS-USERS', now, 'data', 'authorized'); sgt.run(sw, '', '10.1.4.21', 10, 'authenticated', now);
      sess.run(sw, m('10.1.8.21'), g12, 160, '10.1.8.21', 'SEP00505601080015', 'CAMPUS-VOICE', now, 'voice', 'authorized');
      sess.run(sw, m('10.1.4.33'), g14, 140, '10.1.4.33', 'asmith', 'CAMPUS-USERS', now, 'data', 'authorized'); sgt.run(sw, '', '10.1.4.33', 10, 'authenticated', now);
      sess.run(sw, m('10.1.4.60'), g15, 0, '10.1.4.60', '', '', now, 'unknown', 'idle');
      // a camera whose port is configured for VLAN 140 but whose authentication assigned VLAN 150
      fdb.run(sw, m('10.1.7.140'), 150, g16, first, now, first); arp.run(sw, '10.1.7.140', m('10.1.7.140'), ix('dist-sw-01', 'Vl150'), now);
      sess.run(sw, m('10.1.7.140'), g16, 150, '10.1.7.140', 'cam-lobby-2', 'CAMPUS-WIFI', now, 'data', 'authorized'); sgt.run(sw, '', '10.1.7.140', 74, 'authenticated', now);
      for (const ip of ['10.9.0.5', '10.9.0.12', '10.9.0.30', '10.9.2.30']) sgt.run(sw, '', ip, 30, 'authenticated', now);
    }
    for (const [sw, port, ip] of LEARNED_VIA) fdb.run(net.ids.get(sw)!, hostMac(ip), HOSTS.find(h => h.ip === ip)!.vlan, ix(sw, port), first, now, first);
    for (const [key, [proto, name, port, kind, caps]] of Object.entries(NEIGHBORS)) {
      const [dev, ifn] = key.split('|');
      nb.run(net.ids.get(dev)!, ix(dev, ifn), proto, name + '/' + port, name, port, '', kind, caps, now);
    }
    for (const d of DEVS) db.prepare('UPDATE devices SET hosts_at = ?, hosts_note = NULL, qos_note = NULL WHERE id = ?').run(now, net.ids.get(d.name)!);
  });
}

export async function startDemo(app: App): Promise<void> {
  const net = new Net();
  seedConfig(app, net);
  const model = new SnmpModel(net, app);
  const r = rng(7);
  const now = Date.now();
  const flowBatch = async (specs: { sp: Spec; start: number }[]) => {
    const recs: FlowRecord[] = [];
    for (const { sp, start } of specs) recs.push(...makeRecords(net, sp, start, r));
    recs.sort((a, b) => a.ts0 - b.ts0);
    for (let i = 0; i < recs.length; i += 4000) await app.store.insertFlows(recs.slice(i, i + 4000));
    return recs.length;
  };

  const seeded = app.settings.raw('demoSeededAt');
  if (!seeded) {
    app.log.info('demo', 'Seeding the simulated network: 8 devices, 3 days of SNMP history and flow records');
    // SNMP: 2 days at 5-minute spacing, then 1 day at 1-minute spacing
    for (let t = now - 3 * 86400000; t < now; t += (t < now - 86400000 ? 300_000 : 60_000)) {
      const step = t < now - 86400000 ? 300 : 60;
      const p = model.point(t, step);
      await app.store.insertSnmp(p.ifs, p.cls);
    }
    // flows: the sample streams, then background sessions over the last 3 days
    await flowBatch(SAMPLE.map(sp => ({ sp, start: now - sp.agoMin * 60000 - Math.floor(r() * 40000) })));
    const bg: { sp: Spec; start: number }[] = [];
    for (let i = 0; i < 1800; i++) { const ago = r() * 3 * 1440; bg.push({ sp: backgroundSpec(r, ago), start: now - ago * 60000 }); }
    await flowBatch(bg);
    app.settings.setRaw('demoSeededAt', String(now));
    try { await app.store.maintain(app.settings.get('retention')); } catch { /* rollups will run at the next maintenance cycle */ }
    app.log.info('demo', 'Demo data is ready');
  }

  app.log.info('demo', 'Demo mode: traffic and SNMP counters are simulated. Nothing here comes from your network.');
  let tick = 0;
  const every = (ms: number, fn: () => Promise<void>) => { const t = setInterval(() => { void fn().catch(e => app.log.error('demo', String(e))); }, ms); t.unref(); };
  // IGMP version 2 membership reports as the spine exports them: three hosts per group also found over SNMP, one that only NetFlow sees, and version 3 reports
  const igmpFlows = async (): Promise<void> => {
    const spine = DEVS.find(d => d.name === 'dc-spine-01'), e9 = net.idx('dc-spine-01', 'Eth1/9'); if (!spine || !e9) return;
    const t = Date.now(), recs: FlowRecord[] = [];
    const rec = (src: string, dst: string, ago: number): FlowRecord => ({ ts0: t - ago, ts1: t - ago, exporter: spine.ip, inIf: e9, outIf: 0, srcIp: src, dstIp: dst, proto: 2, sport: 0, dport: 0, flags: 0, tos: 0xc0, postTos: null, ttlMin: 1, ttlMax: 1, bytes: 32, pkts: 1, srcMac: hostMac(src), dstMac: null, vlan: 140, natSrcIp: null, natDstIp: null, natSport: null, natDport: null, nextHop: null, sampling: 1 });
    for (let gi = 0; gi < 26; gi += 2) {
      const group = `239.${10 + (gi % 4)}.${20 + Math.floor(gi / 4)}.${30 + (gi % 7)}`, last = Number(group.split('.')[3]);
      for (let k = 0; k < 3; k++) recs.push(rec(`10.1.4.${20 + ((last + k * 7) % 40)}`, group, 20_000 + k * 9_000));
      recs.push(rec('10.1.4.99', group, 40_000));
    }
    for (let i = 150; i < 156; i++) recs.push(rec(`10.1.4.${i}`, '224.0.0.22', 30_000));
    await app.store.insertFlows(recs);
  };
  await igmpFlows();
  every(60_000, igmpFlows);
  // new sessions every few seconds while flow collection is on
  every(5000, async () => {
    if (!app.collect().flow) return;
    const n = 2 + Math.floor(r() * 6);
    const specs = Array.from({ length: n }, () => { const sp = backgroundSpec(r, 0); sp.durSec = 1 + Math.floor(r() * 30); return { sp, start: Date.now() - sp.durSec * 1000 }; });
    const c = await flowBatch(specs);
    app.cdb.db.prepare('UPDATE exporters SET last_seen = ?, flows = flows + ?').run(Date.now(), Math.round(c / DEVS.length));
  });
  // SNMP counters every minute (the branch router every fifth minute)
  every(60_000, async () => {
    if (!app.collect().snmp) return;
    tick++;
    const only = new Set(DEVS.filter(d => d.secs === 60 || tick % 5 === 0).map(d => d.name));
    const p = model.point(Date.now(), 60, only);
    await app.store.insertSnmp(p.ifs, p.cls);
    for (const d of DEVS) if (only.has(d.name)) app.devices.recordPoll(net.ids.get(d.name)!, true, null);
  });
  every(60_000, async () => { seedHosts(app, net); for (const d of DEVS) { const id = net.ids.get(d.name)!; app.devices.saveResources(id, demoResources(d, Date.now())); seedHealth(app, id, d, net); if (d.role === 'ap') seedWlan(app, id, Date.now()); } });
  for (const d of DEVS) app.devices.recordPoll(net.ids.get(d.name)!, true, null);
  void dscpName;
  console.log(' Demo sign-ins:  ' + DEMO_LOGINS.map(l => `${l.user} / ${l.password} (${l.role})`).join('   '));
}
