import type { DeviceRow, DeviceService } from './devices.js';
import { hottest, readHealth, readIfExtra } from './health.js';
import { readDai, readNbar, readProcesses, readStack, type Dai, type Nbar } from './cisco_extra.js';
import { classLabel, delta, perInterface, pollIfCounters, QOS_SOURCES, type ClassCounters, type IfCounters, type QosPolicy } from './collect.js';
import type { HostOpts, HostTracker } from './hosts.js';
import type { ClsPoint, IfPoint, TsStore } from '../store/types.js';
import type { AppLog } from '../logger.js';
import type { SnmpClient } from './client.js';
import { readResources } from './resources.js';
import { readMulticast, readIgmpReporters, withLoadRates } from './multicast.js';
import { readFib } from './fib.js';
import { readVrfs, contextOf } from './vrf.js';
import { readEntity } from './entity.js';

/** The slow optional readers. `run` returns whether the device had the table. */
interface SlowReader { name: string; cisco: boolean; every: number; emptyEvery: number; errorEvery: number; run(c: SnmpClient, d: DeviceRow, devs: DeviceService, now: number, cisco: boolean): Promise<boolean> }
const SLOW: SlowReader[] = [
  { name: 'mcast', cisco: false, every: 115_000, emptyEvery: 3600_000, errorEvery: 600_000, run: async (c, d, devs, now, cisco) => { const m0 = await readMulticast(c, now, cisco); const prev = devs.multicast(d.id); const m = m0 ? withLoadRates(m0, prev) : null; devs.saveMulticast(d.id, m); if (m && prev && m.routes.some(r => r.rpfNew != null)) devs.noteRpf(d.id, now, (m.readAt - prev.readAt) / 1000, m.routes.reduce((a, r) => a + (r.rpfNew ?? 0), 0), m.routes.filter(r => (r.rpfNew ?? 0) > 0).length); if (m) devs.noteIgmp(d.id, m.receivers.filter(r => r.lastReporter && !r.self).map(r => ({ group: r.group, ifIndex: r.ifIndex, reporter: r.lastReporter as string })), now, !m.truncated); return !!m; } },
  // The IGMP cache keeps only the last host to report a group, so it is sampled every 30 seconds to catch the others as they answer queries
  { name: 'igmp', cisco: false, every: 30_000, emptyEvery: 600_000, errorEvery: 600_000, run: async (c, d, devs, now) => { if (!devs.multicast(d.id)) return false; const rows = await readIgmpReporters(c); devs.noteIgmp(d.id, rows, now); return rows.length > 0; } },
  // the hardware model (chassis and modules) hardly ever changes
  { name: 'entity', cisco: false, every: 6 * 3600_000, emptyEvery: 86_400_000, errorEvery: 3600_000, run: async (c, d, devs, now) => { const x = await readEntity(c, now); devs.saveData(d.id, 'entity', x, now); return !!x; } },
  // The VRFs a device has (MPLS-L3VPN-STD-MIB). Each is read for multicast in its own SNMP context, below.
  { name: 'vrfs', cisco: true, every: 3600_000, emptyEvery: 86_400_000, errorEvery: 3600_000, run: async (c, d, devs, now) => {
    const v = await readVrfs(c);
    for (const old of devs.vrfs(d.id)) if (!v?.some(x => x.name === old.name)) devs.saveVrfMulticast(d.id, old.name, null);
    devs.saveData(d.id, 'vrfs', v, now); return !!v;
  } },
  // Multicast routing inside each VRF. Needs `snmp-server context vrf-<NAME>` and `snmp context vrf-<NAME>` under the VRF's address family, and a v3 group that may read the context.
  { name: 'vrfmc', cisco: true, every: 295_000, emptyEvery: 3600_000, errorEvery: 600_000, run: async (c, d, devs, now, cisco) => {
    const dflt = devs.multicast(d.id); let any = false;
    for (const v of devs.vrfs(d.id)) {
      const cc = c.forContext(contextOf(v.name));
      try {
        const m0 = await readMulticast(cc, now, cisco);
        if (!m0 || !m0.routes.length) { devs.saveVrfMulticast(d.id, v.name, null); continue; }
        // the VRF's own context does not publish the names of VLAN and tunnel interfaces; they are the same on the whole device
        m0.names = { ...(dflt?.names ?? {}), ...(m0.names ?? {}) }; m0.down = [...new Set([...(dflt?.down ?? []), ...(m0.down ?? [])])];
        const m = withLoadRates(m0, devs.vrfMulticast(d.id, v.name));
        devs.saveVrfMulticast(d.id, v.name, m); any = true;
        devs.noteIgmp(d.id, m.receivers.filter(r => r.lastReporter && !r.self).map(r => ({ group: r.group, ifIndex: r.ifIndex, reporter: r.lastReporter as string })), now, !m.truncated, v.name);
      } catch { /* a VRF whose context is not set up is skipped */ } finally { cc.close(); }
    }
    return any;
  } },
  { name: 'fib', cisco: true, every: 600_000, emptyEvery: 86_400_000, errorEvery: 3600_000, run: async (c, d, devs) => { const f = await readFib(c); devs.saveData(d.id, 'fib', f, f?.readAt); return !!f; } },
  // Cisco extras: the busiest processes, stack health, ARP inspection drops and the applications NBAR2 recognised
  { name: 'procs', cisco: true, every: 300_000, emptyEvery: 86_400_000, errorEvery: 3600_000, run: async (c, d, devs, now) => { const x = await readProcesses(c, now); devs.saveData(d.id, 'procs', x, now); return !!x; } },
  { name: 'stack', cisco: true, every: 300_000, emptyEvery: 86_400_000, errorEvery: 3600_000, run: async (c, d, devs, now) => { const x = await readStack(c, now); devs.saveData(d.id, 'stack', x, now); return !!x; } },
  { name: 'dai', cisco: true, every: 300_000, emptyEvery: 86_400_000, errorEvery: 3600_000, run: async (c, d, devs, now) => { const x = await readDai(c, devs.data<Dai>(d.id, 'dai'), now); devs.saveData(d.id, 'dai', x, now); return !!x; } },
  { name: 'nbar', cisco: true, every: 300_000, emptyEvery: 86_400_000, errorEvery: 3600_000, run: async (c, d, devs, now) => { const x = await readNbar(c, now, devs.data<Nbar>(d.id, 'nbar')); devs.saveData(d.id, 'nbar', x, now); return !!x; } }
];

interface PrevIf { t: number; c: IfCounters }
interface PrevCls { t: number; c: ClassCounters }

export interface PollerOpts { maxConcurrent?: number; isEnabled: () => boolean; hosts?: () => HostOpts }

/** Polls each device on its own interval and stores rates computed from counter differences. */
export class Poller {
  private timer: NodeJS.Timeout | null = null;
  private due = new Map<number, number>();
  private running = new Set<number>();
  private fails = new Map<number, number>();
  private prevIf = new Map<string, PrevIf>();
  private prevCls = new Map<string, PrevCls>();
  private structure = new Map<number, QosPolicy[]>();
  private structureAt = new Map<number, number>();
  private stopped = false;
  private hostDue = new Map<number, number>();
  private hostRunning = new Set<number>();
  private refreshDue = new Map<number, number>();
  private refreshing = false;
  private lastPurge = 0;
  private resourcesAt = new Map<number, number>();
  /** Hardware and link-quality reads are slower to change and heavier to ask for, so they run less often than the counters. */
  private healthAt = new Map<number, number>();
  private hottest = new Map<number, number | null>();
  /** Large optional tables (multicast routes, forwarding table, Cisco extras) each have their own schedule per device, and are read on a session of their own so they never delay the counter polls. */
  private slow = new Map<string, { at: number; every: number }>();
  private slowRunning = new Set<number>();

  constructor(private devs: DeviceService, private store: Pick<TsStore, 'insertSnmp'>, private log: AppLog, private o: PollerOpts, private hosts?: HostTracker) {}

  start(): void {
    this.timer = setInterval(() => this.tick(), 1000);
    this.timer.unref();
  }
  stop(): void { this.stopped = true; if (this.timer) clearInterval(this.timer); }

  /** Forget cached counters and structure for a device (after removal or re-discovery). */
  forget(devId: number): void {
    this.due.delete(devId); this.fails.delete(devId); this.structure.delete(devId); this.structureAt.delete(devId); this.hostDue.delete(devId); this.refreshDue.delete(devId); this.resourcesAt.delete(devId); this.healthAt.delete(devId); this.hottest.delete(devId); for (const k of [...this.slow.keys()]) if (k.startsWith(devId + '/')) this.slow.delete(k);
    for (const k of [...this.prevIf.keys()]) if (k.startsWith(devId + '/')) this.prevIf.delete(k);
    for (const k of [...this.prevCls.keys()]) if (k.startsWith(devId + '/')) this.prevCls.delete(k);
  }

  /** Polls one device now, outside the schedule. Used by "poll now" and by tests. */
  async pollNow(devId: number): Promise<void> {
    const d = this.devs.row(devId);
    if (d) await this.pollOne(d);
  }

  private tick(): void {
    if (this.stopped || !this.o.isEnabled()) return;
    const now = Date.now();
    const max = this.o.maxConcurrent ?? 16;
    for (const d of this.devs.rows()) {
      if (this.running.size >= max) break;
      if (d.polling !== 1 || this.running.has(d.id)) continue;
      const due = this.due.get(d.id);
      if (due === undefined) { this.due.set(d.id, now + Math.floor(Math.random() * Math.min(d.interval_sec, 10)) * 1000); continue; }
      if (due > now) continue;
      void this.pollOne(d);
    }
    this.tickExtras(now);
  }

  /** Host tables and the hourly re-read of interfaces, VLANs and QoS policies. These run beside the counter polls and never delay them. */
  private tickExtras(now: number): void {
    const h = this.o.hosts?.();
    for (const d of this.devs.rows()) {
      if (d.polling !== 1 || d.last_ok === null) continue;
      if (this.hosts && h?.enabled && !this.hostRunning.has(d.id) && this.hostRunning.size < 2) {
        const due = this.hostDue.get(d.id);
        if (due === undefined) this.hostDue.set(d.id, now + 10_000 + Math.floor(Math.random() * 30_000));
        else if (due <= now) void this.hostCycle(d, h);
      }
      if (!this.slowRunning.has(d.id) && this.slowRunning.size < 2 && SLOW.some(r => this.slowDue(d, r.name, now))) void this.slowCycle(d);
      if (!this.refreshing) {
        const due = this.refreshDue.get(d.id);
        if (due === undefined) this.refreshDue.set(d.id, now + 120_000 + Math.floor(Math.random() * 600_000));
        else if (due <= now) void this.refresh(d);
      }
    }
    if (this.hosts && now - this.lastPurge > 3600_000) { this.lastPurge = now; try { this.hosts.purge(now); } catch (e) { this.log.warn('snmp', `Could not purge old host records: ${(e as Error).message}`); } }
  }

  private async hostCycle(d: DeviceRow, h: HostOpts): Promise<void> {
    this.hostRunning.add(d.id);
    let c: SnmpClient | null = null;
    try {
      c = this.devs.open(d);
      const r = await this.hosts!.refresh(d, c);
      this.log.debug?.('snmp', `Host tables from ${d.name}: ${r.macs} MAC addresses, ${r.arp} ARP entries, ${r.neighbors} neighbours${r.note ? ' (' + r.note + ')' : ''}`);
      this.hostDue.set(d.id, Date.now() + Math.max(60, h.intervalSec) * 1000);
    } catch (e) {
      this.hosts!.fail(d.id, (e as Error).message);
      this.hostDue.set(d.id, Date.now() + Math.max(300, h.intervalSec) * 1000);
    } finally { c?.close(); this.hostRunning.delete(d.id); }
  }

  private slowDue(d: DeviceRow, name: string, now: number): boolean { const t = this.slow.get(d.id + '/' + name); return !t || now - t.at >= t.every; }

  /** Reads whichever of the slow optional tables are due, one after another on one session. A table a device does not publish is asked about only rarely. */
  private async slowCycle(d: DeviceRow): Promise<void> {
    const cisco = (d.sys_object_id ?? '').startsWith('1.3.6.1.4.1.9.');
    this.slowRunning.add(d.id);
    let c: SnmpClient | null = null;
    try {
      c = this.devs.open(d);
      for (const r of SLOW) {
        const now = Date.now();
        if (!this.slowDue(d, r.name, now) || (r.cisco && !cisco)) continue;
        let every = r.errorEvery;
        try { const had = await r.run(c, d, this.devs, now, cisco); every = had ? r.every : r.emptyEvery; } catch { /* optional: a device without the MIB is simply skipped */ }
        this.slow.set(d.id + '/' + r.name, { at: now, every });
      }
    } catch { /* could not open a session */ }
    finally { c?.close(); this.slowRunning.delete(d.id); }
  }

  /** Re-discovers a device so policies, VLAN names and interfaces added after the first discovery appear without anyone pressing a button. */
  private async refresh(d: DeviceRow): Promise<void> {
    this.refreshing = true;
    try {
      await this.devs.rediscover(d.id);
      this.structureAt.delete(d.id); this.structure.delete(d.id);
    } catch (e) { this.log.warn('snmp', `Re-reading ${d.name} failed: ${(e as Error).message}`); }
    finally { this.refreshing = false; this.refreshDue.set(d.id, Date.now() + 3600_000); }
  }

  private async pollOne(d: DeviceRow): Promise<void> {
    if (this.running.has(d.id)) return;
    this.running.add(d.id);
    let c: SnmpClient | null = null;
    try {
      c = this.devs.open(d);
      const t = Date.now();
      const ifc = await pollIfCounters(c);
      if (!ifc.size) throw new Error('The device returned no interface counters');
      const ifs: IfPoint[] = []; const cls: ClsPoint[] = [];
      const ifRows = new Map((this.devs.interfaces(d.id)).map(i => [i.ifIndex, i]));
      for (const [idx, cur] of ifc) {
        const key = `${d.id}/${idx}`; const prev = this.prevIf.get(key);
        this.prevIf.set(key, { t, c: cur });
        if (!prev) continue;
        const dt = (t - prev.t) / 1000;
        if (dt < 1 || dt > d.interval_sec * 6) continue;
        const wide = cur.hc && prev.c.hc;
        const dIn = delta(cur.inOct, prev.c.inOct, wide), dOut = delta(cur.outOct, prev.c.outOct, wide);
        if (dIn === null || dOut === null) continue;
        const speed = (ifRows.get(idx)?.speedMbps || cur.speedMbps) * 1e6;
        const inBps = Number(dIn) * 8 / dt, outBps = Number(dOut) * 8 / dt;
        if (cur.oper !== 1 && inBps === 0 && outBps === 0) continue;
        const d32 = (a: bigint, b: bigint) => Number(delta(a, b, false) ?? 0n);
        ifs.push({
          ts: t, dev: d.id, ifIndex: idx, dt, inBps, outBps,
          utilIn: speed > 0 ? Math.min(100, 100 * inBps / speed) : 0, utilOut: speed > 0 ? Math.min(100, 100 * outBps / speed) : 0,
          inDisc: d32(cur.inDisc, prev.c.inDisc), outDisc: d32(cur.outDisc, prev.c.outDisc), inErr: d32(cur.inErr, prev.c.inErr), outErr: d32(cur.outErr, prev.c.outErr), oper: cur.oper
        });
      }
      const qosSource = QOS_SOURCES[d.profile ?? ''];
      if (qosSource) {
        const age = Date.now() - (this.structureAt.get(d.id) ?? 0);
        if (!this.structure.has(d.id) || age > 3600_000) {
          this.structure.set(d.id, await qosSource.read(c)); this.structureAt.set(d.id, Date.now());
        }
        const q = await qosSource.poll(c, this.structure.get(d.id) ?? []);
        for (const pol of this.structure.get(d.id) ?? []) {
          if (!perInterface(pol)) continue;
          for (const k of pol.classes) {
            const cur = q.classes.get(`${pol.policyIdx}.${k.objIdx}`);
            if (!cur) continue;
            const label = classLabel(pol, k.name);
            const key = `${d.id}/${pol.ifIndex}/${label}`; const prev = this.prevCls.get(key);
            this.prevCls.set(key, { t, c: cur });
            if (!prev) continue;
            const dt = (t - prev.t) / 1000;
            if (dt < 1 || dt > d.interval_sec * 6) continue;
            const dd = (a: bigint, b: bigint) => delta(a, b, q.wide);
            const pre = dd(cur.pre, prev.c.pre), preB = dd(cur.preB, prev.c.preB), postB = dd(cur.postB, prev.c.postB), drop = dd(cur.drop, prev.c.drop), dropB = dd(cur.dropB, prev.c.dropB);
            if (pre === null || preB === null || postB === null || drop === null || dropB === null) continue;
            const qd = k.queueObjIdx !== null ? q.queueDepth.get(`${pol.policyIdx}.${k.queueObjIdx}`) ?? 0 : 0;
            cls.push({ ts: t, dev: d.id, ifIndex: pol.ifIndex, cls: label, dt, prePkts: Number(pre), preBytes: Number(preB), postBytes: Number(postB), dropPkts: Number(drop), dropBytes: Number(dropB), qdepth: qd });
          }
        }
      }
      // Uptime, CPU, memory and disk change slowly, so they are read about once a minute. A device that does not publish them never fails the poll.
      if (Date.now() - (this.resourcesAt.get(d.id) ?? 0) >= 55_000) {
        this.resourcesAt.set(d.id, Date.now());
        try { const r = await readResources(c, d.sys_object_id ?? ''); if (r) { const t = this.hottest.get(d.id); if (t !== undefined && t !== null) r.tempC = t; this.devs.saveResources(d.id, r); } } catch { /* optional */ }
      }
      // Sensors, PoE, spanning tree, routing neighbours and per-interface link quality, about every three minutes
      if (Date.now() - (this.healthAt.get(d.id) ?? 0) >= 170_000) {
        this.healthAt.set(d.id, Date.now());
        try {
          const hl = await readHealth(c, d.sys_object_id ?? '');
          this.devs.saveHealth(d.id, hl); this.hottest.set(d.id, hl ? hottest(hl.sensors) : null);
          const ex = await readIfExtra(c, Date.now(), (d.sys_object_id ?? '').startsWith('1.3.6.1.4.1.9.')); if (ex.size) this.devs.saveIfExtra(d.id, ex);
        } catch { /* optional */ }
      }
      if (ifs.length || cls.length) await this.store.insertSnmp(ifs, cls);
      this.devs.recordPoll(d.id, true, null);
      this.fails.delete(d.id);
      this.due.set(d.id, Date.now() + d.interval_sec * 1000);
    } catch (e) {
      const n = (this.fails.get(d.id) ?? 0) + 1; this.fails.set(d.id, n);
      const msg = (e as Error).message;
      this.devs.recordPoll(d.id, false, msg);
      if (n === 1 || n % 20 === 0) this.log.warn('snmp', `Polling ${d.name} (${d.ip}) failed${n > 1 ? ` ${n} times in a row` : ''}: ${msg}`);
      this.due.set(d.id, Date.now() + Math.min(d.interval_sec * 2 ** Math.min(n, 3), 600) * 1000);
    } finally {
      c?.close();
      this.running.delete(d.id);
    }
  }
}
