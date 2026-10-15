import type { DeviceRow, DeviceService } from './devices.js';
import { classLabel, delta, perInterface, pollIfCounters, pollQosCounters, readQosStructure, type ClassCounters, type IfCounters, type QosPolicy } from './collect.js';
import type { HostOpts, HostTracker } from './hosts.js';
import type { ClsPoint, IfPoint, TsStore } from '../store/types.js';
import type { AppLog } from '../logger.js';
import type { SnmpClient } from './client.js';
import { readResources } from './resources.js';

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

  constructor(private devs: DeviceService, private store: Pick<TsStore, 'insertSnmp'>, private log: AppLog, private o: PollerOpts, private hosts?: HostTracker) {}

  start(): void {
    this.timer = setInterval(() => this.tick(), 1000);
    this.timer.unref();
  }
  stop(): void { this.stopped = true; if (this.timer) clearInterval(this.timer); }

  /** Forget cached counters and structure for a device (after removal or re-discovery). */
  forget(devId: number): void {
    this.due.delete(devId); this.fails.delete(devId); this.structure.delete(devId); this.structureAt.delete(devId); this.hostDue.delete(devId); this.refreshDue.delete(devId); this.resourcesAt.delete(devId);
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
      if (d.profile === 'cisco-cbqos') {
        const age = Date.now() - (this.structureAt.get(d.id) ?? 0);
        if (!this.structure.has(d.id) || age > 3600_000) {
          this.structure.set(d.id, await readQosStructure(c)); this.structureAt.set(d.id, Date.now());
        }
        const q = await pollQosCounters(c);
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
        try { const r = await readResources(c, d.sys_object_id ?? ''); if (r) this.devs.saveResources(d.id, r); } catch { /* optional */ }
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
