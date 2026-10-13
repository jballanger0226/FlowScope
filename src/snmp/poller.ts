import type { DeviceRow, DeviceService } from './devices.js';
import { delta, pollIfCounters, pollQosCounters, readQosStructure, type ClassCounters, type IfCounters, type QosPolicy } from './collect.js';
import type { ClsPoint, IfPoint, TsStore } from '../store/types.js';
import type { AppLog } from '../logger.js';
import type { SnmpClient } from './client.js';

interface PrevIf { t: number; c: IfCounters }
interface PrevCls { t: number; c: ClassCounters }

export interface PollerOpts { maxConcurrent?: number; isEnabled: () => boolean }

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

  constructor(private devs: DeviceService, private store: Pick<TsStore, 'insertSnmp'>, private log: AppLog, private o: PollerOpts) {}

  start(): void {
    this.timer = setInterval(() => this.tick(), 1000);
    this.timer.unref();
  }
  stop(): void { this.stopped = true; if (this.timer) clearInterval(this.timer); }

  /** Forget cached counters and structure for a device (after removal or re-discovery). */
  forget(devId: number): void {
    this.due.delete(devId); this.fails.delete(devId); this.structure.delete(devId); this.structureAt.delete(devId);
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
          if (pol.direction !== 'output') continue;
          for (const k of pol.classes) {
            const cur = q.classes.get(`${pol.policyIdx}.${k.objIdx}`);
            if (!cur) continue;
            const key = `${d.id}/${pol.ifIndex}/${k.name}`; const prev = this.prevCls.get(key);
            this.prevCls.set(key, { t, c: cur });
            if (!prev) continue;
            const dt = (t - prev.t) / 1000;
            if (dt < 1 || dt > d.interval_sec * 6) continue;
            const dd = (a: bigint, b: bigint) => delta(a, b, true);
            const pre = dd(cur.pre, prev.c.pre), preB = dd(cur.preB, prev.c.preB), postB = dd(cur.postB, prev.c.postB), drop = dd(cur.drop, prev.c.drop), dropB = dd(cur.dropB, prev.c.dropB);
            if (pre === null || preB === null || postB === null || drop === null || dropB === null) continue;
            const qd = k.queueObjIdx !== null ? q.queueDepth.get(`${pol.policyIdx}.${k.queueObjIdx}`) ?? 0 : 0;
            cls.push({ ts: t, dev: d.id, ifIndex: pol.ifIndex, cls: k.name, dt, prePkts: Number(pre), preBytes: Number(preB), postBytes: Number(postB), dropPkts: Number(drop), dropBytes: Number(dropB), qdepth: qd });
          }
        }
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
