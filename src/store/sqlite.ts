import { Worker } from 'node:worker_threads';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import type { FlowRecord } from '../collector/types.js';
import type { Retention } from '../settings.js';
import type {
  ClassLatest, ClassSeries, ClsPoint, IfLatest, IfPoint, IfSeries, ReportResult, ReportSpec, StoreStats, StreamPage, StreamQuery, TimeRange, TsStore
} from './types.js';

type Pending = { resolve: (v: any) => void; reject: (e: Error) => void };

/** Calls into one storage worker thread. If the worker dies (an uncaught error, running out of memory), the next call starts a new one. */
export class Rpc {
  private w!: Worker;
  private seq = 1;
  private pending = new Map<number, Pending>();
  private ready!: Promise<void>;
  /** Set by close(): the worker was stopped on purpose and is not restarted. */
  closed = false;
  private dead = false;
  private lastSpawn = 0;
  restarts = 0;
  /** Calls started and not yet answered. */
  load = 0;

  constructor(private dir: string, private writer: boolean, private note: (m: string) => void = () => undefined, private restartDelayMs = 1000) { this.spawn(); }

  private spawn(): void {
    const file = path.join(path.dirname(fileURLToPath(import.meta.url)), 'worker.js');
    const w = new Worker(file, { workerData: { dir: this.dir, writer: this.writer } });
    this.w = w; this.dead = false; this.lastSpawn = Date.now();
    const fail = (e: Error) => { for (const p of this.pending.values()) p.reject(e); this.pending.clear(); };
    this.ready = new Promise((res, rej) => {
      const onMsg = (m: any) => { if (m && m.ready) { w.off('message', onMsg); if (this.pending.size === 0) w.unref(); res(); } };
      w.on('message', onMsg);
      w.once('error', rej);
      w.once('exit', () => rej(new Error('storage worker exited')));
    });
    this.ready.catch(() => undefined);
    w.on('message', (m: any) => {
      if (this.w !== w || !m || m.ready) return;
      const p = this.pending.get(m.id);
      if (!p) return;
      this.pending.delete(m.id);
      if (this.pending.size === 0) w.unref();
      if (m.ok) p.resolve(m.res); else p.reject(new Error(m.err));
    });
    w.on('error', e => { if (this.w === w) { this.note(`The ${this.writer ? 'writing' : 'reading'} storage worker failed: ${e.message}`); fail(e); } });
    w.on('exit', () => {
      if (this.w !== w) return;
      this.dead = true;
      fail(new Error('storage worker exited'));
    });
  }

  async call<T>(op: string, ...args: unknown[]): Promise<T> {
    this.load++;
    try { return await this.callNow<T>(op, args); } finally { this.load--; }
  }

  private async callNow<T>(op: string, args: unknown[]): Promise<T> {
    if (this.closed) throw new Error('storage worker is closed');
    if (this.dead) {
      if (Date.now() - this.lastSpawn < this.restartDelayMs) throw new Error('storage worker is restarting');
      this.restarts++;
      this.note(`Restarting the ${this.writer ? 'writing' : 'reading'} storage worker (restart ${this.restarts})`);
      this.spawn();
    }
    await this.ready;
    if (this.closed) throw new Error('storage worker is closed');
    const id = this.seq++;
    const w = this.w;
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      w.ref();
      w.postMessage({ id, op, args });
    });
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    if (this.dead) return;
    await this.ready.catch(() => undefined);
    const w = this.w;
    w.ref();
    await new Promise<void>(res => { w.once('exit', () => res()); w.postMessage({ close: true }); });
  }
}

/** Default storage backend: an embedded SQLite file in the data directory. Writes and reads run on separate worker threads. */
export class SqliteStore implements TsStore {
  readonly kind = 'sqlite' as const;
  private writer: Rpc;
  /** Two read-only workers: a slow search on one does not hold up every other page waiting behind it. */
  private readers: Rpc[] = [];
  private ingested = 0;
  private dropped = 0;

  private constructor(dir: string, private note: (m: string) => void) {
    this.writer = new Rpc(dir, true, note);
  }

  /** Opens the database. The writer creates the schema first; the read-only reader is started after that. */
  static async open(dir: string, note: (m: string) => void = () => undefined): Promise<SqliteStore> {
    const s = new SqliteStore(dir, note);
    await s.writer.call('stats');
    s.readers = [new Rpc(dir, false, note), new Rpc(dir, false, note)];
    await Promise.all(s.readers.map(r => r.call('stats')));
    return s;
  }

  async insertFlows(records: FlowRecord[]): Promise<void> {
    try { await this.writer.call('insertFlows', records); this.ingested += records.length; } catch (e) { this.dropped += records.length; throw e; }
  }
  /** The reader with the least work waiting. */
  private get reader(): Rpc { return this.readers[0].load <= this.readers[1].load ? this.readers[0] : this.readers[1]; }
  insertSnmp(ifs: IfPoint[], cls: ClsPoint[]): Promise<void> { return this.writer.call('insertSnmp', ifs, cls); }
  searchStreams(q: StreamQuery): Promise<StreamPage> { return this.reader.call('searchStreams', q); }
  streamRecords(skey: string, range: TimeRange): Promise<FlowRecord[]> { return this.reader.call('streamRecords', skey, range); }
  report(spec: ReportSpec): Promise<ReportResult> { return this.reader.call('report', spec); }
  ifSeries(dev: number, ifIndex: number, range: TimeRange, retention: Retention, points: number): Promise<IfSeries> { return this.reader.call('ifSeries', dev, ifIndex, range, retention, points); }
  classSeries(dev: number, ifIndex: number, range: TimeRange, retention: Retention, points: number): Promise<ClassSeries> { return this.reader.call('classSeries', dev, ifIndex, range, retention, points); }
  classLatest(sinceMs: number): Promise<ClassLatest[]> { return this.reader.call('classLatest', sinceMs); }
  ifLatest(sinceMs: number): Promise<IfLatest[]> { return this.reader.call('ifLatest', sinceMs); }
  maintain(retention: Retention, now?: number): Promise<{ dropped: string[] }> { return this.writer.call('maintain', retention, now ?? Date.now()); }
  deleteDevice(dev: number): Promise<void> { return this.writer.call('deleteDevice', dev); }
  async stats(): Promise<StoreStats> {
    const s = await this.reader.call<Omit<StoreStats, 'backend' | 'dropped' | 'ingested'>>('stats');
    return { ...s, backend: 'sqlite', ingested: this.ingested, dropped: this.dropped };
  }
  async close(): Promise<void> { await Promise.all([this.writer.close(), ...this.readers.map(r => r.close())]); }
}
