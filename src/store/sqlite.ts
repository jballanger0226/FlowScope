import { Worker } from 'node:worker_threads';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import type { FlowRecord } from '../collector/types.js';
import type { Retention } from '../settings.js';
import type {
  ClassLatest, ClassSeries, ClsPoint, IfLatest, IfPoint, IfSeries, ReportResult, ReportSpec, StoreStats, StreamPage, StreamQuery, TimeRange, TsStore
} from './types.js';

type Pending = { resolve: (v: any) => void; reject: (e: Error) => void };

class Rpc {
  private w: Worker;
  private seq = 1;
  private pending = new Map<number, Pending>();
  private ready: Promise<void>;
  closed = false;

  constructor(dir: string, writer: boolean) {
    const file = path.join(path.dirname(fileURLToPath(import.meta.url)), 'worker.js');
    this.w = new Worker(file, { workerData: { dir, writer } });
    this.ready = new Promise((res, rej) => {
      const onMsg = (m: any) => { if (m && m.ready) { this.w.off('message', onMsg); if (this.pending.size === 0) this.w.unref(); res(); } };
      this.w.on('message', onMsg);
      this.w.once('error', rej);
    });
    this.w.on('message', (m: any) => {
      if (!m || m.ready) return;
      const p = this.pending.get(m.id);
      if (!p) return;
      this.pending.delete(m.id);
      if (this.pending.size === 0) this.w.unref();
      if (m.ok) p.resolve(m.res); else p.reject(new Error(m.err));
    });
    const fail = (e: Error) => { for (const p of this.pending.values()) p.reject(e); this.pending.clear(); };
    this.w.on('error', fail);
    this.w.on('exit', () => { this.closed = true; fail(new Error('storage worker exited')); });
  }

  async call<T>(op: string, ...args: unknown[]): Promise<T> {
    await this.ready;
    if (this.closed) throw new Error('storage worker is closed');
    const id = this.seq++;
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.w.ref();
      this.w.postMessage({ id, op, args });
    });
  }

  async close(): Promise<void> {
    if (this.closed) return;
    await this.ready.catch(() => undefined);
    this.w.ref();
    await new Promise<void>(res => { this.w.once('exit', () => res()); this.w.postMessage({ close: true }); });
  }
}

/** Default storage backend: an embedded SQLite file in the data directory. Writes and reads run on separate worker threads. */
export class SqliteStore implements TsStore {
  readonly kind = 'sqlite' as const;
  private writer: Rpc;
  private reader!: Rpc;
  private ingested = 0;
  private dropped = 0;

  private constructor(dir: string) {
    this.writer = new Rpc(dir, true);
  }

  /** Opens the database. The writer creates the schema first; the read-only reader is started after that. */
  static async open(dir: string): Promise<SqliteStore> {
    const s = new SqliteStore(dir);
    await s.writer.call('stats');
    s.reader = new Rpc(dir, false);
    await s.reader.call('stats');
    return s;
  }

  async insertFlows(records: FlowRecord[]): Promise<void> {
    try { await this.writer.call('insertFlows', records); this.ingested += records.length; } catch (e) { this.dropped += records.length; throw e; }
  }
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
  async close(): Promise<void> { await Promise.all([this.writer.close(), this.reader.close()]); }
}
