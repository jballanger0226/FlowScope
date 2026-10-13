import type { FlowRecord } from '../collector/types.js';
import type { Retention } from '../settings.js';
import type { ClassLatest, ClassSeries, ClsPoint, IfLatest, IfPoint, IfSeries, ReportResult, ReportSpec, StoreStats, StreamPage, StreamQuery, TimeRange, TsStore } from './types.js';

/** Holds the active store so the backend can be changed without restarting the services that use it. */
export class SwitchableStore implements TsStore {
  constructor(private inner: TsStore) {}
  get kind(): 'sqlite' | 'clickhouse' { return this.inner.kind; }
  /** Replaces the active store and closes the old one. Callers must make sure nothing is writing. */
  async swap(next: TsStore): Promise<void> { const old = this.inner; this.inner = next; await old.close(); }
  insertFlows(r: FlowRecord[]): Promise<void> { return this.inner.insertFlows(r); }
  insertSnmp(i: IfPoint[], c: ClsPoint[]): Promise<void> { return this.inner.insertSnmp(i, c); }
  searchStreams(q: StreamQuery): Promise<StreamPage> { return this.inner.searchStreams(q); }
  streamRecords(k: string, r: TimeRange): Promise<FlowRecord[]> { return this.inner.streamRecords(k, r); }
  report(s: ReportSpec): Promise<ReportResult> { return this.inner.report(s); }
  ifSeries(d: number, i: number, r: TimeRange, t: Retention, p: number): Promise<IfSeries> { return this.inner.ifSeries(d, i, r, t, p); }
  classSeries(d: number, i: number, r: TimeRange, t: Retention, p: number): Promise<ClassSeries> { return this.inner.classSeries(d, i, r, t, p); }
  classLatest(s: number): Promise<ClassLatest[]> { return this.inner.classLatest(s); }
  ifLatest(s: number): Promise<IfLatest[]> { return this.inner.ifLatest(s); }
  maintain(t: Retention, now?: number): Promise<{ dropped: string[] }> { return this.inner.maintain(t, now); }
  deleteDevice(d: number): Promise<void> { return this.inner.deleteDevice(d); }
  stats(): Promise<StoreStats> { return this.inner.stats(); }
  close(): Promise<void> { return this.inner.close(); }
}
