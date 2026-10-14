import type { FlowRecord } from '../collector/types.js';
import type { Retention } from '../settings.js';
import type { ClassLatest, ClassSeries, ClsPoint, IfLatest, IfPoint, IfSeries, ReportResult, ReportSpec, StoreStats, StreamPage, StreamQuery, TimeRange, TsStore } from './types.js';

/**
 * Remembers read results for a few seconds and lets identical requests that arrive together share one run. The explorer repeats its
 * search on a timer and several people look at the same view, so the heaviest reads would otherwise be repeated unchanged.
 * Ranges that end now are rounded to the same few seconds, so "the last hour" asked twice in a row is the same question.
 */
export class QueryCache {
  private entries = new Map<string, { at: number; p: Promise<unknown> }>();
  constructor(readonly ttlMs = 5000, private max = 24, private now: () => number = Date.now) {}
  /** A range that ends within a minute of now is "live": its edges move with the clock, so they are bucketed for the key. */
  range(r: TimeRange): { from: number; to: number; live?: true } {
    const t = this.now();
    if (Math.abs(r.to - t) > 60_000) return { from: r.from, to: r.to };
    const b = this.ttlMs;
    return { from: Math.floor(r.from / b) * b, to: Math.floor(r.to / b) * b, live: true };
  }
  run<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const t = this.now();
    const hit = this.entries.get(key);
    if (hit && t - hit.at < this.ttlMs) return (hit.p as Promise<T>).then(v => structuredClone(v));
    for (const [k, e] of this.entries) if (t - e.at >= this.ttlMs) this.entries.delete(k);
    while (this.entries.size >= this.max) this.entries.delete(this.entries.keys().next().value as string);
    const p = fn();
    this.entries.set(key, { at: t, p });
    p.catch(() => { if (this.entries.get(key)?.p === p) this.entries.delete(key); });
    return p.then(v => structuredClone(v));
  }
  clear(): void { this.entries.clear(); }
}

/** Holds the active store so the backend can be changed without restarting the services that use it. */
export class SwitchableStore implements TsStore {
  private cache = new QueryCache();
  constructor(private inner: TsStore) {}
  get kind(): 'sqlite' | 'clickhouse' { return this.inner.kind; }
  /** Replaces the active store and closes the old one. Callers must make sure nothing is writing. */
  async swap(next: TsStore): Promise<void> { const old = this.inner; this.inner = next; this.cache.clear(); await old.close(); }
  insertFlows(r: FlowRecord[]): Promise<void> { return this.inner.insertFlows(r); }
  insertSnmp(i: IfPoint[], c: ClsPoint[]): Promise<void> { return this.inner.insertSnmp(i, c); }
  searchStreams(q: StreamQuery): Promise<StreamPage> { return this.cache.run(JSON.stringify(['streams', this.inner.kind, { ...q, range: this.cache.range(q.range) }]), () => this.inner.searchStreams(q)); }
  streamRecords(k: string, r: TimeRange): Promise<FlowRecord[]> { return this.cache.run(JSON.stringify(['records', this.inner.kind, k, this.cache.range(r)]), () => this.inner.streamRecords(k, r)); }
  report(s: ReportSpec): Promise<ReportResult> { return this.cache.run(JSON.stringify(['report', this.inner.kind, { ...s, range: this.cache.range(s.range) }]), () => this.inner.report(s)); }
  ifSeries(d: number, i: number, r: TimeRange, t: Retention, p: number): Promise<IfSeries> { return this.inner.ifSeries(d, i, r, t, p); }
  classSeries(d: number, i: number, r: TimeRange, t: Retention, p: number): Promise<ClassSeries> { return this.inner.classSeries(d, i, r, t, p); }
  classLatest(s: number): Promise<ClassLatest[]> { return this.inner.classLatest(s); }
  ifLatest(s: number): Promise<IfLatest[]> { return this.inner.ifLatest(s); }
  async maintain(t: Retention, now?: number): Promise<{ dropped: string[] }> { const r = await this.inner.maintain(t, now); if (r.dropped.length) this.cache.clear(); return r; }
  async deleteDevice(d: number): Promise<void> { await this.inner.deleteDevice(d); this.cache.clear(); }
  stats(): Promise<StoreStats> { return this.inner.stats(); }
  close(): Promise<void> { return this.inner.close(); }
}
