/** Lining up moments when an interface dropped or discarded packets with the CPU of the device at those moments. */
export interface Moment { ts: number }
export interface CpuPoint { ts: number; cpu: number | null; cpuMax: number | null }
export interface Correlation { moments: number; high: number; withData: number; avgDuring: number | null; avgOther: number | null; peak: number | null }

/** The CPU reading nearest in time to `ts`, as long as one lies within `reach` ms. The busiest value of the bucket is used where the history was averaged. */
function cpuAt(points: CpuPoint[], ts: number, reach: number): number | null {
  let best: CpuPoint | null = null, gap = Infinity;
  for (const p of points) { const g = Math.abs(p.ts - ts); if (g < gap && (p.cpuMax ?? p.cpu) !== null) { best = p; gap = g; } }
  return best && gap <= reach ? (best.cpuMax ?? best.cpu) : null;
}

export function correlate(momentsTs: number[], cpu: CpuPoint[], threshold: number, reach: number): Correlation {
  const during: number[] = [];
  for (const t of momentsTs) { const v = cpuAt(cpu, t, reach); if (v !== null) during.push(v); }
  const marked = new Set(momentsTs);
  const other = cpu.filter(p => !momentsTs.some(t => Math.abs(p.ts - t) <= reach) && !marked.has(p.ts)).map(p => p.cpu).filter((v): v is number => v !== null);
  const avg = (a: number[]): number | null => (a.length ? a.reduce((x, y) => x + y, 0) / a.length : null);
  return { moments: momentsTs.length, withData: during.length, high: during.filter(v => v >= threshold).length, avgDuring: avg(during), avgOther: avg(other), peak: during.length ? Math.max(...during) : null };
}

/** One plain sentence on what the match says. */
export function verdict(c: Correlation, threshold: number): { text: string; level: 'info' | 'warn' | 'ok' } {
  if (!c.moments) return { text: 'No drops or discards in this range.', level: 'ok' };
  if (!c.withData) return { text: 'There is no CPU history for these moments.', level: 'info' };
  const share = c.high / c.withData;
  const base = `${c.high} of ${c.withData} moments with drops or discards had the CPU at ${threshold}% or more (busiest ${Math.round(c.peak ?? 0)}%).`;
  const cmp = c.avgDuring !== null && c.avgOther !== null ? ` Average CPU was ${Math.round(c.avgDuring)}% during them and ${Math.round(c.avgOther)}% at other times.` : '';
  if (share >= 0.5 && c.avgOther !== null && (c.avgDuring ?? 0) > c.avgOther + 10) return { text: `Likely related: ${base}${cmp} A busy CPU can drop packets it has to process itself.`, level: 'warn' };
  if (share >= 0.5) return { text: `${base}${cmp} The CPU is high much of the time, so this alone does not show a link.`, level: 'info' };
  return { text: `Probably not CPU: ${base}${cmp}`, level: 'ok' };
}
