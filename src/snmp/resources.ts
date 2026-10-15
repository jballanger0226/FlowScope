import { toNum, toStr, type SnmpClient, type SnmpValue } from './client.js';
import { OID } from './oids.js';

/** What a device reports about its own health: uptime, processor, memory and storage. Any part the device does not publish stays null. */
export interface DiskUse { name: string; usedPct: number; totalBytes: number; usedBytes: number }
export interface Resources {
  /** How long the host has been up (HOST-RESOURCES hrSystemUptime), not the SNMP agent: the agent restarts without the device rebooting. */
  uptimeSec: number | null;
  cpuPct: number | null; cores: number | null;
  /** 1, 5 and 15 minute load averages (net-snmp agents). */
  load: [number, number, number] | null;
  memPct: number | null; memTotal: number | null; memUsed: number | null;
  swapPct: number | null;
  disks: DiskUse[];
  /** Which MIBs the figures came from, for the "not published" explanation and for support. */
  source: string;
  readAt: number;
}

const num = (v: SnmpValue | undefined): number | null => (v === undefined || v === null ? null : toNum(v));
const pctOf = (used: number, total: number): number => Math.round(Math.max(0, Math.min(100, (used / total) * 100)) * 10) / 10;
const HR_RAM = '1.3.6.1.2.1.25.2.1.2', HR_VIRTUAL = '1.3.6.1.2.1.25.2.1.3', HR_DISK = '1.3.6.1.2.1.25.2.1.4';
const MIN_DISK = 100 * 1024 * 1024;

/** One request for all scalars; if the device rejects it (SNMPv1 agents refuse a request that names an object they lack), one request each. */
async function getEach(c: SnmpClient, oids: string[]): Promise<Map<string, { value: SnmpValue }>> {
  try { return await c.get(oids); } catch { /* fall through */ }
  const out = new Map<string, { value: SnmpValue }>();
  for (const o of oids) { try { for (const [k, v] of await c.get([o])) out.set(k, v); } catch { /* not there */ } }
  return out;
}

/**
 * Reads uptime, CPU, memory and disk use with whatever the device supports: Cisco's process and memory pool MIBs, the UCD-SNMP-MIB
 * (net-snmp agents such as OPNsense, pfSense and Linux), and HOST-RESOURCES-MIB as the general fallback. Returns null when none of them answer.
 */
export async function readResources(c: SnmpClient, objectId = '', now = Date.now()): Promise<Resources | null> {
  const empty = new Map<string, SnmpValue>();
  const col = (o: string) => c.column(o).catch(() => empty);
  const r: Resources = { uptimeSec: null, cpuPct: null, cores: null, load: null, memPct: null, memTotal: null, memUsed: null, swapPct: null, disks: [], source: '', readAt: now };
  const src: string[] = [];

  const sc = await getEach(c, [OID.hrSystemUptime, OID.ssCpuIdle, OID.memTotalReal, OID.memAvailReal, OID.memBuffer, OID.memCached, OID.memTotalSwap, OID.memAvailSwap]);
  const g = (o: string) => num(sc.get(o)?.value);
  const ticks = g(OID.hrSystemUptime);
  if (ticks !== null && ticks >= 0) r.uptimeSec = Math.floor(ticks / 100);

  // Cisco: CISCO-PROCESS-MIB for the processor and CISCO-MEMORY-POOL-MIB for memory (the "Processor" pool)
  if (objectId.startsWith('1.3.6.1.4.1.9.')) {
    const [m1, m5s, names, used, free] = await Promise.all([col(OID.cpmCPUTotal1minRev), col(OID.cpmCPUTotal5secRev), col(OID.ciscoMemoryPoolName), col(OID.ciscoMemoryPoolUsed), col(OID.ciscoMemoryPoolFree)]);
    const cpus = [...(m1.size ? m1 : m5s).values()].map(num).filter((x): x is number => x !== null && x >= 0 && x <= 100);
    if (cpus.length) { r.cpuPct = Math.max(...cpus); src.push('CISCO-PROCESS-MIB'); }
    const key = [...names].find(([, v]) => /^processor$/i.test(toStr(v)))?.[0] ?? [...used.keys()][0];
    const u = key === undefined ? null : num(used.get(key)), f = key === undefined ? null : num(free.get(key));
    if (u !== null && f !== null && u + f > 0) { r.memUsed = u; r.memTotal = u + f; r.memPct = pctOf(u, u + f); src.push('CISCO-MEMORY-POOL-MIB'); }
  }

  // UCD-SNMP-MIB: net-snmp agents. "Used" leaves out cache and buffers, the way free(1) does, so a file cache does not read as a full memory.
  const idle = g(OID.ssCpuIdle);
  if (r.cpuPct === null && idle !== null && idle >= 0 && idle <= 100) { r.cpuPct = 100 - idle; src.push('UCD-SNMP-MIB'); }
  const totalKb = g(OID.memTotalReal), availKb = g(OID.memAvailReal);
  if (r.memPct === null && totalKb && totalKb > 0 && availKb !== null) {
    const usedKb = Math.max(0, totalKb - availKb - (g(OID.memBuffer) ?? 0) - (g(OID.memCached) ?? 0));
    r.memTotal = totalKb * 1024; r.memUsed = usedKb * 1024; r.memPct = pctOf(usedKb, totalKb);
    if (!src.includes('UCD-SNMP-MIB')) src.push('UCD-SNMP-MIB');
  }
  const swapTotal = g(OID.memTotalSwap), swapAvail = g(OID.memAvailSwap);
  if (swapTotal && swapTotal > 0 && swapAvail !== null) r.swapPct = pctOf(swapTotal - swapAvail, swapTotal);
  if (idle !== null || totalKb) {
    const la = await col(OID.laLoadInt);
    const l = ['1', '2', '3'].map(k => num(la.get(k)));
    if (l.every(x => x !== null)) r.load = l.map(x => Math.round(x as number) / 100) as [number, number, number];
  }

  // HOST-RESOURCES-MIB: processors, and memory and storage where the vendor MIBs did not already give them
  const [load, type, descr, unit, size, usedCol] = await Promise.all([col(OID.hrProcessorLoad), col(OID.hrStorageType), col(OID.hrStorageDescr), col(OID.hrStorageAllocationUnits), col(OID.hrStorageSize), col(OID.hrStorageUsed)]);
  const loads = [...load.values()].map(num).filter((x): x is number => x !== null && x >= 0 && x <= 100);
  if (loads.length) {
    r.cores = loads.length;
    if (r.cpuPct === null) { r.cpuPct = Math.round(loads.reduce((a, b) => a + b, 0) / loads.length); src.push('HOST-RESOURCES-MIB'); }
  }
  const rows = [...type.keys()].map(k => {
    const u = num(unit.get(k)) ?? 0;
    return { k, type: toStr(type.get(k) ?? null), descr: toStr(descr.get(k) ?? null), size: (num(size.get(k)) ?? 0) * u, used: (num(usedCol.get(k)) ?? 0) * u };
  });
  if (r.memPct === null) {
    const ram = rows.find(x => x.type === HR_RAM && x.size > 0);
    if (ram) {
      // net-snmp reports file cache and buffers as separate rows and counts them as used in the RAM row
      const cache = rows.filter(x => /^(cached memory|memory buffers)$/i.test(x.descr)).reduce((a, x) => a + x.used, 0);
      const used = Math.max(0, ram.used - cache);
      r.memTotal = ram.size; r.memUsed = used; r.memPct = pctOf(used, ram.size);
      if (!src.includes('HOST-RESOURCES-MIB')) src.push('HOST-RESOURCES-MIB');
    }
  }
  if (r.swapPct === null) {
    const sw = rows.find(x => x.type === HR_VIRTUAL && /swap|page|virtual memory/i.test(x.descr) && x.size > 0) ?? rows.find(x => /^swap space$/i.test(x.descr) && x.size > 0);
    if (sw) r.swapPct = pctOf(sw.used, sw.size);
  }
  // filesystems: skip small and special ones, and the many mounts of one pool (ZFS datasets share a size)
  const seen = new Set<string>();
  const disks: DiskUse[] = [];
  for (const x of rows) {
    if (x.type !== HR_DISK || x.size < MIN_DISK) continue;
    const key = `${x.size}|${x.used}`;
    if (seen.has(key)) continue;
    seen.add(key);
    disks.push({ name: x.descr, usedPct: pctOf(x.used, x.size), totalBytes: x.size, usedBytes: x.used });
  }
  r.disks = disks.sort((a, b) => b.usedPct - a.usedPct).slice(0, 4);
  if (r.disks.length && !src.includes('HOST-RESOURCES-MIB')) src.push('HOST-RESOURCES-MIB');

  r.source = src.join(' + ');
  const any = r.uptimeSec !== null || r.cpuPct !== null || r.memPct !== null || r.disks.length > 0 || r.load !== null;
  return any ? r : null;
}
