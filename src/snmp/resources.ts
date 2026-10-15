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
  /** Firewalls: sessions in use now and the most the device can hold. */
  sessions?: number | null; sessionsMax?: number | null;
  /** The hottest chassis sensor in degrees Celsius, when the device has temperature sensors (see health.ts). */
  tempC?: number | null;
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

/* ---- vendor MIBs. The OIDs were checked against the vendors' published MIB definitions; none has been run against real hardware here. ---- */
const ENT = {
  juniperDescr: '1.3.6.1.4.1.2636.3.1.13.1.5', juniperCpu: '1.3.6.1.4.1.2636.3.1.13.1.8', juniperBuffer: '1.3.6.1.4.1.2636.3.1.13.1.11', juniperMemoryMb: '1.3.6.1.4.1.2636.3.1.13.1.15',
  huaweiCpu: '1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5', huaweiMem: '1.3.6.1.4.1.2011.5.25.31.1.1.1.1.7',
  h3cCpu: '1.3.6.1.4.1.25506.2.6.1.1.1.1.6', h3cMem: '1.3.6.1.4.1.25506.2.6.1.1.1.1.8',
  hpCpu: '1.3.6.1.4.1.11.2.14.11.5.1.9.6.1.0', hpMemAlloc: '1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.5', hpMemFree: '1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.6', hpMemTotal: '1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.7',
  fgCpu: '1.3.6.1.4.1.12356.101.4.1.3.0', fgMem: '1.3.6.1.4.1.12356.101.4.1.4.0', fgMemCap: '1.3.6.1.4.1.12356.101.4.1.5.0', fgDisk: '1.3.6.1.4.1.12356.101.4.1.6.0', fgDiskCap: '1.3.6.1.4.1.12356.101.4.1.7.0', fgSes: '1.3.6.1.4.1.12356.101.4.1.8.0',
  panSesMax: '1.3.6.1.4.1.25461.2.1.2.3.2.0', panSesActive: '1.3.6.1.4.1.25461.2.1.2.3.3.0'
};
const maxOf = (m: Map<string, SnmpValue>): number | null => { const v = [...m.values()].map(num).filter((x): x is number => x !== null && x > 0 && x <= 100); return v.length ? Math.max(...v) : null; };

/** CPU, memory, sessions and disk from a vendor's own MIB, picked by the enterprise number in sysObjectID. Fills only what is still empty. */
export async function vendorResources(c: SnmpClient, objectId: string, r: Resources, src: string[], g: (o: string) => number | null): Promise<void> {
  const empty = new Map<string, SnmpValue>();
  const col = (o: string) => c.column(o).catch(() => empty);
  const ent = /^1\.3\.6\.1\.4\.1\.(\d+)\./.exec(objectId)?.[1];
  if (ent === '2636') {
    // Juniper: the routing engine row carries the CPU and the memory ("buffer") use in percent
    const [descr, cpu, buf, mb] = await Promise.all([col(ENT.juniperDescr), col(ENT.juniperCpu), col(ENT.juniperBuffer), col(ENT.juniperMemoryMb)]);
    const rows = [...cpu.keys()].map(k => ({ k, descr: toStr(descr.get(k) ?? null), cpu: num(cpu.get(k)) ?? 0 }));
    const re = rows.filter(x => /routing engine|fpc/i.test(x.descr) && x.cpu > 0).sort((a, b) => b.cpu - a.cpu)[0] ?? rows.filter(x => x.cpu > 0).sort((a, b) => b.cpu - a.cpu)[0];
    if (re && r.cpuPct === null) { r.cpuPct = Math.min(100, re.cpu); src.push('JUNIPER-MIB'); }
    const bp = re ? num(buf.get(re.k)) : null, total = re ? num(mb.get(re.k)) : null;
    if (re && bp !== null && bp > 0 && bp <= 100 && r.memPct === null) {
      r.memPct = bp;
      if (total && total > 0) { r.memTotal = total * 1024 * 1024; r.memUsed = Math.round(r.memTotal * bp / 100); }
      if (!src.includes('JUNIPER-MIB')) src.push('JUNIPER-MIB');
    }
  } else if (ent === '2011') {
    // Huawei: HUAWEI-ENTITY-EXTENT-MIB, one row per board; the busiest is shown
    const [cpu, mem] = await Promise.all([col(ENT.huaweiCpu), col(ENT.huaweiMem)]);
    const c1 = maxOf(cpu), m1 = maxOf(mem);
    if (c1 !== null && r.cpuPct === null) { r.cpuPct = c1; src.push('HUAWEI-ENTITY-EXTENT-MIB'); }
    if (m1 !== null && r.memPct === null) { r.memPct = m1; if (!src.includes('HUAWEI-ENTITY-EXTENT-MIB')) src.push('HUAWEI-ENTITY-EXTENT-MIB'); }
  } else if (ent === '25506') {
    // H3C and HPE Comware: HH3C-ENTITY-EXT-MIB
    const [cpu, mem] = await Promise.all([col(ENT.h3cCpu), col(ENT.h3cMem)]);
    const c1 = maxOf(cpu), m1 = maxOf(mem);
    if (c1 !== null && r.cpuPct === null) { r.cpuPct = c1; src.push('HH3C-ENTITY-EXT-MIB'); }
    if (m1 !== null && r.memPct === null) { r.memPct = m1; if (!src.includes('HH3C-ENTITY-EXT-MIB')) src.push('HH3C-ENTITY-EXT-MIB'); }
  } else if (ent === '11') {
    // HP ProCurve and older HPE switches: the CPU scalar and the first memory row. The three memory columns are sanity checked, since vendors disagree on their order.
    const m = await getEach(c, [ENT.hpCpu, ENT.hpMemAlloc + '.1', ENT.hpMemFree + '.1', ENT.hpMemTotal + '.1']);
    const cpu = num(m.get(ENT.hpCpu)?.value);
    if (cpu !== null && cpu >= 0 && cpu <= 100 && r.cpuPct === null) { r.cpuPct = cpu; src.push('STATISTICS-MIB'); }
    const alloc = num(m.get(ENT.hpMemAlloc + '.1')?.value), free = num(m.get(ENT.hpMemFree + '.1')?.value), total = num(m.get(ENT.hpMemTotal + '.1')?.value);
    if (alloc !== null && free !== null && total !== null && total > 0 && Math.abs(alloc + free - total) <= total * 0.05 && r.memPct === null) {
      r.memTotal = total; r.memUsed = alloc; r.memPct = pctOf(alloc, total); if (!src.includes('STATISTICS-MIB')) src.push('STATISTICS-MIB');
    }
  } else if (ent === '12356') {
    // Fortinet FortiGate
    const m = await getEach(c, [ENT.fgCpu, ENT.fgMem, ENT.fgMemCap, ENT.fgDisk, ENT.fgDiskCap, ENT.fgSes]);
    const v = (o: string) => num(m.get(o)?.value);
    const cpu = v(ENT.fgCpu), mem = v(ENT.fgMem), memCap = v(ENT.fgMemCap), disk = v(ENT.fgDisk), diskCap = v(ENT.fgDiskCap), ses = v(ENT.fgSes);
    if (cpu !== null && cpu >= 0 && cpu <= 100 && r.cpuPct === null) r.cpuPct = cpu;
    if (mem !== null && mem >= 0 && mem <= 100 && r.memPct === null) { r.memPct = mem; if (memCap && memCap > 0) { r.memTotal = memCap * 1024; r.memUsed = Math.round(r.memTotal * mem / 100); } }
    if (disk !== null && diskCap && diskCap > 0 && !r.disks.length) { const tb = diskCap * 1024 * 1024; r.disks = [{ name: 'disk', usedPct: pctOf(disk, diskCap), totalBytes: tb, usedBytes: disk * 1024 * 1024 }]; }
    if (ses !== null && ses >= 0) r.sessions = ses;
    if (cpu !== null || mem !== null || ses !== null) src.push('FORTINET-FORTIGATE-MIB');
  } else if (ent === '25461') {
    // Palo Alto: sessions here; CPU and memory come from HOST-RESOURCES-MIB below
    const m = await getEach(c, [ENT.panSesActive, ENT.panSesMax]);
    const act = num(m.get(ENT.panSesActive)?.value), max = num(m.get(ENT.panSesMax)?.value);
    if (act !== null && act >= 0) { r.sessions = act; r.sessionsMax = max && max > 0 ? max : null; src.push('PAN-COMMON-MIB'); }
  }
  void g;
}

/**
 * Reads uptime, CPU, memory and disk use with whatever the device supports: Cisco's process and memory pool MIBs, the UCD-SNMP-MIB
 * (net-snmp agents such as OPNsense, pfSense and Linux), and HOST-RESOURCES-MIB as the general fallback. Returns null when none of them answer.
 */
export async function readResources(c: SnmpClient, objectId = '', now = Date.now()): Promise<Resources | null> {
  const empty = new Map<string, SnmpValue>();
  const col = (o: string) => c.column(o).catch(() => empty);
  const r: Resources = { uptimeSec: null, cpuPct: null, cores: null, load: null, memPct: null, memTotal: null, memUsed: null, swapPct: null, sessions: null, sessionsMax: null, tempC: null, disks: [], source: '', readAt: now };
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

  await vendorResources(c, objectId, r, src, g);

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
