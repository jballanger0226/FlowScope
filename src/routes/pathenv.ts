import type { App } from '../app.js';
import { portKey, type PathEnv } from '../analysis/path.js';

/** Connects the path analysis (analysis/path.ts) to the device list, the interface names, the neighbour tables and host tracking. */
export function pathEnv(app: App): PathEnv {
  let devs: ReturnType<PathEnv['devices']> | null = null;
  const ifs = new Map<number, ReturnType<App['devices']['interfaces']>>();
  const interfaces = (id: number) => { let v = ifs.get(id); if (!v) { v = app.devices.interfaces(id); ifs.set(id, v); } return v; };
  return {
    devices() {
      if (!devs) {
        const ips = new Map<number, string[]>();
        for (const r of app.cdb.db.prepare('SELECT dev_id, ip FROM device_ips').all() as unknown as { dev_id: number; ip: string }[]) { const a = ips.get(r.dev_id) ?? []; a.push(r.ip); ips.set(r.dev_id, a); }
        devs = app.devices.rows().map(d => ({ id: d.id, name: d.name, sysName: d.sys_name ?? '', ips: [d.ip, ...(ips.get(d.id) ?? [])] }));
      }
      return devs;
    },
    ifName: (devId, ifIndex) => interfaces(devId).find(i => i.ifIndex === ifIndex)?.name ?? `if${ifIndex}`,
    ifIndexByName(devId, name) {
      const k = portKey(name);
      if (!k) return null;
      const list = interfaces(devId);
      const hit = list.find(i => portKey(i.name) === k) ?? list.find(i => i.descr && portKey(i.descr) === k);
      return hit ? hit.ifIndex : null;
    },
    neighborsOf: (devId, ifIndex) => app.hosts.neighborsOf(devId, ifIndex).map(n => ({ ...n, ifIndex })),
    neighborsOfDevice: devId => app.hosts.neighborsOfDevice(devId),
    locate(ip, macHint) {
      try {
        const at = app.hosts.locate(ip, macHint).attach;
        return at && at.confidence !== 'low' ? { devId: at.devId, ifIndex: at.ifIndex } : null;
      } catch { return null; }   // host tracking is optional
    }
  };
}
