import type { App } from '../app.js';
import { HttpError } from '../server/http.js';
import { int, parseRange, str } from './util.js';
import { streamView } from './flows.js';

/** How many flows the page may ask for. Anything else is refused, so the page and the server agree on what is offered. */
export const TOP_COUNTS = [25, 50, 100, 200, 500] as const;
const DIRS = ['either', 'in', 'out'] as const;
const SORTS = ['bytes', 'pkts', 'time'] as const;

export function registerPortFlows(app: App): void {
  const w = app.web;

  // What the picker offers: every polled device with its ports, then the exporters that send flows but are not polled (their ports are numbers only).
  w.get('/api/ports/sources', 'ro', c => {
    const devices = app.devices.list().map(d => ({
      id: d.id, name: d.name, ip: d.ip, role: d.role,
      ports: app.devices.interfaces(d.id).map(i => ({ ifIndex: i.ifIndex, name: i.name, alias: i.alias, speedMbps: i.speedMbps, oper: i.oper === 1 ? 'up' : i.oper === 2 ? 'down' : 'other' }))
    }));
    const rows = app.cdb.db.prepare('SELECT ip, last_seen AS lastSeen FROM exporters ORDER BY last_seen DESC').all() as unknown as { ip: string; lastSeen: number }[];
    const exporters = rows.filter(r => app.devices.deviceIdForExporter(r.ip) === null).map(r => ({ ip: r.ip, name: app.devices.deviceName(r.ip), lastSeen: r.lastSeen }));
    c.json({ devices, exporters, counts: TOP_COUNTS });
  });

  // The biggest flows through one port of one device. `dev` is a polled device id, or `exporter` an address that is not polled.
  // `if` is the interface number, 0 for every port of the device. `dir`: either, in (entering the port) or out (leaving it).
  w.get('/api/ports/flows', 'ro', async c => {
    const devId = int(c.query.get('dev'), 0, 0, 1e9), exporter = str(c.query.get('exporter') ?? '', 64).trim();
    const ifIndex = int(c.query.get('if'), 0, 0, 1e9);
    const limit = int(c.query.get('limit'), 25, 1, 1e6);
    if (!(TOP_COUNTS as readonly number[]).includes(limit)) throw new HttpError(400, `limit must be one of ${TOP_COUNTS.join(', ')}`);
    const dir = DIRS.find(d => d === c.query.get('dir')) ?? 'either';
    const sort = SORTS.find(s => s === c.query.get('sort')) ?? 'bytes';
    const range = parseRange(c.query, '1h');
    let ips: string[], name: string, address: string, port: { ifIndex: number; name: string; alias: string } | null = null;
    if (devId) {
      const d = app.devices.row(devId);
      if (!d) throw new HttpError(404, 'No such device');
      ips = app.devices.exporterIpsForDevice(devId); name = d.name; address = d.ip;
      if (ifIndex) { const i = app.devices.interfaces(devId).find(x => x.ifIndex === ifIndex); port = { ifIndex, name: i?.name ?? `ifIndex ${ifIndex}`, alias: i?.alias ?? '' }; }
    } else if (exporter) {
      if (app.devices.deviceIdForExporter(exporter) !== null) throw new HttpError(400, `${exporter} is a polled device. Choose it by name.`);
      ips = [exporter]; name = app.devices.deviceName(exporter); address = exporter;
      if (ifIndex) port = { ifIndex, name: `ifIndex ${ifIndex}`, alias: '' };
    } else throw new HttpError(400, 'Choose a device');
    const page = await app.store.searchStreams({ range, conds: [{ kind: 'ifport', ips, ifIndex, dir }], sort, dir: 'desc', limit, localIps: app.localIps() });
    c.json({ device: { id: devId || null, name, address }, port, dir, sort, limit, range, total: page.total, shown: page.rows.length, rows: page.rows.map(r => streamView(app, r)) });
  });
}
