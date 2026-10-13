import type { App } from '../app.js';
import { VERSION } from '../app.js';
import { appByName, APPS } from '../query/apps.js';

export function registerSystem(app: App): void {
  const w = app.web;

  // Status for the header chip and the paused banner.
  w.get('/api/status', 'ro', async c => {
    const col = app.collect();
    const devs = app.devices.list();
    c.json({
      version: VERSION, uptimeSec: Math.floor((Date.now() - app.startedAt) / 1000), demo: app.demo,
      collect: col, collecting: app.collecting(),
      flow: { packets: app.collector.stats.packets, records: app.collector.stats.records, errors: app.collector.stats.errors, dropped: app.collector.droppedRecords, exporters: app.collector.exporters.size },
      snmp: { devices: devs.length, ok: devs.filter(d => d.status === 'ok').length, failing: devs.filter(d => d.status === 'error').length, paused: devs.filter(d => d.status === 'paused').length },
      storeNote: app.storeError
    });
  });

  // Names the search box can complete.
  w.get('/api/meta', 'ro', c => {
    const vlans = app.cdb.db.prepare('SELECT id, name FROM vlans ORDER BY id').all();
    c.json({
      vlans,
      devices: app.devices.list().map(d => ({ id: d.id, name: d.name, ip: d.ip, role: d.role })),
      apps: APPS.map(a => ({ name: a.name, ports: a.ports })),
      tokens: ['src', 'dst', 'ip', 'port', 'sport', 'dport', 'proto', 'app', 'vlan', 'mac', 'hop', 'dev', 'qos', 'dscp'],
      examples: ['qos:changed', 'src:10.1.4.0/24', 'dst:10.9.0.0/16 proto:tcp', 'app:smb', 'hop:fw-edge-01', 'vlan:150', 'vlan:campus', 'port:5432']
    });
    void appByName;
  });

  w.get('/api/vlans', 'ro', c => c.json({ vlans: app.cdb.db.prepare('SELECT id, name, source FROM vlans ORDER BY id').all() }));

  // Flow exporters seen by the collector
  w.get('/api/exporters', 'snmp', c => {
    const rows = app.cdb.db.prepare('SELECT * FROM exporters ORDER BY last_seen DESC').all() as unknown as { ip: string; first_seen: number; last_seen: number; flows: number; version: string | null; device_id: number | null }[];
    const live = app.collector.exporters;
    c.json({
      exporters: rows.map(r => {
        const l = live.get(r.ip);
        return { ip: r.ip, name: app.devices.deviceName(r.ip), version: l?.version || r.version || '', firstSeen: r.first_seen, lastSeen: l?.lastSeen ?? r.last_seen, records: l?.records ?? r.flows, lastError: l?.lastError ?? null, inDeviceList: app.devices.deviceIdForExporter(r.ip) !== null };
      }),
      ports: app.collector.boundPorts, stats: app.collector.stats
    });
  });
}
