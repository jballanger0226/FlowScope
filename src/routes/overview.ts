import type { App } from '../app.js';
import type { LogRow } from '../logger.js';
import type { OvInput, OvWlan } from '../../web/views/overview_logic.js';
import { service, serviceLabel } from '../query/apps.js';
import { buildNotices, downDevices, exporterSummary, verdict, type DeviceState } from '../overview.js';
import { linkDevices, linkHealth } from './links.js';
import { chooseTier } from './reports.js';
import { streamView } from './flows.js';

const HOUR = 3600_000;
/** How many items each box on the home page lists. */
const TOP = 5;
const NOTICES = 6;
const LOGS = 6;
const LOG_WINDOW_HOURS = 24;
const FLOW_WINDOW_MIN = 60;
/** A device that has been up for less than this has restarted recently. */
const RECENT_RESTART_SEC = 3600;
/** The flow searches are the slowest part of the page, and several people may open it at once, so their answers are reused for this long. */
const FLOW_CACHE_MS = 30_000;

type StreamView = ReturnType<typeof streamView>;
interface FlowSummary {
  top: StreamView[] | null; error: string | null;
  /** Everything recorded in the window, and the biggest applications in it. Bytes are counted once per stream. */
  traffic: { bytes: number; flows: number; apps: { name: string; bytes: number; share: number }[] } | null;
  /** How many streams in the window had a TTL that ran out, and how many had their DSCP marking changed on the way. null when that could not be counted. */
  anomalies: { ttlExpired: number | null; qosChanged: number | null };
}

export function registerOverview(app: App): void {
  const w = app.web;
  let cache: { at: number; value: FlowSummary } | null = null;

  async function flowSummary(now: number): Promise<FlowSummary> {
    if (cache && now - cache.at < FLOW_CACHE_MS) return cache.value;
    const range = { from: now - FLOW_WINDOW_MIN * 60_000, to: now + 60_000 };
    const localIps = app.localIps();
    const [top, traffic, ttl, qos] = await Promise.allSettled([
      app.store.searchStreams({ range, conds: [], sort: 'bytes', dir: 'desc', limit: TOP, localIps }),
      app.store.report({ range, tier: chooseTier(app, range, undefined), dims: ['proto', 'svc'], prefix: 32, bidir: false, conds: [], sortBy: 'bytes', topN: 20000, localIps }),
      app.store.searchStreams({ range, conds: [{ kind: 'ttl', mode: 'expired' }], sort: 'time', dir: 'desc', limit: 1, localIps }),
      app.store.searchStreams({ range, conds: [{ kind: 'qos', mode: 'changed' }], sort: 'time', dir: 'desc', limit: 1, localIps })
    ]);
    let apps: NonNullable<FlowSummary['traffic']>['apps'] = [];
    if (traffic.status === 'fulfilled') {
      // the application is the protocol plus the service port, grouped here the same way the Report builder does it
      const by = new Map<string, number>();
      for (const r of traffic.value.rows) { const k = serviceLabel(service(Number(r.dims.proto), Number(r.dims.svc), Number(r.dims.svc))); by.set(k, (by.get(k) ?? 0) + r.bytes); }
      const total = traffic.value.totals.bytes;
      apps = [...by].sort((a, b) => b[1] - a[1]).slice(0, TOP).map(([name, bytes]) => ({ name, bytes, share: total > 0 ? bytes / total : 0 }));
    }
    const value: FlowSummary = {
      top: top.status === 'fulfilled' ? top.value.rows.map(r => streamView(app, r)) : null,
      error: top.status === 'rejected' ? (top.reason as Error).message : null,
      traffic: traffic.status === 'fulfilled' ? { bytes: traffic.value.totals.bytes, flows: traffic.value.totals.flows, apps } : null,
      anomalies: { ttlExpired: ttl.status === 'fulfilled' ? ttl.value.total : null, qosChanged: qos.status === 'fulfilled' ? qos.value.total : null }
    };
    cache = { at: now, value };
    return value;
  }

  // One read of everything the home page shows. The logs are for administrators only, as on the Admin page, so other roles get null for them.
  w.get('/api/overview', 'ro', async c => {
    const now = Date.now();
    const [links, flows] = await Promise.all([linkDevices(app, 10), flowSummary(now)]);
    const polled = app.devices.list();
    const states: DeviceState[] = polled.map(d => ({ id: d.id, name: d.name, ip: d.ip, role: d.role, status: d.status, lastOk: d.lastOk, lastError: d.lastError, addedAt: d.addedAt }));
    const linkBy = new Map(links.devices.map(d => [d.id, d]));

    // notices: the same rules as each device's own "Needs attention" list, read for every device that is answering.
    // Devices that are not answering are listed in their own panel, so they are not repeated among the notices.
    const inputs = states.map(dev => {
      const ld = linkBy.get(dev.id);
      if (!ld || dev.status !== 'ok') return { dev, ov: null };
      const hr = linkHealth(app, dev.id);
      const wl = ld.hasWlan ? (app.hosts.wlanOf(dev.id) as unknown as OvWlan | null) : null;
      const ov: OvInput = { dev: ld, health: hr, wlan: wl, neighbours: null, arp: null, hasHardware: false, thresholds: links.thresholds };
      return { dev, ov };
    });
    const notices = buildNotices(inputs, now).filter(n => n.kind === 'issue');
    const bad = notices.filter(n => n.level === 'bad').length;

    // flow exporters: live counters where the collector has them, otherwise what was stored
    const live = app.collector.exporters;
    const rows = app.cdb.db.prepare('SELECT ip, first_seen, last_seen, flows, version FROM exporters ORDER BY last_seen DESC').all() as unknown as { ip: string; first_seen: number; last_seen: number; flows: number; version: string | null }[];
    const exporters = rows.map(r => {
      const l = live.get(r.ip);
      return { ip: r.ip, name: app.devices.deviceName(r.ip), devId: app.devices.deviceIdForExporter(r.ip), version: l?.version || r.version || '', records: l?.records ?? r.flows, lastSeen: l?.lastSeen ?? r.last_seen, lastError: l?.lastError ?? null };
    });
    const ex = exporterSummary(exporters, now);

    // the busiest links in the last few minutes, from SNMP. VLAN interfaces are left out: they carry a whole subnet and say little about one port.
    const busiest = links.devices.flatMap(d => d.interfaces.filter(i => !i.isVlanIf && i.oper === 'up' && (i.utilIn !== null || i.utilOut !== null)).map(i => ({
      devId: d.id, dev: d.name, ifIndex: i.ifIndex, name: i.name, alias: i.alias, speedMbps: i.speedMbps, utilIn: i.utilIn, utilOut: i.utilOut, inBps: i.inBps, outBps: i.outBps, util: Math.max(i.utilIn ?? 0, i.utilOut ?? 0), over: i.flagged
    }))).filter(i => i.util > 0).sort((a, b) => b.util - a.util).slice(0, TOP);

    const answering = polled.filter(d => d.status === 'ok');
    const busyCpu = answering.filter(d => d.resources?.cpuPct != null).map(d => ({ id: d.id, name: d.name, role: d.role, cpuPct: d.resources!.cpuPct, memPct: d.resources!.memPct })).sort((a, b) => (b.cpuPct ?? 0) - (a.cpuPct ?? 0)).slice(0, 3);
    // devices that restarted in the last hour: a reboot nobody planned is worth knowing about even though the device is answering again
    const restarted = answering.filter(d => d.resources?.uptimeSec != null && d.resources.uptimeSec < RECENT_RESTART_SEC).map(d => ({ id: d.id, name: d.name, role: d.role, uptimeSec: d.resources!.uptimeSec! })).sort((a, b) => a.uptimeSec - b.uptimeSec).slice(0, TOP);

    const down = downDevices(states, now);
    const collect = app.collect();
    const polls = polled.filter(d => d.polling && d.lastPoll !== null).map(d => d.lastPoll!);

    let logs: { windowHours: number; errors: number; warnings: number; items: LogRow[] } | null = null;
    if (c.user().role === 'admin') {
      app.log.flush();
      const since = now - LOG_WINDOW_HOURS * HOUR;
      const counts = app.cdb.db.prepare("SELECT level, COUNT(*) AS n FROM logs WHERE ts >= ? AND level IN ('WARN', 'ERROR') GROUP BY level").all(since) as unknown as { level: string; n: number }[];
      const items = app.cdb.db.prepare("SELECT id, ts, level, source, user, message FROM logs WHERE ts >= ? AND level IN ('WARN', 'ERROR') ORDER BY CASE level WHEN 'ERROR' THEN 0 ELSE 1 END, ts DESC, id DESC LIMIT ?").all(since, LOGS) as unknown as LogRow[];
      logs = { windowHours: LOG_WINDOW_HOURS, errors: counts.find(x => x.level === 'ERROR')?.n ?? 0, warnings: counts.find(x => x.level === 'WARN')?.n ?? 0, items };
    }

    c.json({
      generatedAt: now,
      collect,
      verdict: verdict({ down: down.length, bad, warn: notices.length - bad, silentExporters: ex.silent.length, collect }),
      // when data was last received: a collector that has quietly stopped is the failure that is easiest to miss
      freshness: { lastFlowAt: exporters.length ? Math.max(...exporters.map(e => e.lastSeen)) : null, lastPollAt: polls.length ? Math.max(...polls) : null },
      notices: { total: notices.length, bad, warn: notices.length - bad, items: notices.slice(0, NOTICES) },
      devices: { total: states.length, ok: answering.length, paused: states.filter(d => d.status === 'paused').length, pending: states.filter(d => d.status === 'pending').length, down, busyCpu, restarted },
      flows: {
        windowMinutes: FLOW_WINDOW_MIN, top: flows.top, error: flows.error, traffic: flows.traffic, anomalies: flows.anomalies,
        stats: { packets: app.collector.stats.packets, records: app.collector.stats.records, errors: app.collector.stats.errors, dropped: app.collector.droppedRecords },
        exporters: { total: ex.total, active: ex.active, silent: ex.silent.slice(0, TOP), top: [...exporters].sort((a, b) => b.records - a.records).slice(0, TOP) }
      },
      ports: { windowMinutes: 10, busiest },
      logs
    });
  });
}
