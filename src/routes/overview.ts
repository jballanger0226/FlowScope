import type { App } from '../app.js';
import type { LogRow } from '../logger.js';
import type { OvInput, OvWlan } from '../../web/views/overview_logic.js';
import { buildNotices, downDevices, exporterSummary, type DeviceState } from '../overview.js';
import { linkDevices, linkHealth } from './links.js';
import { streamView } from './flows.js';

const HOUR = 3600_000;
/** How many items each box on the home page lists. */
const TOP = 5;
const NOTICES = 8;
const LOGS = 8;
const LOG_WINDOW_HOURS = 24;
const FLOW_WINDOW_MIN = 60;
/** The slowest part of the page is the flow search, and several people may open the page at once, so its answer is reused for this long. */
const FLOW_CACHE_MS = 30_000;

export function registerOverview(app: App): void {
  const w = app.web;
  let flowCache: { at: number; value: { top: ReturnType<typeof streamView>[] | null; error: string | null } } | null = null;

  async function topFlows(now: number): Promise<{ top: ReturnType<typeof streamView>[] | null; error: string | null }> {
    if (flowCache && now - flowCache.at < FLOW_CACHE_MS) return flowCache.value;
    let value: { top: ReturnType<typeof streamView>[] | null; error: string | null };
    try {
      const page = await app.store.searchStreams({ range: { from: now - FLOW_WINDOW_MIN * 60_000, to: now + 60_000 }, conds: [], sort: 'bytes', dir: 'desc', limit: TOP, localIps: app.localIps() });
      value = { top: page.rows.map(r => streamView(app, r)), error: null };
    } catch (e) { value = { top: null, error: (e as Error).message }; }
    flowCache = { at: now, value };
    return value;
  }

  // One read of everything the home page shows. The logs are for administrators only, as on the Admin page, so other roles get null for them.
  w.get('/api/overview', 'ro', async c => {
    const now = Date.now();
    const [links, flows] = await Promise.all([linkDevices(app, 10), topFlows(now)]);
    const polled = app.devices.list();
    const states: DeviceState[] = polled.map(d => ({ id: d.id, name: d.name, ip: d.ip, role: d.role, status: d.status, lastOk: d.lastOk, lastError: d.lastError, addedAt: d.addedAt }));
    const linkBy = new Map(links.devices.map(d => [d.id, d]));

    // notices: the same rules as each device's own "Needs attention" list, read for every device that is answering
    const inputs = states.map(dev => {
      const ld = linkBy.get(dev.id);
      if (!ld || dev.status !== 'ok') return { dev, ov: null };
      const hr = linkHealth(app, dev.id);
      const wl = ld.hasWlan ? (app.hosts.wlanOf(dev.id) as unknown as OvWlan | null) : null;
      const ov: OvInput = { dev: ld, health: hr, wlan: wl, neighbours: null, arp: null, hasHardware: false, thresholds: links.thresholds };
      return { dev, ov };
    });
    const notices = buildNotices(inputs, now);

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

    const busyCpu = polled.filter(d => d.status === 'ok' && d.resources?.cpuPct != null).map(d => ({ id: d.id, name: d.name, role: d.role, cpuPct: d.resources!.cpuPct, memPct: d.resources!.memPct })).sort((a, b) => (b.cpuPct ?? 0) - (a.cpuPct ?? 0)).slice(0, 3);

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
      collect: app.collect(),
      notices: { total: notices.length, bad: notices.filter(n => n.level === 'bad').length, warn: notices.filter(n => n.level === 'warn').length, items: notices.slice(0, NOTICES) },
      devices: {
        total: states.length, ok: states.filter(d => d.status === 'ok').length, paused: states.filter(d => d.status === 'paused').length, pending: states.filter(d => d.status === 'pending').length,
        down: downDevices(states, now), busyCpu
      },
      flows: {
        windowMinutes: FLOW_WINDOW_MIN, top: flows.top, error: flows.error,
        stats: { packets: app.collector.stats.packets, records: app.collector.stats.records, errors: app.collector.stats.errors, dropped: app.collector.droppedRecords },
        exporters: { total: ex.total, active: ex.active, silent: ex.silent.slice(0, TOP), top: [...exporters].sort((a, b) => b.records - a.records).slice(0, TOP) }
      },
      ports: { windowMinutes: 10, busiest },
      logs
    });
  });
}
