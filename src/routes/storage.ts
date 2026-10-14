import type { App } from '../app.js';
import { HttpError } from '../server/http.js';
import { clampRetention, DEFAULTS, type Retention } from '../settings.js';

const LABEL: Record<keyof Retention, string> = { raw: 'raw flow records', m1: '1-minute rollups', h1: '1-hour rollups', d1: 'daily rollups', sRaw: 'SNMP raw samples', sH: 'SNMP hourly rollups' };

/** Coarser tiers must keep at least as long as the finer tier they are built from, otherwise they add no history. */
export function checkRetention(r: Retention): string | null {
  const chain: [keyof Retention, keyof Retention][] = [['m1', 'raw'], ['h1', 'm1'], ['d1', 'h1'], ['sH', 'sRaw']];
  for (const [coarse, fine] of chain) if (r[coarse] < r[fine]) return `Keep ${LABEL[coarse]} at least as long as ${LABEL[fine]} (${r[fine]} days). A coarser tier that expires first leaves a gap.`;
  return null;
}

export function registerStorage(app: App): void {
  const w = app.web;

  // Visible to the SNMP admin and the full admin; only the full admin may change anything.
  w.get('/api/storage', 'snmp', async c => {
    const stats = await app.store.stats();
    const backend = app.settings.get('backend');
    c.json({
      retention: app.settings.get('retention'), defaults: DEFAULTS.retention,
      backend, activeBackend: app.store.kind, backends: [
        { id: 'sqlite', name: 'Embedded SQLite', note: 'Nothing to run. Suits small sites, up to a few thousand flows per second.', available: true },
        { id: 'clickhouse', name: 'ClickHouse', note: 'The default for Docker, Linux and Proxmox installs. Needs a ClickHouse server (set FLOWSCOPE_CLICKHOUSE_URL).', available: !!app.cfg.clickhouseUrl }
      ],
      collecting: app.collecting(), collect: app.collect(),
      canEdit: c.user().role === 'admin',
      stats, storeNote: app.storeError,
      logDays: app.settings.get('logDays')
    });
  });

  w.put('/api/storage/retention', 'admin', async c => {
    const b = await c.body<Partial<Retention>>(10_000);
    const base = app.settings.get('retention');
    for (const k of Object.keys(LABEL) as (keyof Retention)[]) {
      if (b[k] === undefined) continue;
      const n = Number(b[k]);
      if (!Number.isInteger(n) || n < 1 || n > 3650) throw new HttpError(400, `Retention for ${LABEL[k]} must be a whole number of days from 1 to 3650`);
    }
    const next = clampRetention(b, base);
    const err = checkRetention(next);
    if (err) throw new HttpError(400, err);
    const before = app.settings.get('retention');
    app.settings.set('retention', next);
    const changed = (Object.keys(next) as (keyof Retention)[]).filter(k => next[k] !== before[k]).map(k => `${LABEL[k]} ${before[k]} → ${next[k]} days`);
    if (changed.length) app.log.audit(c.user().username, 'Retention changed: ' + changed.join(', '));
    c.json({ retention: next, note: 'Expired data is removed at the next cleanup (every few minutes).' });
  });

  w.post('/api/storage/retention/reset', 'admin', c => {
    app.settings.set('retention', { ...DEFAULTS.retention });
    app.log.audit(c.user().username, 'Retention reset to defaults');
    c.json({ retention: DEFAULTS.retention });
  });

  w.put('/api/storage/logs', 'admin', async c => {
    const b = await c.body<{ days?: number }>(1000);
    const n = Number(b.days);
    if (!Number.isInteger(n) || n < 1 || n > 3650) throw new HttpError(400, 'Log retention must be 1 to 3650 days');
    app.settings.set('logDays', n);
    app.log.audit(c.user().username, `Application log retention set to ${n} days`);
    c.json({ logDays: n });
  });

  w.put('/api/storage/backend', 'admin', async c => {
    const b = await c.body<{ backend?: string }>(1000);
    if (b.backend !== 'sqlite' && b.backend !== 'clickhouse') throw new HttpError(400, 'Choose sqlite or clickhouse');
    if (app.collecting()) throw new HttpError(409, 'The storage backend is locked while collection is running. Stop flow collection and SNMP polling first.');
    const cur = app.settings.get('backend');
    if (b.backend === cur && app.store.kind === b.backend) return c.json({ backend: cur, changed: false });
    if (b.backend === 'clickhouse' && !app.cfg.clickhouseUrl) throw new HttpError(400, 'ClickHouse is not configured. Set FLOWSCOPE_CLICKHOUSE_URL and restart.');
    app.storeError = null;
    const next = await app.openStore(b.backend);
    if (next.kind !== b.backend) { await next.close(); throw new HttpError(502, app.storeError || 'The backend could not be opened'); }
    await app.store.swap(next);
    app.settings.set('backend', b.backend);
    app.log.audit(c.user().username, `Storage backend changed from ${cur} to ${b.backend}. The new backend starts empty; data in the old one is not migrated.`, 'WARN');
    c.json({ backend: b.backend, changed: true, note: 'The new backend starts empty. Data in the old one stays where it is and is not migrated.' });
  });
}
