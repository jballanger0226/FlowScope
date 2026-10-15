import type { App } from '../app.js';
import { HttpError } from '../server/http.js';
import { DeviceError } from '../snmp/devices.js';
import { CredError, type CredInput } from '../snmp/creds.js';
import { TargetPolicy } from '../snmp/allowed.js';
import { attachment, int, str, stamp } from './util.js';
import { runChecks, cleanOid } from '../snmp/diagnose.js';
import { WalkJobs, WalkBusy, jobView, filterRows, exportRows, EXPORT_FORMATS, type ExportFormat } from '../snmp/walkjobs.js';

/** Turns the service-level errors into HTTP errors with the right status. */
async function guard<T>(fn: () => T | Promise<T>): Promise<T> {
  try { return await fn(); } catch (e) {
    if (e instanceof DeviceError) throw new HttpError(e.status, e.message);
    if (e instanceof CredError) throw new HttpError(400, e.message);
    throw e;
  }
}

function credInput(b: Record<string, unknown>): CredInput {
  return {
    name: str(b.name, 64), version: b.version as 'v2c' | 'v3',
    community: typeof b.community === 'string' && b.community ? b.community : undefined,
    username: str(b.username, 64), level: (str(b.level, 20) || undefined) as CredInput['level'],
    authProto: str(b.authProto, 20) || undefined, authKey: typeof b.authKey === 'string' && b.authKey ? b.authKey : undefined,
    privProto: str(b.privProto, 20) || undefined, privKey: typeof b.privKey === 'string' && b.privKey ? b.privKey : undefined,
    context: str(b.context, 64)
  };
}

export function registerDevices(app: App): void {
  const w = app.web;
  const who = (c: { user(): { username: string } }) => c.user().username;

  /* ---- devices ---- */
  /** SNMP-role users may be limited to certain networks; administrators never are. */
  const policy = () => new TargetPolicy(app.settings.get('snmpAccess').allowedNets);
  const mayReach = (c: { user(): { role: string } }) => { const p = policy(); return c.user().role === 'admin' || p.open ? undefined : (ip: string) => p.allows(ip); };
  const checkTarget = (c: { user(): { role: string } }, ip: string) => {
    const ok = mayReach(c);
    if (ok && !ok(ip)) throw new HttpError(403, `${ip} is outside the networks you may use. An administrator sets them under Admin, SNMP credentials.`);
  };

  w.get('/api/devices', 'snmp', c => c.json({ devices: app.devices.list(), polling: app.collect().snmp }));

  w.post('/api/devices/test', 'snmp', async c => {
    const b = await c.body<{ ip?: string; port?: number; credId?: number }>(2000);
    const credId = b.credId ?? app.creds.defaultId();
    if (credId === null || credId === undefined) throw new HttpError(400, 'Create a credential set first');
    const ip = str(b.ip, 64).trim(), port = int(b.port, 161, 1, 65535);
    checkTarget(c, ip);
    // a test sends the stored credential to the address, so it is recorded whether or not the device answers
    app.log.audit(who(c), `Tested SNMP credential set "${app.creds.list().find(x => x.id === credId)?.name ?? credId}" against ${ip}:${port}`);
    const p = await guard(() => app.devices.test(ip, port, credId));
    c.json({
      ok: true, sysName: p.info.sysName, sysDescr: p.info.sysDescr, uptimeSec: p.info.uptimeSec, interfaces: p.ifaces.length,
      policies: p.qos.length, classes: p.qos.reduce((a, q) => a + q.classes.length, 0), profile: p.profile
    });
  });

  w.post('/api/devices', 'snmp', async c => {
    const b = await c.body<{ ip?: string; name?: string; port?: number; credId?: number; intervalSec?: number }>(5000);
    checkTarget(c, str(b.ip, 64).trim());
    const d = await guard(() => app.devices.add({
      ip: str(b.ip, 64), name: str(b.name, 64) || undefined, port: b.port === undefined ? undefined : Number(b.port),
      credId: b.credId === undefined ? undefined : Number(b.credId), intervalSec: b.intervalSec === undefined ? undefined : Number(b.intervalSec)
    }));
    app.log.audit(who(c), `Added SNMP device ${d.name} (${d.ip})`);
    c.json({ device: d }, 201);
  });

  w.patch('/api/devices/:id', 'snmp', async c => {
    const b = await c.body<{ name?: string; credId?: number; intervalSec?: number; port?: number }>(5000);
    const id = int(c.params.id, 0, 0, 1e9);
    const d = await guard(() => app.devices.update(id, {
      name: b.name === undefined ? undefined : str(b.name, 64), credId: b.credId === undefined ? undefined : Number(b.credId),
      intervalSec: b.intervalSec === undefined ? undefined : Number(b.intervalSec), port: b.port === undefined ? undefined : Number(b.port)
    }));
    app.log.audit(who(c), `Edited SNMP device ${d.name}`);
    c.json({ device: d });
  });

  w.post('/api/devices/:id/polling', 'snmp', async c => {
    const b = await c.body<{ on?: boolean }>(500);
    const id = int(c.params.id, 0, 0, 1e9);
    if (typeof b.on !== 'boolean') throw new HttpError(400, 'Send {"on": true} or {"on": false}');
    await guard(() => app.devices.setPolling(id, b.on!));
    const d = app.devices.list().find(x => x.id === id)!;
    app.log.audit(who(c), `Polling ${b.on ? 'resumed' : 'paused'} for ${d.name}`);
    c.json({ device: d });
  });

  w.post('/api/devices/:id/rediscover', 'snmp', async c => {
    const d = await guard(() => app.devices.rediscover(int(c.params.id, 0, 0, 1e9)));
    app.log.audit(who(c), `Re-read interfaces and QoS policies from ${d.name}`);
    c.json({ device: d });
  });

  // Reads the MAC address, ARP and neighbour tables now, and says what came back. Useful when a new switch model is added.
  w.post('/api/devices/:id/read-hosts', 'snmp', async c => {
    const id = int(c.params.id, 0, 0, 1e9);
    const d = app.devices.row(id);
    if (!d) throw new HttpError(404, 'No such device');
    const cl = app.devices.open(d);
    try {
      const r = await app.hosts.refresh(d, cl);
      app.log.audit(who(c), `Read host tables from ${d.name}: ${r.macs} MAC addresses, ${r.arp} ARP entries, ${r.neighbors} neighbours`);
      c.json({ ...r, device: app.devices.list().find(x => x.id === id) });
    } catch (e) { throw new HttpError(502, (e as Error).message); } finally { cl.close(); }
  });

  /* ---- diagnostics: what the device publishes, and a read-only look at one OID ---- */
  const busy = new Set<number>();   // one diagnostic at a time per device, so a click-happy user cannot hammer a switch
  const withDevice = async <T>(c: { params: Record<string, string>; user(): { role: string } }, fn: (d: NonNullable<ReturnType<typeof app.devices.row>>, cl: ReturnType<typeof app.devices.open>) => Promise<T>): Promise<T> => {
    const id = int(c.params.id, 0, 0, 1e9);
    const d = app.devices.row(id);
    if (!d) throw new HttpError(404, 'No such device');
    checkTarget(c, d.ip);
    if (busy.has(id)) throw new HttpError(429, 'A check or walk is already running on this device. Wait for it to finish.');
    busy.add(id);
    const cl = app.devices.open(d);
    try { return await fn(d, cl); } finally { cl.close(); busy.delete(id); }
  };

  w.post('/api/devices/:id/check', 'snmp', async c => {
    const r = await withDevice(c, async (d, cl) => {
      try { await cl.get(['1.3.6.1.2.1.1.2.0']); } catch (e) { throw new HttpError(502, (e as Error).message); }
      const checks = await runChecks(cl, { role: d.role ?? 'device', cisco: (d.sys_object_id ?? '').startsWith('1.3.6.1.4.1.9.') });
      app.log.audit(who(c), `Checked what ${d.name} publishes over SNMP`);
      return { device: d.name, checkedAt: Date.now(), checks };
    });
    c.json(r);
  });

  // A walk of the whole device (or any part of it) runs in the background and is read back a page at a time, because a switch has
  // tens of thousands of rows. Reads only: GET and GETBULK with the device's own credential. The OID and device are recorded.
  const walks = new WalkJobs();
  const jobOf = (c: { params: Record<string, string>; user(): { role: string } }) => {
    const id = int(c.params.id, 0, 0, 1e9), d = app.devices.row(id);
    if (!d) throw new HttpError(404, 'No such device');
    checkTarget(c, d.ip);
    const j = walks.get(c.params.jid ?? '');
    if (!j || j.devId !== id) throw new HttpError(404, 'That walk has expired. Start it again.');
    return j;
  };

  w.post('/api/devices/:id/walks', 'snmp', async c => {
    const b = await c.body<{ oid?: string }>(1000);
    const text = str(b.oid, 300).trim();
    const oid = text === '' ? '' : cleanOid(text);
    if (oid === null) throw new HttpError(400, 'Enter a numeric OID such as 1.0.8802.1.1.2.1.4 (a leading dot is fine), or leave it blank to walk everything.');
    const id = int(c.params.id, 0, 0, 1e9), d = app.devices.row(id);
    if (!d) throw new HttpError(404, 'No such device');
    checkTarget(c, d.ip);
    if (busy.has(id)) throw new HttpError(429, 'A check is running on this device. Wait for it to finish.');
    let j;
    try { j = walks.start({ id, name: d.name, ip: d.ip }, app.devices.open(d), oid, who(c)); }
    catch (e) { if (e instanceof WalkBusy) throw new HttpError(429, e.message); throw e; }
    app.log.audit(who(c), `Started an SNMP walk of ${oid ? oid : 'the whole tree'} on ${d.name}`);
    c.json({ job: jobView(j) }, 202);
  });

  // Status, plus one page of rows when asked: ?offset=0&limit=100&q=filter words. limit=0 returns the status alone.
  w.get('/api/devices/:id/walks/:jid', 'snmp', c => {
    const j = jobOf(c);
    const limit = int(c.query.get('limit'), 100, 0, 500), offset = int(c.query.get('offset'), 0, 0, 1e9);
    const q = str(c.query.get('q') ?? '', 200);
    const matched = limit ? filterRows(j.rows, q) : j.rows;
    c.json({ job: jobView(j), matched: matched.length, offset, rows: limit ? matched.slice(offset, offset + limit).map(r => ({ oid: r[0], type: r[1], text: r[2].length > 400 ? r[2].slice(0, 400) + '…' : r[2] })) : [] });
  });
  w.post('/api/devices/:id/walks/:jid/cancel', 'snmp', c => { const j = jobOf(c); walks.cancel(j.id); c.json({ job: jobView(j) }); });

  w.get('/api/devices/:id/walks/:jid/export', 'snmp', c => {
    const j = jobOf(c);
    const fmt = (c.query.get('format') ?? 'txt') as ExportFormat;
    if (!EXPORT_FORMATS.includes(fmt)) throw new HttpError(400, 'format must be one of ' + EXPORT_FORMATS.join(', '));
    const q = str(c.query.get('q') ?? '', 200);
    const rows = filterRows(j.rows, q);
    const out = exportRows(j, rows, fmt, q);
    app.log.audit(who(c), `Exported ${rows.length} rows of an SNMP walk of ${j.device} as ${fmt}`);
    attachment(c, `snmpwalk-${j.device.replace(/[^\w.-]+/g, '_').slice(0, 60)}-${stamp()}.${out.ext}`, out.type, out.body);
  });

  w.del('/api/devices/:id', 'snmp', async c => {
    const id = int(c.params.id, 0, 0, 1e9);
    const d = app.devices.list().find(x => x.id === id);
    await guard(() => app.devices.remove(id));
    if (d) app.log.audit(who(c), `Removed SNMP device ${d.name} (${d.ip}) and its stored history`, 'WARN');
    c.json({ ok: true });
  });

  w.get('/api/devices/:id/interfaces', 'snmp', c => {
    const id = int(c.params.id, 0, 0, 1e9);
    if (!app.devices.row(id)) throw new HttpError(404, 'No such device');
    c.json({ interfaces: app.devices.interfaces(id) });
  });

  // Which DSCP values a QoS class carries is not always readable from the device, so it can be corrected here.
  w.put('/api/devices/:id/classes', 'snmp', async c => {
    const b = await c.body<{ ifIndex?: number; cls?: string; dscps?: number[] }>(5000);
    if (!Array.isArray(b.dscps)) throw new HttpError(400, 'dscps must be a list of numbers');
    await guard(() => app.devices.setClassDscps(int(c.params.id, 0, 0, 1e9), int(b.ifIndex, -1, -1, 1e9), str(b.cls, 128), b.dscps!.map(Number)));
    app.log.audit(who(c), `DSCP list changed for class ${str(b.cls, 128)} on device ${c.params.id}`);
    c.json({ ok: true });
  });

  /* ---- discovery ---- */
  w.post('/api/discovery', 'snmp', async c => {
    const b = await c.body<{ spec?: string; credId?: number; tryOthers?: boolean }>(5000);
    const j = await guard(() => app.discovery.start(str(b.spec, 2000), who(c), b.credId === undefined ? undefined : Number(b.credId), b.tryOthers === true, mayReach(c)));
    c.json({ job: j }, 202);
  });
  w.get('/api/discovery/:id', 'snmp', c => {
    const j = app.discovery.get(c.params.id);
    if (!j) throw new HttpError(404, 'That scan has expired');
    c.json({ job: j });
  });
  w.post('/api/discovery/:id/cancel', 'snmp', c => { app.discovery.cancel(c.params.id); c.json({ ok: true }); });
  w.post('/api/discovery/:id/add', 'snmp', async c => {
    const b = await c.body<{ ips?: string[]; intervalSec?: number }>(100_000);
    if (!Array.isArray(b.ips) || !b.ips.length) throw new HttpError(400, 'Choose at least one device');
    c.json(await guard(() => app.discovery.addFound(c.params.id, b.ips!.map(s => str(s, 64)), who(c), b.intervalSec === undefined ? undefined : Number(b.intervalSec))));
  });

  /* ---- credential sets: readable by the SNMP admin, changed only by the full admin ---- */
  w.get('/api/snmp/credentials', 'snmp', c => c.json({ credentials: app.creds.list(), canEdit: c.user().role === 'admin' }));

  // Which networks SNMP-role users may send credentials to. Everyone with the role can read it; only a full admin changes it.
  w.get('/api/snmp/access', 'snmp', c => c.json({ allowedNets: app.settings.get('snmpAccess').allowedNets, canEdit: c.user().role === 'admin' }));
  w.put('/api/snmp/access', 'admin', async c => {
    const b = await c.body<{ allowedNets?: string }>(5000);
    const text = str(b.allowedNets, 2000).trim();
    let p: TargetPolicy;
    try { p = new TargetPolicy(text); } catch (e) { throw new HttpError(400, (e as Error).message); }
    app.settings.set('snmpAccess', { allowedNets: p.entries.join(', ') });
    app.log.audit(who(c), p.open ? 'SNMP users may send credentials to any address' : `SNMP users may send credentials only to ${p.entries.join(', ')}`);
    c.json({ allowedNets: p.entries.join(', '), canEdit: true });
  });

  w.post('/api/snmp/credentials', 'admin', async c => {
    const b = await c.body<Record<string, unknown>>(10_000);
    const id = await guard(() => app.creds.create(credInput(b), b.isDefault === true));
    app.log.audit(who(c), `Created SNMP credential set "${str(b.name, 64)}" (${b.version})`);
    c.json({ id, credentials: app.creds.list() }, 201);
  });
  w.put('/api/snmp/credentials/:id', 'admin', async c => {
    const b = await c.body<Record<string, unknown>>(10_000);
    await guard(() => app.creds.update(int(c.params.id, 0, 0, 1e9), credInput(b)));
    app.log.audit(who(c), `Edited SNMP credential set "${str(b.name, 64)}"`);
    c.json({ credentials: app.creds.list() });
  });
  w.post('/api/snmp/credentials/:id/default', 'admin', async c => {
    await guard(() => app.creds.setDefault(int(c.params.id, 0, 0, 1e9)));
    app.log.audit(who(c), `Default SNMP credential set is now #${c.params.id}`);
    c.json({ credentials: app.creds.list() });
  });
  w.del('/api/snmp/credentials/:id', 'admin', async c => {
    const id = int(c.params.id, 0, 0, 1e9);
    const name = app.creds.list().find(x => x.id === id)?.name;
    await guard(() => app.creds.remove(id));
    app.log.audit(who(c), `Deleted SNMP credential set "${name ?? id}"`, 'WARN');
    c.json({ credentials: app.creds.list() });
  });
}
