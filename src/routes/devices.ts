import type { App } from '../app.js';
import { HttpError } from '../server/http.js';
import { DeviceError } from '../snmp/devices.js';
import { CredError, type CredInput } from '../snmp/creds.js';
import { int, str } from './util.js';

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
  w.get('/api/devices', 'snmp', c => c.json({ devices: app.devices.list(), polling: app.collect().snmp }));

  w.post('/api/devices/test', 'snmp', async c => {
    const b = await c.body<{ ip?: string; port?: number; credId?: number }>(2000);
    const credId = b.credId ?? app.creds.defaultId();
    if (credId === null || credId === undefined) throw new HttpError(400, 'Create a credential set first');
    const p = await guard(() => app.devices.test(str(b.ip, 64).trim(), int(b.port, 161, 1, 65535), credId));
    c.json({
      ok: true, sysName: p.info.sysName, sysDescr: p.info.sysDescr, uptimeSec: p.info.uptimeSec, interfaces: p.ifaces.length,
      policies: p.qos.length, classes: p.qos.reduce((a, q) => a + q.classes.length, 0), profile: p.profile
    });
  });

  w.post('/api/devices', 'snmp', async c => {
    const b = await c.body<{ ip?: string; name?: string; port?: number; credId?: number; intervalSec?: number }>(5000);
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
    const b = await c.body<{ spec?: string; credId?: number }>(5000);
    const j = await guard(() => app.discovery.start(str(b.spec, 2000), who(c), b.credId === undefined ? undefined : Number(b.credId)));
    c.json({ job: j }, 202);
  });
  w.get('/api/discovery/:id', 'snmp', c => {
    const j = app.discovery.get(c.params.id);
    if (!j) throw new HttpError(404, 'That scan has expired');
    c.json({ job: j });
  });
  w.post('/api/discovery/:id/cancel', 'snmp', c => { app.discovery.cancel(c.params.id); c.json({ ok: true }); });
  w.post('/api/discovery/:id/add', 'snmp', async c => {
    const b = await c.body<{ ips?: string[] }>(100_000);
    if (!Array.isArray(b.ips) || !b.ips.length) throw new HttpError(400, 'Choose at least one device');
    c.json(await guard(() => app.discovery.addFound(c.params.id, b.ips!.map(s => str(s, 64)), who(c))));
  });

  /* ---- credential sets: readable by the SNMP admin, changed only by the full admin ---- */
  w.get('/api/snmp/credentials', 'snmp', c => c.json({ credentials: app.creds.list(), canEdit: c.user().role === 'admin' }));

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
