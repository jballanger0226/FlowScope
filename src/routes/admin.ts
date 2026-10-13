import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import type { App } from '../app.js';
import { VERSION } from '../app.js';
import { HttpError } from '../server/http.js';
import { AuthError, ROLE_RANK } from '../auth/service.js';
import { CertError } from '../tls/manager.js';
import type { KeyType } from '../tls/x509.js';
import type { AaaSettings, Provider, Role, Service } from '../settings.js';
import { inContainer } from '../config.js';
import { randomToken } from '../secrets.js';
import { attachment, int, parseRange, stamp, str, toCsv } from './util.js';

const PROVIDERS: Provider[] = ['local', 'radius', 'ldap', 'ad', 'saml'];
const KEY_TYPES: KeyType[] = ['ecdsa-p256', 'ecdsa-p384', 'ecdsa-p521', 'rsa-2048', 'rsa-3072', 'rsa-4096', 'ed25519'];

async function guard<T>(fn: () => T | Promise<T>): Promise<T> {
  try { return await fn(); } catch (e) {
    if (e instanceof CertError) throw new HttpError(400, e.message);
    if (e instanceof AuthError) throw new HttpError(e.status, e.message);
    throw e;
  }
}

/** The AAA settings with secrets replaced by "is set" flags. Secrets never leave the server. */
export function maskAaa(a: AaaSettings) {
  const { secretEnc, ...radius } = a.radius;
  const { bindPwEnc: l, ...ldap } = a.ldap;
  const { bindPwEnc: d, ...ad } = a.ad;
  return { ...a, radius: { ...radius, hasSecret: !!secretEnc }, ldap: { ...ldap, hasBindPw: !!l }, ad: { ...ad, hasBindPw: !!d } };
}

const bool = (v: unknown, d: boolean) => (typeof v === 'boolean' ? v : d);
const s = (v: unknown, d: string, max = 512) => (typeof v === 'string' ? v.trim().slice(0, max) : d);
const n = (v: unknown, d: number, lo: number, hi: number) => { const x = Math.floor(Number(v)); return Number.isFinite(x) ? Math.min(hi, Math.max(lo, x)) : d; };

type Draft = Record<string, any>;

/** Merges the posted settings over the stored ones, field by field, with validation. Blank secret fields keep the stored secret. */
export function mergeAaa(app: App, cur: AaaSettings, b: Draft): AaaSettings {
  const next: AaaSettings = structuredClone(cur);
  if (b.services) for (const svc of ['web', 'api', 'cli'] as Service[]) {
    const v = b.services[svc];
    if (v === undefined) continue;
    if (!PROVIDERS.includes(v)) throw new HttpError(400, `Unknown provider "${v}"`);
    if (v === 'saml' && svc !== 'web') throw new HttpError(400, 'SAML signs people in through a browser, so it can only be used for the web interface.');
    next.services[svc] = v;
  }
  next.fallback = bool(b.fallback, cur.fallback);
  if (b.local) next.local = { minLen: n(b.local.minLen, cur.local.minLen, 8, 128), lockout: n(b.local.lockout, cur.local.lockout, 0, 100), idle: n(b.local.idle, cur.local.idle, 1, 1440) };
  if (b.radius) {
    const r = b.radius, c = cur.radius;
    next.radius = {
      host1: s(r.host1, c.host1, 255), host2: s(r.host2, c.host2, 255), authPort: n(r.authPort, c.authPort, 1, 65535), acctPort: n(r.acctPort, c.acctPort, 1, 65535),
      timeout: n(r.timeout, c.timeout, 1, 60), retries: n(r.retries, c.retries, 0, 10),
      attr: ['Filter-Id', 'Class', 'Reply-Message'].includes(r.attr) ? r.attr : c.attr, acct: bool(r.acct, c.acct),
      secretEnc: typeof r.secret === 'string' && r.secret ? app.secrets.encryptJson(r.secret) : r.clearSecret === true ? '' : c.secretEnc
    };
  }
  if (b.ldap) {
    const l = b.ldap, c = cur.ldap;
    const url = s(l.url, c.url, 512);
    if (url && !/^ldaps?:\/\/[^\s/]+(:\d+)?\/?$/i.test(url)) throw new HttpError(400, 'The LDAP address must look like ldaps://ldap.example.com or ldap://host:389');
    next.ldap = {
      url, bindDn: s(l.bindDn, c.bindDn), baseDn: s(l.baseDn, c.baseDn), filter: s(l.filter, c.filter), groupBase: s(l.groupBase, c.groupBase), verify: bool(l.verify, c.verify),
      bindPwEnc: typeof l.bindPw === 'string' && l.bindPw ? app.secrets.encryptJson(l.bindPw) : l.clearBindPw === true ? '' : c.bindPwEnc
    };
    if (next.ldap.filter && !next.ldap.filter.includes('{user}')) throw new HttpError(400, 'The LDAP user filter must contain {user}, for example (uid={user})');
  }
  if (b.ad) {
    const a = b.ad, c = cur.ad;
    next.ad = {
      domain: s(a.domain, c.domain, 255), dcs: s(a.dcs, c.dcs, 1000), bindUser: s(a.bindUser, c.bindUser), baseDn: s(a.baseDn, c.baseDn),
      ldaps: bool(a.ldaps, c.ldaps), nested: bool(a.nested, c.nested), verify: bool(a.verify, c.verify),
      bindPwEnc: typeof a.bindPw === 'string' && a.bindPw ? app.secrets.encryptJson(a.bindPw) : a.clearBindPw === true ? '' : c.bindPwEnc
    };
  }
  if (b.saml) {
    const m = b.saml, c = cur.saml;
    next.saml = {
      idp: s(m.idp, c.idp, 100), sp: s(m.sp, c.sp, 512), nameAttr: s(m.nameAttr, c.nameAttr, 255), groupAttr: s(m.groupAttr, c.groupAttr, 255), sign: bool(m.sign, c.sign),
      idpEntity: s(m.idpEntity, c.idpEntity, 512), idpSso: s(m.idpSso, c.idpSso, 1024), idpCert: typeof m.idpCert === 'string' ? m.idpCert.trim().slice(0, 20000) : c.idpCert
    };
    if (next.saml.idpSso && !/^https:\/\//i.test(next.saml.idpSso)) throw new HttpError(400, 'The IdP sign-on URL must start with https://');
  }
  if (b.map) for (const p of ['radius', 'ldap', 'ad', 'saml'] as const) {
    if (!b.map[p]) continue;
    next.map[p] = { admin: s(b.map[p].admin, cur.map[p].admin, 512), snmp: s(b.map[p].snmp, cur.map[p].snmp, 512), ro: s(b.map[p].ro, cur.map[p].ro, 512) };
  }
  if (b.def) for (const p of ['radius', 'ldap', 'ad', 'saml'] as const) {
    if (b.def[p] === undefined) continue;
    if (b.def[p] !== 'deny' && b.def[p] !== 'ro') throw new HttpError(400, 'The default for unmapped users is deny or ro');
    next.def[p] = b.def[p];
  }
  // Safety: do not let the administrator lock themselves out of a service with a remote provider that cannot give anyone the admin role.
  for (const svc of ['web', 'api', 'cli'] as Service[]) {
    const p = next.services[svc];
    if (p !== 'local' && !next.fallback && p !== cur.services[svc] && !next.map[p].admin) {
      throw new HttpError(400, `Sign-in for ${svc} would use ${p.toUpperCase()} with local fallback off and no group mapped to the Admin role, so nobody could administer FlowScope. Map an admin group or keep local fallback on.`);
    }
  }
  return next;
}

export function registerAdmin(app: App): void {
  const w = app.web;
  const who = (c: { user(): { username: string } }) => c.user().username;

  /* ---- about this installation ---- */
  w.get('/api/admin/system', 'admin', async c => {
    const stats = await app.store.stats();
    let free: number | null = null;
    try { const st = fs.statfsSync(app.cfg.dataDir); free = Number(st.bavail) * Number(st.bsize); } catch { /* not available everywhere */ }
    c.json({
      version: VERSION, node: process.version, platform: `${process.platform} ${process.arch}`, os: `${os.type()} ${os.release()}`, container: inContainer(),
      dataDir: path.resolve(app.cfg.dataDir), freeBytes: free, ports: app.ports, flowPorts: app.collector.boundPorts, tls: app.cfg.tls, store: stats,
      uptimeSec: Math.floor((Date.now() - app.startedAt) / 1000), memoryMb: Math.round(process.memoryUsage().rss / 1048576), demo: app.demo
    });
  });

  /* ---- data collection switches ---- */
  w.get('/api/admin/collection', 'admin', c => c.json({ collect: app.collect(), collecting: app.collecting() }));
  w.put('/api/admin/collection', 'admin', async c => {
    const b = await c.body<{ flow?: boolean; snmp?: boolean; confirm?: boolean }>(1000);
    for (const k of ['flow', 'snmp'] as const) if (b[k] !== undefined && typeof b[k] !== 'boolean') throw new HttpError(400, `${k} must be true or false`);
    const stopping = (b.flow === false && app.collect().flow) || (b.snmp === false && app.collect().snmp);
    if (stopping && b.confirm !== true) throw new HttpError(409, 'Stopping collection leaves a gap in the data. Send confirm: true to proceed.', { needsConfirm: true });
    c.json({ collect: app.setCollect({ flow: b.flow, snmp: b.snmp }, who(c)), collecting: app.collecting() });
  });

  /* ---- HTTPS certificate ---- */
  const hostOf = (c: { req: { headers: Record<string, string | string[] | undefined> } }) => String(c.req.headers.host || '').replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
  w.get('/api/admin/cert', 'admin', c => c.json({ ...app.certs.status(), tls: app.cfg.tls, keyTypes: KEY_TYPES }));
  w.post('/api/admin/cert/pem', 'admin', async c => {
    const b = await c.body<{ cert?: string; key?: string }>(200_000);
    const r = await guard(() => app.certs.stagePem({ certPem: str(b.cert, 100_000), keyPem: str(b.key, 50_000), expectHost: hostOf(c) }));
    app.log.audit(who(c), 'Staged a new HTTPS certificate (PEM)');
    c.json({ ...r, status: app.certs.status() });
  });
  w.post('/api/admin/cert/p12', 'admin', async c => {
    const b = await c.body<{ pfx?: string; passphrase?: string }>(2_000_000);
    const pfx = Buffer.from(str(b.pfx, 2_000_000), 'base64');
    const r = await guard(() => app.certs.stageP12({ pfx, passphrase: str(b.passphrase, 1024), expectHost: hostOf(c) }));
    app.log.audit(who(c), 'Staged a new HTTPS certificate (PKCS#12)');
    c.json({ ...r, status: app.certs.status() });
  });
  w.post('/api/admin/cert/csr', 'admin', async c => {
    const b = await c.body<{ cn?: string; sans?: string[] | string; keyType?: string; o?: string; ou?: string; c?: string }>(10_000);
    if (!KEY_TYPES.includes(b.keyType as KeyType)) throw new HttpError(400, 'Choose one of: ' + KEY_TYPES.join(', '));
    const sans = Array.isArray(b.sans) ? b.sans.map(x => str(x, 255)) : str(b.sans, 2000).split(/[\s,;]+/).filter(Boolean);
    const csr = await guard(() => app.certs.generateCsr({ cn: str(b.cn, 255), sans, keyType: b.keyType as KeyType, o: str(b.o, 64), ou: str(b.ou, 64), c: str(b.c, 2) }));
    app.log.audit(who(c), `Created a certificate signing request for ${csr.cn} (${csr.keyDesc})`);
    c.json({ csr, status: app.certs.status() });
  });
  w.post('/api/admin/cert/apply', 'admin', async c => {
    const opts = await guard(() => app.certs.apply());
    app.web.reloadTls(opts);
    app.log.audit(who(c), 'Applied the staged HTTPS certificate', 'WARN');
    c.json({ status: app.certs.status() });
  });
  w.post('/api/admin/cert/rollback', 'admin', async c => {
    const opts = await guard(() => app.certs.rollback());
    app.web.reloadTls(opts);
    app.log.audit(who(c), 'Rolled back to the previous HTTPS certificate', 'WARN');
    c.json({ status: app.certs.status() });
  });
  w.post('/api/admin/cert/discard', 'admin', c => { app.certs.discardStaged(); app.log.audit(who(c), 'Discarded the staged HTTPS certificate'); c.json({ status: app.certs.status() }); });

  /* ---- AAA ---- */
  w.get('/api/admin/aaa', 'admin', c => c.json({ aaa: maskAaa(app.settings.get('aaa')), callback: `${app.cfg.publicUrl || ''}/api/auth/saml/acs` }));
  w.put('/api/admin/aaa', 'admin', async c => {
    const b = await c.body<Draft>(200_000);
    const cur = app.settings.get('aaa');
    const next = mergeAaa(app, cur, b);
    app.settings.set('aaa', next);
    const diff: string[] = [];
    for (const svc of ['web', 'api', 'cli'] as Service[]) if (next.services[svc] !== cur.services[svc]) diff.push(`${svc} sign-in ${cur.services[svc]} → ${next.services[svc]}`);
    if (next.fallback !== cur.fallback) diff.push(`local fallback ${next.fallback ? 'on' : 'off'}`);
    app.log.audit(who(c), 'Authentication settings saved' + (diff.length ? ': ' + diff.join(', ') : ''), diff.length ? 'WARN' : 'INFO');
    c.json({ aaa: maskAaa(next) });
  });
  w.post('/api/admin/aaa/test', 'admin', async c => {
    const b = await c.body<{ provider?: string; username?: string; password?: string }>(5000);
    if (!PROVIDERS.includes(b.provider as Provider)) throw new HttpError(400, 'Unknown provider');
    const r = await app.auth.testProvider(b.provider as Provider, str(b.username, 256), str(b.password, 1024));
    app.log.audit(who(c), `Tested ${b.provider} connection: ${r.ok ? 'worked' : 'failed'}`);
    c.json(r);
  });

  /* ---- users ---- */
  w.get('/api/admin/users', 'admin', c => c.json({ users: app.auth.listUsers(), minLen: app.settings.get('aaa').local.minLen }));
  w.post('/api/admin/users', 'admin', async c => {
    const b = await c.body<{ username?: string; password?: string; role?: Role; mustChange?: boolean }>(5000);
    if (!b.role || !ROLE_RANK[b.role]) throw new HttpError(400, 'Choose a role');
    // without a password, a temporary one is generated, shown once, and must be changed at first sign-in
    const generated = !b.password;
    const password = generated ? randomToken(12).replace(/[-_]/g, 'x') : str(b.password, 1024);
    await guard(() => app.auth.createUser(who(c), { username: str(b.username, 128), password, role: b.role!, mustChange: generated ? true : b.mustChange }));
    c.json({ users: app.auth.listUsers(), temporaryPassword: generated ? password : undefined }, 201);
  });
  w.patch('/api/admin/users/:id', 'admin', async c => {
    const b = await c.body<{ role?: Role; disabled?: boolean; password?: string; unlock?: boolean }>(5000);
    await guard(() => app.auth.updateUser(who(c), int(c.params.id, 0, 0, 1e9), { role: b.role, disabled: b.disabled, password: b.password === undefined ? undefined : str(b.password, 1024), unlock: b.unlock }));
    c.json({ users: app.auth.listUsers() });
  });
  w.del('/api/admin/users/:id', 'admin', async c => {
    await guard(() => app.auth.deleteUser(who(c), int(c.params.id, 0, 0, 1e9)));
    c.json({ users: app.auth.listUsers() });
  });

  /* ---- VLAN names ---- */
  w.put('/api/admin/vlans/:id', 'admin', async c => {
    const id = Number(c.params.id);
    const b = await c.body<{ name?: string }>(1000);
    const name = str(b.name, 64).trim();
    if (!Number.isInteger(id) || id < 1 || id > 4094) throw new HttpError(400, 'A VLAN ID is 1 to 4094');
    if (!name) throw new HttpError(400, 'Enter a name');
    app.cdb.db.prepare("INSERT INTO vlans(id, name, source) VALUES (?,?,'manual') ON CONFLICT(id) DO UPDATE SET name = excluded.name, source = 'manual'").run(id, name);
    app.log.audit(who(c), `VLAN ${id} named "${name}"`);
    c.json({ vlans: app.cdb.db.prepare('SELECT id, name, source FROM vlans ORDER BY id').all() });
  });
  w.del('/api/admin/vlans/:id', 'admin', c => {
    const id = Number(c.params.id);
    if (!Number.isInteger(id) || id < 1 || id > 4094) throw new HttpError(400, 'A VLAN ID is 1 to 4094');
    app.cdb.db.prepare('DELETE FROM vlans WHERE id = ?').run(id);
    app.log.audit(who(c), `VLAN ${id} name removed`);
    c.json({ vlans: app.cdb.db.prepare('SELECT id, name, source FROM vlans ORDER BY id').all() });
  });

  /* ---- application logs ---- */
  const logQuery = (c: { query: URLSearchParams }, limit: number) => {
    const q = c.query;
    const since = q.get('range') || q.get('from') ? parseRange(q, '24h').from : undefined;
    return app.log.query({ level: str(q.get('level'), 10) || undefined, source: str(q.get('source'), 32) || undefined, q: str(q.get('q'), 200) || undefined, since, limit });
  };
  w.get('/api/admin/logs', 'admin', c => {
    const rows = logQuery(c, int(c.query.get('limit'), 500, 1, 5000));
    const sources = (app.cdb.db.prepare('SELECT DISTINCT source FROM logs ORDER BY source').all() as unknown as { source: string }[]).map(r => r.source);
    c.json({ logs: rows, sources, retentionDays: app.settings.get('logDays') });
  });
  w.get('/api/admin/logs/export', 'admin', c => {
    const rows = logQuery(c, int(c.query.get('limit'), 50000, 1, 50000));
    app.log.audit(who(c), `Exported ${rows.length} log entries`);
    const fmt = c.query.get('format') === 'json' ? 'json' : 'csv';
    if (fmt === 'json') return attachment(c, `flowscope-logs-${stamp()}.json`, 'application/json', JSON.stringify(rows.map(r => ({ time: new Date(r.ts).toISOString(), level: r.level, source: r.source, user: r.user, message: r.message })), null, 2));
    attachment(c, `flowscope-logs-${stamp()}.csv`, 'text/csv; charset=utf-8', toCsv(['time', 'level', 'source', 'user', 'message'], rows.map(r => [new Date(r.ts).toISOString(), r.level, r.source, r.user, r.message])));
  });
}
