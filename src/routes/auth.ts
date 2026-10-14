import type { App } from '../app.js';
import { SESSION_COOKIE, HttpError } from '../server/http.js';
import type { Principal } from '../auth/service.js';
import { ROLE_RANK, AuthError } from '../auth/service.js';
import type { Role } from '../settings.js';
import { int, str } from './util.js';

export function caps(role: Role) {
  return {
    flows: true, links: true, reports: true,
    storage: ROLE_RANK[role] >= ROLE_RANK.snmp, devices: ROLE_RANK[role] >= ROLE_RANK.snmp,
    storageEdit: role === 'admin', admin: role === 'admin'
  };
}

export function me(app: App, p: Principal) {
  return {
    username: p.username, role: p.role, source: p.source, service: p.service, csrf: p.csrf ?? null, mustChange: !!p.mustChange,
    caps: caps(p.role), collect: app.collect(), demo: app.demo, idleMinutes: app.settings.get('aaa').local.idle
  };
}

export function registerAuth(app: App): void {
  const w = app.web;

  // Public: which sign-in the web interface uses, so the page can show the right form.
  w.get('/api/auth/config', null, c => {
    const aaa = app.settings.get('aaa');
    c.json({ provider: aaa.services.web, saml: aaa.services.web === 'saml', fallback: aaa.fallback, product: 'FlowScope', demo: app.demo });
  });

  w.post('/api/auth/login', null, async c => {
    const b = await c.body<{ username?: string; password?: string }>(10_000);
    const r = await app.auth.authenticate('web', str(b.username, 256), str(b.password, 1024), c.ip);
    const s = app.auth.createSession(r.principal, c.ip);
    c.setCookie(SESSION_COOKIE, s.token, { maxAge: 12 * 3600 });
    c.principal = { ...r.principal, csrf: s.csrf, mustChange: r.mustChange };
    c.json(me(app, c.principal));
  }, { csrf: false });

  w.post('/api/auth/logout', 'ro', c => {
    const sid = /(?:^|;\s*)fs_sid=([^;]+)/.exec(String(c.req.headers.cookie || ''))?.[1];
    if (sid) app.auth.destroySession(decodeURIComponent(sid));
    c.setCookie(SESSION_COOKIE, '', { clear: true });
    app.log.audit(c.user().username, 'Signed out');
    c.json({ ok: true });
  });

  w.get('/api/auth/me', 'ro', c => c.json(me(app, c.user())));

  w.post('/api/auth/password', 'ro', async c => {
    const b = await c.body<{ current?: string; next?: string }>(10_000);
    const p = c.user();
    if (p.source !== 'local') throw new HttpError(400, `Your password is managed by ${p.source}. Change it there.`);
    app.auth.changePassword(p.username, str(b.current, 1024), str(b.next, 1024));
    app.auth.revokeSessions(p.username);
    const s = app.auth.createSession({ ...p, mustChange: false }, c.ip);
    c.setCookie(SESSION_COOKIE, s.token, { maxAge: 12 * 3600 });
    c.json({ ok: true, csrf: s.csrf });
  });

  // API tokens (for scripts and other tools)
  w.get('/api/auth/tokens', 'ro', c => c.json({ tokens: app.auth.listTokens(c.user()) }));
  w.post('/api/auth/tokens', 'ro', async c => {
    const b = await c.body<{ name?: string; role?: Role; days?: number }>(10_000);
    // A token that could mint more tokens turns a leaked short-lived one into a permanent one. Sign in (browser or password) to create one.
    if (c.user().source === 'token') throw new HttpError(403, 'Create API tokens from a signed-in session, not with another token');
    const t = app.auth.createToken(c.user(), { name: str(b.name, 64), role: b.role, days: b.days === undefined ? undefined : int(b.days, 90, 0, 3650) });
    c.json({ token: t.token, id: t.id, note: 'This is the only time the token is shown.' });
  });
  w.del('/api/auth/tokens/:id', 'ro', c => { app.auth.revokeToken(c.user(), int(c.params.id, 0, 0, 1e9)); c.json({ ok: true }); });

  // CLI sign-in: returns an API token valid for a day when the "cli" service accepts the credentials.
  w.post('/api/auth/cli', null, async c => {
    const b = await c.body<{ username?: string; password?: string }>(10_000);
    const r = await app.auth.authenticate('cli', str(b.username, 256), str(b.password, 1024), c.ip);
    if (r.mustChange) throw new AuthError('Change the password in the web interface first', 403);
    const t = app.auth.createToken(r.principal, { name: 'cli ' + new Date().toISOString().slice(0, 16), days: 1 });
    c.json({ token: t.token, role: r.principal.role });
  }, { csrf: false });
}
