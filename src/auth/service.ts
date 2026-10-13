import crypto from 'node:crypto';
import type { ConfigDb } from '../db/configdb.js';
import type { Settings, Role, Service, Provider, AaaSettings } from '../settings.js';
import type { Secrets } from '../secrets.js';
import { hashPassword, verifyPassword, randomToken, sha256 } from '../secrets.js';
import type { AppLog } from '../logger.js';
import * as radius from './radius.js';
import { adLogin, groupMatches, ldapLogin } from './ldap.js';

export const ROLE_RANK: Record<Role, number> = { ro: 1, snmp: 2, admin: 3 };
export const ROLE_LABEL: Record<Role, string> = { ro: 'Read only', snmp: 'SNMP admin', admin: 'Admin' };

export interface Principal { username: string; role: Role; source: string; service: Service; sessionHash?: string; tokenId?: number; csrf?: string; mustChange?: boolean }
export class AuthError extends Error { constructor(m: string, readonly status = 401) { super(m); } }

export interface UserView { id: number; username: string; role: Role; source: string; createdAt: number; lastLogin: number | null; lastSource: string | null; disabled: boolean; locked: boolean; mustChange: boolean }
export interface LoginResult { principal: Principal; token?: string; csrf?: string; mustChange: boolean }

const COMMON = new Set(['password', 'password1', 'password123', 'letmein', 'welcome', 'qwerty', 'admin', 'changeme', 'flowscope', 'netflow']);
const LOCK_MS = 15 * 60_000;
const SESSION_ABS_MS = 12 * 3600_000;

class Limiter {
  private hits = new Map<string, number[]>();
  constructor(private max: number, private windowMs: number) {}
  blocked(key: string): boolean { const now = Date.now(); const a = (this.hits.get(key) ?? []).filter(t => now - t < this.windowMs); this.hits.set(key, a); return a.length >= this.max; }
  fail(key: string): void { const a = this.hits.get(key) ?? []; a.push(Date.now()); this.hits.set(key, a); if (this.hits.size > 20000) this.hits.clear(); }
  clear(key: string): void { this.hits.delete(key); }
}

export function validUsername(u: string): boolean { return /^[A-Za-z0-9][A-Za-z0-9._@\\-]{0,127}$/.test(u); }

export class AuthService {
  private limiter = new Limiter(10, 5 * 60_000);
  private dummyHash = hashPassword(crypto.randomBytes(8).toString('hex'));
  private lastTouch = new Map<string, number>();

  constructor(private cdb: ConfigDb, private settings: Settings, private secrets: Secrets, private log: AppLog) {}

  private aaa(): AaaSettings { return this.settings.get('aaa'); }

  /** Creates the first administrator when there are no users. Returns the generated password, if one was created. */
  bootstrap(envPassword?: string): string | null {
    const n = (this.cdb.db.prepare('SELECT COUNT(*) AS n FROM users').get() as { n: number }).n;
    if (n > 0) return null;
    const pw = envPassword && envPassword.length >= 12 ? envPassword : randomToken(12).replace(/[-_]/g, 'x');
    this.cdb.db.prepare("INSERT INTO users(username, pw_hash, role, source, created_at, must_change) VALUES ('admin', ?, 'admin', 'local', ?, ?)").run(hashPassword(pw), Date.now(), envPassword && envPassword.length >= 12 ? 0 : 1);
    this.log.warn('auth', 'Created the first administrator "admin"' + (envPassword && envPassword.length >= 12 ? ' with the password from FLOWSCOPE_ADMIN_PASSWORD' : ' with a generated password. Sign in and change it.'));
    return envPassword && envPassword.length >= 12 ? null : pw;
  }

  /* ---------------------------------------------------------------- users */

  policyCheck(username: string, pw: string): void {
    const min = this.aaa().local.minLen;
    if (pw.length < min) throw new AuthError(`The password must be at least ${min} characters`, 400);
    if (pw.length > 256) throw new AuthError('The password is too long', 400);
    if (COMMON.has(pw.toLowerCase())) throw new AuthError('That password is too common', 400);
    if (username && pw.toLowerCase().includes(username.toLowerCase())) throw new AuthError('The password must not contain the user name', 400);
    if (/^(.)\1+$/.test(pw)) throw new AuthError('The password is too simple', 400);
  }

  listUsers(): UserView[] {
    const now = Date.now();
    return (this.cdb.db.prepare('SELECT * FROM users ORDER BY username').all() as unknown as { id: number; username: string; role: Role; source: string; created_at: number; last_login: number | null; last_source: string | null; disabled: number; locked_until: number; must_change: number }[])
      .map(u => ({ id: u.id, username: u.username, role: u.role, source: u.source, createdAt: u.created_at, lastLogin: u.last_login, lastSource: u.last_source, disabled: u.disabled === 1, locked: u.locked_until > now, mustChange: u.must_change === 1 }));
  }

  private enabledLocalAdmins(exceptId?: number): number {
    return (this.cdb.db.prepare("SELECT COUNT(*) AS n FROM users WHERE source = 'local' AND role = 'admin' AND disabled = 0 AND id != ?").get(exceptId ?? -1) as { n: number }).n;
  }

  createUser(actor: string, o: { username: string; password: string; role: Role; mustChange?: boolean }): void {
    if (!validUsername(o.username)) throw new AuthError('User names may use letters, digits and . _ - @ \\ (up to 128 characters)', 400);
    if (!ROLE_RANK[o.role]) throw new AuthError('Unknown role', 400);
    this.policyCheck(o.username, o.password);
    try {
      this.cdb.db.prepare("INSERT INTO users(username, pw_hash, role, source, created_at, must_change) VALUES (?,?,?,'local',?,?)").run(o.username, hashPassword(o.password), o.role, Date.now(), o.mustChange === false ? 0 : 1);
    } catch (e) { if (/UNIQUE/.test((e as Error).message)) throw new AuthError('That user name is taken', 409); throw e; }
    this.log.audit(actor, `Created local user ${o.username} with role ${ROLE_LABEL[o.role]}`);
  }

  private userRow(id: number) { return this.cdb.db.prepare('SELECT * FROM users WHERE id = ?').get(id) as unknown as { id: number; username: string; role: Role; source: string; disabled: number } | undefined; }

  updateUser(actor: string, id: number, patch: { role?: Role; disabled?: boolean; password?: string; unlock?: boolean }): void {
    const u = this.userRow(id);
    if (!u) throw new AuthError('No such user', 404);
    const losesAdmin = u.source === 'local' && u.role === 'admin' && ((patch.role && patch.role !== 'admin') || patch.disabled === true);
    if (losesAdmin && this.enabledLocalAdmins(id) === 0) throw new AuthError('This is the last enabled local administrator. Create another first.', 409);
    if (patch.role) { if (!ROLE_RANK[patch.role]) throw new AuthError('Unknown role', 400); this.cdb.db.prepare('UPDATE users SET role = ? WHERE id = ?').run(patch.role, id); this.log.audit(actor, `Changed role of ${u.username} to ${ROLE_LABEL[patch.role]}`); }
    if (patch.disabled !== undefined) {
      this.cdb.db.prepare('UPDATE users SET disabled = ? WHERE id = ?').run(patch.disabled ? 1 : 0, id);
      if (patch.disabled) this.revokeSessions(u.username);
      this.log.audit(actor, `${patch.disabled ? 'Disabled' : 'Enabled'} user ${u.username}`);
    }
    if (patch.password !== undefined) {
      if (u.source !== 'local') throw new AuthError('This user signs in through ' + u.source + '. Its password is managed there.', 400);
      this.policyCheck(u.username, patch.password);
      this.cdb.db.prepare('UPDATE users SET pw_hash = ?, must_change = 1, failed = 0, locked_until = 0 WHERE id = ?').run(hashPassword(patch.password), id);
      this.revokeSessions(u.username);
      this.log.audit(actor, `Reset the password of ${u.username}`);
    }
    if (patch.unlock) { this.cdb.db.prepare('UPDATE users SET failed = 0, locked_until = 0 WHERE id = ?').run(id); this.log.audit(actor, `Unlocked ${u.username}`); }
  }

  deleteUser(actor: string, id: number): void {
    const u = this.userRow(id);
    if (!u) throw new AuthError('No such user', 404);
    if (u.username.toLowerCase() === actor.toLowerCase()) throw new AuthError('You cannot delete your own account', 409);
    if (u.source === 'local' && u.role === 'admin' && this.enabledLocalAdmins(id) === 0) throw new AuthError('This is the last enabled local administrator', 409);
    this.cdb.db.prepare('DELETE FROM users WHERE id = ?').run(id);
    this.revokeSessions(u.username);
    this.cdb.db.prepare('DELETE FROM api_tokens WHERE username = ?').run(u.username);
    this.log.audit(actor, `Deleted user ${u.username}`);
  }

  changePassword(username: string, current: string, next: string): void {
    const u = this.cdb.db.prepare("SELECT * FROM users WHERE username = ? AND source = 'local'").get(username) as unknown as { id: number; pw_hash: string } | undefined;
    if (!u || !verifyPassword(current, u.pw_hash)) throw new AuthError('The current password is wrong', 403);
    this.policyCheck(username, next);
    if (current === next) throw new AuthError('Choose a different password', 400);
    this.cdb.db.prepare('UPDATE users SET pw_hash = ?, must_change = 0 WHERE id = ?').run(hashPassword(next), u.id);
    this.log.audit(username, 'Changed own password');
  }

  /* ---------------------------------------------------------------- login */

  private mapRole(p: 'radius' | 'ldap' | 'ad' | 'saml', values: string[]): Role | null {
    const a = this.aaa();
    const m = a.map[p];
    for (const r of ['admin', 'snmp', 'ro'] as Role[]) if (m[r] && groupMatches(values, m[r])) return r;
    return a.def[p] === 'ro' ? 'ro' : null;
  }

  private upsertRemote(username: string, role: Role, source: string): void {
    const ex = this.cdb.db.prepare('SELECT id, source, disabled FROM users WHERE username = ?').get(username) as unknown as { id: number; source: string; disabled: number } | undefined;
    if (ex && ex.source === 'local') throw new AuthError('A local account with this name exists. Rename one of them.', 409);
    if (ex && ex.disabled) throw new AuthError('This account is disabled', 403);
    if (ex) this.cdb.db.prepare('UPDATE users SET role = ?, source = ? WHERE id = ?').run(role, source, ex.id);
    else this.cdb.db.prepare('INSERT INTO users(username, pw_hash, role, source, created_at) VALUES (?, NULL, ?, ?, ?)').run(username, role, source, Date.now());
  }

  private radiusOpts(): radius.RadiusOpts {
    const r = this.aaa().radius;
    const hosts = [r.host1, r.host2].filter(Boolean).map(h => { const m = /^(\[[^\]]+\]|[^:]+)(?::(\d+))?$/.exec(h.trim()); return { host: (m ? m[1] : h).replace(/^\[|\]$/g, ''), port: m?.[2] ? Number(m[2]) : r.authPort }; });
    return { servers: hosts, secret: this.secrets.decryptJson<string>(r.secretEnc, ''), timeoutMs: r.timeout * 1000, retries: r.retries, nasId: 'flowscope' };
  }

  private async remote(provider: Provider, username: string, password: string): Promise<{ ok: boolean; role?: Role; reason?: string; unreachable?: boolean; groups?: string[] }> {
    const a = this.aaa();
    if (provider === 'radius') {
      const o = this.radiusOpts();
      if (!o.servers.length || !o.secret) return { ok: false, reason: 'RADIUS is not configured', unreachable: true };
      try {
        const r = await radius.authenticate(o, username, password);
        if (!r.accepted) return { ok: false, reason: r.replyMessage || 'Rejected by the RADIUS server' };
        const vals = a.radius.attr === 'Class' ? r.classes : a.radius.attr === 'Reply-Message' ? r.replyMessage.split(/[\s,;]+/).filter(Boolean) : r.filterIds;
        const role = this.mapRole('radius', vals);
        if (!role) return { ok: false, reason: `The RADIUS server accepted the login but sent no ${a.radius.attr} that maps to a role` };
        if (a.radius.acct) void radius.account(o, username, 'fs-' + randomToken(6), 'start').catch(() => undefined);
        return { ok: true, role, groups: vals };
      } catch (e) { return { ok: false, reason: (e as Error).message, unreachable: (e as radius.RadiusError).kind === 'timeout' || (e as radius.RadiusError).kind === 'config' }; }
    }
    if (provider === 'ldap') {
      const l = a.ldap;
      if (!l.url || !l.baseDn) return { ok: false, reason: 'LDAP is not configured', unreachable: true };
      const r = await ldapLogin({ url: l.url, bindDn: l.bindDn, bindPw: this.secrets.decryptJson<string>(l.bindPwEnc, ''), baseDn: l.baseDn, filter: l.filter, groupBase: l.groupBase, verify: l.verify }, username, password);
      if (!r.ok) return { ok: false, reason: r.reason, unreachable: r.unreachable };
      const role = this.mapRole('ldap', r.groups);
      return role ? { ok: true, role, groups: r.groups } : { ok: false, reason: 'The directory accepted the login but the user is in no group that maps to a role' };
    }
    if (provider === 'ad') {
      const l = a.ad;
      if (!l.domain || !l.baseDn) return { ok: false, reason: 'Active Directory is not configured', unreachable: true };
      const r = await adLogin({ domain: l.domain, dcs: l.dcs.split(/[\s,;]+/).filter(Boolean), bindUser: l.bindUser, bindPw: this.secrets.decryptJson<string>(l.bindPwEnc, ''), baseDn: l.baseDn, ldaps: l.ldaps, nested: l.nested, verify: l.verify }, username, password);
      if (!r.ok) return { ok: false, reason: r.reason, unreachable: r.unreachable };
      const role = this.mapRole('ad', r.groups);
      return role ? { ok: true, role, groups: r.groups } : { ok: false, reason: 'The directory accepted the login but the user is in no group that maps to a role' };
    }
    return { ok: false, reason: 'This service does not use passwords' };
  }

  private localLogin(username: string, password: string): { ok: boolean; role?: Role; reason?: string; mustChange?: boolean; name?: string } {
    const u = this.cdb.db.prepare("SELECT * FROM users WHERE username = ? AND source = 'local'").get(username) as unknown as { id: number; username: string; pw_hash: string; role: Role; failed: number; locked_until: number; disabled: number; must_change: number } | undefined;
    if (!u) { verifyPassword(password, this.dummyHash); return { ok: false, reason: 'Wrong user name or password' }; }
    const now = Date.now();
    if (u.disabled) { verifyPassword(password, this.dummyHash); return { ok: false, reason: 'This account is disabled' }; }
    if (u.locked_until > now) return { ok: false, reason: `This account is locked for ${Math.ceil((u.locked_until - now) / 60000)} more minutes after too many wrong passwords` };
    if (!verifyPassword(password, u.pw_hash)) {
      const failed = u.failed + 1; const max = this.aaa().local.lockout;
      if (max > 0 && failed >= max) { this.cdb.db.prepare('UPDATE users SET failed = 0, locked_until = ? WHERE id = ?').run(now + LOCK_MS, u.id); this.log.warn('auth', `Locked ${username} for 15 minutes after ${failed} wrong passwords`); }
      else this.cdb.db.prepare('UPDATE users SET failed = ? WHERE id = ?').run(failed, u.id);
      return { ok: false, reason: 'Wrong user name or password' };
    }
    this.cdb.db.prepare('UPDATE users SET failed = 0, locked_until = 0 WHERE id = ?').run(u.id);
    return { ok: true, role: u.role, mustChange: u.must_change === 1, name: u.username };
  }

  /** Checks credentials for a service using the provider chosen for it. Creates no session. */
  async authenticate(service: Service, usernameIn: string, password: string, ip: string): Promise<{ principal: Principal; mustChange: boolean }> {
    const username = (usernameIn || '').trim();
    const key = `${ip}|${username.toLowerCase()}`;
    if (!username || !password || username.length > 256 || password.length > 1024 || /[\0-\x1f]/.test(username)) throw new AuthError('Enter a user name and password');
    if (this.limiter.blocked(key) || this.limiter.blocked('ip|' + ip + '|*')) throw new AuthError('Too many failed attempts. Wait a few minutes and try again.', 429);
    const a = this.aaa();
    const provider = a.services[service];
    let outcome: { ok: boolean; role?: Role; reason?: string; mustChange?: boolean; unreachable?: boolean; name?: string } & { source?: string };
    if (provider === 'local') outcome = { ...this.localLogin(username, password), source: 'local' };
    else if (provider === 'saml') outcome = { ok: false, reason: 'This service signs in through SAML in the browser' };
    else {
      const r = await this.remote(provider, username, password);
      outcome = { ...r, source: provider };
      if (r.ok) { try { this.upsertRemote(username, r.role!, provider); outcome.name = (this.cdb.db.prepare('SELECT username FROM users WHERE username = ?').get(username) as { username: string }).username; } catch (e) { outcome = { ok: false, reason: (e as Error).message }; } }
      else if (r.unreachable && a.fallback) {
        // Break-glass: when the directory cannot be reached, local administrators may still sign in so the server is not locked out.
        const local = this.localLogin(username, password);
        if (local.ok && local.role === 'admin') { outcome = { ...local, source: 'local' }; this.log.warn('auth', `${username} signed in with the local break-glass account because ${provider} is unreachable (${r.reason})`, username); }
        else outcome = { ok: false, reason: `${provider.toUpperCase()} is unreachable and the local fallback is limited to local administrators` };
      }
    }
    if (!outcome.ok) {
      this.limiter.fail(key); this.limiter.fail('ip|' + ip + '|*');
      this.log.warn('auth', `Failed ${service} sign-in for ${username} from ${ip} (${provider}): ${outcome.reason}`, username);
      throw new AuthError(outcome.reason && /locked|disabled|Too many|fallback|not configured|unreachable|maps? to a role|no group|manage|already exists|local account/.test(outcome.reason) ? outcome.reason : 'Wrong user name or password');
    }
    this.limiter.clear(key);
    const canon = outcome.name ?? username;
    this.cdb.db.prepare('UPDATE users SET last_login = ?, last_source = ? WHERE username = ?').run(Date.now(), `${service} from ${ip}`, canon);
    this.log.audit(canon, `Signed in to ${service} from ${ip} (${outcome.source})`);
    return { principal: { username: canon, role: outcome.role!, source: outcome.source!, service }, mustChange: !!outcome.mustChange };
  }

  /** Completes a browser sign-in whose identity was already proven by the SAML identity provider. */
  samlLogin(name: string, groups: string[], ip: string): { principal: Principal; mustChange: boolean } {
    const role = this.mapRole('saml', groups);
    if (!role) { this.log.warn('auth', `SAML sign-in for ${name} from ${ip} refused: none of the groups (${groups.slice(0, 6).join(', ') || 'none sent'}) maps to a role`, name); throw new AuthError('You signed in, but none of your groups maps to a FlowScope role. Ask an administrator to map one.', 403); }
    try { this.upsertRemote(name, role, 'saml'); } catch (e) { this.log.warn('auth', `SAML sign-in for ${name} from ${ip} refused: ${(e as Error).message}`, name); throw e; }
    const canon = (this.cdb.db.prepare('SELECT username FROM users WHERE username = ?').get(name) as { username: string }).username;
    this.cdb.db.prepare('UPDATE users SET last_login = ?, last_source = ? WHERE username = ?').run(Date.now(), `web from ${ip}`, canon);
    this.log.audit(canon, `Signed in to web from ${ip} (saml)`);
    return { principal: { username: canon, role, source: 'saml', service: 'web' }, mustChange: false };
  }

  /* ---------------------------------------------------------------- sessions */

  createSession(p: Principal, ip: string): { token: string; csrf: string } {
    const token = randomToken(32), csrf = randomToken(24);
    const now = Date.now();
    this.cdb.db.prepare('INSERT INTO sessions(id, username, role, source, service, csrf, created_at, last_seen, expires_at, ip) VALUES (?,?,?,?,?,?,?,?,?,?)').run(sha256(token), p.username, p.role, p.source, p.service, csrf, now, now, now + SESSION_ABS_MS, ip);
    return { token, csrf };
  }

  /** Looks up a session cookie. Applies the idle timeout and re-reads the role so changes take effect immediately. */
  fromSession(token: string): Principal | null {
    if (!token || token.length > 200) return null;
    const h = sha256(token);
    const s = this.cdb.db.prepare('SELECT * FROM sessions WHERE id = ?').get(h) as unknown as { username: string; source: string; service: Service; csrf: string; last_seen: number; expires_at: number } | undefined;
    if (!s) return null;
    const now = Date.now(); const idle = Math.max(1, this.aaa().local.idle) * 60_000;
    if (s.expires_at < now || now - s.last_seen > idle) { this.cdb.db.prepare('DELETE FROM sessions WHERE id = ?').run(h); return null; }
    const u = this.cdb.db.prepare('SELECT role, disabled, must_change FROM users WHERE username = ?').get(s.username) as unknown as { role: Role; disabled: number; must_change: number } | undefined;
    if (!u || u.disabled) { this.cdb.db.prepare('DELETE FROM sessions WHERE id = ?').run(h); return null; }
    if (now - (this.lastTouch.get(h) ?? 0) > 20_000) { this.lastTouch.set(h, now); this.cdb.db.prepare('UPDATE sessions SET last_seen = ? WHERE id = ?').run(now, h); if (this.lastTouch.size > 5000) this.lastTouch.clear(); }
    return { username: s.username, role: u.role, source: s.source, service: s.service, sessionHash: h, csrf: s.csrf, mustChange: u.must_change === 1 };
  }

  destroySession(token: string): void { this.cdb.db.prepare('DELETE FROM sessions WHERE id = ?').run(sha256(token)); }
  revokeSessions(username: string): void { this.cdb.db.prepare('DELETE FROM sessions WHERE username = ?').run(username); }
  sweep(): void { this.cdb.db.prepare('DELETE FROM sessions WHERE expires_at < ? OR last_seen < ?').run(Date.now(), Date.now() - Math.max(1, this.aaa().local.idle) * 60_000); }

  /* ---------------------------------------------------------------- API tokens */

  createToken(p: Principal, o: { name: string; role?: Role; days?: number }): { token: string; id: number } {
    const name = (o.name || '').trim();
    if (!name || name.length > 64) throw new AuthError('Give the token a name of up to 64 characters', 400);
    const role = o.role ?? p.role;
    if (!ROLE_RANK[role] || ROLE_RANK[role] > ROLE_RANK[p.role]) throw new AuthError('A token cannot have more access than you do', 403);
    const days = o.days === undefined ? 90 : o.days;
    if (!Number.isInteger(days) || days < 0 || days > 3650) throw new AuthError('Lifetime must be 0 (no expiry) to 3650 days', 400);
    const token = 'fs_' + randomToken(32);
    const r = this.cdb.db.prepare('INSERT INTO api_tokens(username, role, name, token_hash, created_at, expires_at) VALUES (?,?,?,?,?,?)').run(p.username, role, name, sha256(token), Date.now(), days ? Date.now() + days * 86400_000 : null);
    this.log.audit(p.username, `Created API token "${name}" (${ROLE_LABEL[role]}, ${days ? days + ' days' : 'no expiry'})`);
    return { token, id: Number(r.lastInsertRowid) };
  }

  listTokens(p: Principal): { id: number; username: string; name: string; role: Role; createdAt: number; lastUsed: number | null; expiresAt: number | null }[] {
    const rows = (p.role === 'admin' ? this.cdb.db.prepare('SELECT * FROM api_tokens ORDER BY id').all() : this.cdb.db.prepare('SELECT * FROM api_tokens WHERE username = ? ORDER BY id').all(p.username)) as unknown as { id: number; username: string; name: string; role: Role; created_at: number; last_used: number | null; expires_at: number | null }[];
    return rows.map(r => ({ id: r.id, username: r.username, name: r.name, role: r.role, createdAt: r.created_at, lastUsed: r.last_used, expiresAt: r.expires_at }));
  }

  revokeToken(p: Principal, id: number): void {
    const t = this.cdb.db.prepare('SELECT username, name FROM api_tokens WHERE id = ?').get(id) as unknown as { username: string; name: string } | undefined;
    if (!t) throw new AuthError('No such token', 404);
    if (t.username !== p.username && p.role !== 'admin') throw new AuthError('You can only revoke your own tokens', 403);
    this.cdb.db.prepare('DELETE FROM api_tokens WHERE id = ?').run(id);
    this.log.audit(p.username, `Revoked API token "${t.name}" of ${t.username}`);
  }

  fromToken(token: string): Principal | null {
    if (!token.startsWith('fs_') || token.length > 200) return null;
    const t = this.cdb.db.prepare('SELECT * FROM api_tokens WHERE token_hash = ?').get(sha256(token)) as unknown as { id: number; username: string; role: Role; expires_at: number | null } | undefined;
    if (!t || (t.expires_at !== null && t.expires_at < Date.now())) return null;
    const u = this.cdb.db.prepare('SELECT role, disabled FROM users WHERE username = ?').get(t.username) as unknown as { role: Role; disabled: number } | undefined;
    if (!u || u.disabled) return null;
    const role = ROLE_RANK[t.role] <= ROLE_RANK[u.role] ? t.role : u.role;
    this.cdb.db.prepare('UPDATE api_tokens SET last_used = ? WHERE id = ?').run(Date.now(), t.id);
    return { username: t.username, role, source: 'token', service: 'api', tokenId: t.id };
  }

  /** Admin console: try a provider with the given test credentials without changing anything. */
  async testProvider(provider: Provider, username: string, password: string): Promise<{ ok: boolean; message: string; role?: Role | null; groups?: string[] }> {
    if (provider === 'local') return { ok: true, message: 'Local accounts need no connection.' };
    if (provider === 'saml') return this.testSaml();
    if (!username || !password) {
      if (provider === 'radius') {
        const o = this.radiusOpts();
        if (!o.servers.length) return { ok: false, message: 'Enter at least one RADIUS server' };
        if (!o.secret) return { ok: false, message: 'Enter the shared secret' };
        try { const r = await radius.authenticate(o, 'flowscope-probe', 'flowscope-probe'); return { ok: true, message: `${r.server} answered (it rejected the probe user, as expected), so the address and shared secret work.` }; }
        catch (e) { return { ok: false, message: (e as Error).message }; }
      }
      return { ok: false, message: 'Enter a test user name and password to try a full sign-in' };
    }
    const r = await this.remote(provider, username, password);
    if (!r.ok) return { ok: false, message: r.reason ?? 'Sign-in failed' };
    this.log.info('auth', `Test sign-in for ${username} against ${provider} succeeded (role ${r.role})`);
    return { ok: true, message: `Signed in as ${username}. Mapped role: ${ROLE_LABEL[r.role!]}.`, role: r.role, groups: r.groups };
  }

  private testSaml(): { ok: boolean; message: string } {
    const s = this.aaa().saml;
    if (!s.idpSso) return { ok: false, message: 'Enter the IdP sign-on URL' };
    if (!s.idpCert) return { ok: false, message: 'Paste the IdP signing certificate' };
    try { const c = new crypto.X509Certificate(s.idpCert); if (Date.parse(c.validTo) < Date.now()) return { ok: false, message: 'The IdP signing certificate has expired' }; }
    catch { return { ok: false, message: 'The IdP signing certificate is not valid PEM' }; }
    return { ok: true, message: 'The IdP settings are complete and the signing certificate is valid. A real sign-in is the only full test.' };
  }
}
