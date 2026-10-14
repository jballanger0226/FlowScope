import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ConfigDb } from '../src/db/configdb.js';
import { Secrets } from '../src/secrets.js';
import { Settings } from '../src/settings.js';
import { AppLog } from '../src/logger.js';
import { AuthService, AuthError } from '../src/auth/service.js';
import { mockRadius, mockDirectory } from './helpers.js';

function env() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-auth-'));
  const cdb = new ConfigDb(dir); const settings = new Settings(cdb); const secrets = new Secrets(dir, 'k');
  const log = new AppLog(cdb, settings, 'error'); log.quiet = true;
  const auth = new AuthService(cdb, settings, secrets, log);
  return { dir, cdb, settings, secrets, log, auth, done: () => { log.close(); cdb.close(); fs.rmSync(dir, { recursive: true, force: true }); } };
}

test('bootstrap admin, password policy, change password, sessions with idle timeout', async () => {
  const e = env();
  try {
    const pw = e.auth.bootstrap()!;
    assert.ok(pw && pw.length >= 12);
    assert.equal(e.auth.bootstrap(), null);
    const r = await e.auth.authenticate('web', 'admin', pw, '10.0.0.1');
    assert.equal(r.principal.role, 'admin'); assert.equal(r.mustChange, true);
    assert.throws(() => e.auth.changePassword('admin', pw, 'short'), /at least 12/);
    assert.throws(() => e.auth.changePassword('admin', pw, 'password123'), AuthError);
    assert.throws(() => e.auth.changePassword('admin', 'wrong', 'a-good-long-passphrase'), /current password/);
    e.auth.changePassword('admin', pw, 'a-good-long-passphrase');
    const r2 = await e.auth.authenticate('web', 'ADMIN', 'a-good-long-passphrase', '10.0.0.1');
    assert.equal(r2.mustChange, false);
    const { token, csrf } = e.auth.createSession(r2.principal, '10.0.0.1');
    const p = e.auth.fromSession(token)!;
    assert.equal(p.username, 'admin'); assert.equal(p.csrf, csrf);
    assert.equal(e.auth.fromSession(token + 'x'), null);
    // role change takes effect on the live session
    e.auth.createUser('admin', { username: 'viewer', password: 'long-secret-passphrase-2', role: 'ro' });
    const v = await e.auth.authenticate('web', 'viewer', 'long-secret-passphrase-2', '10.0.0.2');
    const vs = e.auth.createSession(v.principal, '10.0.0.2');
    const vid = e.auth.listUsers().find(u => u.username === 'viewer')!.id;
    e.auth.updateUser('admin', vid, { role: 'snmp' });
    assert.equal(e.auth.fromSession(vs.token)!.role, 'snmp');
    e.auth.updateUser('admin', vid, { disabled: true });
    assert.equal(e.auth.fromSession(vs.token), null);
    // idle timeout
    e.cdb.db.prepare('UPDATE sessions SET last_seen = ? WHERE id != ?').run(Date.now() - 31 * 60_000, 'none');
    assert.equal(e.auth.fromSession(token), null);
    // last admin protection
    const adminId = e.auth.listUsers().find(u => u.username === 'admin')!.id;
    assert.throws(() => e.auth.updateUser('admin', adminId, { disabled: true }), /last enabled/);
    assert.throws(() => e.auth.deleteUser('admin', adminId), /own account|last enabled/);
  } finally { e.done(); }
});

test('lockout after repeated failures and rate limiting', async () => {
  const e = env();
  try {
    e.auth.bootstrap('initial-admin-password');
    e.auth.createUser('admin', { username: 'carol', password: 'long-secret-passphrase-1', role: 'ro', mustChange: false });
    for (let i = 0; i < 5; i++) await assert.rejects(() => e.auth.authenticate('web', 'carol', 'wrong' + i, '10.1.1.' + i), /Wrong user name or password/);
    await assert.rejects(() => e.auth.authenticate('web', 'carol', 'long-secret-passphrase-1', '10.1.1.99'), /locked/);
    const id = e.auth.listUsers().find(u => u.username === 'carol')!.id;
    assert.equal(e.auth.listUsers().find(u => u.username === 'carol')!.locked, true);
    e.auth.updateUser('admin', id, { unlock: true });
    await e.auth.authenticate('web', 'carol', 'long-secret-passphrase-1', '10.1.1.99');
    // same address hammering different names is limited
    for (let i = 0; i < 10; i++) await assert.rejects(() => e.auth.authenticate('web', 'user' + i, 'x' + i, '10.9.9.9'));
    await assert.rejects(() => e.auth.authenticate('web', 'carol', 'long-secret-passphrase-1', '10.9.9.9'), /Too many failed/);
  } finally { e.done(); }
});

test('API tokens: cannot exceed creator role, expire, revoke, die with the user', async () => {
  const e = env();
  try {
    e.auth.bootstrap('initial-admin-password');
    const admin = (await e.auth.authenticate('api', 'admin', 'initial-admin-password', '1.1.1.1')).principal;
    e.auth.createUser('admin', { username: 'snmpadm', password: 'long-secret-passphrase-3', role: 'snmp', mustChange: false });
    const snmp = (await e.auth.authenticate('api', 'snmpadm', 'long-secret-passphrase-3', '1.1.1.2')).principal;
    assert.throws(() => e.auth.createToken(snmp, { name: 'x', role: 'admin' }), /more access/);
    const t = e.auth.createToken(admin, { name: 'grafana', role: 'ro', days: 1 });
    assert.match(t.token, /^fs_/);
    assert.equal(e.auth.fromToken(t.token)!.role, 'ro');
    assert.ok(!JSON.stringify(e.cdb.db.prepare('SELECT * FROM api_tokens').all()).includes(t.token));
    e.cdb.db.prepare('UPDATE api_tokens SET expires_at = ?').run(Date.now() - 1000);
    assert.equal(e.auth.fromToken(t.token), null);
    const t2 = e.auth.createToken(snmp, { name: 'mine', days: 0 });
    assert.equal(e.auth.listTokens(snmp).length, 1);
    assert.equal(e.auth.listTokens(admin).length, 2);
    assert.throws(() => e.auth.revokeToken(snmp, e.auth.listTokens(admin)[0].id), /own tokens/);
    // demoting the user caps the token
    const uid = e.auth.listUsers().find(u => u.username === 'snmpadm')!.id;
    e.auth.updateUser('admin', uid, { role: 'ro' });
    assert.equal(e.auth.fromToken(t2.token)!.role, 'ro');
    e.auth.deleteUser('admin', uid);
    assert.equal(e.auth.fromToken(t2.token), null);
  } finally { e.done(); }
});

test('RADIUS login maps Filter-Id to a role; unreachable server uses break-glass only for local admins', async () => {
  const e = env();
  const srv = await mockRadius('sh4red', { rad_admin: { pw: 'radius-pass-1', filter: 'fs-admins' }, rad_ro: { pw: 'radius-pass-2', filter: 'fs-viewers' }, rad_none: { pw: 'radius-pass-3', filter: 'other' } });
  try {
    e.auth.bootstrap('initial-admin-password');
    e.auth.createUser('admin', { username: 'localro', password: 'local-ro-password', role: 'ro', mustChange: false });
    const a = e.settings.get('aaa');
    a.services.web = 'radius';
    a.radius.host1 = '127.0.0.1:' + srv.port; a.radius.timeout = 1; a.radius.retries = 0; a.radius.secretEnc = e.secrets.encryptJson('sh4red');
    a.map.radius = { admin: 'fs-admins', snmp: 'fs-snmp', ro: 'fs-viewers' };
    e.settings.set('aaa', a);
    const r = await e.auth.authenticate('web', 'rad_admin', 'radius-pass-1', '2.2.2.2');
    assert.equal(r.principal.role, 'admin'); assert.equal(r.principal.source, 'radius');
    assert.equal((await e.auth.authenticate('web', 'rad_ro', 'radius-pass-2', '2.2.2.2')).principal.role, 'ro');
    await assert.rejects(() => e.auth.authenticate('web', 'rad_none', 'radius-pass-3', '2.2.2.2'), /maps to a role/);
    await assert.rejects(() => e.auth.authenticate('web', 'rad_admin', 'bad', '2.2.2.3'), /Wrong user name or password/);
    assert.equal(e.auth.listUsers().find(u => u.username === 'rad_admin')!.source, 'radius');
    // a remote user cannot use the local password path
    // default role when nothing maps
    a.def.radius = 'ro'; e.settings.set('aaa', a);
    assert.equal((await e.auth.authenticate('web', 'rad_none', 'radius-pass-3', '2.2.2.4')).principal.role, 'ro');
    // test button
    const t = await e.auth.testProvider('radius', 'rad_admin', 'radius-pass-1');
    assert.equal(t.ok, true); assert.equal(t.role, 'admin');
    // the CLI service stays local
    assert.equal((await e.auth.authenticate('cli', 'admin', 'initial-admin-password', '2.2.2.5')).principal.source, 'local');
    // server goes away: local admin may break glass, a local read-only user may not
    srv.close();
    a.radius.host1 = '127.0.0.1:1'; e.settings.set('aaa', a);
    const bg = await e.auth.authenticate('web', 'admin', 'initial-admin-password', '2.2.2.6');
    assert.equal(bg.principal.source, 'local');
    await assert.rejects(() => e.auth.authenticate('web', 'localro', 'local-ro-password', '2.2.2.7'), /limited to local administrators/);
    a.fallback = false; e.settings.set('aaa', a);
    await assert.rejects(() => e.auth.authenticate('web', 'admin', 'initial-admin-password', '2.2.2.8'));
  } finally { try { srv.close(); } catch { /* already closed */ } e.done(); }
});

test('LDAP login maps groups; AD nested groups', async () => {
  const e = env();
  const dir = await mockDirectory([
    { dn: 'uid=ann,ou=p,dc=ex', attrs: { uid: ['ann'], memberOf: ['cn=fs-snmp,ou=g,dc=ex'] } },
    { dn: 'uid=svc,dc=ex', attrs: { uid: ['svc'] } }
  ], { 'uid=ann,ou=p,dc=ex': 'ann-password-1', 'uid=svc,dc=ex': 'svc-pass' });
  try {
    e.auth.bootstrap('initial-admin-password');
    const a = e.settings.get('aaa');
    a.services.api = 'ldap';
    a.ldap = { url: 'ldap://127.0.0.1:' + dir.port, bindDn: 'uid=svc,dc=ex', baseDn: 'dc=ex', filter: '(uid={user})', groupBase: '', verify: true, bindPwEnc: e.secrets.encryptJson('svc-pass') };
    a.map.ldap = { admin: 'fs-admin', snmp: 'fs-snmp', ro: '' };
    e.settings.set('aaa', a);
    const r = await e.auth.authenticate('api', 'ann', 'ann-password-1', '3.3.3.3');
    assert.equal(r.principal.role, 'snmp');
    assert.equal((await e.auth.testProvider('ldap', 'ann', 'ann-password-1')).ok, true);
    assert.equal((await e.auth.testProvider('ldap', 'ann', 'wrong')).ok, false);
    // web is still local
    await assert.rejects(() => e.auth.authenticate('web', 'ann', 'ann-password-1', '3.3.3.4'));
  } finally { dir.close(); e.done(); }
});

test('with SAML as the web provider, local administrators can still sign in through the form (when fallback is on)', async () => {
  const e = env();
  try {
    e.auth.bootstrap('initial-admin-password');
    e.auth.createUser('admin', { username: 'localro', password: 'local-ro-password', role: 'ro' });
    const a = e.settings.get('aaa');
    a.services.web = 'saml'; a.fallback = true; e.settings.set('aaa', a);
    const r = await e.auth.authenticate('web', 'admin', 'initial-admin-password', '3.3.3.1');
    assert.equal(r.principal.role, 'admin'); assert.equal(r.principal.source, 'local');
    // only administrators, and the answer does not reveal that the password was right
    await assert.rejects(() => e.auth.authenticate('web', 'localro', 'local-ro-password', '3.3.3.2'), /Wrong user name or password/);
    await assert.rejects(() => e.auth.authenticate('web', 'admin', 'not-the-password', '3.3.3.3'), /Wrong user name or password/);
    // a disabled admin stays out
    e.auth.createUser('admin', { username: 'admin2', password: 'second-admin-password', role: 'admin' });
    e.cdb.db.prepare("UPDATE users SET disabled = 1 WHERE username = 'admin2'").run();
    await assert.rejects(() => e.auth.authenticate('web', 'admin2', 'second-admin-password', '3.3.3.4'), /disabled/);
    // repeated failures are still rate limited
    for (let i = 0; i < 10; i++) await assert.rejects(() => e.auth.authenticate('web', 'admin', 'bad-' + i, '3.3.3.5'));
    await assert.rejects(() => e.auth.authenticate('web', 'admin', 'initial-admin-password', '3.3.3.5'), /Too many/);
    // fallback off: SAML only
    a.fallback = false; e.settings.set('aaa', a);
    await assert.rejects(() => e.auth.authenticate('web', 'admin', 'initial-admin-password', '3.3.3.6'), /Wrong user name or password/);
  } finally { e.done(); }
});

test('Message-Authenticator is required by default; a RADIUS setup saved before the setting existed keeps working', async () => {
  const fresh = env();
  try {
    assert.equal(fresh.settings.get('aaa').radius.requireMa, true);
  } finally { fresh.done(); }
  const e = env();
  try {
    // what an older version stored: a configured server and no requireMa
    e.settings.setRaw('aaa', JSON.stringify({ radius: { host1: 'radius.example.com', authPort: 1812 } }));
    assert.equal(e.settings.get('aaa').radius.requireMa, true, 'without migration the default would apply');
    new AuthService(e.cdb, e.settings, e.secrets, e.log);
    assert.equal(e.settings.get('aaa').radius.requireMa, false);
    assert.equal(e.settings.get('aaa').radius.host1, 'radius.example.com');
    // an admin who has chosen is left alone
    e.settings.setRaw('aaa', JSON.stringify({ radius: { host1: 'radius.example.com', requireMa: true } }));
    new AuthService(e.cdb, e.settings, e.secrets, e.log);
    assert.equal(e.settings.get('aaa').radius.requireMa, true);
    // nothing configured: the default stays on
    e.settings.setRaw('aaa', JSON.stringify({ radius: { host1: '' } }));
    new AuthService(e.cdb, e.settings, e.secrets, e.log);
    assert.equal(e.settings.get('aaa').radius.requireMa, true);
  } finally { e.done(); }
});
