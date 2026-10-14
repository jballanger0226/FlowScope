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
    const t2 = e.auth.createToken(snmp, { name: 'mine', days: 30 });
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

test('the sign-in limiter forgets the oldest key when full, not everybody', async () => {
  const { Limiter } = await import('../src/auth/service.js');
  const l = new Limiter(3, 60_000, 100);
  for (let i = 0; i < 3; i++) l.fail('victim');
  assert.equal(l.blocked('victim'), true);
  // a flood of other keys must not release the victim
  for (let i = 0; i < 500; i++) l.fail('spray-' + i);
  assert.equal(l.size, 100);
  assert.equal(l.blocked('spray-499'), false);
  for (let i = 0; i < 3; i++) l.fail('victim');   // an attacker who keeps trying stays blocked
  for (let i = 0; i < 90; i++) l.fail('more-' + i);
  assert.equal(l.blocked('victim'), true);
  // checking does not store anything
  const before = l.size;
  for (let i = 0; i < 1000; i++) l.blocked('probe-' + i);
  assert.equal(l.size, before);
  // clear releases one key
  l.clear('victim'); assert.equal(l.blocked('victim'), false);
});

// --- password hashing (audit A1) ---
test('password hashes: old ones keep working and are upgraded at the next sign-in', async () => {
  const sec = await import('../src/secrets.js');
  const crypto = await import('node:crypto');
  const e = env();
  const prev = process.env.FLOWSCOPE_SCRYPT_LOG2N;
  try {
    e.auth.bootstrap('initial-admin-password');
    // a hash as written by earlier versions: N=16384 (2^14)
    const salt = crypto.randomBytes(16);
    const legacy = `scrypt$16384$8$1$${salt.toString('base64')}$${crypto.scryptSync('initial-admin-password', salt, 32, { N: 16384, r: 8, p: 1 }).toString('base64')}`;
    e.cdb.db.prepare("UPDATE users SET pw_hash = ? WHERE username = 'admin'").run(legacy);
    assert.equal(sec.verifyPassword('initial-admin-password', legacy), true);
    assert.equal(await sec.verifyPasswordAsync('initial-admin-password', legacy), true);
    assert.equal(await sec.verifyPasswordAsync('nope', legacy), false);
    assert.equal(sec.needsRehash(legacy), false, 'at the test cost (2^10) a 2^14 hash is already strong enough');
    process.env.FLOWSCOPE_SCRYPT_LOG2N = '15';
    assert.equal(sec.needsRehash(legacy), true);
    await assert.rejects(() => e.auth.authenticate('web', 'admin', 'wrong-password-here', '5.5.5.1'));
    assert.equal((e.cdb.db.prepare("SELECT pw_hash FROM users WHERE username = 'admin'").get() as { pw_hash: string }).pw_hash, legacy, 'a failed sign-in changes nothing');
    await e.auth.authenticate('web', 'admin', 'initial-admin-password', '5.5.5.2');
    const now = (e.cdb.db.prepare("SELECT pw_hash FROM users WHERE username = 'admin'").get() as { pw_hash: string }).pw_hash;
    assert.match(now, /^scrypt\$32768\$8\$1\$/);
    assert.equal(sec.needsRehash(now), false);
    await e.auth.authenticate('web', 'admin', 'initial-admin-password', '5.5.5.3');   // and the new hash verifies
    // malformed stored values never verify
    assert.equal(await sec.verifyPasswordAsync('x', 'scrypt$1$8$1$AA==$AA=='), false);
    assert.equal(await sec.verifyPasswordAsync('x', 'scrypt$999999999$8$1$AA==$AA=='), false);
    assert.equal(await sec.verifyPasswordAsync('x', 'plain'), false);
  } finally { if (prev === undefined) delete process.env.FLOWSCOPE_SCRYPT_LOG2N; else process.env.FLOWSCOPE_SCRYPT_LOG2N = prev; e.done(); }
});

test('parallel wrong guesses against one account still lock it', async () => {
  const e = env();
  try {
    e.auth.bootstrap('initial-admin-password');
    const a = e.settings.get('aaa'); a.local.lockout = 5; e.settings.set('aaa', a);
    const results = await Promise.allSettled(Array.from({ length: 30 }, (_, i) => e.auth.authenticate('web', 'admin', 'guess-' + i, '6.6.6.' + i)));
    const locked = results.filter(r => r.status === 'rejected' && /locked/.test((r.reason as Error).message)).length;
    assert.ok(locked >= 24, 'only the first five guesses are checked; got ' + locked + ' locked');
    // the right password is refused while locked
    await assert.rejects(() => e.auth.authenticate('web', 'admin', 'initial-admin-password', '6.6.7.1'), /locked/);
  } finally { e.done(); }
});

test('a flood of password checks gets "busy" instead of unbounded work', async () => {
  const sec = await import('../src/secrets.js');
  const h = sec.hashPassword('right');
  const r = await Promise.allSettled(Array.from({ length: 120 }, () => sec.verifyPasswordAsync('right', h)));
  const busy = r.filter(x => x.status === 'rejected' && x.reason instanceof sec.PasswordBusy).length;
  assert.equal(r.filter(x => x.status === 'fulfilled').length, 66);   // 2 running + 64 queued
  assert.equal(busy, 54);
  // and it recovers
  assert.equal(await sec.verifyPasswordAsync('right', h), true);
});

test('API token policy: lifetime limits, no expiry for admins only, revoked on reset, used-time written at most once a minute', async () => {
  const e = env();
  try {
    e.auth.bootstrap('initial-admin-password');
    const admin = (await e.auth.authenticate('api', 'admin', 'initial-admin-password', '7.7.7.1')).principal;
    e.auth.createUser('admin', { username: 'snmpadm', password: 'long-secret-passphrase-3', role: 'snmp', mustChange: false });
    const snmp = (await e.auth.authenticate('api', 'snmpadm', 'long-secret-passphrase-3', '7.7.7.2')).principal;
    assert.throws(() => e.auth.createToken(snmp, { name: 'forever', days: 0 }), /Only administrators/);
    assert.throws(() => e.auth.createToken(snmp, { name: 'long', days: 366 }), /up to 365 days/);
    e.auth.createToken(snmp, { name: 'ok', days: 365 });
    e.auth.createToken(admin, { name: 'forever', days: 0 });
    e.auth.createToken(admin, { name: 'long', days: 1000 });
    assert.throws(() => e.auth.createToken(admin, { name: 'x', days: 4000 }), /1 to 3650/);

    // a reset ends the tokens of that user only
    const uid = e.auth.listUsers().find(u => u.username === 'snmpadm')!.id;
    const tk = e.auth.createToken(snmp, { name: 'script', days: 30 }).token;
    const adminTk = e.auth.createToken(admin, { name: 'ops', days: 30 }).token;
    assert.ok(e.auth.fromToken(tk));
    e.auth.updateUser('admin', uid, { password: 'another-long-passphrase-9' });
    assert.equal(e.auth.fromToken(tk), null);
    assert.equal(e.auth.listTokens(admin).filter(t => t.username === 'snmpadm').length, 0);
    assert.ok(e.auth.fromToken(adminTk), 'other users keep theirs');
    // changing your own password is not a reset: scripts keep working
    e.auth.changePassword('admin', 'initial-admin-password', 'a-brand-new-passphrase-1');
    assert.ok(e.auth.fromToken(adminTk));

    // last_used is not written on every request
    const id = e.auth.listTokens(admin).find(t => t.name === 'ops')!.id;
    const used = () => (e.cdb.db.prepare('SELECT last_used FROM api_tokens WHERE id = ?').get(id) as { last_used: number | null }).last_used!;
    const first = used();
    e.cdb.db.prepare('UPDATE api_tokens SET last_used = ? WHERE id = ?').run(first - 1000, id);
    e.auth.fromToken(adminTk);
    assert.equal(used(), first - 1000, 'a use within a minute of the last is not written');
    e.cdb.db.prepare('UPDATE api_tokens SET last_used = ? WHERE id = ?').run(first - 61_000, id);
    e.auth.fromToken(adminTk);
    assert.ok(used() >= first, 'an older record is refreshed');
  } finally { e.done(); }
});
