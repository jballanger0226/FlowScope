import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import * as d from '../src/tls/der.js';
import { mockDirectory, type Ent } from './helpers.js';
import { ldapLogin, adLogin, encodeFilter, escapeFilter, groupMatches } from '../src/auth/ldap.js';

const dirEntries: Ent[] = [
  { dn: 'uid=alice,ou=people,dc=ex,dc=com', attrs: { uid: ['alice'], cn: ['Alice A'], displayName: ['Alice Anders'], memberOf: ['cn=netops,ou=groups,dc=ex,dc=com'] } },
  { dn: 'uid=bob,ou=people,dc=ex,dc=com', attrs: { uid: ['bob'], cn: ['Bob B'], memberOf: [] } },
  { dn: 'cn=netops,ou=groups,dc=ex,dc=com', attrs: { cn: ['netops'], member: ['uid=alice,ou=people,dc=ex,dc=com'] } },
  { dn: 'cn=svc,dc=ex,dc=com', attrs: { cn: ['svc'] } }
];
const pw = { 'uid=alice,ou=people,dc=ex,dc=com': 'alice-pw', 'uid=bob,ou=people,dc=ex,dc=com': 'bob-pw', 'cn=svc,dc=ex,dc=com': 'svc-pw' };

test('LDAP filter encoding and escaping', () => {
  assert.equal(escapeFilter('a*(b)\\'), 'a\\2a\\28b\\29\\5c');
  const f = d.read(encodeFilter('(&(uid=al\\2aice)(|(cn=*)(mail=a*b*c))(!(x=y))(member:1.2.840.113556.1.4.1941:=cn=g))'));
  assert.equal(f.tag, 0xa0);
  assert.deepEqual(d.children(f).map(c => c.tag), [0xa3, 0xa1, 0xa2, 0xa9]);
  assert.throws(() => encodeFilter('(uid=a'), /Invalid LDAP filter/);
  assert.throws(() => encodeFilter('uid=a'), /Invalid LDAP filter/);
});

test('LDAP login: success with groups, wrong password, unknown user, empty password, injection attempt', async () => {
  const s = await mockDirectory(dirEntries, pw);
  try {
    const cfg = { url: `ldap://127.0.0.1:${s.port}`, bindDn: 'cn=svc,dc=ex,dc=com', bindPw: 'svc-pw', baseDn: 'dc=ex,dc=com', filter: '(uid={user})', groupBase: 'ou=groups,dc=ex,dc=com', verify: true };
    const ok = await ldapLogin(cfg, 'alice', 'alice-pw');
    assert.equal(ok.ok, true); assert.equal(ok.displayName, 'Alice Anders');
    assert.ok(groupMatches(ok.groups, 'NetOps'));
    assert.ok(!groupMatches(ok.groups, 'admins'));
    assert.equal((await ldapLogin(cfg, 'alice', 'nope')).ok, false);
    assert.equal((await ldapLogin(cfg, 'alice', '')).ok, false);
    assert.match((await ldapLogin(cfg, 'ghost', 'x')).reason!, /No such user/);
    const inj = await ldapLogin(cfg, 'a*', 'x');
    assert.equal(inj.ok, false, 'wildcard characters in the user name must not match');
    const b = await ldapLogin(cfg, 'bob', 'bob-pw'); assert.equal(b.ok, true); assert.deepEqual(b.groups, []);
    const bad = await ldapLogin({ ...cfg, bindPw: 'wrong' }, 'alice', 'alice-pw'); assert.equal(bad.ok, false); assert.match(bad.reason!, /service account/);
    const down = await ldapLogin({ ...cfg, url: 'ldap://127.0.0.1:1' }, 'alice', 'x', 800); assert.equal(down.ok, false); assert.equal(down.unreachable, true);
  } finally { s.close(); }
});

test('Active Directory login: UPN bind, nested groups, disabled account', async () => {
  const ad: Ent[] = [
    { dn: 'CN=Carol,OU=Users,DC=corp,DC=ex', attrs: { objectCategory: ['person'], objectClass: ['user'], sAMAccountName: ['carol'], userPrincipalName: ['carol@corp.ex'], displayName: ['Carol C'], memberOf: ['CN=Helpdesk,OU=Groups,DC=corp,DC=ex'], userAccountControl: ['512'] } },
    { dn: 'CN=Dave,OU=Users,DC=corp,DC=ex', attrs: { objectCategory: ['person'], objectClass: ['user'], sAMAccountName: ['dave'], userPrincipalName: ['dave@corp.ex'], memberOf: [], userAccountControl: ['514'] } },
    { dn: 'CN=Helpdesk,OU=Groups,DC=corp,DC=ex', attrs: { objectClass: ['group'], cn: ['Helpdesk'], memberOf: ['CN=NetAdmins,OU=Groups,DC=corp,DC=ex'] } },
    { dn: 'CN=NetAdmins,OU=Groups,DC=corp,DC=ex', attrs: { objectClass: ['group'], cn: ['NetAdmins'] } }
  ];
  const s = await mockDirectory(ad, { 'carol@corp.ex': 'carol-pw', 'dave@corp.ex': 'dave-pw' });
  try {
    const cfg = { domain: 'corp.ex', dcs: ['127.0.0.1:' + s.port], bindUser: '', bindPw: '', baseDn: 'DC=corp,DC=ex', ldaps: false, nested: true, verify: true };
    const r = await adLogin(cfg, 'CORP\\carol', 'carol-pw');
    assert.equal(r.ok, true, String(r.reason));
    assert.ok(groupMatches(r.groups, 'netadmins'), 'nested group is found: ' + r.groups.join('|'));
    assert.equal((await adLogin(cfg, 'carol@corp.ex', 'bad')).ok, false);
    assert.match((await adLogin(cfg, 'dave', 'dave-pw')).reason!, /disabled/);
    const flat = await adLogin({ ...cfg, nested: false }, 'carol', 'carol-pw');
    assert.ok(!groupMatches(flat.groups, 'netadmins') && groupMatches(flat.groups, 'helpdesk'));
    const dead = await adLogin({ ...cfg, dcs: ['127.0.0.1:1', '127.0.0.1:' + s.port] }, 'carol', 'carol-pw', 800);
    assert.equal(dead.ok, true, 'fails over to the second domain controller');
  } finally { s.close(); }
});
