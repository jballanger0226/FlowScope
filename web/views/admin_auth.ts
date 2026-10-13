import { h, type VNode } from '../vdom.js';
import { get, put, post } from '../api.js';
import { redraw } from '../state.js';
import { btn, chip, field, msg, note, numberInput, seg, select, spinner, tabs, textInput, toggle, textArea } from '../components.js';

type Svc = 'web' | 'api' | 'cli';
type Prov = 'local' | 'radius' | 'ldap' | 'ad' | 'saml';
type Ext = 'radius' | 'ldap' | 'ad' | 'saml';
interface Aaa {
  services: Record<Svc, Prov>; fallback: boolean;
  local: { minLen: number; lockout: number; idle: number };
  radius: { host1: string; host2: string; authPort: number; acctPort: number; timeout: number; retries: number; attr: string; acct: boolean; hasSecret: boolean };
  ldap: { url: string; bindDn: string; baseDn: string; filter: string; groupBase: string; verify: boolean; hasBindPw: boolean };
  ad: { domain: string; dcs: string; bindUser: string; baseDn: string; ldaps: boolean; nested: boolean; verify: boolean; hasBindPw: boolean };
  saml: { idp: string; sp: string; nameAttr: string; groupAttr: string; sign: boolean; idpEntity: string; idpSso: string; idpCert: string };
  map: Record<Ext, { admin: string; snmp: string; ro: string }>;
  def: Record<Ext, 'deny' | 'ro'>;
}

let aaa: Aaa | null = null; let callback = ''; let loadErr = '';
let tab: Prov = 'local';
let secrets = { radius: '', ldap: '', ad: '' };       // typed secrets, sent only when filled in
let testUser = '', testPw = '';
let saveMsg = '', saveOk = false, busy = false; let testMsg = '', testOk = false, testBusy = false;

const PROV_NAME: Record<Prov, string> = { local: 'Local accounts', radius: 'RADIUS', ldap: 'LDAP', ad: 'Active Directory', saml: 'SAML single sign-on' };
const SVC_INFO: Record<Svc, [string, string]> = { web: ['Web interface', 'People signing in with a browser'], api: ['REST API', 'Scripts using a user name and password or tokens'], cli: ['Command line', 'The flowscope admin command'] };

export async function load(): Promise<void> {
  try {
    const r = await get<{ aaa: Aaa; callback: string }>('/api/admin/aaa');
    aaa = r.aaa; callback = r.callback || location.origin + '/api/auth/saml/acs'; loadErr = '';
  } catch (e) { loadErr = (e as Error).message; }
  redraw();
}

async function save(): Promise<void> {
  if (!aaa) return;
  busy = true; saveMsg = ''; redraw();
  try {
    const body: Record<string, unknown> = {
      services: aaa.services, fallback: aaa.fallback, local: aaa.local, map: aaa.map, def: aaa.def,
      radius: { ...aaa.radius, secret: secrets.radius || undefined }, ldap: { ...aaa.ldap, bindPw: secrets.ldap || undefined },
      ad: { ...aaa.ad, bindPw: secrets.ad || undefined }, saml: aaa.saml
    };
    const r = await put<{ aaa: Aaa }>('/api/admin/aaa', body);
    aaa = r.aaa; secrets = { radius: '', ldap: '', ad: '' }; saveOk = true; saveMsg = 'Saved. The new sign-in settings apply to the next sign-in; people already signed in stay signed in.';
  } catch (e) { saveOk = false; saveMsg = (e as Error).message; }
  busy = false; redraw();
}

async function test(): Promise<void> {
  if (!aaa) return;
  testBusy = true; testMsg = 'Trying…'; redraw();
  try {
    // save unsaved typed values first so the test uses what is on the screen
    await save();
    if (!saveOk) { testMsg = 'Fix the settings first: ' + saveMsg; testOk = false; testBusy = false; redraw(); return; }
    const r = await post<{ ok: boolean; message: string; role?: string | null; groups?: string[] }>('/api/admin/aaa/test', { provider: tab, username: testUser, password: testPw });
    testOk = r.ok; testMsg = r.message + (r.ok && r.role !== undefined ? ` Role from the group mapping: ${r.role ?? 'none (sign-in would be denied or read only)'}.` : '') + (r.groups?.length ? ` Groups: ${r.groups.slice(0, 8).join(', ')}.` : '');
  } catch (e) { testOk = false; testMsg = (e as Error).message; }
  testBusy = false; redraw();
}

function services(a: Aaa): VNode {
  return h('div', { class: 'panel col', style: 'gap:14px' },
    h('h3', null, 'Sign-in method for each service'),
    (['web', 'api', 'cli'] as Svc[]).map(svc => {
      const opts: Prov[] = svc === 'web' ? ['local', 'radius', 'ldap', 'ad', 'saml'] : ['local', 'radius', 'ldap', 'ad'];
      const p = a.services[svc];
      const warn = p !== 'local' && !a.map[p as Ext].admin ? `No ${PROV_NAME[p]} group is mapped to the Admin role yet.` : '';
      return h('div', { key: svc, class: 'row', style: 'justify-content:space-between;border-bottom:1px solid var(--raised);padding-bottom:10px' },
        h('div', { class: 'col', style: 'gap:2px;min-width:200px' }, h('b', null, SVC_INFO[svc][0]), h('span', { class: 'muted' }, SVC_INFO[svc][1])),
        h('div', { class: 'col', style: 'gap:6px' },
          seg(`${SVC_INFO[svc][0]} sign-in method`, opts.map(o => ({ id: o, label: PROV_NAME[o], on: p === o })), id => { a.services[svc] = id as Prov; tab = id as Prov; redraw(); }),
          warn ? h('span', { style: 'color:var(--warn);font-size:12px' }, warn) : null));
    }),
    toggle('Keep a local break-glass admin if the remote provider is unreachable', a.fallback, () => { a.fallback = !a.fallback; redraw(); }),
    h('p', { class: 'muted' }, 'The fallback applies only when the remote provider cannot be reached at all, and only to local accounts with the Admin role. A wrong password never falls back. SAML is a browser sign-in flow, so it is offered for the web interface only.'));
}

const tx = (label: string, get_: () => string, set: (v: string) => void, o: { ph?: string; hint?: string; type?: string; mono?: boolean } = {}) => field(label, textInput(get_(), v => { set(v); }, { placeholder: o.ph, type: o.type, aria: label, mono: o.mono }), o.hint);
const nm = (label: string, get_: () => number, set: (v: number) => void, min: number, max: number, hint?: string) => field(label, numberInput(get_(), v => { set(Number(v)); }, { min, max, aria: label, width: '100%' }), hint);
const tg = (label: string, on: boolean, set: () => void) => toggle(label, on, () => { set(); redraw(); });
const secretPh = (has: boolean) => has ? 'Stored. Leave blank to keep it.' : 'Not set';

function localForm(a: Aaa): VNode {
  return h('div', { class: 'three' },
    nm('Minimum password length', () => a.local.minLen, v => { a.local.minLen = v; }, 8, 128, 'Applies to new and changed passwords.'),
    nm('Lock an account after failed attempts', () => a.local.lockout, v => { a.local.lockout = v; }, 0, 100, '0 turns lockout off. A locked account is unlocked by an admin under Roles and users.'),
    nm('Sign out idle sessions after (minutes)', () => a.local.idle, v => { a.local.idle = v; }, 1, 1440));
}
function radiusForm(a: Aaa): VNode {
  const r = a.radius;
  return h('div', { class: 'col', style: 'gap:12px' }, h('div', { class: 'two' },
    tx('Primary server', () => r.host1, v => { r.host1 = v; }, { ph: 'radius1.example.com', mono: true }), tx('Secondary server (optional)', () => r.host2, v => { r.host2 = v; }, { ph: 'radius2.example.com', mono: true }),
    field('Shared secret', textInput(secrets.radius, v => { secrets.radius = v; }, { type: 'password', placeholder: secretPh(r.hasSecret), autocomplete: 'new-password', aria: 'Shared secret' })),
    field('Role attribute', select(r.attr, [['Filter-Id', 'Filter-Id'], ['Class', 'Class'], ['Reply-Message', 'Reply-Message']], v => { r.attr = v; redraw(); }, { aria: 'Role attribute' }), 'The attribute in the Access-Accept that carries the group names.'),
    nm('Authentication port', () => r.authPort, v => { r.authPort = v; }, 1, 65535), nm('Accounting port', () => r.acctPort, v => { r.acctPort = v; }, 1, 65535),
    nm('Timeout (seconds)', () => r.timeout, v => { r.timeout = v; }, 1, 60), nm('Retries per server', () => r.retries, v => { r.retries = v; }, 0, 10)),
    tg('Send accounting records for sign-ins', r.acct, () => { r.acct = !r.acct; }));
}
function ldapForm(a: Aaa): VNode {
  const l = a.ldap;
  return h('div', { class: 'col', style: 'gap:12px' }, h('div', { class: 'two' },
    tx('Server address', () => l.url, v => { l.url = v; }, { ph: 'ldaps://ldap.example.com', mono: true }), tx('Search base', () => l.baseDn, v => { l.baseDn = v; }, { ph: 'ou=people,dc=example,dc=com', mono: true }),
    tx('Bind DN (service account)', () => l.bindDn, v => { l.bindDn = v; }, { ph: 'cn=flowscope,ou=svc,dc=example,dc=com', mono: true }),
    field('Bind password', textInput(secrets.ldap, v => { secrets.ldap = v; }, { type: 'password', placeholder: secretPh(l.hasBindPw), autocomplete: 'new-password', aria: 'Bind password' })),
    tx('User filter', () => l.filter, v => { l.filter = v; }, { ph: '(uid={user})', mono: true, hint: '{user} is replaced by the name typed at sign-in.' }),
    tx('Group search base (optional)', () => l.groupBase, v => { l.groupBase = v; }, { ph: 'ou=groups,dc=example,dc=com', mono: true })),
    tg('Verify the server certificate', l.verify, () => { l.verify = !l.verify; }),
    !l.verify ? note('Without certificate verification, anyone who can intercept the connection can read the bind password. Use only for testing.', 'warn') : null);
}
function adForm(a: Aaa): VNode {
  const d = a.ad;
  return h('div', { class: 'col', style: 'gap:12px' }, h('div', { class: 'two' },
    tx('Domain', () => d.domain, v => { d.domain = v; }, { ph: 'corp.example.com', mono: true }), tx('Domain controllers (optional)', () => d.dcs, v => { d.dcs = v; }, { ph: 'dc1.corp.example.com, dc2.corp.example.com', mono: true, hint: 'Found from the domain when blank.' }),
    tx('Bind user', () => d.bindUser, v => { d.bindUser = v; }, { ph: 'svc-flowscope@corp.example.com', mono: true }),
    field('Bind password', textInput(secrets.ad, v => { secrets.ad = v; }, { type: 'password', placeholder: secretPh(d.hasBindPw), autocomplete: 'new-password', aria: 'Bind password' })),
    tx('Search base', () => d.baseDn, v => { d.baseDn = v; }, { ph: 'DC=corp,DC=example,DC=com', mono: true })),
    h('div', { class: 'two' }, tg('Use LDAPS (TLS)', d.ldaps, () => { d.ldaps = !d.ldaps; }), tg('Include nested group membership', d.nested, () => { d.nested = !d.nested; })),
    tg('Verify the server certificate', d.verify, () => { d.verify = !d.verify; }));
}
function samlForm(a: Aaa): VNode {
  const m = a.saml;
  return h('div', { class: 'col', style: 'gap:12px' },
    note('The SAML sign-in is a built-in implementation that has not been checked against a production identity provider. Test it with a non-critical account before relying on it, and keep the local break-glass admin on.', 'warn'),
    h('div', { class: 'two' },
      tx('Identity provider name (for your own reference)', () => m.idp, v => { m.idp = v; }, { ph: 'Entra ID, Okta, ADFS…' }), tx('Service provider entity ID', () => m.sp, v => { m.sp = v; }, { ph: 'Leave blank to use the metadata URL below', mono: true }),
      tx('IdP entity ID', () => m.idpEntity, v => { m.idpEntity = v; }, { mono: true }), tx('IdP single sign-on URL', () => m.idpSso, v => { m.idpSso = v; }, { ph: 'https://login.example.com/saml2', mono: true }),
      tx('User name attribute', () => m.nameAttr, v => { m.nameAttr = v; }, { mono: true }), tx('Group attribute', () => m.groupAttr, v => { m.groupAttr = v; }, { mono: true })),
    field('IdP signing certificate (PEM)', textArea(m.idpCert, v => { m.idpCert = v; }, { rows: 4, placeholder: '-----BEGIN CERTIFICATE-----', aria: 'IdP signing certificate' })),
    tg('Also require the response itself to be signed (assertions must always be signed)', m.sign, () => { m.sign = !m.sign; }),
    h('div', { class: 'layer col', style: 'gap:4px' }, h('b', null, 'Give your identity provider these addresses'),
      h('span', { class: 'muted' }, 'Assertion consumer service (ACS) URL'), h('code', { class: 'code', style: 'word-break:break-all' }, callback),
      h('span', { class: 'muted' }, 'Service provider metadata'), h('code', { class: 'code', style: 'word-break:break-all' }, callback.replace(/\/acs$/, '/metadata'))));
}

function mapping(a: Aaa, p: Ext): VNode {
  const m = a.map[p];
  const ph = p === 'ad' ? 'CN=NetAdmins,OU=Groups,DC=corp,DC=example,DC=com' : p === 'radius' ? 'flowscope-admin' : 'group name or DN';
  return h('div', { class: 'panel col', style: 'gap:12px' },
    h('h3', null, 'Map provider groups to FlowScope roles'),
    h('p', { class: 'muted' }, 'Enter the group names (separate several with a semicolon). A user who matches more than one gets the highest role.'),
    h('div', { class: 'three' },
      field('Full admin', textInput(m.admin, v => { m.admin = v; }, { placeholder: ph, aria: 'Group for the Admin role', mono: true })),
      field('SNMP device admin', textInput(m.snmp, v => { m.snmp = v; }, { placeholder: ph, aria: 'Group for the SNMP admin role', mono: true })),
      field('Read only', textInput(m.ro, v => { m.ro = v; }, { placeholder: ph, aria: 'Group for the Read only role', mono: true }))),
    field('Users who match none of the groups', select(a.def[p], [['deny', 'Deny sign-in'], ['ro', 'Read only']], v => { a.def[p] = v as 'deny' | 'ro'; redraw(); }, { aria: 'Default for unmapped users', width: '240px' })));
}

export function render(): VNode {
  if (!aaa) return loadErr ? note(loadErr, 'bad', true) : spinner();
  const a = aaa;
  const ext = tab !== 'local' ? (tab as Ext) : null;
  return h('section', { 'aria-label': 'Authentication', class: 'col', style: 'gap:16px' },
    services(a),
    tabs('Provider to configure', (Object.keys(PROV_NAME) as Prov[]).map(p => ({ id: p, label: PROV_NAME[p], on: tab === p })), id => { tab = id as Prov; testMsg = ''; redraw(); }),
    h('div', { class: 'panel col', style: 'gap:14px' },
      h('div', { class: 'row', style: 'justify-content:space-between' }, h('h3', null, PROV_NAME[tab]),
        (['web', 'api', 'cli'] as Svc[]).filter(s => a.services[s] === tab).length ? chip('In use for ' + (['web', 'api', 'cli'] as Svc[]).filter(s => a.services[s] === tab).map(s => SVC_INFO[s][0].toLowerCase()).join(', '), 'ok') : chip('Not in use', 'default')),
      tab === 'local' ? localForm(a) : tab === 'radius' ? radiusForm(a) : tab === 'ldap' ? ldapForm(a) : tab === 'ad' ? adForm(a) : samlForm(a)),
    ext ? mapping(a, ext) : null,
    ext && ext !== 'saml' ? h('div', { class: 'panel col', style: 'gap:10px' }, h('h3', null, 'Test connection'),
      h('p', { class: 'muted' }, 'With a user name and password, FlowScope tries a full sign-in and shows the role it would give. With them blank, it only checks the server address' + (ext === 'radius' ? ' and shared secret.' : ' and the bind account.')),
      h('div', { class: 'row end' }, field('Test user', textInput(testUser, v => { testUser = v; }, { aria: 'Test user name', autocomplete: 'off' })), field('Test password', textInput(testPw, v => { testPw = v; }, { type: 'password', aria: 'Test password', autocomplete: 'new-password' })),
        btn(testBusy ? 'Testing…' : 'Save and test', { disabled: testBusy || busy, onclick: () => void test() })),
      testMsg ? note(testMsg, testOk ? 'ok' : testMsg === 'Trying…' ? 'info' : 'bad', true) : null) : null,
    h('div', { class: 'sticky-save' }, btn(busy ? 'Saving…' : 'Save authentication settings', { kind: 'primary', disabled: busy, onclick: () => void save() }), msg(saveMsg, saveOk ? 'ok' : 'bad')));
}
