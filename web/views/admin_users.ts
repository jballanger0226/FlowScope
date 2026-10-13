import { h, type VNode } from '../vdom.js';
import { get, post, put, patch, del } from '../api.js';
import { session, redraw } from '../state.js';
import { btn, chip, empty, field, msg, note, select, spinner, textInput, toggle } from '../components.js';
import { ago, stamp } from '../util.js';

interface User { id: number; username: string; role: 'ro' | 'snmp' | 'admin'; source: string; createdAt: number; lastLogin: number | null; lastSource: string | null; disabled: boolean; locked: boolean; mustChange: boolean }
interface Cred { id: number; name: string; version: string; username: string; level: string; authProto: string; privProto: string; context: string; isDefault: boolean; usedBy: number; hasSecret: boolean }

const ROLES: [string, string][] = [['ro', 'Read only'], ['snmp', 'SNMP device admin'], ['admin', 'Full admin']];
const MATRIX: [string, boolean, boolean, boolean][] = [
  ['Search flows, follow streams, view Links and QoS', true, true, true],
  ['Build and export reports', true, true, true],
  ['Create API tokens for themselves', true, true, true],
  ['View Storage and retention', false, true, true],
  ['Add, discover, pause and remove SNMP devices', false, true, true],
  ['View SNMP credential set names (never secrets)', false, true, true],
  ['Change retention and the storage backend', false, false, true],
  ['Create SNMP credential sets', false, false, true],
  ['Turn data collection on or off', false, false, true],
  ['HTTPS certificate, authentication, users, logs', false, false, true]
];

let users: User[] = []; let minLen = 12; let uErr = ''; let loaded = false;
let uName = '', uRole = 'ro', uMsg = '', uOk = false, uTemp = ''; let resetFor = 0, resetPw = '';
let creds: Cred[] = []; let cErr = '';
let editId = 0; let pendingDel = '';
let cf = blank();
let cMsg = '', cOk = false, cBusy = false;

function blank() { return { name: '', version: 'v3', username: '', level: 'authPriv', authProto: 'SHA-256', authKey: '', privProto: 'AES-128', privKey: '', context: '', community: '', def: false }; }

export async function load(): Promise<void> {
  try { const r = await get<{ users: User[]; minLen: number }>('/api/admin/users'); users = r.users; minLen = r.minLen; uErr = ''; } catch (e) { uErr = (e as Error).message; }
  try { creds = (await get<{ credentials: Cred[] }>('/api/snmp/credentials')).credentials; cErr = ''; } catch (e) { cErr = (e as Error).message; }
  loaded = true; redraw();
}

async function addUser(): Promise<void> {
  uMsg = ''; uTemp = ''; redraw();
  try { const r = await post<{ users: User[]; temporaryPassword?: string }>('/api/admin/users', { username: uName.trim(), role: uRole }); users = r.users; uTemp = r.temporaryPassword ?? ''; uOk = true; uMsg = `Added ${uName.trim()}.`; uName = ''; }
  catch (e) { uOk = false; uMsg = (e as Error).message; }
  redraw();
}
async function patchUser(u: User, body: Record<string, unknown>, ok: string): Promise<void> {
  uMsg = ''; uTemp = '';
  try { users = (await patch<{ users: User[] }>('/api/admin/users/' + u.id, body)).users; uOk = true; uMsg = ok; } catch (e) { uOk = false; uMsg = (e as Error).message; await load(); }
  redraw();
}
async function removeUser(u: User): Promise<void> {
  uMsg = ''; uTemp = '';
  try { users = (await del<{ users: User[] }>('/api/admin/users/' + u.id)).users; uOk = true; uMsg = `Deleted ${u.username}.`; } catch (e) { uOk = false; uMsg = (e as Error).message; }
  redraw();
}

function usersPanel(): VNode {
  const me = session.me!.username;
  return h('div', { class: 'col', style: 'gap:16px' },
    h('div', { class: 'panel col', style: 'gap:10px' },
      h('h3', null, 'What each role can do'), h('p', { class: 'muted' }, 'Roles are fixed. Remote users receive one of them through the group mapping on the Authentication tab.'),
      h('div', { class: 'tbl matrix' }, h('div', { class: 'inner', style: '--w:720px' },
        h('div', { class: 'tr head' }, h('span', null, 'Capability'), h('span', null, 'Read only'), h('span', null, 'SNMP device admin'), h('span', null, 'Full admin')),
        MATRIX.map(([cap, a, b, c], i) => h('div', { key: i, class: 'tr' }, h('span', null, cap), ...[a, b, c].map((v, k) => h('span', { key: k, class: v ? 'yes' : 'no', 'aria-label': v ? 'Yes' : 'No' }, v ? '✓ Yes' : '—')))))),
    ),
    h('div', { class: 'panel col', style: 'gap:12px' },
      h('h3', null, 'Local users'),
      uErr ? note(uErr, 'bad', true) : null,
      h('div', { class: 'tbl' }, h('div', { class: 'inner', style: '--cols:minmax(180px,1.4fr) 190px minmax(190px,1.4fr) 300px;--w:900px' },
        h('div', { class: 'tr head' }, ...['User', 'Role', 'Last sign-in', ''].map(t => h('span', null, t))),
        users.map(u => h('div', { key: u.id, class: 'tr tall' },
          h('div', null, h('div', { style: 'font-weight:600' }, u.username, u.username === me ? h('span', { class: 'dim' }, ' (you)') : null), h('div', { class: 'row', style: 'gap:6px' }, u.disabled ? chip('Disabled', 'default') : null, u.locked ? chip('Locked', 'bad') : null, u.mustChange ? chip('Must change password', 'warn') : null)),
          select(u.role, ROLES, v => void patchUser(u, { role: v }, `${u.username} is now ${ROLES.find(r => r[0] === v)![1]}.`), { aria: `Role for ${u.username}`, disabled: u.username === me, width: '100%' }),
          h('span', { class: 'muted' }, u.lastLogin ? `${ago(u.lastLogin)} (${stamp(u.lastLogin).slice(0, 16)})` : 'never'),
          h('div', { class: 'row', style: 'gap:6px' },
            u.locked ? btn('Unlock', { small: true, onclick: () => void patchUser(u, { unlock: true }, `Unlocked ${u.username}.`) }) : null,
            btn(u.disabled ? 'Enable' : 'Disable', { small: true, kind: 'ghost', disabled: u.username === me, onclick: () => void patchUser(u, { disabled: !u.disabled }, `${u.disabled ? 'Enabled' : 'Disabled'} ${u.username}.`) }),
            btn('Reset password', { small: true, kind: 'ghost', onclick: () => { resetFor = resetFor === u.id ? 0 : u.id; resetPw = ''; redraw(); } }),
            btn(pendingDel === 'u' + u.id ? 'Confirm delete' : 'Delete', { small: true, kind: 'danger', disabled: u.username === me, title: pendingDel === 'u' + u.id ? 'Their API tokens and sessions are removed too' : undefined, onclick: () => { if (pendingDel === 'u' + u.id) { pendingDel = ''; void removeUser(u); } else { pendingDel = 'u' + u.id; redraw(); } } })))),
        !users.length && loaded ? empty('No local users.') : null)),
      resetFor ? h('div', { class: 'note col', style: 'gap:8px' }, h('b', null, `Set a new password for ${users.find(u => u.id === resetFor)?.username}`),
        h('div', { class: 'row end' }, field('New password', textInput(resetPw, v => { resetPw = v; }, { type: 'password', autocomplete: 'new-password', aria: 'New password' }), `At least ${minLen} characters. The user must change it at the next sign-in.`),
          btn('Set password', { kind: 'primary', disabled: resetPw.length < minLen, onclick: () => { const u = users.find(x => x.id === resetFor)!; const pw = resetPw; resetFor = 0; resetPw = ''; void patchUser(u, { password: pw }, `Password reset for ${u.username}. They must change it at their next sign-in.`); } }), btn('Cancel', { kind: 'ghost', onclick: () => { resetFor = 0; redraw(); } }))) : null,
      h('div', { class: 'row end' },
        field('Add a local user', textInput(uName, v => { uName = v; }, { placeholder: 'Username', aria: 'New username', onenter: () => void addUser() })),
        field('Role', select(uRole, ROLES, v => { uRole = v; redraw(); }, { aria: 'Role for the new user' })),
        btn('Add user', { kind: 'primary', disabled: !uName.trim(), onclick: () => void addUser() }), msg(uMsg, uOk ? 'ok' : 'bad')),
      uTemp ? h('div', { class: 'note ok col', style: 'gap:6px' }, h('b', null, 'Temporary password. It is shown only once.'), h('code', { class: 'code', style: 'user-select:all;font-size:14px' }, uTemp), h('span', null, 'The user must change it at first sign-in.')) : null,
      h('p', { class: 'muted' }, 'A temporary password is generated and shown once. The user must change it at first sign-in.')));
}

/* ------------------------------------------------------------------ SNMP credential sets */

function summary(c: Cred): string {
  if (c.version === 'v2c') return 'SNMPv2c · community string';
  return `SNMPv3 · ${c.username} · ${c.level}${c.level !== 'noAuthNoPriv' ? ' · ' + c.authProto : ''}${c.level === 'authPriv' ? ' + ' + c.privProto : ''}`;
}
function editCred(c: Cred): void { editId = c.id; cf = { ...blank(), name: c.name, version: c.version, username: c.username, level: c.level, authProto: c.authProto, privProto: c.privProto, context: c.context }; cMsg = ''; redraw(); }
function newCred(): void { editId = 0; cf = blank(); cMsg = ''; redraw(); }

async function saveCred(): Promise<void> {
  cBusy = true; cMsg = ''; redraw();
  try {
    const body = { name: cf.name.trim(), version: cf.version, username: cf.username.trim(), level: cf.level, authProto: cf.authProto, privProto: cf.privProto, context: cf.context.trim(), community: cf.community || undefined, authKey: cf.authKey || undefined, privKey: cf.privKey || undefined, isDefault: cf.def };
    const r = editId ? await put<{ credentials: Cred[] }>('/api/snmp/credentials/' + editId, body) : await post<{ credentials: Cred[] }>('/api/snmp/credentials', body);
    creds = r.credentials; cOk = true; cMsg = editId ? 'Saved.' : 'Credential set created.'; editId = 0; cf = blank();
  } catch (e) { cOk = false; cMsg = (e as Error).message; }
  cBusy = false; redraw();
}
async function credAction(fn: () => Promise<{ credentials: Cred[] }>, ok: string): Promise<void> {
  try { creds = (await fn()).credentials; cOk = true; cMsg = ok; } catch (e) { cOk = false; cMsg = (e as Error).message; }
  redraw();
}

function credsPanel(): VNode {
  const v3 = cf.version === 'v3';
  const hasAuth = v3 && cf.level !== 'noAuthNoPriv', hasPriv = v3 && cf.level === 'authPriv';
  const ph = editId ? 'Stored. Leave blank to keep it.' : '';
  return h('div', { class: 'split' },
    h('div', { class: 'mainp', style: 'flex-basis:520px' }, h('div', { class: 'panel col', style: 'gap:12px' },
      h('h3', null, 'Credential sets'),
      h('p', { class: 'muted' }, 'Create each set once. When someone adds a device or runs a discovery on the SNMP devices tab, they pick a set by name and never type a secret. The default set is preselected.'),
      cErr ? note(cErr, 'bad', true) : null,
      creds.map(c => h('div', { key: c.id, class: 'layer col', style: 'gap:6px' },
        h('div', { class: 'row', style: 'justify-content:space-between' }, h('b', null, c.name), h('div', { class: 'row', style: 'gap:6px' }, c.isDefault ? chip('Default', 'accent') : null, c.version === 'v2c' ? chip('Clear-text community', 'warn') : null)),
        h('span', { class: 'muted' }, summary(c)), h('span', { class: 'dim' }, c.usedBy ? `Used by ${c.usedBy} device${c.usedBy === 1 ? '' : 's'}` : 'Not used by any device'),
        h('div', { class: 'row', style: 'gap:6px' }, btn('Edit', { small: true, onclick: () => editCred(c) }), !c.isDefault ? btn('Make default', { small: true, kind: 'ghost', onclick: () => void credAction(() => post(`/api/snmp/credentials/${c.id}/default`), `${c.name} is now the default.`) }) : null,
          btn(pendingDel === 'c' + c.id ? 'Confirm delete' : 'Delete', { small: true, kind: 'danger', disabled: c.usedBy > 0, title: c.usedBy ? 'In use by devices' : undefined, onclick: () => { if (pendingDel === 'c' + c.id) { pendingDel = ''; void credAction(() => del(`/api/snmp/credentials/${c.id}`), `Deleted ${c.name}.`); } else { pendingDel = 'c' + c.id; redraw(); } } })))),
      !creds.length && loaded ? empty('No credential sets yet. Create the first one on the right.') : null,
      msg(cMsg && !editId ? cMsg : '', cOk ? 'ok' : 'bad'))),
    h('div', { class: 'mainp', style: 'flex-basis:520px' }, h('div', { class: 'panel col', style: 'gap:12px' },
      h('h3', null, editId ? `Edit ${creds.find(c => c.id === editId)?.name ?? 'credential set'}` : 'New credential set'),
      h('div', { class: 'two' },
        field('Name', textInput(cf.name, v => { cf.name = v; }, { placeholder: 'snmpv3-branch', aria: 'Name' })),
        field('SNMP version', select(cf.version, [['v3', 'SNMPv3'], ['v2c', 'SNMPv2c']], v => { cf.version = v; redraw(); }, { aria: 'SNMP version' }))),
      v3 ? h('div', { class: 'col', style: 'gap:12px' },
        h('div', { class: 'two' }, field('User name', textInput(cf.username, v => { cf.username = v; }, { aria: 'SNMPv3 user name' })),
          field('Security level', select(cf.level, [['authPriv', 'authPriv (authentication and encryption)'], ['authNoPriv', 'authNoPriv (authentication only)'], ['noAuthNoPriv', 'noAuthNoPriv (none)']], v => { cf.level = v; redraw(); }, { aria: 'Security level' }))),
        hasAuth ? h('div', { class: 'two' }, field('Authentication protocol', select(cf.authProto, [['SHA-256', 'SHA-256'], ['SHA-384', 'SHA-384'], ['SHA-512', 'SHA-512'], ['SHA-1', 'SHA-1']], v => { cf.authProto = v; redraw(); }, { aria: 'Authentication protocol' })),
          field('Authentication password', textInput(cf.authKey, v => { cf.authKey = v; }, { type: 'password', autocomplete: 'new-password', placeholder: ph, aria: 'Authentication password' }))) : null,
        hasPriv ? h('div', { class: 'two' }, field('Privacy protocol', select(cf.privProto, [['AES-128', 'AES-128'], ['AES-256', 'AES-256'], ['DES', 'DES (legacy)']], v => { cf.privProto = v; redraw(); }, { aria: 'Privacy protocol' })),
          field('Privacy password', textInput(cf.privKey, v => { cf.privKey = v; }, { type: 'password', autocomplete: 'new-password', placeholder: ph, aria: 'Privacy password' }))) : null,
        field('Context name (optional)', textInput(cf.context, v => { cf.context = v; }, { aria: 'Context name' }))) :
        h('div', { class: 'col', style: 'gap:8px' }, field('Community string', textInput(cf.community, v => { cf.community = v; }, { type: 'password', autocomplete: 'new-password', placeholder: ph, aria: 'Community string' })),
          h('span', { style: 'color:var(--warn);font-size:12.5px' }, 'SNMPv2c sends the community string in clear text. Use it only for devices that cannot do SNMPv3.')),
      !editId ? toggle('Make this the default set', cf.def, () => { cf.def = !cf.def; redraw(); }) : null,
      h('div', { class: 'row' }, btn(cBusy ? 'Saving…' : 'Save credential set', { kind: 'primary', disabled: cBusy || !cf.name.trim(), onclick: () => void saveCred() }), editId ? btn('Cancel and start a new one', { kind: 'ghost', onclick: newCred }) : null, msg(editId || cMsg ? cMsg : '', cOk ? 'ok' : 'bad')),
      h('p', { class: 'muted' }, 'Secrets are encrypted on the server and never sent back to this page. Leave a secret blank when editing to keep the stored one. SNMPv3 passwords need at least 8 characters.'))));
}

export function renderUsers(): VNode { return !loaded ? spinner() : h('section', { 'aria-label': 'Roles and users' }, usersPanel()); }
export function renderCreds(): VNode { return !loaded ? spinner() : h('section', { 'aria-label': 'SNMP credentials' }, credsPanel()); }
