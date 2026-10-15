import { h, mount, type VNode } from './vdom.js';
import { get, post, ApiError } from './api.js';
import { session, parseHash, go, type Me, type View, type Status } from './state.js';
import { btn, chip, field, textInput, note } from './components.js';
import { refreshStatus } from './status.js';
import * as overview from './views/overview.js';
import * as explorer from './views/explorer.js';
import * as ports from './views/ports.js';
import * as links from './views/links.js';
import * as devices from './views/devices.js';
import * as storage from './views/storage.js';
import * as reports from './views/reports.js';
import * as admin from './views/admin.js';
import * as account from './views/account.js';
import { getTheme, setTheme, type ThemePref } from './theme.js';

interface ViewMod { enter(p: URLSearchParams): void; render(): VNode }
const VIEWS: Record<View, ViewMod> = { overview, explorer, ports, links, devices, storage, reports, admin, account };

const root = document.getElementById('app')!;
let booting = true;
let loginError = '';
let loginBusy = false;
let loginUser = '', loginPass = '';
let showLocal = false;
let expired = false;

let queued = false;
export function redraw(): void {
  if (queued) return;
  queued = true;
  queueMicrotask(() => { queued = false; paint(); });
}
session.redraw = redraw;
session.onExpired = () => { if (session.me) { session.me = null; expired = true; redraw(); } };

function paint(): void {
  let tree: VNode;
  if (booting) tree = h('div', { class: 'boot' }, 'Loading FlowScope…');
  else if (!session.me) tree = loginView();
  else if (session.me.mustChange) tree = account.forcedChange();
  else tree = shell();
  mount(root, tree);
}

/* ------------------------------------------------------------------ login */

async function doLogin(): Promise<void> {
  loginBusy = true; loginError = ''; redraw();
  try {
    const me = await post<Me>('/api/auth/login', { username: loginUser, password: loginPass });
    loginPass = '';
    await startSession(me);
  } catch (e) { loginError = (e as Error).message; }
  loginBusy = false; redraw();
}

function loginView(): VNode {
  const cfg = session.authCfg;
  const saml = cfg?.provider === 'saml';
  const form = h('form', { class: 'panel', onsubmit: (e: Event) => { e.preventDefault(); void doLogin(); } },
    h('h3', null, saml ? 'Local administrator sign-in' : 'Sign in'),
    field('User name', textInput(loginUser, v => { loginUser = v; }, { autocomplete: 'username', aria: 'User name' })),
    field('Password', textInput(loginPass, v => { loginPass = v; }, { type: 'password', autocomplete: 'current-password', aria: 'Password' })),
    loginError ? note(loginError, 'bad', true) : expired ? note('Your session ended. Sign in again.', 'warn', true) : null,
    btn(loginBusy ? 'Signing in…' : 'Sign in', { kind: 'primary', type: 'submit', disabled: loginBusy || !loginUser || !loginPass }),
    cfg && cfg.provider !== 'local' && !saml ? h('p', { class: 'hint' }, `Sign-in uses ${({ radius: 'RADIUS', ldap: 'LDAP', ad: 'Active Directory' } as Record<string, string>)[cfg.provider] ?? cfg.provider}. ${cfg.fallback ? 'If it cannot be reached, a local administrator can still sign in.' : ''}`) : null);
  return h('div', { class: 'loginpage' }, h('div', { class: 'logintheme' }, themeControl()), h('div', { class: 'login' },
    h('div', { class: 'brand' }, logo(), h('b', null, 'FlowScope'), chip('NetFlow / IPFIX collector')),
    cfg?.demo ? note('Demo mode: the data is simulated. Sign in as admin, netops or viewer. The passwords are printed where the server was started.', 'warn') : null,
    saml ? h('div', { class: 'panel' }, h('h3', null, 'Single sign-on'), h('p', { class: 'blurb' }, 'Your organisation signs you in with SAML.'), h('a', { class: 'btn primary', href: '/api/auth/saml/login' }, 'Sign in with SAML'),
      h('button', { class: 'btn ghost', type: 'button', onclick: () => { showLocal = !showLocal; redraw(); } }, showLocal ? 'Hide local sign-in' : 'Local administrator sign-in')) : null,
    !saml || showLocal ? form : null));
}

export function logo(): VNode {
  return h('svg', { 'aria-hidden': 'true', width: 28, height: 28, viewBox: '0 0 28 28', fill: 'none', style: 'stroke:var(--accent)', 'stroke-width': 2, 'stroke-linecap': 'round' },
    h('circle', { cx: 6, cy: 14, r: 3 }), h('circle', { cx: 22, cy: 6, r: 3 }), h('circle', { cx: 22, cy: 22, r: 3 }), h('path', { d: 'M9 12.5l10-5M9 15.5l10 5' }));
}

/* ------------------------------------------------------------------ shell */

function navItems(me: Me): { v: View; label: string }[] {
  const n: { v: View; label: string }[] = [{ v: 'overview', label: 'Overview' }, { v: 'explorer', label: 'Flow explorer' }, { v: 'ports', label: 'Flows by port' }, { v: 'links', label: 'Network health' }, { v: 'reports', label: 'Report builder' }];
  if (me.caps.storage) n.push({ v: 'storage', label: 'Storage and retention' });
  if (me.caps.devices) n.push({ v: 'devices', label: 'SNMP devices' });
  if (me.caps.admin) n.push({ v: 'admin', label: 'Admin' });
  return n;
}

export function themeControl(): VNode {
  const cur = getTheme();
  const opt = (p: ThemePref, label: string, tip: string) => h('button', { key: p, type: 'button', class: 'themebtn', 'aria-pressed': cur === p, title: tip, onclick: () => { setTheme(p); redraw(); } }, label);
  return h('div', { class: 'themectl', role: 'group', 'aria-label': 'Colour theme' },
    opt('system', 'System', 'Follow the operating system setting'), opt('light', 'Light', 'Light mode'), opt('dark', 'Dark', 'Dark mode'));
}

function initials(name: string): string {
  const p = name.split(/[\s._@-]+/).filter(Boolean);
  return ((p[0]?.[0] ?? '?') + (p.length > 1 ? p[p.length - 1][0] : '')).toUpperCase();
}

function userBlock(me: Me): VNode {
  return h('div', { class: 'userbar' },
    h('button', { class: 'userbtn', type: 'button', onclick: () => go('account'), title: 'Your account: password and API tokens', 'aria-label': `Signed in as ${me.username}, ${ROLE_LABEL[me.role]}. Open account.` },
      h('span', { class: 'avatar', 'aria-hidden': 'true' }, initials(me.username)),
      h('span', { class: 'uname' }, h('b', null, me.username), h('small', null, ROLE_LABEL[me.role] + (me.source && me.source !== 'local' ? ' · ' + me.source : '')))),
    h('button', { class: 'btn small signout', type: 'button', onclick: () => void signOut() }, 'Sign out'));
}

const ROLE_LABEL = { ro: 'Read only', snmp: 'SNMP admin', admin: 'Admin' } as const;

function header(me: Me): VNode {
  const st = session.status;
  const col = me.collect;
  const flowOn = st ? st.collect.flow : col.flow, snmpOn = st ? st.collect.snmp : col.snmp;
  const chipKind = flowOn && snmpOn ? 'ok' : !flowOn && !snmpOn ? 'bad' : 'warn';
  const chipText = flowOn && snmpOn ? 'Collecting' : !flowOn && !snmpOn ? 'Collection paused' : flowOn ? 'SNMP polling paused' : 'Flow collection paused';
  return h('header', { class: 'hdr' },
    h('div', { class: 'brand' }, logo(), h('b', null, 'FlowScope'), chip('NetFlow / IPFIX collector')),
    h('div', { class: 'htop' }, themeControl(), userBlock(me)),
    h('nav', { class: 'nav', 'aria-label': 'Views' }, navItems(me).map(i => h('button', { key: i.v, type: 'button', 'aria-current': session.view === i.v ? 'page' : undefined, onclick: () => go(i.v) }, i.label))),
    h('div', { class: 'hstatus' },
      chip(chipText, chipKind),
      me.demo || st?.demo ? chip('Sample data', 'warn', 'Simulated network: nothing here comes from your devices') : null,
      h('span', { class: 'mono' }, st ? `${st.flow.exporters} exporter${st.flow.exporters === 1 ? '' : 's'}` : ''),
      h('span', null, new Date().toLocaleString(undefined, { weekday: 'short', day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', timeZoneName: 'short' }))));
}

function banner(me: Me): VNode | null {
  const st = session.status; const col = st?.collect ?? me.collect;
  const parts: string[] = [];
  if (!col.flow) parts.push('Flow collection is off, so incoming NetFlow/IPFIX packets are being discarded');
  if (!col.snmp) parts.push('SNMP polling is off, so link and queue statistics are not being recorded');
  if (st?.storeNote) return h('div', { class: 'banner bad', role: 'status' }, st.storeNote);
  return parts.length ? h('div', { class: 'banner', role: 'status' }, parts.join('. ') + '. Stored data stays searchable, and there will be a gap in what is recorded.' + (me.role === 'admin' ? ' Turn collection back on under Admin, Data collection.' : ' A full admin can turn it back on.')) : null;
}

function shell(): VNode {
  const me = session.me!;
  const v = VIEWS[session.view];
  const allowed = session.view === 'account' || navItems(me).some(i => i.v === session.view);
  return h('div', { class: 'shell' }, header(me), banner(me), allowed ? v.render() : h('main', null, note('Your role does not include this page.', 'warn')));
}

async function signOut(): Promise<void> {
  try { await post('/api/auth/logout'); } catch { /* already signed out */ }
  session.me = null; session.csrf = ''; expired = false; location.hash = '#/overview'; redraw();
}

/* ------------------------------------------------------------------ start up */

async function startSession(me: Me): Promise<void> {
  session.me = me; session.csrf = me.csrf ?? ''; expired = false;
  if (me.mustChange) return;
  await Promise.all([refreshStatus(), get('/api/meta').then(m => { session.meta = m; }).catch(() => undefined)]);
  route();
}

function route(): void {
  const { view, params } = parseHash();
  session.view = view; session.params = params;
  const me = session.me;
  if (me && !me.mustChange && (view === 'account' || navItems(me).some(i => i.v === view))) VIEWS[view].enter(params);
  redraw();
}

async function boot(): Promise<void> {
  window.addEventListener('hashchange', route);
  try { session.authCfg = await get('/api/auth/config'); } catch { /* the login page still works */ }
  try { const me = await get<Me>('/api/auth/me'); await startSession(me); } catch { /* not signed in */ }
  booting = false; redraw();
  setInterval(() => { if (session.me && !session.me.mustChange) void refreshStatus(); }, 15_000);
}
void boot();
