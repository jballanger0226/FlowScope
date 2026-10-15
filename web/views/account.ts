import { h, type VNode } from '../vdom.js';
import { get, post, del } from '../api.js';
import { session, redraw, go } from '../state.js';
import { btn, empty, field, heading, msg, note, select, textInput } from '../components.js';
import { ago, stamp } from '../util.js';

interface Token { id: number; username: string; name: string; role: string; createdAt: number; lastUsed: number | null; expiresAt: number | null }

let cur = '', next = '', again = ''; let pwMsg = ''; let pwOk = false; let pwBusy = false;
let tokens: Token[] = []; let tName = ''; let tDays = '90'; let tMsg = ''; let tNew = ''; let tBusy = false;

export function enter(_p: URLSearchParams): void { cur = next = again = ''; pwMsg = ''; tNew = ''; tMsg = ''; void loadTokens(); }

async function loadTokens(): Promise<void> {
  try { tokens = (await get<{ tokens: Token[] }>('/api/auth/tokens')).tokens; } catch { tokens = []; }
  redraw();
}

async function changePw(forced: boolean): Promise<void> {
  if (next !== again) { pwOk = false; pwMsg = 'The two new passwords are different.'; redraw(); return; }
  pwBusy = true; pwMsg = ''; redraw();
  try {
    const r = await post<{ csrf: string }>('/api/auth/password', { current: cur, next });
    session.csrf = r.csrf;
    cur = next = again = ''; pwOk = true; pwMsg = 'Password changed.';
    if (forced && session.me) {
      session.me.mustChange = false;
      const m = await get('/api/auth/me').catch(() => null);
      if (m) { session.me = m; session.csrf = m.csrf ?? r.csrf; }
      location.hash = '#/overview'; location.reload();
      return;
    }
  } catch (e) { pwOk = false; pwMsg = (e as Error).message; }
  pwBusy = false; redraw();
}

function pwForm(forced: boolean): VNode {
  const minLen = 12;
  const external = session.me && session.me.source !== 'local';
  if (external) return h('div', { class: 'panel col' }, h('h3', null, 'Password'), h('p', { class: 'muted' }, `Your password is managed by ${session.me!.source}. Change it there.`));
  return h('form', { class: 'panel col', style: 'gap:12px', onsubmit: (e: Event) => { e.preventDefault(); void changePw(forced); } },
    h('h3', null, forced ? 'Choose a new password' : 'Change password'),
    forced ? note('You are signing in with a temporary or reset password. Choose your own before continuing.', 'warn') : null,
    field('Current password', textInput(cur, v => { cur = v; }, { type: 'password', autocomplete: 'current-password', aria: 'Current password' })),
    field('New password', textInput(next, v => { next = v; }, { type: 'password', autocomplete: 'new-password', aria: 'New password' }), `At least ${minLen} characters, not containing your user name, and not a common password.`),
    field('New password again', textInput(again, v => { again = v; }, { type: 'password', autocomplete: 'new-password', aria: 'New password again' })),
    h('div', { class: 'row' }, btn(pwBusy ? 'Saving…' : 'Change password', { kind: 'primary', type: 'submit', disabled: pwBusy || !cur || !next || !again }), msg(pwMsg, pwOk ? 'ok' : 'bad')));
}

export function forcedChange(): VNode {
  return h('div', { class: 'login' },
    h('div', { class: 'brand' }, h('b', null, 'FlowScope')),
    pwForm(true),
    h('button', { class: 'btn ghost', type: 'button', onclick: async () => { try { await post('/api/auth/logout'); } catch { /* ignore */ } location.reload(); } }, 'Sign out'));
}

async function createToken(): Promise<void> {
  tBusy = true; tMsg = ''; tNew = ''; redraw();
  try {
    const r = await post<{ token: string }>('/api/auth/tokens', { name: tName.trim(), days: Number(tDays) });
    tNew = r.token; tName = ''; await loadTokens();
  } catch (e) { tMsg = (e as Error).message; }
  tBusy = false; redraw();
}
async function revoke(t: Token): Promise<void> {
  try { await del('/api/auth/tokens/' + t.id); tMsg = `Revoked "${t.name}".`; } catch (e) { tMsg = (e as Error).message; }
  await loadTokens();
}

export function render(): VNode {
  const me = session.me!;
  return h('main', null,
    heading('Account', me.username, `Signed in as ${me.role === 'admin' ? 'a full administrator' : me.role === 'snmp' ? 'an SNMP device administrator' : 'a read-only user'}, through ${me.source === 'local' ? 'a local account' : me.source}.`),
    h('div', { class: 'split' },
      h('div', { class: 'mainp', style: 'flex-basis:420px' }, pwForm(false)),
      h('div', { class: 'mainp', style: 'flex-basis:560px' }, h('section', { class: 'panel col', style: 'gap:12px', 'aria-label': 'API tokens' },
        h('h3', null, 'API tokens'),
        h('p', { class: 'muted' }, 'Tokens let scripts call the REST API with the header Authorization: Bearer <token>. A token carries your role or less.'),
        h('div', { class: 'row end' },
          field('Name', textInput(tName, v => { tName = v; }, { placeholder: 'grafana-readonly', aria: 'Token name', onenter: () => void createToken() })),
          field('Valid for', select(tDays, [['30', '30 days'], ['90', '90 days'], ['365', '1 year'], ...(me.role === 'admin' ? [['0', 'No expiry'] as [string, string]] : [])], v => { tDays = v; redraw(); }, { aria: 'Token lifetime' })),
          btn(tBusy ? 'Creating…' : 'Create token', { kind: 'primary', disabled: tBusy || !tName.trim(), onclick: () => void createToken() })),
        tNew ? h('div', { class: 'note ok col', style: 'gap:6px' }, h('b', null, 'Copy this token now. It is shown only once.'), h('code', { class: 'code', style: 'word-break:break-all;user-select:all' }, tNew)) : null,
        msg(tMsg, tMsg.startsWith('Revoked') ? 'ok' : 'bad'),
        tokens.length ? h('div', { class: 'tbl' }, h('div', { class: 'inner', style: '--cols:1.2fr 80px 130px 110px 90px;--w:620px' },
          h('div', { class: 'tr head' }, ...['Name', 'Role', 'Created', 'Last used', ''].map(t => h('span', null, t))),
          tokens.map(t => h('div', { key: t.id, class: 'tr' }, h('span', null, t.name, me.role === 'admin' && t.username !== me.username ? h('span', { class: 'dim' }, ' · ' + t.username) : null), h('span', { class: 'muted' }, t.role), h('span', { class: 'mono', style: 'font-size:12px' }, stamp(t.createdAt).slice(0, 10)), h('span', { class: 'muted' }, ago(t.lastUsed)), btn('Revoke', { small: true, kind: 'danger', onclick: () => void revoke(t) }))))) : empty('You have no API tokens.')))),
    btn('Back to the overview', { kind: 'ghost', onclick: () => go('overview') }));
}
