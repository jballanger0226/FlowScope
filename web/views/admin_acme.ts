import { h, type VNode } from '../vdom.js';
import { get, post, put } from '../api.js';
import { redraw } from '../state.js';
import { btn, chip, field, kv, msg, note, numberInput, select, seg, textArea, textInput, toggle } from '../components.js';
import { ago, stamp } from '../util.js';

interface Cfg {
  enabled: boolean; preset: 'letsencrypt' | 'letsencrypt-staging' | 'custom'; directoryUrl: string; email: string; tosAgreed: boolean; names: string[]; challenge: 'http-01' | 'dns-01'; httpPort: number;
  dnsProvider: 'manual' | 'cloudflare'; dnsWaitSec: number; cloudflareTokenSet: boolean; eabKid: string; eabHmacSet: boolean; caPem: string; keyType: string; autoRenew: boolean; renewDays: number;
}
interface State { lastAttemptAt: number | null; lastOkAt: number | null; lastError: string | null; nextAttemptAt: number | null; fingerprint: string | null; names: string[]; applied: boolean | null; note: string | null }
interface Status {
  config: Cfg; presets: { id: string; label: string }[]; keyTypes: string[]; state: State; running: boolean; steps: { at: number; text: string }[];
  pending: { at: number; records: { domain: string; name: string; value: string }[] } | null; account: { registered: boolean; directoryUrl: string | null };
  managed: boolean; renewAt: number | null; httpListener: { port: number; own: boolean };
}

let st: Status | null = null; let err = '';
/** The form. Secrets are typed here and sent only when filled in; the server never sends them back. */
let f: (Omit<Cfg, 'names'> & { names: string; cloudflareToken: string; eabHmac: string }) | null = null;
let dirty = false, busy = false, formMsg = '', formOk = false, copied = '';
let timer: ReturnType<typeof setTimeout> | null = null;

const KEY_LABEL: Record<string, string> = { 'ecdsa-p256': 'ECDSA P-256 (recommended)', 'ecdsa-p384': 'ECDSA P-384', 'rsa-2048': 'RSA 2048', 'rsa-3072': 'RSA 3072', 'rsa-4096': 'RSA 4096' };
const edit = (fn: () => void): void => { fn(); dirty = true; formMsg = ''; redraw(); };

function fill(s: Status): void {
  const c = s.config;
  f = { ...c, names: c.names.length ? c.names.join(', ') : '', cloudflareToken: '', eabHmac: '' };
  dirty = false;
}

export async function load(): Promise<void> {
  try { const s = await get<Status>('/api/admin/acme'); st = s; err = ''; if (!f || !dirty) fill(s); } catch (e) { err = (e as Error).message; }
  redraw();
  schedule();
}

/** While a request is running the CA is being waited for, so the page follows along every two seconds, and stops when the person leaves the tab. */
function schedule(): void {
  if (timer) { clearTimeout(timer); timer = null; }
  if (st?.running && !st.pending && location.hash.startsWith('#/admin')) timer = setTimeout(() => void load(), 2000);
}

async function save(): Promise<boolean> {
  if (!f) return false;
  busy = true; formMsg = 'Saving…'; formOk = false; redraw();
  try {
    st = await put<Status>('/api/admin/acme', {
      enabled: f.enabled, preset: f.preset, directoryUrl: f.directoryUrl, email: f.email, tosAgreed: f.tosAgreed, names: f.names, challenge: f.challenge, httpPort: f.httpPort,
      dnsProvider: f.dnsProvider, dnsWaitSec: f.dnsWaitSec, cloudflareToken: f.cloudflareToken || undefined, eabKid: f.eabKid, eabHmac: f.eabHmac || undefined, caPem: f.caPem, keyType: f.keyType, autoRenew: f.autoRenew, renewDays: f.renewDays
    });
    fill(st); formOk = true; formMsg = 'Saved.'; busy = false; redraw(); schedule(); return true;
  } catch (e) { formOk = false; formMsg = (e as Error).message; busy = false; redraw(); return false; }
}

async function act(path: string, ok: string): Promise<void> {
  busy = true; formMsg = ''; redraw();
  try { st = await post<Status>('/api/admin/acme/' + path); formOk = true; formMsg = ok; if (!dirty && st) fill(st); } catch (e) { formOk = false; formMsg = (e as Error).message; await load(); }
  busy = false; redraw(); schedule();
}
async function saveAndRequest(): Promise<void> { if (await save()) await act('issue', 'The request is running. This page shows its progress.'); }

function copy(text: string, key: string): void {
  void navigator.clipboard?.writeText(text).then(() => { copied = key; redraw(); setTimeout(() => { if (copied === key) { copied = ''; redraw(); } }, 1500); }).catch(() => undefined);
}

function statusLine(s: Status): VNode {
  const c = s.config, t = s.state;
  const chips: VNode[] = [];
  if (s.running && !s.pending) chips.push(chip('Requesting a certificate…', 'info'));
  else if (s.pending) chips.push(chip('Waiting for DNS records', 'warn'));
  else if (s.managed) chips.push(chip('Certificate from the CA is in use', 'ok'));
  else if (c.enabled) chips.push(chip('Turned on, no certificate from the CA in use yet', 'warn'));
  else chips.push(chip('Off', 'default'));
  const rows: [string, string][] = [];
  if (s.managed && s.renewAt) rows.push(['Renews', `${stamp(s.renewAt).slice(0, 10)} (${s.renewAt > Date.now() ? 'in ' + Math.max(0, Math.round((s.renewAt - Date.now()) / 86400_000)) + ' days' : 'due now'})${c.autoRenew ? '' : ', automatic renewal is off'}`]);
  if (t.lastOkAt) rows.push(['Last issued', `${stamp(t.lastOkAt)} (${ago(t.lastOkAt)})`]);
  if (t.lastAttemptAt && t.lastAttemptAt !== t.lastOkAt) rows.push(['Last attempt', `${stamp(t.lastAttemptAt)} (${ago(t.lastAttemptAt)})`]);
  if (t.nextAttemptAt && t.nextAttemptAt > Date.now() && c.enabled) rows.push(['Next automatic attempt', stamp(t.nextAttemptAt)]);
  if (s.account.registered) rows.push(['CA account', s.account.directoryUrl ?? 'registered']);
  return h('div', { class: 'col', style: 'gap:10px' },
    h('div', { class: 'row' }, ...chips),
    t.lastError && !s.running ? note('The last request failed: ' + t.lastError, 'bad', true) : null,
    t.note && !s.running ? note(t.note, 'warn') : null,
    rows.length ? kv(rows) : null,
    s.steps.length && !s.pending ? h('ol', { class: 'steps', 'aria-live': 'polite', 'aria-label': 'Progress of the request', style: 'margin:0;padding-left:20px;display:flex;flex-direction:column;gap:2px' }, s.steps.map((x, i) => h('li', { key: i, class: i === s.steps.length - 1 && s.running ? '' : 'muted' }, x.text))) : null);
}

function pendingPanel(s: Status): VNode | null {
  if (!s.pending) return null;
  return h('div', { class: 'layer col', style: 'gap:10px' },
    h('b', null, 'Add these TXT records to your DNS, then choose Continue'),
    h('p', { class: 'muted' }, 'The CA checks for them when you continue. DNS changes can take a few minutes to spread; if the check fails, start again and wait longer before continuing. A request that uses manual records cannot renew by itself, because a person has to add new records each time. A DNS provider with an API avoids that.'),
    s.pending.records.map((r, i) => h('div', { key: i, class: 'col', style: 'gap:4px' },
      h('span', { class: 'muted' }, `For ${r.domain}`),
      h('div', { class: 'row', style: 'gap:6px' }, h('span', { class: 'dim', style: 'min-width:48px' }, 'Name'), h('code', { class: 'mono' }, r.name), btn(copied === `n${i}` ? 'Copied' : 'Copy', { small: true, onclick: () => copy(r.name, `n${i}`) })),
      h('div', { class: 'row', style: 'gap:6px' }, h('span', { class: 'dim', style: 'min-width:48px' }, 'Type'), h('code', { class: 'mono' }, 'TXT')),
      h('div', { class: 'row', style: 'gap:6px' }, h('span', { class: 'dim', style: 'min-width:48px' }, 'Value'), h('code', { class: 'mono' }, r.value), btn(copied === `v${i}` ? 'Copied' : 'Copy', { small: true, onclick: () => copy(r.value, `v${i}`) })))),
    h('div', { class: 'row' }, btn('Continue', { kind: 'primary', disabled: busy, onclick: () => void act('continue', 'The CA is checking the records. This page shows its progress.') }), btn('Cancel', { kind: 'ghost', disabled: busy, onclick: () => void act('cancel', 'Cancelled.') })));
}

export function render(): VNode {
  if (!st || !f) return err ? note(err, 'bad', true) : h('span');
  const s = st, c = f, custom = c.preset === 'custom', locked = busy || s.running;
  const caChoices: [string, string][] = [...s.presets.map(p => [p.id, p.label] as [string, string]), ['custom', 'Internal or other ACME CA (step-ca, Vault, ZeroSSL, Google and others)']];
  return h('section', { 'aria-label': 'Automatic certificate (ACME)', class: 'panel col', style: 'gap:16px' },
    h('div', { class: 'col', style: 'gap:4px' }, h('h3', null, 'Automatic certificate (ACME)'),
      h('p', { class: 'muted' }, 'Let FlowScope get this server\'s HTTPS certificate from a certificate authority and renew it before it expires. Use Let\'s Encrypt for a public domain name, or your own internal ACME CA for internal names. The certificate is installed like any other, so the previous one is kept for roll back.')),
    statusLine(s), pendingPanel(s),
    h('div', { class: 'split' },
      h('div', { class: 'mainp col', style: 'gap:12px;flex-basis:420px' },
        h('b', null, '1. Where the certificate comes from'),
        field('Certificate authority', select(c.preset, caChoices, v => edit(() => { c.preset = v as Cfg['preset']; if (c.preset === 'custom' && c.tosAgreed === false) c.tosAgreed = false; }), { aria: 'Certificate authority' })),
        custom ? h('div', { class: 'col', style: 'gap:12px' },
          field('ACME directory address', textInput(c.directoryUrl, v => edit(() => { c.directoryUrl = v; }), { placeholder: 'https://ca.example.com/acme/acme/directory', aria: 'ACME directory address', mono: true }), 'For step-ca this is https://<ca>/acme/<provisioner>/directory. It must be https.'),
          field('The CA\'s root certificate (PEM, only if this server does not already trust it)', textArea(c.caPem, v => edit(() => { c.caPem = v; }), { rows: 4, placeholder: '-----BEGIN CERTIFICATE-----', aria: 'CA root certificate PEM' }), 'Used only to reach the CA itself. It is not installed anywhere else.'),
          h('div', { class: 'two' }, field('External account key id (if the CA requires it)', textInput(c.eabKid, v => edit(() => { c.eabKid = v; }), { aria: 'External account key id', mono: true })),
            field(`External account HMAC key${s.config.eabHmacSet ? ' (saved)' : ''}`, textInput(c.eabHmac, v => edit(() => { c.eabHmac = v; }), { type: 'password', autocomplete: 'new-password', aria: 'External account HMAC key', placeholder: s.config.eabHmacSet ? 'Leave blank to keep the saved key' : '' })))) : null,
        !custom ? note(c.preset === 'letsencrypt-staging' ? 'The staging CA is for testing. Its certificates are not trusted by browsers, so FlowScope stages the certificate for you to look at and never applies it.' : 'Let\'s Encrypt only issues for public domain names you own. It cannot issue for names such as .local or .lan, or for IP addresses.', 'info') : null,
        field('Email address for the CA (optional)', textInput(c.email, v => edit(() => { c.email = v; }), { placeholder: 'ops@example.com', aria: 'Email address', autocomplete: 'email' }), 'Used for expiry warnings and problems with the account.'),
        !custom ? toggle('I accept the CA\'s terms of service', c.tosAgreed, () => edit(() => { c.tosAgreed = !c.tosAgreed; }), { onText: 'Accepted', offText: 'Not accepted' }) : null,
        field('Names and IP addresses for the certificate', textInput(c.names, v => edit(() => { c.names = v; }), { placeholder: location.hostname || 'flowscope.example.com', aria: 'Names for the certificate', mono: true }), 'Separate several with commas. The first is the main name. A wildcard such as *.example.com needs DNS-01. An IP address needs HTTP-01 and an internal CA.')),
      h('div', { class: 'mainp col', style: 'gap:12px;flex-basis:420px' },
        h('b', null, '2. How the CA checks you own the name'),
        seg('Verification method', [{ id: 'http-01', label: 'HTTP-01', on: c.challenge === 'http-01' }, { id: 'dns-01', label: 'DNS-01', on: c.challenge === 'dns-01' }], id => edit(() => { c.challenge = id as Cfg['challenge']; })),
        c.challenge === 'http-01' ? h('div', { class: 'col', style: 'gap:10px' },
          h('p', { class: 'muted' }, 'The CA connects to this server over plain HTTP and fetches a small file. Best for an internal CA, where the CA can reach this server on your network. A public CA must be able to reach this server from the internet, so it suits a server that is open to the internet and not an internal one.'),
          field('HTTP port the CA connects to', numberInput(c.httpPort, v => edit(() => { c.httpPort = Number(v); }), { min: 1, max: 65535, aria: 'HTTP port', width: '120px' }),
            s.httpListener.own ? `The console already listens on this port, so it answers the check.` : `FlowScope opens this port only while the check runs. Port 80 needs the right to use low ports; if the CA reaches this server through port forwarding to another port, enter that port.`)) :
        h('div', { class: 'col', style: 'gap:10px' },
          h('p', { class: 'muted' }, 'The CA looks for a TXT record under _acme-challenge for each name. This works for a server that cannot be reached from the internet, and is the only way to get a wildcard certificate. For a public CA it needs a public domain whose DNS you control.'),
          field('DNS', select(c.dnsProvider, [['manual', 'I add the TXT records myself (cannot renew by itself)'], ['cloudflare', 'Cloudflare (added and removed automatically)']], v => edit(() => { c.dnsProvider = v as Cfg['dnsProvider']; }), { aria: 'DNS provider' })),
          c.dnsProvider === 'cloudflare' ? h('div', { class: 'col', style: 'gap:10px' },
            field(`Cloudflare API token${s.config.cloudflareTokenSet ? ' (saved)' : ''}`, textInput(c.cloudflareToken, v => edit(() => { c.cloudflareToken = v; }), { type: 'password', autocomplete: 'new-password', aria: 'Cloudflare API token', placeholder: s.config.cloudflareTokenSet ? 'Leave blank to keep the saved token' : '' }), 'Create a token with the permission Zone, DNS, Edit for just the zone that holds the name.'),
            field('Seconds to wait for DNS to update', numberInput(c.dnsWaitSec, v => edit(() => { c.dnsWaitSec = Number(v); }), { min: 0, max: 600, aria: 'Seconds to wait', width: '120px' }))) : null),
        h('details', { class: 'col', style: 'gap:10px' }, h('summary', { style: 'cursor:pointer;font-weight:600' }, 'More options'),
          h('div', { class: 'col', style: 'gap:10px;padding-top:10px' },
            field('Key type of the new certificate', select(c.keyType, s.keyTypes.map(k => [k, KEY_LABEL[k] ?? k] as [string, string]), v => edit(() => { c.keyType = v; }), { aria: 'Key type' })),
            toggle('Renew automatically', c.autoRenew, () => edit(() => { c.autoRenew = !c.autoRenew; })),
            field('Start renewing this many days before expiry', numberInput(c.renewDays, v => edit(() => { c.renewDays = Number(v); }), { min: 1, max: 60, aria: 'Days before expiry', width: '120px' }), 'A certificate that lasts less than three times this long is renewed with a third of its life left instead.'))))),
    h('div', { class: 'row', style: 'gap:12px' },
      toggle('Manage the HTTPS certificate with ACME', c.enabled, () => edit(() => { c.enabled = !c.enabled; }), { onText: 'On', offText: 'Off' }),
      btn(busy && !s.running ? 'Working…' : 'Save', { kind: 'primary', disabled: locked || !dirty, onclick: () => void save() }),
      btn('Save and request a certificate now', { disabled: locked || !!s.pending, onclick: () => void saveAndRequest() }),
      msg(formMsg, formOk ? 'ok' : formMsg && formMsg !== 'Saving…' ? 'bad' : '')),
    c.enabled ? h('p', { class: 'muted' }, c.autoRenew ? 'FlowScope checks every few minutes. It requests a certificate when none from the CA is in use, when the names change, and again before the certificate expires. If a request fails it waits six hours before trying again, and writes the reason to the Application logs.' : 'Automatic renewal is off. Use the button above to request a certificate.') : null);
}
