import { h, type VNode } from '../vdom.js';
import { get, post } from '../api.js';
import { redraw } from '../state.js';
import { btn, chip, field, kv, msg, note, select, seg, spinner, textArea, textInput } from '../components.js';
import { stamp } from '../util.js';
import { download } from '../util.js';
import * as acme from './admin_acme.js';

interface Cert { slot: string; subject: string; issuer: string; sans: string[]; notBefore: number; notAfter: number; fingerprint: string; keyDesc: string; selfSigned: boolean; createdAt: number; chainLength: number; format: string; expired: boolean; daysLeft: number }
interface Csr { cn: string; sans: string[]; keyDesc: string; createdAt: number; csrPem: string }
interface Status { active: Cert | null; staged: Cert | null; previous: Cert | null; csr: Csr | null; tls: string; keyTypes: string[] }

let st: Status | null = null; let err = '';
let fmt: 'pem' | 'p12' = 'pem';
let certPem = '', keyPem = '', chainPem = '';
let p12: string = ''; let p12Name = ''; let p12Pw = '';
let certMsg = ''; let certOk = false; let warnings: string[] = []; let busy = false;
let csrCn = '', csrSan = '', csrKey = 'ecdsa-p256', csrO = '', csrOU = '', csrC = ''; let csrMsg = ''; let csrBusy = false;

const KEY_LABEL: Record<string, string> = { 'ecdsa-p256': 'ECDSA P-256 (recommended)', 'ecdsa-p384': 'ECDSA P-384', 'ecdsa-p521': 'ECDSA P-521', 'rsa-2048': 'RSA 2048', 'rsa-3072': 'RSA 3072', 'rsa-4096': 'RSA 4096', ed25519: 'Ed25519' };

export async function load(): Promise<void> {
  try { st = await get<Status>('/api/admin/cert'); err = ''; if (!csrCn) csrCn = location.hostname; } catch (e) { err = (e as Error).message; }
  redraw();
  void acme.load();
}

function readFile(f: File | undefined, as: 'text' | 'b64', done: (s: string, name: string) => void): void {
  if (!f) return;
  const r = new FileReader();
  r.onload = () => {
    if (as === 'text') done(String(r.result), f.name);
    else { const bytes = new Uint8Array(r.result as ArrayBuffer); let s = ''; for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000)); done(btoa(s), f.name); }
    redraw();
  };
  r.onerror = () => { certMsg = 'That file could not be read.'; certOk = false; redraw(); };
  if (as === 'text') r.readAsText(f); else r.readAsArrayBuffer(f);
}

function pemChecks(): { label: string; state: 'ok' | 'bad' | 'wait' }[] {
  const certOk_ = /-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----/.test(certPem);
  const keyOk = /-----BEGIN (RSA |EC )?PRIVATE KEY-----[\s\S]+-----END (RSA |EC )?PRIVATE KEY-----/.test(keyPem);
  const enc = /ENCRYPTED/.test(keyPem);
  return [
    { label: 'Certificate looks like PEM', state: !certPem.trim() ? 'wait' : certOk_ ? 'ok' : 'bad' },
    { label: 'Private key present and unencrypted (blank is fine after creating a signing request)', state: !keyPem.trim() ? 'wait' : enc ? 'bad' : keyOk ? 'ok' : 'bad' }
  ];
}

async function stage(): Promise<void> {
  busy = true; certMsg = 'Checking…'; certOk = false; warnings = []; redraw();
  try {
    const r = fmt === 'pem'
      ? await post<{ warnings: string[]; status: Status }>('/api/admin/cert/pem', { cert: certPem.trim() + (chainPem.trim() ? '\n' + chainPem.trim() : ''), key: keyPem.trim() })
      : await post<{ warnings: string[]; status: Status }>('/api/admin/cert/p12', { pfx: p12, passphrase: p12Pw });
    warnings = r.warnings; certOk = true; certMsg = 'Staged. Review it below, then apply it.';
    certPem = keyPem = chainPem = ''; p12 = ''; p12Name = ''; p12Pw = '';   // the key does not stay on this page
    await load();
  } catch (e) { certMsg = (e as Error).message; certOk = false; }
  busy = false; redraw();
}
async function act(path: string, ok: string): Promise<void> {
  busy = true; certMsg = ''; redraw();
  try { await post('/api/admin/cert/' + path); certOk = true; certMsg = ok; warnings = []; await load(); } catch (e) { certOk = false; certMsg = (e as Error).message; }
  busy = false; redraw();
}
async function makeCsr(): Promise<void> {
  csrBusy = true; csrMsg = ''; redraw();
  try { await post('/api/admin/cert/csr', { cn: csrCn.trim(), sans: csrSan, keyType: csrKey, o: csrO, ou: csrOU, c: csrC }); csrMsg = 'Signing request created.'; await load(); } catch (e) { csrMsg = (e as Error).message; }
  csrBusy = false; redraw();
}

function certCard(title: string, c: Cert | null, empty: string): VNode {
  if (!c) return h('div', { class: 'layer col', style: 'gap:6px' }, h('b', null, title), h('span', { class: 'dim' }, empty));
  return h('div', { class: 'layer col', style: 'gap:8px' },
    h('div', { class: 'row', style: 'justify-content:space-between' }, h('b', null, title),
      c.expired ? chip('Expired', 'bad') : c.daysLeft < 30 ? chip(`Expires in ${c.daysLeft} days`, 'warn') : chip(`Valid for ${c.daysLeft} days`, 'ok')),
    kv([['Subject', c.subject], ['Issuer', c.selfSigned ? 'Self-signed by FlowScope' : c.issuer], ['Names (SAN)', c.sans.join(', ') || '—'], ['Valid', `${stamp(c.notBefore).slice(0, 10)} to ${stamp(c.notAfter).slice(0, 10)}`], ['Key', c.keyDesc], ['SHA-256 fingerprint', c.fingerprint], ['Chain', `${c.chainLength} intermediate${c.chainLength === 1 ? '' : 's'}`]]));
}

export function render(): VNode {
  if (!st) return err ? note(err, 'bad', true) : spinner();
  const s = st;
  const checks = fmt === 'pem' ? pemChecks() : [{ label: 'Bundle file chosen', state: p12 ? 'ok' as const : 'wait' as const }, { label: 'Bundle password entered', state: p12Pw ? 'ok' as const : 'wait' as const }];
  const ready = fmt === 'pem' ? (checks[0].state === 'ok' && checks[1].state !== 'bad') : !!p12 && !!p12Pw;
  return h('section', { 'aria-label': 'HTTPS certificate', class: 'col', style: 'gap:16px' },
    s.tls === 'off' ? note('HTTPS is switched off for this installation (FLOWSCOPE_TLS=off), usually because a reverse proxy in front of it provides HTTPS. Certificates installed here are stored but not used.', 'warn') : null,
    acme.render(),
    h('div', { class: 'split' },
      h('div', { class: 'mainp', style: 'flex-basis:460px' }, certCard('Installed certificate', s.active, 'None installed'),
        s.staged ? h('div', { class: 'col', style: 'gap:10px' }, certCard('Staged, not yet in use', s.staged, ''),
          warnings.length ? note(warnings.join(' '), 'warn') : null,
          h('div', { class: 'row' }, btn('Apply and reload listeners', { kind: 'primary', disabled: busy, onclick: () => void act('apply', 'Applied. New connections use the new certificate; open pages keep working.') }), btn('Discard', { kind: 'ghost', disabled: busy, onclick: () => void act('discard', 'Discarded the staged certificate.') }))) : null,
        s.previous ? h('div', { class: 'col', style: 'gap:10px' }, certCard('Previous certificate (kept for roll back)', s.previous, ''), btn('Roll back to previous', { kind: 'warn', disabled: busy, onclick: () => void act('rollback', 'Rolled back to the previous certificate.') })) : null,
        h('p', { class: 'muted' }, 'The web interface, the REST API and the command line all use this certificate.')),
      h('div', { class: 'mainp', style: 'flex-basis:560px' }, h('div', { class: 'panel col', style: 'gap:14px' },
        h('h3', null, 'Install a certificate'),
        seg('Certificate file format', [{ id: 'pem', label: 'PEM (certificate and key)', on: fmt === 'pem' }, { id: 'p12', label: 'PKCS#12 bundle (.pfx, .p12)', on: fmt === 'p12' }], id => { fmt = id as 'pem' | 'p12'; certMsg = ''; redraw(); }),
        fmt === 'p12' ? h('div', { class: 'col', style: 'gap:10px' },
          h('label', { class: 'field' }, h('span', { class: 'flabel' }, 'Bundle with certificate, key and chain'), h('input', { class: 'input', style: 'padding-top:9px', type: 'file', accept: '.pfx,.p12', 'aria-label': 'Choose a PKCS#12 file', onchange: (e: Event) => readFile((e.target as HTMLInputElement).files?.[0], 'b64', (b, n) => { p12 = b; p12Name = n; }) })),
          p12Name ? h('span', { class: 'muted' }, 'Chosen: ' + p12Name) : null,
          field('Bundle password', textInput(p12Pw, v => { p12Pw = v; redraw(); }, { type: 'password', autocomplete: 'new-password', aria: 'Bundle password' }))) :
        h('div', { class: 'col', style: 'gap:10px' },
          field('Certificate (PEM)', textArea(certPem, v => { certPem = v; redraw(); }, { rows: 5, placeholder: '-----BEGIN CERTIFICATE-----', aria: 'Certificate PEM' })),
          h('input', { class: 'input', style: 'padding-top:9px', type: 'file', accept: '.pem,.crt,.cer', 'aria-label': 'Load certificate from a file', onchange: (e: Event) => readFile((e.target as HTMLInputElement).files?.[0], 'text', t => { certPem = t; }) }),
          field('Private key (PEM, unencrypted)', textArea(keyPem, v => { keyPem = v; redraw(); }, { rows: 4, placeholder: '-----BEGIN PRIVATE KEY-----', aria: 'Private key PEM' }), 'Accepted: RSA 2048 to 4096, ECDSA P-256, P-384 and P-521, and Ed25519, as PKCS#8 ("BEGIN PRIVATE KEY"), PKCS#1 ("BEGIN RSA PRIVATE KEY") or SEC1 ("BEGIN EC PRIVATE KEY"). Leave blank to use the key from a signing request created below.'),
          h('input', { class: 'input', style: 'padding-top:9px', type: 'file', accept: '.pem,.key', 'aria-label': 'Load private key from a file', onchange: (e: Event) => readFile((e.target as HTMLInputElement).files?.[0], 'text', t => { keyPem = t; }) }),
          field('Intermediate chain (PEM, optional)', textArea(chainPem, v => { chainPem = v; redraw(); }, { rows: 3, placeholder: '-----BEGIN CERTIFICATE----- (intermediates)', aria: 'Intermediate chain PEM' }))),
        h('div', { class: 'col', style: 'gap:4px' }, h('b', null, 'Checks in this page'), checks.map((c, i) => h('div', { key: i, class: 'row', style: 'justify-content:space-between' }, h('span', { class: 'muted' }, c.label), chip(c.state === 'ok' ? 'OK' : c.state === 'bad' ? 'Problem' : 'Waiting', c.state === 'ok' ? 'ok' : c.state === 'bad' ? 'bad' : 'default')))),
        h('div', { class: 'row' }, btn(busy ? 'Working…' : 'Stage certificate', { kind: 'primary', disabled: busy || !ready, onclick: () => void stage() }), msg(certMsg, certOk ? 'ok' : certMsg && certMsg !== 'Checking…' ? 'bad' : '')),
        h('p', { class: 'muted' }, 'On the server, the key is checked against the certificate, the chain order, the expiry date and the host name. The key is cleared from this page as soon as the certificate is staged.'))),
      h('div', { class: 'mainp', style: 'flex-basis:460px' }, h('div', { class: 'panel col', style: 'gap:12px' },
        h('h3', null, 'Or request a certificate from your CA'),
        field('Common name', textInput(csrCn, v => { csrCn = v; }, { aria: 'Common name' })),
        field('Subject alternative names (comma separated)', textInput(csrSan, v => { csrSan = v; }, { aria: 'Subject alternative names', placeholder: 'flowscope.example.com, 10.0.0.5' })),
        h('div', { class: 'three' }, field('Organisation (optional)', textInput(csrO, v => { csrO = v; }, { aria: 'Organisation' })), field('Unit (optional)', textInput(csrOU, v => { csrOU = v; }, { aria: 'Organisational unit' })), field('Country (2 letters)', textInput(csrC, v => { csrC = v; }, { aria: 'Country', maxlength: 2 }))),
        field('Key type', select(csrKey, s.keyTypes.map(k => [k, KEY_LABEL[k] ?? k] as [string, string]), v => { csrKey = v; redraw(); }, { aria: 'Key type' })),
        h('div', { class: 'row' }, btn(csrBusy ? 'Generating…' : 'Generate signing request', { kind: 'primary', disabled: csrBusy || !csrCn.trim(), onclick: () => void makeCsr() }), msg(csrMsg, csrMsg.startsWith('Signing') ? 'ok' : 'bad')),
        s.csr ? h('div', { class: 'col', style: 'gap:8px' }, h('b', null, `Signing request for ${s.csr.cn} (${s.csr.keyDesc})`), h('pre', { class: 'pre' }, s.csr.csrPem),
          h('div', { class: 'row' }, btn('Copy', { small: true, onclick: () => { void navigator.clipboard?.writeText(s.csr!.csrPem).then(() => { csrMsg = 'Copied.'; redraw(); }).catch(() => undefined); } }), btn('Download .csr', { small: true, onclick: () => download(`${s.csr!.cn.replace(/[^\w.-]/g, '_')}.csr`, 'application/pkcs10', s.csr!.csrPem) })),
          h('p', { class: 'muted' }, 'The server created the key pair and keeps the private key. Send the request to your CA, then paste the signed certificate on the left with the key box left blank.')) : null))));
}
