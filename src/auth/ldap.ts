import net from 'node:net';
import tls from 'node:tls';
import * as d from '../tls/der.js';

/** A small LDAPv3 client: simple bind and search. Enough to log users in and read their groups. */

export class LdapError extends Error { constructor(m: string, readonly kind: 'connect' | 'auth' | 'protocol' | 'config' = 'protocol') { super(m); } }

const APP = (n: number, constructed = true) => (constructed ? 0x60 : 0x40) | n;

/** Escapes a value for use inside a filter (RFC 4515). */
export function escapeFilter(v: string): string {
  return v.replace(/[\\*()\0]/g, c => '\\' + c.charCodeAt(0).toString(16).padStart(2, '0'));
}
export function escapeDn(v: string): string {
  return v.replace(/[,+"\\<>;=]/g, c => '\\' + c).replace(/^([ #])/, '\\$1').replace(/ $/, '\\ ');
}

/* ---- filter parser: (&(a=b)(|(c=d)(e=*))(!(f=g))(member:1.2.3:=x)) ---- */
export function encodeFilter(f: string): d.Der {
  let i = 0;
  const peek = () => f[i];
  function expect(c: string) { if (f[i] !== c) throw new LdapError(`Invalid LDAP filter: expected "${c}" at position ${i} in ${f}`, 'config'); i++; }
  function unescape(s: string): Buffer {
    const out: number[] = [];
    for (let k = 0; k < s.length; k++) {
      if (s[k] === '\\' && /^[0-9a-fA-F]{2}$/.test(s.slice(k + 1, k + 3))) { out.push(parseInt(s.slice(k + 1, k + 3), 16)); k += 2; }
      else out.push(...Buffer.from(s[k], 'utf8'));
    }
    return Buffer.from(out);
  }
  function item(): d.Der {
    expect('(');
    let r: d.Der;
    const c = peek();
    if (c === '&' || c === '|') {
      i++; const kids: d.Der[] = [];
      while (peek() === '(') kids.push(item());
      r = d.tlv(c === '&' ? 0xa0 : 0xa1, ...kids);
    } else if (c === '!') { i++; r = d.tlv(0xa2, item()); }
    else {
      let j = i; let depth = 0;
      while (j < f.length && !(f[j] === ')' && depth === 0)) { if (f[j] === '(') depth++; if (f[j] === ')') depth--; j++; }
      const expr = f.slice(i, j); i = j;
      const m = /^([^=:~<>]*)(?::(dn))?(?::([0-9.]+))?:=(.*)$/s.exec(expr);
      if (m && (m[3] || m[2] || m[1].includes(':') || expr.includes(':='))) {
        const [, attr, dn, rule, val] = m;
        const parts: d.Der[] = [];
        if (rule) parts.push(d.tlv(0x81, Buffer.from(rule)));
        if (attr) parts.push(d.tlv(0x82, Buffer.from(attr)));
        parts.push(d.tlv(0x83, unescape(val)));
        if (dn) parts.push(d.tlv(0x84, Buffer.from([0xff])));
        r = d.tlv(0xa9, ...parts);
      } else {
        const eq = expr.indexOf('=');
        if (eq < 1) throw new LdapError(`Invalid LDAP filter item "${expr}"`, 'config');
        const attr = expr.slice(0, eq), val = expr.slice(eq + 1);
        if (val === '*') r = d.tlv(0x87, Buffer.from(attr));
        else if (/(^|[^\\])\*/.test(val)) {
          const segs = val.split(/(?<!\\)\*/);
          const subs: d.Der[] = [];
          if (segs[0]) subs.push(d.tlv(0x80, unescape(segs[0])));
          for (let k = 1; k < segs.length - 1; k++) if (segs[k]) subs.push(d.tlv(0x81, unescape(segs[k])));
          if (segs.length > 1 && segs[segs.length - 1]) subs.push(d.tlv(0x82, unescape(segs[segs.length - 1])));
          r = d.tlv(0xa4, d.octets(Buffer.from(attr)), d.seq(...subs));
        } else r = d.tlv(0xa3, d.octets(Buffer.from(attr)), d.octets(unescape(val)));
      }
    }
    expect(')');
    return r;
  }
  const out = item();
  if (i !== f.length) throw new LdapError('Invalid LDAP filter: trailing text', 'config');
  return out;
}

export interface LdapEntry { dn: string; attrs: Map<string, string[]> }
export interface LdapOpts { host: string; port: number; tls: boolean; startTls?: boolean; verify: boolean; timeoutMs: number }

export class LdapConn {
  private sock!: net.Socket;
  private buf = Buffer.alloc(0);
  private waiters: (() => void)[] = [];
  private msgs: Buffer[] = [];
  private id = 1;
  private err: Error | null = null;

  static async open(o: LdapOpts): Promise<LdapConn> {
    const c = new LdapConn();
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => { c.sock?.destroy(); reject(new LdapError(`Could not connect to ${o.host}:${o.port} (timeout)`, 'connect')); }, o.timeoutMs);
      const ok = () => { clearTimeout(timer); resolve(); };
      const fail = (e: Error) => { clearTimeout(timer); reject(new LdapError(`Could not connect to ${o.host}:${o.port}: ${e.message}`, 'connect')); };
      if (o.tls) c.sock = tls.connect({ host: o.host, port: o.port, rejectUnauthorized: o.verify, servername: net.isIP(o.host) ? undefined : o.host }, ok);
      else c.sock = net.connect({ host: o.host, port: o.port }, ok);
      c.sock.once('error', fail);
    });
    c.sock.removeAllListeners('error');
    c.sock.on('error', e => { c.err = e; c.wake(); });
    c.sock.on('close', () => { c.err ??= new LdapError('The directory closed the connection', 'connect'); c.wake(); });
    c.sock.on('data', (b: Buffer) => { c.buf = Buffer.concat([c.buf, b]); c.parse(); c.wake(); });
    return c;
  }

  private wake(): void { for (const w of this.waiters.splice(0)) w(); }

  private parse(): void {
    for (;;) {
      if (this.buf.length < 2) return;
      let l = this.buf[1], hdr = 2;
      if (l & 0x80) { const n = l & 0x7f; if (this.buf.length < 2 + n) return; l = 0; for (let k = 0; k < n; k++) l = l * 256 + this.buf[2 + k]; hdr = 2 + n; }
      if (this.buf.length < hdr + l) return;
      this.msgs.push(this.buf.subarray(0, hdr + l));
      this.buf = this.buf.subarray(hdr + l);
    }
  }

  private async next(timeoutMs: number): Promise<Buffer> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const m = this.msgs.shift();
      if (m) return m;
      if (this.err) throw this.err instanceof LdapError ? this.err : new LdapError(this.err.message, 'connect');
      const left = deadline - Date.now();
      if (left <= 0) throw new LdapError('The directory did not answer in time', 'connect');
      await new Promise<void>(res => {
        const t = setTimeout(() => { const i = this.waiters.indexOf(done); if (i >= 0) this.waiters.splice(i, 1); res(); }, left);
        const done = () => { clearTimeout(t); res(); };
        this.waiters.push(done);
      });
    }
  }

  private send(op: d.Der): number {
    const id = this.id++;
    this.sock.write(d.seq(d.int(id), op));
    return id;
  }

  private static result(op: d.Node): { code: number; matched: string; diag: string } {
    const kids = d.children(op);
    return { code: d.body(kids[0])[0] ?? 0, matched: d.body(kids[1]).toString('utf8'), diag: d.body(kids[2]).toString('utf8') };
  }

  /** Simple bind. An empty password is refused here because directories treat it as an anonymous bind and report success. */
  async bind(dn: string, password: string, timeoutMs = 5000): Promise<void> {
    if (dn && !password) throw new LdapError('Empty password', 'auth');
    this.send(d.tlv(APP(0), d.int(3), d.octets(Buffer.from(dn, 'utf8')), d.tlv(0x80, Buffer.from(password, 'utf8'))));
    const m = d.read(await this.next(timeoutMs));
    const op = d.children(m)[1];
    if (op.tag !== APP(1)) throw new LdapError('Unexpected reply to bind');
    const r = LdapConn.result(op);
    if (r.code !== 0) throw new LdapError(r.code === 49 ? 'Invalid credentials' : `Bind failed (${r.code}) ${r.diag}`, r.code === 49 || r.code === 53 ? 'auth' : 'protocol');
  }

  async search(base: string, filter: string, attrs: string[], o: { scope?: 0 | 1 | 2; sizeLimit?: number; timeoutMs?: number } = {}): Promise<LdapEntry[]> {
    const timeoutMs = o.timeoutMs ?? 8000;
    this.send(d.tlv(APP(3),
      d.octets(Buffer.from(base, 'utf8')), d.tlv(0x0a, Buffer.from([o.scope ?? 2])), d.tlv(0x0a, Buffer.from([0])),
      d.int(o.sizeLimit ?? 1000), d.int(Math.ceil(timeoutMs / 1000)), d.bool(false), encodeFilter(filter), d.seq(...attrs.map(a => d.octets(Buffer.from(a))))));
    const out: LdapEntry[] = [];
    for (;;) {
      const m = d.read(await this.next(timeoutMs));
      const op = d.children(m)[1];
      if (op.tag === APP(4)) {
        const [dn, al] = d.children(op);
        const map = new Map<string, string[]>();
        for (const a of d.children(al)) {
          const [t, vs] = d.children(a);
          map.set(d.body(t).toString('utf8').toLowerCase(), d.children(vs).map(v => d.body(v).toString('utf8')));
        }
        out.push({ dn: d.body(dn).toString('utf8'), attrs: map });
      } else if (op.tag === APP(5)) {
        const r = LdapConn.result(op);
        if (r.code !== 0 && r.code !== 4 /* size limit */) throw new LdapError(`Search failed (${r.code}) ${r.diag}`);
        return out;
      }
      // search references (APP 19) are ignored
    }
  }

  close(): void {
    try { this.sock.write(Buffer.from([0x30, 0x05, 0x02, 0x01, this.id, 0x42, 0x00])); } catch { /* ignore */ }
    this.sock.destroy();
  }
}

export interface DirectoryLogin { ok: boolean; reason?: string; dn?: string; groups: string[]; displayName?: string; unreachable?: boolean }

export interface LdapSettings { url: string; bindDn: string; bindPw: string; baseDn: string; filter: string; groupBase: string; verify: boolean }

function parseUrl(url: string): { host: string; port: number; tls: boolean } {
  const m = /^(ldaps?):\/\/(\[[^\]]+\]|[^:/]+)(?::(\d+))?\/?$/i.exec(url.trim());
  if (!m) throw new LdapError('The directory URL must look like ldaps://dc1.example.com or ldap://10.0.0.5:389', 'config');
  const secure = m[1].toLowerCase() === 'ldaps';
  return { host: m[2].replace(/^\[|\]$/g, ''), port: m[3] ? Number(m[3]) : secure ? 636 : 389, tls: secure };
}

const cnOf = (dn: string) => { const m = /^cn=((?:\\.|[^,])+)/i.exec(dn); return m ? m[1].replace(/\\(.)/g, '$1') : dn; };

/** Logs a user in against a generic LDAP directory: find the entry, bind as that entry, then collect group names. */
export async function ldapLogin(s: LdapSettings, username: string, password: string, timeoutMs = 6000): Promise<DirectoryLogin> {
  if (!password) return { ok: false, reason: 'Empty password', groups: [] };
  if (/[\0]/.test(username) || username.length > 256) return { ok: false, reason: 'Invalid user name', groups: [] };
  const u = parseUrl(s.url);
  let svc: LdapConn;
  try { svc = await LdapConn.open({ ...u, verify: s.verify, timeoutMs }); } catch (e) { return { ok: false, reason: (e as Error).message, groups: [], unreachable: true }; }
  try {
    if (s.bindDn) await svc.bind(s.bindDn, s.bindPw, timeoutMs).catch(e => { throw new LdapError('The service account could not bind: ' + (e as Error).message, 'config'); });
    const filter = s.filter.replace(/\{user\}/g, escapeFilter(username));
    const found = await svc.search(s.baseDn, filter, ['dn', 'memberOf', 'displayName', 'cn'], { sizeLimit: 2, timeoutMs });
    if (found.length === 0) return { ok: false, reason: 'No such user', groups: [] };
    if (found.length > 1) return { ok: false, reason: 'More than one directory entry matches this user name', groups: [] };
    const entry = found[0];
    const user = await LdapConn.open({ ...u, verify: s.verify, timeoutMs });
    try { await user.bind(entry.dn, password, timeoutMs); } catch (e) { return { ok: false, reason: (e as Error).message, groups: [] }; } finally { user.close(); }
    let groups = entry.attrs.get('memberof') ?? [];
    if (s.groupBase) {
      const g = await svc.search(s.groupBase, `(|(member=${escapeFilter(entry.dn)})(uniqueMember=${escapeFilter(entry.dn)})(memberUid=${escapeFilter(username)}))`, ['cn'], { timeoutMs });
      groups = [...groups, ...g.map(x => x.dn)];
    }
    return { ok: true, dn: entry.dn, groups: [...new Set(groups)], displayName: entry.attrs.get('displayname')?.[0] ?? entry.attrs.get('cn')?.[0] };
  } catch (e) {
    const le = e as LdapError;
    return { ok: false, reason: le.message, groups: [], unreachable: le.kind === 'connect' };
  } finally { svc.close(); }
}

export interface AdSettings { domain: string; dcs: string[]; bindUser: string; bindPw: string; baseDn: string; ldaps: boolean; nested: boolean; verify: boolean }

/** Logs a user in against Active Directory. Accepts "user", "DOMAIN\user" and "user@domain". Nested group membership uses the LDAP_MATCHING_RULE_IN_CHAIN rule. */
export async function adLogin(s: AdSettings, username: string, password: string, timeoutMs = 6000): Promise<DirectoryLogin> {
  if (!password) return { ok: false, reason: 'Empty password', groups: [] };
  let sam = username.trim(); let upn: string | null = null;
  if (sam.includes('\\')) sam = sam.split('\\').pop()!;
  else if (sam.includes('@')) { upn = sam; sam = sam.split('@')[0]; }
  if (!sam || /[\0]/.test(sam)) return { ok: false, reason: 'Invalid user name', groups: [] };
  let lastErr = 'No domain controller is configured';
  for (const dc of s.dcs.length ? s.dcs : [s.domain]) {
    if (!dc) continue;
    const hp = /^(\[[^\]]+\]|[^:]+)(?::(\d+))?$/.exec(dc.trim());
    const opts: LdapOpts = { host: (hp ? hp[1] : dc).replace(/^\[|\]$/g, ''), port: hp?.[2] ? Number(hp[2]) : s.ldaps ? 636 : 389, tls: s.ldaps, verify: s.verify, timeoutMs };
    let svc: LdapConn;
    try { svc = await LdapConn.open(opts); } catch (e) { lastErr = (e as Error).message; continue; }
    try {
      if (s.bindUser) await svc.bind(s.bindUser, s.bindPw, timeoutMs).catch(e => { throw new LdapError('The service account could not bind: ' + (e as Error).message, 'config'); });
      else await svc.bind(upn ?? `${sam}@${s.domain}`, password, timeoutMs);
      const f = `(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=${escapeFilter(sam)})${upn ? `(userPrincipalName=${escapeFilter(upn)})` : ''}))`;
      const found = await svc.search(s.baseDn, f, ['distinguishedName', 'memberOf', 'displayName', 'userAccountControl'], { sizeLimit: 2, timeoutMs });
      if (found.length !== 1) return { ok: false, reason: found.length ? 'More than one directory entry matches this user name' : 'No such user', groups: [] };
      const e = found[0];
      if ((Number(e.attrs.get('useraccountcontrol')?.[0] ?? 0) & 2) !== 0) return { ok: false, reason: 'The account is disabled', groups: [] };
      const user = await LdapConn.open(opts);
      try { await user.bind(upn ?? `${sam}@${s.domain}`, password, timeoutMs); } catch (er) { return { ok: false, reason: (er as Error).message, groups: [] }; } finally { user.close(); }
      let groups = e.attrs.get('memberof') ?? [];
      if (s.nested) {
        const g = await svc.search(s.baseDn, `(&(objectClass=group)(member:1.2.840.113556.1.4.1941:=${escapeFilter(e.dn)}))`, ['cn'], { timeoutMs });
        groups = [...groups, ...g.map(x => x.dn)];
      }
      return { ok: true, dn: e.dn, groups: [...new Set(groups)], displayName: e.attrs.get('displayname')?.[0] };
    } catch (er) {
      const le = er as LdapError; lastErr = le.message;
      if (le.kind !== 'connect') return { ok: false, reason: le.message, groups: [] };
    } finally { svc.close(); }
  }
  return { ok: false, reason: lastErr, groups: [], unreachable: true };
}

/** True when any group (full DN or common name) equals one of the comma or semicolon separated names in the mapping. */
export function groupMatches(groups: string[], mapping: string): boolean {
  const want = mapping.split(/[;,\n]+/).map(s => s.trim().toLowerCase()).filter(Boolean);
  if (!want.length) return false;
  return groups.some(g => { const l = g.toLowerCase(); return want.includes(l) || want.includes(cnOf(g).toLowerCase()); });
}
