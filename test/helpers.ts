import dgram from 'node:dgram';
import crypto from 'node:crypto';
import net from 'node:net';
import * as d from '../src/tls/der.js';

const md5 = (...b: Buffer[]) => crypto.createHash('md5').update(Buffer.concat(b)).digest();

/** Independent mock server: decrypts the password per RFC 2865 section 5.2 and checks the request Message-Authenticator. */
export function mockRadius(secret: string, users: Record<string, { pw: string; filter?: string; klass?: string }>, opts: { badSecretReply?: boolean } = {}) {
  const sock = dgram.createSocket('udp4');
  const seen: { code: number; user: string; msgAuthOk: boolean; acctStatus?: number }[] = [];
  sock.on('message', (m, r) => {
    const code = m[0], id = m[1], len = m.readUInt16BE(2), ra = m.subarray(4, 20);
    const attrs = new Map<number, Buffer>();
    let o = 20, macOff = -1;
    while (o < len) { if (m[o] === 80) macOff = o + 2; attrs.set(m[o], m.subarray(o + 2, o + m[o + 1])); o += m[o + 1]; }
    const user = attrs.get(1)?.toString() ?? '';
    let msgAuthOk = true;
    if (code === 1) {
      const copy = Buffer.from(m.subarray(0, len));
      msgAuthOk = macOff > 0;
      if (macOff > 0) { copy.fill(0, macOff, macOff + 16); msgAuthOk = crypto.createHmac('md5', secret).update(copy).digest().equals(attrs.get(80)!); }
    }
    seen.push({ code, user, msgAuthOk, acctStatus: attrs.get(40)?.readUInt32BE(0) });
    const reply = (rc: number, extra: Buffer[] = []) => {
      const body = Buffer.concat(extra);
      const h = Buffer.alloc(20); h[0] = rc; h[1] = id; h.writeUInt16BE(20 + body.length, 2);
      const auth = md5(h.subarray(0, 4), ra, body, Buffer.from(opts.badSecretReply ? 'nope' : secret));
      auth.copy(h, 4);
      sock.send(Buffer.concat([h, body]), r.port, r.address);
    };
    const attr = (t: number, v: string) => Buffer.concat([Buffer.from([t, v.length + 2]), Buffer.from(v)]);
    if (code === 4) {
      // verify request authenticator for accounting
      const zero = Buffer.from(m.subarray(0, len)); zero.fill(0, 4, 20);
      if (!md5(zero, Buffer.from(secret)).equals(ra)) return;
      return reply(5);
    }
    // decrypt password
    const enc = attrs.get(2)!; let prev: Buffer = ra; const out: Buffer[] = [];
    for (let i = 0; i < enc.length; i += 16) { const k = md5(Buffer.from(secret), prev); const blk = enc.subarray(i, i + 16); out.push(Buffer.from(blk.map((b, j) => b ^ k[j]))); prev = blk; }
    const pw = Buffer.concat(out).toString().replace(/\0+$/, '');
    const u = users[user];
    if (!msgAuthOk) return; // drop
    if (u && u.pw === pw) reply(2, [...(u.filter ? [attr(11, u.filter)] : []), ...(u.klass ? [attr(25, u.klass)] : []), attr(18, 'Welcome')]);
    else reply(3, [attr(18, 'Denied')]);
  });
  return new Promise<{ port: number; seen: typeof seen; close: () => void }>(res => sock.bind(0, '127.0.0.1', () => res({ port: sock.address().port, seen, close: () => sock.close() })));
}


export interface Ent { dn: string; attrs: Record<string, string[]> }

/** In-memory LDAP server: simple bind, search with and/or/not/equality/present/substring/extensible(in-chain), unbind. */
export function mockDirectory(entries: Ent[], passwords: Record<string, string>) {
  const lc = (s: string) => s.toLowerCase();
  const get = (e: Ent, a: string) => (e.attrs[Object.keys(e.attrs).find(k => lc(k) === lc(a)) ?? ''] ?? (lc(a) === 'dn' || lc(a) === 'distinguishedname' ? [e.dn] : []));
  const inChain = (e: Ent, groupDn: string, seen = new Set<string>()): boolean => {
    for (const m of get(e, 'memberOf')) { if (lc(m) === lc(groupDn)) return true; const g = entries.find(x => lc(x.dn) === lc(m)); if (g && !seen.has(g.dn)) { seen.add(g.dn); if (inChain(g, groupDn, seen)) return true; } }
    return false;
  };
  function evalF(f: d.Node, e: Ent): boolean {
    const kids = d.children(f);
    switch (f.tag) {
      case 0xa0: return kids.every(k => evalF(k, e));
      case 0xa1: return kids.some(k => evalF(k, e));
      case 0xa2: return !evalF(kids[0], e);
      case 0xa3: return get(e, d.body(kids[0]).toString()).some(v => lc(v) === lc(d.body(kids[1]).toString()));
      case 0x87: return get(e, d.body(f).toString()).length > 0;
      case 0xa4: {
        const vals = get(e, d.body(kids[0]).toString()); const parts = d.children(kids[1]);
        return vals.some(v => { let pos = 0; for (const p of parts) { const t = d.body(p).toString().toLowerCase(); const i = lc(v).indexOf(t, pos); if (i < 0 || (p.tag === 0x80 && i !== 0)) return false; pos = i + t.length; } return true; });
      }
      case 0xa9: {
        let rule = '', attr = '', val = '';
        for (const k of kids) { const b = d.body(k).toString(); if (k.tag === 0x81) rule = b; if (k.tag === 0x82) attr = b; if (k.tag === 0x83) val = b; }
        if (rule === '1.2.840.113556.1.4.1941' && lc(attr) === 'member') { const u = entries.find(x => lc(x.dn) === lc(val)); return !!u && inChain(u, e.dn); }
        return false;
      }
    }
    throw new Error('unsupported filter tag ' + f.tag);
  }
  const srv = net.createServer(sock => {
    let buf = Buffer.alloc(0);
    sock.on("data", (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      for (;;) {
        if (buf.length < 2) return;
        const n = d.read(buf); if (buf.length < n.end) return;
        const msg = buf.subarray(0, n.end); buf = buf.subarray(n.end);
        const [idN, op] = d.children(d.read(msg));
        const id = Number(d.body(idN).readUIntBE(0, d.body(idN).length));
        const resp = (tag: number, ...c: Buffer[]) => sock.write(d.seq(d.int(id), d.tlv(tag, ...c)));
        const done = (tag: number, code: number, diag = '') => resp(tag, d.tlv(0x0a, Buffer.from([code])), d.octets(Buffer.alloc(0)), d.octets(Buffer.from(diag)));
        if (op.tag === 0x60) { // bind
          const [, name, auth] = d.children(op);
          const dn = d.body(name).toString(); const pw = d.body(auth).toString();
          if (dn === '' && pw === '') done(0x61, 0); // anonymous
          else if (passwords[lc(dn)] !== undefined && passwords[lc(dn)] === pw) done(0x61, 0);
          else done(0x61, 49, 'invalid credentials');
        } else if (op.tag === 0x63) { // search
          const k = d.children(op);
          const base = d.body(k[0]).toString(); const filter = k[6]; const attrs = d.children(k[7]).map(a => d.body(a).toString());
          const hits = entries.filter(e => lc(e.dn).endsWith(lc(base)) && evalF(filter, e));
          for (const e of hits) {
            const al = (attrs.length ? attrs : Object.keys(e.attrs)).filter(a => lc(a) !== 'dn').map(a => [a, get(e, a)] as const).filter(([, v]) => v.length)
              .map(([a, v]) => d.seq(d.octets(Buffer.from(a)), d.set(...v.map(x => d.octets(Buffer.from(x))))));
            resp(0x64, d.octets(Buffer.from(e.dn)), d.seq(...al));
          }
          done(0x65, 0);
        } else if (op.tag === 0x42) sock.end();
      }
    });
  });
  return new Promise<{ port: number; close: () => void }>(res => srv.listen(0, '127.0.0.1', () => res({ port: (srv.address() as net.AddressInfo).port, close: () => srv.close() })));
}

