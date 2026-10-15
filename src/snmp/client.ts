import snmp from 'net-snmp';

export type SnmpValue = number | bigint | string | Buffer | null;
export interface VarBind { oid: string; type: number; value: SnmpValue }

export interface SnmpCredential {
  version: 'v1' | 'v2c' | 'v3';
  community?: string;
  username?: string;
  level?: 'noAuthNoPriv' | 'authNoPriv' | 'authPriv';
  authProto?: string;
  authKey?: string;
  privProto?: string;
  privKey?: string;
  context?: string;
}

export interface SnmpTarget { host: string; port: number; timeoutMs?: number; retries?: number }

const AUTH: Record<string, number> = {
  'MD5': snmp.AuthProtocols.md5, 'SHA': snmp.AuthProtocols.sha, 'SHA-1': snmp.AuthProtocols.sha, 'SHA-224': snmp.AuthProtocols.sha224,
  'SHA-256': snmp.AuthProtocols.sha256, 'SHA-384': snmp.AuthProtocols.sha384, 'SHA-512': snmp.AuthProtocols.sha512
};
const PRIV: Record<string, number> = {
  'DES': snmp.PrivProtocols.des, 'AES': snmp.PrivProtocols.aes, 'AES-128': snmp.PrivProtocols.aes,
  'AES-256': snmp.PrivProtocols.aes256b, 'AES-256-CISCO': snmp.PrivProtocols.aes256b, 'AES-256-BLUMENTHAL': snmp.PrivProtocols.aes256r
};
export const SUPPORTED_AUTH = ['MD5', 'SHA-1', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512'];
export const SUPPORTED_PRIV = ['DES', 'AES-128', 'AES-256'];

export function toBigInt(v: SnmpValue): bigint | null {
  if (v === null) return null;
  if (typeof v === 'bigint') return v;
  if (typeof v === 'number') return Number.isFinite(v) ? BigInt(Math.trunc(v)) : null;
  if (Buffer.isBuffer(v)) {
    if (!v.length || v.length > 8) return null;
    let r = 0n; for (const b of v) r = (r << 8n) | BigInt(b); return r;
  }
  return null;
}
export function toNum(v: SnmpValue): number | null { const b = toBigInt(v); return b === null ? null : Number(b); }
export function toStr(v: SnmpValue): string {
  if (v === null) return '';
  if (Buffer.isBuffer(v)) return v.toString('utf8').replace(/\0+$/, '');
  return String(v);
}

function convert(vb: any): VarBind {
  const t = vb.type as number;
  let value: SnmpValue = vb.value;
  if (t === snmp.ObjectType.Counter64 && Buffer.isBuffer(value)) value = toBigInt(value);
  else if (t === snmp.ObjectType.OctetString && Buffer.isBuffer(value)) value = value;
  else if (t === snmp.ObjectType.NoSuchObject || t === snmp.ObjectType.NoSuchInstance || t === snmp.ObjectType.EndOfMibView) value = null;
  return { oid: vb.oid, type: t, value };
}
const isMissing = (t: number) => t === snmp.ObjectType.NoSuchObject || t === snmp.ObjectType.NoSuchInstance || t === snmp.ObjectType.EndOfMibView;

export class SnmpError extends Error {
  constructor(message: string, readonly kind: 'timeout' | 'auth' | 'error' = 'error') { super(message); }
}

function classify(e: Error): SnmpError {
  const m = e.message || String(e);
  if (/timed out|timeout/i.test(m)) return new SnmpError('No response from the device (timeout). Check the address, UDP/161 reachability and the credentials.', 'timeout');
  if (/Unknown user|Unsupported security|wrong digest|decryption|authentication|Not in time/i.test(m)) return new SnmpError('Authentication failed: ' + m, 'auth');
  return new SnmpError(m);
}

/** A thin promise wrapper over a net-snmp session. */
export class SnmpClient {
  private s: any;
  closed = false;

  constructor(readonly target: SnmpTarget, readonly cred: SnmpCredential) {
    const transport = target.host.includes(':') ? 'udp6' : 'udp4';
    const opts: Record<string, unknown> = { port: target.port, retries: target.retries ?? 1, timeout: target.timeoutMs ?? 3000, transport, trapPort: 162, idBitsSize: 32 };
    if (cred.version === 'v3') {
      const level = { noAuthNoPriv: snmp.SecurityLevel.noAuthNoPriv, authNoPriv: snmp.SecurityLevel.authNoPriv, authPriv: snmp.SecurityLevel.authPriv }[cred.level || 'noAuthNoPriv'];
      const user: Record<string, unknown> = { name: cred.username || '', level };
      if (cred.level !== 'noAuthNoPriv') {
        const ap = AUTH[(cred.authProto || 'SHA-256').toUpperCase()];
        if (ap === undefined) throw new SnmpError('Unsupported authentication protocol ' + cred.authProto);
        user.authProtocol = ap; user.authKey = cred.authKey || '';
      }
      if (cred.level === 'authPriv') {
        const pp = PRIV[(cred.privProto || 'AES-128').toUpperCase()];
        if (pp === undefined) throw new SnmpError('Unsupported privacy protocol ' + cred.privProto + '. Supported: ' + SUPPORTED_PRIV.join(', '));
        user.privProtocol = pp; user.privKey = cred.privKey || '';
      }
      if (cred.context) opts.context = cred.context;
      opts.version = snmp.Version3;
      this.s = snmp.createV3Session(target.host, user, opts);
    } else {
      opts.version = cred.version === 'v1' ? snmp.Version1 : snmp.Version2c;
      this.s = snmp.createSession(target.host, cred.community || 'public', opts);
    }
    this.s.on('error', () => { /* surfaced through callbacks */ });
  }

  get(oids: string[]): Promise<Map<string, VarBind>> {
    return new Promise((resolve, reject) => {
      this.s.get(oids, (err: Error | null, vbs: any[]) => {
        if (err) return reject(classify(err));
        const m = new Map<string, VarBind>();
        for (const vb of vbs) { const c = convert(vb); if (!isMissing(vb.type) && !snmp.isVarbindError(vb)) m.set(c.oid, c); }
        resolve(m);
      });
    });
  }

  /** Walks a subtree and returns every varbind under it. */
  walk(oid: string, maxRep = 20, limit = 200_000): Promise<VarBind[]> {
    return new Promise((resolve, reject) => {
      const out: VarBind[] = [];
      let truncated = false;
      const feed = (vbs: any[]) => {
        for (const vb of vbs) {
          if (snmp.isVarbindError(vb) || isMissing(vb.type)) continue;
          if (out.length >= limit) { truncated = true; continue; }
          out.push(convert(vb));
        }
      };
      this.s.subtree(oid, maxRep, feed, (err: Error | null) => { if (err) reject(classify(err)); else { void truncated; resolve(out); } });
    });
  }

  /**
   * Reads at most `max` varbinds under an OID, one batch at a time, and says whether the subtree has more. For a person typing an OID
   * into the diagnostics box, where an unbounded walk of a large table (the MAC table, say) would be a poor answer. A leaf OID is returned as itself.
   */
  async walkBounded(oid: string, max = 200): Promise<{ rows: VarBind[]; more: boolean }> {
    const one = await this.get([oid]);
    const leaf = one.get(oid);
    if (leaf) return { rows: [leaf], more: false };
    const rows: VarBind[] = []; const prefix = oid + '.';
    let cur = oid;
    for (let guard = 0; guard < 200; guard++) {
      const vbs = await new Promise<any[]>((resolve, reject) => {
        const cb = (err: Error | null, v: any[]) => err ? reject(classify(err)) : resolve(v ?? []);
        if (this.cred.version === 'v1') this.s.getNext([cur], cb); else this.s.getBulk([cur], 0, 20, cb);
      });
      let progressed = false;
      for (const vb of vbs) {
        if (snmp.isVarbindError(vb) || isMissing(vb.type)) return { rows, more: false };
        if (!String(vb.oid).startsWith(prefix)) return { rows, more: false };
        if (rows.length >= max) return { rows, more: true };
        rows.push(convert(vb)); cur = vb.oid; progressed = true;
      }
      if (!progressed) break;
    }
    return { rows, more: rows.length >= max };
  }

  /** Walks a column and returns map of the index suffix to value. */
  async column(colOid: string, maxRep = 20): Promise<Map<string, SnmpValue>> {
    const vbs = await this.walk(colOid, maxRep);
    const m = new Map<string, SnmpValue>();
    const pre = colOid + '.';
    for (const vb of vbs) if (vb.oid.startsWith(pre)) m.set(vb.oid.slice(pre.length), vb.value);
    return m;
  }

  /**
   * A second session that reads one VLAN of a Cisco switch. These switches keep one MAC table per VLAN and pick it by the
   * community ("public@140") for SNMPv1/v2c, or by the SNMPv3 context "vlan-140". The caller closes the session.
   */
  forVlan(vlan: number): SnmpClient {
    const c = this.cred;
    const cred: SnmpCredential = c.version === 'v3' ? { ...c, context: `vlan-${vlan}` } : { ...c, community: `${c.community || 'public'}@${vlan}` };
    return new SnmpClient(this.target, cred);
  }

  close(): void { if (!this.closed) { this.closed = true; try { this.s.close(); } catch { /* ignore */ } } }
}
