import type { ConfigDb } from '../db/configdb.js';
import type { Secrets } from '../secrets.js';
import type { Settings } from '../settings.js';
import type { SnmpCredential } from './client.js';
import { SUPPORTED_AUTH, SUPPORTED_PRIV } from './client.js';

export interface CredInput {
  name: string; version: 'v2c' | 'v3';
  community?: string;
  username?: string; level?: 'noAuthNoPriv' | 'authNoPriv' | 'authPriv';
  authProto?: string; authKey?: string; privProto?: string; privKey?: string; context?: string;
}
export interface CredView {
  id: number; name: string; version: string; username: string; level: string; authProto: string; privProto: string; context: string;
  isDefault: boolean; usedBy: number; hasSecret: boolean; updatedAt: number;
}

interface Row { id: number; name: string; version: string; username: string; level: string; auth_proto: string; priv_proto: string; context: string; secrets: string | null; created_at: number; updated_at: number }

export class CredError extends Error {}

/** SNMP credential sets. Secrets are encrypted with the master key and never returned by the API. */
export class CredentialStore {
  constructor(private cdb: ConfigDb, private secrets: Secrets, private settings: Settings) {}

  defaultId(): number | null {
    const v = this.settings.raw('snmpDefaultCred');
    const n = v === undefined ? NaN : Number(v);
    if (!Number.isInteger(n)) return null;
    return this.cdb.db.prepare('SELECT id FROM snmp_credentials WHERE id = ?').get(n) ? n : null;
  }

  list(): CredView[] {
    const def = this.defaultId();
    const rows = this.cdb.db.prepare('SELECT * FROM snmp_credentials ORDER BY name').all() as unknown as Row[];
    const used = new Map((this.cdb.db.prepare('SELECT cred_id, COUNT(*) AS n FROM devices GROUP BY cred_id').all() as unknown as { cred_id: number; n: number }[]).map(r => [r.cred_id, r.n]));
    return rows.map(r => ({
      id: r.id, name: r.name, version: r.version, username: r.username, level: r.level, authProto: r.auth_proto, privProto: r.priv_proto, context: r.context,
      isDefault: r.id === def, usedBy: used.get(r.id) ?? 0, hasSecret: !!r.secrets, updatedAt: r.updated_at
    }));
  }

  private validate(i: CredInput, existing?: Row): void {
    if (!i.name || !i.name.trim()) throw new CredError('Give the credential set a name');
    if (i.name.length > 64) throw new CredError('The name is too long');
    if (i.version !== 'v2c' && i.version !== 'v3') throw new CredError('Version must be v2c or v3');
    if (i.version === 'v2c') {
      if (!i.community && !existing) throw new CredError('Enter the community string');
    } else {
      if (!i.username) throw new CredError('SNMPv3 needs a user name');
      const level = i.level || 'noAuthNoPriv';
      if (!['noAuthNoPriv', 'authNoPriv', 'authPriv'].includes(level)) throw new CredError('Unknown security level');
      if (level !== 'noAuthNoPriv') {
        if (!SUPPORTED_AUTH.includes((i.authProto || 'SHA-256').toUpperCase())) throw new CredError('Unsupported authentication protocol. Choose one of ' + SUPPORTED_AUTH.join(', '));
        if (!i.authKey && !existing) throw new CredError('Enter the authentication passphrase');
        if (i.authKey && i.authKey.length < 8) throw new CredError('SNMPv3 passphrases must be at least 8 characters');
      }
      if (level === 'authPriv') {
        if (!SUPPORTED_PRIV.includes((i.privProto || 'AES-128').toUpperCase())) throw new CredError('Unsupported privacy protocol. Choose one of ' + SUPPORTED_PRIV.join(', '));
        if (!i.privKey && !existing) throw new CredError('Enter the privacy passphrase');
        if (i.privKey && i.privKey.length < 8) throw new CredError('SNMPv3 passphrases must be at least 8 characters');
      }
    }
  }

  private sealed(i: CredInput, old?: Row): string {
    const prev = old?.secrets ? JSON.parse(this.secrets.decrypt(old.secrets)) as Record<string, string> : {};
    const next: Record<string, string> = {};
    if (i.version === 'v2c') next.community = i.community || prev.community || '';
    else {
      const level = i.level || 'noAuthNoPriv';
      if (level !== 'noAuthNoPriv') next.authKey = i.authKey || prev.authKey || '';
      if (level === 'authPriv') next.privKey = i.privKey || prev.privKey || '';
    }
    return this.secrets.encrypt(JSON.stringify(next));
  }

  create(i: CredInput, makeDefault = false): number {
    this.validate(i);
    const now = Date.now();
    let id: number;
    try {
      const r = this.cdb.db.prepare('INSERT INTO snmp_credentials(name, version, username, level, auth_proto, priv_proto, context, secrets, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)')
        .run(i.name.trim(), i.version, i.version === 'v3' ? i.username! : '', i.version === 'v3' ? i.level || 'noAuthNoPriv' : 'noAuthNoPriv',
          (i.authProto || 'SHA-256').toUpperCase(), (i.privProto || 'AES-128').toUpperCase(), i.context || '', this.sealed(i), now, now);
      id = Number(r.lastInsertRowid);
    } catch (e) {
      if (/UNIQUE/.test((e as Error).message)) throw new CredError('A credential set with that name already exists');
      throw e;
    }
    if (makeDefault || this.defaultId() === null) this.settings.setRaw('snmpDefaultCred', String(id));
    return id;
  }

  update(id: number, i: CredInput): void {
    const old = this.cdb.db.prepare('SELECT * FROM snmp_credentials WHERE id = ?').get(id) as unknown as Row | undefined;
    if (!old) throw new CredError('No such credential set');
    this.validate(i, old);
    if (i.version !== old.version) {
      // switching version: old secrets do not apply
      if (i.version === 'v2c' && !i.community) throw new CredError('Enter the community string');
      old.secrets = null;
    }
    try {
      this.cdb.db.prepare('UPDATE snmp_credentials SET name=?, version=?, username=?, level=?, auth_proto=?, priv_proto=?, context=?, secrets=?, updated_at=? WHERE id=?')
        .run(i.name.trim(), i.version, i.version === 'v3' ? i.username! : '', i.version === 'v3' ? i.level || 'noAuthNoPriv' : 'noAuthNoPriv',
          (i.authProto || 'SHA-256').toUpperCase(), (i.privProto || 'AES-128').toUpperCase(), i.context || '', this.sealed(i, old), Date.now(), id);
    } catch (e) {
      if (/UNIQUE/.test((e as Error).message)) throw new CredError('A credential set with that name already exists');
      throw e;
    }
  }

  setDefault(id: number): void {
    if (!this.cdb.db.prepare('SELECT 1 FROM snmp_credentials WHERE id = ?').get(id)) throw new CredError('No such credential set');
    this.settings.setRaw('snmpDefaultCred', String(id));
  }

  remove(id: number): void {
    const used = this.cdb.db.prepare('SELECT COUNT(*) AS n FROM devices WHERE cred_id = ?').get(id) as { n: number };
    if (used.n > 0) throw new CredError(`This set is used by ${used.n} device${used.n === 1 ? '' : 's'}. Move them to another set first.`);
    if (this.defaultId() === id) throw new CredError('This is the default set. Choose another default first.');
    this.cdb.db.prepare('DELETE FROM snmp_credentials WHERE id = ?').run(id);
  }

  /** Decrypted credential for a session. */
  resolve(id: number): SnmpCredential {
    const r = this.cdb.db.prepare('SELECT * FROM snmp_credentials WHERE id = ?').get(id) as unknown as Row | undefined;
    if (!r) throw new CredError('Credential set ' + id + ' no longer exists');
    const sec = r.secrets ? JSON.parse(this.secrets.decrypt(r.secrets)) as Record<string, string> : {};
    return r.version === 'v3'
      ? { version: 'v3', username: r.username, level: r.level as SnmpCredential['level'], authProto: r.auth_proto, privProto: r.priv_proto, authKey: sec.authKey, privKey: sec.privKey, context: r.context }
      : { version: 'v2c', community: sec.community };
  }
}
