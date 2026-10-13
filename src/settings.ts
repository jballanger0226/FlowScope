import type { ConfigDb } from './db/configdb.js';

export interface Retention { raw: number; m1: number; h1: number; d1: number; sRaw: number; sH: number }
export type Role = 'ro' | 'snmp' | 'admin';
export type Provider = 'local' | 'radius' | 'ldap' | 'ad' | 'saml';
export type Service = 'web' | 'api' | 'cli';

export interface RoleMap { admin: string; snmp: string; ro: string }

export interface AaaSettings {
  services: Record<Service, Provider>;
  fallback: boolean;
  local: { minLen: number; lockout: number; idle: number };
  radius: { host1: string; host2: string; authPort: number; acctPort: number; timeout: number; retries: number; attr: 'Filter-Id' | 'Class' | 'Reply-Message'; acct: boolean; secretEnc: string };
  ldap: { url: string; bindDn: string; baseDn: string; filter: string; groupBase: string; verify: boolean; bindPwEnc: string };
  ad: { domain: string; dcs: string; bindUser: string; baseDn: string; ldaps: boolean; nested: boolean; verify: boolean; bindPwEnc: string };
  saml: { idp: string; sp: string; nameAttr: string; groupAttr: string; sign: boolean; idpEntity: string; idpSso: string; idpCert: string };
  map: Record<'radius' | 'ldap' | 'ad' | 'saml', RoleMap>;
  def: Record<'radius' | 'ldap' | 'ad' | 'saml', 'deny' | 'ro'>;
}

export interface CollectSettings { flow: boolean; snmp: boolean; flowAt: number; snmpAt: number }

export const DEFAULTS = {
  retention: { raw: 7, m1: 30, h1: 395, d1: 1095, sRaw: 30, sH: 395 } as Retention,
  collect: { flow: true, snmp: true, flowAt: 0, snmpAt: 0 } as CollectSettings,
  backend: 'sqlite' as 'sqlite' | 'clickhouse',
  logDays: 90,
  alerts: { util: 90, drop: 1 },
  aaa: {
    services: { web: 'local', api: 'local', cli: 'local' },
    fallback: true,
    local: { minLen: 12, lockout: 5, idle: 30 },
    radius: { host1: '', host2: '', authPort: 1812, acctPort: 1813, timeout: 5, retries: 2, attr: 'Filter-Id', acct: false, secretEnc: '' },
    ldap: { url: '', bindDn: '', baseDn: '', filter: '(uid={user})', groupBase: '', verify: true, bindPwEnc: '' },
    ad: { domain: '', dcs: '', bindUser: '', baseDn: '', ldaps: true, nested: true, verify: true, bindPwEnc: '' },
    saml: { idp: '', sp: '', nameAttr: 'email', groupAttr: 'groups', sign: false, idpEntity: '', idpSso: '', idpCert: '' },
    map: {
      radius: { admin: '', snmp: '', ro: '' }, ldap: { admin: '', snmp: '', ro: '' },
      ad: { admin: '', snmp: '', ro: '' }, saml: { admin: '', snmp: '', ro: '' }
    },
    def: { radius: 'deny', ldap: 'deny', ad: 'deny', saml: 'deny' }
  } as AaaSettings
};

type Defaults = typeof DEFAULTS;

/** Typed key/value settings stored as JSON. Objects are merged over their defaults so new fields appear after an upgrade. */
export class Settings {
  constructor(private cdb: ConfigDb) {}

  get<K extends keyof Defaults>(key: K): Defaults[K] {
    const row = this.cdb.db.prepare('SELECT value FROM settings WHERE key = ?').get(key) as { value: string } | undefined;
    const def = DEFAULTS[key];
    if (!row) return structuredClone(def);
    try {
      const v = JSON.parse(row.value);
      if (v && typeof v === 'object' && !Array.isArray(v)) return deepMerge(structuredClone(def), v) as Defaults[K];
      return v as Defaults[K];
    } catch { return structuredClone(def); }
  }

  set<K extends keyof Defaults>(key: K, value: Defaults[K]): void {
    this.cdb.db.prepare('INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(key, JSON.stringify(value));
  }

  raw(key: string): string | undefined {
    const row = this.cdb.db.prepare('SELECT value FROM settings WHERE key = ?').get(key) as { value: string } | undefined;
    return row?.value;
  }
  setRaw(key: string, value: string): void {
    this.cdb.db.prepare('INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(key, value);
  }
}

function deepMerge(a: any, b: any): any {
  for (const k of Object.keys(b)) {
    if (b[k] && typeof b[k] === 'object' && !Array.isArray(b[k]) && a[k] && typeof a[k] === 'object') a[k] = deepMerge(a[k], b[k]);
    else a[k] = b[k];
  }
  return a;
}

export function clampRetention(r: Partial<Retention>, base: Retention): Retention {
  const f = (v: unknown, d: number) => { const n = Math.floor(Number(v)); return Number.isFinite(n) ? Math.min(3650, Math.max(1, n)) : d; };
  return { raw: f(r.raw, base.raw), m1: f(r.m1, base.m1), h1: f(r.h1, base.h1), d1: f(r.d1, base.d1), sRaw: f(r.sRaw, base.sRaw), sH: f(r.sH, base.sH) };
}
