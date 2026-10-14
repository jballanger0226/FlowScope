import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import { secureDataDir, secureDbFiles } from '../perms.js';

const MIGRATIONS: string[] = [
  `
  CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    pw_hash TEXT,
    role TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'local',
    created_at INTEGER NOT NULL,
    last_login INTEGER,
    last_source TEXT,
    failed INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER NOT NULL DEFAULT 0,
    must_change INTEGER NOT NULL DEFAULT 0,
    disabled INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    role TEXT NOT NULL,
    source TEXT NOT NULL,
    service TEXT NOT NULL,
    csrf TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    ip TEXT
  );
  CREATE TABLE api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    role TEXT NOT NULL,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    last_used INTEGER,
    expires_at INTEGER
  );
  CREATE TABLE snmp_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    version TEXT NOT NULL,
    username TEXT NOT NULL DEFAULT '',
    level TEXT NOT NULL DEFAULT 'noAuthNoPriv',
    auth_proto TEXT NOT NULL DEFAULT 'SHA-256',
    priv_proto TEXT NOT NULL DEFAULT 'AES-128',
    context TEXT NOT NULL DEFAULT '',
    secrets TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );
  CREATE TABLE devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    ip TEXT NOT NULL UNIQUE,
    port INTEGER NOT NULL DEFAULT 161,
    cred_id INTEGER NOT NULL,
    interval_sec INTEGER NOT NULL DEFAULT 60,
    polling INTEGER NOT NULL DEFAULT 1,
    src TEXT NOT NULL DEFAULT 'Added by hand',
    added_at INTEGER NOT NULL,
    sys_name TEXT,
    sys_descr TEXT,
    sys_object_id TEXT,
    role TEXT,
    profile TEXT,
    last_poll INTEGER,
    last_ok INTEGER,
    last_error TEXT
  );
  CREATE TABLE interfaces (
    dev_id INTEGER NOT NULL,
    if_index INTEGER NOT NULL,
    name TEXT NOT NULL,
    descr TEXT,
    alias TEXT,
    speed_mbps INTEGER NOT NULL DEFAULT 0,
    oper_status INTEGER NOT NULL DEFAULT 0,
    policy TEXT,
    PRIMARY KEY (dev_id, if_index)
  );
  CREATE TABLE device_ips (dev_id INTEGER NOT NULL, ip TEXT NOT NULL, if_index INTEGER, PRIMARY KEY (dev_id, ip));
  CREATE TABLE class_defs (
    dev_id INTEGER NOT NULL,
    if_index INTEGER NOT NULL,
    cls TEXT NOT NULL,
    queue TEXT,
    dscps TEXT NOT NULL DEFAULT '[]',
    bw TEXT,
    PRIMARY KEY (dev_id, if_index, cls)
  );
  CREATE TABLE vlans (id INTEGER PRIMARY KEY, name TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'manual');
  CREATE TABLE exporters (
    ip TEXT PRIMARY KEY,
    name TEXT,
    device_id INTEGER,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    flows INTEGER NOT NULL DEFAULT 0,
    version TEXT
  );
  CREATE TABLE certs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slot TEXT NOT NULL,
    cert_pem TEXT NOT NULL,
    chain_pem TEXT NOT NULL DEFAULT '',
    key_enc TEXT,
    subject TEXT, issuer TEXT, sans TEXT, not_before INTEGER, not_after INTEGER, fingerprint TEXT, key_desc TEXT,
    created_at INTEGER NOT NULL,
    self_signed INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    level TEXT NOT NULL,
    source TEXT NOT NULL,
    user TEXT NOT NULL,
    message TEXT NOT NULL
  );
  CREATE INDEX logs_ts ON logs(ts);
  `,
  `
  -- port VLANs, input service policies, and why QoS data may be missing
  ALTER TABLE interfaces ADD COLUMN if_type INTEGER NOT NULL DEFAULT 0;
  ALTER TABLE interfaces ADD COLUMN port_mode TEXT NOT NULL DEFAULT '';
  ALTER TABLE interfaces ADD COLUMN vlan INTEGER NOT NULL DEFAULT 0;
  ALTER TABLE interfaces ADD COLUMN voice_vlan INTEGER NOT NULL DEFAULT 0;
  ALTER TABLE interfaces ADD COLUMN vlan_list TEXT NOT NULL DEFAULT '';
  ALTER TABLE interfaces ADD COLUMN policy_in TEXT;
  ALTER TABLE devices ADD COLUMN qos_note TEXT;
  ALTER TABLE devices ADD COLUMN hosts_at INTEGER;
  ALTER TABLE devices ADD COLUMN hosts_note TEXT;
  -- Which MAC address was learned on which port of which switch, and since when. One row per switch, MAC address and VLAN.
  CREATE TABLE fdb (
    dev_id INTEGER NOT NULL, mac TEXT NOT NULL, vlan INTEGER NOT NULL, if_index INTEGER NOT NULL,
    first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, since INTEGER NOT NULL,
    PRIMARY KEY (dev_id, mac, vlan)
  );
  CREATE INDEX fdb_mac ON fdb(mac);
  CREATE INDEX fdb_port ON fdb(dev_id, if_index);
  -- ARP / neighbour cache of the routers and Layer 3 switches: which IP address uses which MAC address
  CREATE TABLE arp (
    dev_id INTEGER NOT NULL, ip TEXT NOT NULL, mac TEXT NOT NULL, if_index INTEGER NOT NULL DEFAULT 0, last_seen INTEGER NOT NULL,
    PRIMARY KEY (dev_id, ip, mac)
  );
  CREATE INDEX arp_ip ON arp(ip);
  CREATE INDEX arp_mac ON arp(mac);
  -- LLDP / CDP neighbours, so ports that lead to another switch or router are not mistaken for the port a host is plugged into
  CREATE TABLE neighbors (
    dev_id INTEGER NOT NULL, if_index INTEGER NOT NULL, proto TEXT NOT NULL, rem_key TEXT NOT NULL,
    rem_name TEXT NOT NULL DEFAULT '', rem_port TEXT NOT NULL DEFAULT '', rem_ip TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL DEFAULT 'other', caps TEXT NOT NULL DEFAULT '',
    seen_at INTEGER NOT NULL,
    PRIMARY KEY (dev_id, if_index, proto, rem_key)
  );
  `
];

export class ConfigDb {
  readonly db: DatabaseSync;

  constructor(dataDir: string, file = 'config.db') {
    secureDataDir(dataDir);
    const full = file === ':memory:' ? file : path.join(dataDir, file);
    this.db = new DatabaseSync(full);
    this.db.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;');
    this.migrate();
    if (file !== ':memory:') secureDbFiles(full);
  }

  private migrate(): void {
    const row = this.db.prepare('PRAGMA user_version').get() as { user_version: number };
    for (let v = row.user_version; v < MIGRATIONS.length; v++) {
      this.db.exec('BEGIN');
      try {
        this.db.exec(MIGRATIONS[v]);
        this.db.exec(`PRAGMA user_version = ${v + 1}`);
        this.db.exec('COMMIT');
      } catch (e) { this.db.exec('ROLLBACK'); throw e; }
    }
  }

  tx<T>(fn: () => T): T {
    this.db.exec('BEGIN');
    try { const r = fn(); this.db.exec('COMMIT'); return r; } catch (e) { this.db.exec('ROLLBACK'); throw e; }
  }

  close(): void { this.db.close(); }
}
