import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';
import type { FlowRecord } from '../collector/types.js';
import type { Retention } from '../settings.js';
import {
  DAY_MS, type ClassLatest, type ClassSeries, type ClsPoint, type Cond, type IfLatest, type IfPoint, type IfSeries, type IpMatch,
  type ReportDim, type ReportResult, type ReportRow, type ReportSpec, type StoreStats, type StreamPage, type StreamQuery, type StreamRow, type TimeRange
} from './types.js';

/* ------------------------------------------------------------------ small helpers */

import { ymd, ipToN, nToIp, skeyOf } from './util.js';
import { ttlSql, type SqlDialect } from '../analysis/ttl.js';
export { ymd, ipToN, nToIp, skeyOf };
function ymdToMs(s: string): number { return Date.UTC(+s.slice(0, 4), +s.slice(4, 6) - 1, +s.slice(6, 8)); }

type SqlArg = string | number | null;

const SQLITE_DIALECT: SqlDialect = {
  nn: e => `COALESCE((${e}), 0)`,
  startsWith: (col, p) => `substr(${col}, 1, ${p.length}) = '${p}'`,
  str: s => `'${s.replace(/'/g, "''")}'`
};
const addrOnly = (l: readonly string[] = []) => l.filter(x => /^[0-9a-fA-F:.]{2,45}$/.test(x));
export function rawTtlSql(local?: readonly string[]) {
  return ttlSql(SQLITE_DIALECT, { ttl: 'ttl_min', srcIp: 'src_ip', dstIp: 'dst_ip', srcN: 'src_n', dstN: 'dst_n', proto: 'proto', sport: 'sport', dport: 'dport', exporter: 'exporter' }, addrOnly(local));
}

const FLOW_COLS = 'ts0, ts1, exporter, in_if, out_if, src_ip, dst_ip, proto, sport, dport, flags, tos, post_tos, ttl_min, ttl_max, bytes, pkts, src_mac, dst_mac, vlan, nat_src, nat_dst, nat_sport, nat_dport, next_hop, skey, primary_hop, src_n, dst_n';

function flowDdl(t: string): string {
  return `CREATE TABLE IF NOT EXISTS ${t} (
    ts0 INTEGER NOT NULL, ts1 INTEGER NOT NULL, exporter TEXT NOT NULL, in_if INTEGER, out_if INTEGER,
    src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL, proto INTEGER, sport INTEGER, dport INTEGER, flags INTEGER,
    tos INTEGER, post_tos INTEGER, ttl_min INTEGER, ttl_max INTEGER, bytes INTEGER, pkts INTEGER,
    src_mac TEXT, dst_mac TEXT, vlan INTEGER, nat_src TEXT, nat_dst TEXT, nat_sport INTEGER, nat_dport INTEGER, next_hop TEXT,
    skey TEXT NOT NULL, primary_hop INTEGER NOT NULL DEFAULT 1, src_n INTEGER, dst_n INTEGER);
  CREATE INDEX IF NOT EXISTS ${t}_ts1 ON ${t}(ts1);
  CREATE INDEX IF NOT EXISTS ${t}_skey ON ${t}(skey);
  CREATE INDEX IF NOT EXISTS ${t}_srcn ON ${t}(src_n);
  CREATE INDEX IF NOT EXISTS ${t}_dstn ON ${t}(dst_n);`;
}

const ROLLUP_COLS = `ts INTEGER NOT NULL, exporter TEXT NOT NULL, in_if INTEGER NOT NULL, vlan INTEGER NOT NULL, src_mac TEXT NOT NULL, dst_mac TEXT NOT NULL,
  src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL, src_n INTEGER, dst_n INTEGER, proto INTEGER NOT NULL, dport INTEGER NOT NULL, svc INTEGER NOT NULL, dscp INTEGER NOT NULL, post_dscp INTEGER NOT NULL,
  bytes INTEGER NOT NULL, pkts INTEGER NOT NULL, flows INTEGER NOT NULL,
  PRIMARY KEY (ts, exporter, in_if, vlan, src_mac, dst_mac, src_ip, dst_ip, proto, dport, svc, dscp, post_dscp)`;

const STATIC_DDL = `
  CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS flow_1m (${ROLLUP_COLS}) WITHOUT ROWID;
  CREATE TABLE IF NOT EXISTS flow_1h (${ROLLUP_COLS}) WITHOUT ROWID;
  CREATE TABLE IF NOT EXISTS flow_1d (${ROLLUP_COLS}) WITHOUT ROWID;
  CREATE TABLE IF NOT EXISTS snmp_if_1h (ts INTEGER NOT NULL, dev INTEGER NOT NULL, if_index INTEGER NOT NULL, secs REAL NOT NULL,
    util_in REAL, util_out REAL, util_out_max REAL, in_bps REAL, out_bps REAL, disc INTEGER, err INTEGER, PRIMARY KEY (ts, dev, if_index)) WITHOUT ROWID;
  CREATE TABLE IF NOT EXISTS snmp_cls_1h (ts INTEGER NOT NULL, dev INTEGER NOT NULL, if_index INTEGER NOT NULL, cls TEXT NOT NULL, secs REAL NOT NULL,
    pre_pkts INTEGER, pre_bytes INTEGER, post_bytes INTEGER, drop_pkts INTEGER, drop_bytes INTEGER, qdepth INTEGER, PRIMARY KEY (ts, dev, if_index, cls)) WITHOUT ROWID;
  CREATE INDEX IF NOT EXISTS snmp_if_1h_dev ON snmp_if_1h(dev, if_index, ts);
  CREATE INDEX IF NOT EXISTS snmp_cls_1h_dev ON snmp_cls_1h(dev, if_index, ts);
`;

function snmpIfDdl(t: string): string {
  return `CREATE TABLE IF NOT EXISTS ${t} (ts INTEGER NOT NULL, dev INTEGER NOT NULL, if_index INTEGER NOT NULL, dt REAL NOT NULL,
    in_bps REAL, out_bps REAL, util_in REAL, util_out REAL, in_disc INTEGER, out_disc INTEGER, in_err INTEGER, out_err INTEGER, oper INTEGER);
  CREATE INDEX IF NOT EXISTS ${t}_k ON ${t}(dev, if_index, ts);`;
}
function snmpClsDdl(t: string): string {
  return `CREATE TABLE IF NOT EXISTS ${t} (ts INTEGER NOT NULL, dev INTEGER NOT NULL, if_index INTEGER NOT NULL, cls TEXT NOT NULL, dt REAL NOT NULL,
    pre_pkts INTEGER, pre_bytes INTEGER, post_bytes INTEGER, drop_pkts INTEGER, drop_bytes INTEGER, qdepth INTEGER);
  CREATE INDEX IF NOT EXISTS ${t}_k ON ${t}(dev, if_index, ts);`;
}

/* ------------------------------------------------------------------ the ops */

export interface OpenOpts { dir: string; file?: string; readOnly?: boolean }

export function openTsDb(o: OpenOpts): DatabaseSync {
  fs.mkdirSync(o.dir, { recursive: true });
  const file = o.file === ':memory:' ? ':memory:' : path.join(o.dir, o.file || 'ts.db');
  const db = new DatabaseSync(file, o.readOnly ? { readOnly: true } : {});
  if (!o.readOnly) {
    db.exec('PRAGMA auto_vacuum = INCREMENTAL;');
    db.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;');
  }
  db.exec('PRAGMA busy_timeout = 10000;');
  return db;
}

interface PrimaryEntry { exp: string; at: number }

export class SqliteOps {
  private created = new Set<string>();
  private insStmts = new Map<string, ReturnType<DatabaseSync['prepare']>>();
  private primary = new Map<string, PrimaryEntry>();
  private tableCache: { at: number; names: string[] } | null = null;
  private statsCache: { at: number; v: Omit<StoreStats, 'backend' | 'ingested' | 'dropped' | 'bytesOnDisk'> } | null = null;
  ingested = 0;

  constructor(readonly db: DatabaseSync, readonly dir: string, readonly writer: boolean) {
    if (writer) db.exec(STATIC_DDL);
  }

  /* -------------------------------------------------------------- table bookkeeping */

  /** Forget the cached table list (readers call this before each query so they see tables created by the writer). */
  refresh(): void { this.tableCache = null; }

  private tables(prefix: string): string[] {
    const now = Date.now();
    if (!this.tableCache || now - this.tableCache.at > 2000) {
      const rows = this.db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND (name LIKE 'flows\\_%' ESCAPE '\\' OR name LIKE 'snmpif\\_%' ESCAPE '\\' OR name LIKE 'snmpcls\\_%' ESCAPE '\\')").all() as { name: string }[];
      this.tableCache = { at: now, names: rows.map(r => r.name) };
    }
    return this.tableCache.names.filter(n => n.startsWith(prefix + '_') && /^\d{8}$/.test(n.slice(prefix.length + 1)));
  }

  private tablesFor(prefix: string, range: TimeRange): string[] {
    const lo = ymd(range.from), hi = ymd(range.to);
    return this.tables(prefix).filter(n => { const d = n.slice(prefix.length + 1); return d >= lo && d <= hi; }).sort();
  }

  private ensure(name: string, ddl: string): void {
    if (this.created.has(name)) return;
    this.db.exec(ddl);
    this.created.add(name);
    this.tableCache = null;
  }

  private stmt(key: string, sql: string) {
    let s = this.insStmts.get(key);
    if (!s) { s = this.db.prepare(sql); this.insStmts.set(key, s); }
    return s;
  }

  private tx<T>(fn: () => T): T {
    this.db.exec('BEGIN');
    try { const r = fn(); this.db.exec('COMMIT'); return r; } catch (e) { this.db.exec('ROLLBACK'); throw e; }
  }

  /* -------------------------------------------------------------- inserts */

  insertFlows(recs: FlowRecord[]): void {
    if (!recs.length) return;
    const now = Date.now();
    this.tx(() => {
      for (const r of recs) {
        const day = ymd(r.ts1);
        // Defence in depth: a time that does not give a plain YYYYMMDD would create a table that is never listed, rolled up or dropped.
        if (!/^\d{8}$/.test(day)) continue;
        const t = 'flows_' + day;
        this.ensure(t, flowDdl(t));
        const skey = skeyOf(r);
        const dirKey = skey + '>' + r.srcIp;
        let prim = 1;
        const e = this.primary.get(dirKey);
        if (e && now - e.at < 30 * 60_000) {
          prim = e.exp === r.exporter ? 1 : 0;
          e.at = now;
        } else {
          this.primary.set(dirKey, { exp: r.exporter, at: now });
        }
        this.stmt('f' + t, `INSERT INTO ${t} (${FLOW_COLS}) VALUES (${new Array(29).fill('?').join(',')})`).run(
          r.ts0, r.ts1, r.exporter, r.inIf, r.outIf, r.srcIp, r.dstIp, r.proto, r.sport, r.dport, r.flags, r.tos, r.postTos, r.ttlMin, r.ttlMax,
          r.bytes, r.pkts, r.srcMac, r.dstMac, r.vlan, r.natSrcIp, r.natDstIp, r.natSport, r.natDport, r.nextHop, skey, prim, ipToN(r.srcIp), ipToN(r.dstIp));
      }
    });
    this.ingested += recs.length;
    if (this.primary.size > 1_500_000) {
      let n = 0;
      for (const k of this.primary.keys()) { this.primary.delete(k); if (++n > 300_000) break; }
    }
  }

  insertSnmp(ifs: IfPoint[], cls: ClsPoint[]): void {
    if (!ifs.length && !cls.length) return;
    this.tx(() => {
      for (const p of ifs) {
        const t = 'snmpif_' + ymd(p.ts);
        this.ensure(t, snmpIfDdl(t));
        this.stmt('i' + t, `INSERT INTO ${t} (ts, dev, if_index, dt, in_bps, out_bps, util_in, util_out, in_disc, out_disc, in_err, out_err, oper) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
          .run(p.ts, p.dev, p.ifIndex, p.dt, p.inBps, p.outBps, p.utilIn, p.utilOut, p.inDisc, p.outDisc, p.inErr, p.outErr, p.oper);
      }
      for (const p of cls) {
        const t = 'snmpcls_' + ymd(p.ts);
        this.ensure(t, snmpClsDdl(t));
        this.stmt('c' + t, `INSERT INTO ${t} (ts, dev, if_index, cls, dt, pre_pkts, pre_bytes, post_bytes, drop_pkts, drop_bytes, qdepth) VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
          .run(p.ts, p.dev, p.ifIndex, p.cls, p.dt, p.prePkts, p.preBytes, p.postBytes, p.dropPkts, p.dropBytes, p.qdepth);
      }
    });
  }

  /* -------------------------------------------------------------- predicates */

  private ipPred(col: string, nCol: string, ms: IpMatch[], args: SqlArg[]): string {
    const parts: string[] = [];
    for (const m of ms) {
      if (m.lo !== undefined && m.hi !== undefined) { parts.push(`(${nCol} BETWEEN ? AND ?)`); args.push(m.lo, m.hi); }
      else if (m.text !== undefined) { parts.push(`${col} LIKE ? ESCAPE '\\'`); args.push(likeEsc(m.text) + '%'); }
    }
    return parts.length ? '(' + parts.join(' OR ') + ')' : '0';
  }

  /**
   * `col IN (...)` for a list of numbers. Runs of three or more consecutive values (port:1000-3000) become `BETWEEN`, so a search
   * for many ranges stays far below SQLite's limit on bound parameters instead of failing with "too many SQL variables".
   */
  private numIn(col: string, vals: number[], args: SqlArg[]): string {
    if (!vals.length) return '0';
    const sorted = [...new Set(vals)].sort((a, b) => a - b);
    const singles: number[] = [], parts: string[] = [];
    for (let i = 0; i < sorted.length;) {
      let j = i;
      while (j + 1 < sorted.length && sorted[j + 1] === sorted[j] + 1) j++;
      if (j - i >= 2) { parts.push(`${col} BETWEEN ? AND ?`); args.push(sorted[i], sorted[j]); }
      else for (let k = i; k <= j; k++) singles.push(sorted[k]);
      i = j + 1;
    }
    if (singles.length) { parts.push(`${col} IN (${singles.map(() => '?').join(',')})`); args.push(...singles); }
    return parts.length === 1 ? parts[0] : '(' + parts.join(' OR ') + ')';
  }

  /** Record-level predicate that is a safe superset of the condition (used to find candidate streams). */
  private recordPred(c: Cond, args: SqlArg[], t: ColMap, local?: readonly string[]): string {
    switch (c.kind) {
      case 'src': case 'dst': case 'ip': {
        const a: SqlArg[] = [], b: SqlArg[] = [];
        const s = this.ipPred(t.srcIp, t.srcN, c.m, a), d = this.ipPred(t.dstIp, t.dstN, c.m, b);
        args.push(...a, ...b); return `(${s} OR ${d})`;
      }
      case 'port': return t.sport ? `(${this.numIn(t.sport, c.ports, args)} OR ${this.numIn(t.dport, c.ports, args)})` : this.numIn(t.dport, c.ports, args);
      case 'sport': return t.sport ? `(${this.numIn(t.sport, c.ports, args)} OR ${this.numIn(t.dport, c.ports, args)})` : this.numIn(t.dport, c.ports, args);
      case 'dport': return t.sport ? `(${this.numIn(t.sport, c.ports, args)} OR ${this.numIn(t.dport, c.ports, args)})` : this.numIn(t.dport, c.ports, args);
      case 'proto': return this.numIn(t.proto, c.protos, args);
      case 'vlan': return this.numIn(t.vlan, c.ids, args);
      case 'mac': { const p = '%' + likeEsc(c.text.toLowerCase()) + '%'; args.push(p, p); return `(${t.srcMac} LIKE ? ESCAPE '\\' OR ${t.dstMac} LIKE ? ESCAPE '\\')`; }
      case 'exporter': if (!c.ips.length) return '0'; args.push(...c.ips); return `${t.exporter} IN (${c.ips.map(() => '?').join(',')})`;
      case 'outif': if (!t.outIf || !c.ips.length) return t.outIf ? '0' : '1'; args.push(...c.ips, c.ifIndex); return `(${t.exporter} IN (${c.ips.map(() => '?').join(',')}) AND ${t.outIf} = ?)`;
      case 'ifport': {
        if (!c.ips.length) return '0';
        args.push(...c.ips);
        const exp = `${t.exporter} IN (${c.ips.map(() => '?').join(',')})`;
        if (!c.ifIndex) return exp;
        if (!t.outIf) return exp;   // the rolled-up tiers keep no interfaces; the page only searches raw data
        if (c.dir === 'in') { args.push(c.ifIndex); return `(${exp} AND ${t.inIf} = ?)`; }
        if (c.dir === 'out') { args.push(c.ifIndex); return `(${exp} AND ${t.outIf} = ?)`; }
        args.push(c.ifIndex, c.ifIndex); return `(${exp} AND (${t.inIf} = ? OR ${t.outIf} = ?))`;
      }
      case 'qos': return '1';
      case 'ttl': {
        if (!t.rawTtl) throw new Error('The TTL filter needs flow records. Pick the raw data tier.');
        const x = rawTtlSql(local);
        return c.mode === 'expired' ? x.any : `NOT ${x.any}`;
      }
      case 'dscp': { const a: SqlArg[] = []; const x = this.numIn(t.dscp, c.values, a); args.push(...a); return x; }
      case 'text': {
        const parts: string[] = [];
        const like = '%' + likeEsc(c.text.toLowerCase()) + '%';
        parts.push(`(${t.srcIp} LIKE ? ESCAPE '\\' OR ${t.dstIp} LIKE ? ESCAPE '\\' OR ${t.srcMac} LIKE ? ESCAPE '\\' OR ${t.dstMac} LIKE ? ESCAPE '\\')`);
        args.push(like, like, like, like);
        if (c.ips.length) { parts.push(`${t.exporter} IN (${c.ips.map(() => '?').join(',')})`); args.push(...c.ips); }
        if (c.vlans.length) parts.push(this.numIn(t.vlan, c.vlans, args));
        if (c.ports.length) parts.push(t.sport ? `(${this.numIn(t.sport, c.ports, args)} OR ${this.numIn(t.dport, c.ports, args)})` : this.numIn(t.dport, c.ports, args));
        return '(' + parts.join(' OR ') + ')';
      }
    }
  }

  /* -------------------------------------------------------------- stream search */

  searchStreams(q: StreamQuery): StreamPage {
    const tabs = this.tablesFor('flows', q.range);
    if (!tabs.length) return { rows: [], total: 0, truncated: false, tier: 'raw' };
    const args: SqlArg[] = [];
    const union = tabs.map(t => { args.push(q.range.from, q.range.to); return `SELECT * FROM ${t} WHERE ts1 BETWEEN ? AND ?`; }).join(' UNION ALL ');
    const raw: ColMap = RAW_COLS;
    // candidate streams: intersect one set per condition
    const sets: string[] = [];
    for (const c of q.conds) {
      if (c.kind === 'qos' || (c.kind === 'ttl' && c.mode === 'ok')) continue;
      const a: SqlArg[] = [];
      const pred = this.recordPred(c, a, raw, q.localIps);
      sets.push(`SELECT DISTINCT skey FROM f WHERE ${pred}`);
      args.push(...a);
    }
    const cand = sets.length ? `WHERE skey IN (${sets.join(' INTERSECT ')})` : '';
    const recent = q.recent && q.recent > 0 ? Math.trunc(q.recent) : 0;
    // a preview reads only the newest records; it is partial when more matching records exist than it reads
    const partial = recent > 0 && Number((this.db.prepare(`WITH f AS (${union}) SELECT COUNT(*) AS n FROM (SELECT 1 FROM f ${cand} LIMIT ${recent + 1})`).get(...args) as { n: number }).n) > recent;
    // exact conditions on the stream's initiator direction
    const exact: string[] = []; const exArgs: SqlArg[] = [];
    let qosCond = '', ttlCond = '';
    const tx = rawTtlSql(q.localIps);
    for (const c of q.conds) {
      if (c.kind === 'src') exact.push(this.ipPred('i.src_ip', 'i.src_n', c.m, exArgs));
      else if (c.kind === 'dst') exact.push(this.ipPred('i.dst_ip', 'i.dst_n', c.m, exArgs));
      else if (c.kind === 'sport') exact.push(this.numIn('i.sport', c.ports, exArgs));
      else if (c.kind === 'dport') exact.push(this.numIn('i.dport', c.ports, exArgs));
      else if (c.kind === 'qos') qosCond = c.mode === 'changed' ? 'AND (t.nd > 1 OR t.rm = 1)' : 'AND NOT (t.nd > 1 OR t.rm = 1)';
      else if (c.kind === 'ttl') ttlCond = c.mode === 'expired' ? 'AND (t.tx = 1 OR t.txi = 1)' : 'AND NOT (t.tx = 1 OR t.txi = 1)';
    }
    const order = q.sort === 'bytes' ? 't.b' : q.sort === 'pkts' ? 't.p' : 't.t1';
    const sql = `
      WITH f AS (${union}),
      fr AS (SELECT *, FIRST_VALUE(tos >> 2) OVER (PARTITION BY skey, src_ip, sport ORDER BY ts0) AS fd FROM ${recent ? `(SELECT * FROM f ${cand} ORDER BY ts1 DESC LIMIT ${recent})` : `f ${cand}`}),
      d AS (
        SELECT skey, src_ip, dst_ip, src_n, dst_n, proto, sport, dport, MIN(ts0) AS t0, MAX(ts1) AS t1,
               SUM(CASE WHEN primary_hop = 1 THEN bytes ELSE 0 END) AS b, SUM(CASE WHEN primary_hop = 1 THEN pkts ELSE 0 END) AS p,
               COUNT(DISTINCT tos >> 2) AS nd, MAX(fd) AS d_in, MIN(tos >> 2) AS d_min, MAX(tos >> 2) AS d_max,
               MAX(CASE WHEN post_tos IS NOT NULL AND (post_tos >> 2) != (tos >> 2) THEN 1 ELSE 0 END) AS rm,
               MAX(CASE WHEN post_tos IS NOT NULL AND (post_tos >> 2) != (tos >> 2) THEN post_tos >> 2 END) AS d_post,
               GROUP_CONCAT(DISTINCT exporter) AS exps, MAX(vlan) AS vlan, MAX(flags) AS fl,
               MAX(CASE WHEN ${tx.expired} THEN 1 ELSE 0 END) AS tx, MAX(CASE WHEN ${tx.icmp} THEN 1 ELSE 0 END) AS txi, MIN(CASE WHEN ${tx.expired} THEN ttl_min END) AS ttl_lo
        FROM fr GROUP BY skey, src_ip, sport),
      i AS (SELECT skey, src_ip, dst_ip, src_n, dst_n, proto, sport, dport, MIN(t0) AS it0 FROM d GROUP BY skey),
      t AS (
        SELECT d.skey AS skey, MIN(d.t0) AS t0, MAX(d.t1) AS t1, SUM(d.b) AS b, SUM(d.p) AS p,
               SUM(CASE WHEN d.src_ip = i.src_ip AND d.sport = i.sport THEN d.b ELSE 0 END) AS fb,
               SUM(CASE WHEN d.src_ip = i.src_ip AND d.sport = i.sport THEN d.p ELSE 0 END) AS fp,
               MAX(d.nd) AS nd, MAX(d.rm) AS rm, GROUP_CONCAT(d.exps) AS exps, MAX(d.vlan) AS vlan, MAX(d.fl) AS fl,
               MIN(d.d_min) AS d_min, MAX(d.d_max) AS d_max, MAX(d.d_post) AS d_post,
               MAX(CASE WHEN d.src_ip = i.src_ip AND d.sport = i.sport THEN d.d_in END) AS d_in,
               MAX(d.tx) AS tx, MAX(d.txi) AS txi, MIN(d.ttl_lo) AS ttl_lo
        FROM d JOIN i ON i.skey = d.skey GROUP BY d.skey)
      SELECT i.skey AS skey, i.src_ip, i.dst_ip, i.proto, i.sport, i.dport, t.t0, t.t1, t.b, t.p, t.fb, t.fp, t.exps, t.vlan, t.fl, t.d_in, t.d_min, t.d_max, t.d_post, t.tx, t.txi, t.ttl_lo,
             (CASE WHEN t.nd > 1 OR t.rm = 1 THEN 1 ELSE 0 END) AS qchg, COUNT(*) OVER () AS total
      FROM i JOIN t ON t.skey = i.skey
      WHERE 1 = 1 ${exact.length ? 'AND ' + exact.join(' AND ') : ''} ${qosCond} ${ttlCond}
      ORDER BY ${order} ${q.dir === 'asc' ? 'ASC' : 'DESC'}, t.t1 DESC
      LIMIT ? OFFSET ?`;
    const rows = this.db.prepare(sql).all(...args, ...exArgs, q.limit, Math.max(0, Math.trunc(q.offset ?? 0))) as unknown as Record<string, number | string | null>[];
    const total = rows.length ? Number(rows[0].total) : 0;
    const out: StreamRow[] = rows.map(r => ({
      skey: String(r.skey), srcIp: String(r.src_ip), dstIp: String(r.dst_ip), proto: Number(r.proto), sport: Number(r.sport), dport: Number(r.dport),
      t0: Number(r.t0), t1: Number(r.t1), bytes: Number(r.b), pkts: Number(r.p), fwdBytes: Number(r.fb), revBytes: Number(r.b) - Number(r.fb),
      fwdPkts: Number(r.fp), revPkts: Number(r.p) - Number(r.fp),
      exporters: [...new Set(String(r.exps || '').split(',').filter(Boolean))], vlan: r.vlan === null ? null : Number(r.vlan),
      qosChanged: Number(r.qchg) === 1, flags: Number(r.fl || 0),
      ttlExpired: Number(r.tx) === 1 || Number(r.txi) === 1, ttlReason: Number(r.tx) === 1 ? 'ttl' : Number(r.txi) === 1 ? 'icmp' : null, ttlLow: r.ttl_lo === null || r.ttl_lo === undefined ? null : Number(r.ttl_lo),
      dscpIn: r.d_in === null ? Number(r.d_min) : Number(r.d_in),
      dscpOut: Number(r.qchg) === 1 ? (r.d_post !== null ? Number(r.d_post) : (Number(r.d_max) !== Number(r.d_in ?? r.d_min) ? Number(r.d_max) : Number(r.d_min))) : null
    }));
    return { rows: out, total, truncated: total > (q.offset ?? 0) + out.length, tier: 'raw', partial };
  }

  streamRecords(skey: string, range: TimeRange): (FlowRecord & { primary: boolean })[] {
    const tabs = this.tablesFor('flows', range);
    const out: (FlowRecord & { primary: boolean })[] = [];
    for (const t of tabs) {
      const rows = this.db.prepare(`SELECT * FROM ${t} WHERE skey = ? AND ts1 BETWEEN ? AND ? ORDER BY ts0`).all(skey, range.from, range.to) as unknown as Record<string, any>[];
      for (const r of rows) {
        out.push({
          ts0: r.ts0, ts1: r.ts1, exporter: r.exporter, inIf: r.in_if, outIf: r.out_if, srcIp: r.src_ip, dstIp: r.dst_ip, proto: r.proto, sport: r.sport, dport: r.dport,
          flags: r.flags, tos: r.tos, postTos: r.post_tos, ttlMin: r.ttl_min, ttlMax: r.ttl_max, bytes: r.bytes, pkts: r.pkts, srcMac: r.src_mac, dstMac: r.dst_mac,
          vlan: r.vlan, natSrcIp: r.nat_src, natDstIp: r.nat_dst, natSport: r.nat_sport, natDport: r.nat_dport, nextHop: r.next_hop, sampling: 1, primary: r.primary_hop === 1
        });
      }
    }
    return out;
  }

  /* -------------------------------------------------------------- reports */

  report(spec: ReportSpec): ReportResult {
    const raw = spec.tier === 'raw';
    const args: SqlArg[] = [];
    let source: string; let cm: ColMap; let wB: string, wP: string, wF: string; let where: string[] = [];
    if (raw) {
      const tabs = this.tablesFor('flows', spec.range);
      if (!tabs.length) return emptyReport();
      source = tabs.map(t => { args.push(spec.range.from, spec.range.to); return `SELECT * FROM ${t} WHERE ts1 BETWEEN ? AND ?`; }).join(' UNION ALL ');
      cm = RAW_COLS; wB = 'bytes'; wP = 'pkts'; wF = '1';
      where.push(spec.exporter ? 'exporter = ?' : 'primary_hop = 1');
      if (spec.exporter) args.push(spec.exporter);
    } else {
      const t = ({ m1: 'flow_1m', h1: 'flow_1h', d1: 'flow_1d' } as Record<string, string>)[spec.tier];
      source = `SELECT * FROM ${t} WHERE ts BETWEEN ? AND ?`; args.push(spec.range.from, spec.range.to);
      cm = ROLLUP_MAP; wB = 'bytes'; wP = 'pkts'; wF = 'flows';
      if (spec.exporter) { where.push('exporter = ?'); args.push(spec.exporter); }
    }
    // filters. In bidirectional reports src and dst filters match either end.
    for (const c of spec.conds) {
      const cc: Cond = spec.bidir && (c.kind === 'src' || c.kind === 'dst') ? { kind: 'ip', m: c.m } : c;
      if (cc.kind === 'qos') {
        where.push(cc.mode === 'changed' ? `(${cm.postDscp} IS NOT NULL AND ${cm.postDscp} >= 0 AND ${cm.postDscp} != ${cm.dscp})` : `(${cm.postDscp} IS NULL OR ${cm.postDscp} < 0 OR ${cm.postDscp} = ${cm.dscp})`);
        continue;
      }
      if (cc.kind === 'src' || cc.kind === 'dst') {
        const a: SqlArg[] = [];
        where.push(this.ipPred(cc.kind === 'src' ? cm.srcIp : cm.dstIp, cc.kind === 'src' ? cm.srcN : cm.dstN, cc.m, a)); args.push(...a); continue;
      }
      if (cc.kind === 'sport' && !cm.sport) continue;
      if (cc.kind === 'sport') { const a: SqlArg[] = []; where.push(this.numIn(cm.sport!, cc.ports, a)); args.push(...a); continue; }
      if (cc.kind === 'dport') { const a: SqlArg[] = []; where.push(this.numIn(cm.dport, cc.ports, a)); args.push(...a); continue; }
      const a: SqlArg[] = [];
      where.push(this.recordPred(cc, a, cm, spec.localIps)); args.push(...a);
    }
    // dimension expressions
    const swp = `(CASE WHEN ${cm.srcN} IS NOT NULL AND ${cm.dstN} IS NOT NULL THEN ${cm.srcN} > ${cm.dstN} ELSE ${cm.srcIp} > ${cm.dstIp} END)`;
    const pick = (a: string, b: string) => spec.bidir ? `(CASE WHEN ${swp} THEN ${b} ELSE ${a} END)` : a;
    const k = 32 - Math.max(0, Math.min(32, spec.prefix));
    const ipExpr = (ip: string, n: string) => k === 0 ? ip : `(CASE WHEN ${n} IS NOT NULL THEN ((${n} >> ${k}) << ${k}) ELSE ${ip} END)`;
    const E: Record<ReportDim, string> = {
      srcMac: pick(cm.srcMac, cm.dstMac), dstMac: pick(cm.dstMac, cm.srcMac), vlan: cm.vlan,
      inIf: `${cm.exporter} || '#' || ${cm.inIf}`,
      srcIp: ipExpr(pick(cm.srcIp, cm.dstIp), pick(cm.srcN, cm.dstN)), dstIp: ipExpr(pick(cm.dstIp, cm.srcIp), pick(cm.dstN, cm.srcN)),
      proto: cm.proto, dscp: cm.dscp, svc: cm.svc,
      qos: `(CASE WHEN ${cm.postDscp} IS NOT NULL AND ${cm.postDscp} >= 0 AND ${cm.postDscp} != ${cm.dscp} THEN ${cm.dscp} || '>' || ${cm.postDscp} ELSE 'unchanged' END)`,
      sport: cm.sport ? pick(cm.sport, cm.dport) : '0', dport: cm.sport ? pick(cm.dport, cm.sport) : pick(cm.dport, '0'), flags: cm.flags || '0'
    };
    const dims = spec.dims.filter(d => E[d] !== undefined);
    const sel = dims.map((d, i) => `${E[d]} AS d${i}`);
    const grp = dims.map((_, i) => `d${i}`);
    const orderCol = spec.sortBy === 'pkts' ? 'p' : spec.sortBy === 'flows' ? 'f' : 'b';
    const sql = `WITH s AS (${source})
      SELECT ${sel.length ? sel.join(', ') + ',' : ''} SUM(${wB}) AS b, SUM(${wP}) AS p, SUM(${wF}) AS f
      FROM s ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ${grp.length ? 'GROUP BY ' + grp.join(', ') : ''}
      ORDER BY ${orderCol} DESC`;
    const rows = this.db.prepare(sql).all(...args) as unknown as Record<string, number | string | null>[];
    const all: ReportRow[] = rows.map(r => {
      const dm: Record<string, string | number | null> = {};
      dims.forEach((d, i) => {
        let v = r['d' + i] as string | number | null;
        if ((d === 'srcIp' || d === 'dstIp') && typeof v === 'number') v = nToIp(v) + (spec.prefix < 32 ? '/' + spec.prefix : '');
        else if ((d === 'srcIp' || d === 'dstIp') && typeof v === 'string' && spec.prefix < 32 && !v.includes('/')) v = v + '/128';
        dm[d] = v;
      });
      return { dims: dm, bytes: Number(r.b), pkts: Number(r.p), flows: Number(r.f) };
    });
    const totals = all.reduce((a, r) => ({ bytes: a.bytes + r.bytes, pkts: a.pkts + r.pkts, flows: a.flows + r.flows }), { bytes: 0, pkts: 0, flows: 0 });
    const top = all.slice(0, spec.topN);
    const rest = all.slice(spec.topN).reduce((a, r) => ({ bytes: a.bytes + r.bytes, pkts: a.pkts + r.pkts, flows: a.flows + r.flows, rows: a.rows + 1 }), { bytes: 0, pkts: 0, flows: 0, rows: 0 });
    return { rows: top, totalRows: all.length, totals, other: rest };
  }

  /* -------------------------------------------------------------- SNMP queries */

  private snmpTier(retention: Retention, from: number, now = Date.now()): 'raw' | 'h1' {
    return from >= now - retention.sRaw * DAY_MS ? 'raw' : 'h1';
  }

  ifSeries(dev: number, ifIndex: number, range: TimeRange, retention: Retention, points: number): IfSeries {
    const tier = this.snmpTier(retention, range.from);
    const step = Math.max(60_000, Math.ceil((range.to - range.from) / Math.max(1, points) / 60_000) * 60_000);
    let rows: Record<string, number>[] = [];
    if (tier === 'raw') {
      const tabs = this.tablesFor('snmpif', range);
      if (tabs.length) {
        const args: SqlArg[] = [];
        const u = tabs.map(t => { args.push(dev, ifIndex, range.from, range.to); return `SELECT * FROM ${t} WHERE dev = ? AND if_index = ? AND ts BETWEEN ? AND ?`; }).join(' UNION ALL ');
        rows = this.db.prepare(`WITH s AS (${u}) SELECT (ts / ${step}) * ${step} AS b, AVG(util_in) AS ui, AVG(util_out) AS uo, AVG(in_bps) AS ib, AVG(out_bps) AS ob, SUM(in_disc + out_disc) AS dc, SUM(in_err + out_err) AS er FROM s GROUP BY b ORDER BY b`).all(...args) as any;
      }
    } else {
      rows = this.db.prepare(`SELECT (ts / ${step}) * ${step} AS b, AVG(util_in) AS ui, AVG(util_out) AS uo, AVG(in_bps) AS ib, AVG(out_bps) AS ob, SUM(disc) AS dc, SUM(err) AS er FROM snmp_if_1h WHERE dev = ? AND if_index = ? AND ts BETWEEN ? AND ? GROUP BY b ORDER BY b`).all(dev, ifIndex, range.from, range.to) as any;
    }
    return { step, tier, points: rows.map(r => ({ ts: r.b, utilIn: r.ui ?? 0, utilOut: r.uo ?? 0, inBps: r.ib ?? 0, outBps: r.ob ?? 0, disc: r.dc ?? 0, err: r.er ?? 0 })) };
  }

  classSeries(dev: number, ifIndex: number, range: TimeRange, retention: Retention, points: number): ClassSeries {
    const tier = this.snmpTier(retention, range.from);
    const step = Math.max(60_000, Math.ceil((range.to - range.from) / Math.max(1, points) / 60_000) * 60_000);
    let rows: Record<string, any>[] = [];
    if (tier === 'raw') {
      const tabs = this.tablesFor('snmpcls', range);
      if (tabs.length) {
        const args: SqlArg[] = [];
        const u = tabs.map(t => { args.push(dev, ifIndex, range.from, range.to); return `SELECT * FROM ${t} WHERE dev = ? AND if_index = ? AND ts BETWEEN ? AND ?`; }).join(' UNION ALL ');
        rows = this.db.prepare(`WITH s AS (${u}) SELECT cls, (ts / ${step}) * ${step} AS b, SUM(drop_pkts) AS dp, SUM(pre_pkts) AS pp, SUM(drop_bytes) AS db, SUM(post_bytes) AS sb, SUM(dt) AS secs, MAX(qdepth) AS qd FROM s GROUP BY cls, b ORDER BY cls, b`).all(...args) as any;
      }
    } else {
      rows = this.db.prepare(`SELECT cls, (ts / ${step}) * ${step} AS b, SUM(drop_pkts) AS dp, SUM(pre_pkts) AS pp, SUM(drop_bytes) AS db, SUM(post_bytes) AS sb, SUM(secs) AS secs, MAX(qdepth) AS qd FROM snmp_cls_1h WHERE dev = ? AND if_index = ? AND ts BETWEEN ? AND ? GROUP BY cls, b ORDER BY cls, b`).all(dev, ifIndex, range.from, range.to) as any;
    }
    const by = new Map<string, ClassSeries['classes'][number]>();
    for (const r of rows) {
      let c = by.get(r.cls);
      if (!c) { c = { cls: r.cls, points: [] }; by.set(r.cls, c); }
      const secs = r.secs > 0 ? r.secs : 1;
      c.points.push({ ts: r.b, dropPct: r.pp > 0 ? 100 * r.dp / r.pp : 0, dropBps: r.db / secs, dropPps: r.dp / secs, sentBps: r.sb / secs, qdepth: r.qd ?? 0 });
    }
    return { step, tier, classes: [...by.values()] };
  }

  classLatest(sinceMs: number): ClassLatest[] {
    const range = { from: sinceMs, to: Date.now() + 60_000 };
    const tabs = this.tablesFor('snmpcls', range);
    if (!tabs.length) return [];
    const args: SqlArg[] = [];
    const u = tabs.map(t => { args.push(range.from, range.to); return `SELECT * FROM ${t} WHERE ts BETWEEN ? AND ?`; }).join(' UNION ALL ');
    const rows = this.db.prepare(`WITH s AS (${u}) SELECT dev, if_index, cls, SUM(drop_pkts) AS dp, SUM(pre_pkts) AS pp, SUM(drop_bytes) AS db, SUM(post_bytes) AS sb, SUM(dt) AS secs, MAX(ts) AS ts,
      (SELECT qdepth FROM s s2 WHERE s2.dev = s.dev AND s2.if_index = s.if_index AND s2.cls = s.cls ORDER BY s2.ts DESC LIMIT 1) AS qd FROM s GROUP BY dev, if_index, cls`).all(...args) as any[];
    return rows.map(r => ({ dev: r.dev, ifIndex: r.if_index, cls: r.cls, dropPct: r.pp > 0 ? 100 * r.dp / r.pp : 0, dropPkts: r.dp, dropBytes: r.db, sentBps: r.sb / Math.max(1, r.secs), qdepth: r.qd ?? 0, ts: r.ts }));
  }

  ifLatest(sinceMs: number): IfLatest[] {
    const range = { from: sinceMs, to: Date.now() + 60_000 };
    const tabs = this.tablesFor('snmpif', range);
    if (!tabs.length) return [];
    const args: SqlArg[] = [];
    const u = tabs.map(t => { args.push(range.from, range.to); return `SELECT * FROM ${t} WHERE ts BETWEEN ? AND ?`; }).join(' UNION ALL ');
    const rows = this.db.prepare(`WITH s AS (${u}) SELECT dev, if_index, AVG(util_in) AS ui, AVG(util_out) AS uo, AVG(in_bps) AS ib, AVG(out_bps) AS ob, SUM(in_disc + out_disc) AS dc, SUM(in_err + out_err) AS er, MAX(ts) AS ts FROM s GROUP BY dev, if_index`).all(...args) as any[];
    return rows.map(r => ({ dev: r.dev, ifIndex: r.if_index, utilIn: r.ui ?? 0, utilOut: r.uo ?? 0, inBps: r.ib ?? 0, outBps: r.ob ?? 0, disc: r.dc ?? 0, err: r.er ?? 0, ts: r.ts }));
  }

  deleteDevice(dev: number): void {
    this.tx(() => {
      for (const t of this.tables('snmpif')) this.db.prepare(`DELETE FROM ${t} WHERE dev = ?`).run(dev);
      for (const t of this.tables('snmpcls')) this.db.prepare(`DELETE FROM ${t} WHERE dev = ?`).run(dev);
      this.db.prepare('DELETE FROM snmp_if_1h WHERE dev = ?').run(dev);
      this.db.prepare('DELETE FROM snmp_cls_1h WHERE dev = ?').run(dev);
    });
  }

  /* -------------------------------------------------------------- maintenance */

  private meta(k: string, d: number): number {
    const r = this.db.prepare('SELECT v FROM meta WHERE k = ?').get(k) as { v: string } | undefined;
    return r ? Number(r.v) : d;
  }
  private setMeta(k: string, v: number): void {
    this.db.prepare('INSERT INTO meta(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v').run(k, String(v));
  }

  /** Rolls raw data up into 1-minute, 1-hour and daily tables, then removes data past its retention. */
  maintain(ret: Retention, now = Date.now()): { dropped: string[] } {
    this.rollupAll(now);
    const dropped: string[] = [];
    const cut = (days: number) => now - days * DAY_MS;
    const dayLimit = (days: number) => ymd(cut(days));
    for (const [prefix, days] of [['flows', ret.raw], ['snmpif', ret.sRaw], ['snmpcls', ret.sRaw]] as const) {
      const lim = dayLimit(days);
      for (const t of this.tables(prefix)) {
        if (t.slice(prefix.length + 1) < lim) { this.db.exec(`DROP TABLE IF EXISTS ${t}`); this.created.delete(t); this.insStmts.delete('f' + t); this.insStmts.delete('i' + t); this.insStmts.delete('c' + t); dropped.push(t); }
      }
    }
    for (const [t, days] of [['flow_1m', ret.m1], ['flow_1h', ret.h1], ['flow_1d', ret.d1]] as const) {
      const r = this.db.prepare(`DELETE FROM ${t} WHERE ts < ?`).run(cut(days));
      if (Number(r.changes) > 0) dropped.push(`${t} (${r.changes} rows)`);
    }
    const r2 = this.db.prepare('DELETE FROM snmp_if_1h WHERE ts < ?').run(cut(ret.sH));
    const r3 = this.db.prepare('DELETE FROM snmp_cls_1h WHERE ts < ?').run(cut(ret.sH));
    if (Number(r2.changes) + Number(r3.changes) > 0) dropped.push(`snmp hourly (${Number(r2.changes) + Number(r3.changes)} rows)`);
    if (dropped.length) { try { this.db.exec('PRAGMA incremental_vacuum(2000)'); } catch { /* ignore */ } this.tableCache = null; this.statsCache = null; }
    return { dropped };
  }

  private rollupAll(now: number): void {
    const MIN = 60_000, HOUR = 3600_000;
    // flows: raw -> 1m. Progress is tracked per raw table by row number, not by time, so a record that arrives late (or
    // is loaded after the fact) is still counted exactly once. Totals are added into the minute the record ended in.
    for (const t of this.tables('flows').sort()) {
      const key = 'rid_' + t;
      const done = this.meta(key, 0);
      const top = (this.db.prepare(`SELECT MAX(rowid) AS m FROM ${t}`).get() as { m: number | null }).m ?? 0;
      if (top <= done) continue;
      for (let lo = done; lo < top; lo += 200_000) {
        const hi = Math.min(top, lo + 200_000);
        this.tx(() => {
          this.db.prepare(`INSERT INTO flow_1m (ts, exporter, in_if, vlan, src_mac, dst_mac, src_ip, dst_ip, src_n, dst_n, proto, dport, svc, dscp, post_dscp, bytes, pkts, flows)
            SELECT (ts1 / ${MIN}) * ${MIN}, exporter, COALESCE(in_if, 0), COALESCE(vlan, 0), COALESCE(src_mac, ''), COALESCE(dst_mac, ''), src_ip, dst_ip, src_n, dst_n, proto, COALESCE(dport, 0), MIN(COALESCE(sport, 0), COALESCE(dport, 0)), tos >> 2,
                   COALESCE(post_tos >> 2, -1), SUM(bytes), SUM(pkts), COUNT(*)
            FROM ${t} WHERE primary_hop = 1 AND rowid > ? AND rowid <= ?
            GROUP BY 1, exporter, 3, 4, 5, 6, src_ip, dst_ip, proto, 12, 13, 14, 15
            ON CONFLICT DO UPDATE SET bytes = bytes + excluded.bytes, pkts = pkts + excluded.pkts, flows = flows + excluded.flows`).run(lo, hi);
          this.setMeta(key, hi);
        });
      }
    }
    // forget progress for raw tables that retention has removed
    const live = new Set(this.tables('flows'));
    for (const r of this.db.prepare("SELECT k FROM meta WHERE k LIKE 'rid\\_%' ESCAPE '\\'").all() as unknown as { k: string }[]) if (!live.has(r.k.slice(4))) this.db.prepare('DELETE FROM meta WHERE k = ?').run(r.k);
    // 1m -> 1h -> 1d. An hour is closed 30 minutes after it ends; records later than that stay in the 1-minute table only.
    this.chain('flow_1m', 'flow_1h', 'wm_1h', HOUR, now - 30 * MIN, now);
    this.chain('flow_1h', 'flow_1d', 'wm_1d', 24 * HOUR, Math.floor(this.meta('wm_1h', 0) / (24 * HOUR)) * 24 * HOUR, now);
    // SNMP hourly
    this.snmpHourly(now);
  }

  private chain(from: string, to: string, key: string, size: number, available: number, now: number): void {
    const complete = Math.floor(Math.min(available, now) / size) * size;
    let wm = this.meta(key, 0);
    if (wm === 0) {
      const r = this.db.prepare(`SELECT MIN(ts) AS m FROM ${from}`).get() as { m: number | null };
      if (r.m === null) return;
      wm = Math.floor(r.m / size) * size;
    }
    if (wm >= complete) return;
    for (let a = wm; a < complete; a += size) {
      const b = a + size;
      this.tx(() => {
        this.db.prepare(`INSERT INTO ${to} (ts, exporter, in_if, vlan, src_mac, dst_mac, src_ip, dst_ip, src_n, dst_n, proto, dport, svc, dscp, post_dscp, bytes, pkts, flows)
          SELECT ${a}, exporter, in_if, vlan, src_mac, dst_mac, src_ip, dst_ip, src_n, dst_n, proto, dport, svc, dscp, post_dscp, SUM(bytes), SUM(pkts), SUM(flows)
          FROM ${from} WHERE ts >= ? AND ts < ? GROUP BY exporter, in_if, vlan, src_mac, dst_mac, src_ip, dst_ip, proto, dport, svc, dscp, post_dscp
          ON CONFLICT DO UPDATE SET bytes = bytes + excluded.bytes, pkts = pkts + excluded.pkts, flows = flows + excluded.flows`).run(a, b);
        this.setMeta(key, b);
      });
    }
  }

  private snmpHourly(now: number): void {
    const HOUR = 3600_000;
    const complete = Math.floor((now - 5 * 60_000) / HOUR) * HOUR;
    let wm = this.meta('wm_snmp', 0);
    if (wm === 0) {
      let first: number | null = null;
      for (const n of this.tables('snmpif').sort()) {
        const r = this.db.prepare(`SELECT MIN(ts) AS m FROM ${n}`).get() as { m: number | null };
        if (r.m !== null) { first = r.m; break; }
      }
      if (first === null) return;
      wm = Math.floor(first / HOUR) * HOUR;
    }
    for (let a = wm; a < complete; a += HOUR) {
      const b = a + HOUR;
      this.tx(() => {
        for (const t of this.tablesFor('snmpif', { from: a, to: b - 1 })) {
          this.db.prepare(`INSERT INTO snmp_if_1h (ts, dev, if_index, secs, util_in, util_out, util_out_max, in_bps, out_bps, disc, err)
            SELECT ${a}, dev, if_index, SUM(dt), AVG(util_in), AVG(util_out), MAX(util_out), AVG(in_bps), AVG(out_bps), SUM(in_disc + out_disc), SUM(in_err + out_err)
            FROM ${t} WHERE ts >= ? AND ts < ? GROUP BY dev, if_index
            ON CONFLICT DO UPDATE SET secs = secs + excluded.secs, util_out_max = MAX(util_out_max, excluded.util_out_max), disc = disc + excluded.disc, err = err + excluded.err`).run(a, b);
        }
        for (const t of this.tablesFor('snmpcls', { from: a, to: b - 1 })) {
          this.db.prepare(`INSERT INTO snmp_cls_1h (ts, dev, if_index, cls, secs, pre_pkts, pre_bytes, post_bytes, drop_pkts, drop_bytes, qdepth)
            SELECT ${a}, dev, if_index, cls, SUM(dt), SUM(pre_pkts), SUM(pre_bytes), SUM(post_bytes), SUM(drop_pkts), SUM(drop_bytes), MAX(qdepth)
            FROM ${t} WHERE ts >= ? AND ts < ? GROUP BY dev, if_index, cls
            ON CONFLICT DO UPDATE SET secs = secs + excluded.secs, pre_pkts = pre_pkts + excluded.pre_pkts, pre_bytes = pre_bytes + excluded.pre_bytes,
              post_bytes = post_bytes + excluded.post_bytes, drop_pkts = drop_pkts + excluded.drop_pkts, drop_bytes = drop_bytes + excluded.drop_bytes, qdepth = MAX(qdepth, excluded.qdepth)`).run(a, b);
        }
        this.setMeta('wm_snmp', b);
      });
    }
  }

  /* -------------------------------------------------------------- stats */

  stats(): Omit<StoreStats, 'backend' | 'dropped'> {
    const now = Date.now();
    if (!this.statsCache || now - this.statsCache.at > 15_000) {
      const flows = this.tables('flows').sort();
      let rawRows = 0, oldest: number | null = null, newest: number | null = null;
      for (const t of flows) {
        const r = this.db.prepare(`SELECT COUNT(*) AS n, MIN(ts1) AS a, MAX(ts1) AS b FROM ${t}`).get() as { n: number; a: number | null; b: number | null };
        rawRows += r.n; if (r.a !== null && (oldest === null || r.a < oldest)) oldest = r.a; if (r.b !== null && (newest === null || r.b > newest)) newest = r.b;
      }
      const cnt = (t: string) => (this.db.prepare(`SELECT COUNT(*) AS n FROM ${t}`).get() as { n: number }).n;
      let snmpRaw = 0;
      for (const t of [...this.tables('snmpif'), ...this.tables('snmpcls')]) snmpRaw += cnt(t);
      this.statsCache = {
        at: now,
        v: { rawDays: flows.length, rawRows, m1Rows: cnt('flow_1m'), h1Rows: cnt('flow_1h'), d1Rows: cnt('flow_1d'), snmpRawRows: snmpRaw, snmpHourlyRows: cnt('snmp_if_1h') + cnt('snmp_cls_1h'), oldestFlow: oldest, newestFlow: newest }
      };
    }
    let bytes = 0;
    for (const f of ['ts.db', 'ts.db-wal']) { try { bytes += fs.statSync(path.join(this.dir, f)).size; } catch { /* missing */ } }
    return { ...this.statsCache!.v, ingested: this.ingested, bytesOnDisk: bytes };
  }
}

/* ------------------------------------------------------------------ column maps */

interface ColMap {
  srcIp: string; dstIp: string; srcN: string; dstN: string; sport: string | null; dport: string; proto: string; vlan: string;
  srcMac: string; dstMac: string; exporter: string; inIf: string; dscp: string; postDscp: string; flags: string | null; svc: string; outIf: string | null;
  /** True when the table has TTL columns (raw flow tables only). */
  rawTtl: boolean;
}
const RAW_COLS: ColMap = {
  srcIp: 'src_ip', dstIp: 'dst_ip', srcN: 'src_n', dstN: 'dst_n', sport: 'sport', dport: 'dport', proto: 'proto', vlan: 'vlan',
  srcMac: 'src_mac', dstMac: 'dst_mac', exporter: 'exporter', inIf: 'in_if', dscp: '(tos >> 2)', postDscp: '(CASE WHEN post_tos IS NULL THEN NULL ELSE post_tos >> 2 END)', flags: 'flags', svc: 'MIN(COALESCE(sport, 0), COALESCE(dport, 0))', outIf: 'out_if', rawTtl: true
};
const ROLLUP_MAP: ColMap = {
  srcIp: 'src_ip', dstIp: 'dst_ip', srcN: 'src_n', dstN: 'dst_n', sport: null, dport: 'dport', proto: 'proto', vlan: 'vlan',
  srcMac: 'src_mac', dstMac: 'dst_mac', exporter: 'exporter', inIf: 'in_if', dscp: 'dscp', postDscp: 'post_dscp', flags: null, svc: 'svc', outIf: null, rawTtl: false
};

function likeEsc(s: string): string { return s.replace(/[\\%_]/g, m => '\\' + m); }
function emptyReport(): ReportResult { return { rows: [], totalRows: 0, totals: { bytes: 0, pkts: 0, flows: 0 }, other: { bytes: 0, pkts: 0, flows: 0, rows: 0 } }; }

export { ymdToMs };
