import type { AppLog } from '../logger.js';
import type { FlowRecord } from '../collector/types.js';
import type { Retention } from '../settings.js';
import {
  DAY_MS, type ClassLatest, type ClassSeries, type ClsPoint, type Cond, type IfLatest, type IfPoint, type IfSeries, type IpMatch,
  type ReportDim, type ReportResult, type ReportRow, type ReportSpec, type StoreStats, type StreamPage, type StreamQuery, type StreamRow, type TimeRange, type TsStore
} from './types.js';
import { skeyOf, ymd } from './util.js';
import { ttlSql, type SqlDialect } from '../analysis/ttl.js';

/*
 * ClickHouse storage backend (experimental). Talks to the server over its HTTP interface, so it has no native dependencies.
 *
 * Layout: flow_raw (daily partitions) feeds flow_1m through a materialized view, so the 1-minute tier is exact and needs no
 * bookkeeping. 1h and 1d are filled by maintain() from the tier below, once the hour/day is closed, tracked in `meta`.
 * SNMP raw tables roll up to hourly the same way. Retention drops daily partitions and deletes old rollup rows.
 */

const MIN = 60_000, HOUR = 3600_000;

/* ------------------------------------------------------------------ literals */

function S(s: string): string {
  return "'" + s.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n').replace(/\r/g, '\\r').replace(/\0/g, '\\0') + "'";
}
function N(n: number): string {
  if (!Number.isFinite(n)) throw new Error('invalid number in query');
  return String(n);
}
const num = (v: unknown, d = 0): number => (typeof v === 'number' && Number.isFinite(v) ? v : d);
const nul = (v: number | null | undefined): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);

/* ------------------------------------------------------------------ http client */

interface ChOpts { settings?: Record<string, string | number>; body?: string; noDb?: boolean; timeoutMs?: number }

class ChClient {
  private origin: string;
  readonly db: string;
  private auth: string | null = null;

  constructor(url: string) {
    const u = new URL(url);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('FLOWSCOPE_CLICKHOUSE_URL must start with http:// or https://');
    this.origin = u.origin;
    this.db = decodeURIComponent(u.pathname.replace(/^\/+|\/+$/g, '')) || 'flowscope';
    if (!/^[A-Za-z0-9_]+$/.test(this.db)) throw new Error('ClickHouse database name may only contain letters, digits and underscores');
    if (u.username) this.auth = 'Basic ' + Buffer.from(decodeURIComponent(u.username) + ':' + decodeURIComponent(u.password)).toString('base64');
  }

  async raw(sql: string, o: ChOpts = {}): Promise<string> {
    const p = new URLSearchParams();
    if (!o.noDb) p.set('database', this.db);
    p.set('output_format_json_quote_64bit_integers', '0');
    p.set('output_format_json_quote_denormals', '0');
    for (const [k, v] of Object.entries(o.settings || {})) p.set(k, String(v));
    let body: string;
    if (o.body !== undefined) { p.set('query', sql); body = o.body; } else body = sql;
    const headers: Record<string, string> = { 'Content-Type': 'text/plain; charset=utf-8' };
    if (this.auth) headers.Authorization = this.auth;
    const res = await fetch(`${this.origin}/?${p.toString()}`, { method: 'POST', headers, body, signal: AbortSignal.timeout(o.timeoutMs ?? 120_000) });
    const text = await res.text();
    if (!res.ok) throw new Error(`ClickHouse ${res.status}: ${text.replace(/\s+/g, ' ').slice(0, 400)}`);
    return text;
  }

  async exec(sql: string, o: ChOpts = {}): Promise<void> { await this.raw(sql, o); }

  async rows<T = Record<string, any>>(sql: string): Promise<T[]> {
    const t = await this.raw(sql + '\nFORMAT JSONEachRow');
    const out: T[] = [];
    for (const line of t.split('\n')) if (line) out.push(JSON.parse(line));
    return out;
  }

  async insert(table: string, rows: object[]): Promise<void> {
    for (let i = 0; i < rows.length; i += 20_000) {
      const body = rows.slice(i, i + 20_000).map(r => JSON.stringify(r)).join('\n');
      await this.raw(`INSERT INTO ${table} FORMAT JSONEachRow`, { body, settings: { input_format_null_as_default: 1 } });
    }
  }
}

/* ------------------------------------------------------------------ schema */

const DAY_PART = (c: string) => `toYYYYMMDD(toDateTime(intDiv(${c}, 1000), 'UTC'))`;
const MON_PART = (c: string) => `toYYYYMM(toDateTime(intDiv(${c}, 1000), 'UTC'))`;

const ROLLUP_COLS = `ts Int64, exporter String, in_if UInt32, vlan Int32, src_mac String, dst_mac String, src_ip String, dst_ip String,
  proto UInt8, dport UInt16, svc UInt16, dscp UInt8, post_dscp Int16, bytes UInt64, pkts UInt64, flows UInt64`;
const ROLLUP_KEY = 'ts, exporter, in_if, vlan, src_mac, dst_mac, src_ip, dst_ip, proto, dport, svc, dscp, post_dscp';
const ROLLUP_KEYCOLS = ROLLUP_KEY.split(', ');

function rollupDdl(t: string): string {
  return `CREATE TABLE IF NOT EXISTS ${t} (${ROLLUP_COLS}) ENGINE = SummingMergeTree((bytes, pkts, flows)) PARTITION BY ${MON_PART('ts')} ORDER BY (${ROLLUP_KEY})`;
}

const DDL: string[] = [
  `CREATE TABLE IF NOT EXISTS meta (k String, v Int64, ver UInt64) ENGINE = ReplacingMergeTree(ver) ORDER BY k`,
  `CREATE TABLE IF NOT EXISTS flow_raw (
    ts0 Int64, ts1 Int64, exporter String, in_if UInt32, out_if UInt32, src_ip String, dst_ip String, proto UInt8, sport UInt16, dport UInt16, flags UInt16,
    tos UInt8, post_tos Nullable(UInt8), ttl_min Nullable(UInt8), ttl_max Nullable(UInt8), nbytes UInt64, npkts UInt64,
    src_mac Nullable(String), dst_mac Nullable(String), vlan Nullable(UInt16), nat_src Nullable(String), nat_dst Nullable(String),
    nat_sport Nullable(UInt16), nat_dport Nullable(UInt16), next_hop Nullable(String), skey String, primary_hop UInt8,
    INDEX ix_skey skey TYPE bloom_filter(0.01) GRANULARITY 4)
    ENGINE = MergeTree PARTITION BY ${DAY_PART('ts1')} ORDER BY (ts1, skey)`,
  rollupDdl('flow_1m'), rollupDdl('flow_1h'), rollupDdl('flow_1d'),
  // raw -> 1m is done at insert time. Only the primary hop is counted, so bytes are not multiplied by the number of exporters.
  `CREATE MATERIALIZED VIEW IF NOT EXISTS flow_1m_mv TO flow_1m AS
    SELECT intDiv(ts1, 60000) * 60000 AS ts, exporter, in_if, ifNull(vlan, 0) AS vlan, ifNull(src_mac, '') AS src_mac, ifNull(dst_mac, '') AS dst_mac,
           src_ip, dst_ip, proto, dport, least(sport, dport) AS svc, bitShiftRight(tos, 2) AS dscp, ifNull(bitShiftRight(post_tos, 2), -1) AS post_dscp,
           sum(nbytes) AS bytes, sum(npkts) AS pkts, count() AS flows
    FROM flow_raw WHERE primary_hop = 1
    GROUP BY ts, exporter, in_if, vlan, src_mac, dst_mac, src_ip, dst_ip, proto, dport, svc, dscp, post_dscp`,
  `CREATE TABLE IF NOT EXISTS snmp_if (ts Int64, dev Int64, if_index UInt32, dt Float64, in_bps Float64, out_bps Float64, util_in Float64, util_out Float64,
    in_disc Int64, out_disc Int64, in_err Int64, out_err Int64, oper Int32) ENGINE = MergeTree PARTITION BY ${DAY_PART('ts')} ORDER BY (dev, if_index, ts)`,
  `CREATE TABLE IF NOT EXISTS snmp_cls (ts Int64, dev Int64, if_index UInt32, cls String, dt Float64, pre_pkts Int64, pre_bytes Int64, post_bytes Int64,
    drop_pkts Int64, drop_bytes Int64, qdepth Int64) ENGINE = MergeTree PARTITION BY ${DAY_PART('ts')} ORDER BY (dev, if_index, ts)`,
  `CREATE TABLE IF NOT EXISTS snmp_if_1h (ts Int64, dev Int64, if_index UInt32, secs SimpleAggregateFunction(sum, Float64), n SimpleAggregateFunction(sum, UInt64),
    util_in_s SimpleAggregateFunction(sum, Float64), util_out_s SimpleAggregateFunction(sum, Float64), in_bps_s SimpleAggregateFunction(sum, Float64),
    out_bps_s SimpleAggregateFunction(sum, Float64), disc SimpleAggregateFunction(sum, Int64), err SimpleAggregateFunction(sum, Int64))
    ENGINE = AggregatingMergeTree PARTITION BY ${MON_PART('ts')} ORDER BY (dev, if_index, ts)`,
  `CREATE TABLE IF NOT EXISTS snmp_cls_1h (ts Int64, dev Int64, if_index UInt32, cls String, secs SimpleAggregateFunction(sum, Float64),
    pre_pkts SimpleAggregateFunction(sum, Int64), pre_bytes SimpleAggregateFunction(sum, Int64), post_bytes SimpleAggregateFunction(sum, Int64),
    drop_pkts SimpleAggregateFunction(sum, Int64), drop_bytes SimpleAggregateFunction(sum, Int64), qdepth SimpleAggregateFunction(max, Int64))
    ENGINE = AggregatingMergeTree PARTITION BY ${MON_PART('ts')} ORDER BY (dev, if_index, cls, ts)`
];

/* ------------------------------------------------------------------ predicates */

const CH_DIALECT: SqlDialect = { nn: e => `ifNull((${e}), 0)`, startsWith: (col, p) => `startsWith(${col}, ${S(p)})`, str: S };
const addrOnly = (l: readonly string[] = []) => l.filter(x => /^[0-9a-fA-F:.]{2,45}$/.test(x));
function rawTtlSql(local?: readonly string[]) {
  return ttlSql(CH_DIALECT, { ttl: 'ttl_min', srcIp: 'src_ip', dstIp: 'dst_ip', srcN: 'IPv4StringToNumOrNull(src_ip)', dstN: 'IPv4StringToNumOrNull(dst_ip)', proto: 'proto', sport: 'sport', dport: 'dport', exporter: 'exporter' }, addrOnly(local));
}

interface Cm {
  srcIp: string; dstIp: string; srcN: string; dstN: string; sport: string | null; dport: string; proto: string; vlan: string;
  srcMac: string; dstMac: string; exporter: string; inIf: string; dscp: string; postDscp: string; flags: string | null; svc: string; outIf: string | null;
  bytes: string; pkts: string; flows: string;
  rawTtl: boolean;
}
const RAW: Cm = {
  srcIp: 'src_ip', dstIp: 'dst_ip', srcN: 'IPv4StringToNumOrNull(src_ip)', dstN: 'IPv4StringToNumOrNull(dst_ip)', sport: 'sport', dport: 'dport', proto: 'proto', vlan: 'vlan',
  srcMac: 'src_mac', dstMac: 'dst_mac', exporter: 'exporter', inIf: 'in_if', dscp: 'bitShiftRight(tos, 2)', postDscp: 'ifNull(bitShiftRight(post_tos, 2), -1)',
  flags: 'flags', svc: 'least(sport, dport)', outIf: 'out_if', bytes: 'nbytes', pkts: 'npkts', flows: '1', rawTtl: true
};
const ROLL: Cm = {
  srcIp: 'src_ip', dstIp: 'dst_ip', srcN: 'IPv4StringToNumOrNull(src_ip)', dstN: 'IPv4StringToNumOrNull(dst_ip)', sport: null, dport: 'dport', proto: 'proto', vlan: 'vlan',
  srcMac: 'src_mac', dstMac: 'dst_mac', exporter: 'exporter', inIf: 'in_if', dscp: 'dscp', postDscp: 'post_dscp', flags: null, svc: 'svc', outIf: null,
  bytes: 'bytes', pkts: 'pkts', flows: 'flows', rawTtl: false
};

function ipPred(col: string, nExpr: string, ms: IpMatch[]): string {
  const parts: string[] = [];
  for (const m of ms) {
    if (m.lo !== undefined && m.hi !== undefined) parts.push(`ifNull(${nExpr} BETWEEN ${N(m.lo)} AND ${N(m.hi)}, 0)`);
    else if (m.text !== undefined) parts.push(`startsWith(${col}, ${S(m.text)})`);
  }
  return parts.length ? '(' + parts.join(' OR ') + ')' : '0';
}
const numIn = (col: string, vals: number[]): string => (vals.length ? `${col} IN (${vals.map(N).join(',')})` : '0');
const has = (col: string, text: string): string => `ifNull(position(${col}, ${S(text)}) > 0, 0)`;
const portPred = (t: Cm, ports: number[]): string => (t.sport ? `(${numIn(t.sport, ports)} OR ${numIn(t.dport, ports)})` : numIn(t.dport, ports));

/** Record-level predicate that is a safe superset of the condition (used to find candidate streams). */
function recordPred(c: Cond, t: Cm, local?: readonly string[]): string {
  switch (c.kind) {
    case 'src': case 'dst': case 'ip': return `(${ipPred(t.srcIp, t.srcN, c.m)} OR ${ipPred(t.dstIp, t.dstN, c.m)})`;
    case 'port': case 'sport': case 'dport': return portPred(t, c.ports);
    case 'proto': return numIn(t.proto, c.protos);
    case 'vlan': return numIn(t.vlan, c.ids);
    case 'mac': { const x = c.text.toLowerCase(); return `(${has(t.srcMac, x)} OR ${has(t.dstMac, x)})`; }
    case 'exporter': return c.ips.length ? `${t.exporter} IN (${c.ips.map(S).join(',')})` : '0';
    case 'outif':
      if (!t.outIf) return '1';
      return c.ips.length ? `(${t.exporter} IN (${c.ips.map(S).join(',')}) AND ${t.outIf} = ${N(c.ifIndex)})` : '0';
    case 'ifport': {
      if (!c.ips.length) return '0';
      const exp = `${t.exporter} IN (${c.ips.map(S).join(',')})`;
      if (!c.ifIndex || !t.outIf) return exp;
      if (c.dir === 'in') return `(${exp} AND ${t.inIf} = ${N(c.ifIndex)})`;
      if (c.dir === 'out') return `(${exp} AND ${t.outIf} = ${N(c.ifIndex)})`;
      return `(${exp} AND (${t.inIf} = ${N(c.ifIndex)} OR ${t.outIf} = ${N(c.ifIndex)}))`;
    }
    case 'qos': return '1';
    case 'ttl': {
      if (!t.rawTtl) throw new Error('The TTL filter needs flow records. Pick the raw data tier.');
      const x = rawTtlSql(local);
      return c.mode === 'expired' ? x.any : `NOT ${x.any}`;
    }
    case 'dscp': return numIn(t.dscp, c.values);
    case 'text': {
      const x = c.text.toLowerCase();
      const parts = [`(${has(t.srcIp, x)} OR ${has(t.dstIp, x)} OR ${has(t.srcMac, x)} OR ${has(t.dstMac, x)})`];
      if (c.ips.length) parts.push(`${t.exporter} IN (${c.ips.map(S).join(',')})`);
      if (c.vlans.length) parts.push(numIn(t.vlan, c.vlans));
      if (c.ports.length) parts.push(portPred(t, c.ports));
      return '(' + parts.join(' OR ') + ')';
    }
  }
}

const RM = '(isNotNull(post_tos) AND bitShiftRight(assumeNotNull(post_tos), 2) != bitShiftRight(tos, 2))';

/* ------------------------------------------------------------------ store */

interface PrimaryEntry { exp: string; at: number }

export async function openClickHouse(url: string, log: AppLog): Promise<TsStore> {
  if (!url) throw new Error('FLOWSCOPE_CLICKHOUSE_URL is not set');
  const c = new ChClient(url);
  await c.exec(`CREATE DATABASE IF NOT EXISTS ${c.db}`, { noDb: true });
  for (const d of DDL) await c.exec(d);
  const v = (await c.rows<{ v: string }>('SELECT version() AS v'))[0]?.v;
  log.info('store', `ClickHouse ${v} ready (database ${c.db})`);
  return new ClickHouseStore(c);
}

class ClickHouseStore implements TsStore {
  readonly kind = 'clickhouse' as const;
  private primary = new Map<string, PrimaryEntry>();
  private ingested = 0;
  private dropped = 0;
  private statsCache: { at: number; v: Omit<StoreStats, 'backend' | 'ingested' | 'dropped'> } | null = null;
  private metaSeq = 0;

  constructor(private c: ChClient) {}

  /* ------------------------------------------------------------ inserts */

  async insertFlows(recs: FlowRecord[]): Promise<void> {
    if (!recs.length) return;
    const now = Date.now();
    const rows = recs.map(r => {
      const skey = skeyOf(r);
      const dirKey = skey + '>' + r.srcIp;
      let prim = 1;
      const e = this.primary.get(dirKey);
      if (e && now - e.at < 30 * 60_000) { prim = e.exp === r.exporter ? 1 : 0; e.at = now; } else this.primary.set(dirKey, { exp: r.exporter, at: now });
      return {
        ts0: num(r.ts0), ts1: num(r.ts1), exporter: r.exporter, in_if: num(r.inIf), out_if: num(r.outIf), src_ip: r.srcIp, dst_ip: r.dstIp, proto: num(r.proto),
        sport: num(r.sport), dport: num(r.dport), flags: num(r.flags), tos: num(r.tos), post_tos: nul(r.postTos), ttl_min: nul(r.ttlMin), ttl_max: nul(r.ttlMax),
        nbytes: num(r.bytes), npkts: num(r.pkts), src_mac: r.srcMac, dst_mac: r.dstMac, vlan: nul(r.vlan), nat_src: r.natSrcIp, nat_dst: r.natDstIp,
        nat_sport: nul(r.natSport), nat_dport: nul(r.natDport), next_hop: r.nextHop, skey, primary_hop: prim
      };
    });
    try { await this.c.insert('flow_raw', rows); } catch (e) { this.dropped += recs.length; throw e; }
    this.ingested += recs.length;
    if (this.primary.size > 1_500_000) {
      let n = 0;
      for (const k of this.primary.keys()) { this.primary.delete(k); if (++n > 300_000) break; }
    }
  }

  async insertSnmp(ifs: IfPoint[], cls: ClsPoint[]): Promise<void> {
    if (ifs.length) {
      await this.c.insert('snmp_if', ifs.map(p => ({
        ts: num(p.ts), dev: num(p.dev), if_index: num(p.ifIndex), dt: num(p.dt), in_bps: num(p.inBps), out_bps: num(p.outBps), util_in: num(p.utilIn), util_out: num(p.utilOut),
        in_disc: Math.round(num(p.inDisc)), out_disc: Math.round(num(p.outDisc)), in_err: Math.round(num(p.inErr)), out_err: Math.round(num(p.outErr)), oper: num(p.oper)
      })));
    }
    if (cls.length) {
      await this.c.insert('snmp_cls', cls.map(p => ({
        ts: num(p.ts), dev: num(p.dev), if_index: num(p.ifIndex), cls: p.cls, dt: num(p.dt), pre_pkts: Math.round(num(p.prePkts)), pre_bytes: Math.round(num(p.preBytes)),
        post_bytes: Math.round(num(p.postBytes)), drop_pkts: Math.round(num(p.dropPkts)), drop_bytes: Math.round(num(p.dropBytes)), qdepth: Math.round(num(p.qdepth))
      })));
    }
  }

  /* ------------------------------------------------------------ stream search */

  async searchStreams(q: StreamQuery): Promise<StreamPage> {
    if (!q.range || !Number.isFinite(q.range.from) || !Number.isFinite(q.range.to)) throw new Error('invalid time range');
    const inRange = `ts1 BETWEEN ${N(q.range.from)} AND ${N(q.range.to)}`;
    const cand = q.conds.filter(c => c.kind !== 'qos' && !(c.kind === 'ttl' && c.mode === 'ok')).map(c => `AND skey IN (SELECT skey FROM flow_raw WHERE ${inRange} AND ${recordPred(c, RAW, q.localIps)})`).join('\n');
    const tx = rawTtlSql(q.localIps);
    let ttlCond = '';
    const exact: string[] = [];
    let qos = '';
    for (const c of q.conds) {
      if (c.kind === 'src') exact.push(ipPred('i.i_ip', 'IPv4StringToNumOrNull(i.i_ip)', c.m));
      else if (c.kind === 'dst') exact.push(ipPred('i.i_dip', 'IPv4StringToNumOrNull(i.i_dip)', c.m));
      else if (c.kind === 'sport') exact.push(numIn('i.i_sp', c.ports));
      else if (c.kind === 'dport') exact.push(numIn('i.i_dp', c.ports));
      else if (c.kind === 'qos') qos = c.mode === 'changed' ? 'AND (t.tnd > 1 OR t.trm = 1)' : 'AND NOT (t.tnd > 1 OR t.trm = 1)';
      else if (c.kind === 'ttl') ttlCond = c.mode === 'expired' ? 'AND (t.ttx = 1 OR t.ttxi = 1)' : 'AND NOT (t.ttx = 1 OR t.ttxi = 1)';
    }
    const order = q.sort === 'bytes' ? 't.tb' : q.sort === 'pkts' ? 't.tp' : 't.tt1';
    const sql = `
      WITH d AS (
        SELECT skey AS k, src_ip AS s_ip, sport AS s_port, any(dst_ip) AS d_ip, any(dport) AS d_port, any(proto) AS pr,
               min(ts0) AS t0, max(ts1) AS t1,
               sumIf(nbytes, primary_hop = 1) AS b, sumIf(npkts, primary_hop = 1) AS p,
               uniqExact(bitShiftRight(tos, 2)) AS nd, argMin(bitShiftRight(tos, 2), ts0) AS d_in,
               min(bitShiftRight(tos, 2)) AS d_min, max(bitShiftRight(tos, 2)) AS d_max,
               max(${RM}) AS rm, maxIf(bitShiftRight(assumeNotNull(post_tos), 2), ${RM}) AS d_post,
               groupUniqArray(exporter) AS exps, max(vlan) AS vl, max(flags) AS fl,
               max(${tx.expired}) AS tx, max(${tx.icmp}) AS txi, minIf(ttl_min, ${tx.expired}) AS ttl_lo
        FROM flow_raw WHERE ${inRange} ${cand}
        GROUP BY skey, src_ip, sport),
      i AS (
        SELECT k, argMin(s_ip, t0) AS i_ip, argMin(d_ip, t0) AS i_dip, argMin(s_port, t0) AS i_sp, argMin(d_port, t0) AS i_dp, argMin(pr, t0) AS i_pr
        FROM d GROUP BY k),
      t AS (
        SELECT d.k AS k, min(d.t0) AS tt0, max(d.t1) AS tt1, sum(d.b) AS tb, sum(d.p) AS tp,
               sumIf(d.b, d.s_ip = i.i_ip AND d.s_port = i.i_sp) AS tfb, sumIf(d.p, d.s_ip = i.i_ip AND d.s_port = i.i_sp) AS tfp,
               max(d.nd) AS tnd, max(d.rm) AS trm, groupUniqArrayArray(d.exps) AS texps, max(d.vl) AS tvl, max(d.fl) AS tfl,
               min(d.d_min) AS tdmin, max(d.d_max) AS tdmax, max(d.d_post) AS tdpost,
               maxIf(d.d_in, d.s_ip = i.i_ip AND d.s_port = i.i_sp) AS tdin,
               max(d.tx) AS ttx, max(d.txi) AS ttxi, min(d.ttl_lo) AS tttl
        FROM d INNER JOIN i ON i.k = d.k GROUP BY d.k)
      SELECT i.k AS skey, i.i_ip AS src_ip, i.i_dip AS dst_ip, i.i_pr AS proto, i.i_sp AS sport, i.i_dp AS dport,
             t.tt0 AS t0, t.tt1 AS t1, t.tb AS b, t.tp AS p, t.tfb AS fb, t.tfp AS fp, t.texps AS exps, t.tvl AS vlan, t.tfl AS fl,
             t.tdin AS d_in, t.tdmin AS d_min, t.tdmax AS d_max, t.tdpost AS d_post, t.trm AS rm, t.ttx AS tx, t.ttxi AS txi, t.tttl AS ttl_lo,
             if(t.tnd > 1 OR t.trm = 1, 1, 0) AS qchg, count() OVER () AS total
      FROM i INNER JOIN t ON t.k = i.k
      WHERE 1 = 1 ${exact.length ? 'AND ' + exact.join(' AND ') : ''} ${qos} ${ttlCond}
      ORDER BY ${order} ${q.dir === 'asc' ? 'ASC' : 'DESC'}, t.tt1 DESC
      LIMIT ${N(Math.max(1, Math.trunc(q.limit)))}`;
    const rows = await this.c.rows<Record<string, any>>(sql);
    const total = rows.length ? Number(rows[0].total) : 0;
    const out: StreamRow[] = rows.map(r => {
      const qchg = Number(r.qchg) === 1;
      const dIn = Number(r.d_in);
      return {
        skey: String(r.skey), srcIp: String(r.src_ip), dstIp: String(r.dst_ip), proto: Number(r.proto), sport: Number(r.sport), dport: Number(r.dport),
        t0: Number(r.t0), t1: Number(r.t1), bytes: Number(r.b), pkts: Number(r.p), fwdBytes: Number(r.fb), revBytes: Number(r.b) - Number(r.fb),
        fwdPkts: Number(r.fp), revPkts: Number(r.p) - Number(r.fp),
        exporters: [...new Set<string>(r.exps as string[])], vlan: r.vlan === null || r.vlan === undefined ? null : Number(r.vlan),
        qosChanged: qchg, flags: Number(r.fl || 0), dscpIn: dIn,
        ttlExpired: Number(r.tx) === 1 || Number(r.txi) === 1, ttlReason: Number(r.tx) === 1 ? 'ttl' : Number(r.txi) === 1 ? 'icmp' : null,
        ttlLow: Number(r.tx) === 1 && r.ttl_lo !== null && r.ttl_lo !== undefined ? Number(r.ttl_lo) : null,
        dscpOut: qchg ? (Number(r.rm) === 1 ? Number(r.d_post) : (Number(r.d_max) !== dIn ? Number(r.d_max) : Number(r.d_min))) : null
      };
    });
    return { rows: out, total, truncated: total > out.length, tier: 'raw' };
  }

  async streamRecords(skey: string, range: TimeRange): Promise<(FlowRecord & { primary: boolean })[]> {
    const rows = await this.c.rows<Record<string, any>>(`SELECT * FROM flow_raw WHERE skey = ${S(skey)} AND ts1 BETWEEN ${N(range.from)} AND ${N(range.to)} ORDER BY ts0`);
    return rows.map(r => ({
      ts0: Number(r.ts0), ts1: Number(r.ts1), exporter: r.exporter, inIf: r.in_if, outIf: r.out_if, srcIp: r.src_ip, dstIp: r.dst_ip, proto: r.proto, sport: r.sport, dport: r.dport,
      flags: r.flags, tos: r.tos, postTos: r.post_tos, ttlMin: r.ttl_min, ttlMax: r.ttl_max, bytes: Number(r.nbytes), pkts: Number(r.npkts), srcMac: r.src_mac, dstMac: r.dst_mac,
      vlan: r.vlan, natSrcIp: r.nat_src, natDstIp: r.nat_dst, natSport: r.nat_sport, natDport: r.nat_dport, nextHop: r.next_hop, sampling: 1, primary: Number(r.primary_hop) === 1
    }));
  }

  /* ------------------------------------------------------------ reports */

  async report(spec: ReportSpec): Promise<ReportResult> {
    const raw = spec.tier === 'raw';
    const cm = raw ? RAW : ROLL;
    const where: string[] = [];
    let source: string;
    if (raw) {
      source = 'flow_raw';
      where.push(`ts1 BETWEEN ${N(spec.range.from)} AND ${N(spec.range.to)}`);
      where.push(spec.exporter ? `exporter = ${S(spec.exporter)}` : 'primary_hop = 1');
    } else {
      source = ({ m1: 'flow_1m', h1: 'flow_1h', d1: 'flow_1d' } as Record<string, string>)[spec.tier];
      where.push(`ts BETWEEN ${N(spec.range.from)} AND ${N(spec.range.to)}`);
      if (spec.exporter) where.push(`exporter = ${S(spec.exporter)}`);
    }
    for (const c of spec.conds) {
      const cc: Cond = spec.bidir && (c.kind === 'src' || c.kind === 'dst') ? { kind: 'ip', m: c.m } : c;
      if (cc.kind === 'qos') {
        const chg = `(${cm.postDscp} >= 0 AND ${cm.postDscp} != ${cm.dscp})`;
        where.push(cc.mode === 'changed' ? chg : `NOT ${chg}`);
      } else if (cc.kind === 'src') where.push(ipPred(cm.srcIp, cm.srcN, cc.m));
      else if (cc.kind === 'dst') where.push(ipPred(cm.dstIp, cm.dstN, cc.m));
      else if (cc.kind === 'sport') { if (cm.sport) where.push(numIn(cm.sport, cc.ports)); }
      else if (cc.kind === 'dport') where.push(numIn(cm.dport, cc.ports));
      else where.push(recordPred(cc, cm, spec.localIps));
    }
    const swp = `ifNull(${cm.srcN} > ${cm.dstN}, ${cm.srcIp} > ${cm.dstIp})`;
    const pick = (a: string, b: string) => (spec.bidir ? `if(${swp}, ${b}, ${a})` : a);
    const prefix = Math.max(0, Math.min(32, Math.trunc(spec.prefix)));
    const k = 32 - prefix;
    const sfx4 = prefix < 32 ? '/' + prefix : '', sfx6 = prefix < 32 ? '/128' : '';
    const ipExpr = (ip: string, n: string) => k === 0 ? ip
      : `if(isNotNull(${n}), concat(IPv4NumToString(toUInt32(bitShiftLeft(bitShiftRight(toUInt64(assumeNotNull(${n})), ${k}), ${k}))), ${S(sfx4)}), concat(${ip}, ${S(sfx6)}))`;
    const E: Record<ReportDim, string> = {
      srcMac: pick(cm.srcMac, cm.dstMac), dstMac: pick(cm.dstMac, cm.srcMac), vlan: cm.vlan,
      inIf: `concat(${cm.exporter}, '#', toString(${cm.inIf}))`,
      srcIp: ipExpr(pick(cm.srcIp, cm.dstIp), pick(cm.srcN, cm.dstN)), dstIp: ipExpr(pick(cm.dstIp, cm.srcIp), pick(cm.dstN, cm.srcN)),
      proto: cm.proto, dscp: cm.dscp, svc: cm.svc,
      qos: `if(${cm.postDscp} >= 0 AND ${cm.postDscp} != ${cm.dscp}, concat(toString(${cm.dscp}), '>', toString(${cm.postDscp})), 'unchanged')`,
      sport: cm.sport ? pick(cm.sport, cm.dport) : '0', dport: cm.sport ? pick(cm.dport, cm.sport) : pick(cm.dport, '0'), flags: cm.flags || '0'
    };
    const dims = spec.dims.filter(d => E[d] !== undefined);
    const sel = dims.map((d, i) => `${E[d]} AS d${i}`);
    const grp = dims.map((_, i) => `d${i}`);
    const orderCol = spec.sortBy === 'pkts' ? 'p' : spec.sortBy === 'flows' ? 'f' : 'b';
    const sql = `
      SELECT *, sum(b) OVER () AS tot_b, sum(p) OVER () AS tot_p, sum(f) OVER () AS tot_f, count() OVER () AS n_rows
      FROM (SELECT ${sel.length ? sel.join(', ') + ',' : ''} sum(${cm.bytes}) AS b, sum(${cm.pkts}) AS p, sum(${cm.flows}) AS f
            FROM ${source} WHERE ${where.join(' AND ')} ${grp.length ? 'GROUP BY ' + grp.join(', ') : ''})
      ORDER BY ${orderCol} DESC
      LIMIT ${N(Math.max(0, Math.trunc(spec.topN)))}`;
    const rows = await this.c.rows<Record<string, any>>(sql);
    if (!rows.length) {
      // top-N of zero, or nothing matched: still report totals
      const tot = (await this.c.rows<Record<string, any>>(`SELECT sum(${cm.bytes}) AS b, sum(${cm.pkts}) AS p, sum(${cm.flows}) AS f, 0 AS n FROM ${source} WHERE ${where.join(' AND ')}`))[0];
      const totals = { bytes: Number(tot?.b || 0), pkts: Number(tot?.p || 0), flows: Number(tot?.f || 0) };
      return { rows: [], totalRows: 0, totals, other: { ...totals, rows: 0 } };
    }
    const out: ReportRow[] = rows.map(r => {
      const dm: Record<string, string | number | null> = {};
      dims.forEach((d, i) => { dm[d] = r['d' + i] as string | number | null; });
      return { dims: dm, bytes: Number(r.b), pkts: Number(r.p), flows: Number(r.f) };
    });
    const totals = { bytes: Number(rows[0].tot_b), pkts: Number(rows[0].tot_p), flows: Number(rows[0].tot_f) };
    const shown = out.reduce((a, r) => ({ bytes: a.bytes + r.bytes, pkts: a.pkts + r.pkts, flows: a.flows + r.flows }), { bytes: 0, pkts: 0, flows: 0 });
    const totalRows = Number(rows[0].n_rows);
    return {
      rows: out, totalRows, totals,
      other: { bytes: totals.bytes - shown.bytes, pkts: totals.pkts - shown.pkts, flows: totals.flows - shown.flows, rows: Math.max(0, totalRows - out.length) }
    };
  }

  /* ------------------------------------------------------------ SNMP queries */

  private snmpTier(retention: Retention, from: number): 'raw' | 'h1' { return from >= Date.now() - retention.sRaw * DAY_MS ? 'raw' : 'h1'; }
  private step(range: TimeRange, points: number): number { return Math.max(MIN, Math.ceil((range.to - range.from) / Math.max(1, points) / MIN) * MIN); }

  async ifSeries(dev: number, ifIndex: number, range: TimeRange, retention: Retention, points: number): Promise<IfSeries> {
    const tier = this.snmpTier(retention, range.from);
    const step = this.step(range, points);
    const w = `dev = ${N(dev)} AND if_index = ${N(ifIndex)} AND ts BETWEEN ${N(range.from)} AND ${N(range.to)}`;
    const rows = tier === 'raw'
      ? await this.c.rows<Record<string, any>>(`SELECT intDiv(ts, ${step}) * ${step} AS bk, avg(util_in) AS ui, avg(util_out) AS uo, avg(in_bps) AS ib, avg(out_bps) AS ob,
          sum(in_disc + out_disc) AS dc, sum(in_err + out_err) AS er FROM snmp_if WHERE ${w} GROUP BY bk ORDER BY bk`)
      : await this.c.rows<Record<string, any>>(`SELECT intDiv(ts, ${step}) * ${step} AS bk, sum(util_in_s) / greatest(sum(n), 1) AS ui, sum(util_out_s) / greatest(sum(n), 1) AS uo,
          sum(in_bps_s) / greatest(sum(n), 1) AS ib, sum(out_bps_s) / greatest(sum(n), 1) AS ob, sum(disc) AS dc, sum(err) AS er FROM snmp_if_1h WHERE ${w} GROUP BY bk ORDER BY bk`);
    return { step, tier, points: rows.map(r => ({ ts: Number(r.bk), utilIn: r.ui ?? 0, utilOut: r.uo ?? 0, inBps: r.ib ?? 0, outBps: r.ob ?? 0, disc: Number(r.dc ?? 0), err: Number(r.er ?? 0) })) };
  }

  async classSeries(dev: number, ifIndex: number, range: TimeRange, retention: Retention, points: number): Promise<ClassSeries> {
    const tier = this.snmpTier(retention, range.from);
    const step = this.step(range, points);
    const w = `dev = ${N(dev)} AND if_index = ${N(ifIndex)} AND ts BETWEEN ${N(range.from)} AND ${N(range.to)}`;
    const t = tier === 'raw' ? 'snmp_cls' : 'snmp_cls_1h';
    const secs = tier === 'raw' ? 'dt' : 'secs';
    const rows = await this.c.rows<Record<string, any>>(`SELECT cls, intDiv(ts, ${step}) * ${step} AS bk, sum(drop_pkts) AS dp, sum(pre_pkts) AS pp, sum(drop_bytes) AS dbytes,
      sum(post_bytes) AS sb, sum(${secs}) AS secs_, max(qdepth) AS qd FROM ${t} WHERE ${w} GROUP BY cls, bk ORDER BY cls, bk`);
    const by = new Map<string, ClassSeries['classes'][number]>();
    for (const r of rows) {
      let c = by.get(r.cls);
      if (!c) { c = { cls: r.cls, points: [] }; by.set(r.cls, c); }
      const secs2 = r.secs_ > 0 ? r.secs_ : 1;
      const dp = Number(r.dp), pp = Number(r.pp);
      c.points.push({ ts: Number(r.bk), dropPct: pp > 0 ? 100 * dp / pp : 0, dropBps: Number(r.dbytes) / secs2, dropPps: dp / secs2, sentBps: Number(r.sb) / secs2, qdepth: Number(r.qd ?? 0) });
    }
    return { step, tier, classes: [...by.values()] };
  }

  async classLatest(sinceMs: number): Promise<ClassLatest[]> {
    const rows = await this.c.rows<Record<string, any>>(`SELECT dev, if_index, cls, sum(drop_pkts) AS dp, sum(pre_pkts) AS pp, sum(drop_bytes) AS dbytes, sum(post_bytes) AS sb,
      sum(dt) AS secs_, max(ts) AS mts, argMax(qdepth, ts) AS qd FROM snmp_cls WHERE ts BETWEEN ${N(sinceMs)} AND ${N(Date.now() + 60_000)} GROUP BY dev, if_index, cls`);
    return rows.map(r => ({
      dev: Number(r.dev), ifIndex: Number(r.if_index), cls: r.cls, dropPct: Number(r.pp) > 0 ? 100 * Number(r.dp) / Number(r.pp) : 0, dropPkts: Number(r.dp), dropBytes: Number(r.dbytes),
      sentBps: Number(r.sb) / Math.max(1, Number(r.secs_)), qdepth: Number(r.qd ?? 0), ts: Number(r.mts)
    }));
  }

  async ifLatest(sinceMs: number): Promise<IfLatest[]> {
    const rows = await this.c.rows<Record<string, any>>(`SELECT dev, if_index, avg(util_in) AS ui, avg(util_out) AS uo, avg(in_bps) AS ib, avg(out_bps) AS ob,
      sum(in_disc + out_disc) AS dc, sum(in_err + out_err) AS er, max(ts) AS mts FROM snmp_if WHERE ts BETWEEN ${N(sinceMs)} AND ${N(Date.now() + 60_000)} GROUP BY dev, if_index`);
    return rows.map(r => ({ dev: Number(r.dev), ifIndex: Number(r.if_index), utilIn: r.ui ?? 0, utilOut: r.uo ?? 0, inBps: r.ib ?? 0, outBps: r.ob ?? 0, disc: Number(r.dc ?? 0), err: Number(r.er ?? 0), ts: Number(r.mts) }));
  }

  async deleteDevice(dev: number): Promise<void> {
    for (const t of ['snmp_if', 'snmp_cls', 'snmp_if_1h', 'snmp_cls_1h']) await this.c.exec(`ALTER TABLE ${t} DELETE WHERE dev = ${N(dev)}`, { settings: { mutations_sync: 2 } });
    this.statsCache = null;
  }

  /* ------------------------------------------------------------ maintenance */

  private async meta(k: string): Promise<number | null> {
    const r = await this.c.rows<{ v: number }>(`SELECT v FROM meta FINAL WHERE k = ${S(k)}`);
    return r.length ? Number(r[0].v) : null;
  }
  private async setMeta(k: string, v: number): Promise<void> {
    await this.c.insert('meta', [{ k, v, ver: Date.now() * 1000 + (this.metaSeq++ % 1000) }]);
  }

  /** Rolls closed hours/days up from the tier below, then removes data past its retention. */
  async maintain(ret: Retention, now = Date.now()): Promise<{ dropped: string[] }> {
    await this.rollup(now);
    const dropped: string[] = [];
    const cut = (days: number) => now - days * DAY_MS;
    for (const [table, label, days] of [['flow_raw', 'flows', ret.raw], ['snmp_if', 'snmpif', ret.sRaw], ['snmp_cls', 'snmpcls', ret.sRaw]] as const) {
      const lim = ymd(cut(days));
      const parts = await this.c.rows<{ partition: string }>(`SELECT DISTINCT partition FROM system.parts WHERE database = ${S(this.c.db)} AND table = ${S(table)} AND active`);
      for (const p of parts) {
        if (/^\d{8}$/.test(p.partition) && p.partition < lim) {
          await this.c.exec(`ALTER TABLE ${table} DROP PARTITION ${p.partition}`);
          dropped.push(`${label}_${p.partition}`);
        }
      }
    }
    const del = async (t: string, days: number, label: string) => {
      const n = Number((await this.c.rows<{ n: number }>(`SELECT count() AS n FROM ${t} WHERE ts < ${N(cut(days))}`))[0]?.n || 0);
      if (n > 0) {
        await this.c.exec(`ALTER TABLE ${t} DELETE WHERE ts < ${N(cut(days))}`, { settings: { mutations_sync: 2 } });
        dropped.push(`${label} (${n} rows)`);
      }
    };
    await del('flow_1m', ret.m1, 'flow_1m');
    await del('flow_1h', ret.h1, 'flow_1h');
    await del('flow_1d', ret.d1, 'flow_1d');
    await del('snmp_if_1h', ret.sH, 'snmp hourly (interfaces)');
    await del('snmp_cls_1h', ret.sH, 'snmp hourly (classes)');
    this.statsCache = null;
    return { dropped };
  }

  private async rollup(now: number): Promise<void> {
    await this.chain('flow_1m', 'flow_1h', 'wm_1h', HOUR, now - 30 * MIN, now);
    await this.chain('flow_1h', 'flow_1d', 'wm_1d', 24 * HOUR, Math.floor(((await this.meta('wm_1h')) ?? 0) / (24 * HOUR)) * 24 * HOUR, now);
    await this.snmpHourly(now);
  }

  private async chain(from: string, to: string, key: string, size: number, available: number, now: number): Promise<void> {
    const complete = Math.floor(Math.min(available, now) / size) * size;
    let wm = await this.meta(key);
    if (wm === null) {
      const r = (await this.c.rows<{ m: number | null; n: number }>(`SELECT min(ts) AS m, count() AS n FROM ${from}`))[0];
      if (!r || !Number(r.n)) return;
      wm = Math.floor(Number(r.m) / size) * size;
    }
    const keyExpr = ROLLUP_KEYCOLS.map(x => (x === 'ts' ? `intDiv(ts, ${size}) * ${size}` : x)).join(', ');
    while (wm < complete) {
      const b = Math.min(complete, wm + 24 * size);
      // positional insert: the sum() columns must not be aliased to the names of the source columns
      await this.c.exec(`INSERT INTO ${to} (${ROLLUP_KEY}, bytes, pkts, flows)
        SELECT ${keyExpr}, sum(bytes), sum(pkts), sum(flows)
        FROM ${from} WHERE ts >= ${N(wm)} AND ts < ${N(b)}
        GROUP BY ${keyExpr}`);
      wm = b;
      await this.setMeta(key, wm);
    }
  }

  private async snmpHourly(now: number): Promise<void> {
    const complete = Math.floor((now - 5 * MIN) / HOUR) * HOUR;
    let wm = await this.meta('wm_snmp');
    if (wm === null) {
      const r = (await this.c.rows<{ m: number | null; n: number }>(`SELECT min(ts) AS m, count() AS n FROM snmp_if`))[0];
      const r2 = (await this.c.rows<{ m: number | null; n: number }>(`SELECT min(ts) AS m, count() AS n FROM snmp_cls`))[0];
      const firsts = [r, r2].filter(x => x && Number(x.n) > 0).map(x => Number(x.m));
      if (!firsts.length) return;
      wm = Math.floor(Math.min(...firsts) / HOUR) * HOUR;
    }
    while (wm < complete) {
      const b = Math.min(complete, wm + 24 * HOUR);
      const w = `ts >= ${N(wm)} AND ts < ${N(b)}`;
      await this.c.exec(`INSERT INTO snmp_if_1h (ts, dev, if_index, secs, n, util_in_s, util_out_s, in_bps_s, out_bps_s, disc, err)
        SELECT intDiv(ts, ${HOUR}) * ${HOUR}, dev, if_index, sum(dt), count(), sum(util_in), sum(util_out), sum(in_bps), sum(out_bps), sum(in_disc + out_disc), sum(in_err + out_err)
        FROM snmp_if WHERE ${w} GROUP BY intDiv(ts, ${HOUR}) * ${HOUR}, dev, if_index`);
      await this.c.exec(`INSERT INTO snmp_cls_1h (ts, dev, if_index, cls, secs, pre_pkts, pre_bytes, post_bytes, drop_pkts, drop_bytes, qdepth)
        SELECT intDiv(ts, ${HOUR}) * ${HOUR}, dev, if_index, cls, sum(dt), sum(pre_pkts), sum(pre_bytes), sum(post_bytes), sum(drop_pkts), sum(drop_bytes), max(qdepth)
        FROM snmp_cls WHERE ${w} GROUP BY intDiv(ts, ${HOUR}) * ${HOUR}, dev, if_index, cls`);
      wm = b;
      await this.setMeta('wm_snmp', wm);
    }
  }

  /* ------------------------------------------------------------ stats */

  async stats(): Promise<StoreStats> {
    const now = Date.now();
    if (!this.statsCache || now - this.statsCache.at > 15_000) {
      const parts = await this.c.rows<{ table: string; rows: number; bytes: number; parts: number }>(
        `SELECT table, sum(rows) AS rows, sum(bytes_on_disk) AS bytes, count() AS parts FROM system.parts WHERE database = ${S(this.c.db)} AND active GROUP BY table`);
      const m = new Map(parts.map(p => [p.table, p]));
      const rows = (t: string) => Number(m.get(t)?.rows || 0);
      const days = Number((await this.c.rows<{ n: number }>(`SELECT uniqExact(partition) AS n FROM system.parts WHERE database = ${S(this.c.db)} AND table = 'flow_raw' AND active AND rows > 0`))[0]?.n || 0);
      const mm = (await this.c.rows<{ a: number | null; b: number | null }>('SELECT min(ts1) AS a, max(ts1) AS b FROM flow_raw'))[0];
      const rawRows = rows('flow_raw');
      this.statsCache = {
        at: now,
        v: {
          rawDays: days, rawRows, m1Rows: rows('flow_1m'), h1Rows: rows('flow_1h'), d1Rows: rows('flow_1d'),
          snmpRawRows: rows('snmp_if') + rows('snmp_cls'), snmpHourlyRows: rows('snmp_if_1h') + rows('snmp_cls_1h'),
          bytesOnDisk: parts.reduce((a, p) => a + Number(p.bytes), 0),
          oldestFlow: rawRows && mm?.a != null ? Number(mm.a) : null, newestFlow: rawRows && mm?.b != null ? Number(mm.b) : null
        }
      };
    }
    return { backend: 'clickhouse', ...this.statsCache.v, ingested: this.ingested, dropped: this.dropped };
  }

  async close(): Promise<void> { /* HTTP is stateless */ }
}
