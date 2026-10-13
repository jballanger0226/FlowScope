import type { FlowRecord } from '../collector/types.js';
import type { Retention } from '../settings.js';

export interface TimeRange { from: number; to: number }

/** An IPv4 address range as numbers (inclusive), or a text prefix for IPv6. */
export interface IpMatch { lo?: number; hi?: number; text?: string }

export type Cond =
  | { kind: 'src'; m: IpMatch[] }
  | { kind: 'dst'; m: IpMatch[] }
  | { kind: 'ip'; m: IpMatch[] }
  | { kind: 'port'; ports: number[] }
  | { kind: 'sport'; ports: number[] }
  | { kind: 'dport'; ports: number[] }
  | { kind: 'proto'; protos: number[] }
  | { kind: 'vlan'; ids: number[] }
  | { kind: 'mac'; text: string }
  | { kind: 'exporter'; ips: string[] }
  | { kind: 'outif'; ips: string[]; ifIndex: number }
  | { kind: 'qos'; mode: 'changed' | 'unchanged' }
  | { kind: 'dscp'; values: number[] }
  | { kind: 'text'; text: string; ips: string[]; vlans: number[]; ports: number[] };

export interface StreamQuery {
  range: TimeRange;
  conds: Cond[];
  sort: 'time' | 'bytes' | 'pkts';
  dir: 'asc' | 'desc';
  limit: number;
}

export interface StreamRow {
  skey: string;
  srcIp: string; dstIp: string; sport: number; dport: number; proto: number;
  t0: number; t1: number;
  bytes: number; pkts: number; fwdBytes: number; revBytes: number; fwdPkts: number; revPkts: number;
  exporters: string[];
  vlan: number | null;
  qosChanged: boolean;
  flags: number;
  /** DSCP seen first, and the DSCP it became when the stream was re-marked (otherwise null). */
  dscpIn: number;
  dscpOut: number | null;
}

export interface StreamPage { rows: StreamRow[]; total: number; truncated: boolean; tier: 'raw' }

export type ReportDim = 'srcMac' | 'dstMac' | 'vlan' | 'inIf' | 'srcIp' | 'dstIp' | 'proto' | 'dscp' | 'qos' | 'sport' | 'dport' | 'svc' | 'flags';

export interface ReportSpec {
  range: TimeRange;
  tier: 'raw' | 'm1' | 'h1' | 'd1';
  dims: ReportDim[];
  prefix: number;
  bidir: boolean;
  conds: Cond[];
  sortBy: 'bytes' | 'pkts' | 'flows';
  topN: number;
  exporter?: string;
}

export interface ReportRow { dims: Record<string, string | number | null>; bytes: number; pkts: number; flows: number }
export interface ReportResult { rows: ReportRow[]; totalRows: number; totals: { bytes: number; pkts: number; flows: number }; other: { bytes: number; pkts: number; flows: number; rows: number } }

export interface IfPoint {
  ts: number; dev: number; ifIndex: number; dt: number;
  inBps: number; outBps: number; utilIn: number; utilOut: number;
  inDisc: number; outDisc: number; inErr: number; outErr: number; oper: number;
}
export interface ClsPoint {
  ts: number; dev: number; ifIndex: number; cls: string; dt: number;
  prePkts: number; preBytes: number; postBytes: number; dropPkts: number; dropBytes: number; qdepth: number;
}

export interface SeriesPoint { ts: number; v: number }
export interface IfSeries { step: number; points: { ts: number; utilIn: number; utilOut: number; inBps: number; outBps: number; disc: number; err: number }[]; tier: 'raw' | 'h1' }
export interface ClassSeries {
  step: number; tier: 'raw' | 'h1';
  classes: { cls: string; points: { ts: number; dropPct: number; dropBps: number; dropPps: number; sentBps: number; qdepth: number }[] }[];
}
export interface ClassLatest { dev: number; ifIndex: number; cls: string; dropPct: number; dropPkts: number; dropBytes: number; sentBps: number; qdepth: number; ts: number }
export interface IfLatest { dev: number; ifIndex: number; utilIn: number; utilOut: number; inBps: number; outBps: number; disc: number; err: number; ts: number }

export interface StoreStats {
  backend: string;
  rawDays: number; rawRows: number; m1Rows: number; h1Rows: number; d1Rows: number; snmpRawRows: number; snmpHourlyRows: number;
  bytesOnDisk: number; oldestFlow: number | null; newestFlow: number | null;
  ingested: number; dropped: number;
}

/** Storage interface. The default implementation is SQLite; a ClickHouse implementation can be selected for larger sites. */
export interface TsStore {
  readonly kind: 'sqlite' | 'clickhouse';
  insertFlows(records: FlowRecord[]): Promise<void>;
  insertSnmp(ifs: IfPoint[], cls: ClsPoint[]): Promise<void>;
  searchStreams(q: StreamQuery): Promise<StreamPage>;
  streamRecords(skey: string, range: TimeRange): Promise<FlowRecord[]>;
  report(spec: ReportSpec): Promise<ReportResult>;
  ifSeries(dev: number, ifIndex: number, range: TimeRange, retention: Retention, points: number): Promise<IfSeries>;
  classSeries(dev: number, ifIndex: number, range: TimeRange, retention: Retention, points: number): Promise<ClassSeries>;
  classLatest(sinceMs: number): Promise<ClassLatest[]>;
  ifLatest(sinceMs: number): Promise<IfLatest[]>;
  /** Runs rollups and drops data older than the retention settings. */
  maintain(retention: Retention, now?: number): Promise<{ dropped: string[] }>;
  deleteDevice(dev: number): Promise<void>;
  stats(): Promise<StoreStats>;
  close(): Promise<void>;
}

export const DAY_MS = 86400_000;
