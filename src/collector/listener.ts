import dgram from 'node:dgram';
import type { FlowRecord, DecodeStats } from './types.js';
import { decodeV5, TemplateDecoder } from './decode.js';

export interface ExporterInfo {
  ip: string; firstSeen: number; lastSeen: number; packets: number; records: number; version: string; lastError: string | null;
}

export interface CollectorLog { info(s: string, m: string): void; warn(s: string, m: string): void; error(s: string, m: string): void }
export interface FlowIngest { insertFlows(r: FlowRecord[]): Promise<void> }

export interface CollectorOpts {
  bind: string; ports: number[]; log: CollectorLog; ingest: FlowIngest;
  /** Called for each new exporter IP, so the device list can be linked to it. */
  onExporter?: (ip: string) => void;
  maxBuffered?: number; flushMs?: number; flushRecords?: number;
  /**
   * Accepted range for flow times, in ms since the epoch. Records outside it are dropped and counted, because the flow time chooses the
   * storage table and a wrong or forged time creates tables nothing will ever read or remove. Default: the year 2000 up to one day ahead.
   */
  timeWindow?: () => { minMs: number; maxMs: number };
}

const DAY = 86_400_000;
const Y2000 = Date.UTC(2000, 0, 1);

/** UDP listener for NetFlow v5, v9 and IPFIX. Records are batched and handed to the store. */
export class FlowCollector {
  enabled = true;
  readonly stats: DecodeStats = { packets: 0, records: 0, v5: 0, v9: 0, ipfix: 0, errors: 0, missingTemplate: 0, templates: 0, discarded: 0 };
  readonly exporters = new Map<string, ExporterInfo>();
  private sockets: dgram.Socket[] = [];
  private decoder = new TemplateDecoder();
  private buf: FlowRecord[] = [];
  private flushing = false;
  private timer: NodeJS.Timeout | null = null;
  private dropped = 0;
  private lastDropLog = 0;
  private lastTimeLog = new Map<string, number>();
  boundPorts: number[] = [];

  constructor(private o: CollectorOpts) {}

  get droppedRecords(): number { return this.dropped; }

  async start(): Promise<void> {
    const family = this.o.bind.includes(':') ? 'udp6' : 'udp4';
    for (const port of this.o.ports) {
      await new Promise<void>((resolve, reject) => {
        const s = dgram.createSocket({ type: family, reuseAddr: false });
        s.on('error', e => { this.o.log.error('collector', `UDP ${port}: ${e.message}`); reject(e); });
        s.on('message', (msg, rinfo) => this.onPacket(msg, rinfo.address));
        s.bind(port, this.o.bind, () => {
          try { s.setRecvBufferSize(8 * 1024 * 1024); } catch { /* platform limit */ }
          this.sockets.push(s);
          this.boundPorts.push((s.address() as { port: number }).port);
          this.o.log.info('collector', `listening on udp/${(s.address() as { port: number }).port}`);
          resolve();
        });
      });
    }
    this.timer = setInterval(() => void this.flush(), this.o.flushMs ?? 500);
    this.timer.unref();
  }

  private norm(addr: string): string {
    return addr.startsWith('::ffff:') ? addr.slice(7) : addr;
  }

  private onPacket(msg: Buffer, from: string): void {
    if (!this.enabled) { this.stats.discarded++; return; }
    if (msg.length < 20) { this.stats.errors++; return; }
    const ip = this.norm(from);
    let info = this.exporters.get(ip);
    const now = Date.now();
    if (!info) {
      if (this.exporters.size >= 5000) { this.stats.errors++; return; }
      info = { ip, firstSeen: now, lastSeen: now, packets: 0, records: 0, version: '', lastError: null };
      this.exporters.set(ip, info);
      this.o.log.info('collector', `new exporter ${ip}`);
      try { this.o.onExporter?.(ip); } catch { /* ignore */ }
    }
    info.lastSeen = now; info.packets++; this.stats.packets++;
    let recs: FlowRecord[];
    try {
      const ver = msg.readUInt16BE(0);
      if (ver === 5) { recs = decodeV5(msg, ip); this.stats.v5++; info.version = 'v5'; }
      else if (ver === 9 || ver === 10) {
        recs = this.decoder.decode(msg, ip);
        if (ver === 9) { this.stats.v9++; info.version = 'v9'; } else { this.stats.ipfix++; info.version = 'IPFIX'; }
        this.stats.templates = this.decoder.stats.templates; this.stats.missingTemplate = this.decoder.stats.missingTemplate;
      } else { throw new Error('unsupported NetFlow version ' + ver); }
      info.lastError = null;
    } catch (e) {
      this.stats.errors++; info.lastError = (e as Error).message;
      return;
    }
    if (!recs.length) return;
    recs = this.inWindow(recs, info, now);
    if (!recs.length) return;
    info.records += recs.length; this.stats.records += recs.length;
    const max = this.o.maxBuffered ?? 500_000;
    if (this.buf.length + recs.length > max) {
      this.dropped += recs.length;
      if (now - this.lastDropLog > 10_000) { this.lastDropLog = now; this.o.log.warn('collector', `storage is behind; dropped ${this.dropped} records so far`); }
      return;
    }
    for (const r of recs) this.buf.push(r);
    if (this.buf.length >= (this.o.flushRecords ?? 5000)) void this.flush();
  }

  /** Drops records whose flow times are not usable and says so, at most once every 10 minutes per exporter. */
  private inWindow(recs: FlowRecord[], info: ExporterInfo, now: number): FlowRecord[] {
    const w = this.o.timeWindow?.() ?? { minMs: Y2000, maxMs: now + DAY };
    const ok = recs.filter(r => Number.isFinite(r.ts0) && Number.isFinite(r.ts1) && r.ts1 >= w.minMs && r.ts1 <= w.maxMs && r.ts0 >= w.minMs && r.ts0 <= w.maxMs);
    const bad = recs.length - ok.length;
    if (bad) {
      this.stats.badTime = (this.stats.badTime ?? 0) + bad;
      info.lastError = `${bad} record${bad === 1 ? '' : 's'} with flow times outside the accepted range (is the exporter's clock set?)`;
      const last = this.lastTimeLog.get(info.ip) ?? 0;
      if (now - last > 600_000) {
        if (this.lastTimeLog.size > 5000) this.lastTimeLog.clear();
        this.lastTimeLog.set(info.ip, now);
        this.o.log.warn('collector', `${info.ip}: dropped ${bad} record${bad === 1 ? '' : 's'} with flow times outside ${new Date(w.minMs).toISOString().slice(0, 10)} to ${new Date(w.maxMs).toISOString().slice(0, 10)}. Check the exporter's clock.`);
      }
    }
    return ok;
  }

  async flush(): Promise<void> {
    if (this.flushing || !this.buf.length) return;
    this.flushing = true;
    try {
      while (this.buf.length) {
        const batch = this.buf.splice(0, 20_000);
        try { await this.o.ingest.insertFlows(batch); } catch (e) { this.dropped += batch.length; this.o.log.error('collector', 'store write failed: ' + (e as Error).message); }
      }
    } finally { this.flushing = false; }
  }

  async stop(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    for (const s of this.sockets) await new Promise<void>(res => { try { s.close(() => res()); } catch { res(); } });
    this.sockets = [];
    await this.flush();
  }
}
