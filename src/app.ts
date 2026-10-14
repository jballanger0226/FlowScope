import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AppConfig } from './config.js';
import { ConfigDb } from './db/configdb.js';
import { Secrets } from './secrets.js';
import { Settings, type CollectSettings } from './settings.js';
import { AppLog } from './logger.js';
import { AuthService } from './auth/service.js';
import { CertManager } from './tls/manager.js';
import { CredentialStore } from './snmp/creds.js';
import { DeviceService } from './snmp/devices.js';
import { Discovery } from './snmp/discovery.js';
import { Poller } from './snmp/poller.js';
import { HostTracker } from './snmp/hosts.js';
import { FlowCollector } from './collector/listener.js';
import { SqliteStore } from './store/sqlite.js';
import type { TsStore } from './store/types.js';
import { SwitchableStore } from './store/switchable.js';
import { WebServer } from './server/http.js';
import type { Resolver } from './query/tokens.js';
import { SamlState } from './auth/saml/saml.js';
import { registerRoutes } from './routes/index.js';

export const VERSION = '0.1.0';

/** The running application: owns every service and wires them together. */
export class App {
  readonly startedAt = Date.now();
  cdb!: ConfigDb; secrets!: Secrets; settings!: Settings; log!: AppLog; auth!: AuthService; certs!: CertManager;
  creds!: CredentialStore; devices!: DeviceService; discovery!: Discovery; poller!: Poller; hosts!: HostTracker; collector!: FlowCollector; store!: SwitchableStore; web!: WebServer;
  initialAdminPassword: string | null = null;
  saml = new SamlState();
  private timers: NodeJS.Timeout[] = [];
  private collectCache: CollectSettings = { flow: true, snmp: true, flowAt: 0, snmpAt: 0 };
  ports: { https?: number; http?: number } = {};
  /** Set by demo mode so the UI can say so. */
  demo = false;
  storeError: string | null = null;

  constructor(readonly cfg: AppConfig) {}

  static async create(cfg: AppConfig): Promise<App> {
    const a = new App(cfg);
    await a.init();
    return a;
  }

  private async init(): Promise<void> {
    const cfg = this.cfg;
    fs.mkdirSync(cfg.dataDir, { recursive: true });
    this.cdb = new ConfigDb(cfg.dataDir);
    this.secrets = new Secrets(cfg.dataDir);
    this.settings = new Settings(this.cdb);
    this.log = new AppLog(this.cdb, this.settings, cfg.logLevel);
    this.auth = new AuthService(this.cdb, this.settings, this.secrets, this.log);
    this.certs = new CertManager(this.cdb, this.secrets, this.log);
    this.creds = new CredentialStore(this.cdb, this.secrets, this.settings);
    this.collectCache = this.settings.get('collect');
    this.store = new SwitchableStore(await this.openStore(this.resolveBackend(), cfg.clickhouseWaitSec));
    this.devices = new DeviceService(this.cdb, this.creds, this.store, this.log);
    this.discovery = new Discovery(this.devices, this.creds, this.log);
    this.hosts = new HostTracker(this.cdb, this.devices, this.log, () => this.settings.get('hosts'));
    this.poller = new Poller(this.devices, this.store, this.log, { isEnabled: () => this.collectCache.snmp, hosts: () => this.settings.get('hosts') }, this.hosts);
    this.collector = new FlowCollector({
      bind: cfg.flowBind, ports: cfg.flowPorts, log: { info: (s, m) => this.log.info(s, m), warn: (s, m) => this.log.warn(s, m), error: (s, m) => this.log.error(s, m) },
      ingest: this.store, onExporter: ip => this.noteExporter(ip),
      // Raw tables older than the raw retention are removed at the next maintenance run, so such records are not worth storing.
      timeWindow: () => { const now = Date.now(); return { minMs: now - (this.settings.get('retention').raw + 1) * 86_400_000, maxMs: now + 86_400_000 }; }
    });
    this.collector.enabled = this.collectCache.flow;

    const here = path.dirname(fileURLToPath(import.meta.url));
    const webRoot = fs.existsSync(path.join(here, '..', 'web')) ? path.join(here, '..', 'web') : path.join(here, '..', '..', 'web');
    this.web = new WebServer({
      fromSession: t => this.auth.fromSession(t), fromToken: t => this.auth.fromToken(t),
      basic: async (u, p, ip) => (await this.auth.authenticate('api', u, p, ip)).principal
    }, webRoot, cfg.tls !== 'off');
    this.web.trustProxy = cfg.trustProxy;
    registerRoutes(this);
  }

  /**
   * Chooses the storage backend. A choice made earlier (stored setting) always wins, so an upgrade never moves an install to a different store.
   * For a first start: FLOWSCOPE_BACKEND, else SQLite if this data folder already holds a SQLite store, else ClickHouse when a ClickHouse
   * server is configured (the Docker compose files, the Linux installer and the Proxmox installer and template all configure one), else SQLite.
   * The result is stored, so it stays the same later even if the environment changes.
   */
  resolveBackend(): 'sqlite' | 'clickhouse' {
    const stored = this.settings.raw('backend');
    if (stored !== undefined) return this.settings.get('backend');
    let pick: 'sqlite' | 'clickhouse';
    if (this.cfg.backend) pick = this.cfg.backend;
    else if (fs.existsSync(path.join(this.cfg.dataDir, 'ts', 'ts.db'))) pick = 'sqlite';
    else pick = this.cfg.clickhouseUrl ? 'clickhouse' : 'sqlite';
    this.settings.set('backend', pick);
    this.log.info('store', `Storage backend for this install: ${pick}`);
    return pick;
  }

  /**
   * Opens the chosen backend. Falls back to SQLite when ClickHouse cannot be reached, so start-up never fails because of it.
   * `waitSec` keeps trying for that long first, because ClickHouse is often still starting when FlowScope is (a reboot, `docker compose up`).
   */
  async openStore(want: 'sqlite' | 'clickhouse', waitSec = 0): Promise<TsStore> {
    if (want === 'clickhouse') {
      const { openClickHouse } = await import('./store/clickhouse.js');
      const deadline = Date.now() + waitSec * 1000;
      for (let attempt = 1; ; attempt++) {
        try {
          const s = await openClickHouse(this.cfg.clickhouseUrl, this.log);
          this.storeError = null;
          return s;
        } catch (e) {
          const msg = (e as Error).message;
          const settingsProblem = /Invalid URL|is not set|must start with|database name may only/.test(msg);
          if (!settingsProblem && Date.now() + 2000 < deadline) {
            if (attempt === 1) this.log.warn('store', `ClickHouse is not answering yet (${msg}). Waiting up to ${waitSec} s for it.`);
            await new Promise(r => setTimeout(r, 2000));
            continue;
          }
          this.storeError = `ClickHouse is selected but could not be used (${msg}). Falling back to the embedded SQLite store so nothing is lost.`;
          this.log.error('store', this.storeError);
          break;
        }
      }
    }
    return SqliteStore.open(path.join(this.cfg.dataDir, 'ts'));
  }

  /* ---- collection switches ---- */

  collect(): CollectSettings { return this.collectCache; }

  setCollect(patch: { flow?: boolean; snmp?: boolean }, user: string): CollectSettings {
    const c = { ...this.collectCache };
    if (patch.flow !== undefined && patch.flow !== c.flow) { c.flow = patch.flow; c.flowAt = Date.now(); this.log.audit(user, `Flow collection turned ${c.flow ? 'on' : 'off'}`, c.flow ? 'INFO' : 'WARN'); }
    if (patch.snmp !== undefined && patch.snmp !== c.snmp) { c.snmp = patch.snmp; c.snmpAt = Date.now(); this.log.audit(user, `SNMP polling turned ${c.snmp ? 'on' : 'off'}`, c.snmp ? 'INFO' : 'WARN'); }
    this.settings.set('collect', c);
    this.collectCache = c;
    this.collector.enabled = c.flow;
    return c;
  }

  collecting(): boolean { return this.collectCache.flow || this.collectCache.snmp; }

  /* ---- exporters ---- */

  private noteExporter(ip: string): void {
    const now = Date.now();
    this.cdb.db.prepare('INSERT INTO exporters(ip, first_seen, last_seen) VALUES (?,?,?) ON CONFLICT(ip) DO UPDATE SET last_seen = excluded.last_seen').run(ip, now, now);
    const id = this.devices.deviceIdForExporter(ip);
    if (id !== null) this.cdb.db.prepare('UPDATE exporters SET device_id = ? WHERE ip = ?').run(id, ip);
  }

  private syncExporters(): void {
    const st = this.cdb.db.prepare('UPDATE exporters SET last_seen = ?, flows = ?, version = ? WHERE ip = ?');
    this.cdb.tx(() => { for (const e of this.collector.exporters.values()) st.run(e.lastSeen, e.records, e.version, e.ip); });
  }

  knownExporters(): string[] {
    const s = new Set(this.collector.exporters.keys());
    for (const r of this.cdb.db.prepare('SELECT ip FROM exporters').all() as unknown as { ip: string }[]) s.add(r.ip);
    return [...s];
  }

  /** Name lookups for the search box. */
  /** Addresses that belong to our own routers and switches, used so traffic addressed to a router is not reported as TTL-expired. */
  localIps(): string[] { return [...new Set([...this.devices.allAddresses(), ...this.knownExporters()])]; }

  resolver(): Resolver {
    return {
      vlanIdsByName: text => {
        const t = text.toLowerCase();
        return (this.cdb.db.prepare('SELECT id, name FROM vlans').all() as unknown as { id: number; name: string }[]).filter(v => v.name.toLowerCase().includes(t)).map(v => v.id);
      },
      exporterIpsByName: text => this.devices.exporterIpsByName(text, this.knownExporters())
    };
  }

  vlanName(id: number): string { return (this.cdb.db.prepare('SELECT name FROM vlans WHERE id = ?').get(id) as { name: string } | undefined)?.name ?? ''; }

  /* ---- lifecycle ---- */

  async start(): Promise<void> {
    const cfg = this.cfg;
    let nicAddresses: string[] = [];
    try {
      nicAddresses = Object.values(os.networkInterfaces()).flat().filter(i => i && !i.internal).map(i => i!.address);
    } catch (e) {
      // A sandbox (for example a systemd unit without AF_NETLINK) can make the interface lookup fail; the certificate then only
      // lists the fixed names instead of the service refusing to start.
      this.log.warn('cert', 'Could not list the network interfaces, the certificate will not include their addresses: ' + (e as Error).message);
    }
    const hosts = [os.hostname(), 'localhost', '127.0.0.1', '::1', ...nicAddresses];
    if (cfg.tls === 'auto') await this.certs.ensureActive(hosts);
    this.initialAdminPassword = this.auth.bootstrap(process.env.FLOWSCOPE_ADMIN_PASSWORD);
    try { await this.collector.start(); } catch (e) { this.log.error('collector', 'Could not open the flow ports: ' + (e as Error).message); }
    this.ports = await this.web.listen({
      host: cfg.bind, httpsPort: cfg.tls === 'auto' ? cfg.httpsPort : undefined, httpPort: cfg.httpPort > 0 ? cfg.httpPort : undefined,
      tls: cfg.tls === 'auto' ? this.certs.options() : null, redirectToHttps: cfg.tls === 'auto'
    });
    if (!this.demo) this.poller.start();
    const every = (ms: number, fn: () => void | Promise<void>) => { const t = setInterval(() => { try { void Promise.resolve(fn()).catch(e => this.log.error('app', String(e))); } catch (e) { this.log.error('app', String(e)); } }, ms); t.unref(); this.timers.push(t); };
    every(60_000, async () => { const r = await this.store.maintain(this.settings.get('retention')); if (r.dropped.length) this.log.info('store', `Retention removed ${r.dropped.join(', ')}`); });
    every(60_000, () => this.syncExporters());
    every(3600_000, () => this.auth.sweep());
    every(6 * 3600_000, () => { const a = this.certs.status().active; if (a && a.daysLeft < 30) this.log.warn('cert', `The HTTPS certificate expires in ${a.daysLeft} days`); });
    void this.store.maintain(this.settings.get('retention')).catch(() => undefined);
    this.log.info('app', `FlowScope ${VERSION} started. Web: ${this.ports.https ? 'https://:' + this.ports.https : ''} ${this.ports.http ? 'http://:' + this.ports.http : ''}; flow ports: ${this.collector.boundPorts.join(', ')}; data: ${cfg.dataDir}`);
  }

  async stop(): Promise<void> {
    for (const t of this.timers) clearInterval(t);
    this.poller.stop();
    await this.web.close();
    await this.collector.stop();
    await this.store.close();
    this.log.info('app', 'Stopped');
    this.log.close();
    this.cdb.close();
  }
}
