import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';

/** Runtime configuration. Everything comes from environment variables so the same build works
 *  as a service on Windows, macOS and Linux and as a container. */
export interface AppConfig {
  dataDir: string;
  bind: string;
  httpsPort: number;
  /** Plain HTTP port. 0 disables it. When TLS is "off" this is the only web listener. */
  httpPort: number;
  /** "auto" generates a self-signed certificate on first start. "off" serves plain HTTP only (use behind a TLS proxy). */
  tls: 'auto' | 'off';
  flowBind: string;
  /** UDP ports that accept NetFlow v5, v9 and IPFIX. */
  flowPorts: number[];
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  /** Starts the built-in demo network instead of waiting for real exporters. */
  demo: boolean;
  /** Public base URL used for SAML callbacks when the app sits behind a proxy. */
  publicUrl: string;
  /** `http://user:pass@host:8123/database`. The Docker compose files, the Linux installer and the Proxmox installer and template set it. */
  clickhouseUrl: string;
  /** Forces the storage backend for a new install ("sqlite" or "clickhouse"). Empty: ClickHouse when clickhouseUrl is set, else SQLite. */
  backend: 'sqlite' | 'clickhouse' | '';
  /** How long start-up waits for a configured ClickHouse server to answer before falling back to SQLite for this run. */
  clickhouseWaitSec: number;
  /** Number of reverse proxies in front of the web server; 0 trusts no forwarded headers. */
  trustProxy: number;
}

function num(v: string | undefined, d: number): number {
  if (v === undefined || v === '') return d;
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
}

export function inContainer(): boolean {
  if (process.env.FLOWSCOPE_CONTAINER === '1') return true;
  try { return fs.existsSync('/.dockerenv'); } catch { return false; }
}

export function defaultDataDir(): string {
  if (process.env.FLOWSCOPE_DATA_DIR) return path.resolve(process.env.FLOWSCOPE_DATA_DIR);
  if (inContainer()) return '/data';
  const home = os.homedir();
  switch (process.platform) {
    case 'win32': return path.join(process.env.ProgramData || process.env.LOCALAPPDATA || home, 'FlowScope');
    case 'darwin': return path.join(home, 'Library', 'Application Support', 'FlowScope');
    default: return process.getuid && process.getuid() === 0 ? '/var/lib/flowscope' : path.join(process.env.XDG_DATA_HOME || path.join(home, '.local', 'share'), 'flowscope');
  }
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const ports = (env.FLOWSCOPE_FLOW_PORTS || '2055,4739').split(',').map(s => Number(s.trim())).filter(n => n > 0 && n < 65536);
  const tls = (env.FLOWSCOPE_TLS || 'auto') === 'off' ? 'off' : 'auto';
  return {
    dataDir: defaultDataDir(),
    bind: env.FLOWSCOPE_BIND || (inContainer() ? '0.0.0.0' : '0.0.0.0'),
    httpsPort: num(env.FLOWSCOPE_HTTPS_PORT, 8443),
    httpPort: num(env.FLOWSCOPE_HTTP_PORT, tls === 'off' ? 8080 : 0),
    tls,
    flowBind: env.FLOWSCOPE_FLOW_BIND || '0.0.0.0',
    flowPorts: ports.length ? ports : [2055, 4739],
    logLevel: (['debug', 'info', 'warn', 'error'].includes(env.FLOWSCOPE_LOG_LEVEL || '') ? env.FLOWSCOPE_LOG_LEVEL : 'info') as AppConfig['logLevel'],
    demo: env.FLOWSCOPE_DEMO === '1',
    publicUrl: (env.FLOWSCOPE_PUBLIC_URL || '').replace(/\/$/, ''),
    clickhouseUrl: env.FLOWSCOPE_CLICKHOUSE_URL || '',
    backend: env.FLOWSCOPE_BACKEND === 'sqlite' || env.FLOWSCOPE_BACKEND === 'clickhouse' ? env.FLOWSCOPE_BACKEND : '',
    clickhouseWaitSec: Math.max(0, Math.min(600, num(env.FLOWSCOPE_CLICKHOUSE_WAIT, 60))),
    trustProxy: /^\d{1,2}$/.test(env.FLOWSCOPE_TRUST_PROXY || '') ? Number(env.FLOWSCOPE_TRUST_PROXY) : 0
  };
}
