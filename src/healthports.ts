import fs from 'node:fs';
import path from 'node:path';

/**
 * The server records the web ports it opened in <data folder>/ports.json, so `flowscope healthcheck` (and anything else run from a shell)
 * checks the port the server really uses. The settings come to the server from its service file or container, not to a shell, so
 * without this a check run by hand looked at the built-in default and failed on a server that was running fine.
 */
export interface WebPorts { https?: number; http?: number }

const FILE = 'ports.json';
const valid = (n: unknown): n is number => typeof n === 'number' && Number.isInteger(n) && n > 0 && n < 65536;

export function writePorts(dataDir: string, ports: WebPorts): void {
  try { fs.writeFileSync(path.join(dataDir, FILE), JSON.stringify({ https: ports.https, http: ports.http }) + '\n', { mode: 0o600 }); } catch { /* the check then uses the configured ports */ }
}

export function readPorts(dataDir: string): WebPorts {
  try {
    const j = JSON.parse(fs.readFileSync(path.join(dataDir, FILE), 'utf8')) as WebPorts;
    return { https: valid(j.https) ? j.https : undefined, http: valid(j.http) ? j.http : undefined };
  } catch { return {}; }
}

/** The ports to check: one set explicitly in the environment wins, then what the server recorded, then the configured default. */
export function checkPorts(cfg: { httpsPort: number; httpPort: number; dataDir: string }, env: NodeJS.ProcessEnv, recorded: WebPorts = readPorts(cfg.dataDir)): { https: number; http: number } {
  return {
    https: env.FLOWSCOPE_HTTPS_PORT !== undefined && env.FLOWSCOPE_HTTPS_PORT !== '' ? cfg.httpsPort : recorded.https ?? cfg.httpsPort,
    http: env.FLOWSCOPE_HTTP_PORT !== undefined && env.FLOWSCOPE_HTTP_PORT !== '' ? cfg.httpPort : recorded.http ?? cfg.httpPort
  };
}
