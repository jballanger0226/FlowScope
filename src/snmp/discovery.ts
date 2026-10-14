import { randomUUID } from 'node:crypto';
import type { DeviceService, DeviceView } from './devices.js';
import { parseTargets, DeviceError } from './devices.js';
import type { CredentialStore } from './creds.js';
import { SnmpClient } from './client.js';
import { probe, type Probe } from './collect.js';
import type { AppLog } from '../logger.js';

export type FoundStatus = 'found' | 'already' | 'noresponse' | 'authfail' | 'error';
export interface Found { ip: string; status: FoundStatus; via?: string; sysName?: string; sysDescr?: string; role?: string; interfaces?: number; policies?: number; error?: string; deviceId?: number }
export interface Job {
  id: string; spec: string; credName: string; startedAt: number; finishedAt: number | null; total: number; done: number; cancelled: boolean;
  results: Found[]; user: string; tryOthers: boolean;
}

/** Scans an address range with SNMP and offers the devices that answer. */
export class Discovery {
  private jobs = new Map<string, Job & { probes: Map<string, { p: Probe; credId: number }>; credId: number }>();

  constructor(private devs: DeviceService, private creds: CredentialStore, private log: AppLog, private o: { timeoutMs?: number; concurrency?: number; port?: number } = {}) {}

  /** `allow`, when given, must accept every address in the search; otherwise nothing is sent. */
  start(spec: string, user: string, credId?: number, tryOthers = false, allow?: (ip: string) => boolean): Job {
    const targets = parseTargets(spec);
    const outside = allow ? targets.find(ip => !allow(ip)) : undefined;
    if (outside) throw new DeviceError(`${outside} is outside the networks you may scan. An administrator sets them under Admin, SNMP credentials.`, 403);
    const cid = credId ?? this.creds.defaultId();
    if (cid === null || cid === undefined) throw new DeviceError('Create a credential set first, then scan');
    const cred = this.creds.list().find(c => c.id === cid);
    if (!cred) throw new DeviceError('No such credential set');
    for (const [id, j] of this.jobs) if (j.finishedAt && Date.now() - j.finishedAt > 3600_000) this.jobs.delete(id);
    if ([...this.jobs.values()].filter(j => !j.finishedAt).length >= 3) throw new DeviceError('Three scans are already running. Wait for one to finish.', 429);
    const job = { id: randomUUID(), spec, credName: cred.name, startedAt: Date.now(), finishedAt: null, total: targets.length, done: 0, cancelled: false, results: [] as Found[], user, tryOthers, probes: new Map<string, { p: Probe; credId: number }>(), credId: cid };
    this.jobs.set(job.id, job);
    this.log.info('snmp', `Discovery started on ${spec} (${targets.length} addresses) with credential set "${cred.name}"`, user);
    void this.run(job, targets);
    return this.view(job);
  }

  private async run(job: Job & { probes: Map<string, { p: Probe; credId: number }>; credId: number }, targets: string[]): Promise<void> {
    const existing = new Map(this.devs.list().map(d => [d.ip, d]));
    // the chosen set first; with "try the others" every other set is tried for addresses that do not answer
    const order = [job.credId, ...(job.tryOthers ? this.creds.list().map(c => c.id).filter(i => i !== job.credId) : [])];
    const names = new Map(this.creds.list().map(c => [c.id, c.name]));
    const queue = targets.slice();
    const worker = async () => {
      for (;;) {
        const ip = queue.shift();
        if (ip === undefined || job.cancelled) return;
        const ex = existing.get(ip);
        if (ex) { job.results.push({ ip, status: 'already', sysName: ex.sysName || ex.name, sysDescr: ex.sysDescr, deviceId: ex.id }); job.done++; continue; }
        let authFailed = false, lastError = '', found = false;
        for (const cid of order) {
          if (job.cancelled) break;
          const c = new SnmpClient({ host: ip, port: this.o.port ?? 161, timeoutMs: this.o.timeoutMs ?? 1500, retries: 0 }, this.creds.resolve(cid));
          try {
            const p = await probe(c);
            job.probes.set(ip, { p, credId: cid });
            job.results.push({ ip, status: 'found', via: names.get(cid), sysName: p.info.sysName, sysDescr: p.info.sysDescr, role: undefined, interfaces: p.ifaces.length, policies: p.qos.length });
            found = true; break;
          } catch (e) {
            const m = (e as { kind?: string }).kind;
            if (m === 'auth') authFailed = true;
            else if (m !== 'timeout') lastError = (e as Error).message;
          } finally { c.close(); }
        }
        if (!found) {
          // most addresses are silent and are not listed
          if (authFailed) job.results.push({ ip, status: 'authfail', error: 'The device answered but rejected these credentials' });
          else if (lastError) job.results.push({ ip, status: 'error', error: lastError });
        }
        job.done++;
      }
    };
    await Promise.all(Array.from({ length: Math.min(this.o.concurrency ?? 48, targets.length) }, worker));
    job.finishedAt = Date.now();
    job.results.sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }));
    this.log.info('snmp', `Discovery on ${job.spec} finished: ${job.results.filter(r => r.status === 'found').length} new, ${job.results.filter(r => r.status === 'already').length} already added`, job.user);
  }

  private view(j: Job): Job { const { id, spec, credName, startedAt, finishedAt, total, done, cancelled, results, user, tryOthers } = j; return { id, spec, credName, startedAt, finishedAt, total, done, cancelled, results: results.slice(), user, tryOthers }; }

  get(id: string): Job | undefined { const j = this.jobs.get(id); return j ? this.view(j) : undefined; }
  cancel(id: string): void { const j = this.jobs.get(id); if (j) j.cancelled = true; }

  /** Adds the chosen devices from a finished (or running) scan using what the scan already read. */
  async addFound(id: string, ips: string[], user: string, intervalSec?: number): Promise<{ added: DeviceView[]; failed: { ip: string; error: string }[] }> {
    const j = this.jobs.get(id);
    if (!j) throw new DeviceError('That scan has expired. Run it again.', 404);
    const added: DeviceView[] = []; const failed: { ip: string; error: string }[] = [];
    for (const ip of ips) {
      const found = j.probes.get(ip);
      if (!found) { failed.push({ ip, error: 'Not found by this scan' }); continue; }
      try { added.push(await this.devs.add({ ip, credId: found.credId, probed: found.p, source: `Discovered ${j.spec}`, intervalSec })); j.probes.delete(ip); const r = j.results.find(x => x.ip === ip); if (r) r.status = 'already'; }
      catch (e) { failed.push({ ip, error: (e as Error).message }); }
    }
    if (added.length) this.log.audit(user, `Added ${added.length} device${added.length === 1 ? '' : 's'} from discovery ${j.spec}: ${added.map(d => d.name).join(', ')}`);
    return { added, failed };
  }
}
