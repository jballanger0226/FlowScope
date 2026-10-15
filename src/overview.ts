/**
 * The home page's summary logic: which SNMP devices are down and for how long, and which notices matter most.
 * Everything here is a pure function of its input, so it is tested without a running server.
 *
 * What counts as a notice is decided by the same rules the Network health page uses for one device ("Needs attention"),
 * so a notice on the home page always matches what the device's own page shows. Those rules live in web/views/overview_logic.ts,
 * which has no browser dependencies.
 */
import { issues, type OvInput, type Target } from '../web/views/overview_logic.js';

/** A tab of one device's page on Network health, and for an interface problem the interface and the section with the detail. */
export type NoticeTarget = { tab: Target['tab'] | 'overview'; ifIndex?: number; section?: 'traffic' | 'quality' };

/** The fields of a polled device this module needs. */
export interface DeviceState { id: number; name: string; ip: string; role: string; status: 'ok' | 'error' | 'paused' | 'pending'; lastOk: number | null; lastError: string | null; addedAt: number }

export interface DownDevice {
  id: number; name: string; ip: string; role: string;
  /** When it last answered. When it never has, the moment it was added. */
  since: number;
  /** True when no poll has ever succeeded, so "down since" is only when it was added. */
  neverReached: boolean;
  /** How long it has been unreachable, in milliseconds, as of `now`. */
  downMs: number;
  lastError: string | null;
}

/**
 * Devices whose latest poll failed, longest outage first.
 * A device is "down" from its last successful poll: the exact moment it dropped lies between that poll and the next one,
 * so the duration is accurate to within one polling interval.
 */
export function downDevices(devs: DeviceState[], now: number): DownDevice[] {
  return devs.filter(d => d.status === 'error').map(d => {
    const since = d.lastOk ?? d.addedAt;
    return { id: d.id, name: d.name, ip: d.ip, role: d.role, since, neverReached: d.lastOk === null, downMs: Math.max(0, now - since), lastError: d.lastError };
  }).sort((a, b) => b.downMs - a.downMs || a.name.localeCompare(b.name));
}

export interface Notice {
  level: 'bad' | 'warn';
  kind: 'device-down' | 'issue';
  title: string;
  detail: string;
  devId: number; dev: string;
  /** Where to review it: a tab of the device's page on Network health, and for an interface problem the interface and section. */
  target: NoticeTarget;
}

/** How much a problem on this kind of device affects the network around it. */
const ROLE_WEIGHT: Record<string, number> = { firewall: 10, router: 10, switch: 6 };

/** Higher is worse. A bad notice always outranks a warning; a device that cannot be reached outranks everything else of its level. */
export function impact(n: Pick<Notice, 'level' | 'kind'>, role: string): number {
  return (n.level === 'bad' ? 100 : 50) + (n.kind === 'device-down' ? 20 : 0) + (ROLE_WEIGHT[role] ?? 2);
}

export interface NoticeInput { dev: DeviceState; ov: OvInput | null }

/**
 * Every notice across all devices, highest impact first.
 * A device that is not answering gets one "not responding" notice and nothing else, because the interface and sensor readings
 * it left behind are old and would only mislead. Devices that are paused or not yet polled raise none.
 */
export function buildNotices(inputs: NoticeInput[], now: number): Notice[] {
  const scored: { n: Notice; score: number }[] = [];
  for (const { dev, ov } of inputs) {
    if (dev.status === 'error') {
      const d = downDevices([dev], now)[0]!;
      const n: Notice = {
        level: 'bad', kind: 'device-down', title: `${dev.name} is not responding`,
        detail: d.neverReached ? 'It has never answered an SNMP poll.' : 'It stopped answering SNMP polls. The page above shows for how long.',
        devId: dev.id, dev: dev.name, target: { tab: 'overview' }
      };
      scored.push({ n, score: impact(n, dev.role) });
      continue;
    }
    if (dev.status !== 'ok' || !ov) continue;
    for (const i of issues(ov)) {
      const n: Notice = { level: i.level, kind: 'issue', title: i.title, detail: i.detail, devId: dev.id, dev: dev.name, target: i.target ?? { tab: 'interfaces' } };
      scored.push({ n, score: impact(n, dev.role) });
    }
  }
  return scored.sort((a, b) => b.score - a.score || a.n.dev.localeCompare(b.n.dev) || a.n.title.localeCompare(b.n.title)).map(s => s.n);
}

/** Flow exporters silent for longer than this are reported as not sending. Exporters usually send every few seconds to a minute. */
export const EXPORTER_STALE_MS = 5 * 60_000;

export interface ExporterState { ip: string; name: string; /** The polled device this exporter is, or null when it is not polled. */ devId: number | null; version: string; records: number; lastSeen: number; lastError: string | null }

/** How many exporters are sending, and which ones went quiet, longest silence first. */
export function exporterSummary(list: ExporterState[], now: number): { total: number; active: number; silent: (ExporterState & { silentMs: number })[] } {
  const silent = list.filter(e => now - e.lastSeen > EXPORTER_STALE_MS).map(e => ({ ...e, silentMs: now - e.lastSeen })).sort((a, b) => b.silentMs - a.silentMs);
  return { total: list.length, active: list.length - silent.length, silent };
}
