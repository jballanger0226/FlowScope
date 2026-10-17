import type { App } from '../app.js';

/**
 * Hosts that joined a multicast group, as seen in NetFlow. An IGMP version 1 or 2 membership report is an IP packet (protocol 2) from the host to the
 * group address itself, so an exporter that reports it names both the host and the group, and the interface it arrived on.
 *
 * What this cannot see: IGMP version 3 reports go to 224.0.0.22 and carry the groups inside the packet, so only the host is known, not the group.
 * Exporters that do not export control traffic (many do not export IGMP at all), and sampled exports, give nothing or only part of it.
 */
export interface IgmpFlows {
  /** group|ifIndex -> host -> seen in the last few minutes */
  members: Map<string, Map<string, { recent: boolean }>>;
  /** version 1 and 2 reports counted, and the hosts that sent them */
  reports: number; hosts: number;
  /** hosts that sent version 3 reports in the window: they joined something, the group is not visible */
  v3Hosts: number;
  windowMin: number; recentMin: number;
}

const WINDOW_MS = 30 * 60_000, RECENT_MS = 5 * 60_000;
const ip32 = (s: string): number => s.split('.').reduce((t, o) => t * 256 + Number(o), 0);
// 224.0.0.0/24 is link-local control traffic (224.0.0.2 leaves, 224.0.0.22 version 3 reports); groups start at 224.0.1.0
const GROUPS = [{ lo: ip32('224.0.1.0'), hi: ip32('239.255.255.255') }];
const V3 = [{ lo: ip32('224.0.0.22'), hi: ip32('224.0.0.22') }];

export async function igmpFromFlows(app: App, exporterIps: string[], now = Date.now()): Promise<IgmpFlows | null> {
  if (!exporterIps.length) return null;
  const base = { tier: 'raw' as const, prefix: 32, bidir: false, sortBy: 'flows' as const, topN: 5000 };
  const conds = (dst: { lo: number; hi: number }[]) => [{ kind: 'proto' as const, protos: [2] }, { kind: 'dst' as const, m: dst }, { kind: 'exporter' as const, ips: exporterIps }];
  try {
    const [all, recent, v3] = await Promise.all([
      app.store.report({ ...base, range: { from: now - WINDOW_MS, to: now }, dims: ['inIf', 'srcIp', 'dstIp'], conds: conds(GROUPS) }),
      app.store.report({ ...base, range: { from: now - RECENT_MS, to: now }, dims: ['inIf', 'srcIp', 'dstIp'], conds: conds(GROUPS) }),
      app.store.report({ ...base, range: { from: now - WINDOW_MS, to: now }, dims: ['srcIp'], conds: conds(V3) })
    ]);
    // the interface dimension comes back as "exporter#ifIndex"
    const ifOf = (v: string | number | null | undefined): number => Number(String(v ?? '').split('#').pop());
    const fresh = new Set(recent.rows.map(r => `${r.dims.dstIp}|${ifOf(r.dims.inIf)}|${r.dims.srcIp}`));
    const members: IgmpFlows['members'] = new Map(); const hosts = new Set<string>(); let reports = 0;
    for (const r of all.rows) {
      const g = String(r.dims.dstIp), ifx = ifOf(r.dims.inIf), host = String(r.dims.srcIp);
      if (!host || host === '0.0.0.0' || !Number.isFinite(ifx)) continue;
      const k = `${g}|${ifx}`; const m = members.get(k) ?? new Map<string, { recent: boolean }>(); members.set(k, m);
      m.set(host, { recent: fresh.has(`${g}|${ifx}|${host}`) }); hosts.add(host); reports += r.flows;
    }
    return { members, reports, hosts: hosts.size, v3Hosts: v3.rows.length, windowMin: WINDOW_MS / 60_000, recentMin: RECENT_MS / 60_000 };
  } catch { return null; }
}
