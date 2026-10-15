import type { HopView, NeighborView, PortSource, StreamDetail } from './hops.js';
import { isMulticast } from './hops.js';

/**
 * Fills in the switch ports of a followed stream and says what is cabled to each one.
 *
 * Flow exporters often report only the ingress interface (a switch that exports on input, or one that does not know the egress port for
 * hardware-switched traffic), so a hop can show "out —". The missing port is worked out from what else is known, best evidence first:
 *   1. the other direction of the same stream: the port the reply came IN on is the port the request went OUT of;
 *   2. the neighbour tables: the port whose CDP/LLDP neighbour is the next (or previous) device on the path;
 *   3. host tracking: the port the destination (or source) host is plugged into on that switch.
 * Every filled-in port says which of these it came from, and nothing is guessed beyond them.
 *
 * Each port on the path also lists its CDP / LLDP neighbours, linked to the SNMP target they are when they are one of ours.
 */

export interface PathNeighbor { ifIndex: number; proto: string; name: string; port: string; ip: string; kind: string; caps: string }
export interface PathDevice { id: number; name: string; sysName: string; ips: string[] }
export interface PathEnv {
  devices(): PathDevice[];
  ifName(devId: number, ifIndex: number): string;
  /** ifIndex of the port called `name` (any spelling: Gi1/0/46, GigabitEthernet1/0/46) on a device, or null. */
  ifIndexByName(devId: number, name: string): number | null;
  neighborsOf(devId: number, ifIndex: number): PathNeighbor[];
  neighborsOfDevice(devId: number): PathNeighbor[];
  /** The port a host is plugged into, from MAC and ARP tables; null when not known. */
  locate(ip: string, macHint: string | null): { devId: number; ifIndex: number } | null;
}

const SHORT: [RegExp, string][] = [
  [/^tengigabitethernet/, 'te'], [/^twentyfivegige/, 'twe'], [/^fortygigabitethernet/, 'fo'], [/^hundredgige/, 'hu'], [/^gigabitethernet/, 'gi'],
  [/^fastethernet/, 'fa'], [/^port-channel/, 'po'], [/^ethernet/, 'eth']
];
/** "GigabitEthernet1/0/46", "Gi1/0/46" and "gi 1/0/46" are the same port. */
export function portKey(name: string): string {
  let n = name.trim().toLowerCase().replace(/\s+/g, '');
  for (const [re, to] of SHORT) if (re.test(n)) { n = n.replace(re, to); break; }
  return n;
}

const firstLabel = (n: string): string => n.toLowerCase().split('.')[0];

/** The polled device a neighbour is: by management address (CDP), else by name, with or without the domain. Null when it is not one of ours or when two match. */
export function matchDevice(n: { name: string; ip: string }, devs: PathDevice[]): PathDevice | null {
  if (n.ip) { const d = devs.find(x => x.ips.includes(n.ip)); if (d) return d; }
  const name = n.name.trim().toLowerCase();
  if (!name) return null;
  const exact = devs.filter(d => d.name.toLowerCase() === name || d.sysName.toLowerCase() === name);
  if (exact.length === 1) return exact[0];
  if (exact.length > 1) return null;
  const label = firstLabel(name);
  if (label.length < 3) return null;
  const loose = devs.filter(d => firstLabel(d.name) === label || (d.sysName && firstLabel(d.sysName) === label));
  return loose.length === 1 ? loose[0] : null;
}

/** CDP and LLDP often both describe the same neighbour on a port; show it once, with both protocols named. */
export function neighborViews(rows: PathNeighbor[], env: PathEnv, devs: PathDevice[]): NeighborView[] {
  const out = new Map<string, NeighborView>();
  for (const r of rows) {
    const key = firstLabel(r.name || r.ip) + '|' + portKey(r.port);
    const proto = r.proto === 'cdp' ? 'cdp' : 'lldp';
    const caps = r.caps ? r.caps.split(',').map(x => x.trim()).filter(Boolean) : [];
    const have = out.get(key);
    if (have) {
      if (!have.protos.includes(proto)) have.protos.push(proto);
      if (!have.ip && r.ip) have.ip = r.ip;
      for (const c of caps) if (!have.caps.includes(c)) have.caps.push(c);
      continue;
    }
    out.set(key, { protos: [proto], name: r.name, port: r.port, ip: r.ip, kind: r.kind, caps, device: null, devicePort: null });
  }
  for (const v of out.values()) {
    const d = matchDevice(v, devs);
    if (!d) continue;
    v.device = { id: d.id, name: d.name };
    if (v.port) {
      const ix = env.ifIndexByName(d.id, v.port);
      if (ix !== null) v.devicePort = { ifIndex: ix, name: env.ifName(d.id, ix) };
    }
  }
  return [...out.values()].sort((a, b) => a.protos.join().localeCompare(b.protos.join()) || a.name.localeCompare(b.name));
}

type Dir = { hops: HopView[]; src: string; dst: string };

/** The one port of `devId` whose neighbour is device `other`, if there is exactly one. */
function portToward(devId: number, other: number, env: PathEnv, devs: PathDevice[]): number | null {
  const found = new Set<number>();
  for (const n of env.neighborsOfDevice(devId)) { const d = matchDevice(n, devs); if (d && d.id === other) found.add(n.ifIndex); }
  return found.size === 1 ? [...found][0] : null;
}

export function enrichPath(detail: StreamDetail, env: PathEnv, exporterDevice: (exporterIp: string) => number | null): void {
  const devs = env.devices();
  const all = [...detail.forward, ...detail.reverse];
  for (const hp of all) { hp.devId = exporterDevice(hp.exporter); hp.inFrom = hp.inIfIndex ? 'flow' : undefined; hp.outFrom = hp.outIfIndex ? 'flow' : undefined; }

  if (!isMulticast(detail.responder.ip)) {
    // original values only, so one inferred port is never the evidence for another
    const orig = new Map<HopView, { inIx: number; outIx: number }>(all.map(h => [h, { inIx: h.inIfIndex, outIx: h.outIfIndex }]));
    const dirs: [Dir, Dir][] = [
      [{ hops: detail.forward, src: detail.initiator.ip, dst: detail.responder.ip }, { hops: detail.reverse, src: detail.responder.ip, dst: detail.initiator.ip }],
      [{ hops: detail.reverse, src: detail.responder.ip, dst: detail.initiator.ip }, { hops: detail.forward, src: detail.initiator.ip, dst: detail.responder.ip }]
    ];
    for (const [mine, other] of dirs) {
      mine.hops.forEach((hp, i) => {
        if (hp.devId == null) return;
        const devId = hp.devId;
        const counterpart = other.hops.find(o => o.exporter === hp.exporter);
        const prev = i > 0 ? mine.hops[i - 1] : null, next = i < mine.hops.length - 1 ? mine.hops[i + 1] : null;
        const fill = (side: 'in' | 'out', cands: [() => number | null, PortSource][]): void => {
          for (const [get, from] of cands) {
            const ix = get();
            if (!ix) continue;
            if (side === 'in') { hp.inIfIndex = ix; hp.inIf = env.ifName(devId, ix); hp.inFrom = from; }
            else { hp.outIfIndex = ix; hp.outIf = env.ifName(devId, ix); hp.outIfs = [hp.outIf]; hp.outFrom = from; }
            return;
          }
        };
        const here = (ip: string, mac: string | null): number | null => { const at = env.locate(ip, mac); return at && at.devId === devId ? at.ifIndex : null; };
        if (!hp.outIfIndex) fill('out', [
          [() => (counterpart ? orig.get(counterpart)?.inIx ?? 0 : 0), 'reverse'],
          [() => (next?.devId != null ? portToward(devId, next.devId, env, devs) : null), 'neighbor'],
          [() => (!next ? here(mine.dst, hp.frameDst) : null), 'host']
        ]);
        if (!hp.inIfIndex) fill('in', [
          [() => (counterpart ? orig.get(counterpart)?.outIx ?? 0 : 0), 'reverse'],
          [() => (prev?.devId != null ? portToward(devId, prev.devId, env, devs) : null), 'neighbor'],
          [() => (!prev ? here(mine.src, hp.frameSrc) : null), 'host']
        ]);
      });
    }
  }

  for (const hp of all) {
    if (hp.devId == null) continue;
    const devId = hp.devId;
    hp.inNeighbors = hp.inIfIndex ? neighborViews(env.neighborsOf(devId, hp.inIfIndex), env, devs) : [];
    const outs = hp.outIfIndex ? [hp.outIfIndex] : [];
    hp.outNeighbors = outs.length ? neighborViews(env.neighborsOf(devId, hp.outIfIndex), env, devs) : [];
  }
}
