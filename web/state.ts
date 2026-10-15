/** Shared application state. Views keep their own local state in their modules and call redraw() after changing it. */

export interface Caps { flows: boolean; links: boolean; reports: boolean; storage: boolean; devices: boolean; storageEdit: boolean; admin: boolean }
export interface Me { username: string; role: 'ro' | 'snmp' | 'admin'; source: string; csrf: string | null; mustChange: boolean; caps: Caps; collect: { flow: boolean; snmp: boolean; flowAt: number; snmpAt: number }; demo: boolean; idleMinutes: number }
export interface Status { version: string; revision: string; uptimeSec: number; demo: boolean; collect: Me['collect']; collecting: boolean; flow: { packets: number; records: number; errors: number; dropped: number; exporters: number }; snmp: { devices: number; ok: number; failing: number; paused: number }; storeNote: string | null }

export type View = 'overview' | 'explorer' | 'ports' | 'links' | 'devices' | 'storage' | 'reports' | 'admin' | 'account';

export const session = {
  csrf: '' as string,
  me: null as Me | null,
  status: null as Status | null,
  meta: null as { vlans: { id: number; name: string }[]; devices: { id: number; name: string; ip: string; role: string }[]; apps: { name: string; ports: number[] }[]; examples: string[] } | null,
  authCfg: null as { provider: string; saml: boolean; fallback: boolean; demo: boolean } | null,
  view: 'overview' as View,
  params: new URLSearchParams(),
  onExpired: null as null | (() => void),
  redraw: (() => undefined) as () => void
};

export function redraw(): void { session.redraw(); }

export function go(view: View, params: Record<string, string | number | undefined> = {}): void {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== '') p.set(k, String(v));
  const s = p.toString();
  location.hash = '#/' + view + (s ? '?' + s : '');
}

export function parseHash(): { view: View; params: URLSearchParams } {
  const m = /^#\/([a-z]+)(?:\?(.*))?$/.exec(location.hash);
  const views: View[] = ['overview', 'explorer', 'ports', 'links', 'devices', 'storage', 'reports', 'admin', 'account'];
  const v = (m && views.includes(m[1] as View) ? m[1] : 'overview') as View;
  return { view: v, params: new URLSearchParams(m?.[2] ?? '') };
}
