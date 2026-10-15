import { h, type VNode } from './vdom.js';
import { go } from './state.js';

/** What CDP / LLDP says is at the other end of a port. `device` is set when that neighbour is one of the polled SNMP devices. */
export interface Neighbor {
  protos: string[]; name: string; port: string; ip: string; kind: string; caps: string[];
  device: { id: number; name: string } | null; devicePort: { ifIndex: number; name: string } | null;
}
export type PortSource = 'flow' | 'reverse' | 'neighbor' | 'host';

export const KIND_TEXT: Record<string, string> = { infra: 'switch or router', phone: 'IP phone', ap: 'wireless access point', host: 'end host', other: 'other device', unknown: 'unknown device' };

export const PORT_SOURCE_TEXT: Record<string, string> = {
  reverse: 'The exporter did not report this port. It is the port the other direction of this stream used on the same device.',
  neighbor: 'The exporter did not report this port. It is the only port whose CDP/LLDP neighbour is the next (or previous) device on the path.',
  host: 'The exporter did not report this port. The MAC address and ARP tables show the host is plugged in to it.'
};

/** Opens the Network health page on a device and port. */
export function openPort(dev: string, port?: string): void { go('links', { dev, if: port }); }

/** A port name that opens that port in Network health, with a note when it was worked out rather than exported. */
export function portLink(dev: string, name: string, from?: PortSource, canOpen = true): VNode {
  const label = name || '—';
  const link = canOpen && name && name !== '—'
    ? h('button', { type: 'button', class: 'lnk', title: `Open ${label} on ${dev}`, onclick: () => openPort(dev, name) }, label)
    : h('span', null, label);
  return from && from !== 'flow' ? h('span', null, link, ' ', h('span', { class: 'tag info', title: PORT_SOURCE_TEXT[from] }, 'worked out')) : link;
}

/** One line per neighbour: protocols, name, remote port, what kind of device it is, and links to it when it is a polled device. */
export function neighborLines(ns: Neighbor[] | undefined): VNode | null {
  if (!ns || !ns.length) return null;
  return h('div', { class: 'nbrs' }, ns.map((n, i) => {
    const what = KIND_TEXT[n.kind] ?? n.kind;
    return h('div', { key: i, class: 'nbr', title: `${n.protos.map(p => p.toUpperCase()).join(' and ')} neighbour${n.ip ? ' ' + n.ip : ''}${n.caps.length ? ' · ' + n.caps.join(', ') : ''}` },
      h('span', { class: 'dim' }, n.protos.map(p => p.toUpperCase()).join('·') + ' '),
      n.device
        ? h('button', { type: 'button', class: 'lnk', title: `Open ${n.device.name} in Network health`, onclick: () => openPort(n.device!.name, n.devicePort?.name) }, n.name || n.device.name)
        : h('span', null, n.name || n.ip || 'unnamed'),
      n.port ? h('span', { class: 'dim' }, ' · ' + n.port) : null,
      h('span', { class: 'dim' }, ` (${what}${n.device ? ', polled' : ''})`));
  }));
}
