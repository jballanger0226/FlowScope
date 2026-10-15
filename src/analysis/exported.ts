/**
 * Says which of the L2 and TTL details an exporter does not send, from the field ids in its templates (IANA IPFIX / NetFlow v9 numbering).
 * The ingress fields are the ones FlowScope shows ("Frame in"); a template that carries only the egress ones (post-routing) is called out
 * because the data is there but is not the same thing.
 */
export function notExported(version: string, ids: ReadonlySet<number> | null): string[] {
  if (version === 'v5') return ['MAC addresses', 'VLAN', 'TTL (NetFlow v5 does not carry them)'];
  if (!ids) return [];
  const has = (...f: number[]) => f.some(x => ids.has(x));
  const out: string[] = [];
  if (!has(56, 80)) out.push(has(57, 81) ? 'MAC addresses (only the output-side fields are sent)' : 'MAC addresses');
  if (!has(58, 243)) out.push(has(59) ? 'VLAN (only the output-side field is sent)' : 'VLAN');
  if (!has(52, 53)) out.push('TTL');
  return out;
}
