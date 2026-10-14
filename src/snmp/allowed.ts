import net from 'node:net';

/**
 * The networks that SNMP-role users may send stored credentials to. Empty means no limit, which is how earlier versions behaved.
 * Entries are IPv4 or IPv6 addresses or CIDR prefixes, separated by commas, spaces or line breaks. Administrators are never limited.
 */
export class TargetPolicy {
  private list = new net.BlockList();
  readonly entries: string[];
  constructor(text: string) {
    this.entries = [];
    for (const raw of (text || '').split(/[\s,;]+/).filter(Boolean)) {
      const m = /^([^/]+)(?:\/(\d{1,3}))?$/.exec(raw);
      const addr = m?.[1] ?? '';
      const fam = net.isIPv4(addr) ? 'ipv4' : net.isIPv6(addr) ? 'ipv6' : null;
      if (!m || !fam) throw new Error(`"${raw}" is not an address or prefix like 10.0.0.0/24`);
      const max = fam === 'ipv4' ? 32 : 128;
      if (m[2] === undefined) this.list.addAddress(addr, fam);
      else {
        const bits = Number(m[2]);
        if (bits > max) throw new Error(`"${raw}": the prefix length can be at most ${max}`);
        this.list.addSubnet(addr, bits, fam);
      }
      this.entries.push(raw);
    }
  }
  get open(): boolean { return this.entries.length === 0; }
  allows(ip: string): boolean {
    if (this.open) return true;
    const v4 = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
    const a = v4 ? v4[1] : ip;
    const fam = net.isIPv4(a) ? 'ipv4' : net.isIPv6(a) ? 'ipv6' : null;
    return !!fam && this.list.check(a, fam);
  }
}
