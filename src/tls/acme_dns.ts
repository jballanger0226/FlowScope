import { AcmeError, request } from './acme.js';

/** Puts a TXT record in DNS for a dns-01 challenge and returns a function that removes it again. */
export interface DnsProvider {
  present(domain: string, value: string): Promise<() => Promise<void>>;
}

/** The record the CA looks for: _acme-challenge under the name being proven. A wildcard is proven at the name without "*.". */
export const challengeName = (domain: string): string => `_acme-challenge.${domain.replace(/^\*\./, '')}`;

/** Cloudflare's DNS API with an API token that has Zone, DNS, Edit on the zone. */
export class Cloudflare implements DnsProvider {
  constructor(private token: string, private base = 'https://api.cloudflare.com/client/v4') {}

  private async call(method: string, path: string, body?: unknown): Promise<any> {
    const r = await request(this.base + path, { method, headers: { authorization: `Bearer ${this.token}`, 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body), timeoutMs: 20_000 });
    let j: any = null;
    try { j = JSON.parse(r.body.toString('utf8')); } catch { /* handled below */ }
    if (r.status === 401 || r.status === 403) throw new AcmeError('Cloudflare did not accept the API token. It needs the permission Zone, DNS, Edit for the zone.');
    if (!j || j.success === false || r.status >= 400) throw new AcmeError('Cloudflare: ' + (j?.errors?.[0]?.message || `HTTP ${r.status}`));
    return j.result;
  }

  /** The zone is the longest suffix of the name that Cloudflare knows (a.b.example.com tries itself, b.example.com, example.com). */
  private async zoneOf(domain: string): Promise<string> {
    const labels = domain.replace(/^\*\./, '').split('.');
    for (let i = 0; i < labels.length - 1; i++) {
      const cand = labels.slice(i).join('.');
      const zones = await this.call('GET', `/zones?name=${encodeURIComponent(cand)}&per_page=1`) as { id: string }[];
      if (zones?.length) return zones[0]!.id;
    }
    throw new AcmeError(`Cloudflare has no zone for ${domain} that this API token can see.`);
  }

  async present(domain: string, value: string): Promise<() => Promise<void>> {
    const zone = await this.zoneOf(domain);
    const rec = await this.call('POST', `/zones/${zone}/dns_records`, { type: 'TXT', name: challengeName(domain), content: value, ttl: 60 }) as { id: string };
    return async () => { try { await this.call('DELETE', `/zones/${zone}/dns_records/${rec.id}`); } catch { /* a leftover TXT record is harmless; it is removed the next time */ } };
  }
}
