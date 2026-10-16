/**
 * Whether an IPv4 address is a public (internet-routable) address. Kept free of browser code so the tests can import it.
 *
 * Everything that is reserved for private use, sharing, loopback, link-local, documentation, benchmarking, multicast or future use is NOT public.
 * Carrier-grade NAT space (100.64.0.0/10) counts as not public: it is not reachable from the internet either.
 */
const RESERVED: readonly (readonly [string, number])[] = [
  ['0.0.0.0', 8],        // "this network"
  ['10.0.0.0', 8],       // private
  ['100.64.0.0', 10],    // carrier-grade NAT
  ['127.0.0.0', 8],      // loopback
  ['169.254.0.0', 16],   // link-local
  ['172.16.0.0', 12],    // private
  ['192.0.0.0', 24],     // IETF protocol assignments
  ['192.0.2.0', 24],     // documentation (TEST-NET-1)
  ['192.168.0.0', 16],   // private
  ['198.18.0.0', 15],    // benchmarking
  ['198.51.100.0', 24],  // documentation (TEST-NET-2)
  ['203.0.113.0', 24],   // documentation (TEST-NET-3)
  ['224.0.0.0', 4],      // multicast
  ['240.0.0.0', 4]       // reserved, including the broadcast address
];

/** The address as a 32-bit number, or null when it is not a dotted IPv4 address. A "/prefix" after it is ignored. */
export function ipv4ToInt(text: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/\d{1,2})?$/.exec(text.trim());
  if (!m) return null;
  let n = 0;
  for (let k = 1; k <= 4; k++) { const o = Number(m[k]); if (o > 255) return null; n = n * 256 + o; }
  return n;
}

const RANGES = RESERVED.map(([base, bits]) => { const lo = ipv4ToInt(base)!; return { lo, hi: lo + 2 ** (32 - bits) - 1 }; });

/** True for an IPv4 address that is routable on the internet. False for private and other reserved addresses, and for anything that is not an IPv4 address. */
export function isPublicIPv4(text: string): boolean {
  const n = ipv4ToInt(text);
  return n !== null && !RANGES.some(r => n >= r.lo && n <= r.hi);
}

/** The public ones among an interface's addresses, in the form they were given ("203.0.113.9/30"). */
export function publicAddresses(addresses: readonly string[] | null | undefined): string[] {
  return (addresses ?? []).filter(isPublicIPv4);
}
