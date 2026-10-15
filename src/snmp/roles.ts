/** Guesses what kind of network device an SNMP agent is from what it says about itself. */
export function guessRole(descr: string, name: string, objectId = ''): string {
  const t = (descr + ' ' + name).toLowerCase();
  // wireless access points, before the switch test: an Aruba AP says "ArubaOS (MODEL: 535)", a controller or switch has a longer model name
  // other vendors: Ubiquiti UniFi (enterprise 41112) and Ruckus (25053) devices are access points or Wi-Fi controllers; Meraki, Cambium, Omada, FortiAP and Cisco lightweight APs say so in their description
  if (/^1\.3\.6\.1\.4\.1\.(41112|25053)\./.test(objectId) || /meraki mr\d|cambium|cnpilot|epmp|\beap\d{3}\b|fortiap|\bfap-?\d{2,3}|cisco ap software|ruckus wireless (r|h|t|e|zf|zd|m)\d{2,4}\b|ruckus (unleashed|zonedirector)/.test(t)) return 'ap';
  if (/^1\.3\.6\.1\.4\.1\.14823\.1\.2\./.test(objectId) || /arubaos \(model: \d{3}[a-z]{0,2}\)|access point|wireless ap\b|aironet|\bunifi\b.*\bap\b|(^|[-_ ])(ap|iap|wap)([-_ ]|\d|$)/.test(t)) return 'ap';
  if (/firewall|\basa\b|fortigate|pan-os|palo alto|checkpoint|sonicwall|srx|opnsense|pfsense/.test(t) || /(^|[-_])(fw|firewall)([-_]|\d|$)/.test(name.toLowerCase())) return 'firewall';
  if (/switch|catalyst|nexus|\bex\d|aruba|procurve|ruckus|(^|[-_])(sw|sw\d|access|dist)([-_]|\d|$)/.test(t)) return 'switch';
  if (/router|\bios\b|ios-xe|junos|mx\d|asr|isr|vyos|mikrotik|(^|[-_])(rtr|gw|edge|core)([-_]|\d|$)/.test(t)) return 'router';
  return 'device';
}
