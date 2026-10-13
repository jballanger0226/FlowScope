/** One unidirectional flow record as reported by one exporter. Times are milliseconds since the Unix epoch. */
export interface FlowRecord {
  ts0: number;
  ts1: number;
  exporter: string;
  inIf: number;
  outIf: number;
  srcIp: string;
  dstIp: string;
  proto: number;
  sport: number;
  dport: number;
  flags: number;
  /** Full IP TOS byte on ingress (DSCP is tos >> 2). */
  tos: number;
  /** TOS byte after the exporter's egress policy, when the exporter reports it (IPFIX IE 55). */
  postTos: number | null;
  ttlMin: number | null;
  ttlMax: number | null;
  bytes: number;
  pkts: number;
  srcMac: string | null;
  dstMac: string | null;
  vlan: number | null;
  natSrcIp: string | null;
  natDstIp: string | null;
  natSport: number | null;
  natDport: number | null;
  nextHop: string | null;
  sampling: number;
}

export interface DecodeStats {
  packets: number;
  records: number;
  v5: number;
  v9: number;
  ipfix: number;
  errors: number;
  missingTemplate: number;
  templates: number;
  discarded: number;
}

export type FlowSink = (records: FlowRecord[], exporter: string, version: string) => void;
