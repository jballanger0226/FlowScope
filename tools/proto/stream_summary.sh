#!/usr/bin/env bash
# Prototype of the stream summary table (docs/design/stream-summary.md). Run on the ClickHouse box. It only creates tables whose names start with proto_;
# flow_raw is read, never changed. `cleanup` removes everything it made.
#
#   tools/proto/stream_summary.sh setup      create proto_stream_dir and backfill it from flow_raw (a day at a time), then attach the live view
#   tools/proto/stream_summary.sh bench      time the current search shape against the summary for 1 hour, 24 hours and everything, with row counts and memory
#   tools/proto/stream_summary.sh load       replay the last hour of flow_raw into scratch tables with and without the view, at small insert blocks, to find the insert ceiling
#   tools/proto/stream_summary.sh cleanup    drop every proto_ table and view
#
# Environment: DB (default flowscope), CH_ARGS (extra clickhouse-client arguments, e.g. "--user x --password y").
set -euo pipefail
DB="${DB:-flowscope}"
CH_ARGS="${CH_ARGS:-}"
ch() { clickhouse-client $CH_ARGS --database "$DB" "$@"; }
q()  { ch --multiquery --query "$1"; }

DIR_COLS="skey String, src_ip String, sport UInt16, day UInt32,
  dst_ip SimpleAggregateFunction(any, String), dport SimpleAggregateFunction(any, UInt16), proto SimpleAggregateFunction(any, UInt8),
  t0 SimpleAggregateFunction(min, Int64), t1 SimpleAggregateFunction(max, Int64),
  b SimpleAggregateFunction(sum, UInt64), p SimpleAggregateFunction(sum, UInt64),
  d_in AggregateFunction(argMin, UInt8, Int64), d_min SimpleAggregateFunction(min, UInt8), d_max SimpleAggregateFunction(max, UInt8),
  rm SimpleAggregateFunction(max, UInt8), d_post SimpleAggregateFunction(max, Int16),
  exps SimpleAggregateFunction(groupUniqArrayArray, Array(String)), vlan SimpleAggregateFunction(max, Int32), fl SimpleAggregateFunction(max, UInt16),
  ttl_lo SimpleAggregateFunction(min, UInt8)"

# one row per (stream, sender, port, day) out of a block of raw records
SELECT_DIR="SELECT skey, src_ip, sport, toUInt32(toYYYYMMDD(toDateTime(intDiv(ts1, 1000), 'UTC'))) AS day,
    any(dst_ip) AS dst_ip, any(dport) AS dport, any(proto) AS proto, min(ts0) AS t0, max(ts1) AS t1,
    sumIf(nbytes, primary_hop = 1) AS b, sumIf(npkts, primary_hop = 1) AS p,
    argMinState(bitShiftRight(tos, 2), ts0) AS d_in, min(bitShiftRight(tos, 2)) AS d_min, max(bitShiftRight(tos, 2)) AS d_max,
    max(toUInt8(isNotNull(post_tos) AND bitShiftRight(assumeNotNull(post_tos), 2) != bitShiftRight(tos, 2))) AS rm,
    maxIf(toInt16(bitShiftRight(assumeNotNull(post_tos), 2)), isNotNull(post_tos) AND bitShiftRight(assumeNotNull(post_tos), 2) != bitShiftRight(tos, 2)) AS d_post,
    groupUniqArray(exporter) AS exps, max(toInt32(ifNull(vlan, 0))) AS vlan, max(flags) AS fl, min(ifNull(ttl_min, 255)) AS ttl_lo"

create_dir() {  # $1 table name
  q "CREATE TABLE IF NOT EXISTS $1 ($DIR_COLS) ENGINE = AggregatingMergeTree PARTITION BY day ORDER BY (skey, src_ip, sport)"
}

case "${1:-}" in
setup)
  create_dir proto_stream_dir
  echo "Backfilling, one day at a time..."
  for d in $(ch --query "SELECT DISTINCT toYYYYMMDD(toDateTime(intDiv(ts1, 1000), 'UTC')) FROM flow_raw ORDER BY 1"); do
    t=$(date +%s)
    q "INSERT INTO proto_stream_dir $SELECT_DIR FROM flow_raw WHERE toYYYYMMDD(toDateTime(intDiv(ts1, 1000), 'UTC')) = $d GROUP BY skey, src_ip, sport, day SETTINGS max_memory_usage = 6000000000, max_bytes_before_external_group_by = 2000000000"
    echo "  day $d: $(( $(date +%s) - t )) s"
  done
  # live view last. A few minutes of records around this moment can be counted twice; fine for a prototype, the real change backfills up to a recorded cut-off.
  q "CREATE MATERIALIZED VIEW IF NOT EXISTS proto_stream_dir_mv TO proto_stream_dir AS $SELECT_DIR FROM flow_raw GROUP BY skey, src_ip, sport, day"
  q "SELECT 'flow_raw rows' AS what, count() AS n FROM flow_raw UNION ALL SELECT 'summary rows', count() FROM proto_stream_dir UNION ALL SELECT 'distinct streams', uniqExact(skey) FROM proto_stream_dir"
  ;;
bench)
  now_ms=$(( $(date +%s) * 1000 ))
  run() {  # $1 label  $2 from_ms  $3 sql builder name
    for kind in old new; do
      ch --query "$($3 $kind "$2" "$now_ms")" --format Null --log_comment "proto_${kind}_$1" --max_memory_usage 12000000000 --max_execution_time 300 2>&1 | head -3 || true
    done
  }
  # the streams page as the application builds it today (no filters, newest first, 200 rows, exact total)
  list_sql() {
    local from="$2" to="$3" src
    if [ "$1" = old ]; then
      src="SELECT skey AS k, src_ip AS s_ip, sport AS s_port, any(dst_ip) AS d_ip, any(dport) AS d_port, any(proto) AS pr, min(ts0) AS t0, max(ts1) AS t1,
             sumIf(nbytes, primary_hop = 1) AS b, sumIf(npkts, primary_hop = 1) AS p, uniqExact(bitShiftRight(tos, 2)) AS nd,
             max(toUInt8(isNotNull(post_tos) AND bitShiftRight(assumeNotNull(post_tos), 2) != bitShiftRight(tos, 2))) AS rm
           FROM flow_raw WHERE ts1 BETWEEN $from AND $to GROUP BY skey, src_ip, sport"
    else
      src="SELECT * FROM (SELECT skey AS k, src_ip AS s_ip, sport AS s_port, any(dst_ip) AS d_ip, any(dport) AS d_port, any(proto) AS pr, min(t0) AS t0, max(t1) AS t1,
             sum(b) AS b, sum(p) AS p, if(min(d_min) != max(d_max), 2, 1) AS nd, max(rm) AS rm
           FROM proto_stream_dir WHERE day BETWEEN toYYYYMMDD(toDateTime(intDiv($from, 1000), 'UTC')) AND toYYYYMMDD(toDateTime(intDiv($to, 1000), 'UTC'))
           GROUP BY skey, src_ip, sport) WHERE t1 BETWEEN $from AND $to"
    fi
    echo "WITH d AS ($src),
      i AS (SELECT k, argMin(s_ip, t0) AS i_ip, argMin(s_port, t0) AS i_sp FROM d GROUP BY k),
      t AS (SELECT d.k AS k, min(d.t0) AS tt0, max(d.t1) AS tt1, sum(d.b) AS tb, sum(d.p) AS tp, max(d.nd) AS tnd, max(d.rm) AS trm FROM d INNER JOIN i ON i.k = d.k GROUP BY d.k)
      SELECT i.k, i.i_ip, i.i_sp, t.tt0, t.tt1, t.tb, t.tp, if(t.tnd > 1 OR t.trm = 1, 1, 0) AS qchg, count() OVER () AS total
      FROM i INNER JOIN t ON t.k = i.k ORDER BY t.tt1 DESC LIMIT 200"
  }
  run 1h  $(( now_ms - 3600000 ))        list_sql
  run 24h $(( now_ms - 86400000 ))       list_sql
  run all 0                              list_sql
  ch --query "SYSTEM FLUSH LOGS"
  ch --query "SELECT replaceOne(log_comment, 'proto_', '') AS run, round(query_duration_ms / 1000, 2) AS seconds, formatReadableQuantity(read_rows) AS rows_read,
      formatReadableSize(memory_usage) AS peak_memory FROM system.query_log WHERE type = 'QueryFinish' AND log_comment LIKE 'proto_%' AND event_time > now() - INTERVAL 30 MINUTE
      ORDER BY splitByChar('_', log_comment)[3], splitByChar('_', log_comment)[2]" --format PrettyCompactMonoBlock
  ;;
load)
  q "DROP TABLE IF EXISTS proto_load_mv; DROP TABLE IF EXISTS proto_load_dir; DROP TABLE IF EXISTS proto_load_plain; DROP TABLE IF EXISTS proto_load_withview"
  q "CREATE TABLE proto_load_plain AS flow_raw; CREATE TABLE proto_load_withview AS flow_raw"
  create_dir proto_load_dir
  q "CREATE MATERIALIZED VIEW proto_load_mv TO proto_load_dir AS $SELECT_DIR FROM proto_load_withview GROUP BY skey, src_ip, sport, day"
  mx=$(ch --query "SELECT max(ts1) FROM flow_raw")
  rows=$(ch --query "SELECT count() FROM flow_raw WHERE ts1 > $mx - 3600000")
  echo "Replaying the last hour ($rows rows) in blocks of 500 rows, the size the application inserts at today."
  for t in proto_load_plain proto_load_withview; do
    s=$(date +%s.%N)
    q "INSERT INTO $t SELECT * FROM flow_raw WHERE ts1 > $mx - 3600000 SETTINGS max_block_size = 500, min_insert_block_size_rows = 500, min_insert_block_size_bytes = 0, max_insert_threads = 1"
    e=$(date +%s.%N)
    awk -v t="$t" -v s="$s" -v e="$e" -v r="$rows" 'BEGIN { d = e - s; printf "  %-22s %7.1f s   %8.0f rows/s\n", t, d, r / d }'
  done
  echo "Today's rate is about 650 rows/s; ten times that is 6,500 rows/s."
  q "DROP TABLE proto_load_mv; DROP TABLE proto_load_dir; DROP TABLE proto_load_plain; DROP TABLE proto_load_withview"
  ;;
cleanup)
  q "DROP TABLE IF EXISTS proto_stream_dir_mv; DROP TABLE IF EXISTS proto_stream_dir; DROP TABLE IF EXISTS proto_load_mv; DROP TABLE IF EXISTS proto_load_dir; DROP TABLE IF EXISTS proto_load_plain; DROP TABLE IF EXISTS proto_load_withview"
  echo "Removed."
  ;;
*) sed -n 2,13p "$0"; exit 1 ;;
esac
