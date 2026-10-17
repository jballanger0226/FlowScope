# Stream summary table (plan)

Status: proposed. Items 1 to 3 (query limits, a cap on wide lists with a "200+" total, and a background Overview refresh) stop one search from taking the machine down. This is the change that makes the lists fast and cheap on a week or more of flows.

## Problem

`searchStreams` rebuilds every stream from raw records on every request: group records by (stream, sender, port), pick the initiator, join the directions together, count, sort, then keep one page. The work grows with the number of raw records in the range, not with the 200 rows shown. A week at the current rate is hundreds of millions of records, and each page click, the Overview and the TTL/QoS counters repeat it.

## Idea

Keep a per-stream summary that is built once, as records arrive, and let the lists read that instead of `flow_raw`. `flow_raw` stays as the source for the hop-by-hop view of one stream (`streamRecords`), which is already a cheap lookup by stream key.

### Table

`flow_stream_dir` (ClickHouse, `AggregatingMergeTree`), one row per stream, direction and day. A stream's records can arrive over hours, so partial states merge in the background.

- Key: `ORDER BY (day, skey, src_ip, sport)`, `PARTITION BY` day (same as `flow_raw`).
- Columns are aggregate states: `minState(ts0)`, `maxState(ts1)`, `sumStateIf(nbytes, primary_hop = 1)`, `sumStateIf(npkts, ...)`, `uniqExactState(dscp)`, `argMinState(dscp, ts0)`, `min/maxState(dscp)`, rewritten-DSCP flags, `groupUniqArrayState(exporter)`, `maxState(vlan)`, `maxState(flags)`, TTL-expired flags, `minState(ttl_min)`, `anyState` of the other end's address and port.
- Fed by a materialised view on `flow_raw` inserts, so it needs no extra write path in the collector.

### Time-ordered list

A second small table, `flow_stream_recent` (plain `MergeTree`, `ORDER BY (t1_bucket, t1, skey)`, short retention such as the raw retention), holds one row per stream with its latest end time. "Newest streams" reads the last N rows of it directly, with no grouping. It can lag the summary table by a minute, which is acceptable for a list sorted by time.

### Sorted by bytes or packets

Read `flow_stream_dir` for the range, merge the days (`-Merge` combinators), `ORDER BY bytes DESC LIMIT`. This is still an aggregation over the number of streams (not records), roughly 1/10 to 1/100 of the records, and it is spillable. If that is still too slow for a month, add a daily top-N table.

### Counts

Totals ("N streams") come from `uniqExact(skey)` over the summary table, which is cheap, and the TTL-expired and QoS-changed counts are `countIf` over the same rows. This replaces `count() OVER ()` over a full rebuild, and the Overview counters become one small query.

## Migration and risk

1. Add the tables and view; backfill the last N days with an `INSERT ... SELECT` from `flow_raw`, a day at a time, throttled. Until a day is backfilled, queries touching it fall back to the current path. Record the backfilled range in the `meta` table.
2. Dual-run behind a setting for one release: run both queries on a sample of requests and log any difference in totals or order.
3. The summary is a derived copy: it is dropped and rebuilt by retention the same way partitions of `flow_raw` are.
4. SQLite has no equivalent and keeps the current path, with items 1 to 3 as its protection. SQLite is meant for small installs, so this is acceptable.

## Decisions

- **Streams that span midnight:** the summary is partitioned by day and a query reads the adjacent days and merges them. No monthly partition.
- **Which streams stay in the recent-streams table:** all of them for a short time (12 to 24 hours), then only the significant ones, kept for the full retention: streams with a TTL-expired or QoS-changed flag, streams where hop analysis found loss or an error, streams above a size threshold, and streams still active. A "significant" flag is computed at insert and updated while the stream is still growing, and the prune waits long enough for a stream to become significant. Pruned streams stay in the summary table, so address search and reports still find them.
- **Sizing:** plan for ten times today's ingest.

## Measured on the production box (2026-10-17)

- Ingest is about 650 rows/s (175,000 to 260,000 rows per 5 minutes) in about 1.6 inserts/s, 7 to 8 ms per insert (worst 16 to 32 ms) and 9 to 12 MiB peak memory.
- The existing rollup view adds 5 ms per insert, writes about 590,000 rows an hour and peaks at 4 MiB. A summary view should cost about the same.
- A heavy 7-day search raised insert time to 50 to 76 ms average and 1.6 s worst while it ran, so the read path must be bounded (done in the limits change).
- About 55 million raw records a day make about 2.7 million streams, which is about 20 records per stream, so the summary should hold about a tenth of the rows.
- Ten times today's rate is about 6,500 rows/s. `tools/proto/stream_summary.sh load` replays the last hour at the application's block size, with and without the view, to find the ceiling.

## Prototype

`tools/proto/stream_summary.sh` creates `proto_` tables only. `setup` builds `proto_stream_dir` (an `AggregatingMergeTree` keyed by stream, sender and port, partitioned by day) and the live view; `bench` times the current query shape against the summary for 1 hour, 24 hours and all data; `load` measures the insert ceiling; `cleanup` removes everything. The prototype omits the TTL-expired flags that depend on the router address list, which will be computed at read time from stored ICMP and TTL columns.

## Open questions

- What is the extra storage per day, and does the summary compress as well as the raw table? Answered by `setup`.
- Can the "significant" flag be computed in the view, or does it need a periodic job? Depends on how soon hop-analysis findings (loss, latency) are available; those come from several exporters' records, so a job is likely.

## Rough sequence

1. Prototype the view and one query by hand on the production ClickHouse and time it against the current query for 1 h, 24 h and 7 d.
2. Implement the table creation, the backfill and the new read path behind a setting.
3. Dual-run, then switch the default and remove the old path for ClickHouse.
