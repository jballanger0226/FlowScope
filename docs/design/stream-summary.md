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

## Open questions

- A stream that spans midnight lands in two day partitions: should the merge read adjacent days, or should the summary partition by month?
- How much more insert load does the materialised view add at the highest rate we plan to ingest? Needs a measurement on the production box.
- Should the recent-streams table keep every stream, or only those above a size or with a TTL or QoS flag, for a much smaller table?

## Rough sequence

1. Prototype the view and one query by hand on the production ClickHouse and time it against the current query for 1 h, 24 h and 7 d.
2. Implement the table creation, the backfill and the new read path behind a setting.
3. Dual-run, then switch the default and remove the old path for ClickHouse.
