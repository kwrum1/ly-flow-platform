package main

import "time"

// defaultObservabilityWindow bounds list queries that do not specify a time
// range. Both the threat list and the session list used to run with "1=1",
// which made ClickHouse scan 31M session rows (ordered by session_uid, not by
// time) and Postgres aggregate the whole threat table. Seven days keeps the
// live view useful while letting the observed_at minmax index prune.
const defaultObservabilityWindow = 7 * 24 * time.Hour

func defaultObservabilityFrom(now time.Time) *time.Time {
	from := now.UTC().Add(-defaultObservabilityWindow)
	return &from
}
