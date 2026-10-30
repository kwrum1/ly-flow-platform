package main

import (
	"context"
	"fmt"
	"math"
	"time"
)

// retentionPromiseDays is the number of days of event history LyFlow promises
// to keep available for investigation.
const retentionPromiseDays = 30

// retentionAuditQuery reads the retained event window directly from the
// ClickHouse event table. It intentionally has no WHERE clause so the answer
// reflects everything that is actually still stored.
const retentionAuditQuery = "SELECT min(event_at) AS earliest, max(event_at) AS latest, count() AS rows " +
	"FROM lyflow_events_v2 FORMAT JSONEachRow"

// retentionAudit is the result of checking how far back events are retained.
type retentionAudit struct {
	Earliest  time.Time `json:"earliest"`
	Latest    time.Time `json:"latest"`
	Rows      int64     `json:"rows"`
	SpanDays  float64   `json:"span_days"`
	Status    string    `json:"status"`
	Reason    string    `json:"reason,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

// retentionQuerier is the minimal read surface the audit needs. Callers can
// back it with the ClickHouse HTTP client or with a fake in tests.
type retentionQuerier interface {
	QueryRetention(ctx context.Context) (earliest, latest time.Time, rows int64, err error)
}

// evaluateRetention derives the retention audit from an observed event window.
// It is pure: the only clock it uses is the supplied now.
func evaluateRetention(earliest, latest time.Time, rows int64, now time.Time) retentionAudit {
	audit := retentionAudit{
		Earliest:  earliest,
		Latest:    latest,
		Rows:      rows,
		CheckedAt: now,
	}

	if rows == 0 {
		audit.Status = "empty"
		audit.Reason = "no events stored"
		return audit
	}
	if earliest.IsZero() || latest.IsZero() {
		audit.Status = "unknown"
		audit.Reason = "earliest or latest timestamp not recorded"
		return audit
	}
	if latest.Before(earliest) {
		audit.Status = "invalid"
		audit.Reason = "latest timestamp before earliest timestamp"
		return audit
	}
	futureCutoff := now.Add(5 * time.Minute)
	if earliest.After(futureCutoff) || latest.After(futureCutoff) {
		audit.Status = "invalid"
		audit.Reason = "future timestamp"
		return audit
	}

	spanDays := math.Round(latest.Sub(earliest).Hours()/24*10) / 10
	audit.SpanDays = spanDays

	if spanDays >= retentionPromiseDays-1 {
		audit.Status = "ok"
		return audit
	}
	audit.Status = "short"
	audit.Reason = fmt.Sprintf("observed span %.1f days is below promised %d days",
		spanDays, retentionPromiseDays)
	return audit
}

// runRetentionAudit asks the querier for the stored event window and evaluates
// it. Querier errors are returned unchanged so callers can classify them.
func runRetentionAudit(ctx context.Context, q retentionQuerier, now time.Time) (retentionAudit, error) {
	earliest, latest, rows, err := q.QueryRetention(ctx)
	if err != nil {
		return retentionAudit{}, err
	}
	return evaluateRetention(earliest, latest, rows, now), nil
}
