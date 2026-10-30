package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type retentionFakeQuerier struct {
	earliest time.Time
	latest   time.Time
	rows     int64
	err      error
	calls    int
}

func (fake *retentionFakeQuerier) QueryRetention(ctx context.Context) (time.Time, time.Time, int64, error) {
	fake.calls++
	if fake.err != nil {
		return time.Time{}, time.Time{}, 0, fake.err
	}
	return fake.earliest, fake.latest, fake.rows, nil
}

func retentionTestNow() time.Time {
	return time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
}

func TestRetentionAuditEmptyWhenNoEvents(t *testing.T) {
	now := retentionTestNow()
	audit := evaluateRetention(time.Time{}, time.Time{}, 0, now)
	if audit.Status != "empty" {
		t.Fatalf("status=%q, want empty", audit.Status)
	}
	if audit.Reason != "no events stored" {
		t.Fatalf("reason=%q, want %q", audit.Reason, "no events stored")
	}
	if audit.Rows != 0 || audit.SpanDays != 0 {
		t.Fatalf("empty audit carries rows=%d span=%v", audit.Rows, audit.SpanDays)
	}
	if !audit.CheckedAt.Equal(now) {
		t.Fatalf("checked_at=%v, want %v", audit.CheckedAt, now)
	}
}

func TestRetentionAuditOKAtPromiseBoundary(t *testing.T) {
	now := retentionTestNow()
	// 29 days of history: the allowed one day of partition/clock slack.
	earliest := now.Add(-29 * 24 * time.Hour)
	latest := now.Add(-time.Hour)
	audit := evaluateRetention(earliest, latest, 4200, now)
	if audit.Status != "ok" {
		t.Fatalf("status=%q reason=%q, want ok", audit.Status, audit.Reason)
	}
	if audit.SpanDays < 28.9 || audit.SpanDays > 29.1 {
		t.Fatalf("span_days=%v, want about 29", audit.SpanDays)
	}
	if audit.Reason != "" {
		t.Fatalf("ok audit has reason %q", audit.Reason)
	}
	if !audit.Earliest.Equal(earliest) || !audit.Latest.Equal(latest) || audit.Rows != 4200 {
		t.Fatalf("audit window not preserved: %#v", audit)
	}
}

func TestRetentionAuditOKForFullPromise(t *testing.T) {
	now := retentionTestNow()
	audit := evaluateRetention(now.Add(-30*24*time.Hour), now.Add(-time.Minute), 9000, now)
	if audit.Status != "ok" {
		t.Fatalf("status=%q reason=%q, want ok", audit.Status, audit.Reason)
	}
	if audit.SpanDays != 30 {
		t.Fatalf("span_days=%v, want 30", audit.SpanDays)
	}
}

func TestRetentionAuditShortWhenSpanBelowPromise(t *testing.T) {
	now := retentionTestNow()
	audit := evaluateRetention(now.Add(-3*24*time.Hour), now.Add(-time.Hour), 120, now)
	if audit.Status != "short" {
		t.Fatalf("status=%q, want short", audit.Status)
	}
	if audit.SpanDays < 2.9 || audit.SpanDays > 3.0 {
		t.Fatalf("span_days=%v, want about 3", audit.SpanDays)
	}
	if !strings.Contains(audit.Reason, "3.0") {
		t.Fatalf("reason=%q does not state observed days", audit.Reason)
	}
	if !strings.Contains(audit.Reason, "30") {
		t.Fatalf("reason=%q does not state promised days", audit.Reason)
	}
}

func TestRetentionAuditInvalidReversedRange(t *testing.T) {
	now := retentionTestNow()
	audit := evaluateRetention(now.Add(-time.Hour), now.Add(-2*time.Hour), 10, now)
	if audit.Status != "invalid" {
		t.Fatalf("status=%q, want invalid", audit.Status)
	}
	if !strings.Contains(audit.Reason, "before") {
		t.Fatalf("reason=%q does not describe reversed range", audit.Reason)
	}
}

func TestRetentionAuditInvalidFutureTimestamp(t *testing.T) {
	now := retentionTestNow()
	cases := []struct {
		name       string
		earliest   time.Time
		latest     time.Time
		wantStatus string
	}{
		{name: "latest in future", earliest: now.Add(-48 * time.Hour), latest: now.Add(10 * time.Minute), wantStatus: "invalid"},
		{name: "earliest in future", earliest: now.Add(10 * time.Minute), latest: now.Add(20 * time.Minute), wantStatus: "invalid"},
		{name: "within five minute grace", earliest: now.Add(-30 * 24 * time.Hour), latest: now.Add(3 * time.Minute), wantStatus: "ok"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			audit := evaluateRetention(testCase.earliest, testCase.latest, 5, now)
			if audit.Status != testCase.wantStatus {
				t.Fatalf("status=%q reason=%q, want %s", audit.Status, audit.Reason, testCase.wantStatus)
			}
			if testCase.wantStatus == "invalid" && audit.Reason != "future timestamp" {
				t.Fatalf("reason=%q, want future timestamp", audit.Reason)
			}
		})
	}
}

func TestRetentionAuditUnknownForZeroTimestamps(t *testing.T) {
	now := retentionTestNow()
	cases := []struct {
		name     string
		earliest time.Time
		latest   time.Time
	}{
		{name: "zero earliest", earliest: time.Time{}, latest: now.Add(-time.Hour)},
		{name: "zero latest", earliest: now.Add(-24 * time.Hour), latest: time.Time{}},
		{name: "both zero", earliest: time.Time{}, latest: time.Time{}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			audit := evaluateRetention(testCase.earliest, testCase.latest, 7, now)
			if audit.Status != "unknown" {
				t.Fatalf("status=%q reason=%q, want unknown", audit.Status, audit.Reason)
			}
			if audit.Reason == "" {
				t.Fatal("unknown audit has no reason")
			}
			if !audit.CheckedAt.Equal(now) {
				t.Fatalf("checked_at=%v, want %v", audit.CheckedAt, now)
			}
		})
	}
}

func TestRetentionAuditRunUsesQuerierWindow(t *testing.T) {
	now := retentionTestNow()
	fake := &retentionFakeQuerier{
		earliest: now.Add(-31 * 24 * time.Hour),
		latest:   now.Add(-time.Minute),
		rows:     10000,
	}
	audit, err := runRetentionAudit(context.Background(), fake, now)
	if err != nil {
		t.Fatalf("run retention audit: %v", err)
	}
	if fake.calls != 1 {
		t.Fatalf("querier calls=%d, want 1", fake.calls)
	}
	if audit.Status != "ok" || audit.Rows != 10000 || !audit.CheckedAt.Equal(now) {
		t.Fatalf("unexpected audit: %#v", audit)
	}
}

func TestRetentionAuditRunPropagatesQuerierError(t *testing.T) {
	wantErr := errors.New("clickhouse unavailable")
	fake := &retentionFakeQuerier{err: wantErr}
	audit, err := runRetentionAudit(context.Background(), fake, retentionTestNow())
	if !errors.Is(err, wantErr) {
		t.Fatalf("error=%v, want %v", err, wantErr)
	}
	if err != wantErr {
		t.Fatalf("error was wrapped: %v", err)
	}
	if audit != (retentionAudit{}) {
		t.Fatalf("audit=%#v, want zero value on error", audit)
	}
}

func TestRetentionAuditQueryTargetsEventWindow(t *testing.T) {
	for _, fragment := range []string{"min(event_at)", "max(event_at)", "count()", "FROM lyflow_events_v2", "FORMAT JSONEachRow"} {
		if !strings.Contains(retentionAuditQuery, fragment) {
			t.Fatalf("retentionAuditQuery missing %q: %s", fragment, retentionAuditQuery)
		}
	}
}
