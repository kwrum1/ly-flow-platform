// Command eventbench generates deterministic EventV2 data, ingests it into
// ClickHouse, and measures query latency percentiles.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
	"github.com/lyflow/ly-flow-platform/server/analytics"
	"github.com/lyflow/ly-flow-platform/server/bench"
)

type ingestResult struct {
	Events       int     `json:"events"`
	Seconds      float64 `json:"seconds"`
	EPS          float64 `json:"eps"`
	BytesApprox  int64   `json:"bytes_approx"`
	Batch        int     `json:"batch"`
	Writers      int     `json:"writers"`
	PayloadBytes int     `json:"payload_bytes"`
}

type queryResult struct {
	Name    string  `json:"name"`
	Samples int     `json:"samples"`
	Errors  int     `json:"errors"`
	P50MS   float64 `json:"p50_ms"`
	P95MS   float64 `json:"p95_ms"`
	P99MS   float64 `json:"p99_ms"`
	Error   string  `json:"error,omitempty"`
}

type report struct {
	ClickHouse string        `json:"clickhouse"`
	Dataset    datasetReport `json:"dataset"`
	Ingest     ingestResult  `json:"ingest"`
	Throughput ingestResult  `json:"throughput"`
	Queries    []queryResult `json:"queries"`
	Status     string        `json:"status"`
	Notes      []string      `json:"notes,omitempty"`
}

type datasetReport struct {
	Days         int       `json:"days"`
	EPS          float64   `json:"eps"`
	Events       int       `json:"events"`
	Start        time.Time `json:"start"`
	End          time.Time `json:"end"`
	PayloadBytes int       `json:"payload_bytes"`
}

func main() {
	clickhouse := flag.String("clickhouse", "http://127.0.0.1:8123", "ClickHouse HTTP endpoint")
	database := flag.String("database", "", "ClickHouse database (optional)")
	days := flag.Int("days", 30, "retention dataset days")
	eps := flag.Float64("eps", 5, "retention dataset events per second")
	payloadBytes := flag.Int("payload-bytes", 0, "retention event payload bytes")
	ingestEPS := flag.Float64("ingest-eps", 20000, "throughput target events per second")
	ingestSeconds := flag.Float64("ingest-seconds", 60, "throughput test duration")
	throughputPayload := flag.Int("throughput-payload-bytes", 0, "throughput event payload bytes (5500 ~= 1Gbps at 20k EPS)")
	batch := flag.Int("batch", 5000, "insert batch size")
	writers := flag.Int("writers", 1, "parallel insert writers")
	iters := flag.Int("iters", 20, "measured iterations per query")
	p95MS := flag.Float64("p95-ms", 2000, "query p95 threshold in milliseconds")
	create := flag.Bool("create", true, "create table and materialized views")
	recreate := flag.Bool("recreate", false, "drop and recreate schema")
	skipRetention := flag.Bool("skip-retention", false, "skip 30-day dataset ingest")
	skipThroughput := flag.Bool("skip-throughput", false, "skip 20k EPS ingest test")
	skipQueries := flag.Bool("skip-queries", false, "skip query latency phase")
	settleSeconds := flag.Int("settle-seconds", 60, "wait for ClickHouse merges before queries")
	optimize := flag.Bool("optimize", false, "run OPTIMIZE TABLE FINAL between ingest and query phases")
	output := flag.String("output", "", "write JSON report")
	flag.Parse()

	if *batch <= 0 || *iters <= 0 {
		log.Fatal("eventbench: batch and iters must be positive")
	}
	logger := log.New(os.Stderr, "eventbench: ", log.LstdFlags)
	client, err := analytics.NewHTTPClickHouse(analytics.HTTPClickHouseConfig{
		Endpoint: *clickhouse, Database: *database, Timeout: 10 * time.Minute,
	})
	if err != nil {
		log.Fatalf("eventbench: %v", err)
	}
	ctx := context.Background()
	if *recreate {
		for _, table := range []string{"lyflow_events_1m", "lyflow_events_1h", "lyflow_events_v2"} {
			if _, err := client.Exec(ctx, "DROP TABLE IF EXISTS "+table); err != nil {
				log.Fatalf("eventbench: drop %s: %v", table, err)
			}
		}
	}
	if *create {
		for _, ddl := range analytics.ClickHouseEventsV2SchemaDDL() {
			if _, err := client.Exec(ctx, ddl); err != nil {
				log.Fatalf("eventbench: create schema: %v", err)
			}
		}
	}

	now := time.Now().UTC()
	start := now.Add(-time.Duration(*days) * 24 * time.Hour)
	generator := bench.NewGenerator(bench.GeneratorConfig{
		Start: start, Days: *days, EPS: *eps, PayloadBytes: *payloadBytes, Seed: 20261019,
	})
	rep := report{
		ClickHouse: *clickhouse,
		Dataset: datasetReport{
			Days: *days, EPS: *eps, Events: generator.Count(), Start: start, End: now,
			PayloadBytes: *payloadBytes,
		},
		Status: "pass",
	}
	if !*skipRetention {
		logger.Printf("ingesting %d retention events (%.1f EPS, %d payload bytes)", generator.Count(), *eps, *payloadBytes)
		rep.Ingest, err = ingest(ctx, client, generator, generator.Count(), *batch, *writers, *payloadBytes, logger, "retention")
		if err != nil {
			log.Fatalf("eventbench: retention ingest: %v", err)
		}
		if *skipThroughput {
			settleTable(ctx, client, *optimize, *settleSeconds, logger)
		} else {
			// Do not OPTIMIZE between retention and throughput: a single huge
			// part makes the large-payload insert slower. Let the throughput
			// phase run, then optimize before queries.
			waitForMerges(ctx, client, *settleSeconds, logger)
		}
	}
	if !*skipThroughput {
		count := int(*ingestEPS * *ingestSeconds)
		throughputGenerator := bench.NewGenerator(bench.GeneratorConfig{
			Start: now.Add(-time.Duration(*ingestSeconds * float64(time.Second))),
			Days:  1, EPS: *ingestEPS, PayloadBytes: *throughputPayload, Seed: 20261020,
		})
		logger.Printf("ingesting %d throughput events at target %.0f EPS for %.0fs", count, *ingestEPS, *ingestSeconds)
		rep.Throughput, err = ingest(ctx, client, throughputGenerator, count, *batch, *writers, *throughputPayload, logger, "throughput")
		if err != nil {
			log.Fatalf("eventbench: throughput ingest: %v", err)
		}
		settleTable(ctx, client, *optimize, *settleSeconds, logger)
	}
	if !*skipQueries {
		rep.Queries = runQueries(ctx, client, now, *iters, *p95MS, logger)
	}
	if !*skipThroughput && rep.Throughput.EPS < *ingestEPS {
		rep.Status = "fail"
		rep.Notes = append(rep.Notes, fmt.Sprintf("throughput %.1f EPS is below target %.1f EPS", rep.Throughput.EPS, *ingestEPS))
	}
	for _, query := range rep.Queries {
		if query.Errors > 0 || query.P95MS > *p95MS {
			rep.Status = "fail"
		}
	}
	rep.Notes = append(rep.Notes,
		"retention dataset is sampled by -eps; full 30d at 20k EPS would be ~51.8B rows",
		"1Gbps is approximated by throughput payload size; capture throughput is validated separately",
	)
	payload, _ := json.MarshalIndent(rep, "", "  ")
	payload = append(payload, '\n')
	if *output != "" {
		if err := os.WriteFile(*output, payload, 0o644); err != nil {
			log.Fatalf("eventbench: write report: %v", err)
		}
	}
	os.Stdout.Write(payload)
	if rep.Status != "pass" {
		os.Exit(1)
	}
}

func ingest(ctx context.Context, client *analytics.HTTPClickHouse, generator *bench.Generator, count, batch, writers, payloadBytes int, logger *log.Logger, label string) (ingestResult, error) {
	started := time.Now()
	result := ingestResult{Batch: batch, Writers: writers, PayloadBytes: payloadBytes}
	if count <= 0 {
		return result, nil
	}
	if writers < 1 {
		writers = 1
	}
	if writers > count {
		writers = count
	}
	insertCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var inserted atomic.Int64
	var bytesInserted atomic.Int64
	var wg sync.WaitGroup
	var errOnce sync.Once
	var firstErr error
	for writer := 0; writer < writers; writer++ {
		start := count * writer / writers
		end := count * (writer + 1) / writers
		wg.Add(1)
		go func(writer, start, end int) {
			defer wg.Done()
			for offset := start; offset < end; offset += batch {
				if insertCtx.Err() != nil {
					return
				}
				batchEnd := offset + batch
				if batchEnd > end {
					batchEnd = end
				}
				events := make([]contracts.EventV2, 0, batchEnd-offset)
				for index := offset; index < batchEnd; index++ {
					events = append(events, generator.Event(index))
				}
				if err := client.InsertEventsV2(insertCtx, events); err != nil {
					errOnce.Do(func() {
						firstErr = err
						cancel()
					})
					return
				}
				inserted.Add(int64(len(events)))
				bytesInserted.Add(int64(len(events) * (payloadBytes + 512)))
				if ((offset-start)/batch)%20 == 0 {
					elapsed := time.Since(started).Seconds()
					logger.Printf("%s writer=%d: %d/%d events (%.0f EPS)", label, writer, inserted.Load(), count, float64(inserted.Load())/elapsed)
				}
			}
		}(writer, start, end)
	}
	wg.Wait()
	result.Events = int(inserted.Load())
	result.BytesApprox = bytesInserted.Load()
	result.Seconds = time.Since(started).Seconds()
	if result.Seconds > 0 {
		result.EPS = float64(result.Events) / result.Seconds
	}
	return result, firstErr
}

func settleTable(ctx context.Context, client *analytics.HTTPClickHouse, optimize bool, seconds int, logger *log.Logger) {
	if optimize {
		started := time.Now()
		logger.Printf("optimizing lyflow_events_v2 FINAL")
		if _, err := client.Exec(ctx, "OPTIMIZE TABLE lyflow_events_v2 FINAL"); err != nil {
			logger.Printf("optimize failed: %v", err)
			return
		}
		logger.Printf("optimized in %.1fs", time.Since(started).Seconds())
		return
	}
	waitForMerges(ctx, client, seconds, logger)
}

func waitForMerges(ctx context.Context, client *analytics.HTTPClickHouse, seconds int, logger *log.Logger) {
	if seconds <= 0 {
		return
	}
	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	for time.Now().Before(deadline) {
		body, err := client.Exec(ctx, "SELECT count() FROM system.merges WHERE database = currentDatabase() FORMAT TabSeparated")
		if err == nil {
			if count, parseErr := strconv.Atoi(strings.TrimSpace(string(body))); parseErr == nil && count == 0 {
				logger.Printf("clickhouse merges settled")
				time.Sleep(2 * time.Second)
				return
			}
		}
		time.Sleep(2 * time.Second)
	}
	logger.Printf("clickhouse merges did not settle within %ds; continuing", seconds)
}

func runQueries(ctx context.Context, client *analytics.HTTPClickHouse, now time.Time, iters int, p95Threshold float64, logger *log.Logger) []queryResult {
	base := []struct {
		name  string
		query analytics.EventV2Query
	}{
		{"event_list_1h", analytics.EventV2Query{From: now.Add(-time.Hour), To: now, Limit: 50}},
		{"event_list_24h_high", analytics.EventV2Query{From: now.Add(-24 * time.Hour), To: now, Severity: "high", Limit: 50}},
		{"event_list_7d_suricata", analytics.EventV2Query{From: now.Add(-7 * 24 * time.Hour), To: now, Source: "adapter.suricata", Limit: 50}},
		{"keyword_asset_30d", analytics.EventV2Query{From: now.Add(-30 * 24 * time.Hour), To: now, Query: "asset-0042", Limit: 50}},
		{"keyword_ip_24h", analytics.EventV2Query{From: now.Add(-24 * time.Hour), To: now, Query: "10.1.2.3", Limit: 50}},
		{"stage_lateral_7d", analytics.EventV2Query{From: now.Add(-7 * 24 * time.Hour), To: now, Stage: "lateral_movement", Limit: 50}},
	}
	results := make([]queryResult, 0, len(base)+4)
	for _, item := range base {
		result := measureEventQuery(ctx, client, item.name, item.query, iters)
		logger.Printf("query %s: p50=%.1fms p95=%.1fms p99=%.1fms errors=%d", result.Name, result.P50MS, result.P95MS, result.P99MS, result.Errors)
		results = append(results, result)
	}
	// Cursor pagination: fetch a page, then request the next page.
	first := analytics.EventV2Query{From: now.Add(-30 * 24 * time.Hour), To: now, Limit: 50}
	page, err := client.QueryEventsV2(ctx, first)
	if err == nil && len(page.Items) > 0 {
		results = append(results, measureEventQuery(ctx, client, "detail_event", analytics.EventV2Query{}, iters, page.Items[0].EventUID))
		if page.NextCursor != "" {
			cursorAt, cursorUID, decodeErr := analytics.DecodeEventV2Cursor(page.NextCursor)
			if decodeErr == nil {
				next := first
				next.CursorAt, next.CursorUID = cursorAt, cursorUID
				results = append(results, measureEventQuery(ctx, client, "cursor_next_page", next, iters))
			}
		}
	}
	for _, raw := range []struct{ name, query string }{
		{"aggregate_count_24h", "SELECT count() FROM lyflow_events_v2 WHERE event_at >= now() - INTERVAL 24 HOUR FORMAT TabSeparated"},
		{"aggregate_1m_24h", "SELECT sum(events) FROM lyflow_events_1m WHERE bucket >= now() - INTERVAL 24 HOUR FORMAT TabSeparated"},
	} {
		results = append(results, measureRawQuery(ctx, client, raw.name, raw.query, iters))
	}
	return results
}

func measureEventQuery(ctx context.Context, client *analytics.HTTPClickHouse, name string, query analytics.EventV2Query, iters int, detailUID ...string) queryResult {
	result := queryResult{Name: name}
	samples := make([]time.Duration, 0, iters)
	for i := 0; i < iters; i++ {
		started := time.Now()
		var err error
		if len(detailUID) > 0 {
			_, err = client.GetEventV2(ctx, detailUID[0])
		} else {
			_, err = client.QueryEventsV2(ctx, query)
		}
		elapsed := time.Since(started)
		if err != nil {
			result.Errors++
			result.Error = err.Error()
			continue
		}
		samples = append(samples, elapsed)
	}
	result.Samples = len(samples)
	result.P50MS = bench.Percentile(samples, 50).Seconds() * 1000
	result.P95MS = bench.Percentile(samples, 95).Seconds() * 1000
	result.P99MS = bench.Percentile(samples, 99).Seconds() * 1000
	return result
}

func measureRawQuery(ctx context.Context, client *analytics.HTTPClickHouse, name, query string, iters int) queryResult {
	result := queryResult{Name: name}
	samples := make([]time.Duration, 0, iters)
	for i := 0; i < iters; i++ {
		started := time.Now()
		body, err := client.Exec(ctx, query)
		elapsed := time.Since(started)
		if err != nil {
			result.Errors++
			result.Error = err.Error()
			continue
		}
		if _, err := strconv.ParseInt(strings.TrimSpace(string(body)), 10, 64); err != nil {
			result.Errors++
			result.Error = fmt.Sprintf("unexpected aggregate response %q", strings.TrimSpace(string(body)))
			continue
		}
		samples = append(samples, elapsed)
	}
	result.Samples = len(samples)
	result.P50MS = bench.Percentile(samples, 50).Seconds() * 1000
	result.P95MS = bench.Percentile(samples, 95).Seconds() * 1000
	result.P99MS = bench.Percentile(samples, 99).Seconds() * 1000
	return result
}
