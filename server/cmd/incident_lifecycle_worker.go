package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

// Incident materialization used to be a pure side effect of
// GET /api/v1/incidents?live=1. The read path looked back a hard-coded 30
// minutes with LIMIT 100, so any alert window during which nobody opened the
// Incidents page was never turned into an Incident at all. Measured on the
// mirror sensor: 9,413 traffic alerts over seven days produced 5 Incidents,
// the newest on 2026-11-02, because the only three page loads that happened to
// overlap an alert window were on that day.
//
// This worker removes the dependency on a browser. It runs the same
// materialization on a fixed interval, and the window/limit are configurable so
// a deployment can widen the lookback after an outage instead of losing the gap.

const (
	incidentTrafficLookbackEnv = "LYFLOW_INCIDENT_TRAFFIC_LOOKBACK"
	incidentTrafficLimitEnv    = "LYFLOW_INCIDENT_TRAFFIC_LIMIT"
	incidentWorkerIntervalEnv  = "LYFLOW_INCIDENT_WORKER_INTERVAL"
	incidentWorkerEnabledEnv   = "LYFLOW_INCIDENT_WORKER"

	defaultIncidentTrafficLookback = 30 * time.Minute
	defaultIncidentTrafficLimit    = 100
	defaultIncidentWorkerInterval  = 60 * time.Second
)

// incidentTrafficWindow is the query window for traffic-to-incident
// materialization. It is a value type so tests can exercise arbitrary windows
// without touching process environment.
type incidentTrafficWindow struct {
	Lookback time.Duration
	Limit    int
}

// incidentPipelineReport is the per-tick outcome. It is returned rather than
// only logged so a test can assert that a tick actually created rows.
type incidentPipelineReport struct {
	Window        time.Duration `json:"window"`
	Limit         int           `json:"limit"`
	Scanned       int           `json:"scanned"`
	Eligible      int           `json:"eligible"`
	Withheld      int           `json:"withheld"`
	Created       int           `json:"created"`
	Updated       int           `json:"updated"`
	EvidenceAdded int           `json:"evidence_added"`
	ElapsedMS     int64         `json:"elapsed_ms"`
}

func incidentTrafficWindowFromEnv() incidentTrafficWindow {
	window := incidentTrafficWindow{
		Lookback: defaultIncidentTrafficLookback,
		Limit:    defaultIncidentTrafficLimit,
	}
	if raw := strings.TrimSpace(os.Getenv(incidentTrafficLookbackEnv)); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			window.Lookback = parsed
		} else {
			log.Printf("[incident] %s=%q is not a positive duration; using %s", incidentTrafficLookbackEnv, raw, defaultIncidentTrafficLookback)
		}
	}
	if raw := strings.TrimSpace(os.Getenv(incidentTrafficLimitEnv)); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			window.Limit = parsed
		} else {
			log.Printf("[incident] %s=%q is not a positive integer; using %d", incidentTrafficLimitEnv, raw, defaultIncidentTrafficLimit)
		}
	}
	return window
}

func incidentWorkerIntervalFromEnv() time.Duration {
	raw := strings.TrimSpace(os.Getenv(incidentWorkerIntervalEnv))
	if raw == "" {
		return defaultIncidentWorkerInterval
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil || parsed <= 0 {
		log.Printf("[incident] %s=%q is not a positive duration; using %s", incidentWorkerIntervalEnv, raw, defaultIncidentWorkerInterval)
		return defaultIncidentWorkerInterval
	}
	return parsed
}

// startIncidentLifecycleWorker materializes traffic incidents on a fixed
// interval so the pipeline no longer depends on someone opening a page.
//
// It is safe to run alongside the HTTP live-sync path: materialization is an
// idempotent upsert keyed by a deterministic incident ID, so overlapping runs
// cannot duplicate rows.
func startIncidentLifecycleWorker(cfg *Config) {
	if cfg == nil || cfg.DBPool == nil || cfg.Incidents == nil {
		return
	}
	if strings.EqualFold(strings.TrimSpace(getEnv(incidentWorkerEnabledEnv, "true")), "false") {
		log.Printf("[incident] worker disabled by %s=false", incidentWorkerEnabledEnv)
		return
	}
	interval := incidentWorkerIntervalFromEnv()
	window := incidentTrafficWindowFromEnv()
	log.Printf("[incident] worker started interval=%s lookback=%s limit=%d", interval, window.Lookback, window.Limit)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			report, err := runIncidentPipelineTick(context.Background(), cfg, window)
			if err != nil {
				log.Printf("[incident] pipeline tick failed: %v", err)
				continue
			}
			// One structured line per tick so "is the pipeline alive" is
			// answerable from logs alone, which the old design could not do.
			log.Printf("[incident] pipeline tick: window=%s scanned=%d eligible=%d withheld=%d created=%d updated=%d evidence=%d elapsed=%dms",
				report.Window, report.Scanned, report.Eligible, report.Withheld,
				report.Created, report.Updated, report.EvidenceAdded, report.ElapsedMS)
		}
	}()
}

// runIncidentPipelineTick performs one materialization pass. It recovers from
// panics so a single malformed payload cannot kill the worker for the lifetime
// of the process.
func runIncidentPipelineTick(ctx context.Context, cfg *Config, window incidentTrafficWindow) (report incidentPipelineReport, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("incident pipeline panic: %v", recovered)
			log.Printf("[incident] pipeline panic recovered: %v\n%s", recovered, debug.Stack())
		}
	}()
	if cfg == nil || cfg.Incidents == nil {
		return report, fmt.Errorf("incident store unavailable")
	}
	return runTrafficIncidentSync(ctx, cfg, cfg.Incidents, window)
}
