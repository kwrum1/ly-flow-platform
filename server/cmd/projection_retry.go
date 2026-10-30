package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lyflow/ly-flow-platform/contracts"
)

const (
	projectionStatusPending   = "pending"
	projectionStatusRetrying  = "retryable_failed"
	projectionStatusProcess   = "processing"
	projectionStatusSucceeded = "succeeded"
	projectionStatusPermanent = "permanent_failed"
	projectionMaxAttempts     = 8
	projectionBaseBackoff     = 30 * time.Second
	projectionMaxBackoff      = time.Hour
)

const projectionRetrySchema = `CREATE TABLE IF NOT EXISTS xdr_projection_jobs (
  event_uid TEXT PRIMARY KEY,
  payload JSONB NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  attempts INT NOT NULL DEFAULT 0,
  next_retry_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_error TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS xdr_projection_jobs_due ON xdr_projection_jobs(status, next_retry_at)`

// projectionBackoff is the delay before the next attempt. Attempt 0 waits the
// base interval; the delay doubles and is capped at one hour.
func projectionBackoff(attempts int) time.Duration {
	if attempts < 1 {
		return projectionBaseBackoff
	}
	if attempts > 16 {
		return projectionMaxBackoff
	}
	delay := projectionBaseBackoff * time.Duration(math.Pow(2, float64(attempts-1)))
	if delay > projectionMaxBackoff || delay <= 0 {
		return projectionMaxBackoff
	}
	return delay
}

// projectionNextStatus decides whether another attempt is possible.
func projectionNextStatus(attempts int, permanent bool) string {
	if permanent || attempts >= projectionMaxAttempts {
		return projectionStatusPermanent
	}
	return projectionStatusRetrying
}

type projectionJob struct {
	EventUID string
	Payload  []byte
	Attempts int
}

type projectionRetryStore struct {
	pool *pgxpool.Pool
}

func newProjectionRetryStore(pool *pgxpool.Pool) *projectionRetryStore {
	if pool == nil {
		return nil
	}
	return &projectionRetryStore{pool: pool}
}

func (store *projectionRetryStore) EnsureSchema(ctx context.Context) error {
	if store == nil || store.pool == nil {
		return nil
	}
	if _, err := store.pool.Exec(ctx, projectionRetrySchema); err != nil {
		return fmt.Errorf("create projection retry schema: %w", err)
	}
	return nil
}

// Enqueue records an event whose XDR projection failed. Re-enqueueing the same
// event after a later failure keeps the original payload and bumps the attempt
// bookkeeping only through MarkFailed, so a retry loop cannot reset progress.
func (store *projectionRetryStore) Enqueue(ctx context.Context, eventUID string, payload []byte, cause error) error {
	if store == nil || store.pool == nil {
		return nil
	}
	if eventUID == "" || len(payload) == 0 {
		return nil
	}
	message := ""
	if cause != nil {
		message = cause.Error()
	}
	_, err := store.pool.Exec(ctx, `
		INSERT INTO xdr_projection_jobs(event_uid, payload, status, last_error)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (event_uid) DO UPDATE
		SET last_error = EXCLUDED.last_error, updated_at = NOW()
		WHERE xdr_projection_jobs.status NOT IN ($5, $6)`,
		eventUID, payload, projectionStatusPending, message,
		projectionStatusSucceeded, projectionStatusPermanent)
	if err != nil {
		return fmt.Errorf("enqueue projection job %s: %w", eventUID, err)
	}
	return nil
}

func (store *projectionRetryStore) ClaimDue(ctx context.Context, limit int) ([]projectionJob, error) {
	if store == nil || store.pool == nil || limit <= 0 {
		return nil, nil
	}
	rows, err := store.pool.Query(ctx, `
		WITH due AS (
			SELECT event_uid FROM xdr_projection_jobs
			WHERE status IN ($1, $2) AND next_retry_at <= NOW()
			ORDER BY next_retry_at
			LIMIT $3
			FOR UPDATE SKIP LOCKED
		)
		UPDATE xdr_projection_jobs job
		SET status = $4, updated_at = NOW()
		FROM due
		WHERE job.event_uid = due.event_uid
		RETURNING job.event_uid, job.payload::text, job.attempts`,
		projectionStatusPending, projectionStatusRetrying, limit, projectionStatusProcess)
	if err != nil {
		return nil, fmt.Errorf("claim projection jobs: %w", err)
	}
	defer rows.Close()
	jobs := make([]projectionJob, 0, limit)
	for rows.Next() {
		var job projectionJob
		var payload string
		if err := rows.Scan(&job.EventUID, &payload, &job.Attempts); err != nil {
			return nil, fmt.Errorf("scan projection job: %w", err)
		}
		job.Payload = []byte(payload)
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

func (store *projectionRetryStore) MarkSucceeded(ctx context.Context, eventUID string) error {
	if store == nil || store.pool == nil {
		return nil
	}
	_, err := store.pool.Exec(ctx, `
		UPDATE xdr_projection_jobs
		SET status = $2, last_error = '', updated_at = NOW()
		WHERE event_uid = $1`, eventUID, projectionStatusSucceeded)
	if err != nil {
		return fmt.Errorf("mark projection job succeeded %s: %w", eventUID, err)
	}
	return nil
}

func (store *projectionRetryStore) MarkFailed(ctx context.Context, eventUID string, attempts int, permanent bool, cause error) error {
	if store == nil || store.pool == nil {
		return nil
	}
	message := ""
	if cause != nil {
		message = cause.Error()
	}
	next := projectionNextStatus(attempts+1, permanent)
	backoff := projectionBackoff(attempts + 1)
	_, err := store.pool.Exec(ctx, `
		UPDATE xdr_projection_jobs
		SET status = $2, attempts = attempts + 1, last_error = $3,
		    next_retry_at = NOW() + ($4 * interval '1 second'), updated_at = NOW()
		WHERE event_uid = $1`, eventUID, next, message, int(backoff.Seconds()))
	if err != nil {
		return fmt.Errorf("mark projection job failed %s: %w", eventUID, err)
	}
	return nil
}

func (store *projectionRetryStore) Stats(ctx context.Context) (pending int, permanent int, err error) {
	if store == nil || store.pool == nil {
		return 0, 0, nil
	}
	row := store.pool.QueryRow(ctx, `
		SELECT
		  COUNT(*) FILTER (WHERE status IN ($1, $2, $3)),
		  COUNT(*) FILTER (WHERE status = $4)
		FROM xdr_projection_jobs`,
		projectionStatusPending, projectionStatusRetrying, projectionStatusProcess, projectionStatusPermanent)
	if err := row.Scan(&pending, &permanent); err != nil {
		return 0, 0, fmt.Errorf("projection job stats: %w", err)
	}
	return pending, permanent, nil
}

// ReplayFailed resets permanent failures so an operator can replay them after a
// fix. It is explicit and audited by the caller; it never runs automatically.
func (store *projectionRetryStore) ReplayFailed(ctx context.Context, limit int) (int64, error) {
	if store == nil || store.pool == nil {
		return 0, nil
	}
	if limit <= 0 {
		limit = 100
	}
	tag, err := store.pool.Exec(ctx, `
		UPDATE xdr_projection_jobs
		SET status = $1, attempts = 0, next_retry_at = NOW(), updated_at = NOW()
		WHERE event_uid IN (
			SELECT event_uid FROM xdr_projection_jobs WHERE status = $2 LIMIT $3
		)`, projectionStatusPending, projectionStatusPermanent, limit)
	if err != nil {
		return 0, fmt.Errorf("replay projection jobs: %w", err)
	}
	return tag.RowsAffected(), nil
}

// requeueProjectionFailure is called from the ingest path. It must never fail
// the ingest: the event is already durable in ClickHouse.
func (runtime *StorageEventRuntime) requeueProjectionFailure(ctx context.Context, event contracts.EventV2, cause error) {
	if runtime == nil || runtime.projectionRetry == nil {
		return
	}
	payload, err := json.Marshal(event)
	if err != nil {
		log.Printf("xdr projection retry serialization failed event=%s: %v", event.EventUID, err)
		return
	}
	if err := runtime.projectionRetry.Enqueue(ctx, event.EventUID, payload, cause); err != nil {
		log.Printf("xdr projection retry enqueue failed event=%s: %v", event.EventUID, err)
	}
}

// runProjectionRetryWorker drains the durable projection queue.
func runProjectionRetryWorker(ctx context.Context, runtime *StorageEventRuntime, interval time.Duration) {
	if runtime == nil || runtime.projectionRetry == nil {
		return
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			drainProjectionRetries(ctx, runtime, 20)
		}
	}
}

func drainProjectionRetries(ctx context.Context, runtime *StorageEventRuntime, limit int) int {
	store := runtime.projectionRetry
	if store == nil {
		return 0
	}
	jobs, err := store.ClaimDue(ctx, limit)
	if err != nil {
		log.Printf("xdr projection retry claim failed: %v", err)
		return 0
	}
	replayed := 0
	for _, job := range jobs {
		var event contracts.EventV2
		if err := json.Unmarshal(job.Payload, &event); err != nil {
			_ = store.MarkFailed(ctx, job.EventUID, job.Attempts, true, err)
			continue
		}
		projection, err := canonicalProjectionFromV2(event)
		if err == nil {
			err = runtime.WriteCanonical(ctx, projection)
		}
		if err == nil {
			_ = store.MarkSucceeded(ctx, job.EventUID)
			replayed++
			continue
		}
		permanent := errors.Is(err, pgx.ErrNoRows)
		_ = store.MarkFailed(ctx, job.EventUID, job.Attempts, permanent, err)
	}
	return replayed
}
