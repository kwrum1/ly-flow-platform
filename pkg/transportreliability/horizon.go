package transportreliability

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
	"github.com/redis/go-redis/v9"
)

const RetirementHorizonKey = "transport_reliability:retirement_horizon"
const producerRegistryKey = "transport_reliability:producers"
const ProducerProtocolVersion = "todo7.v2"
const ProducerLeaseTTL = 5 * time.Minute

var requiredProducers = []string{
	"agent-traffic", "server-consumer", "server-unified", "server-xdr", "security-engine", "dpi-engine",
}

type HorizonRecord struct {
	MaximumSpoolRetryHorizon time.Duration `json:"maximum_spool_retry_horizon"`
	ZeroLegacyReadsSince     time.Time     `json:"zero_legacy_reads_since"`
	AllProducersUpgraded     bool          `json:"all_producers_upgraded"`
	PersistedAt              time.Time     `json:"persisted_at"`
	LastObservationAt        time.Time     `json:"last_observation_at"`
}

type HorizonObservation struct {
	MaximumSpoolRetryHorizon time.Duration
	LegacyRead               bool
	ObservedAt               time.Time
}

type ProducerRegistration struct {
	Name                     string        `json:"name"`
	Version                  string        `json:"version"`
	MaximumSpoolRetryHorizon time.Duration `json:"maximum_spool_retry_horizon"`
	RegisteredAt             time.Time     `json:"registered_at"`
	ExpiresAt                time.Time     `json:"expires_at"`
}

type RedisHorizonStore struct {
	client *redis.Client
}

func NewRedisHorizonStore(client *redis.Client) RedisHorizonStore {
	return RedisHorizonStore{client: client}
}

func RequiredProducers() []string {
	return append([]string(nil), requiredProducers...)
}

func RegisterProducer(ctx context.Context, client *redis.Client, producer string) error {
	if client == nil || producer == "" {
		return fmt.Errorf("Redis client and producer name are required")
	}
	maxAgeSeconds, err := parsePositiveInt64("LYFLOW_TRANSPORT_RETRY_HORIZON_SECONDS", int64((7*24*time.Hour)/time.Second))
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	return RegisterProducerEvidence(ctx, client, ProducerRegistration{
		Name: producer, Version: ProducerProtocolVersion,
		MaximumSpoolRetryHorizon: time.Duration(maxAgeSeconds) * time.Second,
		RegisteredAt:             now, ExpiresAt: now.Add(ProducerLeaseTTL),
	})
}

func RegisterProducerEvidence(ctx context.Context, client *redis.Client, registration ProducerRegistration) error {
	now := time.Now().UTC()
	if client == nil || !isRequiredProducer(registration.Name) || registration.Name != strings.TrimSpace(registration.Name) || registration.Version != ProducerProtocolVersion || registration.MaximumSpoolRetryHorizon <= 0 || registration.RegisteredAt.IsZero() || registration.RegisteredAt.After(now) || !registration.ExpiresAt.After(now) || registration.ExpiresAt.Sub(registration.RegisteredAt) > ProducerLeaseTTL {
		return fmt.Errorf("current producer registration with full horizon and bounded lease is required")
	}
	data, err := json.Marshal(registration)
	if err != nil {
		return fmt.Errorf("encode reliable producer %s: %w", registration.Name, err)
	}
	if err := client.HSet(ctx, producerRegistryKey, registration.Name, data).Err(); err != nil {
		return fmt.Errorf("register reliable producer %s: %w", registration.Name, err)
	}
	return nil
}

func (store RedisHorizonStore) AllProducersUpgraded(ctx context.Context) (bool, error) {
	return store.AllProducersUpgradedAt(ctx, 7*24*time.Hour, time.Now().UTC())
}

func (store RedisHorizonStore) AllProducersUpgradedAt(ctx context.Context, maximum time.Duration, now time.Time) (bool, error) {
	if store.client == nil {
		return false, fmt.Errorf("retirement horizon Redis client is required")
	}
	if maximum <= 0 || now.IsZero() {
		return false, fmt.Errorf("maximum horizon and current time are required")
	}
	for _, producer := range requiredProducers {
		data, err := store.client.HGet(ctx, producerRegistryKey, producer).Bytes()
		if err == redis.Nil {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("check reliable producer %s: %w", producer, err)
		}
		var registration ProducerRegistration
		if json.Unmarshal(data, &registration) != nil || registration.Name != producer || registration.Version != ProducerProtocolVersion || registration.MaximumSpoolRetryHorizon < maximum || !registration.ExpiresAt.After(now) || registration.RegisteredAt.After(now) || registration.ExpiresAt.Sub(registration.RegisteredAt) > ProducerLeaseTTL {
			return false, nil
		}
	}
	return true, nil
}

func (store RedisHorizonStore) Refresh(ctx context.Context, maximum time.Duration, legacyRead bool, now time.Time) error {
	return store.RefreshObservation(ctx, HorizonObservation{MaximumSpoolRetryHorizon: maximum, LegacyRead: legacyRead, ObservedAt: now}, now)
}

func (store RedisHorizonStore) RefreshObservation(ctx context.Context, observation HorizonObservation, persistedAt time.Time) error {
	if observation.MaximumSpoolRetryHorizon <= 0 || observation.ObservedAt.IsZero() || persistedAt.IsZero() || persistedAt.Before(observation.ObservedAt) {
		return fmt.Errorf("maximum horizon, observation time, and persistence time are required")
	}
	record, err := store.loadRecord(ctx)
	if err != nil && err != redis.Nil {
		return err
	}
	if !record.LastObservationAt.IsZero() && !observation.ObservedAt.After(record.LastObservationAt) {
		return nil
	}
	maximum := observation.MaximumSpoolRetryHorizon
	if record.MaximumSpoolRetryHorizon > observation.MaximumSpoolRetryHorizon {
		maximum = record.MaximumSpoolRetryHorizon
	}
	zeroSince := record.ZeroLegacyReadsSince
	if zeroSince.IsZero() || observation.LegacyRead {
		zeroSince = observation.ObservedAt.UTC()
	}
	upgraded, err := store.AllProducersUpgradedAt(ctx, maximum, observation.ObservedAt)
	if err != nil {
		return err
	}
	return store.Persist(ctx, HorizonRecord{
		MaximumSpoolRetryHorizon: maximum, ZeroLegacyReadsSince: zeroSince,
		AllProducersUpgraded: upgraded, PersistedAt: persistedAt.UTC(), LastObservationAt: observation.ObservedAt.UTC(),
	})
}

func (store RedisHorizonStore) Persist(ctx context.Context, record HorizonRecord) error {
	if store.client == nil {
		return fmt.Errorf("retirement horizon Redis client is required")
	}
	if record.MaximumSpoolRetryHorizon <= 0 || record.PersistedAt.IsZero() || record.PersistedAt.After(time.Now().UTC()) {
		return fmt.Errorf("maximum spool/retry horizon and persisted time are required")
	}
	if record.AllProducersUpgraded {
		ready, err := store.AllProducersUpgradedAt(ctx, record.MaximumSpoolRetryHorizon, record.PersistedAt)
		if err != nil {
			return err
		}
		if !ready {
			return fmt.Errorf("persisted producer readiness requires current leases for every producer")
		}
	}
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode retirement horizon: %w", err)
	}
	if err := store.client.Set(ctx, RetirementHorizonKey, data, 0).Err(); err != nil {
		return fmt.Errorf("persist retirement horizon: %w", err)
	}
	return nil
}

func (store RedisHorizonStore) Load(ctx context.Context) (contracts.PersistedRetirementHorizon, error) {
	if store.client == nil {
		return contracts.PersistedRetirementHorizon{}, fmt.Errorf("retirement horizon Redis client is required")
	}
	record, err := store.loadRecord(ctx)
	if err != nil {
		return contracts.PersistedRetirementHorizon{}, err
	}
	if record.AllProducersUpgraded {
		ready, readinessErr := store.AllProducersUpgradedAt(ctx, record.MaximumSpoolRetryHorizon, time.Now().UTC())
		if readinessErr != nil {
			return contracts.PersistedRetirementHorizon{}, readinessErr
		}
		if !ready {
			return contracts.PersistedRetirementHorizon{}, fmt.Errorf("persisted producer readiness is stale or forged")
		}
	}
	horizon, err := contracts.NewPersistedRetirementHorizon(
		record.MaximumSpoolRetryHorizon, record.ZeroLegacyReadsSince, record.AllProducersUpgraded, record.PersistedAt,
	)
	if err != nil {
		return contracts.PersistedRetirementHorizon{}, fmt.Errorf("validate retirement horizon: %w", err)
	}
	return horizon, nil
}

func isRequiredProducer(name string) bool {
	for _, producer := range requiredProducers {
		if name == producer {
			return true
		}
	}
	return false
}

func (store RedisHorizonStore) LoadRecord(ctx context.Context) (HorizonRecord, error) {
	return store.loadRecord(ctx)
}

func (store RedisHorizonStore) loadRecord(ctx context.Context) (HorizonRecord, error) {
	data, err := store.client.Get(ctx, RetirementHorizonKey).Bytes()
	if err != nil {
		return HorizonRecord{}, err
	}
	var record HorizonRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return HorizonRecord{}, fmt.Errorf("decode retirement horizon: %w", err)
	}
	return record, nil
}
