package transportreliability

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

type producerRegistryFixture struct {
	ctx    context.Context
	client *redis.Client
}

func TestProducerReadinessRejectsForgedEvidenceAcrossActualProducerSet(t *testing.T) {
	client, ctx := testRedis(t)
	registry := producerRegistryFixture{ctx: ctx, client: client}
	now := time.Now().UTC().Truncate(time.Second)
	maximum := 7 * 24 * time.Hour
	cases := []struct {
		name  string
		forge func(string) *ProducerRegistration
	}{
		{name: "missing producer", forge: func(string) *ProducerRegistration { return nil }},
		{name: "wrong version", forge: func(name string) *ProducerRegistration {
			return &ProducerRegistration{Name: name, Version: "todo7.future", MaximumSpoolRetryHorizon: maximum, RegisteredAt: now, ExpiresAt: now.Add(ProducerLeaseTTL)}
		}},
		{name: "future dated", forge: func(name string) *ProducerRegistration {
			return &ProducerRegistration{Name: name, Version: ProducerProtocolVersion, MaximumSpoolRetryHorizon: maximum, RegisteredAt: now.Add(time.Minute), ExpiresAt: now.Add(time.Minute + ProducerLeaseTTL)}
		}},
		{name: "expired lease", forge: func(name string) *ProducerRegistration {
			return &ProducerRegistration{Name: name, Version: ProducerProtocolVersion, MaximumSpoolRetryHorizon: maximum, RegisteredAt: now.Add(-ProducerLeaseTTL), ExpiresAt: now}
		}},
	}

	for _, producer := range RequiredProducers() {
		for _, testCase := range cases {
			t.Run(producer+"/"+testCase.name, func(t *testing.T) {
				if err := client.FlushDB(ctx).Err(); err != nil {
					t.Fatalf("reset producer registry: %v", err)
				}
				for _, actual := range RequiredProducers() {
					registration := &ProducerRegistration{Name: actual, Version: ProducerProtocolVersion, MaximumSpoolRetryHorizon: maximum, RegisteredAt: now, ExpiresAt: now.Add(ProducerLeaseTTL)}
					if actual == producer {
						registration = testCase.forge(actual)
					}
					if registration != nil {
						registry.persistForged(t, *registration)
					}
				}

				ready, err := NewRedisHorizonStore(client).AllProducersUpgradedAt(ctx, maximum, now)
				if err != nil || ready {
					t.Fatalf("forged %s readiness accepted for %s: ready=%v err=%v", testCase.name, producer, ready, err)
				}
			})
		}
	}
}

func TestProducerRegistrationRejectsInvalidLeaseEvidence(t *testing.T) {
	client, ctx := testRedis(t)
	now := time.Now().UTC()
	maximum := 7 * 24 * time.Hour
	tests := []struct {
		name         string
		registration ProducerRegistration
	}{
		{name: "missing producer", registration: ProducerRegistration{Name: "missing-adapter", Version: ProducerProtocolVersion, MaximumSpoolRetryHorizon: maximum, RegisteredAt: now, ExpiresAt: now.Add(ProducerLeaseTTL)}},
		{name: "wrong version", registration: ProducerRegistration{Name: "agent-traffic", Version: "todo7.future", MaximumSpoolRetryHorizon: maximum, RegisteredAt: now, ExpiresAt: now.Add(ProducerLeaseTTL)}},
		{name: "future dated", registration: ProducerRegistration{Name: "agent-traffic", Version: ProducerProtocolVersion, MaximumSpoolRetryHorizon: maximum, RegisteredAt: now.Add(time.Minute), ExpiresAt: now.Add(time.Minute + ProducerLeaseTTL)}},
		{name: "expired lease", registration: ProducerRegistration{Name: "agent-traffic", Version: ProducerProtocolVersion, MaximumSpoolRetryHorizon: maximum, RegisteredAt: now.Add(-ProducerLeaseTTL), ExpiresAt: now}},
		{name: "unbounded lease", registration: ProducerRegistration{Name: "agent-traffic", Version: ProducerProtocolVersion, MaximumSpoolRetryHorizon: maximum, RegisteredAt: now, ExpiresAt: now.Add(ProducerLeaseTTL + time.Second)}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if err := RegisterProducerEvidence(ctx, client, testCase.registration); err == nil {
				t.Fatalf("invalid producer registration accepted: %+v", testCase.registration)
			}
		})
	}
}

func TestProducerRegistrationRenewsPersistedFreshnessAcrossActualProducerSet(t *testing.T) {
	client, ctx := testRedis(t)
	registeredAt := time.Now().UTC().Add(-2 * time.Minute).Truncate(time.Second)
	renewedAt := registeredAt.Add(time.Minute)
	maximum := 7 * 24 * time.Hour
	for _, producer := range RequiredProducers() {
		if err := RegisterProducerEvidence(ctx, client, ProducerRegistration{Name: producer, Version: ProducerProtocolVersion, MaximumSpoolRetryHorizon: maximum, RegisteredAt: registeredAt, ExpiresAt: registeredAt.Add(ProducerLeaseTTL)}); err != nil {
			t.Fatalf("register %s: %v", producer, err)
		}
	}

	for _, producer := range RequiredProducers() {
		if err := RegisterProducerEvidence(ctx, client, ProducerRegistration{Name: producer, Version: ProducerProtocolVersion, MaximumSpoolRetryHorizon: maximum, RegisteredAt: renewedAt, ExpiresAt: renewedAt.Add(ProducerLeaseTTL)}); err != nil {
			t.Fatalf("renew %s: %v", producer, err)
		}
		data, err := client.HGet(ctx, producerRegistryKey, producer).Bytes()
		if err != nil {
			t.Fatalf("load renewed %s: %v", producer, err)
		}
		var persisted ProducerRegistration
		if err := json.Unmarshal(data, &persisted); err != nil {
			t.Fatalf("decode renewed %s: %v", producer, err)
		}
		if !persisted.RegisteredAt.Equal(renewedAt) || !persisted.ExpiresAt.Equal(renewedAt.Add(ProducerLeaseTTL)) {
			t.Fatalf("renewed freshness not persisted for %s: %+v", producer, persisted)
		}
	}
	ready, err := NewRedisHorizonStore(client).AllProducersUpgradedAt(ctx, maximum, renewedAt)
	if err != nil || !ready {
		t.Fatalf("valid renewed producer set not ready: ready=%v err=%v", ready, err)
	}
}

func TestRedisHorizonRejectsForgedProducerReadiness(t *testing.T) {
	client, ctx := testRedis(t)
	now := time.Now().UTC()
	err := NewRedisHorizonStore(client).Persist(ctx, HorizonRecord{
		MaximumSpoolRetryHorizon: 7 * 24 * time.Hour,
		ZeroLegacyReadsSince:     now.Add(-7 * 24 * time.Hour),
		AllProducersUpgraded:     true,
		PersistedAt:              now,
	})
	if err == nil {
		t.Fatal("forged producer readiness persisted without current producer leases")
	}
}

func (registry producerRegistryFixture) persistForged(t testing.TB, registration ProducerRegistration) {
	t.Helper()
	data, err := json.Marshal(registration)
	if err != nil {
		t.Fatalf("encode forged registration: %v", err)
	}
	if err := registry.client.HSet(registry.ctx, producerRegistryKey, registration.Name, data).Err(); err != nil {
		t.Fatalf("persist forged registration: %v", err)
	}
}
