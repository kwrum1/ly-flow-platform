package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

var errXDRLegacyWindowExpired = errors.New("XDR legacy read adapter window expired")

type xdrAdapterHealth struct {
	CanonicalReads     uint64    `json:"canonical_reads"`
	LegacyReads        uint64    `json:"legacy_reads"`
	Quarantined        uint64    `json:"quarantined"`
	LegacyWindowEndsAt time.Time `json:"legacy_window_ends_at"`
}

type xdrCanonicalAdapter struct {
	now              func() time.Time
	legacyWindowEnds time.Time
	canonicalReads   atomic.Uint64
	legacyReads      atomic.Uint64
	quarantined      atomic.Uint64
}

func newXDRCanonicalAdapter(now func() time.Time, legacyWindowEnds time.Time) *xdrCanonicalAdapter {
	return &xdrCanonicalAdapter{now: now, legacyWindowEnds: legacyWindowEnds.UTC()}
}

func (adapter *xdrCanonicalAdapter) Decode(data []byte) (contracts.CanonicalSecurityEvent, error) {
	var header struct {
		SchemaVersion string                   `json:"schema_version"`
		Identity      contracts.SourceIdentity `json:"identity"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		adapter.quarantined.Add(1)
		return contracts.CanonicalSecurityEvent{}, &contracts.QuarantineError{Reason: contracts.QuarantineMalformed, Source: "canonical", Err: err}
	}
	if header.SchemaVersion == contracts.LegacySecurityEventSchemaVersion && !adapter.now().Before(adapter.legacyWindowEnds) {
		adapter.quarantined.Add(1)
		return contracts.CanonicalSecurityEvent{}, &contracts.QuarantineError{Reason: contracts.QuarantineFutureSchema, Source: "canonical", Err: errXDRLegacyWindowExpired}
	}
	event, warnings, err := contracts.ParseCanonical(data, contracts.PrincipalIdentity(header.Identity.PrincipalID))
	if err != nil {
		adapter.quarantined.Add(1)
		return contracts.CanonicalSecurityEvent{}, fmt.Errorf("decode XDR canonical input: %w", err)
	}
	if len(warnings) > 0 {
		adapter.legacyReads.Add(1)
	} else {
		adapter.canonicalReads.Add(1)
	}
	return event, nil
}

func (adapter *xdrCanonicalAdapter) Health() xdrAdapterHealth {
	return xdrAdapterHealth{
		CanonicalReads: adapter.canonicalReads.Load(), LegacyReads: adapter.legacyReads.Load(),
		Quarantined: adapter.quarantined.Load(), LegacyWindowEndsAt: adapter.legacyWindowEnds,
	}
}

func xdrV2ActiveIdentity() models.AlgorithmIdentity {
	return models.AlgorithmV2Active
}

func xdrV3ShadowIdentity() models.AlgorithmIdentity {
	return models.AlgorithmV3Shadow
}
