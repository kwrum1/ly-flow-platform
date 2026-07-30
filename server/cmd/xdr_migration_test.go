package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
	xdrmodels "github.com/lyflow/ly-flow-platform/server/xdr/models"
)

var (
	_ xdrIncidentInput          = activeXDRResult{}
	_ xdrSuppressionInput       = activeXDRResult{}
	_ xdrResponseCandidateInput = activeXDRResult{}
	_ xdrActiveRouteResult      = activeXDRResult{}
	_ xdrShadowRouteResult      = shadowXDRResult{}
)

func TestXDRAlgorithmIdentities_are_versioned_and_only_v2_is_incident_eligible(t *testing.T) {
	// Given / When
	active := xdrV2ActiveIdentity()
	shadow := xdrV3ShadowIdentity()

	// Then
	if active.String() != "v2-active" || shadow.String() != "v3-shadow" {
		t.Fatalf("algorithm identities active=%q shadow=%q", active.String(), shadow.String())
	}
	if !active.IncidentEligible() || shadow.IncidentEligible() {
		t.Fatalf("incident eligibility active=%t shadow=%t", active.IncidentEligible(), shadow.IncidentEligible())
	}
	activeType := reflect.TypeOf(activeXDRResult{})
	shadowType := reflect.TypeOf(shadowXDRResult{})
	if activeType.Field(0).Type == shadowType.Field(0).Type {
		t.Fatal("active and shadow results erase chains to the same structural type")
	}
	for name, writerInput := range map[string]reflect.Type{
		"incident":           reflect.TypeOf((*xdrIncidentInput)(nil)).Elem(),
		"suppression":        reflect.TypeOf((*xdrSuppressionInput)(nil)).Elem(),
		"response candidate": reflect.TypeOf((*xdrResponseCandidateInput)(nil)).Elem(),
	} {
		if !activeType.Implements(writerInput) {
			t.Fatalf("v2-active does not implement %s writer input", name)
		}
		if shadowType.Implements(writerInput) {
			t.Fatalf("v3-shadow implements forbidden %s writer input", name)
		}
	}
	for _, name := range []string{"Incidents", "Suppressions", "ResponseCandidates"} {
		if _, exists := shadowType.MethodByName(name); exists {
			t.Fatalf("v3-shadow exposes forbidden writer path %s", name)
		}
	}
}

func TestXDRCanonicalAdapter_replays_v0_and_v1_during_measured_window(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	adapter := newXDRCanonicalAdapter(func() time.Time { return now }, now.Add(time.Hour))
	current := canonicalXDRTestEvent(t, "current", now)
	legacy := current
	legacy.SchemaVersion = contracts.LegacySecurityEventSchemaVersion
	currentPayload := marshalXDRFixture(t, current)
	legacyPayload := marshalXDRFixture(t, legacy)

	// When
	currentEvent, err := adapter.Decode(currentPayload)
	if err != nil {
		t.Fatalf("decode current fixture: %v", err)
	}
	legacyEvent, err := adapter.Decode(legacyPayload)
	if err != nil {
		t.Fatalf("decode legacy fixture: %v", err)
	}

	// Then
	if currentEvent.EventUID != legacyEvent.EventUID {
		t.Fatalf("compatibility replay changed event UID: %s != %s", currentEvent.EventUID, legacyEvent.EventUID)
	}
	health := adapter.Health()
	if health.CanonicalReads != 1 || health.LegacyReads != 1 || health.LegacyWindowEndsAt != now.Add(time.Hour) {
		t.Fatalf("adapter health=%+v", health)
	}
}

func TestXDRCanonicalAdapter_quarantines_unknown_schema_without_returning_event(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	adapter := newXDRCanonicalAdapter(func() time.Time { return now }, now.Add(time.Hour))
	event := canonicalXDRTestEvent(t, "future", now)
	event.SchemaVersion = "lyflow.security_event.v99"

	// When
	_, err := adapter.Decode(marshalXDRFixture(t, event))

	// Then
	var quarantine *contracts.QuarantineError
	if !errors.As(err, &quarantine) || quarantine.Reason != contracts.QuarantineFutureSchema {
		t.Fatalf("unknown schema error=%v", err)
	}
	if adapter.Health().Quarantined != 1 {
		t.Fatalf("quarantine count=%d", adapter.Health().Quarantined)
	}
}

func TestXDRCanonicalAdapter_rejects_stale_legacy_fixture_after_window(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	adapter := newXDRCanonicalAdapter(func() time.Time { return now }, now.Add(-time.Second))
	legacy := canonicalXDRTestEvent(t, "stale", now)
	legacy.SchemaVersion = contracts.LegacySecurityEventSchemaVersion

	// When
	_, err := adapter.Decode(marshalXDRFixture(t, legacy))

	// Then
	if !errors.Is(err, errXDRLegacyWindowExpired) {
		t.Fatalf("stale legacy error=%v", err)
	}
	if adapter.Health().LegacyReads != 0 || adapter.Health().Quarantined != 1 {
		t.Fatalf("stale adapter health=%+v", adapter.Health())
	}
}

func canonicalXDRTestEvent(t *testing.T, id string, now time.Time) contracts.CanonicalSecurityEvent {
	t.Helper()
	alert := migrationTestAlert(id)
	alert.OccurredAt = now.Add(-time.Minute)
	event, err := alert.Canonical(contracts.PrincipalIdentity(alert.Entities.AgentID), now)
	if err != nil {
		t.Fatalf("canonicalize fixture: %v", err)
	}
	return event
}

func marshalXDRFixture(t *testing.T, value contracts.CanonicalSecurityEvent) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return payload
}

func TestXDRGraphChecksum_is_deterministic_for_mixed_order(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	events := []contracts.CanonicalSecurityEvent{
		canonicalXDRTestEvent(t, "second", now.Add(time.Minute)),
		canonicalXDRTestEvent(t, "first", now),
	}
	reversed := []contracts.CanonicalSecurityEvent{events[1], events[0]}

	// When
	first := deterministicXDRGraphChecksum(events)
	second := deterministicXDRGraphChecksum(reversed)

	// Then
	if first == "" || first != second {
		t.Fatalf("mixed-version checksum first=%q second=%q", first, second)
	}
}

func TestXDRActiveResult_is_the_only_incident_input(t *testing.T) {
	// Given
	active := activeXDRResult{chains: activeXDRChains{{ID: "hyp-1", EventCount: 2, Stages: []string{"initial_access", "execution"}, HypothesisStatus: xdrmodels.HypothesisStatusCandidate}}}

	// When
	incidents := incidentsFromActiveXDR(active)

	// Then
	if len(incidents) != 1 {
		t.Fatalf("active incident count=%d", len(incidents))
	}
}

func TestXDRShadowResult_emits_no_response_candidates(t *testing.T) {
	// Given
	events := []*xdrmodels.CanonicalEventV2{
		{EventUID: "event-1", VictimAsset: "asset-1"},
		{EventUID: "event-2", VictimAsset: "asset-1"},
	}
	hypothesis := &xdrmodels.ChainHypothesisV2{
		HypothesisUID: "hyp-1", ChainScore: 80, Severity: "high", HypothesisStatus: xdrmodels.HypothesisStatusCandidate,
		PathNodeUIDs: []string{"node-1", "node-2"}, PathEvidence: &xdrmodels.PathEvidence{Stages: []string{"initial_access", "execution"}},
	}

	// When
	active := activeXDRRows(events, []*xdrmodels.ChainHypothesisV2{hypothesis}, 1)
	shadow := shadowXDRRows(events, []*xdrmodels.ChainHypothesisV2{hypothesis}, 1)

	// Then
	if len(active[0].ResponseCandidates) == 0 {
		t.Fatal("v2-active response candidates missing")
	}
	if len(shadow[0].ResponseCandidates) != 0 {
		t.Fatal("v3-shadow emitted response candidates")
	}
}

func TestXDRRoutes_fail_closed_without_persistent_graph_instead_of_falling_back(t *testing.T) {
	// Given
	cases := []struct {
		name    string
		path    string
		handler http.Handler
	}{
		{name: "chains", path: "/api/v1/xdr/chains", handler: xdrChainsHandler(&Config{})},
		{name: "incidents", path: "/api/v1/incidents", handler: incidentsHandler(&Config{})},
		{name: "response candidates", path: "/api/v1/response/candidates", handler: responseCandidatesHandler(&Config{})},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			// When
			response := httptest.NewRecorder()
			testCase.handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, testCase.path, nil))

			// Then
			if response.Code != http.StatusServiceUnavailable {
				t.Fatalf("route status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}
