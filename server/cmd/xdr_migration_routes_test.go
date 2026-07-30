package main

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

type fixtureXDRInput struct {
	records [][]byte
}

func (input fixtureXDRInput) ReadCanonicalPayloads(context.Context, int64) ([][]byte, error) {
	return input.records, nil
}

func TestXDRRoutes_restart_replays_old_and_new_canonical_fixtures(t *testing.T) {
	// Given
	pool, ctx := xdrMigrationTestPool(t)
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	current := canonicalXDRTestEvent(t, "route-current", now)
	legacy := canonicalXDRTestEvent(t, "route-legacy", now.Add(time.Minute))
	legacy.SchemaVersion = "lyflow.security_event.v0"
	input := fixtureXDRInput{records: [][]byte{marshalXDRFixture(t, current), marshalXDRFixture(t, legacy)}}
	first, err := newXDRGraphRuntime(ctx, pool, newXDRCanonicalAdapter(func() time.Time { return now }, now.Add(time.Hour)))
	if err != nil {
		t.Fatalf("create first route runtime: %v", err)
	}

	// When
	firstResponse := serveXDRRoute(xdrChainsHandler(&Config{XDRGraph: first, XDRInput: input}), "/api/v1/xdr/chains")
	restarted, err := newXDRGraphRuntime(ctx, pool, newXDRCanonicalAdapter(func() time.Time { return now }, now.Add(time.Hour)))
	if err != nil {
		t.Fatalf("restart route runtime: %v", err)
	}
	restartedResponse := serveXDRRoute(xdrChainsHandler(&Config{XDRGraph: restarted, XDRInput: input}), "/api/v1/xdr/chains")

	// Then
	if firstResponse.Code != http.StatusOK || restartedResponse.Code != http.StatusOK {
		t.Fatalf("route responses first=%d %s restarted=%d %s", firstResponse.Code, firstResponse.Body.String(), restartedResponse.Code, restartedResponse.Body.String())
	}
	assertXDRPersistenceCounts(t, ctx, pool, models.AlgorithmV2Active.String(), 2, 1)
	health := restarted.Health()
	if health.ReadAdapter.CanonicalReads != 1 || health.ReadAdapter.LegacyReads != 1 {
		t.Fatalf("restart adapter health=%+v", health.ReadAdapter)
	}
}

func TestXDRChainsRoute_future_schema_persists_redacted_quarantine_without_graph_mutation(t *testing.T) {
	// Given
	pool, ctx := xdrMigrationTestPool(t)
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	valid := canonicalXDRTestEvent(t, "route-valid", now)
	runtime, err := newXDRGraphRuntime(ctx, pool, newXDRCanonicalAdapter(func() time.Time { return now }, now.Add(time.Hour)))
	if err != nil {
		t.Fatalf("create route runtime: %v", err)
	}
	validInput := fixtureXDRInput{records: [][]byte{marshalXDRFixture(t, valid)}}
	if response := serveXDRRoute(xdrChainsHandler(&Config{XDRGraph: runtime, XDRInput: validInput}), "/api/v1/xdr/chains"); response.Code != http.StatusOK {
		t.Fatalf("seed route status=%d body=%s", response.Code, response.Body.String())
	}
	before := countXDRRows(t, ctx, pool, "xdr_graph_nodes_versioned", models.AlgorithmV2Active.String())
	future := valid
	future.SchemaVersion = "lyflow.security_event.v99"
	future.Provenance.Source = "server.xdr_v2"
	future.Payload = json.RawMessage(`{"token":"route-secret","command":"whoami"}`)
	futureInput := fixtureXDRInput{records: [][]byte{marshalXDRFixture(t, future)}}

	// When
	response := serveXDRRoute(xdrChainsHandler(&Config{XDRGraph: runtime, XDRInput: futureInput}), "/api/v1/xdr/chains")

	// Then
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("future route status=%d body=%s", response.Code, response.Body.String())
	}
	if after := countXDRRows(t, ctx, pool, "xdr_graph_nodes_versioned", models.AlgorithmV2Active.String()); after != before {
		t.Fatalf("future route mutated graph before=%d after=%d", before, after)
	}
	var reason, schemaVersion, source, redactedRecord string
	var quarantinedAt time.Time
	if err := pool.QueryRow(ctx, `SELECT reason, schema_version, source, redacted_record::text, quarantined_at
		FROM xdr_input_quarantine WHERE algorithm_version=$1`, models.AlgorithmV2Active.String()).Scan(
		&reason, &schemaVersion, &source, &redactedRecord, &quarantinedAt,
	); err != nil {
		t.Fatalf("read route quarantine: %v", err)
	}
	if reason != "future_schema" || schemaVersion != future.SchemaVersion || source != string(future.Provenance.Source) || quarantinedAt.IsZero() {
		t.Fatalf("quarantine reason=%q schema=%q source=%q at=%s", reason, schemaVersion, source, quarantinedAt)
	}
	if strings.Contains(redactedRecord, "route-secret") || !strings.Contains(redactedRecord, "***REDACTED***") {
		t.Fatalf("quarantine record was not redacted: %s", redactedRecord)
	}
}

func TestXDRChainsRoute_malformed_record_is_quarantined_without_hiding_valid_events(t *testing.T) {
	pool, ctx := xdrMigrationTestPool(t)
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	valid := canonicalXDRTestEvent(t, "route-valid-among-malformed", now)
	malformed := valid
	malformed.EventUID = "route-malformed"
	malformed.Payload = json.RawMessage(`{"token":"must-not-enter-graph","command":"whoami"}`)
	input := fixtureXDRInput{records: [][]byte{marshalXDRFixture(t, malformed), marshalXDRFixture(t, valid)}}
	runtime, err := newXDRGraphRuntime(ctx, pool, newXDRCanonicalAdapter(func() time.Time { return now }, now.Add(time.Hour)))
	if err != nil {
		t.Fatalf("create route runtime: %v", err)
	}

	response := serveXDRRoute(xdrChainsHandler(&Config{XDRGraph: runtime, XDRInput: input}), "/api/v1/xdr/chains")

	if response.Code != http.StatusOK {
		t.Fatalf("mixed route status=%d body=%s", response.Code, response.Body.String())
	}
	if got := countXDRRows(t, ctx, pool, "xdr_graph_nodes_versioned", models.AlgorithmV2Active.String()); got != 1 {
		t.Fatalf("graph nodes=%d, want only the valid event", got)
	}
	if got := runtime.Health().ReadAdapter.Quarantined; got != 1 {
		t.Fatalf("quarantined=%d, want 1", got)
	}
	var redactedRecord string
	if err := pool.QueryRow(ctx, `SELECT redacted_record::text FROM xdr_input_quarantine
		WHERE algorithm_version=$1`, models.AlgorithmV2Active.String()).Scan(&redactedRecord); err != nil {
		t.Fatalf("read quarantine: %v", err)
	}
	if strings.Contains(redactedRecord, "must-not-enter-graph") || !strings.Contains(redactedRecord, "***REDACTED***") {
		t.Fatalf("quarantine record was not redacted: %s", redactedRecord)
	}
}

func TestXDRChainsRoute_quarantine_persistence_failure_fails_closed(t *testing.T) {
	// Given
	pool, ctx := xdrMigrationTestPool(t)
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	runtime, err := newXDRGraphRuntime(ctx, pool, newXDRCanonicalAdapter(func() time.Time { return now }, now.Add(time.Hour)))
	if err != nil {
		t.Fatalf("create route runtime: %v", err)
	}
	valid := canonicalXDRTestEvent(t, "audit-failure", now)
	if _, err := runtime.RunActive(ctx, []contracts.CanonicalSecurityEvent{valid}, 20); err != nil {
		t.Fatalf("seed graph: %v", err)
	}
	before := countXDRRows(t, ctx, pool, "xdr_graph_nodes_versioned", models.AlgorithmV2Active.String())
	if _, err := pool.Exec(ctx, `DROP TABLE xdr_input_quarantine`); err != nil {
		t.Fatalf("break quarantine persistence: %v", err)
	}
	future := valid
	future.SchemaVersion = "lyflow.security_event.v99"
	input := fixtureXDRInput{records: [][]byte{marshalXDRFixture(t, future)}}

	// When
	response := serveXDRRoute(xdrChainsHandler(&Config{XDRGraph: runtime, XDRInput: input}), "/api/v1/xdr/chains")

	// Then
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "persist quarantine") {
		t.Fatalf("audit failure status=%d body=%s", response.Code, response.Body.String())
	}
	if after := countXDRRows(t, ctx, pool, "xdr_graph_nodes_versioned", models.AlgorithmV2Active.String()); after != before {
		t.Fatalf("audit failure mutated graph before=%d after=%d", before, after)
	}
}

func TestXDRHealthRoute_exposes_degraded_persistence_without_incident_promotion(t *testing.T) {
	// Given
	pool, ctx := xdrMigrationTestPool(t)
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	runtime, err := newXDRGraphRuntime(ctx, pool, newXDRCanonicalAdapter(func() time.Time { return now }, now.Add(time.Hour)))
	if err != nil {
		t.Fatalf("create route runtime: %v", err)
	}
	input := fixtureXDRInput{records: [][]byte{marshalXDRFixture(t, canonicalXDRTestEvent(t, "degraded-route", now))}}
	config := &Config{XDRGraph: runtime, XDRInput: input}
	pool.Close()

	// When
	incidentResponse := serveXDRRoute(incidentsHandler(config), "/api/v1/incidents")
	healthResponse := serveXDRRoute(healthHandler(config), "/health")

	// Then
	if incidentResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("incident status=%d body=%s", incidentResponse.Code, incidentResponse.Body.String())
	}
	var health struct {
		Status string           `json:"status"`
		XDR    xdrRuntimeHealth `json:"xdr"`
	}
	if err := json.Unmarshal(healthResponse.Body.Bytes(), &health); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	if health.Status != string(xdrHealthDegraded) || health.XDR.Status != xdrHealthDegraded || health.XDR.LastPersistenceError == "" {
		t.Fatalf("health response=%s", healthResponse.Body.String())
	}
}

func TestXDRProductionRoutes_have_no_fallback_or_shadow_promotion_calls(t *testing.T) {
	// Given
	files := []string{"main.go", "xdr_v2_api.go"}
	forbidden := map[string]struct{}{
		"buildXDRChains": {}, "loadXDRComponentEvents": {}, "xdrV2ChainsResponse": {}, "globalSituationThreatFallback": {},
	}
	promotionSurfaces := map[string]struct{}{
		"incidentsHandler": {}, "incidentDetailHandler": {}, "responseCandidatesHandler": {},
	}

	// When / Then
	for _, path := range files {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read route source %s: %v", path, err)
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
		if err != nil {
			t.Fatalf("parse route source %s: %v", path, err)
		}
		for _, declaration := range parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			_, isPromotionSurface := promotionSurfaces[function.Name.Name]
			ast.Inspect(function.Body, func(node ast.Node) bool {
				identifier, ok := node.(*ast.Ident)
				if !ok {
					return true
				}
				if _, blocked := forbidden[identifier.Name]; blocked && isProductionXDRRoute(function.Name.Name) {
					t.Errorf("production route %s calls fallback %s", function.Name.Name, identifier.Name)
				}
				if isPromotionSurface && identifier.Name == "AlgorithmV3Shadow" {
					t.Errorf("promotion route %s references v3-shadow", function.Name.Name)
				}
				return true
			})
		}
	}
}

func TestXDRProductionRoutes_use_distinct_active_and_shadow_result_paths(t *testing.T) {
	// Given
	forbidden := map[string]struct{}{
		"xdrAlgorithmChainsResponse": {},
	}

	// When
	source, err := os.ReadFile("xdr_v2_api.go")
	if err != nil {
		t.Fatalf("read XDR route source: %v", err)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), "xdr_v2_api.go", source, 0)
	if err != nil {
		t.Fatalf("parse XDR route source: %v", err)
	}

	// Then
	ast.Inspect(parsed, func(node ast.Node) bool {
		function, ok := node.(*ast.FuncDecl)
		if !ok {
			return true
		}
		if _, blocked := forbidden[function.Name.Name]; blocked {
			t.Errorf("shared erased result route remains: %s", function.Name.Name)
		}
		return true
	})
}

func TestXDRTypedRows_forbid_map_erasure_and_shadow_active_conversion(t *testing.T) {
	// Given
	source, err := os.ReadFile("xdr_v2_api.go")
	if err != nil {
		t.Fatalf("read typed XDR rows: %v", err)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), "xdr_v2_api.go", source, 0)
	if err != nil {
		t.Fatalf("parse typed XDR rows: %v", err)
	}

	// When / Then
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Type.Results == nil {
			continue
		}
		if function.Name.Name == "activeXDRRows" || function.Name.Name == "shadowXDRRows" {
			for _, result := range function.Type.Results.List {
				if array, erased := result.Type.(*ast.ArrayType); erased {
					if _, mapType := array.Elt.(*ast.MapType); mapType {
						t.Fatalf("%s returns erased map rows", function.Name.Name)
					}
				}
			}
		}
	}
	shadowType := reflect.TypeOf(shadowXDRRow{})
	for _, name := range []string{"incidentEligible", "incidentChains", "suppressionChains", "responseCandidateChains"} {
		if _, exists := shadowType.MethodByName(name); exists {
			t.Fatalf("shadow row exposes active conversion %s", name)
		}
	}
}

func serveXDRRoute(handler http.Handler, path string) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
	return response
}

func isProductionXDRRoute(name string) bool {
	for _, suffix := range []string{"Handler", "Response"} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}
