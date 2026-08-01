package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lyflow/ly-flow-platform/contracts"
	"github.com/lyflow/ly-flow-platform/server/analytics"
	"github.com/lyflow/ly-flow-platform/server/modules/auth"
	transport "github.com/lyflow/ly-flow-platform/transportreliability"
	"github.com/redis/go-redis/v9"
)

type realDetectionManifestSource struct {
	SourceID           string   `json:"source_id"`
	SID                int      `json:"sid"`
	Revision           int      `json:"revision"`
	ExpectedAlertCount int      `json:"expected_alert_count"`
	ExpectedRawHashes  []string `json:"expected_raw_hashes"`
}

type realDetectionManifest struct {
	Sources []realDetectionManifestSource `json:"sources"`
}

type expectedRealDetectionSource struct {
	sourceID string
	revision string
	count    int
}

func TestRealDetectionPipeline_persistsAgentAlertsInBothStoresAndAPI(t *testing.T) {
	redisAddress := os.Getenv("LYFLOW_TEST_REDIS_ADDR")
	postgresDSN := os.Getenv("LYFLOW_TEST_POSTGRES_DSN")
	clickHouseAddress := os.Getenv("LYFLOW_TEST_CLICKHOUSE_HTTP")
	if redisAddress == "" || postgresDSN == "" || clickHouseAddress == "" || os.Getenv("T12_REAL_DETECTION_PIPELINE") != "1" {
		t.Skip("T12 Agent stream and disposable event stores are required")
	}
	manifestPath := os.Getenv("T12_REAL_DETECTION_MANIFEST")
	if manifestPath == "" {
		t.Fatal("T12_REAL_DETECTION_MANIFEST is required")
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read real-detection manifest: %v", err)
	}
	var manifest realDetectionManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode real-detection manifest: %v", err)
	}
	expectedSources := make(map[string]expectedRealDetectionSource, len(manifest.Sources))
	for _, source := range manifest.Sources {
		nativeID := strconv.Itoa(source.SID)
		expectedSources[nativeID] = expectedRealDetectionSource{sourceID: source.SourceID, revision: strconv.Itoa(source.Revision), count: source.ExpectedAlertCount}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	client := redis.NewClient(&redis.Options{Addr: redisAddress})
	t.Cleanup(func() { _ = client.Close() })
	pool, err := pgxpool.New(ctx, postgresDSN)
	if err != nil {
		t.Fatalf("connect Postgres: %v", err)
	}
	t.Cleanup(pool.Close)
	fixture := storageRuntimeTestFixture{
		postgres:           pool,
		clickHouseAddress:  clickHouseAddress,
		clickHouseUsername: os.Getenv("LYFLOW_TEST_CLICKHOUSE_USER"),
		clickHousePassword: os.Getenv("LYFLOW_TEST_CLICKHOUSE_PASSWORD"),
	}
	if err := resetStorageRuntimeTestState(ctx, fixture); err != nil {
		t.Fatalf("reset storage runtime: %v", err)
	}
	if err := ensureRuntimeSchema(ctx, pool); err != nil {
		t.Fatalf("initialize server schema: %v", err)
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS agents (uuid TEXT PRIMARY KEY);
INSERT INTO agents (uuid) VALUES ('t12-packet-sensor') ON CONFLICT (uuid) DO NOTHING`); err != nil {
		t.Fatalf("register T12 packet sensor identity: %v", err)
	}
	t.Setenv("CLICKHOUSE_ADDR", clickHouseAddress)
	t.Setenv("CLICKHOUSE_DB", "default")
	t.Setenv("CLICKHOUSE_USER", fixture.clickHouseUsername)
	t.Setenv("CLICKHOUSE_PASSWORD", fixture.clickHousePassword)
	runtime, err := newProductionStorageEventRuntime(ctx, pool)
	if err != nil {
		t.Fatalf("initialize production storage runtime: %v", err)
	}
	if err := runtime.migration.Advance(ctx, analytics.PhaseDualWrite); err != nil {
		t.Fatalf("advance storage runtime to dual write: %v", err)
	}

	messages, err := client.XRange(ctx, "component_alerts:v2", "-", "+").Result()
	if err != nil {
		t.Fatalf("read Agent component alert stream: %v", err)
	}
	if len(messages) != 9 {
		t.Fatalf("Agent component alert count = %d, want 9", len(messages))
	}
	consumer := &ConsumerState{cfg: &Config{Redis: client, DBPool: pool, EventStorage: runtime}}
	for _, message := range messages {
		encoded, ok := message.Values["data"].(string)
		if !ok {
			t.Fatalf("Agent message %s data is %T", message.ID, message.Values["data"])
		}
		var alertPayload map[string]interface{}
		if err := json.Unmarshal([]byte(encoded), &alertPayload); err != nil {
			t.Fatalf("decode Agent message %s: %v", message.ID, err)
		}
		normalized := normalizeComponentAlertStreamEvent("component_alerts:v2", message.ID, alertPayload)
		if trafficThreatHasNoFlowContext(normalized) {
			t.Fatalf("Agent message %s lost flow context: %+v", message.ID, normalized)
		}
		_, err := consumer.processDelivery(ctx, transport.Delivery{
			Stream: "component_alerts:v2", MessageID: message.ID, Values: message.Values,
		})
		if err != nil {
			t.Fatalf("process Agent alert %s: %v", message.ID, err)
		}
	}

	var threatCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM threat_events WHERE source_engine='suricata'`).Scan(&threatCount); err != nil {
		t.Fatalf("count persisted threat events: %v", err)
	}
	if threatCount != 9 {
		t.Fatalf("Postgres threat event count = %d, want 9", threatCount)
	}
	threats, threatTotal, err := loadPersistentThreatEvents(ctx, consumer.cfg, "traffic", 20, 0, "", "", "", "", "", nil, nil)
	if err != nil || threatTotal != 5 || len(threats) != 5 {
		t.Fatalf("traffic threat API projection total=%d items=%d: %v", threatTotal, len(threats), err)
	}
	for _, threat := range threats {
		nativeRule := asMap(threat["native_rule"])
		rawReference := asMap(threat["raw_reference"])
		if asString(nativeRule["source"]) == "" || asString(nativeRule["id"]) == "" || asString(rawReference["hash"]) == "" {
			t.Fatalf("traffic threat API projection lost provenance: native=%v raw=%v", nativeRule, rawReference)
		}
	}
	for index, nativeID := range []string{"aggregation-rule-a", "aggregation-rule-b"} {
		probe := map[string]interface{}{
			"id": "t12-aggregation-probe-" + strconv.Itoa(index), "message_id": "t12-aggregation-probe-" + strconv.Itoa(index),
			"event_type": "suricata.alert", "severity": "high", "component_category": "traffic", "source_engine": "suricata",
			"agent_id": "t12-packet-sensor", "src_ip": "10.20.30.40", "dst_ip": "203.0.113.40", "src_port": 4444, "dst_port": 80,
			"message": "t12-aggregation-probe", "created_at": "2026-07-23T00:00:00Z",
			"native_rule": map[string]interface{}{"source": "aggregation-probe", "id": nativeID},
		}
		if err := persistThreatEvent(ctx, consumer.cfg, probe); err != nil {
			t.Fatalf("persist aggregation probe %s: %v", nativeID, err)
		}
	}
	_, aggregationTotal, err := loadPersistentThreatEvents(ctx, consumer.cfg, "traffic", 20, 0, "t12-aggregation-probe", "", "", "", "", nil, nil)
	if err != nil || aggregationTotal != 2 {
		t.Fatalf("same-flow native rule aggregation total=%d, want 2: %v", aggregationTotal, err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM threat_events WHERE event_uid IN ('t12-aggregation-probe-0','t12-aggregation-probe-1')`); err != nil {
		t.Fatalf("remove aggregation probes: %v", err)
	}
	firstMessage := messages[0]
	firstEncoded, ok := firstMessage.Values["data"].(string)
	if !ok {
		t.Fatalf("first Agent message data is %T", firstMessage.Values["data"])
	}
	var firstAlert contracts.ComponentAlert
	if err := json.Unmarshal([]byte(firstEncoded), &firstAlert); err != nil {
		t.Fatalf("decode first Agent alert for replay: %v", err)
	}
	firstCanonical, _, err := canonicalComponentAlertPayload(firstAlert, firstAlert.OccurredAt)
	if err != nil {
		t.Fatalf("derive first canonical event identity: %v", err)
	}
	threatEventUID := firstNonEmpty(firstAlert.ID, firstMessage.ID)
	var canonicalVersionBefore int64
	var canonicalPayloadBefore string
	if err := pool.QueryRow(ctx, `SELECT version,payload_json FROM lyflow_event_storage_events WHERE event_uid=$1`, firstCanonical.EventUID).Scan(&canonicalVersionBefore, &canonicalPayloadBefore); err != nil {
		t.Fatalf("read canonical event before replay: %v", err)
	}
	var threatUpdatedBefore time.Time
	if err := pool.QueryRow(ctx, `SELECT updated_at FROM threat_events WHERE event_uid=$1`, threatEventUID).Scan(&threatUpdatedBefore); err != nil {
		t.Fatalf("read threat event before replay: %v", err)
	}
	dispatchUID := transport.DeterministicUID("server_dispatch", "component_alerts:v2", firstMessage.ID)
	if err := client.HDel(ctx, "transport_reliability:server_dispatch", dispatchUID).Err(); err != nil {
		t.Fatalf("remove dispatch receipt for crash replay: %v", err)
	}
	if _, err := consumer.processDelivery(ctx, transport.Delivery{Stream: "component_alerts:v2", MessageID: firstMessage.ID, Values: firstMessage.Values}); err != nil {
		t.Fatalf("replay delivery after missing receipt: %v", err)
	}
	var canonicalVersionAfter int64
	var canonicalPayloadAfter string
	if err := pool.QueryRow(ctx, `SELECT version,payload_json FROM lyflow_event_storage_events WHERE event_uid=$1`, firstCanonical.EventUID).Scan(&canonicalVersionAfter, &canonicalPayloadAfter); err != nil {
		t.Fatalf("read canonical event after replay: %v", err)
	}
	var threatUpdatedAfter time.Time
	if err := pool.QueryRow(ctx, `SELECT updated_at FROM threat_events WHERE event_uid=$1`, threatEventUID).Scan(&threatUpdatedAfter); err != nil {
		t.Fatalf("read threat event after replay: %v", err)
	}
	if canonicalVersionAfter != canonicalVersionBefore || canonicalPayloadAfter != canonicalPayloadBefore || !threatUpdatedAfter.Equal(threatUpdatedBefore) {
		t.Fatalf("delivery replay changed persisted state: canonical_version=%d/%d payload_equal=%t threat_updated=%s/%s", canonicalVersionBefore, canonicalVersionAfter, canonicalPayloadBefore == canonicalPayloadAfter, threatUpdatedBefore, threatUpdatedAfter)
	}
	report, err := runtime.migration.Reconcile(ctx)
	if err != nil {
		t.Fatalf("reconcile canonical stores: %v", err)
	}
	if !report.Match || report.PostgresCount != 9 || report.ClickHouseCount != 9 {
		t.Fatalf("canonical store counts drifted: %+v", report)
	}
	receipts, err := client.HLen(ctx, "transport_reliability:server_dispatch").Result()
	if err != nil || receipts != 9 {
		t.Fatalf("server dispatch receipts = %d, want 9: %v", receipts, err)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/security-events?limit=20", nil)
	request = request.WithContext(context.WithValue(request.Context(), auth.RoleContextKey, auth.RoleAnalyst))
	response := httptest.NewRecorder()
	securityEventsHandler(runtime).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("security-events API returned %d: %s", response.Code, response.Body.String())
	}
	var result struct {
		Events []contracts.CanonicalSecurityEvent `json:"events"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode security-events API: %v", err)
	}
	if len(result.Events) != 9 {
		t.Fatalf("security-events API count = %d, want 9", len(result.Events))
	}
	actualCounts := make(map[string]int, len(expectedSources))
	actualRawHashes := make([]string, 0, len(result.Events))
	seenRawHashes := make(map[string]struct{}, len(result.Events))
	eventUIDs := make([]string, 0, len(result.Events))
	for _, event := range result.Events {
		eventUIDs = append(eventUIDs, event.EventUID)
		var payload struct {
			NativeRule   *contracts.RuleReference `json:"native_rule"`
			RawReference *contracts.RawReference  `json:"raw_reference"`
		}
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			t.Fatalf("decode canonical payload %s: %v", event.EventUID, err)
		}
		if payload.NativeRule == nil {
			t.Fatalf("canonical native rule identity is missing")
		}
		expected, ok := expectedSources[payload.NativeRule.ID]
		if !ok || expected.sourceID != payload.NativeRule.Source || expected.revision != payload.NativeRule.Revision {
			t.Fatalf("canonical native rule identity is incomplete: %+v", payload.NativeRule)
		}
		if payload.RawReference == nil {
			t.Fatalf("canonical raw reference is incomplete: %+v", payload.RawReference)
		}
		expectedHash, err := recomputeSuricataRawHash(payload.RawReference)
		if err != nil {
			t.Fatalf("verify canonical raw reference: %v", err)
		}
		if payload.RawReference.Hash != expectedHash {
			t.Fatalf("canonical raw hash = %q, recomputed %q", payload.RawReference.Hash, expectedHash)
		}
		if _, duplicate := seenRawHashes[payload.RawReference.Hash]; duplicate {
			t.Fatalf("canonical raw hash is reused: %q", payload.RawReference.Hash)
		}
		seenRawHashes[payload.RawReference.Hash] = struct{}{}
		actualRawHashes = append(actualRawHashes, payload.RawReference.Hash)
		actualCounts[payload.NativeRule.Source]++
	}
	for _, source := range expectedSources {
		if actualCounts[source.sourceID] != source.count {
			t.Fatalf("security-events API source %s count = %d, want %d", source.sourceID, actualCounts[source.sourceID], source.count)
		}
	}
	sort.Strings(eventUIDs)
	sort.Strings(actualRawHashes)
	unauthorized := httptest.NewRecorder()
	securityEventsHandler(runtime).ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/v1/security-events?limit=20", nil))
	if unauthorized.Code != http.StatusForbidden {
		t.Fatalf("roleless security-events API returned %d, want %d", unauthorized.Code, http.StatusForbidden)
	}
	if output := os.Getenv("T12_PIPELINE_EVIDENCE_OUTPUT"); output != "" {
		evidence := struct {
			SchemaVersion       string         `json:"schema_version"`
			Status              string         `json:"status"`
			AgentStreamCount    int            `json:"agent_stream_count"`
			ThreatEventCount    int            `json:"threat_event_count"`
			CanonicalPostgres   int            `json:"canonical_postgres_count"`
			CanonicalClickHouse int            `json:"canonical_clickhouse_count"`
			ServerDispatchCount int64          `json:"server_dispatch_receipt_count"`
			SecurityEventsAPI   int            `json:"security_events_api_count"`
			RolelessRequestCode int            `json:"roleless_request_status"`
			NativeSourceCounts  map[string]int `json:"native_source_counts"`
			RawHashes           []string       `json:"raw_hashes"`
			EventUIDs           []string       `json:"event_uids"`
		}{
			SchemaVersion: "lyflow.t12.pipeline_result/v1", Status: "PASS", AgentStreamCount: len(messages),
			ThreatEventCount: threatCount, CanonicalPostgres: report.PostgresCount, CanonicalClickHouse: report.ClickHouseCount,
			ServerDispatchCount: receipts, SecurityEventsAPI: len(result.Events), RolelessRequestCode: unauthorized.Code,
			NativeSourceCounts: actualCounts, RawHashes: actualRawHashes, EventUIDs: eventUIDs,
		}
		encoded, err := json.MarshalIndent(evidence, "", "  ")
		if err != nil {
			t.Fatalf("encode pipeline evidence: %v", err)
		}
		if err := os.WriteFile(output, append(encoded, '\n'), 0o644); err != nil {
			t.Fatalf("write pipeline evidence: %v", err)
		}
	}
}

func recomputeSuricataRawHash(reference *contracts.RawReference) (string, error) {
	file, err := os.Open(reference.Path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	if _, err := file.Seek(reference.Offset, io.SeekStart); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(file).ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return "", errors.New("raw reference points to an empty EVE record")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(line, &fields); err != nil {
		return "", err
	}
	delete(fields, "flow_id")
	canonical, err := json.Marshal(fields)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}
