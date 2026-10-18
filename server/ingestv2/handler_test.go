package ingestv2

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

type fakeWriter struct {
	events []contracts.EventV2
	err    error
}

func (writer *fakeWriter) WriteEventsV2(_ context.Context, events []contracts.EventV2) error {
	writer.events = append(writer.events, events...)
	return writer.err
}

func testEvent() contracts.EventV2 {
	now := time.Now().UTC()
	return contracts.EventV2{
		SchemaVersion: contracts.SecurityEventSchemaV2,
		EventUID:      "evt-1",
		TenantID:      "",
		Source:        contracts.SourceSuricata,
		EventType:     "network.signature",
		Timestamps: contracts.EventTimestamps{
			EventAt: now.Add(-time.Second), ObservedAt: now,
		},
		Entities: contracts.Entities{
			Asset: &contracts.AssetEntity{ID: "asset-1"},
			Network: &contracts.NetworkEntity{
				SrcIP: "10.0.0.1", DstIP: "10.0.0.2", DstPort: 443, Proto: "tcp",
			},
		},
		Detection: contracts.Detection{
			RuleID: "1000001", RuleSource: "et-open", Severity: contracts.SeverityHigh,
			Confidence: 0.9, TacticID: "TA0001", TechniqueID: "T1190",
			Stage: contracts.StageInitialAccess,
		},
		Payload: json.RawMessage(`{"http":{"method":"POST"}}`),
		Raw: contracts.RawRef{
			NativeSchema: "suricata.eve.v7", NativeEventID: "native-1",
			Adapter: "adapter", PayloadSHA256: strings.Repeat("a", 64),
		},
		Governance: contracts.GovernanceMetadata{
			Classification: contracts.ClassificationInternal,
			Retention: contracts.RetentionPolicy{
				PolicyID:  contracts.RetentionPolicySecurityEvent30D,
				ExpiresAt: now.Add(30 * 24 * time.Hour),
			},
			Encryption: contracts.EncryptionMetadata{
				Required: true, Algorithm: contracts.EncryptionAlgorithmAES256GCM, KeyRef: "kms://test",
			},
			AccessPolicyID:   contracts.AccessPolicySecurityEventRead,
			DeletionPolicyID: contracts.DeletionPolicySecurityEvent,
			ExportPolicyID:   contracts.ExportPolicySecurityEvent,
		},
	}
}

func requestBody(t *testing.T, events ...contracts.EventV2) *strings.Reader {
	t.Helper()
	encoded, err := json.Marshal(map[string]any{"events": events})
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	return strings.NewReader(string(encoded))
}

func TestHandlerAcceptsValidBatch(t *testing.T) {
	writer := &fakeWriter{}
	handler := Handler{
		Auth:   func(*http.Request, string) (string, error) { return "agent-1", nil },
		Writer: writer,
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v2/ingest/events", requestBody(t, testEvent()))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(writer.events) != 1 {
		t.Fatalf("writer received %d events", len(writer.events))
	}
	event := writer.events[0]
	if event.TenantID != "default" || event.CorrelationID != "evt-1" {
		t.Fatalf("defaults not applied: %+v", event)
	}
	if event.Timestamps.IngestedAt.IsZero() {
		t.Fatal("ingested_at not filled")
	}
}

func TestHandlerBindsAssetWhenMissing(t *testing.T) {
	writer := &fakeWriter{}
	handler := Handler{
		Auth:   func(*http.Request, string) (string, error) { return "agent-1", nil },
		Writer: writer,
	}
	event := testEvent()
	event.Entities.Asset = nil
	request := httptest.NewRequest(http.MethodPost, "/api/v2/ingest/events", requestBody(t, event))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if writer.events[0].Entities.Asset == nil || writer.events[0].Entities.Asset.ID != "agent-1" {
		t.Fatalf("asset not bound: %+v", writer.events[0].Entities.Asset)
	}
}

func TestHandlerComputesPayloadDigest(t *testing.T) {
	writer := &fakeWriter{}
	handler := Handler{
		Auth:   func(*http.Request, string) (string, error) { return "agent-1", nil },
		Writer: writer,
	}
	event := testEvent()
	event.Raw.PayloadSHA256 = ""
	request := httptest.NewRequest(http.MethodPost, "/api/v2/ingest/events", requestBody(t, event))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(writer.events[0].Raw.PayloadSHA256) != 64 {
		t.Fatalf("digest not computed: %q", writer.events[0].Raw.PayloadSHA256)
	}
}

func TestHandlerRejectsUnauthorized(t *testing.T) {
	handler := Handler{
		Auth:   func(*http.Request, string) (string, error) { return "", errors.New("denied") },
		Writer: &fakeWriter{},
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v2/ingest/events", requestBody(t, testEvent()))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", recorder.Code)
	}
}

func TestHandlerRejectsWrongMethod(t *testing.T) {
	handler := Handler{Auth: func(*http.Request, string) (string, error) { return "agent-1", nil }}
	request := httptest.NewRequest(http.MethodGet, "/api/v2/ingest/events", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d, want 405", recorder.Code)
	}
}

func TestHandlerRejectsEmptyBatch(t *testing.T) {
	handler := Handler{
		Auth:   func(*http.Request, string) (string, error) { return "agent-1", nil },
		Writer: &fakeWriter{},
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v2/ingest/events", strings.NewReader(`{"events":[]}`))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", recorder.Code)
	}
}

func TestHandlerRejectsInvalidEvent(t *testing.T) {
	handler := Handler{
		Auth:   func(*http.Request, string) (string, error) { return "agent-1", nil },
		Writer: &fakeWriter{},
	}
	event := testEvent()
	event.Raw.PayloadSHA256 = "bad"
	request := httptest.NewRequest(http.MethodPost, "/api/v2/ingest/events", requestBody(t, event))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400 body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestHandlerRejectsOversizedBatch(t *testing.T) {
	handler := Handler{
		Auth:     func(*http.Request, string) (string, error) { return "agent-1", nil },
		Writer:   &fakeWriter{},
		MaxBatch: 1,
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v2/ingest/events", requestBody(t, testEvent(), testEvent()))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d, want 413", recorder.Code)
	}
}

func TestHandlerReportsWriterFailure(t *testing.T) {
	handler := Handler{
		Auth:   func(*http.Request, string) (string, error) { return "agent-1", nil },
		Writer: &fakeWriter{err: errors.New("down")},
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v2/ingest/events", requestBody(t, testEvent()))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", recorder.Code)
	}
}
