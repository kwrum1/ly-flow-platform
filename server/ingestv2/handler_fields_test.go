package ingestv2

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lyflow/ly-flow-platform/contracts"
)

func fieldHandler(writer *fakeWriter, mode contracts.FieldValidationMode, logs *[]string) Handler {
	return Handler{
		Auth:      func(*http.Request, string) (string, error) { return "agent-1", nil },
		Writer:    writer,
		FieldMode: mode,
		Logf: func(format string, args ...any) {
			if logs != nil {
				*logs = append(*logs, fmt.Sprintf(format, args...))
			}
		},
	}
}

func TestShadowModeAcceptsIncompleteEventAndRecordsFlags(t *testing.T) {
	writer := &fakeWriter{}
	var logs []string
	handler := fieldHandler(writer, contracts.FieldValidationShadow, &logs)

	event := testEvent()
	event.Entities.Network.DstPort = 0

	request := httptest.NewRequest(http.MethodPost, "/api/v2/ingest/events", requestBody(t, event))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("shadow mode must accept, status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(writer.events) != 1 {
		t.Fatalf("writer received %d events", len(writer.events))
	}
	if !writer.events[0].IsInsufficientTelemetry() {
		t.Fatalf("expected insufficient_telemetry, flags=%v", writer.events[0].QualityFlags)
	}
	if len(logs) == 0 {
		t.Fatal("shadow mode must log the field gap")
	}
}

func TestEnforceModeRejectsIncompleteEvent(t *testing.T) {
	writer := &fakeWriter{}
	handler := fieldHandler(writer, contracts.FieldValidationEnforce, nil)

	event := testEvent()
	event.Entities.Network.SrcPort = 51515
	event.Entities.Network.DstPort = 0

	request := httptest.NewRequest(http.MethodPost, "/api/v2/ingest/events", requestBody(t, event))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d body=%s, want 422", recorder.Code, recorder.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload["error_code"] != "insufficient_telemetry" {
		t.Fatalf("error_code=%v body=%s", payload["error_code"], recorder.Body.String())
	}
	if payload["field"] != "network.dst_port" {
		t.Fatalf("field=%v body=%s", payload["field"], recorder.Body.String())
	}
	if len(writer.events) != 0 {
		t.Fatal("rejected event must not reach the writer")
	}
}

func TestEnforceModeAcceptsCompleteEvent(t *testing.T) {
	writer := &fakeWriter{}
	handler := fieldHandler(writer, contracts.FieldValidationEnforce, nil)

	event := testEvent()
	event.Entities.Network.SrcPort = 51515

	request := httptest.NewRequest(http.MethodPost, "/api/v2/ingest/events", requestBody(t, event))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(writer.events) != 1 {
		t.Fatalf("writer received %d events", len(writer.events))
	}
	if writer.events[0].IsInsufficientTelemetry() {
		t.Fatal("complete event must not be marked insufficient")
	}
}

func TestOffModeKeepsPreviousBehaviour(t *testing.T) {
	writer := &fakeWriter{}
	handler := fieldHandler(writer, contracts.FieldValidationOff, nil)

	event := testEvent()
	event.Entities.Network.DstPort = 0

	request := httptest.NewRequest(http.MethodPost, "/api/v2/ingest/events", requestBody(t, event))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if writer.events[0].IsInsufficientTelemetry() {
		t.Fatal("off mode must not add quality flags")
	}
}
