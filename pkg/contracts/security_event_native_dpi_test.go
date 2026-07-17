package contracts

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestCanonicalEventDPIAdapterNormalizesRealOutputAlertShape(t *testing.T) {
	// Given
	data, err := os.ReadFile("testdata/source-fixtures.json")
	if err != nil {
		t.Fatalf("read source fixtures: %v", err)
	}
	var fixtures []SourceFixture
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatalf("decode source fixtures: %v", err)
	}
	var dpiFixture SourceFixture
	for _, fixture := range fixtures {
		if fixture.Source == SourceDPIEngine {
			dpiFixture = fixture
			break
		}
	}
	if dpiFixture.NativeSchema == "" {
		t.Fatal("DPI native fixture missing")
	}

	// When
	event, _, err := NormalizeFixture(dpiFixture, PrincipalIdentity("agent-1"), migrationTestTime)

	// Then
	if err != nil {
		t.Fatalf("normalize real DPI output alert: %v", err)
	}
	if event.Severity != SeverityMedium {
		t.Fatalf("DPI severity=%s, expected %s", event.Severity, SeverityMedium)
	}
	if event.Provenance.Adapter != "contracts.dpiAlertAdapter" {
		t.Fatalf("DPI adapter=%s", event.Provenance.Adapter)
	}
	var payloadFields map[string]json.RawMessage
	if err := json.Unmarshal(event.Payload, &payloadFields); err != nil {
		t.Fatalf("decode normalized DPI payload: %v", err)
	}
	expectedFields := map[string]json.RawMessage{
		"score": json.RawMessage(`75`), "status": json.RawMessage(`"new"`),
		"domain": json.RawMessage(`"fixture.invalid"`), "data": json.RawMessage(`"inert fixture payload"`),
	}
	for name, expected := range expectedFields {
		actual, exists := payloadFields[name]
		if !exists || !bytes.Equal(actual, expected) {
			t.Fatalf("DPI normalized payload field %s=%s, expected %s", name, actual, expected)
		}
	}
}

func TestCanonicalEventDPIAdapterRejectsUnknownProducerField(t *testing.T) {
	// Given
	fixture := SourceFixture{
		Source: SourceDPIEngine, SchemaVersion: SecurityEventSchemaVersion, NativeSchema: NativeDPIAlert,
		Payload: json.RawMessage(`{"id":1001,"timestamp":"2026-07-13T09:59:07Z","type":"dpi","src_ip":"192.0.2.14","dst_ip":"198.51.100.24","src_port":49152,"dst_port":443,"protocol":"tcp","signature":"inert fixture signature","category":"rule","severity":3,"score":75,"status":"new","sensor_id":"agent-1","domain":"fixture.invalid","data":"inert fixture payload","unexpected":"rejected"}`),
	}

	// When
	_, _, err := NormalizeFixture(fixture, PrincipalIdentity("agent-1"), migrationTestTime)

	// Then
	var quarantine *QuarantineError
	if !errors.As(err, &quarantine) || quarantine.Reason != QuarantineInvalidField {
		t.Fatalf("unknown DPI field should quarantine as invalid field: %v", err)
	}
}
