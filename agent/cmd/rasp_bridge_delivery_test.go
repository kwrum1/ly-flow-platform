package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

func TestRASPBridgeEvent_delivers_valid_inert_event_as_canonical_telemetry(t *testing.T) {
	// Given
	publisher := &channelRASPBridgePublisher{events: make(chan contracts.TelemetryEnvelope, 1)}
	bridge := newTestRASPBridge(t, time.Now, 4, true, publisher)

	// When
	response := performRASPBridgeRequest(bridge.Handler(), http.MethodPost, raspBridgeEventsPath, "bridge-token-current", validRASPBridgeBody(t))

	// Then
	if response.Code != http.StatusAccepted {
		t.Fatalf("event status = %d body = %s", response.Code, response.Body.String())
	}
	select {
	case telemetry := <-publisher.events:
		if err := telemetry.Validate(); err != nil {
			t.Fatalf("telemetry invalid: %v", err)
		}
		if telemetry.Fields["command"] != "echo todo12-inert" || telemetry.Fields["evidence"] != "echo todo12-inert" {
			t.Fatalf("command semantic fields missing: %+v", telemetry.Fields)
		}
		canonical, err := telemetry.Canonical(contracts.PrincipalIdentity("agent-todo12"), time.Date(2026, 7, 14, 12, 0, 1, 0, time.UTC))
		if err != nil {
			t.Fatalf("canonicalize delivered event: %v", err)
		}
		if err := canonical.Validate(); err != nil {
			t.Fatalf("canonical event invalid: %v", err)
		}
		if canonical.Provenance.Source != contracts.SourceAgentRASP || canonical.Identity.AgentID != "agent-todo12" {
			t.Fatalf("canonical binding invalid: %+v", canonical)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for canonical RASP delivery")
	}
}

func TestRASPBridgeRealLoopback_delivers_authenticated_inert_event(t *testing.T) {
	// Given
	publisher := &channelRASPBridgePublisher{events: make(chan contracts.TelemetryEnvelope, 1)}
	bridge := newTestRASPBridge(t, time.Now, 4, true, publisher)
	server := httptest.NewServer(bridge.Handler())
	defer server.Close()
	request, err := http.NewRequest(http.MethodPost, server.URL+raspBridgeEventsPath, bytes.NewReader(validRASPBridgeBody(t)))
	if err != nil {
		t.Fatalf("create loopback request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(raspBridgeTokenHeader, "bridge-token-current")
	request.Header.Set(raspBridgeAgentHeader, "agent-todo12")

	// When
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatalf("send loopback request: %v", err)
	}
	defer response.Body.Close()

	// Then
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("loopback status = %d", response.StatusCode)
	}
	select {
	case event := <-publisher.events:
		if event.Entities.AgentID != "agent-todo12" || event.EventType != raspBridgeEventCommand {
			t.Fatalf("unexpected loopback delivery: %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for loopback delivery")
	}
}

func TestRASPBridgeEvent_queue_saturation_rejects_and_persists_integrity_fallback(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	bridge := newTestRASPBridge(t, func() time.Time { return now }, 1, false, &channelRASPBridgePublisher{events: make(chan contracts.TelemetryEnvelope, 1)})

	// When
	accepted := performRASPBridgeRequest(bridge.Handler(), http.MethodPost, raspBridgeEventsPath, "bridge-token-current", validRASPBridgeBody(t))
	rejected := performRASPBridgeRequest(bridge.Handler(), http.MethodPost, raspBridgeEventsPath, "bridge-token-current", validRASPBridgeBody(t))

	// Then
	if accepted.Code != http.StatusAccepted {
		t.Fatalf("first event status = %d", accepted.Code)
	}
	if rejected.Code != http.StatusTooManyRequests {
		t.Fatalf("saturated event status = %d body = %s", rejected.Code, rejected.Body.String())
	}
	record := readRASPBridgeFallback(t, bridge.fallback.path)
	if record.Reason != raspFallbackQueueFull || record.PayloadSHA256 == "" || record.RecordSHA256 == "" || record.PolicyVersion != 12 {
		t.Fatalf("fallback integrity metadata incomplete: %+v", record)
	}
	health := bridge.Health()
	if len(bridge.queue) != 1 || cap(bridge.queue) != 1 || bridge.rejected.Load() != 1 || bridge.fallbackCount.Load() != 1 || health.Status != controlHealthDegraded {
		t.Fatalf("unexpected saturated health: %+v", health)
	}
}

func TestRASPBridgeDelivery_failure_persists_fallback_and_reports_health(t *testing.T) {
	// Given
	publisher := &channelRASPBridgePublisher{events: make(chan contracts.TelemetryEnvelope, 1), err: errors.New("inert downstream outage")}
	bridge := newTestRASPBridge(t, time.Now, 1, true, publisher)

	// When
	response := performRASPBridgeRequest(bridge.Handler(), http.MethodPost, raspBridgeEventsPath, "bridge-token-current", validRASPBridgeBody(t))

	// Then
	if response.Code != http.StatusAccepted {
		t.Fatalf("event status = %d body = %s", response.Code, response.Body.String())
	}
	select {
	case <-bridge.deliveryFinished:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for failed delivery fallback")
	}
	record := readRASPBridgeFallback(t, bridge.fallback.path)
	if record.Reason != raspFallbackDeliveryFailed {
		t.Fatalf("fallback reason = %q", record.Reason)
	}
	health := bridge.Health()
	bridge.healthMu.RLock()
	lastError := bridge.lastError
	bridge.healthMu.RUnlock()
	if bridge.deliveryFailures.Load() != 1 || bridge.fallbackCount.Load() != 1 || lastError == "" || health.Status != controlHealthDegraded {
		t.Fatalf("unexpected failed delivery health: %+v", health)
	}
}

func readRASPBridgeFallback(t *testing.T, path string) raspFallbackRecord {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open fallback log: %v", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		t.Fatalf("read fallback log: %v", scanner.Err())
	}
	var record raspFallbackRecord
	if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
		t.Fatalf("decode fallback record: %v", err)
	}
	return record
}

var _ raspBridgePublisher = (*channelRASPBridgePublisher)(nil)
