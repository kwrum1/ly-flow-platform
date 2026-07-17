package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/lyflow/ly-flow-platform/contracts"
)

func TestConsumeSuricataEVEFileDeadLettersMalformedAndContinues(t *testing.T) {
	// Given
	var mu sync.Mutex
	received := make([]contracts.ComponentAlert, 0, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var alert contracts.ComponentAlert
		if err := decodeDurableAgentPayload(r, &alert); err != nil {
			t.Fatalf("decode alert: %v", err)
		}
		mu.Lock()
		received = append(received, alert)
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]int{"code": 0})
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "eve.json")
	valid := readSuricataFixtureLines(t)[1]
	content := append([]byte("{truncated-json}\n"), valid...)
	content = append(content, '\n')
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write fixture stream: %v", err)
	}
	agent := newSuricataRuntimeTestAgent(t, server.URL)

	// When
	next, err := agent.consumeSuricataEVEFile(path, 0)
	if err != nil {
		t.Fatalf("consume fixture stream: %v", err)
	}

	// Then
	if next != int64(len(content)) {
		t.Fatalf("next offset = %d, want %d", next, len(content))
	}
	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("published alerts = %d, want 1", len(received))
	}
	assertDeadLetterReason(t, path+suricataDeadLetterSuffix, "malformed_json")
	health := agent.suricataProfileHealth()
	if health["parsed_lines"] != uint64(1) || health["dead_lettered_lines"] != uint64(1) {
		t.Fatalf("unexpected parser health: %#v", health)
	}
}

func TestConsumeSuricataEVEFileResumesInterruptedFixtureLine(t *testing.T) {
	// Given
	line := readSuricataFixtureLines(t)[1]
	cut := len(line) / 2
	path := filepath.Join(t.TempDir(), "eve.json")
	if err := os.WriteFile(path, line[:cut], 0o600); err != nil {
		t.Fatalf("write partial fixture: %v", err)
	}
	received := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received <- struct{}{}
		_ = json.NewEncoder(w).Encode(map[string]int{"code": 0})
	}))
	defer server.Close()
	agent := newSuricataRuntimeTestAgent(t, server.URL)

	// When
	firstOffset, err := agent.consumeSuricataEVEFile(path, 0)
	if err != nil {
		t.Fatalf("consume partial fixture: %v", err)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open fixture for completion: %v", err)
	}
	if _, err := file.Write(append(line[cut:], '\n')); err != nil {
		_ = file.Close()
		t.Fatalf("complete fixture: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close fixture: %v", err)
	}
	secondOffset, err := agent.consumeSuricataEVEFile(path, firstOffset)
	if err != nil {
		t.Fatalf("resume fixture: %v", err)
	}

	// Then
	if firstOffset != 0 || secondOffset != int64(len(line)+1) {
		t.Fatalf("offsets = (%d, %d)", firstOffset, secondOffset)
	}
	select {
	case <-received:
	default:
		t.Fatal("completed fixture was not published")
	}
	if _, err := os.Stat(path + suricataDeadLetterSuffix); !os.IsNotExist(err) {
		t.Fatalf("interrupted line was dead-lettered: %v", err)
	}
}

func TestConsumeSuricataEVEFileDeadLettersStableTruncatedAndOversizedLines(t *testing.T) {
	// Given
	path := filepath.Join(t.TempDir(), "eve.json")
	partial := []byte(`{"timestamp":"2026-07-13T10:00:00Z","event_type":"flow"`)
	if err := os.WriteFile(path, partial, 0o600); err != nil {
		t.Fatalf("write truncated fixture: %v", err)
	}
	agent := newSuricataRuntimeTestAgent(t, "http://127.0.0.1:1")

	// When
	firstOffset, err := agent.consumeSuricataEVEFile(path, 0)
	if err != nil {
		t.Fatalf("first truncated consume: %v", err)
	}
	secondOffset, err := agent.consumeSuricataEVEFile(path, firstOffset)
	if err != nil {
		t.Fatalf("second truncated consume: %v", err)
	}
	oversized := strings.Repeat("x", suricataMaxLineBytes+1) + "\n"
	if err := os.WriteFile(path, []byte(oversized), 0o600); err != nil {
		t.Fatalf("write oversized fixture: %v", err)
	}
	oversizedOffset, err := agent.consumeSuricataEVEFile(path, 0)
	if err != nil {
		t.Fatalf("consume oversized fixture: %v", err)
	}

	// Then
	if firstOffset != 0 || secondOffset != int64(len(partial)) || oversizedOffset != int64(len(oversized)) {
		t.Fatalf("offsets = (%d, %d, %d)", firstOffset, secondOffset, oversizedOffset)
	}
	assertDeadLetterReason(t, path+suricataDeadLetterSuffix, "truncated_line")
	assertDeadLetterReason(t, path+suricataDeadLetterSuffix, "line_too_large")
}

func TestConsumeSuricataEVEFileDeadLettersVersionDriftAndUnsupportedProtocol(t *testing.T) {
	// Given
	path := filepath.Join(t.TempDir(), "eve.json")
	content := []byte(
		`{"timestamp":"2026-07-13T10:00:00Z","flow_id":1,"event_type":"flow","suricata_version":"8.0.0","flow":{}}` + "\n" +
			`{"timestamp":"2026-07-13T10:00:01Z","flow_id":2,"event_type":"ssh","suricata_version":"7.0.11","ssh":{}}` + "\n",
	)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write drift fixture: %v", err)
	}
	agent := newSuricataRuntimeTestAgent(t, "http://127.0.0.1:1")

	// When
	next, err := agent.consumeSuricataEVEFile(path, 0)
	if err != nil {
		t.Fatalf("consume drift fixture: %v", err)
	}

	// Then
	if next != int64(len(content)) {
		t.Fatalf("next offset = %d, want %d", next, len(content))
	}
	assertDeadLetterReason(t, path+suricataDeadLetterSuffix, "version_drift")
	assertDeadLetterReason(t, path+suricataDeadLetterSuffix, "unsupported_event_type")
	health := agent.suricataProfileHealth()
	if health["version_drift_lines"] != uint64(1) || health["unsupported_event_lines"] != uint64(1) {
		t.Fatalf("unexpected drift health: %#v", health)
	}
}

func newSuricataRuntimeTestAgent(t *testing.T, api string) *Agent {
	config := durableAgentTestConfig(t, api)
	config.TrafficTelemetryStream = "telemetry:traffic"
	agent := NewAgent(config)
	agent.agentID = "agent-1"
	agent.agentKey = "key-1"
	agent.hostname = "sensor-1"
	return agent
}

func assertDeadLetterReason(t *testing.T, path, reason string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read dead letter: %v", err)
	}
	if !strings.Contains(string(data), `"reason":"`+reason+`"`) {
		t.Fatalf("dead letter %s lacks reason %q: %s", path, reason, data)
	}
}
