package main

import (
	"bytes"
	"os"
	"testing"
	"time"
)

func TestRASPBridgeFallback_rejects_tampered_integrity_chain_on_restart(t *testing.T) {
	// Given
	path := t.TempDir() + "/fallback.jsonl"
	log, err := newRASPBridgeFallbackLog(path, time.Now)
	if err != nil {
		t.Fatalf("create fallback log: %v", err)
	}
	event := raspBridgeEventRequest{
		SchemaVersion: raspBridgeEventSchemaVersion,
		EventID:       "tamper-test",
		AgentID:       "agent-todo12",
		PolicyID:      "rasp-policy-todo12",
		PolicyVersion: 12,
	}
	if err := log.Append(event, raspFallbackDeliveryFailed); err != nil {
		t.Fatalf("append fallback record: %v", err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fallback record: %v", err)
	}
	tampered := bytes.Replace(contents, []byte(`"policy_version":12`), []byte(`"policy_version":11`), 1)
	if err := os.WriteFile(path, tampered, 0o640); err != nil {
		t.Fatalf("tamper fallback record: %v", err)
	}

	// When
	_, err = newRASPBridgeFallbackLog(path, time.Now)

	// Then
	if err == nil {
		t.Fatal("tampered fallback integrity chain accepted")
	}
}
