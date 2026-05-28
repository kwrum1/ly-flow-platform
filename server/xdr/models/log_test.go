package models

import (
	"testing"
	"time"
)

func TestXDRLogInputToNormalizedLog_ParsesRFC3339Timestamp(t *testing.T) {
	in := &XDRLogInput{
		AgentID:   "agent-1",
		Hostname:  "host-a",
		Source:    "sshd",
		Program:   "sshd",
		Level:     "warning",
		Timestamp: "2026-05-09T10:11:12Z",
		Message:   "failed password",
		SrcIP:     "10.0.0.2",
		DstIP:     "10.0.0.3",
		SrcPort:   22,
		DstPort:   51234,
		User:      "root",
		Service:   "ssh",
		Raw:       "raw-line",
		Metadata: map[string]interface{}{
			"attempt": float64(2),
		},
	}

	got, err := in.ToNormalizedLog()
	if err != nil {
		t.Fatalf("ToNormalizedLog() error = %v", err)
	}

	wantTs, _ := time.Parse(time.RFC3339, in.Timestamp)
	if !got.Timestamp.Equal(wantTs) {
		t.Fatalf("Timestamp = %v, want %v", got.Timestamp, wantTs)
	}
	if got.Source != in.Source || got.Program != in.Program || got.User != in.User {
		t.Fatalf("field copy mismatch: got %+v", got)
	}
}

func TestXDRLogInputToNormalizedLog_InvalidTimestampFallsBack(t *testing.T) {
	before := time.Now().Add(-2 * time.Second)
	got, err := (&XDRLogInput{Timestamp: "not-rfc3339"}).ToNormalizedLog()
	after := time.Now().Add(2 * time.Second)
	if err != nil {
		t.Fatalf("ToNormalizedLog() error = %v", err)
	}

	if got.Timestamp.Before(before) || got.Timestamp.After(after) {
		t.Fatalf("fallback timestamp out of expected range: %v", got.Timestamp)
	}
}
