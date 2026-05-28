package model

import (
	"testing"
	"time"
)

func TestFlowDataGetDomainPriority(t *testing.T) {
	flow := &FlowData{TLSSNI: "tls.example", HTTPHost: "http.example", DNSQuery: "dns.example"}
	if got := flow.GetDomain(); got != "tls.example" {
		t.Fatalf("GetDomain() = %q, want tls.example", got)
	}

	flow.TLSSNI = ""
	if got := flow.GetDomain(); got != "http.example" {
		t.Fatalf("GetDomain() = %q, want http.example", got)
	}

	flow.HTTPHost = ""
	if got := flow.GetDomain(); got != "dns.example" {
		t.Fatalf("GetDomain() = %q, want dns.example", got)
	}
}

func TestFlowDataTime(t *testing.T) {
	flow := &FlowData{Timestamp: 1715000000}
	if got := flow.Time(); !got.Equal(time.Unix(1715000000, 0)) {
		t.Fatalf("Time() = %v, want %v", got, time.Unix(1715000000, 0))
	}
}

func TestToSemanticFlowAndSession(t *testing.T) {
	flow := &FlowData{
		ID:          "flow-1",
		Timestamp:   1715000000,
		SensorID:    "sensor-1",
		SrcIP:       "10.0.0.1",
		DstIP:       "8.8.8.8",
		SrcPort:     54545,
		DstPort:     443,
		Protocol:    "TCP",
		AppProtocol: "HTTPS",
		TLSSNI:      "bot-domain.example",
		JA3:         "ja3-fingerprint",
		BytesIn:     100,
		BytesOut:    200,
		Packets:     5,
		DurationMs:  300,
		Direction:   "egress",
	}

	sf := flow.ToSemanticFlow()
	if sf == nil {
		t.Fatal("ToSemanticFlow() returned nil")
	}
	if sf.Domain != "bot-domain.example" || sf.SessionID != flow.ID || sf.Transport != "TCP" {
		t.Fatalf("semantic flow mismatch: %+v", sf)
	}

	ss := flow.ToSemanticSession()
	if ss == nil {
		t.Fatal("ToSemanticSession() returned nil")
	}
	if ss.BehaviorSummary != "https_single_flow_domain" {
		t.Fatalf("BehaviorSummary = %q, want https_single_flow_domain", ss.BehaviorSummary)
	}
	if !ss.SuspectedBot {
		t.Fatal("SuspectedBot = false, want true")
	}
	if ss.RepeatedDomainHits != 1 {
		t.Fatalf("RepeatedDomainHits = %d, want 1", ss.RepeatedDomainHits)
	}
}

func TestNilFlowConversions(t *testing.T) {
	var f *FlowData
	if got := f.ToSemanticFlow(); got != nil {
		t.Fatalf("nil ToSemanticFlow() = %+v, want nil", got)
	}
	if got := f.ToSemanticSession(); got != nil {
		t.Fatalf("nil ToSemanticSession() = %+v, want nil", got)
	}
}
