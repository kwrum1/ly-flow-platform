package main

import (
	"testing"
	"time"
)

func TestThreatCacheCarriesMatchToReverseDirection(t *testing.T) {
	// Given
	collector := &Collector{threats: map[string]threatEntry{}}
	forward := Record{
		"src_ip": "10.0.0.5", "src_port": int64(40000),
		"dst_ip": "10.0.0.9", "dst_port": int64(80),
		"protocol":    int64(6),
		"threat_type": "SQL", "threat_name": "CRUD",
	}
	reverse := Record{
		"src_ip": "10.0.0.9", "src_port": int64(80),
		"dst_ip": "10.0.0.5", "dst_port": int64(40000),
		"protocol": int64(6),
	}

	// When
	collector.applyCachedThreat(forward)
	collector.applyCachedThreat(reverse)

	// Then
	if reverse["threat_type"] != "SQL" || reverse["threat_name"] != "CRUD" {
		t.Fatalf("reverse threat = %v/%v, want SQL/CRUD", reverse["threat_type"], reverse["threat_name"])
	}
	if reverse["threat_cached"] != true {
		t.Fatal("reverse threat was not marked as cached")
	}
	if forward["threat_cached"] == true {
		t.Fatal("original threat record must not be marked cached")
	}
}

func TestThreatCacheKeepsNewestMatchAndExpires(t *testing.T) {
	// Given
	collector := &Collector{threats: map[string]threatEntry{}}
	record := Record{
		"src_ip": "10.0.0.5", "src_port": int64(40000),
		"dst_ip": "10.0.0.9", "dst_port": int64(443),
		"protocol": int64(6),
	}
	collector.applyCachedThreat(Record{
		"src_ip": "10.0.0.5", "src_port": int64(40000),
		"dst_ip": "10.0.0.9", "dst_port": int64(443),
		"protocol":    int64(6),
		"threat_type": "SQL", "threat_name": "CRUD",
	})

	// When
	collector.threatsMu.Lock()
	collector.threats[threatFlowKey(record)] = threatEntry{Type: "SQL", Name: "CRUD", At: time.Now().Add(-11 * time.Minute)}
	collector.threatsMu.Unlock()
	collector.applyCachedThreat(record)

	// Then
	if stringValue(record["threat_type"]) != "" || stringValue(record["threat_name"]) != "" {
		t.Fatalf("expired threat was applied: %v/%v", record["threat_type"], record["threat_name"])
	}
}
