package main

import (
	"testing"

	"github.com/redis/go-redis/v9"
)

func TestRealtimePayloadCreatesIncidentNotification(t *testing.T) {
	message := redis.XMessage{ID: "1-0", Values: map[string]interface{}{"data": `{"message":"attack chain updated","chain_id":"chain-1","severity":"high"}`}}
	payload := realtimePayload("events:xdr", message)
	if payload["type"] != "incident.updated" {
		t.Fatalf("type=%v, want incident.updated", payload["type"])
	}
	if payload["freshness"] != "fresh" || payload["stream"] != "events:xdr" {
		t.Fatalf("unexpected realtime payload: %#v", payload)
	}
}

func TestRealtimePayloadDoesNotExposeRawHighVolumeFlowStream(t *testing.T) {
	message := redis.XMessage{ID: "1-0", Values: map[string]interface{}{"data": `{"id":"flow-1"}`}}
	payload := realtimePayload("alerts:runtime", message)
	if payload["stream"] == "flows:raw" {
		t.Fatalf("raw flow stream should not be emitted: %#v", payload)
	}
}
