package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func lyprobeFlowMessage(id string, payload string) redis.XMessage {
	return redis.XMessage{ID: id, Values: map[string]interface{}{"data": payload}}
}

func TestLyprobeRecentFlowFromMessages(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	recent := now.Add(-2 * time.Minute).Format(time.RFC3339)
	old := now.Add(-10 * time.Minute).Format(time.RFC3339)

	tests := []struct {
		name   string
		msgs   []redis.XMessage
		wantOK bool
	}{
		{
			name:   "recent lyprobe flow is a heartbeat",
			msgs:   []redis.XMessage{lyprobeFlowMessage("1-0", fmt.Sprintf(`{"source":"lyprobe","timestamp":%q}`, recent))},
			wantOK: true,
		},
		{
			name:   "old lyprobe flow is not a heartbeat",
			msgs:   []redis.XMessage{lyprobeFlowMessage("1-0", fmt.Sprintf(`{"source":"lyprobe","timestamp":%q}`, old))},
			wantOK: false,
		},
		{
			name:   "other sources are ignored",
			msgs:   []redis.XMessage{lyprobeFlowMessage("1-0", fmt.Sprintf(`{"source":"suricata","timestamp":%q}`, recent))},
			wantOK: false,
		},
		{
			name:   "message id is the timestamp fallback",
			msgs:   []redis.XMessage{lyprobeFlowMessage(fmt.Sprintf("%d-0", now.Add(-time.Minute).UnixMilli()), `{"source":"lyprobe"}`)},
			wantOK: true,
		},
		{
			name:   "invalid payload is ignored",
			msgs:   []redis.XMessage{lyprobeFlowMessage("1-0", `{invalid`)},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := lyprobeRecentFlowFromMessages(tt.msgs, now, lyprobeHeartbeatWindow)
			if ok != tt.wantOK {
				t.Fatalf("heartbeat = %v, want %v (at=%v)", ok, tt.wantOK, got)
			}
			if ok && got.IsZero() {
				t.Fatal("heartbeat returned zero timestamp")
			}
		})
	}
}

func TestTTLResponseCache(t *testing.T) {
	cache := newTTLResponseCache(20 * time.Millisecond)
	cache.set("key", []byte(`{"ok":true}`))
	if body, ok := cache.get("key"); !ok || string(body) != `{"ok":true}` {
		t.Fatalf("cache hit = %v, body = %q", ok, body)
	}
	cache.clear()
	if _, ok := cache.get("key"); ok {
		t.Fatal("cache still returns entries after clear")
	}
	cache.set("key", []byte(`{"ok":true}`))
	time.Sleep(30 * time.Millisecond)
	if _, ok := cache.get("key"); ok {
		t.Fatal("cache entry did not expire")
	}
}
