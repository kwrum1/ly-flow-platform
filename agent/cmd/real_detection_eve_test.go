package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/lyflow/ly-flow-platform/contracts"
	"github.com/redis/go-redis/v9"
)

func TestRealDetectionEVE_publishesFiveNativeSourcesToRedis(t *testing.T) {
	redisAddress := os.Getenv("LYFLOW_TEST_REDIS_ADDR")
	evidenceDir := os.Getenv("T12_REAL_DETECTION_EVE_DIR")
	if redisAddress == "" || evidenceDir == "" {
		t.Skip("T12 real Redis and generated EVE paths are required")
	}

	ctx := context.Background()
	t.Setenv("LYFLOW_TRANSPORT_SPOOL_KEY", "3031323334353637383961626364656630313233343536373839616263646566")
	apiAddress := os.Getenv("T12_REAL_DETECTION_API")
	agentKey := os.Getenv("T12_REAL_DETECTION_AGENT_KEY")
	agent := NewAgent(&Config{
		API: apiAddress, Redis: redisAddress, AgentID: "t12-packet-sensor", AgentKey: agentKey,
		SpoolEnabled: true, SpoolDir: t.TempDir(),
		SpoolMaxBytes: 1 << 20, SpoolFlushInterval: 60,
	})
	agent.agentID = "t12-packet-sensor"
	agent.agentKey = agentKey
	agent.hostname = "t12-suricata"
	if apiAddress != "" {
		if agentKey == "" {
			t.Fatal("T12_REAL_DETECTION_AGENT_KEY is required with T12_REAL_DETECTION_API")
		}
		agent.sendHeartbeat()
	}

	for _, path := range []string{
		filepath.Join(evidenceDir, "four-source", "eve.json"),
		filepath.Join(evidenceDir, "stamus", "eve.json"),
	} {
		offset := int64(0)
		for {
			next, err := agent.consumeSuricataEVEFile(path, offset)
			if err != nil && !errors.Is(err, errRuntimeCPUBudget) {
				t.Fatalf("consume generated EVE %s at offset %d: %v", path, offset, err)
			}
			if next <= offset {
				t.Fatalf("generated EVE offset did not advance for %s: %d", path, next)
			}
			info, statErr := os.Stat(path)
			if statErr != nil {
				t.Fatalf("stat generated EVE %s: %v", path, statErr)
			}
			if next >= info.Size() {
				break
			}
			offset = next
		}
	}
	if agent.trafficSpool == nil {
		t.Fatal("durable Agent spool was not initialized")
	}
	t.Cleanup(agent.trafficSpool.Close)

	client := redis.NewClient(&redis.Options{Addr: redisAddress})
	t.Cleanup(func() { _ = client.Close() })
	messages, err := client.XRange(ctx, "component_alerts:v2", "-", "+").Result()
	if err != nil {
		t.Fatalf("read component alert stream: %v", err)
	}
	if len(messages) != 9 {
		t.Fatalf("component alert count = %d, want 9", len(messages))
	}

	type expectedRule struct {
		source   string
		revision string
		ruleID   string
	}
	expectedRules := map[string]expectedRule{
		"2002005":   {source: "suricata-et-open", revision: "36", ruleID: "1:2002005"},
		"300000000": {source: "oisf-trafficid", revision: "1", ruleID: "1:990000000"},
		"26655":     {source: "snort-community", revision: "2", ruleID: "1:26655"},
		"10000005":  {source: "ptresearch-attackdetection", revision: "3", ruleID: "1:10000005"},
		"3115102":   {source: "stamus-lateral", revision: "4", ruleID: "1:3115102"},
	}
	expectedCounts := map[string]int{"2002005": 1, "300000000": 2, "26655": 2, "10000005": 2, "3115102": 2}
	expectedRawHashes := map[string]struct{}{
		"b5308e6f1ef208b99d452730fc5f525c49dde8b63132519551cf6fcd97202fdd": {},
		"35612b961f41eeb3daabbbef6a1ec2be1d295a20290dd55822eed479da2ced53": {},
		"43a2414fa6e2b11484bdb54b177b2c4308acb699cb8833615a5e1cc24224b9d7": {},
		"e780d5538c1bf0590e49eb57d7b2e09381c7362157ab65c3ceacdd18c68be80c": {},
		"fb815e0eabbbfe506bf37d550f4d9f86c8d7262b42f38b9c7961c220f86ac310": {},
		"31bf8a471345f3fba783b1f7909fd0b0f4e1dc8123344f9ca6ba7955517173ac": {},
		"9af0dcce518c31c1468141ee1e622d5d010c92a402247775b46274beb9b9c0d5": {},
		"413c09b11e9a055d49b94229576757d6b72857888ec3419d06ce3d17262cde8b": {},
		"2afc0f19ed41a7d5a09c38e0a47507f0c476b734d0fe130c78267e61c5ff14f1": {},
	}
	actualCounts := make(map[string]int, len(expectedCounts))
	for _, message := range messages {
		encoded, ok := message.Values["data"].(string)
		if !ok {
			t.Fatalf("Redis message %s data is %T", message.ID, message.Values["data"])
		}
		var alert contracts.ComponentAlert
		if err := json.Unmarshal([]byte(encoded), &alert); err != nil {
			t.Fatalf("decode Redis message %s: %v", message.ID, err)
		}
		if alert.NativeRule == nil {
			t.Fatalf("alert %s has no native rule", alert.ID)
		}
		sid := alert.NativeRule.ID
		expected, ok := expectedRules[sid]
		if !ok {
			t.Fatalf("unexpected native SID %q in alert %s", sid, alert.ID)
		}
		if alert.NativeRule.Source != expected.source || alert.NativeRule.Revision != expected.revision {
			t.Fatalf("SID %s native identity = %q/%q, want %q/%q", sid, alert.NativeRule.Source, alert.NativeRule.Revision, expected.source, expected.revision)
		}
		if alert.Entities.AgentID != "t12-packet-sensor" || alert.Entities.Hostname != "t12-suricata" {
			t.Fatalf("SID %s Agent identity was not preserved: %+v", sid, alert.Entities)
		}
		if alert.RawReference == nil || alert.RawReference.Path == "" || alert.RawReference.Offset < 0 {
			t.Fatalf("SID %s raw reference is incomplete: %+v", sid, alert.RawReference)
		}
		if _, ok := expectedRawHashes[alert.RawReference.Hash]; !ok {
			t.Fatalf("SID %s raw hash is not pinned: %q", sid, alert.RawReference.Hash)
		}
		delete(expectedRawHashes, alert.RawReference.Hash)
		if alert.RuleID != expected.ruleID {
			t.Fatalf("SID %s rule ID = %q, want %q", sid, alert.RuleID, expected.ruleID)
		}
		actualCounts[sid]++
	}
	if len(expectedRawHashes) != 0 {
		t.Fatalf("Agent output omitted %d pinned raw hashes", len(expectedRawHashes))
	}
	for sid, expected := range expectedCounts {
		if actualCounts[sid] != expected {
			t.Fatalf("SID %s count = %d, want %d", sid, actualCounts[sid], expected)
		}
	}
}
