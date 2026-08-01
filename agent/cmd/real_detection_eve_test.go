package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
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
	actualRawHashes := make(map[string]struct{}, len(messages))
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
		expectedHash, err := rawHashAtReference(alert.RawReference)
		if err != nil {
			t.Fatalf("SID %s verify raw reference: %v", sid, err)
		}
		if alert.RawReference.Hash != expectedHash {
			t.Fatalf("SID %s raw hash = %q, recomputed %q", sid, alert.RawReference.Hash, expectedHash)
		}
		if _, duplicate := actualRawHashes[alert.RawReference.Hash]; duplicate {
			t.Fatalf("SID %s reused raw hash %q", sid, alert.RawReference.Hash)
		}
		actualRawHashes[alert.RawReference.Hash] = struct{}{}
		if alert.RuleID != expected.ruleID {
			t.Fatalf("SID %s rule ID = %q, want %q", sid, alert.RuleID, expected.ruleID)
		}
		actualCounts[sid]++
	}
	if len(actualRawHashes) != len(messages) {
		t.Fatalf("unique raw hashes = %d, want %d", len(actualRawHashes), len(messages))
	}
	for sid, expected := range expectedCounts {
		if actualCounts[sid] != expected {
			t.Fatalf("SID %s count = %d, want %d", sid, actualCounts[sid], expected)
		}
	}
}

func rawHashAtReference(reference *contracts.RawReference) (string, error) {
	file, err := os.Open(reference.Path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	if _, err := file.Seek(reference.Offset, io.SeekStart); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(file).ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return "", errors.New("raw reference points to an empty EVE record")
	}
	return suricataRawHash(line)
}
