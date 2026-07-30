package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestParseSuricataRulesSupportsStamusDCERPCAndPTWhitespace(t *testing.T) {
	tests := []struct {
		name       string
		prefix     string
		content    string
		wantID     string
		wantField  string
		conditions int
	}{
		{
			name: "stamus dcerpc", prefix: "stamus-lateral", wantID: "stamus-lateral-3115102", wantField: "dcerpc.iface", conditions: 2,
			content: `alert smb any any -> $HOME_NET any (msg:"Stamus Networks MS-SCMR service - RCreateServiceW"; dcerpc.iface:367abb81-9844-35f1-ad32-98f038001003; dcerpc.opnum:12; sid:3115102; rev:4;)`,
		},
		{
			name: "pt whitespace", prefix: "ptresearch-attackdetection", wantID: "ptresearch-attackdetection-10000005", wantField: "payload",
			content: `alert tcp any any -> $HOME_NET any (msg: "ATTACK [PTsecurity] malformed RNDC packet"; content:"_auth"; sid: 10000005; rev: 3;)`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rules := parseSuricataRules(test.content, test.prefix)
			if len(rules) != 1 || asString(rules[0]["id"]) != test.wantID || asString(rules[0]["field"]) != test.wantField || len(mapSlice(rules[0]["conditions"])) != test.conditions {
				t.Fatalf("parsed rules=%#v", rules)
			}
		})
	}
}

func TestParseProductionTrafficCorpusRetainsEverySource(t *testing.T) {
	lockPath := filepath.Join("..", "..", "rules", "traffic-corpus.lock.json")
	contents, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("read traffic corpus lock: %v", err)
	}
	var lock struct {
		Sources []struct {
			SourceID string `json:"source_id"`
			Payload  struct {
				CachePath string `json:"cache_path"`
			} `json:"payload"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(contents, &lock); err != nil {
		t.Fatalf("decode traffic corpus lock: %v", err)
	}
	if len(lock.Sources) != 5 {
		t.Fatalf("traffic source count=%d, want 5", len(lock.Sources))
	}
	for _, source := range lock.Sources {
		source := source
		t.Run(source.SourceID, func(t *testing.T) {
			raw, err := os.ReadFile(source.Payload.CachePath)
			if errors.Is(err, os.ErrNotExist) {
				t.Skipf("traffic cache unavailable: %s", source.Payload.CachePath)
			}
			if err != nil {
				t.Fatalf("read traffic payload: %v", err)
			}
			decoded, err := decodeRuleSourceBody(raw)
			if err != nil {
				t.Fatalf("decode traffic payload: %v", err)
			}
			if rules := parseExternalRuleSource(source.SourceID, decoded); len(rules) == 0 {
				t.Fatal("production parser retained zero rules")
			}
		})
	}
}
