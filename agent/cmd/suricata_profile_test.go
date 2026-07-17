package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/lyflow/ly-flow-platform/contracts"
)

func TestSuricataProfileGoldenReplayNormalizesPinnedEVE(t *testing.T) {
	// Given
	fixturePath := filepath.Join("testdata", "suricata", suricataProfileVersion, "eve.jsonl")
	fixture, err := os.Open(fixturePath)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer fixture.Close()
	context := newSuricataProfileContext("agent-1", "sensor-1")
	records := make([]suricataProfileRecord, 0, len(suricataProfileCoverage))
	scanner := bufio.NewScanner(fixture)
	var offset int64

	// When
	for scanner.Scan() {
		line := bytes.Clone(scanner.Bytes())
		record, parseErr := parseSuricataProfileLine(line, context.withRaw(contracts.RawReference{Path: fixturePath, Offset: offset}))
		if parseErr != nil {
			t.Fatalf("parse fixture offset %d: %v", offset, parseErr)
		}
		records = append(records, record)
		offset += int64(len(line) + 1)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan fixture: %v", err)
	}
	actual, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		t.Fatalf("marshal normalized records: %v", err)
	}
	actual = append(actual, '\n')
	goldenPath := filepath.Join("testdata", "suricata", suricataProfileVersion, "canonical.golden.json")
	if os.Getenv("UPDATE_SURICATA_PROFILE_GOLDEN") == "1" {
		if err := os.WriteFile(goldenPath, actual, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}
	expected, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}

	// Then
	if !bytes.Equal(actual, expected) {
		t.Fatalf("normalized replay differs from golden\nactual:\n%s\nexpected:\n%s", actual, expected)
	}
}

func TestSuricataProfileDuplicateFlowAndAlertShareCorrelation(t *testing.T) {
	// Given
	lines := readSuricataFixtureLines(t)
	context := newSuricataProfileContext("agent-1", "sensor-1")
	var alertCorrelation string
	flowCorrelations := make(map[string]struct{})

	// When
	for offset, line := range lines {
		record, err := parseSuricataProfileLine(line, context)
		if err != nil {
			t.Fatalf("parse fixture line %d: %v", offset+1, err)
		}
		switch record.eventType() {
		case "alert":
			alertCorrelation = record.correlationID()
		case "network.flow":
			flowCorrelations[record.correlationID()] = struct{}{}
		}
	}

	// Then
	if alertCorrelation == "" {
		t.Fatal("fixture lacks alert correlation")
	}
	if _, ok := flowCorrelations[alertCorrelation]; !ok {
		t.Fatalf("no flow shares alert correlation %q", alertCorrelation)
	}
}

func TestSuricataProfileRejectsUnknownVersionAndUnsupportedProtocol(t *testing.T) {
	// Given
	context := newSuricataProfileContext("agent-1", "sensor-1")
	unknownVersion := []byte(`{"timestamp":"2026-07-13T10:00:00Z","flow_id":1,"event_type":"flow","suricata_version":"8.0.0","flow":{}}`)
	unsupported := []byte(`{"timestamp":"2026-07-13T10:00:00Z","flow_id":2,"event_type":"ssh","suricata_version":"7.0.11","ssh":{}}`)

	// When
	_, versionErr := parseSuricataProfileLine(unknownVersion, context)
	_, protocolErr := parseSuricataProfileLine(unsupported, context)

	// Then
	if !errors.Is(versionErr, errSuricataVersionDrift) {
		t.Fatalf("unknown version error = %v", versionErr)
	}
	if !errors.Is(protocolErr, errUnsupportedSuricataEventType) {
		t.Fatalf("unsupported protocol error = %v", protocolErr)
	}
}

func TestSuricataProfileCapabilityReportsTruthfulCoverage(t *testing.T) {
	// Given
	t.Setenv(suricataProfileEnabledEnv, "true")
	agent := NewAgent(&Config{})

	// When
	profile := agent.suricataProfileHealth()

	// Then
	coverage, ok := profile["coverage"].([]string)
	if !ok || len(coverage) != 5 {
		t.Fatalf("coverage = %#v", profile["coverage"])
	}
	for _, unsupported := range []string{"ssh", "smb", "kerberos"} {
		for _, supported := range coverage {
			if supported == unsupported {
				t.Fatalf("unsupported protocol %q claimed in coverage", unsupported)
			}
		}
	}
	if profile["engine_version"] != suricataProfileVersion || profile["native_schema"] != suricataProfileNativeSchema {
		t.Fatalf("pinned metadata missing: %#v", profile)
	}
}

func TestSuricataProfileDesiredStateIsOptionalAndPinned(t *testing.T) {
	// Given
	t.Setenv(suricataProfileEnabledEnv, "false")
	disabled := defaultEngineDesiredStatesFromConfig(&Config{})[0]
	t.Setenv(suricataProfileEnabledEnv, "true")

	// When
	enabled := defaultEngineDesiredStatesFromConfig(&Config{TrafficEnabled: false})[0]

	// Then
	if disabled.Enabled {
		t.Fatal("Suricata profile was enabled by default")
	}
	if !enabled.Enabled || enabled.ConfigVersion != suricataProfileNativeSchema || enabled.RulePackVersion != suricataProfileRulePack {
		t.Fatalf("enabled profile is not pinned: %+v", enabled)
	}
}

func readSuricataFixtureLines(t *testing.T) [][]byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "suricata", suricataProfileVersion, "eve.jsonl"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	trimmed := bytes.TrimSpace(data)
	return bytes.Split(trimmed, []byte{'\n'})
}
