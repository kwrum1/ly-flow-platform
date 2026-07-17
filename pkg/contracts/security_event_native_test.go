package contracts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/lyflow/ly-flow-platform/eventinventory"
)

type producerFixtureBinding struct {
	ProducerPath  string      `json:"producer_path"`
	FixtureSource EventSource `json:"fixture_source"`
}

func TestCanonicalEventSourceFixturesUseEveryNativeRecordShape(t *testing.T) {
	data, err := os.ReadFile("testdata/source-fixtures.json")
	if err != nil {
		t.Fatalf("read source fixtures: %v", err)
	}
	var fixtures []SourceFixture
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatalf("decode source fixtures: %v", err)
	}
	expected := map[EventSource]bool{
		SourceAgentTraffic: false, SourceAgentRuntime: false, SourceAgentLogAudit: false, SourceAgentRASP: false,
		SourceSuricata: false, SourceWazuh: false, SourceYARA: false, SourceDPIEngine: false,
		SourceSecurityEngine: false, SourceUnifiedLegacy: false, SourceXDRV2: false,
	}
	adapters := make(map[string]bool, len(fixtures))
	for _, fixture := range fixtures {
		if fixture.NativeSchema == "" {
			t.Fatalf("fixture %s has no native schema", fixture.Source)
		}
		if _, exists := expected[fixture.Source]; !exists {
			t.Fatalf("unexpected native fixture source %s", fixture.Source)
		}
		event, _, err := NormalizeFixture(fixture, PrincipalIdentity("agent-1"), migrationTestTime)
		if err != nil {
			t.Fatalf("normalize native fixture %s: %v", fixture.Source, err)
		}
		if event.Provenance.NativeSchema != fixture.NativeSchema || event.Provenance.Adapter == "contracts.v1SourceAdapter" {
			t.Fatalf("fixture %s used generic adapter: %+v", fixture.Source, event.Provenance)
		}
		expected[fixture.Source] = true
		adapters[event.Provenance.Adapter] = true
	}
	for source, covered := range expected {
		if !covered {
			t.Fatalf("native fixture source missing: %s", source)
		}
	}
	if len(adapters) < 8 {
		t.Fatalf("native fixtures collapsed into too few adapters: %v", adapters)
	}
}

func TestCanonicalEventNativeFixturesCoverEveryActiveProducerPath(t *testing.T) {
	repositoryRoot := filepath.Clean(filepath.Join("..", ".."))
	scannedInventory, err := eventinventory.Scan(repositoryRoot)
	if err != nil {
		t.Fatalf("scan active event paths: %v", err)
	}
	inventoryData, err := os.ReadFile(filepath.Join(repositoryRoot, "docs", "generated", "event-contract-inventory.json"))
	if err != nil {
		t.Fatalf("read generated inventory: %v", err)
	}
	var inventory struct {
		Entries []struct {
			Kind string `json:"kind"`
			Path string `json:"path"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(inventoryData, &inventory); err != nil {
		t.Fatalf("decode generated inventory: %v", err)
	}
	generatedProducers := make(map[string]bool)
	for _, entry := range inventory.Entries {
		if entry.Kind == "producer" {
			generatedProducers[filepath.ToSlash(entry.Path)] = false
		}
	}
	activeProducers := make(map[string]bool)
	for _, entry := range scannedInventory.Entries {
		if entry.Kind == "producer" {
			producerPath := filepath.ToSlash(entry.Path)
			activeProducers[producerPath] = false
			if _, exists := generatedProducers[producerPath]; !exists {
				t.Fatalf("generated inventory missing scanned producer path %s", producerPath)
			}
		}
	}
	for producerPath := range generatedProducers {
		if _, exists := activeProducers[producerPath]; !exists {
			t.Fatalf("generated inventory contains inactive producer path %s", producerPath)
		}
	}

	fixtureData, err := os.ReadFile("testdata/source-fixtures.json")
	if err != nil {
		t.Fatalf("read source fixtures: %v", err)
	}
	var fixtures []SourceFixture
	if err := json.Unmarshal(fixtureData, &fixtures); err != nil {
		t.Fatalf("decode source fixtures: %v", err)
	}
	fixturesBySource := make(map[EventSource]SourceFixture, len(fixtures))
	for _, fixture := range fixtures {
		fixturesBySource[fixture.Source] = fixture
	}

	manifestData, err := os.ReadFile("testdata/producer-native-fixtures.json")
	if err != nil {
		t.Fatalf("read producer fixture manifest: %v", err)
	}
	var bindings []producerFixtureBinding
	if err := json.Unmarshal(manifestData, &bindings); err != nil {
		t.Fatalf("decode producer fixture manifest: %v", err)
	}
	for _, binding := range bindings {
		covered, exists := activeProducers[binding.ProducerPath]
		if !exists {
			t.Fatalf("manifest contains inactive producer path %s", binding.ProducerPath)
		}
		if covered {
			t.Fatalf("manifest duplicates producer path %s", binding.ProducerPath)
		}
		fixture, exists := fixturesBySource[binding.FixtureSource]
		if !exists || fixture.NativeSchema == "" {
			t.Fatalf("producer %s references missing native fixture %s", binding.ProducerPath, binding.FixtureSource)
		}
		if _, _, err := NormalizeFixture(fixture, PrincipalIdentity("agent-1"), migrationTestTime); err != nil {
			t.Fatalf("normalize producer %s native fixture %s: %v", binding.ProducerPath, binding.FixtureSource, err)
		}
		activeProducers[binding.ProducerPath] = true
	}
	for producerPath, covered := range activeProducers {
		if !covered {
			t.Fatalf("active producer has no native fixture: %s", producerPath)
		}
	}
}
