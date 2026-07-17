package contracts

import (
	"encoding/json"
	"os"
	"testing"
)

func TestEventContractInventoryCoversEveryPath(t *testing.T) {
	data, err := os.ReadFile("../../docs/generated/event-contract-inventory.json")
	if err != nil {
		t.Fatalf("read inventory: %v", err)
	}
	var inventory struct {
		CanonicalSchema      string `json:"canonical_schema"`
		RetirementDependency string `json:"retirement_dependency"`
		Entries              []struct {
			ID      string   `json:"id"`
			Kind    string   `json:"kind"`
			Path    string   `json:"path"`
			Roles   []string `json:"roles"`
			Owner   string   `json:"owner"`
			Schemas []string `json:"schemas"`
			Phases  []string `json:"phases"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(data, &inventory); err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	if inventory.CanonicalSchema != SecurityEventSchemaVersion || inventory.RetirementDependency == "" {
		t.Fatalf("inventory contract metadata incomplete: %+v", inventory)
	}
	covered := make(map[string]bool, len(inventory.Entries))
	kinds := make(map[string]bool)
	for _, entry := range inventory.Entries {
		if entry.ID == "" || entry.Kind == "" || entry.Path == "" || entry.Owner == "" || len(entry.Roles) == 0 || len(entry.Schemas) == 0 || len(entry.Phases) == 0 {
			t.Fatalf("incomplete inventory entry: %+v", entry)
		}
		covered[entry.Path] = true
		kinds[entry.Kind] = true
	}
	for _, kind := range []string{"producer", "consumer", "stream", "persistence", "adapter", "schema", "observer"} {
		if !kinds[kind] {
			t.Fatalf("inventory missing contract kind %s", kind)
		}
	}
	for _, path := range []string{
		"agent/cmd/main.go", "agent/cmd/engine_adapters.go", "agent/cmd/engine_runtime.go", "agent/cmd/suricata_adapter.go",
		"security-engine/engine/engine.go", "security-engine/engine/bundle.go", "pkg/contracts/contracts.go",
		"pkg/contracts/event_migration_observe.go",
		"server/unified/schema.go", "server/unified/event.go", "server/consumer/consumer.go", "server/consumer/unified.go",
		"server/xdr/xdr.go", "server/xdr/models/v2_event.go", "server/cmd/main.go", "server/cmd/xdr_v2_normalizer.go",
	} {
		if !covered[path] {
			t.Fatalf("inventory missing mapped path %s", path)
		}
	}
}
