package eventinventory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestGeneratedInventoryMatchesEveryScannedActivePath(t *testing.T) {
	repositoryRoot := filepath.Clean(filepath.Join("..", ".."))
	actual, err := Scan(repositoryRoot)
	if err != nil {
		t.Fatalf("scan active event paths: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(repositoryRoot, "docs", "generated", "event-contract-inventory.json"))
	if err != nil {
		t.Fatalf("read generated inventory: %v", err)
	}
	var expected Inventory
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatalf("decode generated inventory: %v", err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("generated inventory is stale: scanned=%d generated=%d; run go run ./cmd/generate-event-inventory", len(actual.Entries), len(expected.Entries))
	}
}

func TestGeneratedInventoryIncludesAllRequiredKindsAndActiveBlockers(t *testing.T) {
	inventory, err := Scan(filepath.Clean(filepath.Join("..", "..")))
	if err != nil {
		t.Fatalf("scan active event paths: %v", err)
	}
	kinds := make(map[string]bool)
	paths := make(map[string]bool)
	for _, entry := range inventory.Entries {
		kinds[entry.Kind] = true
		paths[entry.Path] = true
		if len(entry.Symbols) == 0 {
			t.Fatalf("inventory entry has no real symbol: %+v", entry)
		}
		if _, err := os.Stat(filepath.Join("..", "..", entry.Path)); err != nil {
			t.Fatalf("inventory path does not exist: %s", entry.Path)
		}
	}
	for _, kind := range []string{"producer", "consumer", "stream", "persistence", "adapter", "schema", "observer"} {
		if !kinds[kind] {
			t.Fatalf("inventory missing scanned kind %s", kind)
		}
	}
	for _, path := range []string{"server/cmd/ingestion_auth.go", "server/cmd/event_migration_reader.go"} {
		if !paths[path] {
			t.Fatalf("inventory missing active blocker path %s", path)
		}
	}
}
