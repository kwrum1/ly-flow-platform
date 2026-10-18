package graph

import (
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

func testEvent(uid, assetID string) contracts.EventV2 {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	return contracts.EventV2{
		SchemaVersion: contracts.SecurityEventSchemaV2,
		EventUID:      uid,
		TenantID:      "default",
		Source:        contracts.SourceAgentRuntime,
		EventType:     "process.exec",
		Timestamps:    contracts.EventTimestamps{EventAt: now, ObservedAt: now, IngestedAt: now},
		Entities: contracts.Entities{
			Asset:   &contracts.AssetEntity{ID: assetID, Hostname: "host-" + assetID},
			User:    &contracts.UserEntity{ID: "user-1", Name: "alice"},
			Process: &contracts.ProcessEntity{PID: 4242, Exe: "/usr/bin/bash"},
			File:    &contracts.FileEntity{Path: "/tmp/webshell.php", Hash: "deadbeef-" + assetID},
			Network: &contracts.NetworkEntity{SrcIP: "10.0.0.10", DstIP: "10.0.0.20", DstPort: 443},
			App:     &contracts.AppEntity{Host: "evil.example"},
		},
		Detection: contracts.Detection{Severity: contracts.SeverityHigh, Stage: contracts.StageExecution},
	}
}

func TestAddEventBuildsEntitiesAndEdges(t *testing.T) {
	graph := New()
	graph.AddEvent(testEvent("evt-1", "asset-1"))

	nodes := graph.Nodes()
	if len(nodes) < 6 {
		t.Fatalf("nodes = %+v", nodes)
	}
	inputs := make([]string, 0, len(nodes))
	for _, node := range nodes {
		inputs = append(inputs, node.ID)
	}
	for _, required := range []string{"asset:asset-1", "user:user-1", "file:deadbeef-asset-1", "ip:10.0.0.10", "ip:10.0.0.20", "domain:evil.example"} {
		found := false
		for _, id := range inputs {
			if id == required {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing node %s in %+v", required, inputs)
		}
	}
	if graph.EdgeCount() < 6 {
		t.Fatalf("edges = %d", graph.EdgeCount())
	}
}

func TestFindPathFromAssetToFile(t *testing.T) {
	graph := New()
	graph.AddEvent(testEvent("evt-1", "asset-1"))
	path, found := graph.FindPath("asset:asset-1", "file:deadbeef-asset-1", 6)
	if !found {
		t.Fatal("path not found")
	}
	if len(path) != 2 || path[0].Type != EdgeSpawn || path[1].Type != EdgeWrite {
		t.Fatalf("path = %+v", path)
	}
}

func TestFindPathFromUserToAsset(t *testing.T) {
	graph := New()
	graph.AddEvent(testEvent("evt-1", "asset-1"))
	path, found := graph.FindPath("user:user-1", "asset:asset-1", 2)
	if !found || len(path) != 1 || path[0].Type != EdgeLogin {
		t.Fatalf("path = %+v found=%v", path, found)
	}
}

func TestComponentsSeparateDisconnectedAssets(t *testing.T) {
	graph := New()
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	for _, assetID := range []string{"asset-1", "asset-2"} {
		graph.AddEvent(contracts.EventV2{
			SchemaVersion: contracts.SecurityEventSchemaV2,
			EventUID:      "evt-" + assetID,
			TenantID:      "default",
			Source:        contracts.SourceAgentRuntime,
			EventType:     "asset.snapshot",
			Timestamps:    contracts.EventTimestamps{EventAt: now, ObservedAt: now, IngestedAt: now},
			Entities:      contracts.Entities{Asset: &contracts.AssetEntity{ID: assetID}},
			Detection:     contracts.Detection{Severity: contracts.SeverityLow, Stage: contracts.StageUnknown},
		})
	}
	components := graph.Components()
	if len(components) != 2 {
		t.Fatalf("components = %+v", components)
	}
}

func TestDuplicateEventDoesNotDuplicateEdges(t *testing.T) {
	graph := New()
	event := testEvent("evt-1", "asset-1")
	graph.AddEvent(event)
	before := graph.EdgeCount()
	graph.AddEvent(event)
	if graph.EdgeCount() != before {
		t.Fatalf("edges changed from %d to %d", before, graph.EdgeCount())
	}
}
