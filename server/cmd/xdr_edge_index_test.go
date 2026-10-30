package main

import (
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

func edgeFixture() []*models.CanonicalEventV2 {
	base := time.Date(2026, 10, 29, 4, 0, 0, 0, time.UTC)
	at := func(minutes int) time.Time { return base.Add(time.Duration(minutes) * time.Minute) }
	return []*models.CanonicalEventV2{
		{EventUID: "e1", TenantID: "default", AgentID: "host-a", ActorIdentity: "user-1", NormalizedSrcIP: "10.0.0.1", VictimAsset: "host-a", EventType: "runtime.process", StageHint: "execution", ObservedAt: at(0)},
		{EventUID: "e2", TenantID: "default", AgentID: "host-a", ActorIdentity: "user-1", NormalizedSrcIP: "10.0.0.1", VictimAsset: "host-a", EventType: "runtime.process", StageHint: "execution", ObservedAt: at(1)},
		{EventUID: "e3", TenantID: "default", AgentID: "host-a", ActorIdentity: "user-2", NormalizedSrcIP: "10.0.0.2", VictimAsset: "host-a", EventType: "runtime.file", StageHint: "persistence", ObservedAt: at(2)},
		{EventUID: "e4", TenantID: "default", AgentID: "host-b", ActorIdentity: "user-1", NormalizedSrcIP: "10.0.0.3", VictimAsset: "host-b", EventType: "runtime.logon", StageHint: "credential_access", ObservedAt: at(3)},
		{EventUID: "e5", TenantID: "default", AgentID: "host-c", ActorIdentity: "user-9", NormalizedSrcIP: "10.0.0.1", VictimAsset: "host-c", EventType: "traffic.flow", StageHint: "lateral_movement", ObservedAt: at(4)},
		{EventUID: "e6", TenantID: "default", AgentID: "host-d", ActorIdentity: "user-9", NormalizedSrcIP: "10.0.0.4", VictimAsset: "host-d", EventType: "traffic.flow", StageHint: "lateral_movement", ObservedAt: at(5)},
		{EventUID: "e7", TenantID: "default", AgentID: "host-e", ActorIdentity: "user-9", NormalizedSrcIP: "10.0.0.5", VictimAsset: "host-e", EventType: "traffic.flow", StageHint: "execution", ObservedAt: at(6)},
		{EventUID: "e8", TenantID: "default", AgentID: "host-f", ActorIdentity: "user-8", NormalizedSrcIP: "10.0.0.6", VictimAsset: "shared-victim", EventType: "traffic.alert", StageHint: "detection", ObservedAt: at(7)},
		{EventUID: "e9", TenantID: "default", AgentID: "host-g", ActorIdentity: "user-7", NormalizedSrcIP: "10.0.0.7", VictimAsset: "shared-victim", EventType: "traffic.alert", StageHint: "detection", ObservedAt: at(8)},
		{EventUID: "e10", TenantID: "default", AgentID: "host-h", ActorIdentity: "user-6", NormalizedSrcIP: "10.0.0.8", VictimAsset: "host-h", EventType: "traffic.alert", StageHint: "detection", ObservedAt: at(300)},
		{EventUID: "e11", TenantID: "default", AgentID: "host-a", ActorIdentity: "user-1", NormalizedSrcIP: "10.0.0.9", VictimAsset: "host-a", EventType: "runtime.process", StageHint: "execution", ObservedAt: at(400)},
	}
}

func bruteForceEdges(events []*models.CanonicalEventV2) map[[2]int]string {
	out := map[[2]int]string{}
	for i := 0; i < len(events); i++ {
		for j := i + 1; j < len(events); j++ {
			if cand := classifyEdge(events[i], events[j]); cand != nil {
				out[[2]int{i, j}] = cand.edgeType
			}
		}
	}
	return out
}

func TestIndexedEdgePairsPreserveClassifiedEdges(t *testing.T) {
	events := edgeFixture()
	want := bruteForceEdges(events)

	pairs, truncated := indexedEdgePairs(events, defaultEdgeIndexConfig())
	if truncated != 0 {
		t.Fatalf("unexpected truncation: %d", truncated)
	}
	got := map[[2]int]string{}
	for _, pair := range pairs {
		if cand := classifyEdge(events[pair[0]], events[pair[1]]); cand != nil {
			got[pair] = cand.edgeType
		}
	}

	for pair, edgeType := range want {
		if got[pair] != edgeType {
			t.Fatalf("missing edge %v (%s); indexed pairs=%d", pair, edgeType, len(pairs))
		}
	}
	for pair := range got {
		if _, ok := want[pair]; !ok {
			t.Fatalf("indexed pair %v produced an edge brute force did not", pair)
		}
	}
	if len(got) == 0 {
		t.Fatal("fixture produced no edges, test is not meaningful")
	}
}

func TestIndexedEdgePairsRespectWindowForVictimEdges(t *testing.T) {
	base := time.Date(2026, 10, 29, 4, 0, 0, 0, time.UTC)
	a := &models.CanonicalEventV2{EventUID: "a", VictimAsset: "shared", StageHint: "detection", ObservedAt: base}
	b := &models.CanonicalEventV2{EventUID: "b", VictimAsset: "shared", StageHint: "detection", ObservedAt: base.Add(2 * time.Hour)}

	if pairs, _ := indexedEdgePairs([]*models.CanonicalEventV2{a, b}, edgeIndexConfig{Window: 30 * time.Minute, MaxPerKey: 256}); len(pairs) != 0 {
		t.Fatalf("victim pair outside window was admitted: %v", pairs)
	}

	b.ObservedAt = base.Add(10 * time.Minute)
	if pairs, _ := indexedEdgePairs([]*models.CanonicalEventV2{a, b}, edgeIndexConfig{Window: 30 * time.Minute, MaxPerKey: 256}); len(pairs) != 1 {
		t.Fatalf("victim pair inside window was dropped: %v", pairs)
	}
}

func TestIndexedEdgePairsReportTruncation(t *testing.T) {
	events := edgeFixture()
	_, truncated := indexedEdgePairs(events, edgeIndexConfig{Window: 2 * time.Hour, MaxPerKey: 1})
	if truncated == 0 {
		t.Fatal("expected truncation with MaxPerKey=1")
	}
}

func TestIndexedEdgePairsHandlesEmptyAndSingle(t *testing.T) {
	if pairs, truncated := indexedEdgePairs(nil, defaultEdgeIndexConfig()); pairs != nil || truncated != 0 {
		t.Fatalf("nil events: %v %d", pairs, truncated)
	}
	one := edgeFixture()[:1]
	if pairs, _ := indexedEdgePairs(one, defaultEdgeIndexConfig()); len(pairs) != 0 {
		t.Fatalf("single event produced %d pairs", len(pairs))
	}
}
