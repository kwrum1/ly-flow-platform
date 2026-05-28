package asset

import (
	"encoding/json"
	"testing"
)

func TestApplyHostMetadataProjectsCapabilities(t *testing.T) {
	metadata, err := json.Marshal(map[string]interface{}{
		"capabilities": map[string]interface{}{
			"schema_version": "lyflow.agent.capability.v1",
			"traffic_collector": map[string]interface{}{
				"active_engine":    "af_packet",
				"backend_status":   "fallback",
				"fallback_reason":  "full_ebpf_program_loader_not_implemented",
				"requested_engine": "ebpf",
			},
		},
		"performance": map[string]interface{}{
			"cpu_cores": float64(2),
			"load_avg":  []interface{}{float64(1)},
		},
		"interfaces":      []interface{}{map[string]interface{}{"name": "ens33", "state": "up"}},
		"listening_ports": []interface{}{map[string]interface{}{"port": float64(8080), "protocol": "tcp", "state": "listen"}},
		"process_count":   float64(7),
	})
	if err != nil {
		t.Fatal(err)
	}

	host := &Host{}
	applyHostMetadata(host, metadata)

	if host.Capabilities == nil {
		t.Fatal("Capabilities not projected from metadata")
	}
	traffic, ok := host.Capabilities["traffic_collector"].(map[string]interface{})
	if !ok {
		t.Fatalf("traffic_collector missing from capabilities: %+v", host.Capabilities)
	}
	if traffic["active_engine"] != "af_packet" || traffic["backend_status"] != "fallback" {
		t.Fatalf("unexpected traffic capability: %+v", traffic)
	}
	if host.CPUUsagePercent == nil {
		t.Fatal("performance projection regressed: CPUUsagePercent is nil")
	}
	if len(host.Interfaces) != 1 || len(host.ListeningPorts) != 1 || host.ProcessCount != 7 {
		t.Fatalf("topology projection missing: interfaces=%d ports=%d process_count=%d", len(host.Interfaces), len(host.ListeningPorts), host.ProcessCount)
	}
	if host.TopologyID == "" || host.MetricsFreshness == "" {
		t.Fatalf("topology_id/metrics_freshness missing: %#v", host)
	}
}

func TestApplyHostMetadataMissingOptionalProcessesDegradesGracefully(t *testing.T) {
	metadata, err := json.Marshal(map[string]interface{}{"interfaces": []interface{}{}})
	if err != nil {
		t.Fatal(err)
	}
	host := &Host{ID: "host-1"}
	applyHostMetadata(host, metadata)
	if host.ProcessCount != 0 {
		t.Fatalf("ProcessCount = %d, want 0", host.ProcessCount)
	}
	if host.TopologyID != "host:host-1" {
		t.Fatalf("TopologyID = %q", host.TopologyID)
	}
}
