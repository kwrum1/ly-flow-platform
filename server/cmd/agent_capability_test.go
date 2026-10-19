package main

import "testing"

func TestCapabilityEnabled(t *testing.T) {
	capabilities := map[string]interface{}{
		"traffic_collector":  map[string]interface{}{"enabled": true, "status": "active"},
		"runtime_sensor":     map[string]interface{}{"enabled": false, "status": "disabled"},
		"rasp_probe_manager": map[string]interface{}{"enabled": true, "status": "monitor"},
	}
	if enabled, present := capabilityEnabled(capabilities, "traffic_collector"); !enabled || !present {
		t.Fatal("traffic capability not detected")
	}
	if enabled, present := capabilityEnabled(capabilities, "runtime_sensor"); enabled || !present {
		t.Fatal("disabled runtime capability treated as enabled")
	}
	if enabled, present := capabilityEnabled(capabilities, "rasp_probe_manager"); !enabled || !present {
		t.Fatal("RASP capability not detected")
	}
	if enabled, present := capabilityEnabled(capabilities, "missing"); enabled || present {
		t.Fatal("missing capability treated as enabled")
	}
}
