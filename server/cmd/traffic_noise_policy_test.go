package main

import "testing"

func TestTrafficNoisePolicyDisablesGPLNETBIOSByDefault(t *testing.T) {
	event := map[string]interface{}{
		"category":          "traffic",
		"component_rule_id": "et-open-2103018",
		"rule_name":         "GPL NETBIOS SMB NT Trans NT CREATE oversized Security Descriptor attempt",
		"severity":          "medium",
	}
	if !shouldSuppressTrafficNoiseEvent(event) {
		t.Fatal("GPL NETBIOS SMB NT Trans NT must be disabled from first install")
	}
}

func TestTrafficNoisePolicyKeepsCredibleTrafficDetections(t *testing.T) {
	event := map[string]interface{}{
		"category":          "traffic",
		"component_rule_id": "et-open-2024001",
		"rule_name":         "ET EXPLOIT Possible SMB exploit attempt",
		"severity":          "high",
	}
	if shouldSuppressTrafficNoiseEvent(event) {
		t.Fatal("credible traffic detections must not be hidden by the NETBIOS noise policy")
	}
}
