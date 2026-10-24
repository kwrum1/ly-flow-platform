package main

import "testing"

func TestTrafficThreatFromXDREventKeepsAlertWithoutFlowEndpoints(t *testing.T) {
	event := map[string]interface{}{
		"category":           "traffic",
		"component_category": "traffic",
		"component_rule_id":  "et-open-2101990",
		"rule_name":          "GPL CHAT MSN user search",
		"severity":           "low",
		"event_type":         "component.alert",
	}
	threat := threatFromXDREvent(event, "traffic")
	if threat == nil {
		t.Fatal("traffic alert without src/dst flow endpoints must remain queryable from persistent storage")
	}
}
