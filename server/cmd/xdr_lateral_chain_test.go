package main

import "testing"

func TestXDRChainAllowsSingleInternalLateralTrafficEvent(t *testing.T) {
	event := map[string]interface{}{
		"category":   "traffic",
		"src_ip":     "10.1.1.181",
		"dst_ip":     "10.1.18.253",
		"severity":   "medium",
		"rule_name":  "ET WEB_SPECIFIC_APPS ClarkConnect Linux proxy.php XSS Attempt",
		"event_type": "component.alert",
	}
	row := &xdrChainAgg{Events: []map[string]interface{}{event}}
	if !xdrChainIsCorrelated(row) {
		t.Fatal("single internal exploit attempt should enter the attack chain")
	}
}

func TestXDRChainDoesNotPromoteSingleExternalNoise(t *testing.T) {
	event := map[string]interface{}{
		"category":  "traffic",
		"src_ip":    "203.0.113.10",
		"dst_ip":    "10.1.18.253",
		"severity":  "medium",
		"rule_name": "GPL POLICY PCAnywhere server response",
	}
	row := &xdrChainAgg{Events: []map[string]interface{}{event}}
	if xdrChainIsCorrelated(row) {
		t.Fatal("single external non-lateral noise must not create an attack chain")
	}
}
