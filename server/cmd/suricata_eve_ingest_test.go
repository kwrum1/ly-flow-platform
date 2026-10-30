package main

import (
	"encoding/json"
	"testing"
)

const testSuricataAlertLine = `{"timestamp":"2026-10-30T04:00:06.756666+0000","flow_id":12345,"event_type":"alert","src_ip":"10.1.0.4","src_port":50655,"dest_ip":"223.6.6.6","dest_port":53,"proto":"UDP","app_proto":"dns","alert":{"signature_id":1000050,"signature":"ET TROJAN High DNS Query Count Possible Tunnel","severity":2},"dns":{"queries":[{"rrname":"example.test"}]}}`

func TestSuricataAlertUIDStable(t *testing.T) {
	var event map[string]interface{}
	if err := json.Unmarshal([]byte(testSuricataAlertLine), &event); err != nil {
		t.Fatal(err)
	}
	first := suricataAlertUID(event)
	second := suricataAlertUID(event)
	if first != second {
		t.Fatalf("uid not stable: %s != %s", first, second)
	}
	if len(first) != len("suricata-")+24 || first[:9] != "suricata-" {
		t.Fatalf("unexpected uid %q", first)
	}
}

func TestSuricataSeverity(t *testing.T) {
	tests := map[int]string{1: "high", 2: "medium", 3: "low", 0: "medium", 9: "medium"}
	for input, want := range tests {
		if got := suricataSeverity(input); got != want {
			t.Fatalf("suricataSeverity(%d)=%q want %q", input, got, want)
		}
	}
}

func TestSanitizeSuricataAlert(t *testing.T) {
	var event map[string]interface{}
	if err := json.Unmarshal([]byte(testSuricataAlertLine), &event); err != nil {
		t.Fatal(err)
	}
	out := sanitizeSuricataAlert(event, "sig", "medium")
	if out["source_engine"] != "suricata" || out["category"] != "traffic" || out["src_ip"] != "10.1.0.4" {
		t.Fatalf("unexpected sanitized alert: %#v", out)
	}
	if out["dns"] == nil {
		t.Fatal("dns payload should be retained")
	}
}

func TestSuricataSignatureSeverity(t *testing.T) {
	cases := map[string]string{
		"ET POLICY Vulnerable Java Version 1.8.x Detected": "low",
		"ET INFO TLS Handshake Failure":                     "low",
		"ET HUNTING ZIP file exfiltration over raw TCP":     "low",
		"ET DNS Query for .cc TLD":                          "low",
		"ET WEB_SERVER Possible SQL Injection (exec)":       "high",
		"ET EXPLOIT Apache Struts OGNL":                     "high",
	}
	for signature, want := range cases {
		if got := suricataSignatureSeverity(signature, "high"); got != want {
			t.Fatalf("suricataSignatureSeverity(%q)=%q, want %q", signature, got, want)
		}
	}
}

func TestSanitizeSuricataAlertCarriesSignatureIdentity(t *testing.T) {
	event := map[string]interface{}{
		"timestamp": "2026-10-30T17:02:01.429503+0000",
		"src_ip":    "10.1.1.181",
		"dest_ip":   "113.194.3.11",
		"src_port":  float64(55214),
		"dest_port": float64(80),
		"proto":     "TCP",
		"alert": map[string]interface{}{
			"signature_id": float64(2008518),
			"signature":    "ET EXPLOIT SQL sp_configure attempt",
			"category":     "Attempted Administrator Privilege Gain",
			"severity":     float64(1),
		},
	}
	out := sanitizeSuricataAlert(event, "ET EXPLOIT SQL sp_configure attempt", "high")
	if got := out["component_rule_id"]; got != "2008518" {
		t.Fatalf("component_rule_id=%v", got)
	}
	if got := out["rule_id"]; got != 2008518 {
		t.Fatalf("rule_id=%v", got)
	}
	if got := out["rule_family"]; got != "ET EXPLOIT" {
		t.Fatalf("rule_family=%v", got)
	}
	if got := out["classtype"]; got != "Attempted Administrator Privilege Gain" {
		t.Fatalf("classtype=%v", got)
	}
}
