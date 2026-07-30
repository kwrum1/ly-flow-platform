package main

import (
	"testing"

	"github.com/lyflow/ly-flow-platform/contracts"
)

func TestComponentAlertFromSuricataEVE(t *testing.T) {
	agent := NewAgent(&Config{})
	agent.agentID = "agent-1"
	agent.hostname = "endpoint-1"
	line := []byte(`{"timestamp":"2026-05-17T05:00:00.123456+0800","event_type":"alert","src_ip":"10.1.18.20","src_port":4444,"dest_ip":"10.1.18.30","dest_port":80,"proto":"TCP","community_id":"1:test","alert":{"action":"allowed","gid":1,"signature_id":2010935,"rev":3,"signature":"ET MALWARE Example","category":"trojan-activity","severity":2,"app_proto":"http"}}`)
	alert, ok, err := componentAlertFromSuricataEVE(line, agent, contracts.RawReference{Path: "/var/log/suricata/eve.json", Offset: 10})
	if err != nil || !ok {
		t.Fatalf("suricata adapter failed ok=%v err=%v", ok, err)
	}
	if alert.Category != contracts.TelemetryNetwork || alert.SourceEngine != contracts.SourceEngineSuricata {
		t.Fatalf("unexpected alert identity: %+v", alert)
	}
	if alert.RuleID != "1:2010935" || alert.NativeRule.Revision != "3" || alert.Entities.SourceIP != "10.1.18.20" {
		t.Fatalf("suricata fields not preserved: %+v", alert)
	}
}

func TestComponentAlertFromSuricataEVE_preservesContributingNativeRuleIdentity(t *testing.T) {
	line := []byte(`{"timestamp":"2026-05-17T05:00:00.123456+0800","event_type":"alert","src_ip":"10.1.18.20","src_port":4444,"dest_ip":"10.1.18.30","dest_port":80,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":990000000,"rev":1,"signature":"LYFLOW OISF Traffic ID flowbit witness","category":"misc-activity","severity":3,"metadata":{"source_id":["oisf-trafficid"],"native_sid":["300000000"],"native_revision":["1"],"witness_sid":["990000000"]}}}`)

	alert, ok, err := componentAlertFromSuricataEVE(line, NewAgent(&Config{}), contracts.RawReference{})
	if err != nil || !ok {
		t.Fatalf("Suricata contributing-rule adapter failed ok=%v err=%v", ok, err)
	}
	if alert.RuleID != "1:990000000" {
		t.Fatalf("emitting witness rule ID = %q, want 1:990000000", alert.RuleID)
	}
	if alert.NativeRule == nil || alert.NativeRule.ID != "300000000" || alert.NativeRule.Revision != "1" || alert.NativeRule.Source != "oisf-trafficid" {
		t.Fatalf("contributing native rule identity was not preserved: %+v", alert.NativeRule)
	}
	if alert.NativeRule.Attributes["metadata.witness_sid"] != "990000000" {
		t.Fatalf("witness SID metadata was not preserved: %+v", alert.NativeRule.Attributes)
	}
}

func TestComponentAlertFromSuricataEVENonAlert(t *testing.T) {
	_, ok, err := componentAlertFromSuricataEVE([]byte(`{"event_type":"flow"}`), nil, contracts.RawReference{})
	if err != nil || ok {
		t.Fatalf("non-alert should be skipped ok=%v err=%v", ok, err)
	}
}

func TestComponentAlertFromWazuh(t *testing.T) {
	alert, err := componentAlertFromWazuh(wazuhAlertInput{RuleID: "5710", RuleName: "sshd authentication failed", Level: 8, Decoder: "sshd", Location: "/var/log/auth.log", FullLog: "Failed password"}, NewAgent(&Config{}), contracts.RawReference{Path: "/var/ossec/logs/alerts/alerts.json"})
	if err != nil {
		t.Fatalf("wazuh adapter failed: %v", err)
	}
	if alert.Category != contracts.TelemetryHost || alert.SourceEngine != contracts.SourceEngineWazuh || alert.Severity != contracts.SeverityHigh {
		t.Fatalf("unexpected wazuh alert: %+v", alert)
	}
}

func TestComponentAlertFromYARA(t *testing.T) {
	alert, err := componentAlertFromYARA(yaraMatchInput{Rule: "webshell_php_eval", Namespace: "webshell", Tags: []string{"webshell"}, FilePath: "/var/www/html/shell.php", FileHash: "abc"}, NewAgent(&Config{}), contracts.RawReference{Path: "/opt/ly-agent/yara/last-scan.json"})
	if err != nil {
		t.Fatalf("yara adapter failed: %v", err)
	}
	if alert.Category != contracts.TelemetryArtifact || alert.SourceEngine != contracts.SourceEngineYARA || alert.RuleID != "webshell_php_eval" {
		t.Fatalf("unexpected yara alert: %+v", alert)
	}
}

func TestComponentAlertFromRASP(t *testing.T) {
	alert, err := componentAlertFromRASP(raspEventInput{RuleID: "rasp-command-exec", RuleName: "Command execution", HookType: "command_exec", Language: "java", Runtime: "jvm", Application: "orders", Evidence: "Runtime.exec curl"}, NewAgent(&Config{}), contracts.RawReference{Path: "/opt/ly-agent/rasp/events.jsonl"})
	if err != nil {
		t.Fatalf("rasp adapter failed: %v", err)
	}
	if alert.Category != contracts.TelemetryRASP || alert.SourceEngine != contracts.SourceEngineRASP || alert.Entities.Application != "orders" {
		t.Fatalf("unexpected rasp alert: %+v", alert)
	}
}

func TestCapabilityModelIncludesEngineSupervisors(t *testing.T) {
	agent := NewAgent(&Config{})
	model := agent.capabilityModel()
	engines := model["engine_supervisors"].(map[string]interface{})
	for _, name := range []string{"suricata", "wazuh", "yara", "rasp"} {
		if _, ok := engines[name]; !ok {
			t.Fatalf("engine supervisor %s missing from capability: %+v", name, engines)
		}
	}
}
