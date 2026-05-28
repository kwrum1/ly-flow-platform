package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/lyflow/ly-flow-platform/contracts"
)

func TestConsumeSuricataEVEFilePublishesAlerts(t *testing.T) {
	received := make(chan contracts.ComponentAlert, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/component-alert" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		var alert contracts.ComponentAlert
		if err := json.NewDecoder(r.Body).Decode(&alert); err != nil {
			t.Fatalf("decode alert: %v", err)
		}
		received <- alert
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 0})
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "eve.json")
	content := `{"timestamp":"2026-05-17T05:00:00.123456+0800","event_type":"flow"}` + "\n" +
		`{"timestamp":"2026-05-17T05:00:01.123456+0800","event_type":"alert","src_ip":"10.1.18.20","src_port":4444,"dest_ip":"10.1.18.30","dest_port":80,"proto":"TCP","community_id":"1:test","alert":{"action":"allowed","gid":1,"signature_id":2010935,"rev":3,"signature":"ET MALWARE Example","category":"trojan-activity","severity":2,"app_proto":"http"}}` + "\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write eve: %v", err)
	}

	agent := NewAgent(&Config{API: server.URL})
	agent.agentID = "agent-1"
	agent.hostname = "endpoint-1"
	next, err := agent.consumeSuricataEVEFile(path, 0)
	if err != nil {
		t.Fatalf("consume eve: %v", err)
	}
	if next <= 0 {
		t.Fatalf("next offset = %d", next)
	}

	select {
	case alert := <-received:
		if alert.SourceEngine != contracts.SourceEngineSuricata || alert.Category != contracts.TelemetryNetwork || alert.Entities.AgentID != "agent-1" {
			t.Fatalf("unexpected alert: %+v", alert)
		}
	default:
		t.Fatal("expected one published alert")
	}
}

func TestConsumeSuricataEVEFileResetsOffsetAfterRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	if err := os.WriteFile(path, []byte(`{"event_type":"flow"}`+"\n"), 0644); err != nil {
		t.Fatalf("write eve: %v", err)
	}
	agent := NewAgent(&Config{API: "http://127.0.0.1:1"})
	next, err := agent.consumeSuricataEVEFile(path, 9999)
	if err != nil {
		t.Fatalf("consume eve: %v", err)
	}
	if next == 9999 {
		t.Fatal("offset did not reset after rotation/truncation")
	}
}

func TestConsumeEngineJSONLineAlertFilePublishesWazuhYARARASP(t *testing.T) {
	received := make(chan contracts.ComponentAlert, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var alert contracts.ComponentAlert
		if err := json.NewDecoder(r.Body).Decode(&alert); err != nil {
			t.Fatalf("decode alert: %v", err)
		}
		received <- alert
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 0})
	}))
	defer server.Close()

	agent := NewAgent(&Config{API: server.URL})
	agent.agentID = "agent-1"
	agent.hostname = "endpoint-1"

	wazuhPath := filepath.Join(t.TempDir(), "alerts.json")
	if err := os.WriteFile(wazuhPath, []byte(`{"timestamp":"2026-05-17T05:00:00Z","rule":{"id":"5710","level":8,"description":"sshd failed auth"},"decoder":{"name":"sshd"},"location":"/var/log/auth.log","full_log":"Failed password"}`+"\n"), 0644); err != nil {
		t.Fatalf("write wazuh: %v", err)
	}
	_, err := agent.consumeJSONLineAlertFile(EngineWazuh, wazuhPath, 0, func(values map[string]interface{}, raw contracts.RawReference) (contracts.ComponentAlert, bool, error) {
		alert, err := componentAlertFromWazuh(wazuhAlertInput{RuleID: jsonString(values, "rule.id"), RuleName: jsonString(values, "rule.description"), Level: jsonInt(values, "rule.level"), Decoder: jsonString(values, "decoder.name"), Location: jsonString(values, "location"), FullLog: jsonString(values, "full_log"), Timestamp: jsonTime(values, "timestamp")}, agent, raw)
		return alert, err == nil, err
	})
	if err != nil {
		t.Fatalf("consume wazuh: %v", err)
	}

	yaraPath := filepath.Join(t.TempDir(), "last-scan.json")
	if err := os.WriteFile(yaraPath, []byte(`{"rule":"webshell_php_eval","namespace":"webshell","file_path":"/var/www/shell.php","file_hash":"abc","tags":["webshell"]}`+"\n"), 0644); err != nil {
		t.Fatalf("write yara: %v", err)
	}
	_, err = agent.consumeJSONLineAlertFile(EngineYARA, yaraPath, 0, func(values map[string]interface{}, raw contracts.RawReference) (contracts.ComponentAlert, bool, error) {
		alert, err := componentAlertFromYARA(yaraMatchInput{Rule: jsonString(values, "rule"), Namespace: jsonString(values, "namespace"), Tags: jsonStringSlice(values["tags"]), FilePath: jsonString(values, "file_path"), FileHash: jsonString(values, "file_hash")}, agent, raw)
		return alert, err == nil, err
	})
	if err != nil {
		t.Fatalf("consume yara: %v", err)
	}

	raspPath := filepath.Join(t.TempDir(), "events.jsonl")
	if err := os.WriteFile(raspPath, []byte(`{"rule_id":"rasp_sql_001","rule_name":"SQL injection","hook_type":"sql","language":"nodejs","application":"shop","evidence":"select * from users where id='1 or 1=1'"}`+"\n"), 0644); err != nil {
		t.Fatalf("write rasp: %v", err)
	}
	_, err = agent.consumeJSONLineAlertFile(EngineRASP, raspPath, 0, func(values map[string]interface{}, raw contracts.RawReference) (contracts.ComponentAlert, bool, error) {
		alert, err := componentAlertFromRASP(raspEventInput{RuleID: jsonString(values, "rule_id"), RuleName: jsonString(values, "rule_name"), HookType: jsonString(values, "hook_type"), Language: jsonString(values, "language"), Application: jsonString(values, "application"), Evidence: jsonString(values, "evidence")}, agent, raw)
		return alert, err == nil, err
	})
	if err != nil {
		t.Fatalf("consume rasp: %v", err)
	}

	seen := map[contracts.SourceEngine]bool{}
	for i := 0; i < 3; i++ {
		select {
		case alert := <-received:
			seen[alert.SourceEngine] = true
		default:
			t.Fatalf("expected alert %d", i+1)
		}
	}
	for _, engine := range []contracts.SourceEngine{contracts.SourceEngineWazuh, contracts.SourceEngineYARA, contracts.SourceEngineRASP} {
		if !seen[engine] {
			t.Fatalf("missing %s alert, seen=%v", engine, seen)
		}
	}
}
