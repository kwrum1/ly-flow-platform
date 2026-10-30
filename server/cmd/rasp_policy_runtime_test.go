package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	shared "github.com/lyflow/ly-flow-platform/rasppolicy"
	"github.com/lyflow/ly-flow-platform/server/agentpolicy"
)

func TestValidateLegacyRASPEnvironment_rejects_blocking_values(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "block default", key: "RASP_BLOCK_BY_DEFAULT", value: "true"},
		{name: "block on hit", key: "RASP_BLOCK_ON_HIT", value: "true"},
		{name: "protect mode", key: "RASP_MODE", value: "protect"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			t.Setenv(test.key, test.value)

			// When
			err := validateLegacyRASPEnvironment()

			// Then
			if !errors.Is(err, errLegacyRASPConflict) {
				t.Fatalf("error = %v, want errLegacyRASPConflict", err)
			}
		})
	}
}

func TestRASPRuntimeLanguages_reads_only_declared_probe_capabilities(t *testing.T) {
	// Given
	capabilities := map[string]interface{}{
		"rasp_probe_manager": map[string]interface{}{"languages": []interface{}{"python"}},
	}

	// When
	languages := raspRuntimeLanguages(capabilities)

	// Then
	if len(languages) != 1 || languages[0] != shared.LanguagePython {
		t.Fatalf("languages = %#v, want python", languages)
	}
	if got := raspRuntimeLanguages(map[string]interface{}{"rasp_probe_manager": map[string]interface{}{"python": "label-only"}}); len(got) != 0 {
		t.Fatalf("undeclared language labels were treated as capabilities: %#v", got)
	}
}

func TestRASPProtectionHTTP_rejects_legacy_block_activation(t *testing.T) {
	// Given
	body, err := json.Marshal(map[string]interface{}{"agent_id": "agent-1", "block_mode": true})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/rasp/protection/enable", bytes.NewReader(body))

	// When
	raspEnableProtectionHandler(&Config{}).ServeHTTP(recorder, request)

	// Then
	if recorder.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestRASPPolicyConfig_enables_block_on_hit_only_when_promoted(t *testing.T) {
	// Given
	policy := agentpolicy.Policy{Mode: agentpolicy.ModeBlock, Version: 7}

	// When
	dryRun := raspPolicyConfig(policy, false)
	enforcing := raspPolicyConfig(policy, true)

	// Then
	if dryRun["mode"] != agentpolicy.ModeBlock || dryRun["block_on_hit"] != false || dryRun["version"] != uint64(7) {
		t.Fatalf("dry-run config = %#v", dryRun)
	}
	if enforcing["block_on_hit"] != true {
		t.Fatalf("enforcing config = %#v", enforcing)
	}
}
