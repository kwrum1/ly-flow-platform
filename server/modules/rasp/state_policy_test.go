package rasp

import (
	"testing"
	"time"
)

func TestResolveProtectionStateNeverInflates(t *testing.T) {
	now := time.Date(2026, 10, 29, 6, 0, 0, 0, time.UTC)
	cases := []struct {
		name  string
		facts StateFacts
		want  string
	}{
		{"no agent", StateFacts{Now: now}, StateNotInstalled},
		{"agent without probe", StateFacts{AgentPresent: true, Now: now}, StateInstalled},
		{"probe without telemetry", StateFacts{AgentPresent: true, ProbeReported: true, Now: now}, StateCollecting},
		{"telemetry monitor only", StateFacts{AgentPresent: true, ProbeReported: true, EventsObserved: true, ProtectionEnabled: true, Now: now}, StateDetecting},
		{
			"blocking requires signed policy",
			StateFacts{AgentPresent: true, ProbeReported: true, EventsObserved: true, ProtectionEnabled: true,
				BlockMode: true, PolicySigned: false, Now: now},
			StateDetecting,
		},
		{
			"blocking requires unexpired policy",
			StateFacts{AgentPresent: true, ProbeReported: true, EventsObserved: true, ProtectionEnabled: true,
				BlockMode: true, PolicySigned: true, PolicyExpiresAt: now.Add(-time.Minute), Now: now},
			StateDetecting,
		},
		{
			"blocking with full facts",
			StateFacts{AgentPresent: true, ProbeReported: true, EventsObserved: true, ProtectionEnabled: true,
				BlockMode: true, PolicySigned: true, PolicyExpiresAt: now.Add(time.Hour), Now: now},
			StateBlocking,
		},
		{
			"emergency stop downgrades blocking",
			StateFacts{AgentPresent: true, ProbeReported: true, EventsObserved: true, ProtectionEnabled: true,
				BlockMode: true, PolicySigned: true, PolicyExpiresAt: now.Add(time.Hour), EmergencyStop: true, Now: now},
			StateDetecting,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := ResolveProtectionState(testCase.facts)
			if got.State != testCase.want {
				t.Fatalf("state = %s (%s), want %s", got.State, got.Reason, testCase.want)
			}
			if got.Reason == "" {
				t.Fatal("state must carry a reason")
			}
		})
	}
}

func TestBlockPolicyFailsSafe(t *testing.T) {
	now := time.Date(2026, 10, 29, 6, 0, 0, 0, time.UTC)

	monitor := BlockPolicy{Mode: BlockModeMonitor, PolicySigned: true, PolicyExpiresAt: now.Add(time.Hour)}
	if decision := monitor.Decide(now, true); decision.Block || decision.WouldBlock || decision.Reason != "mode_monitor" {
		t.Fatalf("monitor decision = %+v", decision)
	}

	dryRun := BlockPolicy{Mode: BlockModeDryRun, PolicySigned: true, PolicyExpiresAt: now.Add(time.Hour)}
	decision := dryRun.Decide(now, true)
	if decision.Block || !decision.WouldBlock || decision.Reason != "dry_run_would_block" {
		t.Fatalf("dry-run decision = %+v", decision)
	}

	enforce := BlockPolicy{Mode: BlockModeEnforce, PolicySigned: true, PolicyExpiresAt: now.Add(time.Hour)}
	if decision := enforce.Decide(now, true); !decision.Block || decision.FailSafe {
		t.Fatalf("enforce decision = %+v", decision)
	}

	unsigned := BlockPolicy{Mode: BlockModeEnforce, PolicySigned: false, PolicyExpiresAt: now.Add(time.Hour)}
	if decision := unsigned.Decide(now, true); decision.Block || !decision.FailSafe || decision.Reason != "unsigned_policy" {
		t.Fatalf("unsigned policy did not fail safe: %+v", decision)
	}

	expired := BlockPolicy{Mode: BlockModeEnforce, PolicySigned: true, PolicyExpiresAt: now.Add(-time.Minute)}
	if decision := expired.Decide(now, true); decision.Block || !decision.FailSafe || decision.Reason != "policy_expired" {
		t.Fatalf("expired policy did not fail safe: %+v", decision)
	}

	emergency := BlockPolicy{Mode: BlockModeEnforce, PolicySigned: true, PolicyExpiresAt: now.Add(time.Hour), EmergencyStop: true}
	if decision := emergency.Decide(now, true); decision.Block || !decision.FailSafe || decision.Reason != "emergency_stop" {
		t.Fatalf("emergency stop did not fail safe: %+v", decision)
	}

	disabled := enforce.Decide(now, false)
	if disabled.Block || disabled.Reason != "agent_not_protected" {
		t.Fatalf("disabled agent decision = %+v", disabled)
	}

	unknown := BlockPolicy{Mode: "bogus", PolicySigned: true, PolicyExpiresAt: now.Add(time.Hour)}
	if decision := unknown.Decide(now, true); decision.Block || decision.Mode != BlockModeMonitor {
		t.Fatalf("unknown mode must degrade to monitor: %+v", decision)
	}
}

func TestNormalizeEventMapDoesNotInventLanguage(t *testing.T) {
	event := NormalizeEventMap(map[string]interface{}{"type": "sql_injection", "blocked": false})
	if event["language"] != "unknown" {
		t.Fatalf("language = %v, must not claim a concrete runtime", event["language"])
	}
	if event["language_known"] != false {
		t.Fatalf("language_known = %v", event["language_known"])
	}
	if event["runtime_schema_version"] != RuntimeSchemaVersion {
		t.Fatalf("runtime schema version = %v", event["runtime_schema_version"])
	}
}

func TestNormalizeEventMapKeepsReportedLanguage(t *testing.T) {
	event := NormalizeEventMap(map[string]interface{}{
		"type": "sqli", "language": "java", "app": "shop", "request_path": "/api/orders",
		"call_stack": []interface{}{
			map[string]interface{}{"module": "com.shop.OrderDao", "function": "find", "file": "OrderDao.java", "line": float64(42)},
			map[string]interface{}{"module": "", "function": "", "file": ""},
		},
	})
	context, ok := event["runtime_context"].(RuntimeContext)
	if !ok {
		t.Fatalf("runtime context missing: %T", event["runtime_context"])
	}
	if !context.LanguageKnown || context.Language != "java" || !context.AppKnown {
		t.Fatalf("context = %+v", context)
	}
	if len(context.CallStack) != 1 || context.CallStack[0].Line != 42 {
		t.Fatalf("call stack = %+v", context.CallStack)
	}
	if context.SchemaVersion != RuntimeSchemaVersion {
		t.Fatalf("schema = %q", context.SchemaVersion)
	}
}

func TestNormalizeRuntimeContextListsMissingFields(t *testing.T) {
	context := NormalizeRuntimeContext(map[string]interface{}{"language": "php"})
	if !context.LanguageKnown || context.AppKnown {
		t.Fatal("app must not be reported as known")
	}
	missing := map[string]bool{}
	for _, field := range context.MissingFields {
		missing[field] = true
	}
	for _, want := range []string{"app", "call_stack", "entrypoint", "request_path", "runtime_version"} {
		if !missing[want] {
			t.Fatalf("missing field %q not listed: %+v", want, context.MissingFields)
		}
	}
	if missing["language"] {
		t.Fatal("reported language was marked missing")
	}
}
