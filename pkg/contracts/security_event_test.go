package contracts

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

var migrationTestTime = time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)

func TestCanonicalEventNormalizesEverySourceFixture(t *testing.T) {
	fixtures := []SourceFixture{
		fixture(SourceAgentTraffic, `{"event_id":"flow-1","agent_id":"agent-1","event_type":"traffic.flow","event_at":"2026-07-13T09:59:00Z","observed_at":"2026-07-13T09:59:01Z","severity":"medium"}`),
		fixture(SourceAgentRuntime, `{"event_id":"runtime-1","agent_id":"agent-1","event_type":"runtime.process","event_at":"2026-07-13T09:59:00Z","observed_at":"2026-07-13T09:59:01Z","severity":"high"}`),
		fixture(SourceAgentLogAudit, `{"event_id":"log-1","agent_id":"agent-1","event_type":"log.audit","event_at":"2026-07-13T09:59:00Z","observed_at":"2026-07-13T09:59:01Z","severity":"low"}`),
		fixture(SourceAgentRASP, `{"event_id":"rasp-1","agent_id":"agent-1","event_type":"rasp.sql","event_at":"2026-07-13T09:59:00Z","observed_at":"2026-07-13T09:59:01Z","severity":"critical"}`),
		fixture(SourceSuricata, `{"event_id":"suricata-1","agent_id":"agent-1","event_type":"network.signature","event_at":"2026-07-13T09:59:00Z","observed_at":"2026-07-13T09:59:01Z","severity":"high"}`),
		fixture(SourceWazuh, `{"event_id":"wazuh-1","agent_id":"agent-1","event_type":"host.rule","event_at":"2026-07-13T09:59:00Z","observed_at":"2026-07-13T09:59:01Z","severity":"high"}`),
		fixture(SourceYARA, `{"event_id":"yara-1","agent_id":"agent-1","event_type":"artifact.match","event_at":"2026-07-13T09:59:00Z","observed_at":"2026-07-13T09:59:01Z","severity":"medium"}`),
		fixture(SourceSecurityEngine, `{"event_id":"engine-1","agent_id":"agent-1","event_type":"component.alert","event_at":"2026-07-13T09:59:00Z","observed_at":"2026-07-13T09:59:01Z","severity":"high"}`),
		fixture(SourceUnifiedLegacy, `{"event_id":"unified-1","agent_id":"agent-1","event_type":"xdr.event","event_at":"2026-07-13T09:59:00Z","observed_at":"2026-07-13T09:59:01Z","severity":"high"}`),
		fixture(SourceXDRV2, `{"event_id":"xdr-1","agent_id":"agent-1","event_type":"xdr.graph","event_at":"2026-07-13T09:59:00Z","observed_at":"2026-07-13T09:59:01Z","severity":"critical"}`),
	}

	for _, input := range fixtures {
		t.Run(string(input.Source), func(t *testing.T) {
			event, warnings, err := NormalizeFixture(input, PrincipalIdentity("agent-1"), migrationTestTime)
			if err != nil {
				t.Fatalf("normalize fixture: %v", err)
			}
			if len(warnings) != 0 {
				t.Fatalf("unexpected warnings: %v", warnings)
			}
			if event.SchemaVersion != SecurityEventSchemaVersion || event.Identity.PrincipalID != "agent-1" {
				t.Fatalf("unexpected canonical event: %+v", event)
			}
			encoded, err := MarshalCanonical(event)
			if err != nil || !json.Valid(encoded) {
				t.Fatalf("invalid canonical JSON: %s (%v)", encoded, err)
			}
		})
	}
}

func TestCanonicalEventPrincipalPrecedence(t *testing.T) {
	matching := fixture(SourceAgentRuntime, `{"event_id":"runtime-1","agent_id":"agent-1","event_type":"runtime.process","event_at":"2026-07-13T09:59:00Z","observed_at":"2026-07-13T09:59:01Z","severity":"high"}`)
	event, _, err := NormalizeFixture(matching, PrincipalIdentity("agent-1"), migrationTestTime)
	if err != nil || event.Identity.PrincipalID != "agent-1" {
		t.Fatalf("principal did not bind identity: %+v (%v)", event.Identity, err)
	}

	conflicting := fixture(SourceAgentRuntime, `{"event_id":"runtime-1","agent_id":"payload-agent","event_type":"runtime.process","event_at":"2026-07-13T09:59:00Z","observed_at":"2026-07-13T09:59:01Z","severity":"high"}`)
	_, _, err = NormalizeFixture(conflicting, PrincipalIdentity("principal-agent"), migrationTestTime)
	if !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("expected identity conflict quarantine, got %v", err)
	}
}

func TestCanonicalEventGovernanceRedactsAndAuthorizes(t *testing.T) {
	input := fixture(SourceAgentRASP, `{"event_id":"rasp-1","agent_id":"agent-1","event_type":"rasp.sql","event_at":"2026-07-13T09:59:00Z","observed_at":"2026-07-13T09:59:01Z","severity":"critical","details":{"authorization":"Bearer secret","query":"select 1"}}`)
	event, _, err := NormalizeFixture(input, PrincipalIdentity("agent-1"), migrationTestTime)
	if err != nil {
		t.Fatalf("normalize fixture: %v", err)
	}
	if strings.Contains(string(event.Payload), "Bearer secret") || !strings.Contains(string(event.Payload), RedactedValue) {
		t.Fatalf("secret was not redacted: %s", event.Payload)
	}
	if err := AuthorizeGovernance(event, RoleViewer, GovernanceExport); !errors.Is(err, ErrGovernanceDenied) {
		t.Fatalf("viewer export should be denied: %v", err)
	}
	if err := AuthorizeGovernance(event, RoleSecurityAdmin, GovernanceExport); err != nil {
		t.Fatalf("security admin export denied: %v", err)
	}
	if err := AuthorizeGovernance(event, RoleViewer, GovernanceDelete); !errors.Is(err, ErrGovernanceDenied) {
		t.Fatalf("viewer delete should be denied: %v", err)
	}
	if err := AuthorizeGovernance(event, RoleViewer, GovernanceRead); !errors.Is(err, ErrGovernanceDenied) {
		t.Fatalf("viewer restricted read should be denied: %v", err)
	}
	if err := AuthorizeGovernance(event, RoleAnalyst, GovernanceRead); err != nil {
		t.Fatalf("analyst restricted read denied: %v", err)
	}
	if err := AuthorizeGovernance(event, RolePrivacyAdmin, GovernanceDelete); err != nil {
		t.Fatalf("privacy admin delete denied: %v", err)
	}
	if event.Governance.Retention.ExpiresAt.Sub(event.Timestamps.IngestedAt) != 30*24*time.Hour || !event.Governance.Encryption.Required {
		t.Fatalf("retention/encryption governance missing: %+v", event.Governance)
	}
}

func TestCanonicalEventSchemaNegotiationQuarantinesInvalidFixtures(t *testing.T) {
	tests := []struct {
		name   string
		input  SourceFixture
		reason QuarantineReason
	}{
		{name: "missing identity", input: fixture(SourceAgentRuntime, `{"event_id":"e1","event_type":"runtime.process","event_at":"2026-07-13T09:59:00Z","severity":"high"}`), reason: QuarantineMissingIdentity},
		{name: "missing timestamp", input: fixture(SourceAgentRuntime, `{"event_id":"e1","agent_id":"agent-1","event_type":"runtime.process","severity":"high"}`), reason: QuarantineMissingTimestamp},
		{name: "missing observed timestamp", input: fixture(SourceAgentRuntime, `{"event_id":"e1","agent_id":"agent-1","event_type":"runtime.process","event_at":"2026-07-13T09:59:00Z","severity":"high"}`), reason: QuarantineMissingTimestamp},
		{name: "future schema", input: SourceFixture{Source: SourceAgentRuntime, SchemaVersion: "lyflow.security_event.v99", Payload: json.RawMessage(`{"event_id":"e1"}`)}, reason: QuarantineFutureSchema},
		{name: "invalid enum", input: fixture(SourceAgentRuntime, `{"event_id":"e1","agent_id":"agent-1","event_type":"runtime.process","event_at":"2026-07-13T09:59:00Z","observed_at":"2026-07-13T09:59:01Z","severity":"urgent"}`), reason: QuarantineInvalidEnum},
		{name: "unknown field", input: fixture(SourceAgentRuntime, `{"event_id":"e1","agent_id":"agent-1","event_type":"runtime.process","event_at":"2026-07-13T09:59:00Z","observed_at":"2026-07-13T09:59:01Z","severity":"high","surprise":true}`), reason: QuarantineInvalidField},
		{name: "malformed JSON", input: fixture(SourceAgentRuntime, `{"event_id":`), reason: QuarantineMalformed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := NormalizeFixture(test.input, PrincipalIdentity("agent-1"), migrationTestTime)
			var quarantine *QuarantineError
			if !errors.As(err, &quarantine) || quarantine.Reason != test.reason {
				t.Fatalf("expected quarantine %q, got %v", test.reason, err)
			}
		})
	}
}

func TestCanonicalEventValidateRejectsIdentityAndMetadataConflicts(t *testing.T) {
	input := fixture(SourceAgentRuntime, `{"event_id":"runtime-1","agent_id":"agent-1","event_type":"runtime.process","event_at":"2026-07-13T09:59:00Z","observed_at":"2026-07-13T09:59:01Z","severity":"high"}`)
	event, _, err := NormalizeFixture(input, PrincipalIdentity("agent-1"), migrationTestTime)
	if err != nil {
		t.Fatalf("normalize fixture: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*CanonicalSecurityEvent)
	}{
		{name: "missing agent identity", mutate: func(value *CanonicalSecurityEvent) { value.Identity.AgentID = "" }},
		{name: "conflicting agent identity", mutate: func(value *CanonicalSecurityEvent) { value.Identity.AgentID = "agent-2" }},
		{name: "unknown quality flag", mutate: func(value *CanonicalSecurityEvent) {
			value.QualityFlags = append(value.QualityFlags, QualityFlag("invented"))
		}},
		{name: "missing quality flags", mutate: func(value *CanonicalSecurityEvent) { value.QualityFlags = nil }},
		{name: "unsupported attack version", mutate: func(value *CanonicalSecurityEvent) { value.Attack.Version = "enterprise-attack.v99" }},
		{name: "unknown access policy", mutate: func(value *CanonicalSecurityEvent) { value.Governance.AccessPolicyID = "allow-all" }},
		{name: "missing provenance adapter", mutate: func(value *CanonicalSecurityEvent) { value.Provenance.Adapter = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := event
			candidate.QualityFlags = append([]QualityFlag(nil), event.QualityFlags...)
			test.mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid canonical event accepted")
			}
		})
	}
}

func TestCanonicalEventParserRejectsUnredactedNestedSecret(t *testing.T) {
	input := fixture(SourceAgentRuntime, `{"event_id":"runtime-1","agent_id":"agent-1","event_type":"runtime.process","event_at":"2026-07-13T09:59:00Z","observed_at":"2026-07-13T09:59:01Z","severity":"high"}`)
	event, _, err := NormalizeFixture(input, PrincipalIdentity("agent-1"), migrationTestTime)
	if err != nil {
		t.Fatalf("normalize fixture: %v", err)
	}
	event.Payload = json.RawMessage(`{"nested":[{"api_token":"plaintext"}]}`)
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal candidate: %v", err)
	}

	_, _, err = ParseCanonical(encoded, PrincipalIdentity("agent-1"))
	if !errors.Is(err, ErrInvalidField) {
		t.Fatalf("unredacted canonical secret accepted: %v", err)
	}
}

func TestCanonicalEventOldFixtureEmitsWarning(t *testing.T) {
	input := fixture(SourceUnifiedLegacy, `{"id":"old-1","agent":"agent-1","type":"legacy.event","event_time":"2026-07-13T09:59:00Z","observed_time":"2026-07-13T09:59:01Z","level":"low"}`)
	input.SchemaVersion = LegacySecurityEventSchemaVersion

	event, warnings, err := NormalizeFixture(input, PrincipalIdentity("agent-1"), migrationTestTime)
	if err != nil {
		t.Fatalf("old fixture rejected: %v", err)
	}
	if len(warnings) != 1 || warnings[0].Code != WarningOldSchema {
		t.Fatalf("expected one old-schema warning, got %+v", warnings)
	}
	if event.Provenance.Adapter != "contracts.v0SourceAdapter" || !slices.Contains(event.QualityFlags, QualityLegacyAdapted) {
		t.Fatalf("v0 fixture did not use explicit adapter: %+v", event.Provenance)
	}
}

func TestTelemetryAndComponentAdaptersNormalizeToCanonical(t *testing.T) {
	telemetry := TelemetryEnvelope{SchemaVersion: TelemetrySchemaVersion, ID: "telemetry-1", Category: TelemetryRuntime, EventType: "runtime.process", ObservedAt: migrationTestTime, Source: "agent", SourceEngine: SourceEngineRuntime, Entities: EntityRef{AgentID: "agent-1"}}
	alert := ComponentAlert{SchemaVersion: ComponentAlertSchemaVersion, ID: "alert-1", Category: TelemetryHost, SourceEngine: SourceEngineWazuh, RuleID: "rule-1", RuleName: "host rule", NativeRule: &RuleReference{Engine: SourceEngineWazuh, ID: "5710", Source: "wazuh-default"}, Severity: SeverityHigh, OccurredAt: migrationTestTime, Source: "security-engine", Entities: EntityRef{AgentID: "agent-1"}, RawReference: &RawReference{Path: "/var/log/wazuh/alerts.json", Hash: "abc123"}, Summary: "host alert"}

	telemetryEvent, err := telemetry.Canonical(PrincipalIdentity("agent-1"), migrationTestTime)
	if err != nil || telemetryEvent.Provenance.Source != SourceAgentRuntime {
		t.Fatalf("telemetry adapter failed: %+v (%v)", telemetryEvent.Provenance, err)
	}
	alertEvent, err := alert.Canonical(PrincipalIdentity("agent-1"), migrationTestTime)
	if err != nil || alertEvent.Provenance.Source != SourceWazuh {
		t.Fatalf("component alert adapter failed: %+v (%v)", alertEvent.Provenance, err)
	}
	var alertPayload struct {
		NativeRule   *RuleReference `json:"native_rule"`
		RawReference *RawReference  `json:"raw_reference"`
	}
	if err := json.Unmarshal(alertEvent.Payload, &alertPayload); err != nil {
		t.Fatalf("decode component alert payload: %v", err)
	}
	if alertPayload.NativeRule == nil || alertPayload.NativeRule.Source != "wazuh-default" || alertPayload.RawReference == nil || alertPayload.RawReference.Hash != "abc123" {
		t.Fatalf("component alert provenance was not preserved: %+v", alertPayload)
	}
}

func TestCanonicalEventParserStrictlyNegotiatesAndBindsPrincipal(t *testing.T) {
	input := fixture(SourceAgentRuntime, `{"event_id":"runtime-1","agent_id":"agent-1","event_type":"runtime.process","event_at":"2026-07-13T09:59:00Z","observed_at":"2026-07-13T09:59:01Z","severity":"high"}`)
	event, _, err := NormalizeFixture(input, PrincipalIdentity("agent-1"), migrationTestTime)
	if err != nil {
		t.Fatalf("normalize fixture: %v", err)
	}
	encoded, err := MarshalCanonical(event)
	if err != nil {
		t.Fatalf("marshal canonical: %v", err)
	}
	parsed, warnings, err := ParseCanonical(encoded, PrincipalIdentity("agent-1"))
	if err != nil || len(warnings) != 0 || parsed.EventUID != event.EventUID {
		t.Fatalf("parse canonical failed: %+v %v %v", parsed, warnings, err)
	}
	_, _, err = ParseCanonical(encoded, "")
	var quarantine *QuarantineError
	if !errors.As(err, &quarantine) || quarantine.Reason != QuarantineMissingIdentity {
		t.Fatalf("missing principal should quarantine: %v", err)
	}
	_, _, err = ParseCanonical(append(encoded, []byte(` {}`)...), PrincipalIdentity("agent-1"))
	if !errors.As(err, &quarantine) || quarantine.Reason != QuarantineMalformed {
		t.Fatalf("trailing JSON should quarantine: %v", err)
	}
}

func TestCanonicalEventSourceFixturesMatchGoldenJSON(t *testing.T) {
	fixtureData, err := os.ReadFile("testdata/source-fixtures.json")
	if err != nil {
		t.Fatalf("read source fixtures: %v", err)
	}
	var fixtures []SourceFixture
	if err := json.Unmarshal(fixtureData, &fixtures); err != nil {
		t.Fatalf("decode source fixtures: %v", err)
	}
	actual := make(map[EventSource]json.RawMessage, len(fixtures))
	for _, input := range fixtures {
		event, _, err := NormalizeFixture(input, PrincipalIdentity("agent-1"), migrationTestTime)
		if err != nil {
			t.Fatalf("normalize %s: %v", input.Source, err)
		}
		encoded, err := MarshalCanonical(event)
		if err != nil {
			t.Fatalf("encode %s: %v", input.Source, err)
		}
		actual[input.Source] = append(json.RawMessage(nil), encoded...)
	}
	expectedData, err := os.ReadFile("testdata/canonical-events.golden.json")
	if err != nil {
		t.Fatalf("read golden events: %v", err)
	}
	var expected map[EventSource]json.RawMessage
	if err := json.Unmarshal(expectedData, &expected); err != nil {
		t.Fatalf("decode golden events: %v", err)
	}
	if len(actual) != len(expected) {
		t.Fatalf("canonical fixture count=%d, golden count=%d", len(actual), len(expected))
	}
	for source, event := range actual {
		golden, exists := expected[source]
		if !exists || !bytes.Equal(compactJSON(event), compactJSON(golden)) {
			t.Fatalf("canonical fixture %s differs from golden:\n%s", source, event)
		}
	}
}

func fixture(source EventSource, payload string) SourceFixture {
	return SourceFixture{Source: source, SchemaVersion: SecurityEventSchemaVersion, Payload: json.RawMessage(payload)}
}
