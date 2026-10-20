package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/lyflow/ly-flow-platform/contracts"
)

// projectEventsV2ForXDR gives the XDR/incident pipeline a canonical projection
// of v2 events without changing the primary v2 ClickHouse write path. The
// projection is intentionally best-effort: if it fails, v2 ingest and query
// remain available and the failure is visible in logs for later repair.
func (runtime *StorageEventRuntime) projectEventsV2ForXDR(ctx context.Context, events []contracts.EventV2) {
	if runtime == nil || runtime.migration == nil {
		return
	}
	for _, event := range events {
		projection, err := canonicalProjectionFromV2(event)
		if err != nil {
			log.Printf("xdr v2 projection skipped event=%s: %v", event.EventUID, err)
			continue
		}
		if err := runtime.WriteCanonical(ctx, projection); err != nil {
			log.Printf("xdr v2 projection failed event=%s: %v", event.EventUID, err)
		}
	}
}

// canonicalProjectionFromV2 maps the validated multi-source v2 contract to the
// canonical v1 envelope consumed by the existing XDR graph and incident
// lifecycle. It keeps the v2 event as the source of truth while adding the
// attack-mapping fields the legacy envelope expects.
func canonicalProjectionFromV2(event contracts.EventV2) (contracts.CanonicalSecurityEvent, error) {
	if err := event.Validate(); err != nil {
		return contracts.CanonicalSecurityEvent{}, fmt.Errorf("validate v2 event: %w", err)
	}
	agentID := ""
	if event.Entities.Asset != nil {
		agentID = strings.TrimSpace(event.Entities.Asset.ID)
		if agentID == "" {
			agentID = strings.TrimSpace(event.Entities.Asset.Hostname)
		}
	}
	if agentID == "" {
		return contracts.CanonicalSecurityEvent{}, fmt.Errorf("v2 event has no asset identity for XDR projection")
	}

	correlationID := strings.TrimSpace(event.CorrelationID)
	if correlationID == "" {
		correlationID = event.EventUID
	}
	payload, err := projectionPayload(event, agentID)
	if err != nil {
		return contracts.CanonicalSecurityEvent{}, err
	}
	qualityFlags := append([]contracts.QualityFlag(nil), event.QualityFlags...)
	if len(qualityFlags) == 0 {
		qualityFlags = []contracts.QualityFlag{contracts.QualityNormalized}
	}
	payloadDigest := strings.TrimSpace(event.Raw.PayloadSHA256)
	if payloadDigest == "" {
		sum := sha256.Sum256(event.Payload)
		payloadDigest = hex.EncodeToString(sum[:])
	}

	projection := contracts.CanonicalSecurityEvent{
		SchemaVersion: contracts.SecurityEventSchemaVersion,
		EventUID:      event.EventUID,
		CorrelationID: correlationID,
		EventType:     event.EventType,
		Severity:      event.Detection.Severity,
		Identity: contracts.SourceIdentity{
			PrincipalID: agentID,
			AgentID:     agentID,
			Component:   string(event.Source),
		},
		Timestamps: event.Timestamps,
		Provenance: contracts.EventProvenance{
			Source:        event.Source,
			NativeSchema:  event.Raw.NativeSchema,
			NativeEventID: event.Raw.NativeEventID,
			Adapter:       event.Raw.Adapter,
			PayloadSHA256: payloadDigest,
		},
		Attack: contracts.AttackMapping{
			TacticID:    event.Detection.TacticID,
			TechniqueID: event.Detection.TechniqueID,
			Version:     contracts.AttackMappingVersion,
		},
		QualityFlags: qualityFlags,
		Governance:   event.Governance,
		Payload:      payload,
	}
	if err := projection.Validate(); err != nil {
		return contracts.CanonicalSecurityEvent{}, fmt.Errorf("validate XDR projection: %w", err)
	}
	return projection, nil
}

func projectionPayload(event contracts.EventV2, agentID string) (json.RawMessage, error) {
	payload := map[string]interface{}{}
	if len(event.Payload) > 0 {
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			return nil, fmt.Errorf("decode v2 payload: %w", err)
		}
	}
	if payload == nil {
		payload = map[string]interface{}{}
	}
	payload["event_uid"] = event.EventUID
	payload["event_type"] = event.EventType
	payload["source"] = string(event.Source)
	payload["asset_id"] = agentID
	payload["summary"] = firstProjectionValue(event.Detection.Description, event.EventType)
	if event.Entities.Asset != nil && event.Entities.Asset.Hostname != "" {
		payload["hostname"] = event.Entities.Asset.Hostname
	}
	if event.Detection.RuleID != "" {
		payload["rule_id"] = event.Detection.RuleID
	}
	if stage := strings.TrimSpace(string(event.Detection.Stage)); stage != "" && stage != string(contracts.StageUnknown) {
		payload["stage_hint"] = stage
	}
	if event.Detection.TacticID != "" {
		payload["mitre_tactic"] = event.Detection.TacticID
	}
	if event.Detection.TechniqueID != "" {
		payload["mitre_technique"] = event.Detection.TechniqueID
	}
	if network := event.Entities.Network; network != nil {
		if network.SrcIP != "" {
			payload["src_ip"] = network.SrcIP
		}
		if network.DstIP != "" {
			payload["dst_ip"] = network.DstIP
		}
		if network.SrcPort != 0 {
			payload["src_port"] = network.SrcPort
		}
		if network.DstPort != 0 {
			payload["dst_port"] = network.DstPort
		}
		if network.Proto != "" {
			payload["protocol"] = network.Proto
		}
	}
	if process := event.Entities.Process; process != nil {
		if process.Exe != "" {
			payload["process_exe"] = process.Exe
			payload["process_name"] = process.Exe
		}
		if process.Cmdline != "" {
			payload["process_cmdline"] = process.Cmdline
		}
		if process.PID != 0 {
			payload["process_pid"] = process.PID
		}
	}
	if app := event.Entities.App; app != nil {
		if app.Host != "" {
			payload["http_host"] = app.Host
		}
		if app.URI != "" {
			payload["http_uri"] = app.URI
		}
		if app.Method != "" {
			payload["http_method"] = app.Method
		}
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode XDR projection payload: %w", err)
	}
	return encoded, nil
}

func firstProjectionValue(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
