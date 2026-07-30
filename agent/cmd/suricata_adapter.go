package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

type suricataEVEEvent struct {
	Timestamp   string                 `json:"timestamp"`
	EventType   string                 `json:"event_type"`
	SrcIP       string                 `json:"src_ip"`
	SrcPort     int                    `json:"src_port"`
	DestIP      string                 `json:"dest_ip"`
	DestPort    int                    `json:"dest_port"`
	Proto       string                 `json:"proto"`
	CommunityID string                 `json:"community_id"`
	Alert       suricataEVEAlert       `json:"alert"`
	Flow        map[string]interface{} `json:"flow"`
}

type suricataEVEAlert struct {
	Action        string              `json:"action"`
	GID           int                 `json:"gid"`
	SignatureID   int                 `json:"signature_id"`
	Revision      int                 `json:"rev"`
	Signature     string              `json:"signature"`
	Category      string              `json:"category"`
	Severity      int                 `json:"severity"`
	Metadata      map[string][]string `json:"metadata"`
	Rule          string              `json:"rule"`
	AppProto      string              `json:"app_proto"`
	SignatureInfo string              `json:"signature_info"`
}

func componentAlertFromSuricataEVE(line []byte, agent *Agent, raw contracts.RawReference) (contracts.ComponentAlert, bool, error) {
	var event suricataEVEEvent
	if err := json.Unmarshal(line, &event); err != nil {
		return contracts.ComponentAlert{}, false, err
	}
	if event.EventType != "alert" || event.Alert.SignatureID == 0 {
		return contracts.ComponentAlert{}, false, nil
	}
	occurredAt := parseSuricataTime(event.Timestamp)
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	ruleID := strconv.Itoa(event.Alert.SignatureID)
	if event.Alert.GID != 0 {
		ruleID = fmt.Sprintf("%d:%d", event.Alert.GID, event.Alert.SignatureID)
	}
	severity := suricataSeverity(event.Alert.Severity)
	score := suricataScore(event.Alert.Severity)
	ruleSource := "suricata"
	nativeRuleID := strconv.Itoa(event.Alert.SignatureID)
	nativeRevision := strconv.Itoa(event.Alert.Revision)
	attributes := map[string]string{
		"gid":              strconv.Itoa(event.Alert.GID),
		"action":           event.Alert.Action,
		"app_proto":        event.Alert.AppProto,
		"emitted_sid":      strconv.Itoa(event.Alert.SignatureID),
		"emitted_revision": strconv.Itoa(event.Alert.Revision),
	}
	for key, values := range event.Alert.Metadata {
		if len(values) == 0 {
			continue
		}
		attributes["metadata."+key] = strings.Join(values, ",")
		if key == "source_id" {
			ruleSource = values[0]
		}
		if key == "native_sid" {
			nativeRuleID = values[0]
		}
		if key == "native_revision" {
			nativeRevision = values[0]
		}
	}
	raw.SourceEngine = contracts.SourceEngineSuricata
	raw.EventType = event.EventType
	alert := contracts.ComponentAlert{
		SchemaVersion: contracts.ComponentAlertSchemaVersion,
		ID:            stableAlertID("suricata", ruleID, event.Timestamp, event.SrcIP, strconv.Itoa(event.SrcPort), event.DestIP, strconv.Itoa(event.DestPort), event.Proto),
		Category:      contracts.TelemetryNetwork,
		SourceEngine:  contracts.SourceEngineSuricata,
		RuleID:        ruleID,
		RuleName:      firstNonEmpty(event.Alert.Signature, "Suricata alert"),
		NativeRule: &contracts.RuleReference{
			Engine:     contracts.SourceEngineSuricata,
			ID:         nativeRuleID,
			Revision:   nativeRevision,
			Category:   event.Alert.Category,
			Source:     ruleSource,
			Attributes: attributes,
		},
		Severity:   severity,
		ScoreHint:  score,
		OccurredAt: occurredAt,
		Source:     "suricata",
		Entities: contracts.EntityRef{
			AgentID:  agentIDOrEmpty(agent),
			Hostname: hostnameOrEmpty(agent),
			SourceIP: event.SrcIP,
			TargetIP: event.DestIP,
		},
		RawReference: &raw,
		Summary:      fmt.Sprintf("%s %s:%d -> %s:%d", firstNonEmpty(event.Alert.Signature, "Suricata alert"), event.SrcIP, event.SrcPort, event.DestIP, event.DestPort),
		Details: map[string]interface{}{
			"src_ip":       event.SrcIP,
			"src_port":     event.SrcPort,
			"dest_ip":      event.DestIP,
			"dest_port":    event.DestPort,
			"proto":        event.Proto,
			"community_id": event.CommunityID,
			"category":     event.Alert.Category,
			"action":       event.Alert.Action,
		},
		Action:        string(contracts.ActionAudit),
		PolicyState:   contracts.PolicyAuditOnly,
		CandidateOnly: true,
	}
	if event.CommunityID != "" {
		alert.Tags = append(alert.Tags, "community_id:"+event.CommunityID)
	}
	if ip := net.ParseIP(event.SrcIP); ip != nil && ip.IsPrivate() {
		alert.Tags = append(alert.Tags, "src_private")
	}
	if err := alert.Validate(); err != nil {
		return contracts.ComponentAlert{}, false, err
	}
	return alert, true, nil
}

func parseSuricataTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	formats := []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999-0700", "2006-01-02T15:04:05.999999Z07:00"}
	for _, layout := range formats {
		if ts, err := time.Parse(layout, value); err == nil {
			return ts.UTC()
		}
	}
	return time.Time{}
}

func suricataSeverity(value int) contracts.AlertSeverity {
	switch {
	case value <= 1:
		return contracts.SeverityCritical
	case value == 2:
		return contracts.SeverityHigh
	case value == 3:
		return contracts.SeverityMedium
	default:
		return contracts.SeverityLow
	}
}

func suricataScore(value int) int {
	switch {
	case value <= 1:
		return 90
	case value == 2:
		return 75
	case value == 3:
		return 55
	default:
		return 30
	}
}

func stableAlertID(parts ...string) string {
	h := sha1.New()
	for _, part := range parts {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return "alert-" + hex.EncodeToString(h.Sum(nil))[:16]
}

func agentIDOrEmpty(agent *Agent) string {
	if agent == nil {
		return ""
	}
	return agent.agentID
}

func hostnameOrEmpty(agent *Agent) string {
	if agent == nil {
		return ""
	}
	return agent.hostname
}
