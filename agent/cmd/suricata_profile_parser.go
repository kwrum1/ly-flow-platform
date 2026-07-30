package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

type suricataProfileRecord interface {
	isSuricataProfileRecord()
	correlationID() string
	eventType() string
	eventTime() time.Time
}

type suricataTelemetryRecord struct {
	Kind        string                      `json:"kind"`
	Correlation string                      `json:"correlation_id"`
	Telemetry   contracts.TelemetryEnvelope `json:"telemetry"`
}

func (suricataTelemetryRecord) isSuricataProfileRecord()     {}
func (record suricataTelemetryRecord) correlationID() string { return record.Correlation }
func (record suricataTelemetryRecord) eventType() string     { return record.Telemetry.EventType }
func (record suricataTelemetryRecord) eventTime() time.Time  { return record.Telemetry.ObservedAt }

type suricataAlertRecord struct {
	Kind        string                   `json:"kind"`
	Correlation string                   `json:"correlation_id"`
	Alert       contracts.ComponentAlert `json:"alert"`
}

func (suricataAlertRecord) isSuricataProfileRecord()     {}
func (record suricataAlertRecord) correlationID() string { return record.Correlation }
func (record suricataAlertRecord) eventType() string     { return "alert" }
func (record suricataAlertRecord) eventTime() time.Time  { return record.Alert.OccurredAt }

type suricataProfileContext struct {
	agentID  string
	hostname string
	raw      contracts.RawReference
}

func newSuricataProfileContext(agentID, hostname string) suricataProfileContext {
	return suricataProfileContext{agentID: agentID, hostname: hostname}
}

func (context suricataProfileContext) withRaw(raw contracts.RawReference) suricataProfileContext {
	context.raw = raw
	return context
}

type suricataProfileEVE struct {
	Timestamp       string              `json:"timestamp"`
	FlowID          uint64              `json:"flow_id"`
	EventType       string              `json:"event_type"`
	SrcIP           string              `json:"src_ip"`
	SrcPort         int                 `json:"src_port"`
	DestIP          string              `json:"dest_ip"`
	DestPort        int                 `json:"dest_port"`
	Proto           string              `json:"proto"`
	AppProto        string              `json:"app_proto"`
	CommunityID     string              `json:"community_id"`
	SuricataVersion string              `json:"suricata_version"`
	Alert           suricataEVEAlert    `json:"alert"`
	Flow            suricataProfileFlow `json:"flow"`
	DNS             suricataProfileDNS  `json:"dns"`
	HTTP            suricataProfileHTTP `json:"http"`
	TLS             suricataProfileTLS  `json:"tls"`
}

type suricataProfileFlow struct {
	PacketsToServer uint64 `json:"pkts_toserver"`
	PacketsToClient uint64 `json:"pkts_toclient"`
	BytesToServer   uint64 `json:"bytes_toserver"`
	BytesToClient   uint64 `json:"bytes_toclient"`
	Start           string `json:"start"`
	End             string `json:"end"`
	Age             uint64 `json:"age"`
	State           string `json:"state"`
	Reason          string `json:"reason"`
	Alerted         bool   `json:"alerted"`
}

type suricataProfileDNS struct {
	Type   string `json:"type"`
	ID     int    `json:"id"`
	RRName string `json:"rrname"`
	RRType string `json:"rrtype"`
	RCode  string `json:"rcode"`
}

type suricataProfileHTTP struct {
	Hostname    string `json:"hostname"`
	URL         string `json:"url"`
	UserAgent   string `json:"http_user_agent"`
	ContentType string `json:"http_content_type"`
	Method      string `json:"http_method"`
	Protocol    string `json:"protocol"`
	Status      int    `json:"status"`
	Length      int64  `json:"length"`
}

type suricataProfileTLS struct {
	Subject     string `json:"subject"`
	Issuer      string `json:"issuerdn"`
	Serial      string `json:"serial"`
	Fingerprint string `json:"fingerprint"`
	SNI         string `json:"sni"`
	Version     string `json:"version"`
	JA3         struct {
		Hash string `json:"hash"`
	} `json:"ja3"`
	JA3S struct {
		Hash string `json:"hash"`
	} `json:"ja3s"`
}

func parseSuricataProfileLine(line []byte, context suricataProfileContext) (suricataProfileRecord, error) {
	var event suricataProfileEVE
	if err := json.Unmarshal(line, &event); err != nil {
		return nil, fmt.Errorf("decode Suricata EVE: %w", err)
	}
	if event.SuricataVersion != "" && event.SuricataVersion != suricataProfileVersion {
		return nil, fmt.Errorf("line version %q, expected %q: %w", event.SuricataVersion, suricataProfileVersion, errSuricataVersionDrift)
	}
	if event.FlowID == 0 || event.EventType == "" {
		return nil, fmt.Errorf("missing flow_id or event_type: %w", contracts.ErrInvalidField)
	}
	occurredAt := parseSuricataTime(event.Timestamp)
	if occurredAt.IsZero() {
		return nil, fmt.Errorf("timestamp %q: %w", event.Timestamp, contracts.ErrMissingTimestamp)
	}
	correlation := "suricata-flow-" + strconv.FormatUint(event.FlowID, 10)
	context.raw.SourceEngine = contracts.SourceEngineSuricata
	context.raw.EventType = event.EventType
	rawHash, err := suricataRawHash(line)
	if err != nil {
		return nil, err
	}
	context.raw.Hash = rawHash
	if event.EventType == "alert" {
		alert, ok, err := componentAlertFromSuricataEVE(line, nil, context.raw)
		if err != nil {
			return nil, fmt.Errorf("normalize Suricata alert: %w", err)
		}
		if !ok {
			return nil, fmt.Errorf("missing alert signature: %w", contracts.ErrInvalidField)
		}
		alert.EngineVersion = suricataProfileVersion
		alert.RulePack = suricataProfileRulePack
		alert.Entities.AgentID = context.agentID
		alert.Entities.Hostname = context.hostname
		alert.Entities.TraceID = correlation
		alert.Details["flow_id"] = strconv.FormatUint(event.FlowID, 10)
		return suricataAlertRecord{Kind: "alert", Correlation: correlation, Alert: alert}, nil
	}
	if !isCoveredSuricataEventType(event.EventType) {
		return nil, fmt.Errorf("event_type %q: %w", event.EventType, errUnsupportedSuricataEventType)
	}
	fields := suricataProfileFields(event)
	telemetry := contracts.TelemetryEnvelope{
		SchemaVersion: contracts.TelemetrySchemaVersion,
		ID:            "suricata-eve-" + strconv.FormatUint(event.FlowID, 10) + "-" + event.EventType,
		Category:      contracts.TelemetryNetwork, EventType: "network." + event.EventType,
		ObservedAt: occurredAt, Source: "suricata-eve", SourceEngine: contracts.SourceEngineSuricata,
		EngineVersion: suricataProfileVersion, RulePack: suricataProfileRulePack,
		Entities:     contracts.EntityRef{AgentID: context.agentID, Hostname: context.hostname, SourceIP: event.SrcIP, TargetIP: event.DestIP, TraceID: correlation},
		RawReference: &context.raw, Fields: fields,
	}
	if err := telemetry.Validate(); err != nil {
		return nil, fmt.Errorf("validate Suricata telemetry: %w", err)
	}
	return suricataTelemetryRecord{Kind: "telemetry", Correlation: correlation, Telemetry: telemetry}, nil
}

func suricataRawHash(line []byte) (string, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(line, &fields); err != nil {
		return "", fmt.Errorf("decode Suricata EVE for raw identity: %w", err)
	}
	delete(fields, "flow_id")
	canonical, err := json.Marshal(fields)
	if err != nil {
		return "", fmt.Errorf("encode Suricata EVE raw identity: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func isCoveredSuricataEventType(eventType string) bool {
	switch eventType {
	case "flow", "dns", "http", "tls":
		return true
	default:
		return false
	}
}

func suricataProfileFields(event suricataProfileEVE) map[string]interface{} {
	fields := map[string]interface{}{
		"flow_id": strconv.FormatUint(event.FlowID, 10), "community_id": event.CommunityID,
		"src_ip": event.SrcIP, "src_port": event.SrcPort, "dest_ip": event.DestIP, "dest_port": event.DestPort,
		"proto": event.Proto, "app_proto": event.AppProto,
	}
	switch event.EventType {
	case "flow":
		fields["flow"] = event.Flow
	case "dns":
		fields["dns"] = event.DNS
	case "http":
		fields["http"] = event.HTTP
	case "tls":
		fields["tls"] = event.TLS
	}
	if strings.TrimSpace(event.CommunityID) == "" {
		delete(fields, "community_id")
	}
	return fields
}
