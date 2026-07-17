package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log"
	"sync/atomic"
	"time"

	transport "github.com/lyflow/ly-flow-platform/transportreliability"
	"ly-flow-platform/dpi-engine/core/domain"
	"ly-flow-platform/dpi-engine/core/output"
	"ly-flow-platform/dpi-engine/core/redis"
	"ly-flow-platform/dpi-engine/core/rules"
	"ly-flow-platform/dpi-engine/model"
)

// Engine is the main DPI analysis engine
type Engine struct {
	consumer   *redis.Consumer
	auditor    *domain.Auditor
	ruleEngine *rules.Engine
	output     *output.Output
	workers    int
	running    atomic.Bool
	stats      struct {
		Flows   uint64
		Alerts  uint64
		Matched uint64
	}
}

// New creates a new DPI engine
func New(consumer *redis.Consumer, auditor *domain.Auditor, ruleEngine *rules.Engine, out *output.Output) *Engine {
	return &Engine{
		consumer:   consumer,
		auditor:    auditor,
		ruleEngine: ruleEngine,
		output:     out,
		workers:    4,
	}
}

// Start begins processing flows
func (e *Engine) Start() error {
	if !e.running.CompareAndSwap(false, true) {
		return nil
	}

	e.consumer.OnFlowReliable(func(_ context.Context, msg redis.XMessage) error {
		flow := e.parseFlow(msg)
		if flow == nil {
			return transport.Permanent(transport.ReasonInvalidPayload, fmt.Errorf("parse flow %s", msg.ID))
		}

		atomic.AddUint64(&e.stats.Flows, 1)

		// Domain audit
		domainResult := e.auditor.Audit(flow.GetDomain())

		// Rule matching
		matchedRules := e.ruleEngine.Match(flow)
		if len(matchedRules) > 0 {
			atomic.AddUint64(&e.stats.Matched, 1)
		}

		if err := e.output.SendSemanticFlow(buildSemanticFlow(flow, domainResult, matchedRules)); err != nil {
			return fmt.Errorf("semantic flow output: %w", err)
		}

		if domainResult.Match {
			if err := e.emitDomainAlert(flow, domainResult, msg.ID); err != nil {
				return err
			}
			atomic.AddUint64(&e.stats.Alerts, 1)
		}

		if len(matchedRules) > 0 {
			if err := e.emitRuleAlerts(flow, matchedRules, msg.ID); err != nil {
				return err
			}
		}
		return nil
	})

	if err := e.consumer.Start(); err != nil {
		return err
	}

	e.output.Start()
	log.Printf("[engine] Started")
	return nil
}

// Stop gracefully stops the engine
func (e *Engine) Stop() {
	if !e.running.CompareAndSwap(true, false) {
		return
	}

	e.output.Stop()
	e.consumer.Stop()
	log.Println("[engine] Stopped")
}

// Stats returns engine statistics
func (e *Engine) Stats() (flows, alerts, matched uint64) {
	return atomic.LoadUint64(&e.stats.Flows),
		atomic.LoadUint64(&e.stats.Alerts),
		atomic.LoadUint64(&e.stats.Matched)
}

// ConsumerStats returns Redis consumer statistics
func (e *Engine) ConsumerStats() (processed, alerts, errors uint64) {
	return e.consumer.Stats()
}

// OutputStats returns output statistics
func (e *Engine) OutputStats() (sent, errors uint64) {
	return e.output.Stats()
}

func (e *Engine) TransportAccounting(ctx context.Context) (transport.AccountingSnapshot, error) {
	return e.consumer.TransportAccounting(ctx)
}

func (e *Engine) parseFlow(msg redis.XMessage) *model.FlowData {
	flow := &model.FlowData{}
	values := unwrapFlowValues(msg.Values)

	if v, ok := values["id"].(string); ok {
		flow.ID = v
	}
	if v, ok := values["timestamp"].(string); ok {
		// Parse timestamp
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			flow.Timestamp = t.Unix()
		}
	} else if v, ok := values["timestamp"].(int64); ok {
		flow.Timestamp = v
	}
	if v, ok := values["sensor_id"].(string); ok {
		flow.SensorID = v
	}
	if v, ok := values["src_ip"].(string); ok {
		flow.SrcIP = v
	}
	if v, ok := values["dst_ip"].(string); ok {
		flow.DstIP = v
	}
	if v, ok := values["src_port"].(string); ok {
		if port, err := parsePort(v); err == nil {
			flow.SrcPort = port
		}
	} else if v, ok := values["src_port"].(int64); ok {
		flow.SrcPort = uint16(v)
	}
	if v, ok := values["dst_port"].(string); ok {
		if port, err := parsePort(v); err == nil {
			flow.DstPort = port
		}
	} else if v, ok := values["dst_port"].(int64); ok {
		flow.DstPort = uint16(v)
	}
	if v, ok := values["protocol"].(string); ok {
		flow.Protocol = v
	}
	if v, ok := values["app_protocol"].(string); ok {
		flow.AppProtocol = v
	}
	if v, ok := values["dns_query"].(string); ok {
		flow.DNSQuery = v
	}
	if v, ok := values["http_host"].(string); ok {
		flow.HTTPHost = v
	}
	if v, ok := values["tls_sni"].(string); ok {
		flow.TLSSNI = v
	}
	if v, ok := values["ja3"].(string); ok {
		flow.JA3 = v
	}
	if v, ok := values["bytes_in"].(string); ok {
		if b, err := parseUint64(v); err == nil {
			flow.BytesIn = b
		}
	} else if v, ok := values["bytes_in"].(int64); ok {
		flow.BytesIn = uint64(v)
	}
	if v, ok := values["bytes_out"].(string); ok {
		if b, err := parseUint64(v); err == nil {
			flow.BytesOut = b
		}
	} else if v, ok := values["bytes_out"].(int64); ok {
		flow.BytesOut = uint64(v)
	}
	if v, ok := values["packets"].(string); ok {
		if p, err := parseUint64(v); err == nil {
			flow.Packets = p
		}
	} else if v, ok := values["packets"].(int64); ok {
		flow.Packets = uint64(v)
	}
	if v, ok := values["duration_ms"].(string); ok {
		if d, err := parseUint64(v); err == nil {
			flow.DurationMs = d
		}
	} else if v, ok := values["duration_ms"].(int64); ok {
		flow.DurationMs = uint64(v)
	}
	if v, ok := values["direction"].(string); ok {
		flow.Direction = v
	}

	return flow
}

func unwrapFlowValues(values map[string]interface{}) map[string]interface{} {
	if values == nil {
		return map[string]interface{}{}
	}

	if raw, ok := values["data"]; ok {
		switch v := raw.(type) {
		case string:
			var nested map[string]interface{}
			if err := json.Unmarshal([]byte(v), &nested); err == nil && len(nested) > 0 {
				merged := make(map[string]interface{}, len(values)+len(nested))
				for k, val := range values {
					merged[k] = val
				}
				for k, val := range nested {
					merged[k] = val
				}
				return merged
			}
		case []byte:
			var nested map[string]interface{}
			if err := json.Unmarshal(v, &nested); err == nil && len(nested) > 0 {
				merged := make(map[string]interface{}, len(values)+len(nested))
				for k, val := range values {
					merged[k] = val
				}
				for k, val := range nested {
					merged[k] = val
				}
				return merged
			}
		}
	}

	return values
}

func buildSemanticFlow(flow *model.FlowData, domainResult *domain.AuditResult, matchedRules []*rules.Rule) *model.SemanticFlow {
	riskScore := 0
	threatType := "benign"
	context := "no detection matched"

	if domainResult != nil && domainResult.Match {
		riskScore = domainResult.Score
		threatType = "domain_" + domainResult.Label
		context = domainResult.Details
		if context == "" {
			context = "domain reputation match"
		}
	}

	for _, rule := range matchedRules {
		ruleScore := scoreFromRule(rule)
		if ruleScore > riskScore {
			riskScore = ruleScore
			threatType = string(rule.Category)
			context = rule.Msg
		}
	}

	return &model.SemanticFlow{
		SchemaVersion: "lyflow.semantic.v1",
		SourceStream:  "flows:raw",
		FlowID:        flow.ID,
		SessionID:     sessionID(flow),
		Timestamp:     flow.Timestamp,
		SensorID:      flow.SensorID,
		SrcIP:         flow.SrcIP,
		DstIP:         flow.DstIP,
		SrcPort:       flow.SrcPort,
		DstPort:       flow.DstPort,
		Transport:     flow.Protocol,
		AppProtocol:   flow.AppProtocol,
		Domain:        flow.GetDomain(),
		DNSQuery:      flow.DNSQuery,
		DNSAnswer:     flow.DNSAnswer,
		DNSDomain:     flow.DNSDomain,
		HTTPHost:      flow.HTTPHost,
		TLSSNI:        flow.TLSSNI,
		JA3:           flow.JA3,
		HTTPMethod:    flow.HTTPMethod,
		HTTPPath:      flow.HTTPPath,
		HTTPStatus:    flow.HTTPStatus,
		RiskScore:     riskScore,
		RiskLevel:     riskLevelFromScore(riskScore),
		ThreatType:    threatType,
		Context:       context,
		BytesIn:       flow.BytesIn,
		BytesOut:      flow.BytesOut,
		Packets:       flow.Packets,
		DurationMs:    flow.DurationMs,
		Direction:     flow.Direction,
	}
}

func scoreFromRule(rule *rules.Rule) int {
	if rule == nil {
		return 0
	}
	switch rule.Severity {
	case rules.SeverityCritical:
		return 95
	case rules.SeverityHigh:
		return 80
	case rules.SeverityMedium:
		return 55
	case rules.SeverityLow:
		return 30
	default:
		return 40
	}
}

func riskLevelFromScore(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 40:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "none"
	}
}

func sessionID(flow *model.FlowData) string {
	if flow.ID != "" {
		return flow.ID
	}
	return flow.SrcIP + ":" + stringPort(flow.SrcPort) + "->" + flow.DstIP + ":" + stringPort(flow.DstPort)
}

func stringPort(port uint16) string {
	if port == 0 {
		return "0"
	}
	buf := [5]byte{}
	i := len(buf)
	for port > 0 {
		i--
		buf[i] = byte('0' + port%10)
		port /= 10
	}
	return string(buf[i:])
}

func (e *Engine) emitDomainAlert(flow *model.FlowData, result *domain.AuditResult, messageID string) error {
	alert := &output.Alert{
		ID:        deterministicAlertID(messageID, "domain:"+result.Label),
		Timestamp: flow.Time().UTC().Format(time.RFC3339),
		Type:      model.AlertTypeDPI,
		SrcIP:     flow.SrcIP,
		DstIP:     flow.DstIP,
		SrcPort:   flow.SrcPort,
		DstPort:   flow.DstPort,
		Protocol:  flow.Protocol,
		Signature: "DomainAudit." + result.Label,
		Category:  result.Label,
		Severity:  severityFromScore(result.Score),
		Score:     result.Score,
		Status:    model.StatusNew,
		SensorID:  flow.SensorID,
		Domain:    result.Domain,
	}
	if err := e.output.SendDirect(alert); err != nil {
		return fmt.Errorf("domain alert output: %w", err)
	}
	return nil
}

func (e *Engine) emitRuleAlerts(flow *model.FlowData, matchedRules []*rules.Rule, messageID string) error {
	for _, rule := range matchedRules {
		alert := &output.Alert{
			ID:        deterministicAlertID(messageID, fmt.Sprintf("rule:%d", rule.SID)),
			Timestamp: flow.Time().UTC().Format(time.RFC3339),
			Type:      model.AlertTypeDPI,
			SrcIP:     flow.SrcIP,
			DstIP:     flow.DstIP,
			SrcPort:   flow.SrcPort,
			DstPort:   flow.DstPort,
			Protocol:  flow.Protocol,
			Signature: rule.Msg,
			Category:  "rule",
			Severity:  2,
			Score:     70,
			Status:    model.StatusNew,
			SensorID:  flow.SensorID,
			Domain:    flow.GetDomain(),
		}
		if err := e.output.SendDirect(alert); err != nil {
			return fmt.Errorf("rule alert %d output: %w", rule.SID, err)
		}
	}
	atomic.AddUint64(&e.stats.Alerts, uint64(len(matchedRules)))
	return nil
}

func deterministicAlertID(messageID, discriminator string) uint64 {
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(messageID + "\x00" + discriminator))
	return hash.Sum64()
}

func severityFromScore(score int) uint8 {
	switch {
	case score >= 80:
		return model.AlertSeverityCritical
	case score >= 60:
		return model.AlertSeverityHigh
	case score >= 40:
		return model.AlertSeverityMedium
	default:
		return model.AlertSeverityLow
	}
}

var idCounter uint64

func generateID() uint64 {
	return atomic.AddUint64(&idCounter, 1)
}

func parsePort(s string) (uint16, error) {
	_, err := parseUint64WithBase(s, 10)
	return 0, err
}

func parseUint64(s string) (uint64, error) {
	return parseUint64WithBase(s, 10)
}

func parseUint64WithBase(s string, base int) (uint64, error) {
	var n uint64
	for _, c := range s {
		n = n*uint64(base) + uint64(c-'0')
	}
	return n, nil
}
