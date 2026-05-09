package engine

import (
	"log"
	"sync"
	"sync/atomic"
	"time"

	"ly-flow-platform/dpi-engine/core/domain"
	"ly-flow-platform/dpi-engine/core/output"
	"ly-flow-platform/dpi-engine/core/redis"
	"ly-flow-platform/dpi-engine/core/rules"
	"ly-flow-platform/dpi-engine/model"
)

// Engine is the main DPI analysis engine
type Engine struct {
	consumer *redis.Consumer
	auditor  *domain.Auditor
	ruleEngine *rules.Engine
	output   *output.Output
	workers  int
	running  atomic.Bool
	stats    struct {
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

	e.consumer.OnFlow(func(msg redis.XMessage) {
		flow := e.parseFlow(msg)
		if flow == nil {
			return
		}

		atomic.AddUint64(&e.stats.Flows, 1)

		// Domain audit
		domainResult := e.auditor.Audit(flow.GetDomain())
		if domainResult.Match {
			e.emitDomainAlert(flow, domainResult)
			atomic.AddUint64(&e.stats.Alerts, 1)
			return
		}

		// Suricata rules matching
		matchedRules := e.ruleEngine.Match(flow)
		if len(matchedRules) > 0 {
			e.emitRuleAlerts(flow, matchedRules)
			atomic.AddUint64(&e.stats.Matched, 1)
		}
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

func (e *Engine) parseFlow(msg redis.XMessage) *model.FlowData {
	flow := &model.FlowData{}

	if v, ok := msg.Values["id"].(string); ok {
		flow.ID = v
	}
	if v, ok := msg.Values["timestamp"].(string); ok {
		// Parse timestamp
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			flow.Timestamp = t.Unix()
		}
	} else if v, ok := msg.Values["timestamp"].(int64); ok {
		flow.Timestamp = v
	}
	if v, ok := msg.Values["sensor_id"].(string); ok {
		flow.SensorID = v
	}
	if v, ok := msg.Values["src_ip"].(string); ok {
		flow.SrcIP = v
	}
	if v, ok := msg.Values["dst_ip"].(string); ok {
		flow.DstIP = v
	}
	if v, ok := msg.Values["src_port"].(string); ok {
		if port, err := parsePort(v); err == nil {
			flow.SrcPort = port
		}
	} else if v, ok := msg.Values["src_port"].(int64); ok {
		flow.SrcPort = uint16(v)
	}
	if v, ok := msg.Values["dst_port"].(string); ok {
		if port, err := parsePort(v); err == nil {
			flow.DstPort = port
		}
	} else if v, ok := msg.Values["dst_port"].(int64); ok {
		flow.DstPort = uint16(v)
	}
	if v, ok := msg.Values["protocol"].(string); ok {
		flow.Protocol = v
	}
	if v, ok := msg.Values["app_protocol"].(string); ok {
		flow.AppProtocol = v
	}
	if v, ok := msg.Values["dns_query"].(string); ok {
		flow.DNSQuery = v
	}
	if v, ok := msg.Values["http_host"].(string); ok {
		flow.HTTPHost = v
	}
	if v, ok := msg.Values["tls_sni"].(string); ok {
		flow.TLSSNI = v
	}
	if v, ok := msg.Values["ja3"].(string); ok {
		flow.JA3 = v
	}
	if v, ok := msg.Values["bytes_in"].(string); ok {
		if b, err := parseUint64(v); err == nil {
			flow.BytesIn = b
		}
	} else if v, ok := msg.Values["bytes_in"].(int64); ok {
		flow.BytesIn = uint64(v)
	}
	if v, ok := msg.Values["bytes_out"].(string); ok {
		if b, err := parseUint64(v); err == nil {
			flow.BytesOut = b
		}
	} else if v, ok := msg.Values["bytes_out"].(int64); ok {
		flow.BytesOut = uint64(v)
	}
	if v, ok := msg.Values["packets"].(string); ok {
		if p, err := parseUint64(v); err == nil {
			flow.Packets = p
		}
	} else if v, ok := msg.Values["packets"].(int64); ok {
		flow.Packets = uint64(v)
	}
	if v, ok := msg.Values["duration_ms"].(string); ok {
		if d, err := parseUint64(v); err == nil {
			flow.DurationMs = d
		}
	} else if v, ok := msg.Values["duration_ms"].(int64); ok {
		flow.DurationMs = uint64(v)
	}
	if v, ok := msg.Values["direction"].(string); ok {
		flow.Direction = v
	}

	return flow
}

func (e *Engine) emitDomainAlert(flow *model.FlowData, result *domain.AuditResult) {
	alert := &output.Alert{
		ID:        generateID(),
		Timestamp: time.Now().Format(time.RFC3339),
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
	e.output.SendDirect(alert)
}

func (e *Engine) emitRuleAlerts(flow *model.FlowData, matchedRules []*rules.Rule) {
	var wg sync.WaitGroup
	for _, rule := range matchedRules {
		wg.Add(1)
		go func(r *rules.Rule) {
			defer wg.Done()
			alert := &output.Alert{
				ID:        generateID(),
				Timestamp: time.Now().Format(time.RFC3339),
				Type:      model.AlertTypeDPI,
				SrcIP:     flow.SrcIP,
				DstIP:     flow.DstIP,
				SrcPort:   flow.SrcPort,
				DstPort:   flow.DstPort,
				Protocol:  flow.Protocol,
				Signature: r.Msg,
				Category:  "rule",
				Severity:  2,
				Score:     70,
				Status:    model.StatusNew,
				SensorID:  flow.SensorID,
				Domain:    flow.GetDomain(),
			}
			e.output.SendDirect(alert)
		}(rule)
	}
	wg.Wait()
	atomic.AddUint64(&e.stats.Alerts, uint64(len(matchedRules)))
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
	var port uint16
	_, err := parseUint64WithBase(s, 10, &port)
	return port, err
}

func parseUint64(s string) (uint64, error) {
	var v uint64
	return parseUint64WithBase(s, 10, &v)
}

func parseUint64WithBase(s string, base int, out interface{}) (uint64, error) {
	var n uint64
	for _, c := range s {
		n = n*uint64(base) + uint64(c-'0')
	}
	return n, nil
}