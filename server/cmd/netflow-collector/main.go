package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// This command is the missing lyprobe -> LyFlow bridge. lyprobe exports
// NetFlow v9 with the servicePlugin THREAT fields. Vector only consumes
// Suricata EVE, so without this collector the probe's flows disappear into
// a UDP socket that nobody reads.
func main() {
	listen := flag.String("listen", env("NETFLOW_LISTEN", "0.0.0.0:9995"), "UDP listen address")
	serverURL := flag.String("server", env("LYFLOW_INGEST_URL", "http://127.0.0.1:8080"), "ly-server base URL")
	agentID := flag.String("agent-id", env("VECTOR_AGENT_ID", env("NETFLOW_AGENT_ID", "")), "ingestion agent id")
	agentKey := flag.String("agent-key", env("VECTOR_AGENT_KEY", env("NETFLOW_AGENT_KEY", "")), "ingestion agent key")
	flag.Parse()
	if strings.TrimSpace(*agentID) == "" || strings.TrimSpace(*agentKey) == "" {
		log.Fatal("netflow collector: VECTOR_AGENT_ID and VECTOR_AGENT_KEY are required")
	}
	addr, err := net.ResolveUDPAddr("udp4", *listen)
	if err != nil {
		log.Fatalf("netflow collector: resolve %s: %v", *listen, err)
	}
	_ = addr
	port := uint16(9995)
	if _, parsedPort, err := net.SplitHostPort(*listen); err == nil {
		if value, convErr := strconv.Atoi(parsedPort); convErr == nil && value > 0 && value <= 65535 {
			port = uint16(value)
		}
	}
	collector := &Collector{
		client:    &http.Client{Timeout: 30 * time.Second},
		server:    strings.TrimRight(*serverURL, "/"),
		agentID:   *agentID,
		agentKey:  *agentKey,
		templates: map[string]Template{},
		queue:     make(chan Record, 4096),
	}
	collector.startWorkers(context.Background(), 8)
	log.Printf("netflow collector listening on UDP/%d, forwarding to %s as %s", port, *serverURL, *agentID)
	if err := listenRaw(context.Background(), port, collector); err != nil {
		log.Fatalf("netflow collector: raw UDP listener: %v", err)
	}
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

type Template struct {
	ID     uint16
	Fields []Field
}

type Field struct {
	Type   uint16
	Length uint16
}

type Record map[string]interface{}

type Collector struct {
	client    *http.Client
	server    string
	agentID   string
	agentKey  string
	templates map[string]Template
	queue     chan Record
}

func (c *Collector) startWorkers(ctx context.Context, count int) {
	if count <= 0 {
		count = 1
	}
	for index := 0; index < count; index++ {
		go func() {
			for record := range c.queue {
				c.publish(ctx, record)
			}
		}()
	}
}

func (c *Collector) handle(ctx context.Context, packet []byte, remote *net.UDPAddr) {
	records, err := DecodeV9(packet, c.templates, remote.IP.String())
	if err != nil {
		log.Printf("netflow collector: decode %s: %v", remote, err)
		return
	}
	log.Printf("netflow collector: packet %d bytes from %s, records=%d templates=%d", len(packet), remote, len(records), len(c.templates))
	if len(records) > 0 {
		log.Printf("netflow collector: received %d records from %s", len(records), remote)
	}
	for _, record := range records {
		select {
		case c.queue <- record:
		default:
			log.Printf("netflow collector: publish queue full, dropping flow %v", record["id"])
		}
	}
}

func (c *Collector) publish(ctx context.Context, record Record) {
	// Every flow goes to the semantic session stream so the traffic page has
	// real NetFlow evidence. Matched threat records additionally become
	// component alerts, which feed XDR/Incident.
	if flow := flowPayload(record); flow != nil {
		flow["agent_id"] = c.agentID
		// Publish into flows:raw, the canonical raw flow stream. The server
		// bridges it into flows:semantic and sessions:semantic, so both the
		// flow table and the session view receive the same probe evidence.
		if err := c.postWithRetry(ctx, "/api/v1/agent/traffic-event", map[string]interface{}{
			"agent_id": c.agentID,
			"stream":   "flows:raw",
			"type":     "flows:raw.event",
			"data":     mustJSON(flow),
		}); err != nil {
			log.Printf("netflow collector: publish flow: %v", err)
		}
	}
	if alert := threatPayload(record, c.agentID); alert != nil {
		if err := c.postWithRetry(ctx, "/api/v1/agent/component-alert", alert); err != nil {
			log.Printf("netflow collector: publish alert: %v", err)
		}
	}
}

func (c *Collector) postWithRetry(ctx context.Context, path string, body interface{}) error {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if lastErr = c.post(ctx, path, body); lastErr == nil {
			return nil
		}
		if attempt == 0 {
			time.Sleep(500 * time.Millisecond)
		}
	}
	return lastErr
}

func (c *Collector) post(ctx context.Context, path string, body interface{}) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.server+path, strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+c.agentKey)
	request.Header.Set("X-Lyflow-Agent-ID", c.agentID)
	response, err := c.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("%s returned %d", path, response.StatusCode)
	}
	return nil
}

func mustJSON(value interface{}) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func flowPayload(record Record) map[string]interface{} {
	src := stringValue(record["src_ip"])
	dst := stringValue(record["dst_ip"])
	if src == "" || dst == "" {
		return nil
	}
	srcPort := intValue(record["src_port"])
	dstPort := intValue(record["dst_port"])
	protocol := protocolName(intValue(record["protocol"]))
	return map[string]interface{}{
		"id":         stringValue(record["id"]),
		"event_type": "flows:semantic.event",
		"timestamp":  stringValue(record["timestamp"]),
		"agent_id":   "",
		"src_ip":     src,
		"dst_ip":     dst,
		"src_port":   srcPort,
		"dst_port":   dstPort,
		"protocol":   protocol,
		"bytes":      intValue(record["bytes"]),
		"bytes_total": intValue(record["bytes"]),
		"packets":    intValue(record["packets"]),
		"source":     "lyprobe",
		"engine":     "lyprobe",
		"threat_type": stringValue(record["threat_type"]),
		"threat_name": stringValue(record["threat_name"]),
	}
}

func threatPayload(record Record, agentID string) map[string]interface{} {
	ruleName := stringValue(record["threat_name"])
	ruleType := stringValue(record["threat_type"])
	if ruleName == "" && ruleType == "" {
		return nil
	}
	src := stringValue(record["src_ip"])
	dst := stringValue(record["dst_ip"])
	if src == "" || dst == "" {
		return nil
	}
	ruleID := ruleName
	if ruleID == "" {
		ruleID = ruleType
	}
	severity := "medium"
	score := 55
	switch strings.ToUpper(ruleType) {
	case "MALWARE", "TROJAN", "C2", "EXPLOIT":
		severity = "high"
		score = 75
	case "WEB", "SCAN":
		severity = "medium"
	}
	return map[string]interface{}{
		"schema_version": "lyflow.component_alert.v1",
		"id":             "lyprobe-" + stringValue(record["id"]),
		"category":       "traffic",
		"source_engine":  "dpi_engine",
		"rule_id":        ruleID,
		"rule_name":      ruleName,
		"native_rule": map[string]interface{}{
			"engine": "dpi_engine", "id": ruleID, "name": ruleName,
			"category": ruleType, "source": "lyprobe",
		},
		"severity":    severity,
		"score_hint":  score,
		"occurred_at": stringValue(record["timestamp"]),
		"source":      "lyprobe",
		"summary":     fmt.Sprintf("%s %s:%d -> %s:%d", ruleName, src, intValue(record["src_port"]), dst, intValue(record["dst_port"])),
		"entities": map[string]interface{}{
			"agent_id": agentID, "source_ip": src, "target_ip": dst,
		},
		"details": map[string]interface{}{
			"protocol": protocolName(intValue(record["protocol"])),
			"bytes":    intValue(record["bytes"]), "packets": intValue(record["packets"]),
			"threat_type": ruleType, "threat_version": stringValue(record["threat_version"]),
		},
		"action":        "audit",
		"policy_state":  "audit_only",
		"candidate_only": false,
	}
}

func protocolName(value int64) string {
	switch value {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	default:
		return fmt.Sprintf("%d", value)
	}
}

func stringValue(value interface{}) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func intValue(value interface{}) int64 {
	switch typed := value.(type) {
	case int:
		return int64(typed)
	case int64:
		return typed
	case uint16:
		return int64(typed)
	case float64:
		return int64(typed)
	case uint32:
		return int64(typed)
	default:
		return 0
	}
}
