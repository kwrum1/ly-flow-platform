package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/server/analytics"
)

// Suricata EVE is the only source in this deployment that actually carries the
// correlation and L7 facts an alert needs:
//
//	flow / http / tls / dns records all include community_id and flow_id,
//	tls includes ja3.hash and ja4, http includes hostname, dns includes rrname.
//
// local-mirror, which produced every row in lyflow_traffic_sessions before this
// change, writes http_host / tls_sni / dns_query / community_id as empty
// strings, so those columns could never be populated from it. Measured over
// 15.8M rows: L7 and join-key non-null rate was exactly 0.
//
// This turns EVE's own records into session rows so that
// "which session does this alert belong to" is answerable by community_id
// rather than by timestamp proximity.

// suricataEVESessionEventTypes are the EVE record types that contribute a
// session row. Alerts are handled separately (they go to threat_events).
var suricataEVESessionEventTypes = map[string]bool{
	"flow": true,
	"http": true,
	"tls":  true,
	"dns":  true,
}

// suricataEVELineIsSession is the byte-level companion to
// suricataEVELineIsAlert. It must stay fail-open for the same reason: a missed
// session silently degrades correlation coverage.
func suricataEVELineIsSession(line string) bool {
	if suricataEVELineIsAlert(line) {
		return false
	}
	eventType, ok := suricataEVEEventType(line)
	if !ok {
		return false
	}
	return suricataEVESessionEventTypes[eventType]
}

// suricataEVEEventType returns the decoded event_type of a raw EVE line.
// ok=false means "could not decide", which callers treat as "not a session".
func suricataEVEEventType(line string) (string, bool) {
	const key = `"event_type"`
	index := strings.Index(line, key)
	if index < 0 {
		return "", false
	}
	cursor := index + len(key)
	for cursor < len(line) && suricataEVEIsSpace(line[cursor]) {
		cursor++
	}
	if cursor >= len(line) || line[cursor] != ':' {
		return "", false
	}
	cursor++
	for cursor < len(line) && suricataEVEIsSpace(line[cursor]) {
		cursor++
	}
	if cursor >= len(line) || line[cursor] != '"' {
		return "", false
	}
	cursor++
	start := cursor
	for cursor < len(line) && line[cursor] != '"' {
		if line[cursor] == '\\' {
			return "", false
		}
		cursor++
	}
	if cursor >= len(line) {
		return "", false
	}
	return strings.ToLower(line[start:cursor]), true
}

// suricataEVESessionTypeFilter limits which EVE session records are
// materialized. The local mirror already writes flow/dns sessions on
// installations that run it; re-ingesting the same records from EVE duplicates
// rows and starves the alert tailer. Operators can set
// SURICATA_EVE_SESSION_TYPES=http,tls to keep only the L7 records that add
// fields the mirror does not carry. The default preserves the historical
// flow,http,tls,dns behaviour.
var suricataEVESessionTypeFilter = strings.ToLower(strings.TrimSpace(getEnv("SURICATA_EVE_SESSION_TYPES", "flow,http,tls,dns")))

func suricataEVESessionTypeEnabled(eventType string) bool {
	if suricataEVESessionTypeFilter == "" || suricataEVESessionTypeFilter == "all" {
		return true
	}
	for _, item := range strings.Split(suricataEVESessionTypeFilter, ",") {
		if strings.TrimSpace(item) == eventType {
			return true
		}
	}
	return false
}

// ingestSuricataEVESession materializes a flow/http/tls/dns EVE record as one
// traffic session. The session UID is derived from the sensor-local flow_id, so
// repeatedly reading the same EVE line cannot create duplicate rows.
func ingestSuricataEVESession(ctx context.Context, cfg *Config, line string) error {
	if cfg == nil || cfg.EventStorage == nil {
		return nil
	}
	var event map[string]interface{}
	if err := json.Unmarshal([]byte(line), &event); err != nil {
		return fmt.Errorf("decode eve session line: %w", err)
	}
	eventType := strings.ToLower(strings.TrimSpace(asString(event["event_type"])))
	if !suricataEVESessionEventTypes[eventType] || !suricataEVESessionTypeEnabled(eventType) {
		return nil
	}
	join := suricataEVEJoinKeys(event)
	l7 := extractSuricataEVEL7(event)
	observed := parseSuricataTimestamp(asString(event["timestamp"]))
	if observed.IsZero() {
		observed = time.Now().UTC()
	}
	sensor := firstNonEmpty(join.Sensor, "suricata")
	flowID := join.FlowID
	uid := suricataEVESessionUID(event, eventType, sensor, flowID, observed)
	record := analytics.TrafficSessionRecord{
		SessionUID:  uid,
		Version:     uint64(observed.UnixNano()),
		ObservedAt:  observed,
		AgentID:     "local",
		Sensor:      sensor,
		SrcIP:       asString(event["src_ip"]),
		DstIP:       asString(event["dest_ip"]),
		SrcPort:     boundedTrafficPort(int64(asInt(event["src_port"]))),
		DstPort:     boundedTrafficPort(int64(asInt(event["dest_port"]))),
		Protocol:    strings.ToUpper(strings.TrimSpace(asString(event["proto"]))),
		AppProto:    firstNonEmpty(join.AppProto, eventType),
		VLAN:        join.VLAN,
		CommunityID: join.CommunityID,
		FlowID:      flowID,
		Direction:   l7.Direction,
		HTTPHost:    l7.HTTPHost,
		HTTPMethod:  l7.HTTPMethod,
		HTTPURI:     l7.HTTPURI,
		TLSSNI:      l7.TLSSNI,
		TLSJA3:      l7.TLSJA3,
		TLSJA4:      l7.TLSJA4,
		DNSQuery:    l7.DNSQuery,
		IngestedAt:  time.Now().UTC(),
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode eve session %s: %w", uid, err)
	}
	record.RawEvent = string(raw)
	if err := cfg.EventStorage.WriteTrafficSession(ctx, record); err != nil {
		return fmt.Errorf("materialize eve session %s: %w", uid, err)
	}
	return nil
}

// suricataEVESessionUID builds a stable identifier per EVE record.
//
// flow_id is only unique within one sensor and one run, so the sensor, the
// event type and the timestamp are part of the key. Alert rows reuse flow_id,
// and the join between an alert and its flow/application records is done on
// community_id plus flow_id, not on this UID.
func suricataEVESessionUID(event map[string]interface{}, eventType, sensor string, flowID uint64, observed time.Time) string {
	if flowID != 0 {
		return fmt.Sprintf("eve-%s-%s-%d", sensor, eventType, flowID)
	}
	parts := []string{
		sensor, eventType,
		strconv.FormatInt(observed.UnixNano(), 10),
		asString(event["src_ip"]), asString(event["src_port"]),
		asString(event["dest_ip"]), asString(event["dest_port"]),
		asString(event["community_id"]),
	}
	return "eve-" + sha256Short(strings.Join(parts, "|"))
}

// sha256Short returns a 24-hex-character digest, matching the alert UID width so
// both identifier families look the same in logs and queries.
func sha256Short(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:24]
}
