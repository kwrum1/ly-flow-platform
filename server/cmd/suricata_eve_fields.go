package main

import (
	"strconv"
	"strings"
)

// suricataEVEJoinKeys and suricataEVEL7Facts are the P0-4/P0-5 extraction
// layer. Two rules shape them:
//
//  1. Alerts and sessions must be joinable. Suricata's EVE carries
//     community_id (stable across sensors and across a NAT boundary) and
//     flow_id (per-sensor), and both were being dropped on ingest. Without them
//     "which session does this alert belong to" could only be approximated by
//     timestamp, which cannot be verified.
//  2. L7 is what makes a session explainable. host / SNI / DNS name / JA3 / JA4
//     are already in EVE. The column was 0% populated for 15.8M sessions only
//     because ingest read them out of raw_event and then stored the blob without
//     promoting them to columns.

// suricataEVEJoinKeyValues holds the correlation identifiers of one EVE record.
type suricataEVEJoinKeyValues struct {
	CommunityID string
	FlowID      uint64
	Sensor      string
	VLAN        uint16
	AppProto    string
}

// suricataEVEL7Values holds the application-layer facts of one EVE record.
type suricataEVEL7Values struct {
	HTTPHost   string
	HTTPMethod string
	HTTPURI    string
	TLSSNI     string
	TLSJA3     string
	TLSJA4     string
	DNSQuery   string
	Direction  string
}

// suricataEVEJoinKeys extracts correlation identifiers from a decoded EVE
// record. Missing values stay zero/false rather than being invented, so a
// coverage query can tell "absent in the source" from "dropped by ingest".
func suricataEVEJoinKeys(event map[string]interface{}) suricataEVEJoinKeyValues {
	keys := suricataEVEJoinKeyValues{
		CommunityID: strings.TrimSpace(asString(event["community_id"])),
		Sensor:      strings.TrimSpace(firstNonEmpty(asString(event["in_iface"]), asString(event["host"]))),
		AppProto:    strings.ToLower(strings.TrimSpace(firstNonEmpty(asString(event["app_proto"]), asString(event["app_protocol"])))),
	}
	// flow_id arrives as float64 from encoding/json and as a string from the
	// session producer, so accept both rather than losing it on one path.
	if value, ok := event["flow_id"].(float64); ok && value >= 0 {
		keys.FlowID = uint64(value)
	} else if raw := strings.TrimSpace(asString(event["flow_id"])); raw != "" {
		if parsed, err := strconv.ParseUint(raw, 10, 64); err == nil {
			keys.FlowID = parsed
		}
	}
	if vlan, ok := firstEVENumber(event["vlan"]); ok {
		keys.VLAN = vlan
	}
	return keys
}

// extractSuricataEVEL7 pulls host / SNI / DNS name / JA3 / JA4 and the flow
// direction out of a decoded EVE record.
func extractSuricataEVEL7(event map[string]interface{}) suricataEVEL7Values {
	var values suricataEVEL7Values
	http := asMap(event["http"])
	if len(http) > 0 {
		values.HTTPHost = strings.TrimSpace(asString(http["hostname"]))
		values.HTTPMethod = strings.ToUpper(strings.TrimSpace(asString(http["http_method"])))
		values.HTTPURI = strings.TrimSpace(asString(http["url"]))
	}
	if tls := asMap(event["tls"]); len(tls) > 0 {
		values.TLSSNI = strings.TrimSpace(asString(tls["sni"]))
		// JA3 appears as {"hash": "..."} in EVE 5+, and as a bare string in
		// older output. Accept both so a sensor upgrade does not blank the field.
		if ja3 := asMap(tls["ja3"]); len(ja3) > 0 {
			values.TLSJA3 = strings.TrimSpace(asString(ja3["hash"]))
		}
		if values.TLSJA3 == "" {
			values.TLSJA3 = strings.TrimSpace(asString(tls["ja3"]))
		}
		if ja4 := asMap(tls["ja4"]); len(ja4) > 0 {
			values.TLSJA4 = strings.TrimSpace(asString(ja4["hash"]))
		}
		if values.TLSJA4 == "" {
			values.TLSJA4 = strings.TrimSpace(asString(tls["ja4"]))
		}
	}
	if dns := asMap(event["dns"]); len(dns) > 0 {
		values.DNSQuery = suricataDNSQuery(dns)
	}
	values.Direction = strings.TrimSpace(asString(event["direction"]))
	return values
}

// suricataDNSQuery resolves the queried name from an EVE DNS record.
//
// EVE v2 puts the name in dns.rrname for single-question records, but a
// multi-question record only has dns.queries[].rrname. Reading just rrname
// silently lost every multi-question DNS event.
func suricataDNSQuery(dns map[string]interface{}) string {
	if name := strings.TrimSpace(asString(dns["rrname"])); name != "" {
		return name
	}
	questions, ok := dns["queries"].([]interface{})
	if !ok {
		return ""
	}
	for _, item := range questions {
		question := asMap(item)
		if name := strings.TrimSpace(asString(question["rrname"])); name != "" {
			return name
		}
	}
	return ""
}

// firstEVENumber accepts the numeric shapes EVE uses for vlan: a scalar, or an
// array when the packet is tagged with several VLANs (outermost first).
func firstEVENumber(value interface{}) (uint16, bool) {
	switch typed := value.(type) {
	case float64:
		if typed < 0 || typed > 65535 {
			return 0, false
		}
		return uint16(typed), true
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return 0, false
		}
		parsed, err := strconv.ParseUint(trimmed, 10, 16)
		if err != nil {
			return 0, false
		}
		return uint16(parsed), true
	case []interface{}:
		for _, item := range typed {
			if result, ok := firstEVENumber(item); ok {
				return result, true
			}
		}
		return 0, false
	default:
		return 0, false
	}
}
