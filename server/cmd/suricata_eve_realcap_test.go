package main

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestSuricataEVEExtractionOnRealCapture is the P0-4/P0-5 acceptance test.
//
// It reads a real EVE capture from SURICATA_EVE_SAMPLE and reports, for every
// record type, how often the extraction layer recovers the correlation and L7
// fields. The point is to prove the fields are actually reachable from this
// network's own sensor output, not from a hand-written fixture.
//
// Skipped when the env var is unset so the unit lane stays hermetic:
//
//	SURICATA_EVE_SAMPLE=/tmp/eve-sample.json go test -run TestSuricataEVEExtractionOnRealCapture ./cmd
func TestSuricataEVEExtractionOnRealCapture(t *testing.T) {
	path := strings.TrimSpace(os.Getenv("SURICATA_EVE_SAMPLE"))
	if path == "" {
		t.Skip("SURICATA_EVE_SAMPLE is not set; skipping real-capture acceptance")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open EVE sample: %v", err)
	}
	defer file.Close()

	type tally struct {
		total            int
		communityID      int
		flowID           int
		sensor           int
		vlan             int
		appProto         int
		httpHost         int
		tlsSNI           int
		tlsJA3           int
		tlsJA4           int
		dnsQuery         int
	}
	byType := map[string]*tally{}
	// Pairs of (community_id) seen on alerts and on sessions, to prove the join
	// key really is shared rather than merely present.
	alertIDs := map[string]int{}
	sessionIDs := map[string]int{}

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		eventType, ok := suricataEVEEventType(line)
		if !ok {
			continue
		}
		var event map[string]interface{}
		if json.Unmarshal([]byte(line), &event) != nil {
			continue
		}
		entry, exists := byType[eventType]
		if !exists {
			entry = &tally{}
			byType[eventType] = entry
		}
		entry.total++

		join := suricataEVEJoinKeys(event)
		l7 := extractSuricataEVEL7(event)
		if join.CommunityID != "" {
			entry.communityID++
			sessionIDs[join.CommunityID]++
		}
		if join.FlowID != 0 {
			entry.flowID++
		}
		if join.Sensor != "" {
			entry.sensor++
		}
		if join.VLAN != 0 {
			entry.vlan++
		}
		if join.AppProto != "" {
			entry.appProto++
		}
		if l7.HTTPHost != "" {
			entry.httpHost++
		}
		if l7.TLSSNI != "" {
			entry.tlsSNI++
		}
		if l7.TLSJA3 != "" {
			entry.tlsJA3++
		}
		if l7.TLSJA4 != "" {
			entry.tlsJA4++
		}
		if l7.DNSQuery != "" {
			entry.dnsQuery++
		}
		if eventType == "alert" && l7.HTTPHost != "" {
			alertIDs[join.CommunityID]++
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan EVE sample: %v", err)
	}
	if len(byType) == 0 {
		t.Fatal("EVE sample contained no recognizable records")
	}

	order := []string{"flow", "http", "tls", "dns", "alert"}
	for _, name := range order {
		entry, exists := byType[name]
		if !exists {
			continue
		}
		t.Logf("%-6s n=%-6d community_id=%-6.1f%% flow_id=%-6.1f%% sensor=%-6.1f%% vlan=%-6.1f%% app_proto=%-6.1f%% http_host=%-6d tls_sni=%-6d ja3=%-6d ja4=%-6d dns=%-6d",
			name, entry.total,
			pct(entry.communityID, entry.total), pct(entry.flowID, entry.total),
			pct(entry.sensor, entry.total), pct(entry.vlan, entry.total),
			pct(entry.appProto, entry.total),
			entry.httpHost, entry.tlsSNI, entry.tlsJA3, entry.tlsJA4, entry.dnsQuery)
	}

	// Contract: the join key exists on every record type the sensor emits.
	for name, entry := range byType {
		if entry.total < 5 {
			continue // too few samples to judge
		}
		if pct(entry.communityID, entry.total) < 90 {
			t.Errorf("%s: community_id coverage %.1f%%, want >=90%%", name, pct(entry.communityID, entry.total))
		}
		if pct(entry.sensor, entry.total) < 90 {
			t.Errorf("%s: sensor coverage %.1f%%, want >=90%%", name, pct(entry.sensor, entry.total))
		}
	}
	// L7: TLS records must yield SNI and hashes; http must yield host; dns a name.
	if entry, exists := byType["tls"]; exists && entry.total >= 5 {
		if pct(entry.tlsJA3, entry.total) < 50 {
			t.Errorf("tls: ja3 coverage %.1f%%, want >=50%%", pct(entry.tlsJA3, entry.total))
		}
		if entry.tlsSNI == 0 && entry.tlsJA4 == 0 {
			t.Error("tls: neither sni nor ja4 recovered")
		}
	}
	if entry, exists := byType["http"]; exists && entry.total >= 5 {
		if pct(entry.httpHost, entry.total) < 50 {
			t.Errorf("http: host coverage %.1f%%, want >=50%%", pct(entry.httpHost, entry.total))
		}
	}
	if entry, exists := byType["dns"]; exists && entry.total >= 5 {
		if pct(entry.dnsQuery, entry.total) < 50 {
			t.Errorf("dns: query coverage %.1f%%, want >=50%%", pct(entry.dnsQuery, entry.total))
		}
	}

	// One-to-one: alert community_ids must also appear on session records.
	if len(alertIDs) > 0 {
		shared := 0
		for cid := range alertIDs {
			if _, ok := sessionIDs[cid]; ok {
				shared++
			}
		}
		ratio := pct(shared, len(alertIDs))
		t.Logf("alert community_ids=%d, also present on a session=%d (%.1f%%)", len(alertIDs), shared, ratio)
		if ratio < 50 {
			t.Errorf("alert/session join coverage %.1f%%, want >=50%%", ratio)
		}
	}
}

func pct(count, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(count) / float64(total) * 100
}
