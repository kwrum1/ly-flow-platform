package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

const defaultSuricataEVEPath = "/app/.sisyphus/runtime/engine-outputs/suricata-profile/eve.json"

type suricataEVEIngestState struct {
	Path   string `json:"path"`
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
}

func suricataEVEInode(info os.FileInfo) uint64 {
	if info == nil {
		return 0
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Ino
	}
	return 0
}

func loadSuricataEVEState(path string) (suricataEVEIngestState, bool) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return suricataEVEIngestState{}, false
	}
	var state suricataEVEIngestState
	if err := json.Unmarshal(payload, &state); err != nil {
		return suricataEVEIngestState{}, false
	}
	return state, true
}

func saveSuricataEVEState(path string, state suricataEVEIngestState) {
	payload, err := json.Marshal(state)
	if err != nil {
		return
	}
	_ = os.WriteFile(path, payload, 0o644)
}

// startSuricataEVEIngest tails the sensor's eve.json and materializes alert
// records into threat_events. Without this, Suricata alerts only exist in the
// raw EVE file and never reach the UI, so log rotation would make them
// unqueryable.
func startSuricataEVEIngest(ctx context.Context, cfg *Config) {
	if cfg == nil || cfg.DBPool == nil {
		return
	}
	if strings.EqualFold(strings.TrimSpace(getEnv("SURICATA_EVE_INGEST", "true")), "false") {
		return
	}
	path := strings.TrimSpace(getEnv("SURICATA_EVE_PATH", defaultSuricataEVEPath))
	if path == "" {
		return
	}
	trustedCIDRs, proxyErr := loadTrustedProxyCIDRs(cfg)
	if proxyErr != nil {
		// XFF attribution is best-effort: without trusted proxies the packet
		// source is kept, so an empty/invalid table never breaks ingestion.
		log.Printf("[suricata-eve] trusted proxy lookup failed: %v", proxyErr)
	}
	go func() {
		statePath := strings.TrimSpace(getEnv("SURICATA_EVE_STATE_PATH", "/app/.sisyphus/runtime/suricata-eve-ingest.state"))
		state, stateOK := loadSuricataEVEState(statePath)
		var offset int64
		var lastInode uint64
		var pending string
		first := true
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			info, err := os.Stat(path)
			if err != nil {
				continue
			}
			inode := suricataEVEInode(info)
			if first {
				switch {
				case stateOK && state.Path == path && state.Inode == inode && info.Size() >= state.Offset:
					// Resume after a server restart without replaying history.
					offset = state.Offset
				case !stateOK:
					// First deployment: do not replay the whole historical file.
					offset = info.Size()
				default:
					// Rotated while the server was down; ingest the new file.
					offset = 0
				}
				lastInode = inode
				first = false
				saveSuricataEVEState(statePath, suricataEVEIngestState{Path: path, Inode: inode, Offset: offset})
				continue
			}
			if lastInode != inode || info.Size() < offset {
				// Rotation or truncation: new file starts at zero.
				offset = 0
				pending = ""
				lastInode = inode
			}
			if info.Size() <= offset {
				continue
			}
			file, err := os.Open(path)
			if err != nil {
				continue
			}
			if _, err := file.Seek(offset, io.SeekStart); err != nil {
				file.Close()
				continue
			}
			chunk, err := io.ReadAll(file)
			file.Close()
			if err != nil {
				continue
			}
			text := pending + string(chunk)
			lines := strings.Split(text, "\n")
			if len(lines) > 0 && !strings.HasSuffix(text, "\n") {
				pending = lines[len(lines)-1]
				lines = lines[:len(lines)-1]
			} else {
				pending = ""
			}
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				// Alerts materialize into threat_events; flow/http/tls/dns
				// materialize into traffic sessions. Both need the JSON decode,
				// everything else (stats, files, anomaly) is skipped at the byte
				// level. The prefilter stays fail-open for the same reason as
				// before: dropping a real record is worse than decoding one extra.
				if suricataEVELineIsAlert(line) {
					if err := ingestSuricataEVELine(ctx, cfg, line, trustedCIDRs); err != nil {
						// Keep the pipeline alive on malformed lines / transient DB
						// errors. The line is dropped rather than blocking rotation.
						log.Printf("[suricata-eve] ingest skipped: %v", err)
					}
					continue
				}
				if !suricataEVELineIsSession(line) {
					continue
				}
				if err := ingestSuricataEVESession(ctx, cfg, line); err != nil {
					log.Printf("[suricata-eve] session ingest skipped: %v", err)
				}
			}
			offset += int64(len(chunk))
			saveSuricataEVEState(statePath, suricataEVEIngestState{Path: path, Inode: inode, Offset: offset})
		}
	}()
}

// suricataEVELineIsAlert is a byte-level prefilter for EVE lines. Real sensor
// output is dominated by dns/flow/http/tls records (roughly 99% of lines), so
// decoding every line into a map just to discard it wastes nearly all of the
// ingest goroutine's CPU. This scans the raw line for an
// {"event_type": "alert"} member and rejects everything else without touching
// encoding/json.
//
// The predicate is deliberately biased towards false positives: any line that
// might carry an alert is parsed, because dropping a real alert is far worse
// than decoding one extra DNS record. It never assumes a fixed offset for
// event_type and tolerates arbitrary whitespace around the colon.
func suricataEVELineIsAlert(line string) bool {
	const key = `"event_type"`
	offset := 0
	for {
		index := strings.Index(line[offset:], key)
		if index < 0 {
			return false
		}
		cursor := offset + index + len(key)
		// A key without a following colon is not decodable JSON, so the
		// parser would reject the line anyway. Parsing it is harmless.
		for cursor < len(line) && suricataEVEIsSpace(line[cursor]) {
			cursor++
		}
		if cursor >= len(line) || line[cursor] != ':' {
			return true
		}
		cursor++
		for cursor < len(line) && suricataEVEIsSpace(line[cursor]) {
			cursor++
		}
		if cursor >= len(line) {
			return true
		}
		if line[cursor] != '"' {
			// Value is not a JSON string (malformed for EVE). Let the real
			// decoder decide instead of guessing.
			return true
		}
		cursor++
		start := cursor
		for cursor < len(line) && line[cursor] != '"' {
			if line[cursor] == '\\' {
				cursor++
			}
			cursor++
		}
		if cursor >= len(line) {
			// The line is a cut-off fragment: the value never closes, so it
			// cannot be a complete event_type yet. The tail is kept in
			// `pending` by the reader loop and re-evaluated after the next
			// chunk is appended, which is why returning false here is safe.
			return false
		}
		if strings.EqualFold(line[start:cursor], "alert") {
			return true
		}
		if strings.IndexByte(line[start:cursor], '\\') >= 0 {
			// The raw value contains JSON escapes, so a byte comparison can
			// disagree with the decoded string (e.g. "ale\u0072t"). Hand the
			// line to the real decoder rather than risk a false negative.
			return true
		}
		offset = cursor + 1
		if offset >= len(line) {
			return false
		}
	}
}

func suricataEVEIsSpace(b byte) bool {
	switch b {
	case ' ', '\t', '\r', '\n':
		return true
	default:
		return false
	}
}

func ingestSuricataEVELine(ctx context.Context, cfg *Config, line string, trustedCIDRs []*net.IPNet) error {
	var event map[string]interface{}
	if err := json.Unmarshal([]byte(line), &event); err != nil {
		return fmt.Errorf("decode eve line: %w", err)
	}
	if !strings.EqualFold(asString(event["event_type"]), "alert") {
		return nil
	}
	alert := asMap(event["alert"])
	signature := strings.TrimSpace(asString(alert["signature"]))
	if signature == "" {
		signature = "Suricata alert"
	}
	severity := suricataSignatureSeverity(signature, suricataSeverity(asInt(alert["severity"])))
	observed := parseSuricataTimestamp(asString(event["timestamp"]))
	uid := suricataAlertUID(event)
	clientIP, proxyIP, attribution := suricataSourceAttribution(event, trustedCIDRs)
	rawEvent := sanitizeSuricataAlert(event, signature, severity)
	rawEvent["src_ip"] = clientIP
	rawEvent["proxy_ip"] = proxyIP
	rawEvent["client_ip"] = clientIP
	if attribution != nil {
		rawEvent["source_attribution"] = attribution
	}
	raw, err := json.Marshal(rawEvent)
	if err != nil {
		return err
	}
	_, err = cfg.DBPool.Exec(ctx, `INSERT INTO threat_events (event_uid, category, severity, source_engine, event_type, agent_id, src_ip, dst_ip, message, observed_at, raw_event, updated_at)
		VALUES ($1,'traffic',$2,'suricata',$3,'local',$4,$5,$6,$7,$8::jsonb,NOW())
		ON CONFLICT (event_uid) DO NOTHING`,
		uid, severity, signature, clientIP, asString(event["dest_ip"]), signature, observed, string(raw))
	if err != nil {
		return fmt.Errorf("insert suricata alert uid=%s: %w", uid, err)
	}
	return nil
}

func sanitizeSuricataAlert(event map[string]interface{}, signature, severity string) map[string]interface{} {
	alert := asMap(event["alert"])
	signatureID := asInt(alert["signature_id"])
	ruleFamily := signature
	if fields := strings.Fields(signature); len(fields) >= 2 {
		ruleFamily = fields[0] + " " + fields[1]
	}
	out := map[string]interface{}{
		"category":          "traffic",
		"severity":          severity,
		"source_engine":     "suricata",
		"event_type":        signature,
		"message":           signature,
		"agent_id":          "local",
		"src_ip":            asString(event["src_ip"]),
		"dst_ip":            asString(event["dest_ip"]),
		"src_port":          asInt(event["src_port"]),
		"dst_port":          asInt(event["dest_port"]),
		"protocol":          asString(event["proto"]),
		"app_proto":         asString(event["app_proto"]),
		"timestamp":         asString(event["timestamp"]),
		"rule_id":           signatureID,
		"component_rule_id": fmt.Sprintf("%d", signatureID),
		"rule_name":         signature,
		"rule_family":       ruleFamily,
		"classtype":         asString(alert["category"]),
		"eve":               event,
	}
	if dns := asMap(event["dns"]); len(dns) > 0 {
		out["dns"] = dns
	}
	if http := asMap(event["http"]); len(http) > 0 {
		out["http"] = http
	}
	// P0-5: TLS was dropped here, which is why tls_sni / Ja3 / Ja4 coverage was
	// 0% even though the sensor emits them on every TLS handshake.
	if tls := asMap(event["tls"]); len(tls) > 0 {
		out["tls"] = tls
	}
	// P0-4: promote join keys next to the payload so a query does not have to
	// reach into eve.* to correlate an alert with its session.
	join := suricataEVEJoinKeys(event)
	l7 := extractSuricataEVEL7(event)
	out["community_id"] = join.CommunityID
	out["flow_id"] = join.FlowID
	out["sensor"] = join.Sensor
	out["vlan"] = join.VLAN
	out["app_proto"] = firstNonEmpty(join.AppProto, asString(out["app_proto"]))
	out["direction"] = l7.Direction
	out["http_host"] = l7.HTTPHost
	out["http_method"] = l7.HTTPMethod
	out["http_uri"] = l7.HTTPURI
	out["tls_sni"] = l7.TLSSNI
	out["tls_ja3"] = l7.TLSJA3
	out["tls_ja4"] = l7.TLSJA4
	out["dns_query"] = l7.DNSQuery
	// Display identity for the two endpoints.
	//
	// The UI shows "来源 → 受害服务器", and both halves were misleading:
	//   - src_ip is the proxy or the public source, while http.xff carries the
	//     real client (1767 of 11896 traffic alerts in this deployment), and
	//   - dst_ip is an internal address, while http.hostname carries the site
	//     the attacker actually targeted (9335 alerts).
	// Store an explicit display pair so the console does not have to guess, and
	// keep the raw fields untouched for traceability.
	if xff := strings.TrimSpace(asAnyMapString(asMap(event["http"]), "xff")); xff != "" {
		out["client_forwarded_for"] = xff
	}
	out["source_display"] = firstNonEmpty(
		asString(out["client_forwarded_for"]),
		asString(event["src_ip"]),
	)
	out["victim_display"] = firstNonEmpty(
		l7.HTTPHost,
		l7.TLSSNI,
		l7.DNSQuery,
		asString(event["dest_ip"]),
	)
	out["victim_ip"] = asString(event["dest_ip"])
	return out
}

// asAnyMapString reads a string member defensively; used for optional EVE
// members that may be absent or non-string.
func asAnyMapString(values map[string]interface{}, key string) string {
	if values == nil {
		return ""
	}
	return asString(values[key])
}

func suricataAlertUID(event map[string]interface{}) string {
	alert := asMap(event["alert"])
	parts := []string{
		asString(event["timestamp"]),
		asString(event["flow_id"]),
		asString(alert["signature_id"]),
		asString(event["src_ip"]),
		asString(event["dest_ip"]),
		asString(event["src_port"]),
		asString(event["dest_port"]),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return "suricata-" + hex.EncodeToString(sum[:])[:24]
}

func suricataSeverity(value int) string {
	switch value {
	case 1:
		return "high"
	case 2:
		return "medium"
	case 3:
		return "low"
	default:
		return "medium"
	}
}

func parseSuricataTimestamp(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Now().UTC()
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999-0700", "2006-01-02T15:04:05-0700"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC()
		}
	}
	return time.Now().UTC()
}

// lowValueSignaturePrefixes are ET Open families that describe policy drift or
// hunting hypotheses rather than an attack. They remain useful as context, but
// must never outrank web-attack signatures in the alert queue.
var lowValueSignaturePrefixes = []string{
	"ET INFO ", "ET POLICY ", "ET HUNTING ", "ET USER_AGENTS ",
	"ET CURRENT_EVENTS ", "ET GAMES ", "ET P2P ", "ET CHAT ", "ET SNMP ",
	"ET DNS Query for ",
}

func suricataSignatureSeverity(signature, severity string) string {
	for _, prefix := range lowValueSignaturePrefixes {
		if strings.HasPrefix(signature, prefix) {
			return "low"
		}
	}
	return severity
}
