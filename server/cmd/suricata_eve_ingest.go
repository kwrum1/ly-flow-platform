package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
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
				if err := ingestSuricataEVELine(ctx, cfg, line); err != nil {
					// Keep the pipeline alive on malformed lines / transient DB
					// errors. The line is dropped rather than blocking rotation.
					log.Printf("[suricata-eve] ingest skipped: %v", err)
				}
			}
			offset += int64(len(chunk))
			saveSuricataEVEState(statePath, suricataEVEIngestState{Path: path, Inode: inode, Offset: offset})
		}
	}()
}

func ingestSuricataEVELine(ctx context.Context, cfg *Config, line string) error {
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
	raw, err := json.Marshal(sanitizeSuricataAlert(event, signature, severity))
	if err != nil {
		return err
	}
	_, err = cfg.DBPool.Exec(ctx, `INSERT INTO threat_events (event_uid, category, severity, source_engine, event_type, agent_id, src_ip, dst_ip, message, observed_at, raw_event, updated_at)
		VALUES ($1,'traffic',$2,'suricata',$3,'local',$4,$5,$6,$7,$8::jsonb,NOW())
		ON CONFLICT (event_uid) DO NOTHING`,
		uid, severity, signature, asString(event["src_ip"]), asString(event["dest_ip"]), signature, observed, string(raw))
	if err != nil {
		return fmt.Errorf("insert suricata alert uid=%s: %w", uid, err)
	}
	return nil
}

func sanitizeSuricataAlert(event map[string]interface{}, signature, severity string) map[string]interface{} {
	out := map[string]interface{}{
		"category":      "traffic",
		"severity":      severity,
		"source_engine": "suricata",
		"event_type":    signature,
		"message":       signature,
		"agent_id":      "local",
		"src_ip":        asString(event["src_ip"]),
		"dst_ip":        asString(event["dest_ip"]),
		"src_port":      asInt(event["src_port"]),
		"dst_port":      asInt(event["dest_port"]),
		"protocol":      asString(event["proto"]),
		"app_proto":     asString(event["app_proto"]),
		"timestamp":     asString(event["timestamp"]),
		"eve":           event,
	}
	if dns := asMap(event["dns"]); len(dns) > 0 {
		out["dns"] = dns
	}
	if http := asMap(event["http"]); len(http) > 0 {
		out["http"] = http
	}
	return out
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
