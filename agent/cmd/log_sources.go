package main

import (
	"bufio"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

// Native log collection. Wazuh's logcollector is replaced here: the agent
// tails configured files, parses the format it knows (nginx access/error, auth
// logs) and publishes the same telemetry envelope the rest of the pipeline
// consumes. No external manager is required.
//
// LOG_SOURCES format: "name:path[,name:path...]"
//
//	nginx-access:/var/log/lyflow/access.log
//	nginx-error:/var/log/lyflow/error.log
//	auth:/var/log/auth.log
type logSourceSpec struct {
	Name    string
	Path    string
	Program string
}

func parseLogSources(raw string) []logSourceSpec {
	specs := make([]logSourceSpec, 0, 4)
	seen := map[string]bool{}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.SplitN(item, ":", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
			continue
		}
		name := strings.TrimSpace(parts[0])
		path := strings.TrimSpace(parts[1])
		if seen[path] {
			continue
		}
		seen[path] = true
		program := name
		if strings.HasPrefix(name, "nginx") {
			program = "nginx"
		}
		specs = append(specs, logSourceSpec{Name: name, Path: path, Program: program})
	}
	return specs
}

// nginxCombinedRe matches the default nginx "combined" access log line.
var nginxCombinedRe = regexp.MustCompile(
	`^(\S+) \S+ (\S+) \[([^\]]+)\] "([A-Z]+) (\S+) [^"]*" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?`,
)

var nginxErrorRe = regexp.MustCompile(
	`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] [^:]+: (.+)$`,
)

func (a *Agent) runLogSources() {
	specs := parseLogSources(os.Getenv("LOG_SOURCES"))
	if len(specs) == 0 {
		return
	}
	fmt.Printf("[log] native collectors active: %d source(s)\n", len(specs))
	offsets := map[string]int64{}
	initialized := map[string]bool{}
	a.collectLogSources(specs, offsets, initialized)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.collectLogSources(specs, offsets, initialized)
		}
	}
}

func (a *Agent) collectLogSources(specs []logSourceSpec, offsets map[string]int64, initialized map[string]bool) {
	for _, spec := range specs {
		handle, err := os.Open(spec.Path)
		if err != nil {
			continue
		}
		info, err := handle.Stat()
		if err != nil {
			handle.Close()
			continue
		}
		size := info.Size()
		offset := offsets[spec.Path]
		if !initialized[spec.Path] {
			// Start at the current end so a restart does not replay history.
			initialized[spec.Path] = true
			offsets[spec.Path] = size
			handle.Close()
			continue
		}
		if size < offset {
			offset = 0
		}
		if _, err := handle.Seek(offset, io.SeekStart); err != nil {
			handle.Close()
			continue
		}
		reader := bufio.NewReaderSize(handle, 64*1024)
		consumed := int64(0)
		published := 0
		for published < 500 {
			line, readErr := reader.ReadString('\n')
			if !strings.HasSuffix(line, "\n") {
				// Leave a partial line for the next tick; do not advance.
				break
			}
			consumed += int64(len(line))
			published++
			a.publishLogLine(spec, strings.TrimRight(line, "\r\n"))
			if readErr != nil {
				break
			}
		}
		offsets[spec.Path] = offset + consumed
		handle.Close()
	}
}

func (a *Agent) publishLogLine(spec logSourceSpec, line string) {
	if strings.TrimSpace(line) == "" {
		return
	}
	message := line
	if spec.Name == "nginx-access" {
		// Decode the request so rules see "union select" instead of
		// "union+select" and "../" instead of the raw escape.
		decoded := strings.ReplaceAll(line, "+", " ")
		if unescaped, err := url.QueryUnescape(decoded); err == nil {
			decoded = unescaped
		}
		message = decoded
	}
	fields := map[string]interface{}{
		"agent_id":   a.agentID,
		"hostname":   a.hostname,
		"source":     spec.Program,
		"program":    spec.Program,
		"message":    message,
		"log_path":   spec.Path,
		"event_type": "log." + spec.Name,
	}
	entity := contracts.EntityRef{
		AgentID:  a.agentID,
		HostID:   a.hostname,
		Hostname: a.hostname,
		TargetIP: a.localIP,
	}
	if spec.Name == "nginx-access" {
		fields["raw_message"] = line
	}

	switch {
	case spec.Name == "nginx-access":
		if match := nginxCombinedRe.FindStringSubmatch(line); match != nil {
			entity.SourceIP = match[1]
			fields["src_ip"] = match[1]
			fields["remote_user"] = match[2]
			fields["method"] = match[4]
			fields["path"] = match[5]
			fields["http_path"] = match[5]
			fields["status"] = match[6]
			fields["bytes"] = match[7]
			if len(match) > 9 {
				fields["referer"] = match[8]
				fields["user_agent"] = match[9]
			}
			fields["event_type"] = "log.nginx.access"
		}
	case spec.Name == "nginx-error":
		if match := nginxErrorRe.FindStringSubmatch(line); match != nil {
			fields["level"] = match[2]
			fields["detail"] = match[3]
			fields["event_type"] = "log.nginx.error"
			if client := regexp.MustCompile(`client: (\S+)`).FindStringSubmatch(match[3]); client != nil {
				entity.SourceIP = client[1]
				fields["src_ip"] = client[1]
			}
			if status := regexp.MustCompile(`request: "[^"]*"?,? ?status: (\d{3})`).FindStringSubmatch(match[3]); status != nil {
				fields["status"] = status[1]
			}
		}
	}

	now := time.Now().UTC()
	eventType := strings.TrimSpace(fmt.Sprint(fields["event_type"]))
	envelope := contracts.TelemetryEnvelope{
		SchemaVersion: contracts.TelemetrySchemaVersion,
		ID:            fmt.Sprintf("log-%s-%s-%d", spec.Name, a.agentID, now.UnixNano()),
		Category:      contracts.TelemetryLogAudit,
		EventType:     eventType,
		ObservedAt:    now,
		ReceivedAt:    now,
		Source:        spec.Program,
		Entities:      entity,
		RawReference:  &contracts.RawReference{Stream: "logs:raw", Path: spec.Path, EventType: spec.Name},
		Fields:        fields,
		Excerpt:       truncateForMetadata(message, 280),
	}

	if err := a.publishAgentStream(a.ctx, "logs:raw", structToMap(envelope), "log_raw"); err != nil {
		a.handleControlHealth(a.runtimeHealth.Degrade("observation_delivery_unavailable", false))
		return
	}
	if strings.TrimSpace(a.cfg.LogAuditTelemetryStream) == "" {
		return
	}
	if err := a.publishAgentStream(a.ctx, a.cfg.LogAuditTelemetryStream, structToMap(envelope), "telemetry_log_audit"); err != nil {
		a.handleControlHealth(a.runtimeHealth.Degrade("observation_delivery_unavailable", false))
	}
}
