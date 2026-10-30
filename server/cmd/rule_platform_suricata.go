package main

import (
	"bufio"
	"regexp"
	"strings"
)

func parseSuricataRules(content, prefix string) []map[string]interface{} {
	out := []map[string]interface{}{}
	scanner := bufio.NewScanner(strings.NewReader(content))
	scanner.Buffer(make([]byte, 0, 1024*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		openIndex, closeIndex := strings.Index(line, "("), strings.LastIndex(line, ")")
		if line == "" || strings.HasPrefix(line, "#") || openIndex < 0 || closeIndex <= openIndex {
			continue
		}
		header := line[:openIndex]
		metadata := line[openIndex+1 : closeIndex]
		if rule := parseSuricataRuleLine(metadata, prefix); len(rule) > 0 {
			rule["source_dest_port"] = suricataHeaderDestPort(header)
			rule["source_flow"] = suricataOption(metadata, `flow\s*:\s*([^;]+)`)
			rule["source_match_options"] = suricataLostMatchOptions(metadata)
			out = append(out, rule)
			if len(out) >= 1000 {
				break
			}
		}
	}
	return out
}

// suricataHeaderDestPort extracts the destination port token from a rule
// header so the conversion can tell whether it drops a real port restriction.
func suricataHeaderDestPort(header string) string {
	fields := strings.Fields(header)
	if len(fields) < 7 {
		return ""
	}
	return strings.TrimSpace(fields[6])
}

// suricataLostMatchOptions lists Suricata options that the flattened
// field/pattern runtime cannot enforce. Their presence means the converted
// rule is broader than the original signature.
func suricataLostMatchOptions(metadata string) []string {
	out := []string{}
	lower := strings.ToLower(metadata)
	for _, key := range []string{"dsize", "offset", "depth", "distance", "within", "byte_test", "byte_jump", "isdataat", "urilen", "threshold", "file_data", "pkt_data"} {
		if strings.Contains(lower, key+":") || strings.Contains(lower, key+" :") {
			out = append(out, key)
		}
	}
	return out
}

func parseSuricataRuleLine(metadata, prefix string) map[string]interface{} {
	sid := suricataOption(metadata, `sid\s*:\s*([0-9]+)`)
	if sid == "" {
		return nil
	}
	message := firstNonEmpty(suricataOption(metadata, `msg\s*:\s*"([^"]+)"`), prefix+" rule "+sid)
	field := suricataField(metadata)
	value, operator := suricataPattern(metadata)
	conditions := suricataStructuredConditions(metadata)
	if value == "" && len(conditions) > 0 {
		field = asString(conditions[0]["field"])
		value = asString(conditions[0]["value"])
		operator = asString(conditions[0]["operator"])
	}
	if value == "" {
		return nil
	}
	return map[string]interface{}{
		"id": prefix + "-" + sid, "name": message, "category": "traffic",
		"severity": severityFromSuricataMessage(message), "stage_hint": inferRuleStage("traffic", message+" "+value),
		"field": field, "operator": operator, "value": value, "regex": operator == "regex",
		"conditions": conditions, "source_operator": "suricata", "candidate": true,
	}
}

func suricataOption(metadata, pattern string) string {
	match := regexp.MustCompile(pattern).FindStringSubmatch(metadata)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}

func suricataField(metadata string) string {
	switch {
	case strings.Contains(metadata, "dns.query") || strings.Contains(metadata, "dns_query"):
		return "dns_query"
	case strings.Contains(metadata, "tls.sni") || strings.Contains(metadata, "tls_sni"):
		return "tls_sni"
	case strings.Contains(metadata, "http.host") || strings.Contains(metadata, "http_host"):
		return "http_host"
	case strings.Contains(metadata, "http.uri") || strings.Contains(metadata, "http.url") || strings.Contains(metadata, "http_uri") || strings.Contains(metadata, "http_raw_uri"):
		return "http_path"
	default:
		return "payload"
	}
}

func suricataPattern(metadata string) (string, string) {
	if pattern := suricataOption(metadata, `pcre\s*:\s*"/([^"/]+)/[A-Za-z]*"`); pattern != "" {
		return pattern, "regex"
	}
	if pattern := suricataOption(metadata, `content\s*:\s*"([^"]+)"`); pattern != "" {
		return decodeSuricataContent(pattern), "contains"
	}
	return "", ""
}

func suricataStructuredConditions(metadata string) []map[string]interface{} {
	conditions := []map[string]interface{}{}
	for _, option := range []struct {
		field   string
		pattern string
	}{
		{field: "dcerpc.iface", pattern: `dcerpc\.iface\s*:\s*([0-9A-Fa-f-]+)`},
		{field: "dcerpc.opnum", pattern: `dcerpc\.opnum\s*:\s*([0-9]+)`},
	} {
		if value := suricataOption(metadata, option.pattern); value != "" {
			conditions = append(conditions, map[string]interface{}{"field": option.field, "operator": "equals", "value": value})
		}
	}
	return conditions
}

func decodeSuricataContent(content string) string {
	replacements := map[string]string{"|20": " ", "|2f": "/", "|2F": "/", "|3a": ":", "|3A": ":", "|2e": ".", "|2E": "."}
	for old, newValue := range replacements {
		content = strings.ReplaceAll(content, old, newValue)
	}
	return strings.TrimSpace(content)
}

func severityFromSuricataMessage(message string) string {
	lower := strings.ToLower(message)
	switch {
	case strings.Contains(lower, "trojan") || strings.Contains(lower, "malware") || strings.Contains(lower, "exploit"):
		return "high"
	case strings.Contains(lower, "scan") || strings.Contains(lower, "policy") || strings.Contains(lower, "info"):
		return "low"
	default:
		return "medium"
	}
}
