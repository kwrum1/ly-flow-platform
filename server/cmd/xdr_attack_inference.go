package main

import (
	"strings"

	"github.com/lyflow/ly-flow-platform/contracts"
)

func canonicalXDRInformational(event contracts.CanonicalSecurityEvent, payload map[string]interface{}) bool {
	haystack := strings.ToLower(strings.Join([]string{
		event.EventType,
		xdrPickString(payload, "event_type", "rule_id", "rule_name", "summary", "scan_status", "source"),
	}, " "))
	return strings.Contains(haystack, "heartbeat") || strings.Contains(haystack, "healthcheck") || strings.Contains(haystack, "scanner.health")
}

func inferCanonicalAttackMapping(event contracts.CanonicalSecurityEvent, payload map[string]interface{}) (string, string, string) {
	if event.Attack.TechniqueID != "" && event.Attack.TacticID != "" {
		return event.Attack.TechniqueID, event.Attack.TacticID, ""
	}
	haystack := strings.ToLower(strings.Join([]string{
		event.EventType, string(event.Provenance.Source),
		xdrPickString(payload, "event_type", "rule_id", "rule_name", "summary", "source", "source_engine", "details.decoder", "details.file_path"),
	}, " "))
	switch {
	case strings.Contains(haystack, "5715"), strings.Contains(haystack, "root login"), strings.Contains(haystack, "accepted password"), strings.Contains(haystack, "accepted publickey"):
		return "T1078", "TA0001", "initial_access"
	case strings.Contains(haystack, "5402"), strings.Contains(haystack, "sudo"), strings.Contains(haystack, "privilege escalation"):
		return "T1548.003", "TA0004", "privilege_escalation"
	case strings.Contains(haystack, "yara"), strings.Contains(haystack, "malware"), strings.Contains(haystack, "file scanner"):
		return "T1204.002", "TA0002", "execution"
	case strings.Contains(haystack, "rasp") && (strings.Contains(haystack, "command") || strings.Contains(haystack, "exec")):
		return "T1059", "TA0002", "execution"
	case strings.Contains(haystack, "port scan"), strings.Contains(haystack, "network scan"), strings.Contains(haystack, "recon"):
		return "T1046", "TA0043", "recon"
	case strings.Contains(haystack, "exploit"), strings.Contains(haystack, "web attack"):
		return "T1190", "TA0001", "initial_access"
	case strings.Contains(haystack, "shell"), strings.Contains(haystack, "command exec"), strings.Contains(haystack, "process exec"):
		return "T1059", "TA0002", "execution"
	default:
		return event.Attack.TechniqueID, event.Attack.TacticID, ""
	}
}
