// Package attack maps rule metadata and tags to ATT&CK tactics, techniques and
// LyFlow kill-chain stages. It is intentionally data-only: no I/O, no globals
// mutated at runtime.
package attack

import (
	"strings"

	"github.com/lyflow/ly-flow-platform/contracts"
)

type Tactic struct {
	ID   string
	Name string
}

type Technique struct {
	ID       string
	Name     string
	TacticID string
}

var Tactics = []Tactic{
	{"TA0043", "Reconnaissance"},
	{"TA0042", "Resource Development"},
	{"TA0001", "Initial Access"},
	{"TA0002", "Execution"},
	{"TA0003", "Persistence"},
	{"TA0004", "Privilege Escalation"},
	{"TA0005", "Defense Evasion"},
	{"TA0006", "Credential Access"},
	{"TA0007", "Discovery"},
	{"TA0008", "Lateral Movement"},
	{"TA0009", "Collection"},
	{"TA0011", "Command and Control"},
	{"TA0010", "Exfiltration"},
	{"TA0040", "Impact"},
}

var Techniques = []Technique{
	{"T1190", "Exploit Public-Facing Application", "TA0001"},
	{"T1566", "Phishing", "TA0001"},
	{"T1195", "Supply Chain Compromise", "TA0001"},
	{"T1199", "Trusted Relationship", "TA0001"},
	{"T1078", "Valid Accounts", "TA0001"},
	{"T1078.001", "Default Accounts", "TA0001"},
	{"T1078.002", "Domain Accounts", "TA0001"},
	{"T1078.003", "Local Accounts", "TA0001"},
	{"T1078.004", "Cloud Accounts", "TA0001"},
	{"T1059", "Command and Scripting Interpreter", "TA0002"},
	{"T1059.001", "PowerShell", "TA0002"},
	{"T1059.003", "Windows Command Shell", "TA0002"},
	{"T1059.004", "Unix Shell", "TA0002"},
	{"T1059.006", "Python", "TA0002"},
	{"T1203", "Exploitation for Client Execution", "TA0002"},
	{"T1204", "User Execution", "TA0002"},
	{"T1106", "Native API", "TA0002"},
	{"T1505.003", "Web Shell", "TA0003"},
	{"T1543.003", "Windows Service", "TA0003"},
	{"T1547.001", "Registry Run Keys / Startup Folder", "TA0003"},
	{"T1053", "Scheduled Task/Job", "TA0003"},
	{"T1098", "Account Manipulation", "TA0003"},
	{"T1136", "Create Account", "TA0003"},
	{"T1546", "Event Triggered Execution", "TA0003"},
	{"T1068", "Exploitation for Privilege Escalation", "TA0004"},
	{"T1548", "Abuse Elevation Control Mechanism", "TA0004"},
	{"T1055", "Process Injection", "TA0005"},
	{"T1134", "Access Token Manipulation", "TA0005"},
	{"T1562", "Impair Defenses", "TA0005"},
	{"T1070", "Indicator Removal", "TA0005"},
	{"T1112", "Modify Registry", "TA0005"},
	{"T1027", "Obfuscated Files or Information", "TA0005"},
	{"T1110", "Brute Force", "TA0006"},
	{"T1110.001", "Password Guessing", "TA0006"},
	{"T1003", "OS Credential Dumping", "TA0006"},
	{"T1558", "Steal or Forge Kerberos Tickets", "TA0006"},
	{"T1552", "Unsecured Credentials", "TA0006"},
	{"T1046", "Network Service Discovery", "TA0007"},
	{"T1018", "Remote System Discovery", "TA0007"},
	{"T1087", "Account Discovery", "TA0007"},
	{"T1082", "System Information Discovery", "TA0007"},
	{"T1021.001", "Remote Desktop Protocol", "TA0008"},
	{"T1021.002", "SMB/Windows Admin Shares", "TA0008"},
	{"T1021.003", "Distributed Component Object Model", "TA0008"},
	{"T1021.004", "SSH", "TA0008"},
	{"T1550", "Use Alternate Authentication Material", "TA0008"},
	{"T1005", "Data from Local System", "TA0009"},
	{"T1560", "Archive Collected Data", "TA0009"},
	{"T1071.001", "Web Protocols", "TA0011"},
	{"T1105", "Ingress Tool Transfer", "TA0011"},
	{"T1572", "Protocol Tunneling", "TA0011"},
	{"T1090", "Proxy", "TA0011"},
	{"T1041", "Exfiltration Over C2 Channel", "TA0010"},
	{"T1048", "Exfiltration Over Alternative Protocol", "TA0010"},
	{"T1486", "Data Encrypted for Impact", "TA0040"},
	{"T1490", "Inhibit System Recovery", "TA0040"},
}

var (
	tacticByID    = indexTactics()
	techniqueByID = indexTechniques()
)

func indexTactics() map[string]Tactic {
	result := make(map[string]Tactic, len(Tactics))
	for _, tactic := range Tactics {
		result[tactic.ID] = tactic
	}
	return result
}

func indexTechniques() map[string]Technique {
	result := make(map[string]Technique, len(Techniques))
	for _, technique := range Techniques {
		result[technique.ID] = technique
	}
	return result
}

func TacticByID(id string) (Tactic, bool) {
	tactic, ok := tacticByID[normalizeID(id)]
	return tactic, ok
}

func TechniqueByID(id string) (Technique, bool) {
	technique, ok := techniqueByID[normalizeID(id)]
	return technique, ok
}

type Input struct {
	RuleID     string
	RuleSource string
	Metadata   map[string]string
	Tags       []string
}

type Mapping struct {
	TacticID    string
	TechniqueID string
	Stage       contracts.AttackStage
	Confidence  float64
	Source      string
}

// RuleFallbacks is an optional rule-id to mapping table for rules that carry no
// ATT&CK metadata. Keep it small and review every entry; unknown is better than
// a guessed technique.
var RuleFallbacks = map[string]Mapping{}

func Resolve(input Input) Mapping {
	return ResolveWithFallback(input, RuleFallbacks)
}

func ResolveWithFallback(input Input, fallbacks map[string]Mapping) Mapping {
	technique, techniqueSource := resolveTechnique(input)
	tactic, tacticSource := resolveTactic(input)

	if technique != "" {
		if known, ok := techniqueByID[technique]; ok {
			if tactic == "" {
				tactic = known.TacticID
				tacticSource = "technique"
			}
			return Mapping{
				TacticID: tactic, TechniqueID: technique,
				Stage: contracts.StageForTactic(tactic), Confidence: 0.8, Source: firstSource(techniqueSource, tacticSource),
			}
		}
		if tactic != "" {
			return Mapping{
				TacticID: tactic, TechniqueID: technique,
				Stage: contracts.StageForTactic(tactic), Confidence: 0.7, Source: firstSource(techniqueSource, tacticSource),
			}
		}
	}

	if tactic != "" {
		return Mapping{
			TacticID: tactic, Stage: contracts.StageForTactic(tactic),
			Confidence: 0.6, Source: tacticSource,
		}
	}

	if fallback, ok := fallbacks[strings.TrimSpace(input.RuleID)]; ok {
		return fallback
	}

	return Mapping{Stage: contracts.StageUnknown, Confidence: 0, Source: "unmapped"}
}

func resolveTechnique(input Input) (string, string) {
	if value := metadataValue(input.Metadata,
		"mitre_technique_id", "mitre_technique", "attack.technique", "technique_id"); value != "" {
		return normalizeID(value), "metadata"
	}
	if value := tagValue(input.Tags,
		"attack.technique:", "mitre.technique:", "mitre:"); value != "" {
		return normalizeID(value), "tag"
	}
	return "", ""
}

func resolveTactic(input Input) (string, string) {
	if value := metadataValue(input.Metadata,
		"mitre_tactic_id", "mitre_tactic", "attack.tactic", "tactic_id"); value != "" {
		return normalizeID(value), "metadata"
	}
	if value := tagValue(input.Tags,
		"attack.tactic:", "mitre.tactic:"); value != "" {
		return normalizeID(value), "tag"
	}
	return "", ""
}

func metadataValue(metadata map[string]string, keys ...string) string {
	for key, value := range metadata {
		normalized := strings.ToLower(strings.TrimSpace(key))
		for _, expected := range keys {
			if normalized == expected {
				return strings.TrimSpace(value)
			}
		}
	}
	return ""
}

func tagValue(tags []string, prefixes ...string) string {
	for _, tag := range tags {
		trimmed := strings.TrimSpace(tag)
		lower := strings.ToLower(trimmed)
		for _, prefix := range prefixes {
			if strings.HasPrefix(lower, prefix) {
				return strings.TrimSpace(trimmed[len(prefix):])
			}
		}
		upper := strings.ToUpper(trimmed)
		if strings.HasPrefix(upper, "TA") && len(upper) == 6 {
			return upper
		}
		if strings.HasPrefix(upper, "T") && (len(upper) == 5 || len(upper) == 9) {
			return upper
		}
	}
	return ""
}

func normalizeID(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}

func firstSource(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return "unmapped"
}
