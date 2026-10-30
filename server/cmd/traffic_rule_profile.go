package main

// Traffic engine rule profile (P2).
//
// The platform runs two independent packet/L7 engines in the server zone:
//
//   - Suricata: full signature set, complex matchers, thresholds, flowbits.
//   - lyprobe : a small, high-confidence subset that its servicePlugin can
//     express as a single regex (converted by server/cmd/rulecompiler).
//
// This file turns a server-zone scenario plus the local rule corpus into two
// disjoint exports. Every rule gets a signature_hash; a rule may belong to
// exactly one engine, and the export fails closed if the two sets overlap.
//
// The flow-only behaviour layer (scan/beacon/DNS-tunnel/volume/rare-destination)
// stays in the security engine and is never duplicated here: detection_rules
// rows without raw signature text are reported as platform_flow_only.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lyflow/ly-flow-platform/server/rulecompiler"
	"gopkg.in/yaml.v3"
)

const (
	trafficProfileSchemaVersion  = "lyflow.traffic-profile/v1"
	trafficScenarioSchemaVersion = "lyflow.traffic-scenario/v1"
	trafficProfileDefaultName    = "server-zone"
	trafficProfileScenarioEnv    = "TRAFFIC_PROFILE_SCENARIO"
	trafficProfileRootEnv        = "TRAFFIC_PROFILE_ROOT"
	trafficProfileHomeNetEnv     = "TRAFFIC_PROFILE_HOME_NET"
	trafficProfileSuricataEnv    = "TRAFFIC_PROFILE_SURICATA_PROFILE"
)

// trafficScenario mirrors rules/scenarios/server-zone.yaml.
type trafficScenario struct {
	SchemaVersion string `yaml:"schema_version" json:"schema_version"`
	Name          string `yaml:"name" json:"name"`
	DisplayName   string `yaml:"display_name" json:"display_name"`
	Description   string `yaml:"description" json:"description"`

	HomeNet struct {
		Mode            string   `yaml:"mode" json:"mode"`
		Env             string   `yaml:"env" json:"env"`
		SuricataProfile string   `yaml:"suricata_profile" json:"suricata_profile"`
		Fallback        []string `yaml:"fallback" json:"fallback"`
		Note            string   `yaml:"note" json:"note"`
	} `yaml:"home_net" json:"home_net"`

	Directions struct {
		Inbound   bool `yaml:"inbound" json:"inbound"`
		Outbound  bool `yaml:"outbound" json:"outbound"`
		Internal  bool `yaml:"internal" json:"internal"`
		Ambiguous bool `yaml:"ambiguous" json:"ambiguous"`
	} `yaml:"directions" json:"directions"`

	Categories struct {
		Include     []string `yaml:"include" json:"include"`
		Exclude     []string `yaml:"exclude" json:"exclude"`
		ExcludeWins bool     `yaml:"exclude_wins" json:"exclude_wins"`
	} `yaml:"categories" json:"categories"`

	Protocols struct {
		Exclude []string `yaml:"exclude" json:"exclude"`
	} `yaml:"protocols" json:"protocols"`

	Ports struct {
		ExcludeInbound   []int    `yaml:"exclude_inbound" json:"exclude_inbound"`
		ExcludeDirection []string `yaml:"exclude_direction" json:"exclude_direction"`
	} `yaml:"ports" json:"ports"`

	Sources []trafficScenarioSource `yaml:"sources" json:"sources"`

	Budget trafficScenarioBudget `yaml:"budget" json:"budget"`

	Assignment struct {
		Lyprobe struct {
			MinSeverity        string   `yaml:"min_severity" json:"min_severity"`
			RequireSimpleMatch bool     `yaml:"require_simple_match" json:"require_simple_match"`
			RequireSingleMatch bool     `yaml:"require_single_match" json:"require_single_match"`
			AllowedBuffers     []string `yaml:"allowed_buffers" json:"allowed_buffers"`
			AllowedCategories  []string `yaml:"allowed_categories" json:"allowed_categories"`
		} `yaml:"lyprobe" json:"lyprobe"`
	} `yaml:"assignment" json:"assignment"`

	Exports struct {
		Root          string `yaml:"root" json:"root"`
		SuricataRules string `yaml:"suricata_rules" json:"suricata_rules"`
		LyprobeSource string `yaml:"lyprobe_source" json:"lyprobe_source"`
		Manifest      string `yaml:"manifest" json:"manifest"`
	} `yaml:"exports" json:"exports"`
}

type trafficScenarioSource struct {
	Kind        string `yaml:"kind" json:"kind"`
	Path        string `yaml:"path" json:"path,omitempty"`
	Glob        string `yaml:"glob" json:"glob,omitempty"`
	Recursive   bool   `yaml:"recursive" json:"recursive,omitempty"`
	Category    string `yaml:"category" json:"category,omitempty"`
	EnabledOnly bool   `yaml:"enabled_only" json:"enabled_only,omitempty"`
}

type trafficScenarioBudget struct {
	MaxTotalRules        int `yaml:"max_total_rules" json:"max_total_rules"`
	MaxSuricataRules     int `yaml:"max_suricata_rules" json:"max_suricata_rules"`
	MaxLyprobeRules      int `yaml:"max_lyprobe_rules" json:"max_lyprobe_rules"`
	MaxTotalBytes        int `yaml:"max_total_bytes" json:"max_total_bytes"`
	MaxLyprobeRegexBytes int `yaml:"max_lyprobe_regex_bytes" json:"max_lyprobe_regex_bytes"`
}

type trafficHomeNet struct {
	Values          []string `json:"values"`
	Source          string   `json:"source"`
	Note            string   `json:"note,omitempty"`
	SuricataProfile string   `json:"suricata_profile,omitempty"`
}

type trafficProfileCounts struct {
	Input               int `json:"input"`
	Accepted            int `json:"accepted"`
	Suricata            int `json:"suricata"`
	Lyprobe             int `json:"lyprobe"`
	Overlap             int `json:"overlap_count"`
	DroppedDirection    int `json:"dropped_direction"`
	DroppedCategory     int `json:"dropped_category"`
	DroppedProtocol     int `json:"dropped_protocol"`
	DroppedPort         int `json:"dropped_port"`
	DroppedDuplicate    int `json:"dropped_duplicate"`
	DroppedDuplicateSID int `json:"dropped_duplicate_sid"`
	DroppedBudget       int `json:"dropped_budget"`
	DroppedInvalid      int `json:"dropped_invalid"`
	DroppedUnsupported  int `json:"dropped_unsupported"`
	PlatformFlowOnly    int `json:"platform_flow_only"`
}

type trafficSourceRule struct {
	Raw       string
	Source    string
	Line      int
	Synthetic bool
}

type trafficSkip struct {
	Source string
	Line   int
	SID    int
	Reason string
}

// trafficRule is a parsed candidate plus its ownership decision.
type trafficRule struct {
	SID           int      `json:"sid"`
	SignatureHash string   `json:"signature_hash"`
	Raw           string   `json:"-"`
	Source        string   `json:"source"`
	Line          int      `json:"line,omitempty"`
	Synthetic     bool     `json:"synthetic,omitempty"`
	Category      string   `json:"category"`
	Direction     string   `json:"direction"`
	Protocol      string   `json:"protocol,omitempty"`
	DestPort      int      `json:"dest_port,omitempty"`
	Severity      string   `json:"severity"`
	Engine        string   `json:"engine"`
	Reason        string   `json:"reason,omitempty"`
	OptionKeys    []string `json:"-"`
	Buffer        string   `json:"-"`
	MatchCount    int      `json:"-"`
	MatchKind     string   `json:"-"`
	MatchValue    string   `json:"-"`
	MatchValues   []string `json:"-"`
	FlowValues    []string `json:"-"`
}

type trafficProfile struct {
	Scenario       trafficScenario
	ScenarioPath   string
	ScenarioSHA256 string
	HomeNet        trafficHomeNet
	ExportRoot     string
	SuricataPath   string
	LyprobePath    string
	ManifestPath   string
	Rules          []trafficRule
	Counts         trafficProfileCounts
	Skipped        []trafficSkip
	Warnings       []string
	Suricata       []byte
	Lyprobe        []byte
	SuricataHash   string
	LyprobeHash    string
	RuleSetHash    string
	OverlapCount   int
	GeneratedAt    time.Time
}

type trafficEngineExport struct {
	Engine    string `json:"engine"`
	RuleCount int    `json:"rule_count"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Bytes     int    `json:"bytes"`
}

type trafficProfileRuleRecord struct {
	SID           int    `json:"sid"`
	SignatureHash string `json:"signature_hash"`
	Engine        string `json:"engine"`
	Category      string `json:"category"`
	Direction     string `json:"direction"`
	Severity      string `json:"severity"`
	Source        string `json:"source"`
	Synthetic     bool   `json:"synthetic,omitempty"`
}

type trafficProfileManifest struct {
	SchemaVersion  string                         `json:"schema_version"`
	Scenario       string                         `json:"scenario"`
	DisplayName    string                         `json:"display_name"`
	ScenarioPath   string                         `json:"scenario_path"`
	ScenarioSHA256 string                         `json:"scenario_sha256"`
	RuleSetHash    string                         `json:"rule_set_hash"`
	GeneratedAt    time.Time                      `json:"generated_at"`
	HomeNet        trafficHomeNet                 `json:"home_net"`
	Counts         trafficProfileCounts           `json:"counts"`
	OverlapCount   int                            `json:"overlap_count"`
	Engines        map[string]trafficEngineExport `json:"engines"`
	Rules          []trafficProfileRuleRecord     `json:"rules"`
	Skipped        []trafficSkip                  `json:"skipped,omitempty"`
	Warnings       []string                       `json:"warnings,omitempty"`
}

type trafficProfileOptions struct {
	ScenarioPath string
	RuleRoot     string
	HomeNet      []string
	Now          time.Time
}

var trafficProfileExportMu sync.Mutex

// ---------------------------------------------------------------------------
// Scenario loading
// ---------------------------------------------------------------------------

func trafficProfileRuleRoot() string {
	root := strings.TrimSpace(os.Getenv(trafficProfileRootEnv))
	if root == "" {
		root = strings.TrimSpace(os.Getenv("ENGINE_RULE_ROOT"))
	}
	if root == "" {
		root = "rules"
	}
	return root
}

func resolveTrafficProfileOptions() trafficProfileOptions {
	root := trafficProfileRuleRoot()
	scenarioPath := strings.TrimSpace(os.Getenv(trafficProfileScenarioEnv))
	if scenarioPath == "" {
		scenarioPath = filepath.Join(root, "scenarios", trafficProfileDefaultName+".yaml")
	}
	var home []string
	if value := strings.TrimSpace(os.Getenv(trafficProfileHomeNetEnv)); value != "" {
		for _, part := range strings.Split(value, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				home = append(home, trimmed)
			}
		}
	}
	return trafficProfileOptions{ScenarioPath: scenarioPath, RuleRoot: root, HomeNet: home}
}

func loadTrafficScenario(path string) (trafficScenario, []byte, string, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return trafficScenario{}, nil, "", fmt.Errorf("traffic profile: read scenario %s: %w", path, err)
	}
	var scenario trafficScenario
	if err := yaml.Unmarshal(payload, &scenario); err != nil {
		return trafficScenario{}, nil, "", fmt.Errorf("traffic profile: parse scenario %s: %w", path, err)
	}
	if err := scenario.validate(); err != nil {
		return trafficScenario{}, nil, "", err
	}
	sum := sha256.Sum256(payload)
	return scenario, payload, hex.EncodeToString(sum[:]), nil
}

func (s trafficScenario) validate() error {
	if !strings.HasPrefix(s.SchemaVersion, "lyflow.traffic-scenario/") {
		return fmt.Errorf("traffic profile: unsupported scenario schema %q", s.SchemaVersion)
	}
	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("traffic profile: scenario name is required")
	}
	if s.Directions.Internal {
		return fmt.Errorf("traffic profile: internal (east-west) direction is not supported in the server zone")
	}
	if s.Budget.MaxSuricataRules <= 0 || s.Budget.MaxLyprobeRules <= 0 || s.Budget.MaxTotalRules <= 0 {
		return fmt.Errorf("traffic profile: budget.max_{total,suricata,lyprobe}_rules must be positive")
	}
	if s.Budget.MaxTotalBytes <= 0 {
		return fmt.Errorf("traffic profile: budget.max_total_bytes must be positive")
	}
	if len(s.Sources) == 0 {
		return fmt.Errorf("traffic profile: at least one rule source is required")
	}
	if strings.TrimSpace(s.Exports.SuricataRules) == "" || strings.TrimSpace(s.Exports.LyprobeSource) == "" {
		return fmt.Errorf("traffic profile: exports.suricata_rules and exports.lyprobe_source are required")
	}
	return nil
}

func resolveTrafficHomeNet(scenario trafficScenario, override []string) trafficHomeNet {
	if len(override) > 0 {
		return trafficHomeNet{Values: override, Source: "env:" + trafficProfileHomeNetEnv, Note: scenario.HomeNet.Note}
	}
	profilePath := strings.TrimSpace(os.Getenv(trafficProfileSuricataEnv))
	if profilePath == "" {
		profilePath = strings.TrimSpace(scenario.HomeNet.SuricataProfile)
	}
	if profilePath != "" {
		if values, ok := readSuricataProfileHomeNet(profilePath); ok {
			return trafficHomeNet{Values: values, Source: "suricata_profile:" + profilePath, Note: scenario.HomeNet.Note, SuricataProfile: profilePath}
		}
	}
	values := append([]string(nil), scenario.HomeNet.Fallback...)
	source := "scenario_fallback"
	if len(values) == 0 {
		source = "unresolved"
	}
	return trafficHomeNet{Values: values, Source: source, Note: scenario.HomeNet.Note, SuricataProfile: profilePath}
}

func readSuricataProfileHomeNet(path string) ([]string, bool) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var document struct {
		Vars struct {
			AddressGroups map[string]string `yaml:"address-groups"`
		} `yaml:"vars"`
	}
	if err := yaml.Unmarshal(payload, &document); err != nil {
		return nil, false
	}
	raw := strings.TrimSpace(document.Vars.AddressGroups["HOME_NET"])
	if raw == "" {
		return nil, false
	}
	raw = strings.Trim(raw, "[]")
	var values []string
	for _, part := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			values = append(values, trimmed)
		}
	}
	return values, len(values) > 0
}

func parseTrafficCIDRs(values []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(strings.TrimPrefix(value, "!"))
		if trimmed == "" || strings.HasPrefix(trimmed, "$") {
			continue
		}
		if ip := net.ParseIP(trimmed); ip != nil {
			bits := 128
			if ip.To4() != nil {
				ip = ip.To4()
				bits = 32
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		if _, network, err := net.ParseCIDR(trimmed); err == nil {
			nets = append(nets, network)
		}
	}
	return nets
}

// ---------------------------------------------------------------------------
// Rule collection
// ---------------------------------------------------------------------------

type trafficRuleLine struct {
	Raw  string
	Line int
}

// splitTrafficRuleText joins Suricata backslash continuations so that the
// multi-line rules in rules/ly-custom are parsed as one signature.
func splitTrafficRuleText(content string) []trafficRuleLine {
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	out := make([]trafficRuleLine, 0, len(lines))
	var builder strings.Builder
	start := 0
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if builder.Len() == 0 {
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			start = index + 1
		}
		if strings.HasSuffix(trimmed, `\`) {
			builder.WriteString(strings.TrimSpace(strings.TrimSuffix(trimmed, `\`)))
			builder.WriteString(" ")
			continue
		}
		builder.WriteString(trimmed)
		raw := strings.TrimSpace(builder.String())
		builder.Reset()
		if raw != "" {
			out = append(out, trafficRuleLine{Raw: raw, Line: start})
		}
	}
	if raw := strings.TrimSpace(builder.String()); raw != "" {
		out = append(out, trafficRuleLine{Raw: raw, Line: start})
	}
	return out
}

func trafficActionPrefix(line string) bool {
	lower := strings.ToLower(strings.TrimSpace(line))
	for _, action := range []string{"alert ", "drop ", "pass ", "reject "} {
		if strings.HasPrefix(lower, action) {
			return true
		}
	}
	return false
}

func collectTrafficInputs(ctx context.Context, cfg *Config, scenario trafficScenario, ruleRoot string, counts *trafficProfileCounts, warnings *[]string) []trafficSourceRule {
	inputs := []trafficSourceRule{}
	for _, source := range scenario.Sources {
		switch strings.ToLower(strings.TrimSpace(source.Kind)) {
		case "files":
			inputs = append(inputs, collectTrafficFileRules(source, ruleRoot, warnings)...)
		case "detection_rules":
			rules, warning := collectTrafficDetectionRules(ctx, cfg, source)
			if warning != "" {
				*warnings = append(*warnings, warning)
			}
			for _, rule := range rules {
				signature, ok := trafficDetectionSignature(rule.RuleJSON)
				if !ok {
					counts.PlatformFlowOnly++
					continue
				}
				inputs = append(inputs, trafficSourceRule{Raw: signature, Source: "detection_rules:" + rule.ID, Synthetic: true})
			}
		default:
			*warnings = append(*warnings, fmt.Sprintf("unsupported rule source kind %q ignored", source.Kind))
		}
	}
	return inputs
}

// resolveTrafficSourcePath accepts both "rules/suricata" (repository style)
// and "suricata" (relative to ENGINE_RULE_ROOT) without double-prefixing.
func resolveTrafficSourcePath(path, ruleRoot string) string {
	if filepath.IsAbs(path) {
		return path
	}
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return path
	}
	if info, err := os.Stat(ruleRoot); err == nil && info.IsDir() {
		if candidate := filepath.Join(ruleRoot, path); trafficPathIsDir(candidate) {
			return candidate
		}
		base := filepath.Base(filepath.Clean(ruleRoot))
		if base != "." && base != "" && strings.HasPrefix(filepath.ToSlash(path), base+"/") {
			trimmed := strings.TrimPrefix(filepath.ToSlash(path), base+"/")
			if candidate := filepath.Join(ruleRoot, filepath.FromSlash(trimmed)); trafficPathIsDir(candidate) {
				return candidate
			}
		}
	}
	return filepath.Join(ruleRoot, path)
}

func trafficPathIsDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func collectTrafficFileRules(source trafficScenarioSource, ruleRoot string, warnings *[]string) []trafficSourceRule {
	base := strings.TrimSpace(source.Path)
	if base == "" {
		return nil
	}
	base = resolveTrafficSourcePath(base, ruleRoot)
	pattern := strings.TrimSpace(source.Glob)
	if pattern == "" {
		pattern = "*.rules"
	}
	files := []string{}
	if source.Recursive {
		_ = filepath.WalkDir(base, func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return nil
			}
			if matched, _ := filepath.Match(pattern, entry.Name()); matched {
				files = append(files, path)
			}
			return nil
		})
	} else {
		matches, err := filepath.Glob(filepath.Join(base, pattern))
		if err != nil {
			*warnings = append(*warnings, fmt.Sprintf("rule source glob %s: %v", base, err))
			return nil
		}
		files = matches
	}
	sort.Strings(files)
	out := []trafficSourceRule{}
	for _, file := range files {
		payload, err := os.ReadFile(file)
		if err != nil {
			*warnings = append(*warnings, fmt.Sprintf("rule source %s unreadable: %v", file, err))
			continue
		}
		for _, line := range splitTrafficRuleText(string(payload)) {
			if !trafficActionPrefix(line.Raw) {
				continue
			}
			out = append(out, trafficSourceRule{Raw: line.Raw, Source: file, Line: line.Line})
		}
	}
	return out
}

type trafficDetectionRule struct {
	ID       string
	RuleJSON string
	Enabled  bool
}

func collectTrafficDetectionRules(ctx context.Context, cfg *Config, source trafficScenarioSource) ([]trafficDetectionRule, string) {
	if cfg == nil || cfg.DBPool == nil {
		return nil, "detection_rules source skipped: database is not configured"
	}
	category := strings.TrimSpace(source.Category)
	if category == "" {
		category = "traffic"
	}
	query := `SELECT id, rule_json::text, enabled FROM detection_rules WHERE category=$1`
	if source.EnabledOnly {
		query += ` AND enabled=true`
	}
	query += ` ORDER BY id`
	rows, err := cfg.DBPool.Query(ctx, query, category)
	if err != nil {
		return nil, "detection_rules source unavailable: " + err.Error()
	}
	defer rows.Close()
	out := []trafficDetectionRule{}
	for rows.Next() {
		var rule trafficDetectionRule
		if err := rows.Scan(&rule.ID, &rule.RuleJSON, &rule.Enabled); err != nil {
			continue
		}
		out = append(out, rule)
	}
	return out, ""
}

// trafficDetectionSignature extracts an original Suricata signature from a
// detection_rules row. Rows that only carry field/value conditions are
// flow-only behaviour rules owned by the security engine and are skipped.
func trafficDetectionSignature(raw string) (string, bool) {
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return "", false
	}
	candidates := []map[string]interface{}{payload}
	if nested, ok := payload["suricata"].(map[string]interface{}); ok {
		candidates = append(candidates, nested)
	}
	for _, candidate := range candidates {
		for _, key := range []string{"signature", "raw_rule", "suricata_rule", "rule"} {
			value, ok := candidate[key].(string)
			if !ok {
				continue
			}
			value = strings.TrimSpace(value)
			if trafficActionPrefix(value) {
				return value, true
			}
		}
	}
	return "", false
}

// ---------------------------------------------------------------------------
// Rule parsing and classification
// ---------------------------------------------------------------------------

var trafficRuleHeader = regexp.MustCompile(`(?i)^\s*(alert|drop|pass|reject)\s+([a-z0-9]+)\s+(\S+)\s+(\S+)\s*->\s*(\S+)\s+(\S+)\s*\((.*)\)\s*$`)

type trafficOption struct {
	Key   string
	Value string
}

// trafficUnsupportedSuricataKeys lists rule keywords that appear in repository
// corpora but are not valid Suricata detection keywords (or were removed in the
// Suricata versions used by the sensor). Rules using them are dropped instead of
// being exported into a file that fails `suricata -T`.
var trafficUnsupportedSuricataKeys = map[string]struct{}{
	"method":         {},
	"icmp.icmp_type": {},
	"ja3_hash":       {},
	"ja3_string":     {},
	"tcp.options":    {},
}

func parseTrafficCandidate(input trafficSourceRule, home []*net.IPNet) (trafficRule, string) {
	match := trafficRuleHeader.FindStringSubmatch(input.Raw)
	if match == nil {
		return trafficRule{}, "unsupported rule header"
	}
	options, err := splitTrafficOptions(match[7])
	if err != nil {
		return trafficRule{}, "unterminated option quote"
	}
	rule := trafficRule{
		Raw:       input.Raw,
		Source:    input.Source,
		Line:      input.Line,
		Synthetic: input.Synthetic,
		Protocol:  strings.ToLower(match[2]),
		Buffer:    "payload",
	}
	if port, err := strconv.Atoi(strings.TrimSpace(match[6])); err == nil && port > 0 && port <= 65535 {
		rule.DestPort = port
	}
	classtype := ""
	nocase := false
	for _, option := range options {
		key := strings.ToLower(strings.TrimSpace(option.Key))
		value := strings.TrimSpace(option.Value)
		if _, bad := trafficUnsupportedSuricataKeys[key]; bad {
			return trafficRule{}, "unsupported keyword " + key
		}
		rule.OptionKeys = append(rule.OptionKeys, key)
		switch key {
		case "sid":
			sid, err := strconv.Atoi(strings.Trim(value, `"`))
			if err != nil || sid <= 0 {
				return trafficRule{}, "invalid sid"
			}
			rule.SID = sid
		case "classtype":
			classtype = value
		case "content", "pcre":
			rule.MatchCount++
			rule.MatchValues = append(rule.MatchValues, value)
			if rule.MatchCount == 1 {
				rule.MatchKind = key
				rule.MatchValue = value
			}
		case "nocase":
			nocase = true
		case "flow":
			rule.FlowValues = append(rule.FlowValues, value)
		case "http_uri", "http.uri":
			rule.Buffer = "http_uri"
		case "http_client_body", "http.request_body":
			rule.Buffer = "http_client_body"
		case "dns_query", "dns.query":
			rule.Buffer = "dns_query"
		case "tls_sni", "tls.sni":
			rule.Buffer = "tls_sni"
		case "http_host", "http.host", "http_header", "http.header", "http_user_agent", "http.user_agent",
			"http_method", "http.method", "http_cookie", "http.cookie", "http_raw_uri", "http.request_line":
			rule.Buffer = "http_head_unsupported"
		case "payload", "pkt_data":
			rule.Buffer = "payload"
		}
	}
	if rule.SID == 0 {
		return trafficRule{}, "missing sid"
	}
	message := trafficRuleMessage(input.Raw)
	rule.Category = deriveTrafficCategory(message, classtype)
	rule.Severity = trafficSeverity(message + " " + classtype)
	rule.SignatureHash = trafficSignatureHash(match, rule, nocase)
	rule.Direction = trafficDirectionFor(
		trafficClassifyAddress(match[3], home),
		trafficClassifyAddress(match[5], home),
	)
	return rule, ""
}

func splitTrafficOptions(body string) ([]trafficOption, error) {
	var options []trafficOption
	var current strings.Builder
	inQuote := false
	escaped := false
	flush := func() {
		part := strings.TrimSpace(current.String())
		current.Reset()
		if part == "" {
			return
		}
		if index := strings.IndexByte(part, ':'); index >= 0 {
			options = append(options, trafficOption{Key: strings.TrimSpace(part[:index]), Value: strings.TrimSpace(part[index+1:])})
			return
		}
		options = append(options, trafficOption{Key: part})
	}
	for _, r := range body {
		if escaped {
			current.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' && inQuote {
			current.WriteRune(r)
			escaped = true
			continue
		}
		if r == '"' {
			inQuote = !inQuote
			current.WriteRune(r)
			continue
		}
		if r == ';' && !inQuote {
			flush()
			continue
		}
		current.WriteRune(r)
	}
	if inQuote {
		return nil, fmt.Errorf("unterminated quote")
	}
	flush()
	return options, nil
}

func trafficRuleMessage(raw string) string {
	lower := strings.ToLower(raw)
	index := strings.Index(lower, `msg:"`)
	if index < 0 {
		return ""
	}
	rest := raw[index+len(`msg:"`):]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return ""
	}
	return rest[:end]
}

func trafficSignatureHash(match []string, rule trafficRule, nocase bool) string {
	parts := []string{
		strings.ToLower(match[1]),
		strings.ToLower(match[2]),
		match[3], match[4], match[5], match[6],
		rule.Buffer,
		rule.MatchKind,
		strings.Join(rule.MatchValues, "\x1e"),
	}
	if nocase {
		parts = append(parts, "nocase")
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return hex.EncodeToString(sum[:])
}

func trafficClassifyAddress(token string, home []*net.IPNet) string {
	value := strings.ToLower(strings.TrimSpace(token))
	switch {
	case value == "" || value == "any":
		return "any"
	case value == "$home_net":
		return "home"
	case value == "$external_net" || value == "!$home_net":
		return "external"
	case strings.HasPrefix(value, "!"):
		return "external"
	case strings.HasPrefix(value, "$"):
		return "other"
	}
	if ip := net.ParseIP(value); ip != nil {
		for _, network := range home {
			if network.Contains(ip) {
				return "home"
			}
		}
		return "external"
	}
	if _, network, err := net.ParseCIDR(value); err == nil {
		for _, known := range home {
			if known.Contains(network.IP) || network.Contains(known.IP) {
				return "home"
			}
		}
		return "external"
	}
	return "other"
}

func trafficDirectionFor(src, dst string) string {
	switch {
	case src == "home" && dst == "home":
		return "internal"
	case src == "home":
		return "outbound"
	case dst == "home":
		return "inbound"
	case src == "external" && dst == "external":
		return "external"
	default:
		return "ambiguous"
	}
}

var trafficCategoryKeywords = []struct {
	category string
	needles  []string
}{
	{"phishing", []string{"PHISH", "FRAUD"}},
	{"policy", []string{"POLICY"}},
	{"user_agents", []string{"USER AGENT", "USER-AGENT"}},
	{"lateral", []string{"LATERAL", "PASS-THE-HASH", "PSExec", "WMI REMOTE", "DCERPC", "KERBEROAST"}},
	{"database", []string{"MYSQL", "POSTGRES", "MSSQL", "REDIS", "ORACLE"}},
	{"mail", []string{"SMTP", "IMAP", "POP3", "MAIL"}},
	{"rdp", []string{"RDP "}},
	{"telnet", []string{"TELNET"}},
	{"netbios", []string{"NETBIOS"}},
	{"smb", []string{"SMB"}},
	{"mining", []string{"MINING", "MINER", "XMRIG", "COINHIVE", "STRATUM"}},
	{"scan", []string{"SCAN", "NMAP", "MASSCAN", "FSCAN", "GOBY", "YAKIT", "SQLMAP", "NIKTO", "BURP"}},
	{"c2", []string{"COBALSTRIKE", "COBALTSTRIKE", "SLIVER", "METERPRETER", "EMPIRE", "COVENANT", "PUPY", "C2", "BEACON"}},
	{"tunnel", []string{"TUNNEL", "FRP", "REGEORG", "PROXY"}},
	{"web_attack", []string{"WEBSHELL", "SQL INJECTION", "XSS", "LFI", "RFI"}},
	{"exploit", []string{"EXPLOIT", "CVE-"}},
	{"trojan", []string{"TROJAN"}},
	{"malware", []string{"MALWARE", "BOTNET", "WORM"}},
	{"dns", []string{"DGA", "DNS "}},
	{"tls", []string{"TLS SNI", "JA3"}},
	{"http", []string{"HTTP "}},
	{"suspicious", []string{"SUSPICIOUS", "ANOMALY"}},
}

func deriveTrafficCategory(message, classtype string) string {
	upper := strings.ToUpper(message)
	for _, entry := range trafficCategoryKeywords {
		for _, needle := range entry.needles {
			if strings.Contains(upper, needle) {
				return entry.category
			}
		}
	}
	lower := strings.ToLower(classtype)
	switch {
	case strings.Contains(lower, "web-application"):
		return "web_attack"
	case strings.Contains(lower, "trojan"), strings.Contains(lower, "malware"):
		return "trojan"
	case strings.Contains(lower, "recon"), strings.Contains(lower, "scan"), strings.Contains(lower, "brute"):
		return "scan"
	case strings.Contains(lower, "exploit"):
		return "exploit"
	case strings.Contains(lower, "policy"):
		return "policy"
	case strings.Contains(lower, "phishing"):
		return "phishing"
	case strings.Contains(lower, "sql"):
		return "web_attack"
	}
	return "uncategorized"
}

func trafficSeverity(text string) string {
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "critical"):
		return "critical"
	case strings.Contains(lower, "trojan"), strings.Contains(lower, "malware"),
		strings.Contains(lower, "c2"), strings.Contains(lower, "exploit"),
		strings.Contains(lower, "mining"), strings.Contains(lower, "tunnel"),
		strings.Contains(lower, "webshell"), strings.Contains(lower, "ransom"):
		return "high"
	case strings.Contains(lower, "scan"), strings.Contains(lower, "recon"),
		strings.Contains(lower, "policy"), strings.Contains(lower, "info"):
		return "low"
	}
	return "medium"
}

func trafficSeverityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func trafficCategoryRank(category string) int {
	ranks := map[string]int{
		"c2": 100, "malware": 95, "trojan": 90, "mining": 85, "exploit": 80,
		"tunnel": 75, "dns": 70, "tls": 65, "web_attack": 60, "scan": 55,
		"http": 50, "suspicious": 45, "worm": 40, "shellcode": 35,
	}
	if rank, ok := ranks[category]; ok {
		return rank
	}
	return 10
}

// ---------------------------------------------------------------------------
// Filtering, ownership, budget
// ---------------------------------------------------------------------------

func trafficDirectionEnabled(direction string, scenario trafficScenario) bool {
	switch direction {
	case "inbound":
		return scenario.Directions.Inbound
	case "outbound":
		return scenario.Directions.Outbound
	case "ambiguous":
		return scenario.Directions.Ambiguous
	case "internal":
		return scenario.Directions.Internal
	default:
		return false
	}
}

func trafficCategoryAllowed(category string, scenario trafficScenario) bool {
	lower := strings.ToLower(strings.TrimSpace(category))
	for _, excluded := range scenario.Categories.Exclude {
		if strings.EqualFold(strings.TrimSpace(excluded), lower) {
			return false
		}
	}
	if len(scenario.Categories.Include) == 0 {
		return true
	}
	for _, included := range scenario.Categories.Include {
		if strings.EqualFold(strings.TrimSpace(included), lower) {
			return true
		}
	}
	return false
}

func trafficProtocolExcluded(protocol string, scenario trafficScenario) bool {
	for _, excluded := range scenario.Protocols.Exclude {
		if strings.EqualFold(strings.TrimSpace(excluded), protocol) {
			return true
		}
	}
	return false
}

func trafficPortExcluded(rule trafficRule, scenario trafficScenario) bool {
	if rule.DestPort == 0 {
		return false
	}
	applies := false
	for _, direction := range scenario.Ports.ExcludeDirection {
		if strings.EqualFold(strings.TrimSpace(direction), rule.Direction) {
			applies = true
			break
		}
	}
	if !applies {
		return false
	}
	for _, port := range scenario.Ports.ExcludeInbound {
		if rule.DestPort == port {
			return true
		}
	}
	return false
}

var trafficLyprobeOptionAllowlist = map[string]bool{
	"msg": true, "sid": true, "rev": true, "classtype": true, "priority": true,
	"metadata": true, "reference": true, "target": true, "nocase": true,
	"content": true, "pcre": true, "flow": true, "fast_pattern": true,
	"http_uri": true, "http.uri": true,
	"http_client_body": true, "http.request_body": true,
	"dns_query": true, "dns.query": true,
	"tls_sni": true, "tls.sni": true,
}

type trafficLyprobePolicy struct {
	MinSeverity        string
	RequireSimpleMatch bool
	RequireSingleMatch bool
	MaxRegexBytes      int
	AllowedBuffers     map[string]bool
	AllowedCategories  map[string]bool
}

func trafficLyprobePolicyFor(scenario trafficScenario) trafficLyprobePolicy {
	policy := trafficLyprobePolicy{
		MinSeverity:        strings.ToLower(strings.TrimSpace(scenario.Assignment.Lyprobe.MinSeverity)),
		RequireSimpleMatch: scenario.Assignment.Lyprobe.RequireSimpleMatch,
		RequireSingleMatch: scenario.Assignment.Lyprobe.RequireSingleMatch,
		MaxRegexBytes:      scenario.Budget.MaxLyprobeRegexBytes,
		AllowedBuffers:     map[string]bool{},
		AllowedCategories:  map[string]bool{},
	}
	for _, buffer := range scenario.Assignment.Lyprobe.AllowedBuffers {
		policy.AllowedBuffers[strings.ToLower(strings.TrimSpace(buffer))] = true
	}
	for _, category := range scenario.Assignment.Lyprobe.AllowedCategories {
		policy.AllowedCategories[strings.ToLower(strings.TrimSpace(category))] = true
	}
	return policy
}

func trafficFlowValuesAllowed(values []string) bool {
	for _, value := range values {
		for _, token := range strings.Split(strings.ToLower(value), ",") {
			switch strings.TrimSpace(token) {
			case "established", "to_server":
			default:
				return false
			}
		}
	}
	return true
}

func assignTrafficEngine(rule trafficRule, policy trafficLyprobePolicy) (string, string) {
	if !policy.AllowedCategories[strings.ToLower(rule.Category)] {
		return "suricata", "category is not lyprobe-eligible"
	}
	if policy.MinSeverity != "" && trafficSeverityRank(rule.Severity) < trafficSeverityRank(policy.MinSeverity) {
		return "suricata", "severity below lyprobe threshold"
	}
	if !policy.AllowedBuffers[strings.ToLower(rule.Buffer)] {
		return "suricata", "buffer is not representable by lyprobe"
	}
	if policy.RequireSingleMatch && rule.MatchCount != 1 {
		return "suricata", "multiple content/pcre matches are Suricata-only"
	}
	if policy.RequireSimpleMatch {
		for _, key := range rule.OptionKeys {
			if !trafficLyprobeOptionAllowlist[strings.ToLower(key)] {
				return "suricata", "option " + key + " is Suricata-only"
			}
		}
	}
	if !trafficFlowValuesAllowed(rule.FlowValues) {
		return "suricata", "flow direction is not representable by lyprobe"
	}
	if limit := policy.MaxRegexBytes; limit > 0 && len(rule.MatchValue) > limit {
		return "suricata", "regex exceeds lyprobe budget"
	}
	result := rulecompiler.Convert([]rulecompiler.SourceFile{{Name: rule.Source, Content: []byte(rule.Raw)}})
	if result.Converted != 1 {
		reason := "rulecompiler rejected rule"
		if len(result.Skipped) > 0 && strings.TrimSpace(result.Skipped[0].Reason) != "" {
			reason = result.Skipped[0].Reason
		}
		return "suricata", reason
	}
	return "lyprobe", "single-match high-confidence rule"
}

func trafficRulePriority(rule trafficRule) int {
	return trafficSeverityRank(rule.Severity)*100 + trafficCategoryRank(rule.Category)
}

func trafficSortByPriority(rules []trafficRule) {
	sort.SliceStable(rules, func(i, j int) bool {
		left, right := trafficRulePriority(rules[i]), trafficRulePriority(rules[j])
		if left != right {
			return left > right
		}
		if rules[i].SID != rules[j].SID {
			return rules[i].SID < rules[j].SID
		}
		return rules[i].SignatureHash < rules[j].SignatureHash
	})
}

// dedupeTrafficSignatures keeps one rule per signature_hash. The winner is
// deterministic: lowest SID, then source path, then line.
func dedupeTrafficSignatures(rules []trafficRule, counts *trafficProfileCounts) []trafficRule {
	sorted := append([]trafficRule(nil), rules...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].SID != sorted[j].SID {
			return sorted[i].SID < sorted[j].SID
		}
		if sorted[i].Source != sorted[j].Source {
			return sorted[i].Source < sorted[j].Source
		}
		return sorted[i].Line < sorted[j].Line
	})
	seen := map[string]bool{}
	out := make([]trafficRule, 0, len(sorted))
	for _, rule := range sorted {
		if seen[rule.SignatureHash] {
			counts.DroppedDuplicate++
			continue
		}
		seen[rule.SignatureHash] = true
		out = append(out, rule)
	}
	return out
}

// dedupeTrafficSIDs resolves conflicting rules that reuse a SID. Suricata
// refuses to load a rule file with duplicate SIDs, so the conflict is resolved
// before export rather than left to the sensor.
func dedupeTrafficSIDs(rules []trafficRule, counts *trafficProfileCounts) []trafficRule {
	bySID := map[int]trafficRule{}
	order := []int{}
	for _, rule := range rules {
		existing, ok := bySID[rule.SID]
		if !ok {
			bySID[rule.SID] = rule
			order = append(order, rule.SID)
			continue
		}
		counts.DroppedDuplicateSID++
		if trafficRulePriority(rule) > trafficRulePriority(existing) {
			bySID[rule.SID] = rule
		}
	}
	out := make([]trafficRule, 0, len(order))
	for _, sid := range order {
		out = append(out, bySID[sid])
	}
	return out
}

// ---------------------------------------------------------------------------
// Profile build
// ---------------------------------------------------------------------------

func buildTrafficProfile(ctx context.Context, cfg *Config, opts trafficProfileOptions) (trafficProfile, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	scenario, _, scenarioHash, err := loadTrafficScenario(opts.ScenarioPath)
	if err != nil {
		return trafficProfile{}, err
	}
	profile := trafficProfile{
		Scenario:       scenario,
		ScenarioPath:   opts.ScenarioPath,
		ScenarioSHA256: scenarioHash,
		HomeNet:        resolveTrafficHomeNet(scenario, opts.HomeNet),
		GeneratedAt:    now,
	}
	profile.ExportRoot = resolveTrafficExportRoot(scenario, opts.RuleRoot)
	profile.SuricataPath = filepath.Join(profile.ExportRoot, scenario.Exports.SuricataRules)
	profile.LyprobePath = filepath.Join(profile.ExportRoot, scenario.Exports.LyprobeSource)
	manifestName := strings.TrimSpace(scenario.Exports.Manifest)
	if manifestName == "" {
		manifestName = "profile-manifest.json"
	}
	profile.ManifestPath = filepath.Join(profile.ExportRoot, manifestName)
	homeNets := parseTrafficCIDRs(profile.HomeNet.Values)
	if len(homeNets) == 0 {
		profile.Warnings = append(profile.Warnings, "home_net could not be resolved; literal addresses are classified as external")
	}
	if profile.HomeNet.Source == "scenario_fallback" {
		profile.Warnings = append(profile.Warnings, "home_net resolved from scenario fallback; set TRAFFIC_PROFILE_HOME_NET or TRAFFIC_PROFILE_SURICATA_PROFILE for exact direction classification")
	}

	inputs := collectTrafficInputs(ctx, cfg, scenario, opts.RuleRoot, &profile.Counts, &profile.Warnings)
	profile.Counts.Input = len(inputs)

	candidates := make([]trafficRule, 0, len(inputs))
	for _, input := range inputs {
		rule, reason := parseTrafficCandidate(input, homeNets)
		if reason != "" {
			if strings.HasPrefix(reason, "unsupported keyword ") {
				profile.Counts.DroppedUnsupported++
			} else {
				profile.Counts.DroppedInvalid++
			}
			profile.Skipped = append(profile.Skipped, trafficSkip{Source: input.Source, Line: input.Line, Reason: reason})
			continue
		}
		candidates = append(candidates, rule)
	}

	candidates = dedupeTrafficSignatures(candidates, &profile.Counts)

	filtered := make([]trafficRule, 0, len(candidates))
	for _, rule := range candidates {
		if !trafficDirectionEnabled(rule.Direction, scenario) {
			profile.Counts.DroppedDirection++
			continue
		}
		if trafficProtocolExcluded(rule.Protocol, scenario) {
			profile.Counts.DroppedProtocol++
			continue
		}
		if trafficPortExcluded(rule, scenario) {
			profile.Counts.DroppedPort++
			continue
		}
		if !trafficCategoryAllowed(rule.Category, scenario) {
			profile.Counts.DroppedCategory++
			continue
		}
		filtered = append(filtered, rule)
	}

	filtered = dedupeTrafficSIDs(filtered, &profile.Counts)

	policy := trafficLyprobePolicyFor(scenario)
	for index := range filtered {
		engine, reason := assignTrafficEngine(filtered[index], policy)
		filtered[index].Engine = engine
		filtered[index].Reason = reason
	}

	// Budget: highest severity / highest-risk categories win. Caps are applied
	// per engine and in total; the byte budget is enforced after rendering.
	trafficSortByPriority(filtered)
	kept := make([]trafficRule, 0, len(filtered))
	suricataCount, lyprobeCount := 0, 0
	for _, rule := range filtered {
		if len(kept) >= scenario.Budget.MaxTotalRules {
			profile.Counts.DroppedBudget++
			continue
		}
		switch rule.Engine {
		case "lyprobe":
			if lyprobeCount >= scenario.Budget.MaxLyprobeRules {
				profile.Counts.DroppedBudget++
				continue
			}
			lyprobeCount++
		default:
			if suricataCount >= scenario.Budget.MaxSuricataRules {
				profile.Counts.DroppedBudget++
				continue
			}
			suricataCount++
		}
		kept = append(kept, rule)
	}

	// Render, then enforce the byte budget by dropping the lowest-priority rule.
	for {
		suricataRules, lyprobeRules := splitTrafficRulesByEngine(kept)
		profile.Suricata = renderTrafficRuleFile("suricata", scenario, profile, now, suricataRules)
		profile.Lyprobe = renderTrafficRuleFile("lyprobe-source", scenario, profile, now, lyprobeRules)
		if scenario.Budget.MaxTotalBytes <= 0 || len(profile.Suricata)+len(profile.Lyprobe) <= scenario.Budget.MaxTotalBytes || len(kept) == 0 {
			break
		}
		victim := trafficLowestPriorityRule(kept)
		next := kept[:0]
		removed := false
		for _, rule := range kept {
			if !removed && rule.SignatureHash == victim.SignatureHash {
				removed = true
				profile.Counts.DroppedBudget++
				continue
			}
			next = append(next, rule)
		}
		kept = next
	}

	trafficSortBySID(kept)
	profile.Rules = kept
	profile.RuleSetHash = trafficRuleSetHash(kept)
	profile.OverlapCount = trafficOverlapCount(kept)
	profile.Counts.Suricata, profile.Counts.Lyprobe = countTrafficEngines(kept)
	profile.Counts.Accepted = len(kept)
	profile.Counts.Overlap = profile.OverlapCount
	if profile.OverlapCount != 0 {
		return trafficProfile{}, fmt.Errorf("traffic profile: %d rules are assigned to both engines", profile.OverlapCount)
	}
	if len(kept) == 0 {
		profile.Warnings = append(profile.Warnings, "no rule survived the scenario filters; exports are empty")
	}
	profile.SuricataHash = trafficBytesHash(profile.Suricata)
	profile.LyprobeHash = trafficBytesHash(profile.Lyprobe)
	return profile, nil
}

func splitTrafficRulesByEngine(rules []trafficRule) ([]trafficRule, []trafficRule) {
	suricata := make([]trafficRule, 0, len(rules))
	lyprobe := make([]trafficRule, 0, len(rules))
	for _, rule := range rules {
		if rule.Engine == "lyprobe" {
			lyprobe = append(lyprobe, rule)
			continue
		}
		suricata = append(suricata, rule)
	}
	trafficSortBySID(suricata)
	trafficSortBySID(lyprobe)
	return suricata, lyprobe
}

func trafficSortBySID(rules []trafficRule) {
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].SID != rules[j].SID {
			return rules[i].SID < rules[j].SID
		}
		return rules[i].SignatureHash < rules[j].SignatureHash
	})
}

func trafficLowestPriorityRule(rules []trafficRule) trafficRule {
	if len(rules) == 0 {
		return trafficRule{}
	}
	victim := rules[0]
	for _, rule := range rules[1:] {
		left, right := trafficRulePriority(rule), trafficRulePriority(victim)
		if left < right || (left == right && rule.SID > victim.SID) {
			victim = rule
		}
	}
	return victim
}

func countTrafficEngines(rules []trafficRule) (int, int) {
	suricata, lyprobe := 0, 0
	for _, rule := range rules {
		if rule.Engine == "lyprobe" {
			lyprobe++
			continue
		}
		suricata++
	}
	return suricata, lyprobe
}

func trafficRuleSetHash(rules []trafficRule) string {
	sorted := append([]trafficRule(nil), rules...)
	trafficSortBySID(sorted)
	var builder strings.Builder
	for _, rule := range sorted {
		fmt.Fprintf(&builder, "%s:%d:%s\n", rule.Engine, rule.SID, rule.SignatureHash)
	}
	return trafficBytesHash([]byte(builder.String()))
}

func trafficOverlapCount(rules []trafficRule) int {
	owners := map[string]string{}
	overlap := 0
	for _, rule := range rules {
		engine := rule.Engine
		if engine != "lyprobe" {
			engine = "suricata"
		}
		if existing, ok := owners[rule.SignatureHash]; ok && existing != engine {
			overlap++
			continue
		}
		owners[rule.SignatureHash] = engine
	}
	return overlap
}

func trafficBytesHash(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func renderTrafficRuleFile(kind string, scenario trafficScenario, profile trafficProfile, now time.Time, rules []trafficRule) []byte {
	var builder strings.Builder
	fmt.Fprintf(&builder, "# LyFlow traffic rule profile — %s\n", scenario.Name)
	fmt.Fprintf(&builder, "# schema: %s\n", trafficProfileSchemaVersion)
	fmt.Fprintf(&builder, "# engine: %s\n", kind)
	fmt.Fprintf(&builder, "# generated_at: %s\n", now.Format(time.RFC3339))
	fmt.Fprintf(&builder, "# scenario_sha256: %s\n", profile.ScenarioSHA256)
	fmt.Fprintf(&builder, "# home_net: %s (%s)\n", strings.Join(profile.HomeNet.Values, ","), profile.HomeNet.Source)
	fmt.Fprintf(&builder, "# rules: %d\n", len(rules))
	builder.WriteString("# DO NOT EDIT — regenerate via POST /api/v1/traffic/rule-profile/export\n")
	for _, rule := range rules {
		builder.WriteString(rule.Raw)
		builder.WriteByte('\n')
	}
	return []byte(builder.String())
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

func trafficProfileExportPlan(profile trafficProfile) (string, string, string) {
	return profile.ExportRoot, profile.SuricataPath, profile.LyprobePath
}

func trafficProfileManifestPath(profile trafficProfile) string {
	return profile.ManifestPath
}

func resolveTrafficExportRoot(scenario trafficScenario, ruleRoot string) string {
	root := strings.TrimSpace(scenario.Exports.Root)
	if root == "" {
		root = filepath.Join("compiled", scenario.Name)
	}
	if filepath.IsAbs(root) {
		return root
	}
	if strings.TrimSpace(ruleRoot) == "" {
		ruleRoot = "rules"
	}
	return filepath.Join(ruleRoot, root)
}

func trafficProfileManifestFor(profile trafficProfile, paths [2]string) trafficProfileManifest {
	manifest := trafficProfileManifest{
		SchemaVersion:  trafficProfileSchemaVersion,
		Scenario:       profile.Scenario.Name,
		DisplayName:    profile.Scenario.DisplayName,
		ScenarioPath:   profile.ScenarioPath,
		ScenarioSHA256: profile.ScenarioSHA256,
		RuleSetHash:    profile.RuleSetHash,
		GeneratedAt:    profile.GeneratedAt,
		HomeNet:        profile.HomeNet,
		Counts:         profile.Counts,
		OverlapCount:   profile.OverlapCount,
		Engines: map[string]trafficEngineExport{
			"suricata": {Engine: "suricata", RuleCount: profile.Counts.Suricata, Path: paths[0], SHA256: profile.SuricataHash, Bytes: len(profile.Suricata)},
			"lyprobe":  {Engine: "lyprobe", RuleCount: profile.Counts.Lyprobe, Path: paths[1], SHA256: profile.LyprobeHash, Bytes: len(profile.Lyprobe)},
		},
		Warnings: profile.Warnings,
	}
	if len(profile.Skipped) > 200 {
		manifest.Skipped = profile.Skipped[:200]
	} else {
		manifest.Skipped = profile.Skipped
	}
	manifest.Rules = make([]trafficProfileRuleRecord, 0, len(profile.Rules))
	for _, rule := range profile.Rules {
		manifest.Rules = append(manifest.Rules, trafficProfileRuleRecord{
			SID: rule.SID, SignatureHash: rule.SignatureHash, Engine: rule.Engine,
			Category: rule.Category, Direction: rule.Direction, Severity: rule.Severity,
			Source: rule.Source, Synthetic: rule.Synthetic,
		})
	}
	return manifest
}

func writeTrafficProfile(profile trafficProfile) (trafficProfileManifest, error) {
	root, suricataPath, lyprobePath := trafficProfileExportPlan(profile)
	if err := os.MkdirAll(root, 0o755); err != nil {
		return trafficProfileManifest{}, fmt.Errorf("traffic profile: create export dir: %w", err)
	}
	if err := writeTrafficFileAtomic(suricataPath, profile.Suricata); err != nil {
		return trafficProfileManifest{}, err
	}
	if err := writeTrafficFileAtomic(lyprobePath, profile.Lyprobe); err != nil {
		return trafficProfileManifest{}, err
	}
	manifest := trafficProfileManifestFor(profile, [2]string{suricataPath, lyprobePath})
	payload, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return trafficProfileManifest{}, fmt.Errorf("traffic profile: encode manifest: %w", err)
	}
	payload = append(payload, '\n')
	if err := writeTrafficFileAtomic(trafficProfileManifestPath(profile), payload); err != nil {
		return trafficProfileManifest{}, err
	}
	return manifest, nil
}

func writeTrafficFileAtomic(path string, payload []byte) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("traffic profile: temp file: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o644); err != nil {
		temp.Close()
		return fmt.Errorf("traffic profile: chmod %s: %w", path, err)
	}
	if _, err := temp.Write(payload); err != nil {
		temp.Close()
		return fmt.Errorf("traffic profile: write %s: %w", path, err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("traffic profile: sync %s: %w", path, err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("traffic profile: close %s: %w", path, err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("traffic profile: rename %s: %w", path, err)
	}
	return nil
}

func loadTrafficProfileManifest(path string) (trafficProfileManifest, bool) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return trafficProfileManifest{}, false
	}
	var manifest trafficProfileManifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		return trafficProfileManifest{}, false
	}
	return manifest, true
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

type trafficProfileEngineStatus struct {
	Engine    string `json:"engine"`
	RuleCount int    `json:"rule_count"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256,omitempty"`
	Exists    bool   `json:"exists"`
	Bytes     int    `json:"bytes,omitempty"`
}

type trafficProfileExportSummary struct {
	GeneratedAt    time.Time                      `json:"generated_at"`
	ScenarioSHA256 string                         `json:"scenario_sha256"`
	RuleSetHash    string                         `json:"rule_set_hash"`
	Counts         trafficProfileCounts           `json:"counts"`
	OverlapCount   int                            `json:"overlap_count"`
	Engines        map[string]trafficEngineExport `json:"engines"`
}

type trafficProfileStatus struct {
	SchemaVersion string                                `json:"schema_version"`
	Scenario      map[string]interface{}                `json:"scenario"`
	HomeNet       trafficHomeNet                        `json:"home_net"`
	Directions    map[string]bool                       `json:"directions"`
	Budget        trafficScenarioBudget                 `json:"budget"`
	Counts        trafficProfileCounts                  `json:"counts"`
	Engines       map[string]trafficProfileEngineStatus `json:"engines"`
	OverlapCount  int                                   `json:"overlap_count"`
	LastExport    *trafficProfileExportSummary          `json:"last_export"`
	Stale         bool                                  `json:"stale"`
	Warnings      []string                              `json:"warnings,omitempty"`
}

func trafficRuleProfileStatus(ctx context.Context, cfg *Config) (trafficProfileStatus, error) {
	opts := resolveTrafficProfileOptions()
	profile, err := buildTrafficProfile(ctx, cfg, opts)
	if err != nil {
		return trafficProfileStatus{}, err
	}
	_, suricataPath, lyprobePath := trafficProfileExportPlan(profile)
	status := trafficProfileStatus{
		SchemaVersion: trafficProfileSchemaVersion,
		Scenario: map[string]interface{}{
			"name":         profile.Scenario.Name,
			"display_name": profile.Scenario.DisplayName,
			"path":         profile.ScenarioPath,
			"sha256":       profile.ScenarioSHA256,
			"description":  profile.Scenario.Description,
		},
		HomeNet: profile.HomeNet,
		Directions: map[string]bool{
			"inbound":   profile.Scenario.Directions.Inbound,
			"outbound":  profile.Scenario.Directions.Outbound,
			"internal":  profile.Scenario.Directions.Internal,
			"ambiguous": profile.Scenario.Directions.Ambiguous,
		},
		Budget:       profile.Scenario.Budget,
		Counts:       profile.Counts,
		OverlapCount: profile.OverlapCount,
		Warnings:     profile.Warnings,
		Engines: map[string]trafficProfileEngineStatus{
			"suricata": {Engine: "suricata", RuleCount: profile.Counts.Suricata, Path: suricataPath, SHA256: profile.SuricataHash, Bytes: len(profile.Suricata)},
			"lyprobe":  {Engine: "lyprobe", RuleCount: profile.Counts.Lyprobe, Path: lyprobePath, SHA256: profile.LyprobeHash, Bytes: len(profile.Lyprobe)},
		},
		Stale: true,
	}
	for name, engine := range status.Engines {
		if info, err := os.Stat(engine.Path); err == nil && !info.IsDir() {
			engine.Exists = true
			engine.Bytes = int(info.Size())
			status.Engines[name] = engine
		}
	}
	manifest, ok := loadTrafficProfileManifest(trafficProfileManifestPath(profile))
	if ok {
		status.LastExport = &trafficProfileExportSummary{
			GeneratedAt: manifest.GeneratedAt, ScenarioSHA256: manifest.ScenarioSHA256,
			RuleSetHash: manifest.RuleSetHash,
			Counts:      manifest.Counts, OverlapCount: manifest.OverlapCount, Engines: manifest.Engines,
		}
		status.Stale = manifest.ScenarioSHA256 != profile.ScenarioSHA256 ||
			manifest.RuleSetHash != profile.RuleSetHash
	}
	return status, nil
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

func trafficRuleProfileStatusHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		status, err := trafficRuleProfileStatus(r.Context(), cfg)
		if err != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "traffic_profile_unavailable", err.Error())
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": status})
	}
}

func trafficRuleProfileExportHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		var request struct {
			DryRun bool `json:"dry_run"`
		}
		if r.Body != nil {
			_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request)
		}
		dryRun := request.DryRun || strings.EqualFold(r.URL.Query().Get("dry_run"), "1") || strings.EqualFold(r.URL.Query().Get("dry_run"), "true")

		trafficProfileExportMu.Lock()
		defer trafficProfileExportMu.Unlock()

		profile, err := buildTrafficProfile(r.Context(), cfg, resolveTrafficProfileOptions())
		if err != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "traffic_profile_unavailable", err.Error())
			return
		}
		_, suricataPath, lyprobePath := trafficProfileExportPlan(profile)
		manifest := trafficProfileManifestFor(profile, [2]string{suricataPath, lyprobePath})
		if !dryRun {
			manifest, err = writeTrafficProfile(profile)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "traffic_profile_export_failed", err.Error())
				return
			}
			log.Printf("traffic rule profile export: scenario=%s suricata=%d lyprobe=%d overlap=%d suricata_sha=%s lyprobe_sha=%s",
				profile.Scenario.Name, profile.Counts.Suricata, profile.Counts.Lyprobe, profile.OverlapCount,
				profile.SuricataHash, profile.LyprobeHash)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 0, "message": "success",
			"data": map[string]interface{}{"dry_run": dryRun, "manifest": manifest, "warnings": profile.Warnings},
		})
	}
}
