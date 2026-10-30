package main

// Request-level RASP rule pack derived from the OWASP Core Rule Set.
//
// This file is intentionally read-only with respect to the platform rule
// engine: CRS request rules are *not* imported into the platform detection
// engine. They are converted into a small, probe-consumable JSON pack that a
// runtime request hook can evaluate inline (virtual patching).
//
// Only CRS request-side paranoia levels 1-2 are extracted, and only operators
// that a runtime probe can evaluate deterministically (@rx / phrase match).
// @detectSQLi cannot be represented as a regular expression and is left to the
// existing sink-level detectors plus the platform engine.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const (
	raspRequestRulesSchema        = "lyflow.rasp.request_rules.v1"
	raspRequestRulesSource        = "owasp-crs"
	raspRequestRulesSourceVersion = "4.31.0-dev"
	// The pack is deterministic. A fixed generation stamp keeps the digest
	// stable across restarts so probes can cache it by ETag.
	raspRequestRulesGeneratedAt = "2026-10-29T00:00:00Z"
	raspRequestRulesMaxParanoia = 2
)

// raspRequestCRSSubset is a curated, executable subset of the CRS request
// rules. Each SecRule keeps the upstream id, message, paranoia level and
// target variables; patterns are verbatim from CRS 4.31.0-dev.
const raspRequestCRSSubset = `
SecRule REQUEST_URI_RAW|ARGS|REQUEST_HEADERS|!REQUEST_HEADERS:Referer|FILES|XML:/*|XML://@* "@rx (?:^|[/;\x5c])\.{2,3}[/;\x5c]" "id:930110,phase:2,deny,msg:'Path Traversal Attack (/../) or (/.../)',tag:'paranoia-level/1',severity:'CRITICAL'"
SecRule ARGS|XML:/*|XML://@* "@rx (?i)^(f(?:ile|tps?)|https?|ssh)://(?:\[?[0-9a-f]+:[0-:a-f]+\]?|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})" "id:931100,phase:2,deny,msg:'Possible Remote File Inclusion (RFI) Attack: URL Parameter using IP Address',tag:'paranoia-level/1',severity:'CRITICAL'"
SecRule ARGS "@rx ^(?i:file|ftps?|https?).*?\?+$" "id:931120,phase:2,deny,msg:'Possible Remote File Inclusion (RFI) Attack: URL Payload Used w/Trailing Question Mark Character (?)',tag:'paranoia-level/1',severity:'CRITICAL'"
SecRule REQUEST_FILENAME|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*|XML://@* "@rx \$(?:\((?:[^\)]+|\([^\)]+\))\)|\{[^\}]+\}|\[[^\]]*\])|[<>]\([^\)]+\)|/[0-9A-Z_a-z]*\[[^\]]+\]" "id:932130,phase:2,deny,msg:'Remote Command Execution: Unix Shell Expression Found',tag:'paranoia-level/1',severity:'CRITICAL'"
SecRule REQUEST_FILENAME|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*|XML://@* "@rx \b(?:for(?:/[dflr].*)? %+[^ ]+ in\(.*\)[\s\x0b]?do|if(?:/i)?(?: not)?(?: (?:e(?:xist|rrorlevel)|defined|cmdextversion)\b|[ \(].*(?:\b(?:g(?:eq|tr)|equ|neq|l(?:eq|ss))\b|==)))" "id:932140,phase:2,deny,msg:'Remote Command Execution: Windows FOR/IF Command Found',tag:'paranoia-level/1',severity:'CRITICAL'"
SecRule REQUEST_HEADERS|REQUEST_LINE "@rx ^\(\s*\)\s+\{" "id:932170,phase:1,deny,msg:'Remote Command Execution: Shellshock (CVE-2014-6271)',tag:'paranoia-level/1',severity:'CRITICAL'"
SecRule REQUEST_FILENAME|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*|XML://@* "@rx \{[0-9A-Z_a-z]*,[,\-0-9A-Z_a-z]*\}" "id:932280,phase:2,deny,msg:'Remote Command Execution: Brace Expansion Found',tag:'paranoia-level/1',severity:'CRITICAL'"
SecRule REQUEST_FILENAME|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*|XML://@* "@rx !-\d" "id:932330,phase:2,deny,msg:'Remote Command Execution: Unix shell history invocation',tag:'paranoia-level/1',severity:'CRITICAL'"
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS|!REQUEST_HEADERS:Cookie|ARGS_NAMES|ARGS|XML:/*|XML://@* "@rx (?i)<\?(?:php[\s\x0b]|[\s\x0b=]|xml(?:[\s\x0b]+[^a-z]|:)|$)|\[[/\x5c]?php\]|\{/?php\}" "id:933100,phase:2,deny,msg:'PHP Injection Attack: PHP Open Tag Found',tag:'paranoia-level/1',severity:'CRITICAL'"
SecRule FILES|REQUEST_HEADERS:X-Filename|REQUEST_HEADERS:X_Filename|REQUEST_HEADERS:X.Filename|REQUEST_HEADERS:X-File-Name "@rx .*\.ph(?:p\d*|tml|ar|ps|t|pt)[./]*$" "id:933110,phase:2,deny,msg:'PHP Injection Attack: PHP Script File Upload Found',tag:'paranoia-level/1',severity:'CRITICAL'"
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*|XML://@* "@rx (?i)php://(?:std(?:in|out|err)|(?:in|out)put|f(?:d|ilter)|memory|temp)" "id:933140,phase:2,deny,msg:'PHP Injection Attack: I/O Stream Found',tag:'paranoia-level/1',severity:'CRITICAL'"
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*|XML://@* "@rx (?i)\b\(?[\"']*(?:assert(?:_options)?|c(?:hr|reate_function)|e(?:val|x(?:ec|p))|f(?:ile(?:group)?|open|puts)|glob|i(?:mage(?:gif|(?:jpe|pn)g|wbmp|xbm)|s_a|ntval)|m(?:d5|kdir)|o(?:pendir|rd)|p(?:assthru|hpinfo|open|r(?:intf|ev))|r(?:eadfile|trim)|s(?:t(?:rip_tags|at)|ubstr|ystem)|tmpfile|u(?:n(?:(?:pac|lin)k|serialize)|sort))(?:/\*[^\*]*\*+(?:[^\*/][^\*]*\*+)*/|(?:#|//)[^\n\r]*[\n\r]|[\s\x0b\"])*[\"']*\)?[\s\x0b]*\([^\)]*\)" "id:933160,phase:2,deny,msg:'PHP Injection Attack: High-Risk PHP Function Call Found',tag:'paranoia-level/1',severity:'CRITICAL'"
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS|ARGS_NAMES|ARGS|XML:/*|XML://@* "@rx [oOcC]:\d+:\".+?\":\d+:\{.*}" "id:933170,phase:2,deny,msg:'PHP Injection Attack: Serialized Object Injection',tag:'paranoia-level/1',severity:'CRITICAL'"
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*|XML://@* "@rx (?:bzip2|expect|glob|ogg|(?:ph|r)ar|ssh2(?:.(?:s(?:hell|(?:ft|c)p)|exec|tunnel))?|z(?:ip|lib))://" "id:933200,phase:2,deny,msg:'PHP Injection Attack: Wrapper scheme detected',tag:'paranoia-level/1',severity:'CRITICAL'"
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_FILENAME|REQUEST_HEADERS|!REQUEST_HEADERS:Cookie|ARGS_NAMES|ARGS|XML:/*|XML://@* "@rx (?i)<script[^>]*>[\s\S]*?" "id:941110,phase:2,deny,msg:'XSS Filter - Category 1: Script Tag Vector',tag:'paranoia-level/1',severity:'CRITICAL'"
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS:User-Agent|ARGS_NAMES|ARGS|REQUEST_FILENAME|XML:/*|XML://@* "@rx (?i).(?:\b(?:(?:x(?:link:href|html|mlns)|data:text/html|formaction)\b|pattern[\s\x0b]*=)|(?:!ENTITY[\s\x0b]+(?:%[\s\x0b]+)?[^\s\x0b]+[\s\x0b]+(?:SYSTEM|PUBLIC)|@import|;base64)\b)" "id:941130,phase:2,deny,msg:'XSS Filter - Category 3: Attribute Vector',tag:'paranoia-level/1',severity:'CRITICAL'"
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|REQUEST_FILENAME|XML:/*|XML://@* "@rx \{\{.*?}}" "id:941380,phase:2,deny,msg:'AngularJS client side template injection detected',tag:'paranoia-level/2',severity:'CRITICAL'"
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|REQUEST_FILENAME|XML:/*|XML://@* "@rx (?i)\b(?:eval|set(?:timeout|interval)|new[\s\x0b]+Function|a(?:lert|tob)|btoa|(?:promp|impor)t|con(?:firm|sole\.(?:log|dir))|fetch)[\s\x0b]*[\(\{]" "id:941390,phase:2,deny,msg:'Javascript method detected',tag:'paranoia-level/1',severity:'CRITICAL'"
SecRule REQUEST_FILENAME|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*|XML://@* "@rx (?i:sleep\s*?\(.*?\)|benchmark\s*?\(.*?\,.*?\))" "id:942160,phase:2,deny,msg:'Detects blind sqli tests using sleep() or benchmark()',tag:'paranoia-level/1',severity:'CRITICAL'"
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*|XML://@* "@rx (?i)(?:select|;)[\s\x0b]+(?:benchmark|if|sleep)[\s\x0b]*?\([\s\x0b]*?\(?[\s\x0b]*?[0-9A-Z_a-z]+" "id:942170,phase:2,deny,msg:'Detects SQL benchmark and sleep injection attempts including conditional queries',tag:'paranoia-level/1',severity:'CRITICAL'"
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*|XML://@* "@rx (?i)union.*?select.*?from" "id:942270,phase:2,deny,msg:'Looking for basic sql injection. Common attack string for mysql, oracle and others',tag:'paranoia-level/1',severity:'CRITICAL'"
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*|XML://@* "@rx (?i)\bx?or\b(?:[\s\x0b]+[0-9]{1,10}(?:[\s\x0b]*[<->])?|[\s\x0b]*[\"'][^=]+[\"'])|[\"'][\s\x0b]+\bx?or\b[\s\x0b]+[^!\+\-<->]+[!\+\-<->]" "id:942390,phase:2,deny,msg:'SQL Injection Attack using (X)OR',tag:'paranoia-level/2',severity:'CRITICAL'"
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*|XML://@* "@rx (?i)/\*[\s\x0b]*?[!\+](?:[\s\x0b\(\)\-0-9=A-Z_a-z]+)?\*/" "id:942500,phase:2,deny,msg:'MySQL in-line comment detected',tag:'paranoia-level/1',severity:'CRITICAL'"
`

// raspRequestScannerPhrases mirrors CRS rule 913100, which uses
// @pmFromFile scanners-user-agents.data. The data file is inlined so the pack
// stays self-contained for offline probes.
var raspRequestScannerPhrases = []string{
	"arachni", "Mozilla/6.0", "betabot", "bewica-security-scan", "BFAC",
	"commix", "Detectify", "dirbuster", "fimap", "fuzz faster", "whatwaf",
	"gobuster", "havij", "hexometer", "jbrofuzz", "jorgee", "libwhisker",
	"masscan", "morfeus", "Mozlila", "Mozilla/5.g", "nessus", "netlab360",
	"netsparker", "nettacker", "nikto", "nmap", "nuclei", "openvas",
	"php2shell", "securityagent", "sitelockspider", "sqlmap", "sysscan",
	"TsunamiSecurityScanner", "w3af.org", "webbandit", "webshag", "wfuzz",
	"whatweb", "wprecon", "wpscan", "feroxbuster", "l9explore", "l9tcpid",
	"wapiti", "vega/", "appspider", "ironwasp", "skipfish", "qualysguard",
	"n-stalker", "acunetix", "cmsmap", "sqlninja", "xsstrike", "xsser",
	"joomscan", "droopescan", "zgrab", "Ghauri", "zmeu", "WPProbe",
	"SSTIMap", "Mozilla/4.0 (Hydra)", "tplmap", "DotDotPwn", "shortscan",
	"Kadimus", "LFISuite", "Mozilla/5.0 (compatible; Panoptic", "LFImap",
	"graphw00f", "graphql-cop", "jSQL", "noseyparker", "TruffleHog",
	"YesWeHack-Hunter", "TInjA", "Mozilla/5.0 (compatible; AppScan;",
}

type raspRequestRuleLimits struct {
	MaxPathBytes    int `json:"max_path_bytes"`
	MaxQueryBytes   int `json:"max_query_bytes"`
	MaxBodyBytes    int `json:"max_body_bytes"`
	MaxHeadersBytes int `json:"max_headers_bytes"`
	MaxHeaderCount  int `json:"max_header_count"`
	MaxEvidence     int `json:"max_evidence_bytes"`
}

type raspRequestRule struct {
	ID       string   `json:"id"`
	Category string   `json:"category"`
	Severity string   `json:"severity"`
	Paranoia int      `json:"paranoia"`
	Operator string   `json:"operator"`
	Pattern  string   `json:"pattern,omitempty"`
	Phrases  []string `json:"phrases,omitempty"`
	Targets  []string `json:"targets"`
	Message  string   `json:"message"`
	Action   string   `json:"action"`
	Source   string   `json:"source"`
}

type raspRequestRulePack struct {
	SchemaVersion string                `json:"schema_version"`
	Source        string                `json:"source"`
	SourceVersion string                `json:"source_version"`
	GeneratedAt   string                `json:"generated_at"`
	ParanoiaLevel int                   `json:"paranoia_level"`
	Limits        raspRequestRuleLimits `json:"limits"`
	Rules         []raspRequestRule     `json:"rules"`
	Notes         []string              `json:"notes,omitempty"`
	Digest        string                `json:"digest"`
}

var (
	raspRequestPackCache = map[int]*raspRequestRulePack{}
	raspRequestPackMu    sync.Mutex
)

// getRASPRequestRulePack builds (and caches) the deterministic pack for the
// requested paranoia level. Levels outside 1-2 are clamped because only PL1-2
// CRS request rules are extracted.
func getRASPRequestRulePack(paranoia int) *raspRequestRulePack {
	if paranoia < 1 {
		paranoia = 1
	}
	if paranoia > raspRequestRulesMaxParanoia {
		paranoia = raspRequestRulesMaxParanoia
	}
	raspRequestPackMu.Lock()
	defer raspRequestPackMu.Unlock()
	if pack, ok := raspRequestPackCache[paranoia]; ok {
		return pack
	}
	pack := buildRASPRequestRulePack(paranoia)
	finalizeRASPRequestRulePack(pack)
	raspRequestPackCache[paranoia] = pack
	return pack
}

func buildRASPRequestRulePack(paranoia int) *raspRequestRulePack {
	rules := make([]raspRequestRule, 0, 32)
	for _, block := range collectModSecurityBlocks(raspRequestCRSSubset) {
		rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(block), "SecRule"))
		targetsToken, rest := nextModSecurityToken(rest)
		id := extractRuleAttribute(block, `id:?'?([0-9]+)'?`)
		if id == "" {
			continue
		}
		level := 1
		if raw := extractRuleAttribute(block, `paranoia-level/([0-9]+)`); raw != "" {
			level, _ = strconv.Atoi(raw)
		}
		if level > paranoia {
			continue
		}
		pattern := extractRulePattern(block)
		if pattern == "" || isMatchAllRegex(pattern) {
			continue
		}
		if _, err := regexp.Compile(pattern); err != nil {
			// A pattern that RE2 cannot compile must never reach a probe:
			// skipping the rule fails open instead of shipping a broken pack.
			continue
		}
		targets := mapRASPRequestTargets(targetsToken)
		if len(targets) == 0 {
			continue
		}
		message := firstNonEmpty(extractRuleAttribute(block, `msg:'([^']+)'`), "OWASP CRS Rule "+id)
		severity := strings.ToLower(firstNonEmpty(extractRuleAttribute(block, `severity:'?([A-Z]+)'?`), "medium"))
		rules = append(rules, raspRequestRule{
			ID:       "owasp-crs-" + id,
			Category: raspRequestCategory(id, pattern),
			Severity: severityFromCRS(severity),
			Paranoia: level,
			Operator: "rx",
			Pattern:  pattern,
			Targets:  targets,
			Message:  message,
			Action:   "block",
			Source:   raspRequestRulesSource,
		})
	}
	if paranoia >= 1 {
		rules = append(rules, raspRequestRule{
			ID:       "owasp-crs-913100",
			Category: "scanner",
			Severity: "critical",
			Paranoia: 1,
			Operator: "pm",
			Phrases:  append([]string(nil), raspRequestScannerPhrases...),
			Targets:  []string{"header:user-agent"},
			Message:  "Found User-Agent associated with security scanner",
			Action:   "block",
			Source:   raspRequestRulesSource,
		})
	}
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return &raspRequestRulePack{
		SchemaVersion: raspRequestRulesSchema,
		Source:        raspRequestRulesSource,
		SourceVersion: raspRequestRulesSourceVersion,
		GeneratedAt:   raspRequestRulesGeneratedAt,
		ParanoiaLevel: paranoia,
		Limits: raspRequestRuleLimits{
			MaxPathBytes: 4096, MaxQueryBytes: 8192, MaxBodyBytes: 64 * 1024,
			MaxHeadersBytes: 8192, MaxHeaderCount: 100, MaxEvidence: 256,
		},
		Rules: rules,
		Notes: []string{
			"@detectSQLi is not representable as a regexp; it stays covered by sink-level detectors and the platform engine.",
			"913100 uses an inlined scanner User-Agent phrase list instead of @pmFromFile.",
			"Only request-side CRS rules at paranoia level 1-2 are included.",
		},
	}
}

func finalizeRASPRequestRulePack(pack *raspRequestRulePack) {
	pack.Digest = ""
	raw, err := json.MarshalIndent(pack, "", "  ")
	if err != nil {
		return
	}
	sum := sha256.Sum256(raw)
	pack.Digest = hex.EncodeToString(sum[:])
}

func encodeRASPRequestRulePack(pack *raspRequestRulePack) ([]byte, error) {
	raw, err := json.MarshalIndent(pack, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// mapRASPRequestTargets translates ModSecurity variable names into the small
// field vocabulary understood by runtime probes.
func mapRASPRequestTargets(raw string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, 4)
	add := func(value string) {
		if value == "" || seen[value] {
			return
		}
		seen[value] = true
		out = append(out, value)
	}
	for _, token := range strings.Split(raw, "|") {
		token = strings.TrimSpace(token)
		if token == "" || strings.HasPrefix(token, "!") {
			continue
		}
		switch token {
		case "ARGS", "ARGS_NAMES", "ARGS_GET", "ARGS_POST", "REQUEST_ARGS":
			add("query")
			add("body")
		case "REQUEST_URI", "REQUEST_URI_RAW", "REQUEST_FILENAME", "REQUEST_BASENAME":
			add("path")
		case "QUERY_STRING":
			add("query")
		case "REQUEST_BODY", "REQUEST_BODY_RAW":
			add("body")
		case "REQUEST_HEADERS":
			add("headers")
		case "REQUEST_COOKIES", "REQUEST_COOKIES_NAMES":
			add("cookies")
		case "REQUEST_METHOD":
			add("method")
		case "REQUEST_LINE":
			add("request_line")
		case "FILES":
			add("header:x-filename")
		default:
			if name, ok := strings.CutPrefix(token, "REQUEST_HEADERS:"); ok {
				name = strings.ToLower(strings.TrimSpace(name))
				if name != "" {
					add("header:" + name)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

func raspRequestCategory(id, pattern string) string {
	switch {
	case strings.HasPrefix(id, "913"):
		return "scanner"
	case strings.HasPrefix(id, "930"):
		return "path_traversal"
	case strings.HasPrefix(id, "931"):
		return "rfi"
	case strings.HasPrefix(id, "932"):
		return "rce"
	case strings.HasPrefix(id, "933"):
		if id == "933140" || id == "933200" {
			return "lfi"
		}
		return "webshell"
	case strings.HasPrefix(id, "941"):
		return "xss"
	case strings.HasPrefix(id, "942"):
		return "sqli"
	case strings.Contains(pattern, `\.\.`):
		return "path_traversal"
	default:
		return "unknown"
	}
}

func raspRequestRuleEnabled() bool {
	return toBool(getEnv("LYFLOW_RASP_REQUEST_RULES_ENABLED", "true"))
}

// raspRequestRulesStatusHandler reports pack metadata without exposing a
// second policy surface. Enforcement remains controlled by the signed RASP
// policy delivered through the existing bridge.
func raspRequestRulesStatusHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		if !raspRequestRuleEnabled() {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code": 0, "message": "success",
				"data": map[string]interface{}{
					"enabled": false, "schema_version": raspRequestRulesSchema,
					"source": raspRequestRulesSource, "source_version": raspRequestRulesSourceVersion,
				},
			})
			return
		}
		pack := getRASPRequestRulePack(raspRequestRulesMaxParanoia)
		categories := map[string]int{}
		for _, rule := range pack.Rules {
			categories[rule.Category]++
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 0, "message": "success",
			"data": map[string]interface{}{
				"enabled":          true,
				"schema_version":   pack.SchemaVersion,
				"source":           pack.Source,
				"source_version":   pack.SourceVersion,
				"generated_at":     pack.GeneratedAt,
				"paranoia_level":   pack.ParanoiaLevel,
				"max_paranoia":     raspRequestRulesMaxParanoia,
				"rule_count":       len(pack.Rules),
				"categories":       categories,
				"limits":           pack.Limits,
				"digest":           pack.Digest,
				"download_path":    "/api/v1/rasp/request-rules/download",
				"enforcement_note": "probe-side monitor/dry-run/block follows the signed RASP policy; this pack does not enable blocking by itself",
			},
		})
	}
}

// raspRequestRulesDownloadHandler serves the probe-consumable JSON pack.
// ?paranoia=1|2 selects the CRS paranoia level (default 2).
func raspRequestRulesDownloadHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		if !raspRequestRuleEnabled() {
			writeJSONError(w, http.StatusNotFound, "rasp_request_rules_disabled", "RASP request rule pack is disabled")
			return
		}
		paranoia := raspRequestRulesMaxParanoia
		if raw := strings.TrimSpace(r.URL.Query().Get("paranoia")); raw != "" {
			value, err := strconv.Atoi(raw)
			if err != nil || value < 1 || value > raspRequestRulesMaxParanoia {
				writeJSONError(w, http.StatusBadRequest, "invalid_paranoia_level", "paranoia must be 1 or 2")
				return
			}
			paranoia = value
		}
		pack := getRASPRequestRulePack(paranoia)
		payload, err := encodeRASPRequestRulePack(pack)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "rasp_request_rules_encode_failed", err.Error())
			return
		}
		etag := `"` + pack.Digest + `"`
		w.Header().Set("ETag", etag)
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Ly-RASP-Rule-Pack", pack.SchemaVersion)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="lyflow-rasp-request-rules.json"`)
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(payload)
	}
}
