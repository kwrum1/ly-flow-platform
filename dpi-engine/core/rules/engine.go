package rules

import (
	"bufio"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"ly-flow-platform/dpi-engine/model"
)

type Severity int

const (
	SeverityUnknown Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

type ThreatCategory string

const (
	CategoryMalware    ThreatCategory = "malware"
	CategoryC2         ThreatCategory = "c2"
	CategoryExploit    ThreatCategory = "exploit"
	CategoryDataExfil  ThreatCategory = "data_exfil"
	CategoryLateral    ThreatCategory = "lateral_movement"
	CategoryRecon      ThreatCategory = "recon"
	CategoryBruteForce ThreatCategory = "brute_force"
	CategorySuspicious ThreatCategory = "suspicious"
	CategoryCrypto     ThreatCategory = "crypto"
)

type Rule struct {
	SID           int
	Msg           string
	Protocol      string
	Severity      Severity
	Category      ThreatCategory
	Match         func(*model.FlowData) bool
	MatchCount    uint64
	LastMatchTime int64
	metadata      map[string]string
}

type Engine struct {
	rules      map[int]*Rule
	rulesByCat map[ThreatCategory][]*Rule
	index      *RuleIndex
	mu         sync.RWMutex
	totalHits  uint64
}

type RuleIndex struct {
	byProtocol map[string][]*Rule
	byPort     map[uint16][]*Rule
	byCategory map[ThreatCategory][]*Rule
	byDomain   *regexp.Regexp
}

func New() *Engine {
	e := &Engine{
		rules:      make(map[int]*Rule),
		rulesByCat: make(map[ThreatCategory][]*Rule),
		index: &RuleIndex{
			byProtocol: make(map[string][]*Rule),
			byPort:     make(map[uint16][]*Rule),
			byCategory: make(map[ThreatCategory][]*Rule),
		},
	}
	e.index.byDomain = regexp.MustCompile(`(?i)(miner|crypto|coin|torrent|malware|exploit|c2|botnet)`)
	return e
}

func (e *Engine) LoadRulesFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		rule, err := parseRule(line)
		if err != nil || rule == nil {
			continue
		}
		e.AddRule(rule)
	}
	return scanner.Err()
}

func (e *Engine) AddRule(rule *Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.rules[rule.SID] = rule
	e.rulesByCat[rule.Category] = append(e.rulesByCat[rule.Category], rule)

	if rule.Protocol != "" {
		e.index.byProtocol[rule.Protocol] = append(e.index.byProtocol[rule.Protocol], rule)
	}

	e.index.byCategory[rule.Category] = append(e.index.byCategory[rule.Category], rule)
}

func (e *Engine) Match(flow *model.FlowData) []*Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var matched []*Rule

	for _, rule := range e.rules {
		if rule.Match(flow) {
			rule.MatchCount++
			rule.LastMatchTime = flow.Timestamp
			matched = append(matched, rule)
		}
	}

	if len(matched) > 0 {
		e.totalHits++
	}

	return matched
}

func (e *Engine) MatchWithIndex(flow *model.FlowData) []*Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var matched []*Rule

	candidates := e.getCandidates(flow)
	for _, rule := range candidates {
		if rule.Match(flow) {
			rule.MatchCount++
			rule.LastMatchTime = flow.Timestamp
			matched = append(matched, rule)
		}
	}

	if len(matched) > 0 {
		e.totalHits++
	}

	return matched
}

func (e *Engine) getCandidates(flow *model.FlowData) []*Rule {
	var candidates []*Rule

	if protoRules, ok := e.index.byProtocol[flow.Protocol]; ok {
		candidates = append(candidates, protoRules...)
	}

	if portRules, ok := e.index.byPort[flow.DstPort]; ok {
		candidates = append(candidates, portRules...)
	}

	if flow.AppProtocol != "" {
		if protoRules, ok := e.index.byProtocol[flow.AppProtocol]; ok {
			candidates = append(candidates, protoRules...)
		}
	}

	if domain := flow.GetDomain(); domain != "" && e.index.byDomain.MatchString(domain) {
		for _, rules := range e.rulesByCat {
			candidates = append(candidates, rules...)
		}
	}

	return candidates
}

func (e *Engine) GetStats() (rules, hits int, byCategory map[string]int) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rules = len(e.rules)
	hits = int(e.totalHits)
	byCategory = make(map[string]int)

	for cat, catRules := range e.rulesByCat {
		count := 0
		for _, r := range catRules {
			count += int(r.MatchCount)
		}
		byCategory[string(cat)] = count
	}

	return
}

func (e *Engine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

func parseRule(line string) (*Rule, error) {
	if !strings.HasPrefix(line, "alert") {
		return nil, nil
	}

	parts := strings.SplitN(line, "(", 2)
	if len(parts) < 2 {
		return nil, nil
	}

	header := strings.TrimSpace(parts[0])
	optionsStr := strings.TrimSuffix(parts[1], ")")

	headerParts := strings.Fields(header)
	if len(headerParts) < 4 {
		return nil, nil
	}

	protocol := headerParts[1]
	options := parseOptions(optionsStr)

	sid := 0
	if sidStr, ok := options["sid"]; ok {
		if v, err := strconv.Atoi(sidStr); err == nil {
			sid = v
		}
	}

	msg := options["msg"]
	if msg == "" {
		msg = "Unknown alert"
	}

	severity := parseSeverity(options["classtype"])

	category := parseCategory(options["classtype"], msg)

	rule := &Rule{
		SID:      sid,
		Msg:      msg,
		Protocol: protocol,
		Severity: severity,
		Category: category,
		Match:    buildMatchFunc(options),
	}

	return rule, nil
}

func parseOptions(opts string) map[string]string {
	result := make(map[string]string)

	parts := strings.Split(opts, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			key := strings.TrimSpace(kv[0])
			value := cleanOptionValue(kv[1])
			result[key] = value
		} else {
			result[part] = ""
		}
	}

	return result
}

func cleanOptionValue(value string) string {
	value = strings.TrimSpace(value)
	if unquoted, err := strconv.Unquote(value); err == nil {
		return unquoted
	}
	return strings.Trim(value, `"`)
}

func parseSeverity(classtype string) Severity {
	high := []string{"attempted-admin", "attempted-user", "injected", "malware", "botnet", "c2", "ransomware"}
	medium := []string{"attempted-dos", "suspicious", "shellcode-detect", "exploit"}
	low := []string{"bad-win", "string-detect", "protocol-command-decode"}

	classtype = strings.ToLower(classtype)

	for _, s := range high {
		if strings.Contains(classtype, s) {
			return SeverityHigh
		}
	}
	for _, s := range medium {
		if strings.Contains(classtype, s) {
			return SeverityMedium
		}
	}
	for _, s := range low {
		if strings.Contains(classtype, s) {
			return SeverityLow
		}
	}

	return SeverityMedium
}

func parseCategory(classtype, msg string) ThreatCategory {
	classtype = strings.ToLower(classtype)
	msg = strings.ToLower(msg)

	if strings.Contains(classtype, "malware") || strings.Contains(msg, "malware") {
		return CategoryMalware
	}
	if strings.Contains(classtype, "c2") || strings.Contains(msg, "c2") || strings.Contains(msg, "command") {
		return CategoryC2
	}
	if strings.Contains(classtype, "exploit") || strings.Contains(msg, "exploit") {
		return CategoryExploit
	}
	if strings.Contains(classtype, "brute") || strings.Contains(msg, "brute") {
		return CategoryBruteForce
	}
	if strings.Contains(classtype, "recon") || strings.Contains(msg, "scan") {
		return CategoryRecon
	}
	if strings.Contains(classtype, "crypto") || strings.Contains(msg, "crypto") || strings.Contains(msg, "mining") {
		return CategoryCrypto
	}
	if strings.Contains(classtype, "exfil") || strings.Contains(msg, "data") {
		return CategoryDataExfil
	}

	return CategorySuspicious
}

func buildMatchFunc(options map[string]string) func(*model.FlowData) bool {
	content := options["content"]
	pcre := options["pcre"]
	domain := options["domain"]
	dnsQuery := options["dns.query"]
	tlsSNI := options["tls.sni"]

	if domain != "" || dnsQuery != "" || tlsSNI != "" {
		domainRE := regexp.MustCompile(domain)
		dnsRE := regexp.MustCompile(dnsQuery)
		tlsRE := regexp.MustCompile(tlsSNI)
		return func(f *model.FlowData) bool {
			dom := f.GetDomain()
			if domain != "" && domainRE.MatchString(dom) {
				return true
			}
			if dnsQuery != "" && dnsRE.MatchString(f.DNSQuery) {
				return true
			}
			if tlsSNI != "" && tlsRE.MatchString(f.TLSSNI) {
				return true
			}
			return false
		}
	}

	if content != "" && pcre != "" {
		contentRe := regexp.MustCompile(content)
		pcreRe := regexp.MustCompile(pcre)
		return func(f *model.FlowData) bool {
			return contentRe.MatchString(f.AppProtocol) && pcreRe.MatchString(f.HTTPHost)
		}
	}

	if content != "" {
		contentRe := regexp.MustCompile(content)
		return func(f *model.FlowData) bool {
			return contentRe.MatchString(f.AppProtocol)
		}
	}

	if pcre != "" {
		pcreRe := regexp.MustCompile(pcre)
		return func(f *model.FlowData) bool {
			return pcreRe.MatchString(f.HTTPHost)
		}
	}

	return func(f *model.FlowData) bool { return false }
}

// LoadDatabaseRules loads database detection rules from a directory
func (e *Engine) LoadDatabaseRules(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	dbRules := map[string]uint16{
		"mysql":    3306,
		"mariadb":  3306,
		"postgres": 5432,
		"redis":    6379,
		"mongodb":  27017,
		"oracle":   1521,
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rules") {
			continue
		}

		file, err := os.Open(dir + "/" + entry.Name())
		if err != nil {
			log.Printf("[规则] 加载数据库规则 %s 失败: %v", entry.Name(), err)
			continue
		}

		dbName := strings.TrimSuffix(entry.Name(), ".rules")
		defaultPort := dbRules[dbName]

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			rule, err := parseDatabaseRule(line, dbName, defaultPort)
			if err != nil || rule == nil {
				continue
			}
			e.AddRule(rule)
		}
		file.Close()
	}

	return nil
}

// parseDatabaseRule parses a database detection rule with port and protocol matching
func parseDatabaseRule(line, dbName string, defaultPort uint16) (*Rule, error) {
	if !strings.HasPrefix(line, "alert") {
		return nil, nil
	}

	parts := strings.SplitN(line, "(", 2)
	if len(parts) < 2 {
		return nil, nil
	}

	header := strings.TrimSpace(parts[0])
	optionsStr := strings.TrimSuffix(parts[1], ")")

	headerParts := strings.Fields(header)
	if len(headerParts) < 5 {
		return nil, nil
	}

	protocol := headerParts[1]
	dstPortStr := headerParts[len(headerParts)-1]

	var port uint16
	if dstPortStr != "any" {
		if p, err := strconv.ParseUint(dstPortStr, 10, 16); err == nil {
			port = uint16(p)
		}
	} else {
		port = defaultPort
	}

	options := parseOptions(optionsStr)

	sid := 0
	if sidStr, ok := options["sid"]; ok {
		if v, err := strconv.Atoi(sidStr); err == nil {
			sid = v
		}
	}

	msg := options["msg"]
	if msg == "" {
		msg = dbName + " alert"
	}

	rule := &Rule{
		SID:      sid,
		Msg:      msg,
		Protocol: protocol,
		Severity: SeverityCritical,
		Category: parseDbCategory(msg),
		Match:    buildDatabaseMatchFunc(options, port),
	}

	return rule, nil
}

// parseDbCategory determines threat category for database alerts
func parseDbCategory(msg string) ThreatCategory {
	msg = strings.ToLower(msg)

	if strings.Contains(msg, "brute") || strings.Contains(msg, "multiple") {
		return CategoryBruteForce
	}
	if strings.Contains(msg, "sql") || strings.Contains(msg, "injection") {
		return CategoryExploit
	}
	if strings.Contains(msg, "unauthorized") || strings.Contains(msg, "access denied") {
		return CategorySuspicious
	}
	if strings.Contains(msg, "malicious") || strings.Contains(msg, "exploit") {
		return CategoryExploit
	}
	if strings.Contains(msg, "exfil") || strings.Contains(msg, "data") {
		return CategoryDataExfil
	}

	return CategorySuspicious
}

// buildDatabaseMatchFunc creates a match function for database rules
func buildDatabaseMatchFunc(options map[string]string, port uint16) func(*model.FlowData) bool {
	content := normalizeSuricataContent(options["content"])
	pcre := options["pcre"]
	var pcreRe *regexp.Regexp
	if pcre != "" {
		pattern := strings.Trim(pcre, "/")
		if compiled, err := regexp.Compile(pattern); err == nil {
			pcreRe = compiled
		}
	}

	if content != "" && pcreRe != nil {
		return func(f *model.FlowData) bool {
			haystack := databaseSearchText(f)
			return f.DstPort == port && strings.Contains(haystack, content) && pcreRe.MatchString(haystack)
		}
	}

	if content != "" {
		return func(f *model.FlowData) bool {
			return f.DstPort == port && strings.Contains(databaseSearchText(f), content)
		}
	}

	return func(f *model.FlowData) bool {
		return f.DstPort == port
	}
}

func normalizeSuricataContent(content string) string {
	content = strings.ToLower(content)
	content = strings.ReplaceAll(content, "|20", " ")
	content = strings.ReplaceAll(content, "|0d", "\r")
	content = strings.ReplaceAll(content, "|0a", "\n")
	return content
}

func databaseSearchText(f *model.FlowData) string {
	if f == nil {
		return ""
	}
	return strings.ToLower(strings.Join([]string{
		f.AppProtocol,
		f.HTTPMethod,
		f.HTTPPath,
		f.HTTPHost,
		f.DNSQuery,
		f.TLSSNI,
	}, " "))
}
