package rules

import (
	"bufio"
	"os"
	"regexp"
	"strconv"
	"strings"

	"ly-flow-platform/dpi-engine/model"
)

// Engine is the Suricata-style rules engine
type Engine struct {
	rules []*Rule
}

// Rule represents a parsed Suricata rule
type Rule struct {
	SID      int
	Msg      string
	Protocol string
	Match    func(*model.FlowData) bool
}

// New creates a new rules engine
func New() *Engine {
	return &Engine{
		rules: make([]*Rule, 0),
	}
}

// LoadRulesFile loads rules from a Suricata rules file
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
		if err != nil {
			continue // skip invalid rules
		}
		e.rules = append(e.rules, rule)
	}
	return scanner.Err()
}

// Match applies all rules to a flow and returns matching rules
func (e *Engine) Match(flow *model.FlowData) []*Rule {
	var matched []*Rule
	for _, rule := range e.rules {
		if rule.Match(flow) {
			matched = append(matched, rule)
		}
	}
	return matched
}

// parseRule parses a Suricata-style rule
func parseRule(line string) (*Rule, error) {
	// Basic format: alert protocol src dst (options)
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

	// Parse options
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

	rule := &Rule{
		SID:      sid,
		Msg:      msg,
		Protocol: protocol,
		Match:    buildMatchFunc(options),
	}

	return rule, nil
}

// parseOptions parses rule options into a map
func parseOptions(opts string) map[string]string {
	result := make(map[string]string)

	// Simple parser for: key1; key2; key3; etc
	// Some options have values: content:"abc"; pcre:"/regex/"
	parts := strings.Split(opts, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Check for quoted value
		if strings.Contains(part, ":") {
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				key := strings.TrimSpace(kv[0])
				val := strings.TrimSpace(kv[1])
				// Remove quotes if present
				if strings.HasPrefix(val, "\"") && strings.HasSuffix(val, "\"") {
					val = val[1 : len(val)-1]
				}
				result[key] = val
			}
		} else {
			result[part] = ""
		}
	}

	return result
}

// buildMatchFunc creates a match function based on rule options
func buildMatchFunc(options map[string]string) func(*model.FlowData) bool {
	var matchers []func(*model.FlowData) bool

	// Content matcher
	if content, ok := options["content"]; ok {
		content := content
		matchers = append(matchers, func(f *model.FlowData) bool {
			// Check all string fields
			return contains(f.DNSQuery, content) ||
				contains(f.HTTPHost, content) ||
				contains(f.TLSSNI, content)
		})
	}

	// PCRE matcher
	if pcre, ok := options["pcre"]; ok {
		pcre := pcre
		re, err := regexp.Compile(pcre)
		if err == nil {
			matcher := re
			matchers = append(matchers, func(f *model.FlowData) bool {
				return matcher.MatchString(f.DNSQuery) ||
					matcher.MatchString(f.HTTPHost) ||
					matcher.MatchString(f.TLSSNI)
			})
		}
	}

	// DNS query matcher
	if dnsQuery, ok := options["dns.query"]; ok {
		dnsQuery := dnsQuery
		matchers = append(matchers, func(f *model.FlowData) bool {
			return contains(f.DNSQuery, dnsQuery)
		})
	}

	// HTTP host matcher
	if httpHost, ok := options["http.host"]; ok {
		httpHost := httpHost
		matchers = append(matchers, func(f *model.FlowData) bool {
			return contains(f.HTTPHost, httpHost)
		})
	}

	// TLS SNI matcher
	if tlsSNI, ok := options["tls.sni"]; ok {
		tlsSNI := tlsSNI
		matchers = append(matchers, func(f *model.FlowData) bool {
			return contains(f.TLSSNI, tlsSNI)
		})
	}

	// If no matchers, return false
	if len(matchers) == 0 {
		return func(*model.FlowData) bool { return false }
	}

	// Return combined matcher
	return func(f *model.FlowData) bool {
		for _, m := range matchers {
			if !m(f) {
				return false
			}
		}
		return true
	}
}

// contains checks if s contains substr (case-insensitive)
func contains(s, substr string) bool {
	if s == "" || substr == "" {
		return false
	}
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// RuleCount returns the number of loaded rules
func (e *Engine) RuleCount() int {
	return len(e.rules)
}