package rulecompiler

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type SourceFile struct {
	Name    string
	Content []byte
}

var ruleHeader = regexp.MustCompile(`(?i)^\s*(alert|drop|pass|reject)\s+([a-z0-9]+)\s+(\S+)\s+(\S+)\s*->\s*(\S+)\s+(\S+)\s*\((.*)\)\s*$`)

type option struct {
	key   string
	value string
}

type ruleState struct {
	sid        int
	msg        string
	classtype  string
	protocol   string
	port       int
	isHTTP     int
	part       string
	regex      string
	buffer     string
	matchValue string
	matchKind  string
	hasMatch   bool
	nocase     bool
	skipReason string
}

// Convert converts Suricata rule files into a ly_probe servicePlugin bundle.
// Unsupported rules are reported in Result.Skipped and never forced.
func Convert(files []SourceFile) Result {
	result := Result{
		Bundle: Bundle{Threat: ThreatClass{Rules: make(map[string]Rule)}},
	}
	seenSID := make(map[int]bool)
	for _, file := range files {
		result.SourceFiles = append(result.SourceFiles, file.Name)
		lines := strings.Split(strings.ReplaceAll(string(file.Content), "\r\n", "\n"), "\n")
		for index, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			state, skipped := parseRule(line)
			if skipped != nil {
				skipped.Source = file.Name
				skipped.Line = index + 1
				result.Skipped = append(result.Skipped, *skipped)
				continue
			}
			if seenSID[state.sid] {
				result.Skipped = append(result.Skipped, SkippedRule{
					SID: state.sid, Msg: state.msg, Reason: "duplicate sid",
					Source: file.Name, Line: index + 1,
				})
				continue
			}
			seenSID[state.sid] = true
			id := strconv.Itoa(state.sid)
			result.Bundle.Threat.Rules[id] = Rule{
				Type: threatType(state.classtype, state.msg), Name: truncate(state.msg, 31),
				Desc: state.msg, Protocol: state.protocol, Port: state.port,
				IsHTTP: state.isHTTP, Part: state.part, Regex: state.regex,
			}
		}
	}
	result.Converted = len(result.Bundle.Threat.Rules)
	return result
}

func parseRule(line string) (*ruleState, *SkippedRule) {
	match := ruleHeader.FindStringSubmatch(line)
	if match == nil {
		return nil, &SkippedRule{Reason: "unsupported rule header"}
	}
	headerProto := strings.ToLower(match[2])
	destPort := match[6]
	options, err := splitOptions(match[7])
	if err != nil {
		return nil, &SkippedRule{Reason: "unterminated option quote"}
	}
	state := &ruleState{buffer: "payload"}
	if port, err := strconv.Atoi(strings.TrimSpace(destPort)); err == nil && port > 0 && port <= 65535 {
		state.port = port
	}
	state.protocol = headerProtocol(headerProto)
	if state.protocol == "" && headerProto != "ip" && headerProto != "any" {
		return nil, &SkippedRule{Reason: "unsupported header protocol " + headerProto}
	}
	state.isHTTP = boolInt(headerProto == "http")

	for _, opt := range options {
		switch opt.key {
		case "msg":
			state.msg = unquote(opt.value)
		case "sid":
			sid, err := strconv.Atoi(strings.TrimSpace(opt.value))
			if err != nil || sid <= 0 || sid > 2147483647 {
				return nil, &SkippedRule{Reason: "invalid sid"}
			}
			state.sid = sid
		case "classtype":
			state.classtype = strings.TrimSpace(opt.value)
		case "content":
			if state.hasMatch {
				state.skipReason = "multiple content/pcre matches are Suricata-only"
				continue
			}
			state.matchValue, state.matchKind, state.hasMatch = opt.value, "content", true
		case "pcre":
			if state.hasMatch {
				state.skipReason = "multiple content/pcre matches are Suricata-only"
				continue
			}
			state.matchValue, state.matchKind, state.hasMatch = opt.value, "pcre", true
		case "nocase":
			state.nocase = true
		case "http_uri", "http.uri", "http_host", "http.host", "http_header", "http.header",
			"http_user_agent", "http.user_agent", "http_method", "http.method", "http_cookie", "http.cookie":
			state.buffer = "http_head"
			state.isHTTP = 1
		case "http_client_body", "http.request_body":
			state.buffer = "http_body"
			state.isHTTP = 1
		case "dns_query", "dns.query":
			state.buffer = "dns_query"
			state.protocol = "udp"
		case "tls_sni", "tls.sni":
			state.buffer = "tls_sni"
			state.protocol = "tcp"
		case "payload", "pkt_data":
			state.buffer = "payload"
		case "flowbits", "byte_test", "byte_jump", "byte_extract", "dsize", "depth", "offset",
			"distance", "within", "file_data", "base64_decode", "base64_data", "luajit",
			"dataset", "threshold", "tag", "replace":
			state.skipReason = "complex matcher is Suricata-only: " + opt.key
			continue
		}
	}
	if state.skipReason != "" {
		return nil, &SkippedRule{SID: state.sid, Msg: state.msg, Reason: state.skipReason}
	}
	if state.sid == 0 {
		return nil, &SkippedRule{Reason: "missing sid"}
	}
	if !state.hasMatch {
		return nil, &SkippedRule{SID: state.sid, Msg: state.msg, Reason: "no simple content/pcre match"}
	}
	applyBuffer(state, state.buffer)
	if state.isHTTP == 1 && state.part == "" {
		state.part = "total"
	}
	if state.matchKind == "content" {
		state.regex, err = contentToRegexForBuffer(state.matchValue, state.buffer)
	} else {
		state.regex, err = pcreToRegex(state.matchValue, state.nocase)
	}
	if err != nil {
		return nil, &SkippedRule{SID: state.sid, Msg: state.msg, Reason: err.Error()}
	}
	if state.nocase && state.matchKind == "content" && !strings.HasPrefix(state.regex, "(?i)") {
		state.regex = "(?i)" + state.regex
	}
	if len(state.regex) > 2048 {
		return nil, &SkippedRule{SID: state.sid, Msg: state.msg, Reason: "regex exceeds 2048 bytes"}
	}
	if _, err := regexp.Compile(state.regex); err != nil {
		return nil, &SkippedRule{SID: state.sid, Msg: state.msg, Reason: "regex not compatible: " + err.Error()}
	}
	if state.msg == "" {
		state.msg = fmt.Sprintf("sid:%d", state.sid)
	}
	return state, nil
}

func applyBuffer(state *ruleState, buffer string) {
	switch buffer {
	case "http_head":
		state.isHTTP, state.part = 1, "head"
	case "http_body":
		state.isHTTP, state.part = 1, "body"
	case "dns_query":
		state.protocol = "udp"
	case "tls_sni":
		state.protocol = "tcp"
	}
}

func headerProtocol(proto string) string {
	switch proto {
	case "http", "tcp", "tls", "ssl", "ssh", "ftp", "smtp", "smb":
		return "tcp"
	case "dns", "udp":
		return "udp"
	case "icmp":
		return ""
	default:
		return ""
	}
}

func threatType(classtype, msg string) string {
	classtype = strings.ToLower(classtype)
	switch {
	case strings.Contains(classtype, "web-application"):
		return "WEB"
	case strings.Contains(classtype, "trojan"), strings.Contains(classtype, "malware"):
		return "MALWARE"
	case strings.Contains(classtype, "recon"), strings.Contains(classtype, "scan"):
		return "RECON"
	case strings.Contains(classtype, "exploit"):
		return "EXPLOIT"
	case strings.Contains(classtype, "policy"):
		return "POLICY"
	case strings.Contains(classtype, "phishing"):
		return "PHISHING"
	case strings.Contains(classtype, "sql"):
		return "SQL"
	case strings.Contains(classtype, "misc"):
		return "MISC"
	}
	upper := strings.ToUpper(msg)
	for _, candidate := range []string{"MALWARE", "EXPLOIT", "WEB", "RECON", "POLICY", "PHISHING", "DNS", "TROJAN", "SHELLCODE"} {
		if strings.Contains(upper, candidate) {
			return candidate
		}
	}
	return "SURICATA"
}

func contentToRegexForBuffer(value, buffer string) (string, error) {
	content, err := decodeContent(value)
	if err != nil {
		return "", err
	}
	if len(content) == 0 {
		return "", fmt.Errorf("empty content")
	}
	if buffer == "dns_query" {
		return dnsContentToRegex(content)
	}
	return bytesToRegex(content), nil
}

func dnsContentToRegex(content []byte) (string, error) {
	labels := strings.Split(string(content), ".")
	if len(labels) == 0 {
		return "", fmt.Errorf("empty dns content")
	}
	var builder strings.Builder
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("dns content is not a plain domain")
		}
		builder.WriteString(fmt.Sprintf(`\x%02x`, len(label)))
		builder.WriteString(bytesToRegex([]byte(label)))
	}
	return builder.String(), nil
}

func pcreToRegex(value string, nocase bool) (string, error) {
	value = strings.TrimSpace(unquote(value))
	if len(value) < 2 || value[0] != '/' {
		return "", fmt.Errorf("pcre must start with /")
	}
	end := -1
	for i := len(value) - 1; i > 0; i-- {
		if value[i] == '/' && value[i-1] != '\\' {
			end = i
			break
		}
	}
	if end < 0 {
		return "", fmt.Errorf("pcre missing closing delimiter")
	}
	flags := value[end+1:]
	for _, flag := range flags {
		if flag != 'i' {
			return "", fmt.Errorf("pcre flag %q is Suricata-only", string(flag))
		}
	}
	pattern := value[1:end]
	pattern = strings.ReplaceAll(pattern, `\/`, `/`)
	if nocase || strings.ContainsRune(flags, 'i') {
		pattern = "(?i)" + pattern
	}
	if _, err := regexp.Compile(pattern); err != nil {
		return "", fmt.Errorf("pcre not compatible: %w", err)
	}
	return pattern, nil
}

func splitOptions(body string) ([]option, error) {
	var options []option
	var current strings.Builder
	inQuote := false
	escaped := false
	flush := func() {
		part := strings.TrimSpace(current.String())
		current.Reset()
		if part == "" {
			return
		}
		if idx := strings.IndexByte(part, ':'); idx >= 0 {
			options = append(options, option{key: strings.ToLower(strings.TrimSpace(part[:idx])), value: strings.TrimSpace(part[idx+1:])})
		} else {
			options = append(options, option{key: strings.ToLower(part)})
		}
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

func decodeContent(value string) ([]byte, error) {
	value = unquote(strings.TrimSpace(value))
	if value == "" {
		return nil, fmt.Errorf("empty content")
	}
	out := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '|':
			end := strings.IndexByte(value[i+1:], '|')
			if end < 0 {
				return nil, fmt.Errorf("unterminated content hex block")
			}
			hexPart := value[i+1 : i+1+end]
			for _, field := range strings.Fields(hexPart) {
				if len(field)%2 != 0 {
					return nil, fmt.Errorf("invalid content hex %q", field)
				}
				for j := 0; j < len(field); j += 2 {
					b, err := strconv.ParseUint(field[j:j+2], 16, 8)
					if err != nil {
						return nil, fmt.Errorf("invalid content hex %q", field)
					}
					out = append(out, byte(b))
				}
			}
			i += end + 1
		case '\\':
			if i+1 < len(value) {
				next := value[i+1]
				switch next {
				case '\\', '"', ';', ':', '|':
					out = append(out, next)
					i++
				case 'x':
					if i+3 < len(value) {
						b, err := strconv.ParseUint(value[i+2:i+4], 16, 8)
						if err == nil {
							out = append(out, byte(b))
							i += 3
							continue
						}
					}
					out = append(out, next)
					i++
				default:
					out = append(out, next)
					i++
				}
			} else {
				out = append(out, '\\')
			}
		default:
			out = append(out, value[i])
		}
	}
	return out, nil
}

func bytesToRegex(content []byte) string {
	var builder strings.Builder
	for _, b := range content {
		if b >= 0x20 && b < 0x7f {
			if strings.ContainsRune(`\.+*?()[]{}^$|`, rune(b)) {
				builder.WriteByte('\\')
			}
			builder.WriteByte(b)
		} else {
			builder.WriteString(fmt.Sprintf(`\x%02x`, b))
		}
	}
	return builder.String()
}

func unquote(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		return value[1 : len(value)-1]
	}
	return value
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
