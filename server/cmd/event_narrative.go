package main

import (
	"fmt"
	"strings"
)

// Human-readable event narrative.
//
// The console previously rendered raw rule text, for example:
//   "ET WEB_SERVER /etc/passwd Detected in URI"
//   "GPL SNMP public access udp"
// plus bare IPs. That is a signature name, not an explanation: it does not say
// who attacked whom, what was attempted, or why it matters. P0-7 review then
// asks an analyst to mark an event true/false positive, which they cannot do
// from a signature name.
//
// suricataEventNarrative produces one sentence that answers:
//   who  -> source, with the real client when a proxy forwarded it
//   whom -> the victim as a hostname when the request named one
//   what -> the attack class, in plain language
//   why  -> the concrete impact if it succeeded
//
// Everything is derived from fields already stored on the event; nothing is
// invented. When a field is missing the sentence degrades to what is known
// rather than guessing.

// attackClass describes a signature family in analyst language.
type attackClass struct {
	// Name is the short label shown in the UI ("SQL 注入").
	Name string
	// Attempt is what the attacker tried to do, as a verb phrase.
	Attempt string
	// Impact is what happens if it works.
	Impact string
	// Keywords match the lowercased signature text.
	Keywords []string
}

// attackClasses is ordered: the first match wins, so the most specific
// families come before the generic ones.
var attackClasses = []attackClass{
	{
		Name: "SQL 注入", Attempt: "在请求参数中注入 SQL 语句，试图让数据库执行它",
		Impact:   "成功后会读取或篡改数据库内容，严重时可通过数据库执行系统命令",
		Keywords: []string{"sql injection", "sqli", "sql inject", "union select", "xp_cmdshell", "select sleep", "information schema"},
	},
	{
		Name: "路径穿越/任意文件读取", Attempt: "用 ../ 或绝对路径跳出网站目录，读取服务器上的文件",
		Impact:   "成功后会泄露配置文件、密码、源码等敏感文件",
		Keywords: []string{"/etc/passwd", "/etc/shadow", "path traversal", "directory traversal", "traversal", "../"},
	},
	{
		Name: "命令注入/远程代码执行", Attempt: "把系统命令或脚本代码塞进请求，让服务器执行",
		Impact:   "成功后会完全控制服务器",
		Keywords: []string{"command execution", "command injection", "rce", "ogNL", "ognl", "expression injection", "eval", "base64_decode", "shell"},
	},
	{
		Name: "WebShell 上传", Attempt: "上传可执行的脚本文件，用于长期控制网站",
		Impact:   "成功后攻击者可以随时远程执行命令、留后门",
		Keywords: []string{"webshell", "web shell", "file upload", "uploaded"},
	},
	{
		Name: "跨站脚本 (XSS)", Attempt: "在页面中注入脚本，劫持访问者的浏览器",
		Impact:   "成功后可窃取登录凭据或以受害者身份操作",
		Keywords: []string{"xss", "cross site scripting", "cross-site scripting"},
	},
	{
		Name: "漏洞利用", Attempt: "利用已知漏洞的攻击代码尝试入侵",
		Impact:   "成功后可能获得服务器权限或导致服务不可用",
		Keywords: []string{"exploit", "cve-", "cve_", "struts", "spring", "log4j", "minio", "activemq", "next.js", "middleware authorization bypass"},
	},
	{
		Name: "未授权访问/默认凭据", Attempt: "用默认或空口令直接访问本应受保护的服务",
		Impact:   "成功后无需破解即可读取设备配置、账号等信息，常被用于下一步横向",
		Keywords: []string{"snmp public access", "public access", "default credential", "default password", "anonymous", "unauthenticated", "unauthorized access"},
	},
	{
		Name: "扫描/探测", Attempt: "探测开放端口、服务版本或可用路径，为后续攻击做准备",
		Impact:   "本身不直接入侵，但说明有主机正在被系统地摸底",
		Keywords: []string{"scan", "nmap", "portscan", "probe", "recon"},
	},
	{
		Name: "暴力破解", Attempt: "反复尝试登录凭据",
		Impact:   "成功后可直接以合法身份进入系统",
		Keywords: []string{"brute", "authentication failure", "failed login", "login attempt"},
	},
	{
		Name: "恶意软件/C2 通信", Attempt: "与已知的恶意基础设施通信",
		Impact:   "说明主机可能已被植入后门，正在接收指令或外传数据",
		Keywords: []string{"malware", "trojan", "c2", "backdoor", "botnet", "rat ", "mining", "coinminer"},
	},
	{
		Name: "DNS 隧道/数据外传", Attempt: "把数据编码进 DNS 查询，绕过常规出口管控外传",
		Impact:   "成功后会持续泄露内部数据且难以被防火墙发现",
		Keywords: []string{"dns tunnel", "tunnel", "exfiltration", "dga"},
	},
	{
		Name: "钓鱼", Attempt: "诱导用户访问仿冒页面或下载带毒文件",
		Impact:   "成功后凭据会被窃取",
		Keywords: []string{"phishing", "phish"},
	},
	{
		Name: "信息泄露", Attempt: "尝试获取服务器配置或内部信息",
		Impact:   "泄露的信息会被用于下一步攻击",
		Keywords: []string{"information leak", "information disclosure", "info leak"},
	},
}

// classifyAttack maps a signature to an attack class. ok=false means no class
// matched, which the narrative reports honestly instead of inventing one.
func classifyAttack(signature string) (attackClass, bool) {
	haystack := strings.ToLower(signature)
	for _, class := range attackClasses {
		for _, keyword := range class.Keywords {
			if strings.Contains(haystack, strings.ToLower(keyword)) {
				return class, true
			}
		}
	}
	return attackClass{}, false
}

// eventNarrativeInput is the minimum an event must provide.
//
// VictimIP is the address the traffic was actually sent to (the wire
// destination). RequestedDomain is what the client asked for (HTTP Host, TLS
// SNI, or DNS name) and is a separate fact: a request can ask for a hostname
// that resolves elsewhere.
type eventNarrativeInput struct {
	Severity        string
	Signature       string
	SourceIP        string
	VictimIP        string
	RequestedDomain string
	// HostLabel names the host that produced a host-side detection (runtime,
	// RASP, YARA). Such an event has no wire destination, so the host itself is
	// the affected target; it is not an address and is never stored as one.
	HostLabel string
	// ForwardedClient is what X-Forwarded-For claimed. Shown as a reference
	// only, never as an established fact: the header is written by the client
	// side.
	ForwardedClient string
	HTTPMethod      string
	HTTPURI         string
	AppProto        string
	Protocol        string
	DstPort         string
	CommunityID     string
}

// buildEventNarrative returns a two-part explanation:
//
//	summary  one sentence: who attacked whom and what was attempted
//	detail   why it matters plus the concrete indicators, one clause each
//
// Both are Chinese prose. The UI shows summary in the list and detail in the
// drawer, so an analyst can triage without knowing Suricata rule names.
func buildEventNarrative(input eventNarrativeInput) (summary, detail string) {
	attacker := strings.TrimSpace(input.SourceIP)
	victimIP := strings.TrimSpace(input.VictimIP)
	domain := strings.TrimSpace(input.RequestedDomain)
	forwarded := strings.TrimSpace(input.ForwardedClient)
	hostLabel := strings.TrimSpace(input.HostLabel)

	who := attacker
	if who == "" {
		who = "未知来源"
	}

	// Whom: the victim is the address the traffic was sent to. The requested
	// domain is reported separately, because requesting a name does not prove
	// which host served it.
	whom := victimIP
	if whom == "" {
		whom = "未知目标（未记录目的地址）"
	}

	class, classified := classifyAttack(input.Signature)
	severityLabel := chineseSeverity(input.Severity)

	var sentence string
	switch {
	case victimIP == "" && hostLabel != "":
		// Host-side detection: there is no wire destination. Name the host that
		// produced the evidence instead of inventing an address for it.
		if classified {
			sentence = fmt.Sprintf("主机 %s 上%s，属于%s。", hostLabel, class.Attempt, class.Name)
		} else {
			sentence = fmt.Sprintf("主机 %s 上触发了一条检测规则「%s」。该规则未归入已知攻击类型，请结合原始载荷判断。", hostLabel, input.Signature)
		}
	case classified:
		sentence = fmt.Sprintf("%s 对 %s %s，属于%s。", who, whom, class.Attempt, class.Name)
	default:
		// No class matched: say what the rule says, without pretending to
		// understand it more than the rule name allows.
		sentence = fmt.Sprintf("%s 对 %s 触发了一条检测规则「%s」。该规则未归入已知攻击类型，请结合原始载荷判断。", who, whom, input.Signature)
	}
	summary = fmt.Sprintf("%s 判定等级：%s。", sentence, severityLabel)

	// Detail: request context first, then the impact.
	parts := make([]string, 0, 5)
	if forwarded != "" && forwarded != attacker {
		// Plain reference: useful for spotting a repeat actor, but the header
		// is self-reported and is not proof of origin.
		parts = append(parts, fmt.Sprintf("请求头自述客户端 %s（X-Forwarded-For，仅供参考）。", forwarded))
	}
	if domain != "" {
		parts = append(parts, fmt.Sprintf("请求的目标域名：%s（域名只说明客户端想访问谁，不等于实际被打的服务器）。", domain))
	}
	if class, ok := classifyAttack(input.Signature); ok {
		parts = append(parts, "如果攻击成功："+class.Impact+"。")
	}
	if uri := strings.TrimSpace(input.HTTPURI); uri != "" {
		method := strings.TrimSpace(input.HTTPMethod)
		if method == "" {
			method = "请求"
		}
		parts = append(parts, fmt.Sprintf("具体请求：%s %s。", method, shorten(uri, 160)))
	}
	if proto := strings.TrimSpace(input.AppProto); proto != "" {
		target := strings.TrimSpace(input.DstPort)
		if target != "" {
			parts = append(parts, fmt.Sprintf("应用层协议 %s，目标端口 %s。", strings.ToUpper(proto), target))
		} else {
			parts = append(parts, fmt.Sprintf("应用层协议 %s。", strings.ToUpper(proto)))
		}
	} else if protocol := strings.TrimSpace(input.Protocol); protocol != "" {
		parts = append(parts, fmt.Sprintf("传输层协议 %s。", strings.ToUpper(protocol)))
	}
	if len(parts) == 0 {
		parts = append(parts, "该事件没有附带更具体的请求细节，请查看原始载荷。")
	}
	return summary, strings.Join(parts, "")
}

// chineseSeverity maps the stored severity to the wording operators use.
func chineseSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return "严重"
	case "high":
		return "高危"
	case "medium":
		return "中危"
	case "low":
		return "低危"
	default:
		return "未知"
	}
}

// shorten trims a long value for inline display, keeping the head because URIs
// are usually distinguished by their path prefix.
func shorten(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "…"
}

// eventNarrativeFromEvent builds the narrative from a stored threat event.
//
// Historical rows predate the promoted columns, so the requested domain is read
// from the nested eve payload when the flat field is absent. The victim is
// always the wire destination: a DNS query or HTTP Host is reported as the
// requested domain, never as the victim.
func eventNarrativeFromEvent(event map[string]interface{}) (string, string) {
	if event == nil {
		return "", ""
	}
	// Incident evidence and unified events wrap the original detector event in
	// raw_event. Read through that wrapper so the same explanation can be built
	// from either shape.
	if inner := asMap(event["raw_event"]); len(inner) > 0 {
		merged := make(map[string]interface{}, len(inner)+len(event))
		for key, value := range inner {
			merged[key] = value
		}
		for key, value := range event {
			merged[key] = value
		}
		event = merged
	}
	httpBlock := asMap(event["http"])
	if len(httpBlock) == 0 {
		httpBlock = asMap(asMap(event["eve"])["http"])
	}
	tlsBlock := asMap(event["tls"])
	if len(tlsBlock) == 0 {
		tlsBlock = asMap(asMap(event["eve"])["tls"])
	}
	dnsBlock := asMap(event["dns"])
	if len(dnsBlock) == 0 {
		dnsBlock = asMap(asMap(event["eve"])["dns"])
	}

	requestedDomain := firstNonEmpty(
		xdrPickString(event, "http_host"),
		xdrPickString(httpBlock, "hostname"),
		xdrPickString(event, "tls_sni"),
		xdrPickString(tlsBlock, "sni"),
		xdrPickString(event, "dns_query"),
		xdrPickString(dnsBlock, "rrname"),
	)

	// X-Forwarded-For is a reference value only. Read it directly from the
	// stored fields; no trust resolution is involved because it is presented as
	// self-reported context, never as the established origin.
	forwarded := firstNonEmpty(
		xdrPickString(event, "client_forwarded_for_observed"),
		xdrPickString(httpBlock, "xff"),
		xdrPickString(event, "client_forwarded_for"),
	)

	return buildEventNarrative(eventNarrativeInput{
		Severity:        xdrPickString(event, "severity"),
		Signature:       firstNonEmpty(xdrPickString(event, "rule_name"), xdrPickString(event, "event_type"), xdrPickString(event, "message")),
		SourceIP:        firstNonEmpty(xdrPickString(event, "src_ip"), xdrPickString(event, "proxy_ip")),
		VictimIP:        firstNonEmpty(xdrPickString(event, "victim_ip"), xdrPickString(event, "dst_ip")),
		RequestedDomain: requestedDomain,
		HostLabel:       firstNonEmpty(xdrPickString(event, "hostname"), xdrPickString(event, "display_name"), xdrPickString(event, "agent_display_name"), xdrPickString(event, "entities.hostname")),
		ForwardedClient: forwarded,
		HTTPMethod:      firstNonEmpty(xdrPickString(event, "http_method"), xdrPickString(httpBlock, "http_method")),
		HTTPURI:         firstNonEmpty(xdrPickString(event, "http_uri"), xdrPickString(httpBlock, "url")),
		AppProto:        xdrPickString(event, "app_proto"),
		Protocol:        xdrPickString(event, "protocol"),
		DstPort:         fmt.Sprintf("%v", event["dst_port"]),
	})
}
