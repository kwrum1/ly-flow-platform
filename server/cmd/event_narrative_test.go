package main

import (
	"strings"
	"testing"
)

// The console must explain an event in plain language, because triage asks an
// analyst to judge an event and a Suricata signature name is not a judgement
// basis.
func TestBuildEventNarrativeExplainsAttackInPlainLanguage(t *testing.T) {
	summary, detail := buildEventNarrative(eventNarrativeInput{
		Severity:        "high",
		Signature:       "ET WEB_SERVER /etc/passwd Detected in URI",
		SourceIP:        "36.137.171.155",
		VictimIP:        "10.1.0.101",
		RequestedDomain: "cas.example.test",
		HTTPMethod:      "GET",
		HTTPURI:         "/chat/imController/showOrDownByurl.do?dbPath=../../../../../etc/passwd",
		AppProto:        "http",
		DstPort:         "80",
	})

	// The victim address and the attack class must be in the sentence.
	for _, want := range []string{"36.137.171.155", "10.1.0.101", "路径穿越", "高危"} {
		if !strings.Contains(summary, want) {
			t.Fatalf("summary missing %q:\n%s", want, summary)
		}
	}
	// The requested domain belongs to the detail, explicitly not the victim.
	if strings.Contains(summary, "cas.example.test") {
		t.Fatalf("requested domain must not be presented as the victim:\n%s", summary)
	}
	if !strings.Contains(detail, "cas.example.test") {
		t.Fatalf("detail must report the requested domain:\n%s", detail)
	}
	// Detail must state the concrete impact and the request.
	if !strings.Contains(detail, "敏感文件") && !strings.Contains(detail, "泄露") {
		t.Fatalf("detail does not explain impact:\n%s", detail)
	}
	if !strings.Contains(detail, "/chat/imController") {
		t.Fatalf("detail does not include the request:\n%s", detail)
	}
}

// X-Forwarded-For is shown as a reference next to the observed source address,
// never substituted for it.
func TestBuildEventNarrativeShowsForwardedForAsReference(t *testing.T) {
	summary, detail := buildEventNarrative(eventNarrativeInput{
		Severity:        "high",
		Signature:       "ET WEB_SERVER Possible SQL Injection",
		SourceIP:        "10.1.18.252",
		ForwardedClient: "203.0.113.59",
		VictimIP:        "10.1.0.192",
		RequestedDomain: "smkx.example.test",
	})
	// The observed source stays the actor in the summary.
	if !strings.Contains(summary, "10.1.18.252") {
		t.Fatalf("observed source missing:\n%s", summary)
	}
	if strings.Contains(summary, "203.0.113.59") {
		t.Fatalf("XFF must not replace the observed source in the summary:\n%s", summary)
	}
	// It appears in the detail, explicitly marked as unverified.
	if !strings.Contains(detail, "203.0.113.59") || !strings.Contains(detail, "仅供参考") {
		t.Fatalf("XFF must be reported as a reference:\n%s", detail)
	}
}

// An unrecognised rule must not be forced into a category; the narrative says so.
func TestBuildEventNarrativeAdmitsUnknownRule(t *testing.T) {
	summary, _ := buildEventNarrative(eventNarrativeInput{
		Severity:  "medium",
		Signature: "ET SOMETHING Entirely Novel Rule Text",
		SourceIP:  "10.1.1.1",
		VictimIP:  "10.1.1.2",
	})
	if !strings.Contains(summary, "未归入已知攻击类型") {
		t.Fatalf("unknown rule was classified anyway:\n%s", summary)
	}
	if strings.Contains(summary, "如果攻击成功") {
		t.Fatalf("unknown rule invented an impact")
	}
}

// Missing fields must degrade to what is known instead of producing empty prose.
func TestBuildEventNarrativeDegradesGracefully(t *testing.T) {
	summary, detail := buildEventNarrative(eventNarrativeInput{
		Severity:  "low",
		Signature: "ET SCAN NMAP SIP Version Detect",
	})
	if !strings.Contains(summary, "未知来源") || !strings.Contains(summary, "未知目标") {
		t.Fatalf("missing endpoints were not stated:\n%s", summary)
	}
	if detail == "" {
		t.Fatal("detail must never be empty")
	}
	if strings.Contains(summary, "（）") {
		t.Fatalf("narrative contains empty parentheses:\n%s", summary)
	}
}

func TestClassifyAttackCoversTheFamiliesSeenInProduction(t *testing.T) {
	cases := map[string]string{
		"ET WEB_SERVER /etc/passwd Detected in URI":          "路径穿越/任意文件读取",
		"ET WEB_SERVER Possible SQL Injection (exec)":        "SQL 注入",
		"ET EXPLOIT Apache Struts Possible OGNL Java Exec":   "命令注入/远程代码执行",
		"ET SCAN Suspicious inbound to Oracle SQL port 1521": "扫描/探测",
		"GPL SNMP public access udp":                         "未授权访问/默认凭据",
		"ET MALWARE Possible Deep Panda User-Agent":          "恶意软件/C2 通信",
	}
	for signature, want := range cases {
		class, ok := classifyAttack(signature)
		if !ok {
			t.Fatalf("%q was not classified", signature)
		}
		if class.Name != want {
			t.Fatalf("%q classified as %q, want %q", signature, class.Name, want)
		}
		if class.Impact == "" || class.Attempt == "" {
			t.Fatalf("%q has an incomplete definition", signature)
		}
	}
}

// Host-side detections have no wire destination. The host that produced the
// evidence is the affected target; it must be named instead of leaving the
// reader with "unknown target".
func TestBuildEventNarrativeNamesTheHostForHostDetections(t *testing.T) {
	summary, _ := buildEventNarrative(eventNarrativeInput{
		Severity:  "medium",
		Signature: "component.alert",
		HostLabel: "web-01",
	})
	if !strings.Contains(summary, "web-01") {
		t.Fatalf("host missing from narrative:\n%s", summary)
	}
	if strings.Contains(summary, "未知目标") {
		t.Fatalf("host detection must not report an unknown target:\n%s", summary)
	}
}

// Every class must be safely renderable: no empty text, no placeholder.
func TestAttackClassesAreComplete(t *testing.T) {
	for _, class := range attackClasses {
		if class.Name == "" || class.Attempt == "" || class.Impact == "" {
			t.Fatalf("incomplete attack class: %+v", class)
		}
		if len(class.Keywords) == 0 {
			t.Fatalf("attack class %q has no keywords", class.Name)
		}
	}
}
