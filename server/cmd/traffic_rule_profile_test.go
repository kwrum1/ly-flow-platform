package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const trafficTestScenarioYAML = `schema_version: lyflow.traffic-scenario/v1
name: server-zone
display_name: 服务器区流量引擎（测试）
description: test scenario
home_net:
  fallback:
    - 10.0.0.0/8
directions:
  inbound: true
  outbound: true
  internal: false
  ambiguous: true
categories:
  include:
    - malware
    - trojan
    - c2
    - mining
    - exploit
    - tunnel
    - dns
    - tls
    - http
    - web_attack
    - scan
    - suspicious
  exclude:
    - chat
    - games
    - p2p
    - streaming
    - adware
    - toolbar
    - mobile
    - web_client
    - phishing
    - policy
    - retired
    - scada
    - voip
    - tftp
    - user_agents
    - lateral
    - database
    - mail
    - rdp
    - telnet
    - netbios
    - rpc
    - smb
    - uncategorized
  exclude_wins: true
protocols:
  exclude:
    - smb
ports:
  exclude_inbound:
    - 3389
    - 3306
    - 445
  exclude_direction:
    - inbound
    - ambiguous
sources:
  - kind: files
    path: suricata
    glob: "*.rules"
    recursive: false
budget:
  max_total_rules: 100
  max_suricata_rules: 80
  max_lyprobe_rules: 20
  max_total_bytes: 1048576
  max_lyprobe_regex_bytes: 512
assignment:
  lyprobe:
    min_severity: medium
    require_simple_match: true
    require_single_match: true
    allowed_buffers:
      - dns_query
      - tls_sni
      - http_uri
      - http_client_body
    allowed_categories:
      - malware
      - trojan
      - c2
      - mining
      - tunnel
      - dns
      - tls
      - scan
exports:
  root: compiled/server-zone
  suricata_rules: suricata.rules
  lyprobe_source: lyprobe-source.rules
  manifest: profile-manifest.json
`

func writeTrafficTestScenario(t *testing.T, scenarioYAML string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	ruleRoot := filepath.Join(dir, "rules")
	if err := os.MkdirAll(filepath.Join(ruleRoot, "suricata"), 0o755); err != nil {
		t.Fatalf("mkdir rules: %v", err)
	}
	scenarioPath := filepath.Join(dir, "server-zone.yaml")
	if err := os.WriteFile(scenarioPath, []byte(scenarioYAML), 0o644); err != nil {
		t.Fatalf("write scenario: %v", err)
	}
	return scenarioPath, ruleRoot
}

func writeTrafficTestRules(t *testing.T, ruleRoot, name, content string) {
	t.Helper()
	path := filepath.Join(ruleRoot, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir rules dir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write rules %s: %v", name, err)
	}
}

func buildTrafficTestProfile(t *testing.T, scenarioPath, ruleRoot string) trafficProfile {
	t.Helper()
	profile, err := buildTrafficProfile(context.Background(), nil, trafficProfileOptions{ScenarioPath: scenarioPath, RuleRoot: ruleRoot})
	if err != nil {
		t.Fatalf("build profile: %v", err)
	}
	return profile
}

func trafficRuleBySID(rules []trafficRule, sid int) (trafficRule, bool) {
	for _, rule := range rules {
		if rule.SID == sid {
			return rule, true
		}
	}
	return trafficRule{}, false
}

func TestTrafficProfileFiltersDirectionCategoryProtocolAndPort(t *testing.T) {
	scenarioPath, ruleRoot := writeTrafficTestScenario(t, trafficTestScenarioYAML)
	writeTrafficTestRules(t, ruleRoot, "suricata/mixed.rules", `alert tcp any any -> $HOME_NET 443 (msg:"ET EXPLOIT inbound web exploit"; flow:to_server,established; content:"/shell"; sid:2000001; rev:1; classtype:web-application-attack;)
alert dns $HOME_NET any -> $EXTERNAL_NET 53 (msg:"ET MALWARE mining dns"; dns.query; content:"pool.example"; sid:2000002; rev:1; classtype:trojan-activity;)
alert tcp $HOME_NET any -> $HOME_NET 22 (msg:"internal east-west"; content:"SSH-"; sid:2000003; rev:1;)
alert tcp 8.8.8.8 any -> 1.1.1.1 443 (msg:"external to external"; content:"xx"; sid:2000004; rev:1;)
alert smb any any -> $HOME_NET 445 (msg:"ET EXPLOIT smb exploit"; content:"srvsvc"; sid:2000005; rev:1;)
alert tcp any any -> $HOME_NET 3389 (msg:"inbound rdp brute"; content:"rdp"; sid:2000006; rev:1; classtype:attempted-recon;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET FRAUD suspected phishing"; http.host; content:"phish"; sid:2000007; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET 445 (msg:"ET TROJAN outbound tunnel"; content:"tunnel"; sid:2000008; rev:1;)
`)

	profile := buildTrafficTestProfile(t, scenarioPath, ruleRoot)
	counts := profile.Counts
	if counts.Input != 8 {
		t.Fatalf("input = %d, want 8", counts.Input)
	}
	if counts.DroppedDirection != 2 {
		t.Fatalf("dropped_direction = %d, want 2", counts.DroppedDirection)
	}
	if counts.DroppedProtocol != 1 {
		t.Fatalf("dropped_protocol = %d, want 1", counts.DroppedProtocol)
	}
	if counts.DroppedPort != 1 {
		t.Fatalf("dropped_port = %d, want 1", counts.DroppedPort)
	}
	if counts.DroppedCategory != 1 {
		t.Fatalf("dropped_category = %d, want 1", counts.DroppedCategory)
	}
	if counts.Accepted != 3 {
		t.Fatalf("accepted = %d, want 3 (%v)", counts.Accepted, profile.Rules)
	}
	for _, sid := range []int{2000001, 2000002, 2000008} {
		if _, ok := trafficRuleBySID(profile.Rules, sid); !ok {
			t.Fatalf("sid %d should survive filtering", sid)
		}
	}
	for _, sid := range []int{2000003, 2000004, 2000005, 2000006, 2000007} {
		if _, ok := trafficRuleBySID(profile.Rules, sid); ok {
			t.Fatalf("sid %d should be filtered out", sid)
		}
	}
	if rule, _ := trafficRuleBySID(profile.Rules, 2000001); rule.Direction != "inbound" {
		t.Fatalf("sid 2000001 direction = %q, want inbound", rule.Direction)
	}
	if rule, _ := trafficRuleBySID(profile.Rules, 2000002); rule.Direction != "outbound" {
		t.Fatalf("sid 2000002 direction = %q, want outbound", rule.Direction)
	}
}

func TestTrafficProfileDropsUnsupportedSuricataKeywords(t *testing.T) {
	scenarioPath, ruleRoot := writeTrafficTestScenario(t, trafficTestScenarioYAML)
	writeTrafficTestRules(t, ruleRoot, "suricata/unsupported.rules", `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN valid rule"; http_uri; content:"evil"; sid:2200001; rev:1; classtype:trojan-activity;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN method keyword"; method:POST; content:"eval"; sid:2200002; rev:1; classtype:web-application-attack;)
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN ja3 keyword"; ja3_hash; content:"a0e2f275"; sid:2200003; rev:1; classtype:trojan-activity;)
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN tcp options"; tcp.options; content:"|02 04|"; sid:2200004; rev:1; classtype:trojan-activity;)
alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN icmp type"; icmp.icmp_type:8; sid:2200005; rev:1; classtype:trojan-activity;)
`)

	profile := buildTrafficTestProfile(t, scenarioPath, ruleRoot)
	if profile.Counts.DroppedUnsupported != 4 {
		t.Fatalf("dropped_unsupported = %d, want 4 (%v)", profile.Counts.DroppedUnsupported, profile.Skipped)
	}
	if profile.Counts.Accepted != 1 {
		t.Fatalf("accepted = %d, want 1", profile.Counts.Accepted)
	}
	if _, ok := trafficRuleBySID(profile.Rules, 2200001); !ok {
		t.Fatalf("valid rule 2200001 should survive")
	}
	for _, token := range []string{"method:", "ja3_hash", "tcp.options", "icmp.icmp_type"} {
		if strings.Contains(string(profile.Suricata), token) {
			t.Fatalf("suricata export still contains unsupported keyword %q", token)
		}
	}
	if len(profile.Skipped) != 4 {
		t.Fatalf("skipped = %d, want 4", len(profile.Skipped))
	}
	for _, skipped := range profile.Skipped {
		if !strings.HasPrefix(skipped.Reason, "unsupported keyword ") {
			t.Fatalf("skip reason = %q, want unsupported keyword prefix", skipped.Reason)
		}
	}
}

func TestTrafficProfileAssignmentHasZeroOverlap(t *testing.T) {
	scenarioPath, ruleRoot := writeTrafficTestScenario(t, trafficTestScenarioYAML)
	writeTrafficTestRules(t, ruleRoot, "suricata/assignment.rules", `alert dns $HOME_NET any -> $EXTERNAL_NET 53 (msg:"ET TROJAN simple dns"; dns.query; content:"evil.example"; sid:2100001; rev:1; classtype:trojan-activity;)
alert tls $HOME_NET any -> $EXTERNAL_NET 443 (msg:"ET TROJAN simple sni"; tls.sni; content:"evil.example"; sid:2100002; rev:1; classtype:trojan-activity;)
alert http $HOME_NET any -> $EXTERNAL_NET 80 (msg:"ET TROJAN simple uri"; http_uri; content:"union select"; nocase; sid:2100003; rev:1; classtype:trojan-activity;)
alert http $HOME_NET any -> $EXTERNAL_NET 80 (msg:"ET TROJAN host only"; http.host; content:"download"; sid:2100004; rev:1; classtype:trojan-activity;)
alert dns $HOME_NET any -> $EXTERNAL_NET 53 (msg:"ET TROJAN dns threshold"; dns.query; content:"tunnel.example"; threshold:type threshold, track by_src, count 50, seconds 60; sid:2100005; rev:1; classtype:trojan-activity;)
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN multi content"; content:"alpha"; content:"beta"; sid:2100006; rev:1; classtype:trojan-activity;)
`)

	profile := buildTrafficTestProfile(t, scenarioPath, ruleRoot)
	if profile.OverlapCount != 0 {
		t.Fatalf("overlap_count = %d, want 0", profile.OverlapCount)
	}
	if profile.Counts.Suricata != 3 || profile.Counts.Lyprobe != 3 {
		t.Fatalf("suricata/lyprobe = %d/%d, want 3/3", profile.Counts.Suricata, profile.Counts.Lyprobe)
	}
	expected := map[int]string{
		2100001: "lyprobe",
		2100002: "lyprobe",
		2100003: "lyprobe",
		2100004: "suricata",
		2100005: "suricata",
		2100006: "suricata",
	}
	for sid, engine := range expected {
		rule, ok := trafficRuleBySID(profile.Rules, sid)
		if !ok {
			t.Fatalf("sid %d missing from profile", sid)
		}
		if rule.Engine != engine {
			t.Fatalf("sid %d engine = %q, want %q (%s)", sid, rule.Engine, engine, rule.Reason)
		}
	}

	suricata := string(profile.Suricata)
	lyprobe := string(profile.Lyprobe)
	for sid, engine := range expected {
		token := "sid:" + strconv.Itoa(sid) + ";"
		inSuricata := strings.Contains(suricata, token)
		inLyprobe := strings.Contains(lyprobe, token)
		if engine == "lyprobe" && (!inLyprobe || inSuricata) {
			t.Fatalf("sid %d must be lyprobe-only (suricata=%v lyprobe=%v)", sid, inSuricata, inLyprobe)
		}
		if engine == "suricata" && (!inSuricata || inLyprobe) {
			t.Fatalf("sid %d must be suricata-only (suricata=%v lyprobe=%v)", sid, inSuricata, inLyprobe)
		}
	}
}

func TestTrafficProfileBudgetCapsBothEngines(t *testing.T) {
	scenario := strings.NewReplacer(
		"max_total_rules: 100", "max_total_rules: 5",
		"max_suricata_rules: 80", "max_suricata_rules: 1",
		"max_lyprobe_rules: 20", "max_lyprobe_rules: 1",
	).Replace(trafficTestScenarioYAML)
	scenarioPath, ruleRoot := writeTrafficTestScenario(t, scenario)
	writeTrafficTestRules(t, ruleRoot, "suricata/budget.rules", `alert dns $HOME_NET any -> $EXTERNAL_NET 53 (msg:"ET TROJAN low priority"; dns.query; content:"a.example"; sid:2200001; rev:1; classtype:policy-violation;)
alert dns $HOME_NET any -> $EXTERNAL_NET 53 (msg:"ET MALWARE top priority"; dns.query; content:"b.example"; sid:2200002; rev:1; classtype:trojan-activity;)
alert dns $HOME_NET any -> $EXTERNAL_NET 53 (msg:"scan medium priority"; dns.query; content:"c.example"; sid:2200003; rev:1; classtype:attempted-recon;)
alert http $HOME_NET any -> $EXTERNAL_NET 80 (msg:"ET MALWARE host primary"; http.host; content:"d.example"; sid:2200004; rev:1; classtype:trojan-activity;)
alert http $HOME_NET any -> $EXTERNAL_NET 80 (msg:"ET TROJAN host secondary"; http.host; content:"e.example"; sid:2200005; rev:1; classtype:attempted-recon;)
`)

	profile := buildTrafficTestProfile(t, scenarioPath, ruleRoot)
	if profile.Counts.Suricata != 1 || profile.Counts.Lyprobe != 1 {
		t.Fatalf("suricata/lyprobe = %d/%d, want 1/1 (dropped_budget=%d)", profile.Counts.Suricata, profile.Counts.Lyprobe, profile.Counts.DroppedBudget)
	}
	if profile.Counts.DroppedBudget < 3 {
		t.Fatalf("dropped_budget = %d, want >= 3", profile.Counts.DroppedBudget)
	}
	lyprobe, ok := trafficRuleBySID(profile.Rules, 2200002)
	if !ok || lyprobe.Engine != "lyprobe" {
		t.Fatalf("highest-priority lyprobe rule 2200002 must win the budget: %+v", profile.Rules)
	}
	suricata, ok := trafficRuleBySID(profile.Rules, 2200004)
	if !ok || suricata.Engine != "suricata" {
		t.Fatalf("highest-priority suricata rule 2200004 must win the budget: %+v", profile.Rules)
	}
}

func TestTrafficProfileDedupesSignatureHashAcrossSources(t *testing.T) {
	scenarioPath, ruleRoot := writeTrafficTestScenario(t, trafficTestScenarioYAML)
	line := `alert dns $HOME_NET any -> $EXTERNAL_NET 53 (msg:"ET TROJAN duplicate"; dns.query; content:"dup.example"; `
	writeTrafficTestRules(t, ruleRoot, "suricata/a.rules", line+"sid:2300001; rev:1; classtype:trojan-activity;)\n")
	writeTrafficTestRules(t, ruleRoot, "suricata/b.rules", line+"sid:2300002; rev:1; classtype:trojan-activity;)\n")

	profile := buildTrafficTestProfile(t, scenarioPath, ruleRoot)
	if profile.Counts.DroppedDuplicate != 1 {
		t.Fatalf("dropped_duplicate = %d, want 1", profile.Counts.DroppedDuplicate)
	}
	if len(profile.Rules) != 1 {
		t.Fatalf("kept rules = %d, want 1", len(profile.Rules))
	}
	if profile.Rules[0].SID != 2300001 {
		t.Fatalf("dedupe winner sid = %d, want 2300001", profile.Rules[0].SID)
	}
}

func TestTrafficDetectionSignatureOnlyAcceptsRawSignatures(t *testing.T) {
	flowOnly := `{"id":"dpi-admin-access-default","category":"traffic","field":"http_path","operator":"regex","value":"/admin","regex":true}`
	if signature, ok := trafficDetectionSignature(flowOnly); ok {
		t.Fatalf("flow-only detection rule must not become a signature: %q", signature)
	}
	raw := `{"id":"et-1","category":"traffic","signature":"alert dns $HOME_NET any -> $EXTERNAL_NET 53 (msg:\"x\"; dns.query; content:\"a.example\"; sid:1; rev:1;)"}`
	signature, ok := trafficDetectionSignature(raw)
	if !ok || !strings.HasPrefix(signature, "alert dns") {
		t.Fatalf("raw signature not extracted: %q ok=%v", signature, ok)
	}
	nested := `{"schema_version":"lyflow.rule/v1","category":"traffic","suricata":{"raw_rule":"alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:\"y\"; content:\"z\"; sid:2; rev:1;)"}}`
	if _, ok := trafficDetectionSignature(nested); !ok {
		t.Fatalf("nested raw_rule signature not extracted")
	}
}

func TestTrafficProfileHomeNetAutoSourceFromSuricataProfile(t *testing.T) {
	dir := t.TempDir()
	profilePath := filepath.Join(dir, "lyflow-suricata-profile.yaml")
	content := "vars:\n  address-groups:\n    HOME_NET: \"[10.1.18.0/24,10.1.19.0/24]\"\n    EXTERNAL_NET: \"!$HOME_NET\"\n"
	if err := os.WriteFile(profilePath, []byte(content), 0o644); err != nil {
		t.Fatalf("write suricata profile: %v", err)
	}
	scenario := trafficScenario{}
	scenario.HomeNet.SuricataProfile = profilePath
	scenario.HomeNet.Fallback = []string{"192.168.0.0/16"}

	home := resolveTrafficHomeNet(scenario, nil)
	if !strings.HasPrefix(home.Source, "suricata_profile:") {
		t.Fatalf("home_net source = %q, want suricata_profile", home.Source)
	}
	if len(home.Values) != 2 || home.Values[0] != "10.1.18.0/24" {
		t.Fatalf("home_net values = %v", home.Values)
	}
	nets := parseTrafficCIDRs(home.Values)
	if got := trafficClassifyAddress("10.1.18.241", nets); got != "home" {
		t.Fatalf("10.1.18.241 classified as %q, want home", got)
	}
	if got := trafficClassifyAddress("8.8.8.8", nets); got != "external" {
		t.Fatalf("8.8.8.8 classified as %q, want external", got)
	}
	override := resolveTrafficHomeNet(scenario, []string{"10.9.0.0/16"})
	if override.Source != "env:"+trafficProfileHomeNetEnv {
		t.Fatalf("override source = %q", override.Source)
	}
}

func TestTrafficProfileExportAndStatus(t *testing.T) {
	scenarioPath, ruleRoot := writeTrafficTestScenario(t, trafficTestScenarioYAML)
	writeTrafficTestRules(t, ruleRoot, "suricata/export.rules", `alert dns $HOME_NET any -> $EXTERNAL_NET 53 (msg:"ET TROJAN export dns"; dns.query; content:"export.example"; sid:2400001; rev:1; classtype:trojan-activity;)
alert http $HOME_NET any -> $EXTERNAL_NET 80 (msg:"ET TROJAN export host"; http.host; content:"export-host"; sid:2400002; rev:1; classtype:trojan-activity;)
`)
	profile := buildTrafficTestProfile(t, scenarioPath, ruleRoot)
	manifest, err := writeTrafficProfile(profile)
	if err != nil {
		t.Fatalf("write profile: %v", err)
	}
	if manifest.OverlapCount != 0 {
		t.Fatalf("manifest overlap = %d", manifest.OverlapCount)
	}
	if manifest.RuleSetHash == "" {
		t.Fatalf("manifest rule_set_hash is empty")
	}
	for _, path := range []string{profile.SuricataPath, profile.LyprobePath, profile.ManifestPath} {
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			t.Fatalf("expected exported file %s: %v", path, err)
		}
	}
	if !strings.Contains(string(profile.Lyprobe), "sid:2400001;") {
		t.Fatalf("lyprobe export missing converted rule")
	}
	if strings.Contains(string(profile.Lyprobe), "sid:2400002;") {
		t.Fatalf("lyprobe export must not contain Suricata-only rule")
	}
	if !strings.Contains(string(profile.Suricata), "sid:2400002;") {
		t.Fatalf("suricata export missing complex rule")
	}

	t.Setenv(trafficProfileRootEnv, ruleRoot)
	t.Setenv(trafficProfileScenarioEnv, scenarioPath)
	status, err := trafficRuleProfileStatus(context.Background(), nil)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.OverlapCount != 0 || status.Counts.Overlap != 0 {
		t.Fatalf("status overlap = %d/%d", status.OverlapCount, status.Counts.Overlap)
	}
	if status.LastExport == nil {
		t.Fatalf("status last_export is nil after export")
	}
	if status.Stale {
		t.Fatalf("status must not be stale right after export")
	}
	if !status.Engines["lyprobe"].Exists || !status.Engines["suricata"].Exists {
		t.Fatalf("exported engine files not reported: %+v", status.Engines)
	}
	if status.Engines["suricata"].RuleCount != 1 || status.Engines["lyprobe"].RuleCount != 1 {
		t.Fatalf("engine counts = %+v", status.Engines)
	}
}

func TestTrafficRuleProfileHandlers(t *testing.T) {
	scenarioPath, ruleRoot := writeTrafficTestScenario(t, trafficTestScenarioYAML)
	writeTrafficTestRules(t, ruleRoot, "suricata/handlers.rules", `alert dns $HOME_NET any -> $EXTERNAL_NET 53 (msg:"ET TROJAN handler dns"; dns.query; content:"handler.example"; sid:2500001; rev:1; classtype:trojan-activity;)
`)
	t.Setenv(trafficProfileRootEnv, ruleRoot)
	t.Setenv(trafficProfileScenarioEnv, scenarioPath)

	statusRecorder := httptest.NewRecorder()
	trafficRuleProfileStatusHandler(nil).ServeHTTP(statusRecorder, httptest.NewRequest(http.MethodGet, "/api/v1/traffic/rule-profile", nil))
	if statusRecorder.Code != http.StatusOK {
		t.Fatalf("status handler code = %d body=%s", statusRecorder.Code, statusRecorder.Body.String())
	}
	var statusEnvelope struct {
		Code int `json:"code"`
		Data struct {
			OverlapCount int                    `json:"overlap_count"`
			Engines      map[string]interface{} `json:"engines"`
			LastExport   map[string]interface{} `json:"last_export"`
		} `json:"data"`
	}
	if err := json.Unmarshal(statusRecorder.Body.Bytes(), &statusEnvelope); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if statusEnvelope.Code != 0 || statusEnvelope.Data.OverlapCount != 0 {
		t.Fatalf("status envelope = %+v", statusEnvelope)
	}
	if statusEnvelope.Data.LastExport != nil {
		t.Fatalf("last_export must be nil before the first export")
	}

	exportRecorder := httptest.NewRecorder()
	trafficRuleProfileExportHandler(nil).ServeHTTP(exportRecorder, httptest.NewRequest(http.MethodPost, "/api/v1/traffic/rule-profile/export", strings.NewReader(`{}`)))
	if exportRecorder.Code != http.StatusOK {
		t.Fatalf("export handler code = %d body=%s", exportRecorder.Code, exportRecorder.Body.String())
	}
	if _, err := os.Stat(filepath.Join(ruleRoot, "compiled", "server-zone", "suricata.rules")); err != nil {
		t.Fatalf("export handler did not write suricata rules: %v", err)
	}
	if _, err := os.Stat(filepath.Join(ruleRoot, "compiled", "server-zone", "lyprobe-source.rules")); err != nil {
		t.Fatalf("export handler did not write lyprobe source: %v", err)
	}

	notAllowed := httptest.NewRecorder()
	trafficRuleProfileExportHandler(nil).ServeHTTP(notAllowed, httptest.NewRequest(http.MethodGet, "/api/v1/traffic/rule-profile/export", nil))
	if notAllowed.Code != http.StatusMethodNotAllowed {
		t.Fatalf("export handler GET code = %d, want 405", notAllowed.Code)
	}
}

func TestServerZoneScenarioLoads(t *testing.T) {
	path := filepath.Join("..", "..", "rules", "scenarios", "server-zone.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("server-zone scenario not available: %v", err)
	}
	scenario, _, digest, err := loadTrafficScenario(path)
	if err != nil {
		t.Fatalf("load server-zone scenario: %v", err)
	}
	if scenario.Name != "server-zone" || digest == "" {
		t.Fatalf("unexpected scenario: %+v digest=%q", scenario, digest)
	}
	if !scenario.Directions.Inbound || !scenario.Directions.Outbound || scenario.Directions.Internal {
		t.Fatalf("unexpected directions: %+v", scenario.Directions)
	}
	for _, required := range []string{"chat", "games", "p2p", "streaming", "adware", "toolbar", "mobile", "web_client", "phishing", "policy", "retired", "scada", "voip", "tftp", "user_agents"} {
		found := false
		for _, excluded := range scenario.Categories.Exclude {
			if excluded == required {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("category %q must be excluded for the server zone", required)
		}
	}
	if scenario.Budget.MaxSuricataRules <= 0 || scenario.Budget.MaxLyprobeRules <= 0 {
		t.Fatalf("budget is not configured: %+v", scenario.Budget)
	}
}
