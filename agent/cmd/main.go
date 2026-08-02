package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/lyflow/ly-flow-platform/contracts"
	shared "github.com/lyflow/ly-flow-platform/rasppolicy"
	transport "github.com/lyflow/ly-flow-platform/transportreliability"
	"github.com/redis/go-redis/v9"
)

var version = "v2.0.0"
var httpInsecureSkipVerify bool
var spoolRecordCounter uint64

const defaultConfigFile = "/opt/ly-agent/etc/agent.yaml"

type Config struct {
	AgentID                  string
	AgentKey                 string
	EnrollmentToken          string
	Mode                     string
	API                      string
	Redis                    string
	RedisUsername            string
	RedisPassword            string
	RedisLegacyPassword      string
	InsecureSkipVerify       bool
	HeartbeatInterval        int
	LogLevel                 string
	LogFile                  string
	TrafficEnabled           bool
	TrafficInterface         string
	CaptureEngine            string
	BPFFilter                string
	Promiscuous              bool
	TrafficSampleEveryN      int
	MaxTrafficEventsPerSec   int
	RawStream                string
	SemanticStream           string
	TrafficTelemetryStream   string
	RuntimeTelemetryStream   string
	RASPTelemetryStream      string
	LogAuditTelemetryStream  string
	SessionEnabled           bool
	SessionStream            string
	RetentionEnabled         bool
	RetentionDir             string
	SpoolEnabled             bool
	SpoolDir                 string
	SpoolMaxBytes            int64
	SpoolFlushInterval       int
	HIDSEnabled              bool
	RuntimeStream            string
	YARACommand              string
	YARARulesPath            string
	YARAScanPaths            string
	YARAScanIntervalSeconds  int
	YARAScanTimeoutSeconds   int
	YARAMaxFileBytes         int64
	YARAMaxMatches           int
	RASPEnabled              bool
	RASPStream               string
	RASPBridgeAddr           string
	RASPBridgeToken          string
	RASPPolicyRootPath       string
	RASPMode                 string
	RASPPolicyVersion        uint64
	RASPBlockOnHit           bool
	AgentBinaryDigestPath    string
	AgentBinaryRootPath      string
	AgentConfigPath          string
	AgentConfigSignaturePath string
	AgentConfigRootPath      string
	AgentIdentityPath        string
	RequireAgentIntegrity    bool
	RequireConfigIntegrity   bool
	AssetEnabled             bool
}

type Agent struct {
	cfg                    *Config
	cfgMu                  sync.RWMutex
	ctx                    context.Context
	cancel                 context.CancelFunc
	restartTraffic         chan struct{}
	status                 string
	agentID                string
	agentKey               string
	hostname               string
	localIP                string
	runtimePublisher       RuntimeEventPublisher
	runtimeHealth          *runtimeControlHealth
	engines                *EngineRegistry
	trafficStarted         bool
	hidsStarted            bool
	raspStarted            bool
	trafficSpool           *durableTrafficSpool
	trafficSpoolMu         sync.Mutex
	trafficStats           trafficRuntimeStats
	clock                  trafficClock
	trafficQuality         *trafficQualityMonitor
	suricataProfile        suricataProfileRuntime
	yaraSeenMu             sync.Mutex
	yaraSeen               map[string]struct{}
	ackPolicyVersion       uint64
	ackPolicySignature     string
	raspPolicyEnvelope     shared.SignedPolicy
	raspPolicyACKed        bool
	raspPolicyExpiresAt    time.Time
	raspPolicyExpired      bool
	raspFailBehavior       shared.FailBehavior
	raspMaxEventsPerSecond int
	raspLanguages          []shared.Language
	raspRateWindow         time.Time
	raspRateCount          int
	raspBridgeMu           sync.RWMutex
	raspBridge             *raspBridgeRuntime
}

type trafficRuntimeStats struct {
	startedAt         int64
	lastPacketAt      int64
	lastPublishAt     int64
	packetCount       uint64
	publishCount      uint64
	publishErrorCount uint64
	lastError         atomic.Value
	selectedInterface atomic.Value
	lastSource        atomic.Value
	lastDestination   atomic.Value
}

type trafficObservation struct {
	Timestamp      time.Time
	Source         string
	Engine         string
	Interface      string
	SrcIP          string
	DstIP          string
	SrcPort        uint16
	DstPort        uint16
	Protocol       string
	AppProtocol    string
	HTTPHost       string
	HTTPMethod     string
	HTTPPath       string
	DNSQuery       string
	TLSSNI         string
	BytesIn        uint64
	BytesOut       uint64
	Packets        uint64
	DurationMillis uint64
	Direction      string
	TCPSYN         bool
	TCPACK         bool
	TCPRST         bool
	TCPFIN         bool
}

type portScanDetector struct {
	window     time.Duration
	minPorts   int
	maxEntries int
	lastPrune  time.Time
	entries    map[string]*portScanEntry
}

type portScanEntry struct {
	firstSeen time.Time
	lastSeen  time.Time
	lastAlert time.Time
	srcPort   uint16
	dstPort   uint16
	ports     map[uint16]struct{}
}

func newPortScanDetector() *portScanDetector {
	return &portScanDetector{window: time.Minute, minPorts: 20, maxEntries: 4096, entries: map[string]*portScanEntry{}}
}

type captureCapability struct {
	RequestedEngine string
	ActiveEngine    string
	Status          string
	FallbackReason  string
}

func NewAgent(cfg *Config) *Agent {
	ctx, cancel := context.WithCancel(context.Background())
	hostname, _ := os.Hostname()
	a := &Agent{
		cfg:            cfg,
		ctx:            ctx,
		cancel:         cancel,
		restartTraffic: make(chan struct{}, 1),
		status:         "starting",
		hostname:       hostname,
		localIP:        getLocalIP(),
		clock:          systemTrafficClock{},
		raspLanguages:  []shared.Language{shared.LanguagePython, shared.LanguageJava},
		runtimeHealth:  newRuntimeControlHealth("agent-runtime", agentRuntimeLimits(), time.Now),
	}
	a.trafficQuality = newTrafficQualityMonitor(a.clock, captureQualityConfigFrom(cfg))
	a.runtimePublisher = NewHTTPRuntimePublisher(a)
	a.engines = NewEngineRegistry(
		newSuricataSupervisor(),
		newWazuhSupervisor(),
		newYARASupervisor(),
		newRASPSupervisor(),
	)
	return a
}

func (a *Agent) capabilityModel() map[string]interface{} {
	trafficConfig := a.captureConfigSnapshot()
	capture := resolveCaptureCapability(selectCaptureEngine(trafficConfig.CaptureEngine))
	runtimeStrategy := detectStrategy()
	runtimeStatus := "disabled"
	runtimeBackend := "disabled"
	if a.cfg.HIDSEnabled {
		runtimeStatus = "fallback"
		runtimeBackend = fallbackBackendLabel(runtimeStrategy)
	}
	yaraStatus := "disabled"
	yaraBackend := "disabled"
	if a.cfg.HIDSEnabled {
		yaraStatus = "degraded"
		yaraBackend = "unavailable"
		if commandExists(a.cfg.YARACommand) {
			if info, err := os.Stat(a.cfg.YARARulesPath); err == nil && !info.IsDir() {
				yaraStatus = "active"
				yaraBackend = "native-yara-cli"
			}
		}
	}

	raspStatus := "disabled"
	if a.cfg.RASPEnabled {
		raspStatus = "monitor"
	}

	return map[string]interface{}{
		"schema_version": "lyflow.agent.capability.v1",
		"control_plane": map[string]interface{}{
			"status":      "active",
			"transport":   "http",
			"enroll":      true,
			"heartbeat":   true,
			"config_pull": true,
			"task_result": true,
		},
		"asset_collector": map[string]interface{}{
			"enabled":      a.cfg.AssetEnabled,
			"status":       enabledStatus(a.cfg.AssetEnabled),
			"collects":     []string{"interfaces", "performance", "processes"},
			"interval_sec": 60,
		},
		"traffic_collector": map[string]interface{}{
			"enabled":            trafficConfig.Enabled,
			"status":             enabledStatus(trafficConfig.Enabled),
			"requested_engine":   capture.RequestedEngine,
			"active_engine":      capture.ActiveEngine,
			"backend_status":     capture.Status,
			"fallback_reason":    capture.FallbackReason,
			"runtime_dependency": trafficRuntimeDependencyStatus(atomicString(a.trafficStats.lastError)),
			"interface":          trafficConfig.Interface,
			"selected_interface": atomicString(a.trafficStats.selectedInterface),
			"bpf_filter":         trafficConfig.BPFFilter,
			"promiscuous":        trafficConfig.Promiscuous,
			"started_at":         unixSecondsRFC3339(atomic.LoadInt64(&a.trafficStats.startedAt)),
			"last_packet_at":     unixSecondsRFC3339(atomic.LoadInt64(&a.trafficStats.lastPacketAt)),
			"last_publish_at":    unixSecondsRFC3339(atomic.LoadInt64(&a.trafficStats.lastPublishAt)),
			"packet_count":       atomic.LoadUint64(&a.trafficStats.packetCount),
			"publish_count":      atomic.LoadUint64(&a.trafficStats.publishCount),
			"publish_errors":     atomic.LoadUint64(&a.trafficStats.publishErrorCount),
			"capture_quality":    a.captureQualityCapability(),
			"last_error":         atomicString(a.trafficStats.lastError),
			"last_source":        atomicString(a.trafficStats.lastSource),
			"last_destination":   atomicString(a.trafficStats.lastDestination),
			"streams": map[string]string{
				"raw":      a.cfg.RawStream,
				"semantic": a.cfg.SemanticStream,
			},
		},
		"runtime_sensor": map[string]interface{}{
			"enabled":        a.cfg.HIDSEnabled,
			"status":         runtimeStatus,
			"mode":           "monitor",
			"strategy":       runtimeStrategy,
			"active_backend": runtimeBackend,
			"collectors":     []string{"process_delta", "auth_log", "file_signal"},
			"stream":         a.cfg.RuntimeStream,
		},
		"log_collector": map[string]interface{}{
			"enabled":       a.cfg.HIDSEnabled,
			"status":        enabledStatus(a.cfg.HIDSEnabled),
			"collectors":    []string{"auth_log"},
			"raw_stream":    "logs:raw",
			"audit_stream":  a.cfg.LogAuditTelemetryStream,
			"source_paths":  []string{"/var/log/auth.log", "/var/log/secure", "/var/log/messages"},
			"output_format": "lyflow.telemetry.v1",
		},
		"yara_scanner": map[string]interface{}{
			"enabled":           a.cfg.HIDSEnabled,
			"status":            yaraStatus,
			"active_backend":    yaraBackend,
			"rule_pack_version": "yara-security",
			"result_path":       "/opt/ly-agent/yara/last-scan.json",
			"stream":            "component_alerts:v2",
		},
		"rasp_probe_manager": map[string]interface{}{
			"enabled":        a.cfg.RASPEnabled,
			"status":         raspStatus,
			"mode":           "monitor",
			"python":         "sitecustomize_runtime_hooks",
			"php":            "native_extension_with_prepend_fallback",
			"java":           "javaagent_security_jdbc_hooks",
			"languages":      []string{"python", "java"},
			"generic":        "local_bridge_transport",
			"active_backend": runtimeLanguageHint(),
			"stream":         a.cfg.RASPStream,
		},
		"engine_supervisors": a.engineSupervisorCapability(),
		"suricata_profile":   a.suricataProfileHealth(),
	}
}

func (a *Agent) engineSupervisorCapability() map[string]interface{} {
	if a.engines == nil {
		return map[string]interface{}{}
	}
	snapshot := a.engines.Snapshot(a.ctx)
	result := make(map[string]interface{}, len(snapshot))
	for name, status := range snapshot {
		result[string(name)] = map[string]interface{}{
			"installed":         status.Installed,
			"running":           status.Running,
			"version":           status.Version,
			"config_hash":       status.ConfigHash,
			"rule_pack_version": status.RulePackVersion,
			"output_path":       status.OutputPath,
			"last_error":        status.LastError,
			"last_event_at":     status.LastEventAt,
		}
	}
	return result
}

func enabledStatus(enabled bool) string {
	if enabled {
		return "active"
	}
	return "disabled"
}

func (a *Agent) markTrafficCaptureStarted(interfaceName string) {
	atomic.StoreInt64(&a.trafficStats.startedAt, a.clock.Now().UTC().Unix())
	a.trafficStats.selectedInterface.Store(interfaceName)
}

func (a *Agent) markTrafficPacket(obs trafficObservation) {
	atomic.AddUint64(&a.trafficStats.packetCount, 1)
	atomic.StoreInt64(&a.trafficStats.lastPacketAt, a.clock.Now().UTC().Unix())
	a.trafficStats.lastSource.Store(obs.SrcIP)
	a.trafficStats.lastDestination.Store(obs.DstIP)
}

func (a *Agent) markTrafficPublish() {
	atomic.AddUint64(&a.trafficStats.publishCount, 1)
	atomic.StoreInt64(&a.trafficStats.lastPublishAt, a.clock.Now().UTC().Unix())
	a.trafficStats.lastError.Store("")
}

func (a *Agent) markTrafficError(err error) {
	if err == nil {
		return
	}
	atomic.AddUint64(&a.trafficStats.publishErrorCount, 1)
	a.trafficStats.lastError.Store(err.Error())
}

func unixSecondsRFC3339(seconds int64) string {
	if seconds <= 0 {
		return ""
	}
	return time.Unix(seconds, 0).UTC().Format(time.RFC3339)
}

func atomicString(value atomic.Value) string {
	if raw := value.Load(); raw != nil {
		if text, ok := raw.(string); ok {
			return text
		}
	}
	return ""
}

func trafficRuntimeDependencyStatus(lastError string) map[string]interface{} {
	status := map[string]interface{}{
		"pcap_runtime": "ready",
		"message":      "",
	}
	errorText := strings.ToLower(strings.TrimSpace(lastError))
	if strings.Contains(errorText, "wpcap.dll") || strings.Contains(errorText, "packet.dll") || strings.Contains(errorText, "npcap") || strings.Contains(errorText, "winpcap") {
		status["pcap_runtime"] = "missing"
		status["message"] = "Npcap/WinPcap runtime is missing; install Npcap with WinPcap-compatible API to enable Windows packet capture"
	}
	return status
}

func (a *Agent) Start() error {
	if err := a.verifyAgentStartupIntegrity(a.ctx, ""); err != nil {
		return err
	}
	if a.isLocalMirrorMode() {
		return a.startLocalMirror()
	}
	a.status = "running"
	a.cfgMu.Lock()
	a.cfg.RASPEnabled = false
	a.cfg.RASPMode = string(shared.ModeOff)
	a.cfgMu.Unlock()
	fmt.Printf("[agent] ly-agent %s starting...\n", version)
	fmt.Printf("[agent] OS: %s, Arch: %s, CPUs: %d\n", runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	fmt.Printf("[agent] API Server: %s\n", a.cfg.API)
	fmt.Printf("[agent] Traffic: %v, HIDS: %v, RASP: %v, Asset: %v\n",
		a.cfg.TrafficEnabled, a.cfg.HIDSEnabled, a.cfg.RASPEnabled, a.cfg.AssetEnabled)

	if err := a.enroll(); err != nil {
		return fmt.Errorf("enroll failed: %v", err)
	}

	a.pullConfigAndReportTasks()
	a.startManagedCollectors()
	if a.cfg.AssetEnabled {
		go a.runAssetCollector()
	}
	a.runEngineAdapters()
	go a.heartbeatLoop()
	go a.configLoop()

	fmt.Printf("[agent] Agent registered successfully with ID: %s\n", a.agentID)
	return nil
}

func (a *Agent) startManagedCollectors() {
	if a.captureConfigSnapshot().Enabled && !a.trafficStarted {
		a.trafficStarted = true
		go a.runTrafficCapture()
	}
	if a.cfg.HIDSEnabled && !a.hidsStarted {
		a.hidsStarted = true
		go a.runHIDS()
		go a.runYARAScanner()
	}
	if a.cfg.RASPEnabled && !a.raspStarted {
		a.raspStarted = true
		go a.runRASP()
		go a.runRASPBridge()
		health := newRuntimeControlHealth("agent-rasp-adapter", agentRuntimeLimits(), time.Now)
		go runSupervisedRuntime(a.ctx, health, runtimeSupervisorConfig{
			Name: "rasp", Run: func(ctx context.Context) { a.runRASPEventAdapterContext(withRuntimeHealth(ctx, health)) }, OnHealth: a.handleControlHealth,
		})
	}
}

func (a *Agent) isLocalMirrorMode() bool {
	mode := strings.ToLower(strings.TrimSpace(a.cfg.Mode))
	return mode == "local-mirror" || mode == "local_mirror" || mode == "mirror"
}

func (a *Agent) startLocalMirror() error {
	a.status = "running"
	a.agentID = "local"
	a.agentKey = "local-mirror"
	a.hostname = "security-server"
	a.cfg.AgentID = a.agentID
	a.cfg.AgentKey = a.agentKey
	a.cfg.TrafficEnabled = true
	a.cfg.SessionEnabled = true
	a.cfg.HIDSEnabled = false
	a.cfg.RASPEnabled = false
	a.cfg.AssetEnabled = false
	a.cfg.RuntimeTelemetryStream = ""
	a.cfg.RASPTelemetryStream = ""
	a.cfg.LogAuditTelemetryStream = ""
	if a.cfg.MaxTrafficEventsPerSec == 20 {
		a.cfg.MaxTrafficEventsPerSec = 0
	}
	if config, ok := loadLocalMirrorConfig(); ok {
		a.cfg.TrafficInterface = config.Interface
	} else if strings.TrimSpace(os.Getenv("MIRROR_CONFIG_FILE")) == "" {
		if iface := fetchMirrorInterface(a.cfg.API); iface != "" {
			a.cfg.TrafficInterface = iface
		}
	}
	if strings.TrimSpace(a.cfg.TrafficInterface) == "" || strings.EqualFold(a.cfg.TrafficInterface, "auto") {
		a.cfg.TrafficInterface = ""
		fmt.Printf("[mirror] Local mirror started without a capture interface; configure it from the control center\n")
		go a.mirrorConfigLoop()
		return nil
	}
	fmt.Printf("[mirror] Local mirror capture starting: interface=%s raw=%s session=%s telemetry=%s\n", a.cfg.TrafficInterface, a.cfg.RawStream, a.cfg.SessionStream, a.cfg.TrafficTelemetryStream)
	go a.mirrorConfigLoop()
	go a.runTrafficCapture()
	return nil
}

func (a *Agent) mirrorConfigLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.applyMirrorConfig()
		}
	}
}

func (a *Agent) applyMirrorConfig() {
	config, ok := loadLocalMirrorConfig()
	if !ok && strings.TrimSpace(os.Getenv("MIRROR_CONFIG_FILE")) == "" {
		config = fetchMirrorConfig(a.cfg.API)
	}
	a.cfgMu.Lock()
	oldInterface := a.cfg.TrafficInterface
	oldEnabled := a.cfg.TrafficEnabled
	if strings.TrimSpace(config.Interface) != "" {
		a.cfg.TrafficInterface = strings.TrimSpace(config.Interface)
	} else {
		a.cfg.TrafficInterface = ""
	}
	a.cfg.TrafficEnabled = config.Enabled
	newInterface := a.cfg.TrafficInterface
	newEnabled := a.cfg.TrafficEnabled
	a.cfgMu.Unlock()
	if oldInterface == "" && newInterface != "" && newEnabled && !a.trafficStarted {
		a.trafficStarted = true
		go a.runTrafficCapture()
	} else if oldInterface != "" && (oldInterface != newInterface || oldEnabled != newEnabled) {
		a.requestTrafficRestart()
	}
}

func loadLocalMirrorConfig() (mirrorRuntimeConfig, bool) {
	path := strings.TrimSpace(os.Getenv("MIRROR_CONFIG_FILE"))
	if path == "" {
		return mirrorRuntimeConfig{}, false
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return mirrorRuntimeConfig{}, false
	}
	var response struct {
		Enabled   bool   `json:"enabled"`
		Interface string `json:"interface"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		fmt.Printf("[mirror] local mirror config parse failed: %v\n", err)
		return mirrorRuntimeConfig{}, false
	}
	return mirrorRuntimeConfig{Enabled: response.Enabled, Interface: strings.TrimSpace(response.Interface)}, true
}
func (a *Agent) Stop() {
	fmt.Printf("[agent] Stopping...\n")
	a.cancel()
	if a.trafficSpool != nil {
		a.trafficSpool.Close()
	}
	a.status = "stopped"
}

func (a *Agent) enroll() error {
	if a.cfg.AgentID != "" && a.cfg.AgentKey != "" {
		a.agentID = a.cfg.AgentID
		a.agentKey = a.cfg.AgentKey
		fmt.Printf("[agent] Using existing credentials: ID=%s\n", a.agentID)
		return nil
	}

	capabilities := map[string]string{
		"traffic": fmt.Sprintf("%v", a.cfg.TrafficEnabled),
		"hids":    fmt.Sprintf("%v", a.cfg.HIDSEnabled),
		"rasp":    fmt.Sprintf("%v", a.cfg.RASPEnabled),
		"asset":   fmt.Sprintf("%v", a.cfg.AssetEnabled),
	}

	metadata := map[string]string{
		"os":       runtime.GOOS,
		"arch":     runtime.GOARCH,
		"kernel":   getKernelVersion(),
		"hostname": a.hostname,
	}

	reqBody := map[string]interface{}{
		"enrollment_token": a.cfg.EnrollmentToken,
		"hostname":         a.hostname,
		"ip":               a.localIP,
		"os":               runtime.GOOS,
		"version":          version,
		"capabilities":     capabilities,
		"capability_model": a.capabilityModel(),
		"metadata":         metadata,
	}

	body, _ := json.Marshal(reqBody)
	resp, err := httpPost(a.cfg.API+"/api/v1/agent/enroll", body)
	if err != nil {
		return fmt.Errorf("enrollment request failed")
	}

	var result struct {
		Code    int                    `json:"code"`
		Message string                 `json:"message"`
		Data    map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return fmt.Errorf("parse enrollment response: %w", err)
	}

	if result.Code != 0 {
		return fmt.Errorf("enrollment rejected by server")
	}

	agentID, idOK := result.Data["agent_id"].(string)
	agentKey, keyOK := result.Data["agent_key"].(string)
	agentID = strings.TrimSpace(agentID)
	agentKey = strings.TrimSpace(agentKey)
	if !idOK || agentID == "" {
		return fmt.Errorf("enrollment response missing valid agent_id")
	}
	if !keyOK || agentKey == "" {
		return fmt.Errorf("enrollment response missing valid agent_key")
	}
	credentialPath := resolveConfigPath(os.Args[1:])
	if a.cfg.RequireConfigIntegrity || strings.TrimSpace(a.cfg.AgentConfigSignaturePath) != "" {
		credentialPath = a.cfg.AgentIdentityPath
		if strings.TrimSpace(credentialPath) == "" {
			return fmt.Errorf("signed config requires a separate agent identity path")
		}
	}
	if err := persistAgentCredentials(credentialPath, agentID, agentKey); err != nil {
		return fmt.Errorf("persist enrollment credentials: %w", err)
	}
	a.agentID = agentID
	a.agentKey = agentKey
	a.cfg.AgentID = agentID
	a.cfg.AgentKey = agentKey

	fmt.Printf("[agent] Enroll successful!\n")
	fmt.Printf("[agent]   Agent ID: %s\n", a.agentID)
	return nil
}

func (a *Agent) heartbeatLoop() {
	interval := 30
	if a.cfg.HeartbeatInterval > 0 {
		interval = a.cfg.HeartbeatInterval
	}

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.sendHeartbeat()
		}
	}
}

func (a *Agent) sendHeartbeat() {
	if a.agentID == "" {
		fmt.Printf("[heartbeat] Not enrolled yet, skipping\n")
		return
	}

	reqBody := map[string]interface{}{
		"agent_id":     a.agentID,
		"agent_key":    a.agentKey,
		"status":       "online",
		"capabilities": a.capabilityModel(),
		"metrics": map[string]int64{
			"cpu_percent":  int64(runtime.NumCPU()),
			"memory_bytes": int64(runtime.NumGoroutine()) * 1024 * 1024,
		},
	}

	body, _ := json.Marshal(reqBody)
	resp, err := httpPost(a.cfg.API+"/api/v1/agent/heartbeat", body)
	if err != nil {
		fmt.Printf("[heartbeat] Failed: %v\n", err)
		return
	}

	var result map[string]interface{}
	json.Unmarshal(resp, &result)

	if data, ok := result["data"].(map[string]interface{}); ok {
		if ack, ok := data["ack"].(bool); ok && ack {
			fmt.Printf("[heartbeat] OK: agent_id=%s\n", a.agentID)
		}
	}
}

func (a *Agent) configLoop() {
	interval := 30
	if a.cfg.HeartbeatInterval > 0 {
		interval = a.cfg.HeartbeatInterval
	}

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.enforceRASPPolicyExpiry(time.Now().UTC())
			a.pullConfigAndReportTasks()
		}
	}
}

func (a *Agent) pullConfigAndReportTasks() {
	if a.agentID == "" {
		return
	}

	ackVersion, ackSignature := a.policyACKSnapshot()
	reqBody := map[string]interface{}{
		"agent_id": a.agentID, "agent_key": a.agentKey,
		"ack_policy_version": ackVersion, "ack_policy_signature": ackSignature,
		"capabilities": a.capabilityModel(),
	}
	body, _ := json.Marshal(reqBody)
	resp, err := httpPostAgent(a.cfg.API+"/api/v1/agent/config", body, a.agentID, a.agentKey)
	if err != nil {
		fmt.Printf("[config] Warning: config pull failed: %v\n", err)
		return
	}

	var result struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Config              map[string]interface{}   `json:"config"`
			EngineDesiredStates []EngineDesiredState     `json:"engine_desired_states"`
			Tasks               []map[string]interface{} `json:"tasks"`
			RASPPolicy          shared.SignedPolicy      `json:"rasp_policy"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		fmt.Printf("[config] Warning: parse config response failed: %v\n", err)
		return
	}
	if result.Code != 0 {
		if result.Message == "" {
			result.Message = "unknown error"
		}
		fmt.Printf("[config] Warning: server returned code=%d message=%s\n", result.Code, result.Message)
		return
	}
	if result.Data.RASPPolicy.Policy.Version > 0 {
		if err := a.applySignedRASPPolicy(result.Data.RASPPolicy); err != nil {
			a.handleControlHealth(a.runtimeHealth.Degrade("signed_config_integrity_failed", true))
			fmt.Printf("[config] Warning: signed RASP policy rejected: %v\n", err)
			return
		} else if err := a.acknowledgePendingRASPPolicy(); err != nil {
			a.handleControlHealth(a.runtimeHealth.Degrade("authorization_failed", true))
			fmt.Printf("[config] Warning: signed RASP policy ACK failed: %v\n", err)
			return
		}
	}
	a.applyPulledConfig(result.Data.Config)

	desired := result.Data.EngineDesiredStates
	if len(desired) == 0 {
		desired = parseEngineDesiredStates(result.Data.Config["engine_desired_states"])
	}
	if len(desired) > 0 && a.engines != nil {
		for index := range desired {
			if desired[index].Name == EngineRASP {
				desired[index].Enabled = a.raspPolicyEnabled()
			}
		}
		statuses := a.engines.Apply(a.ctx, desired)
		fmt.Printf("[config] Applied %d engine desired states\n", len(statuses))
	}

	for _, task := range result.Data.Tasks {
		taskID, _ := task["task_id"].(string)
		status := "ignored"
		if taskID == "" {
			status = "skipped"
		}
		if err := a.reportTaskResult(taskID, status, map[string]interface{}{"note": "task execution stub"}, ""); err != nil {
			fmt.Printf("[task] Warning: failed to report task result task_id=%s: %v\n", taskID, err)
		}
	}
}

func (a *Agent) applyPulledConfig(config map[string]interface{}) {
	policy := mapFromInterface(config["policy"])
	if len(policy) == 0 {
		return
	}
	if traffic := mapFromInterface(policy["traffic"]); len(traffic) > 0 {
		a.cfgMu.Lock()
		oldInterface := a.cfg.TrafficInterface
		if enabled, ok := boolFromInterface(traffic["enabled"]); ok {
			a.cfg.TrafficEnabled = enabled
		}
		if iface := strings.TrimSpace(stringFromInterface(traffic["interface"])); iface != "" && !strings.EqualFold(iface, "auto") {
			a.cfg.TrafficInterface = iface
		}
		if engine := strings.TrimSpace(stringFromInterface(traffic["capture_engine"])); engine != "" {
			a.cfg.CaptureEngine = engine
		}
		if filter, ok := traffic["bpf_filter"]; ok {
			a.cfg.BPFFilter = strings.TrimSpace(stringFromInterface(filter))
		}
		if promiscuous, ok := boolFromInterface(traffic["promiscuous"]); ok {
			a.cfg.Promiscuous = promiscuous
		}
		if sampleEvery, ok := positiveIntFromInterface(traffic["sample_every_n"]); ok {
			a.cfg.TrafficSampleEveryN = sampleEvery
		}
		if rateLimit, ok := nonNegativeIntFromInterface(traffic["max_events_per_second"]); ok {
			a.cfg.MaxTrafficEventsPerSec = rateLimit
		}
		applyPlatformTrafficPolicy(a.cfg)
		qualityConfig := captureQualityConfigFrom(a.cfg)
		newInterface := a.cfg.TrafficInterface
		a.cfgMu.Unlock()
		a.ensureTrafficQuality().UpdateConfig(qualityConfig)
		if oldInterface != newInterface {
			a.requestTrafficRestart()
		}
	}
	if runtimePolicy := mapFromInterface(policy["runtime"]); len(runtimePolicy) > 0 {
		if enabled, ok := boolFromInterface(runtimePolicy["enabled"]); ok {
			a.cfg.HIDSEnabled = enabled
		}
	}
	a.startManagedCollectors()
}

func mapFromInterface(value interface{}) map[string]interface{} {
	if value == nil {
		return map[string]interface{}{}
	}
	if typed, ok := value.(map[string]interface{}); ok {
		return typed
	}
	raw, err := json.Marshal(value)
	if err != nil || string(raw) == "null" {
		return map[string]interface{}{}
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return map[string]interface{}{}
	}
	return decoded
}

func boolFromInterface(value interface{}) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(typed))
		return parsed, err == nil
	default:
		return false, false
	}
}

func stringFromInterface(value interface{}) string {
	if value == nil {
		return ""
	}
	if typed, ok := value.(string); ok {
		return typed
	}
	return fmt.Sprintf("%v", value)
}

func positiveIntFromInterface(value interface{}) (int, bool) {
	parsed, err := strconv.Atoi(strings.TrimSpace(stringFromInterface(value)))
	return parsed, err == nil && parsed > 0
}

func nonNegativeIntFromInterface(value interface{}) (int, bool) {
	parsed, err := strconv.Atoi(strings.TrimSpace(stringFromInterface(value)))
	return parsed, err == nil && parsed >= 0
}

func parseEngineDesiredStates(value interface{}) []EngineDesiredState {
	raw, err := json.Marshal(value)
	if err != nil || string(raw) == "null" {
		return nil
	}
	var desired []EngineDesiredState
	if err := json.Unmarshal(raw, &desired); err != nil {
		return nil
	}
	return desired
}

func (a *Agent) reportTaskResult(taskID, status string, result map[string]interface{}, errorMsg string) error {
	reqBody := map[string]interface{}{
		"agent_id": a.agentID,
		"task_id":  taskID,
		"status":   status,
		"result":   result,
	}
	if strings.TrimSpace(errorMsg) != "" {
		reqBody["error"] = errorMsg
	}

	body, _ := json.Marshal(reqBody)
	resp, err := httpPostAgent(a.cfg.API+"/api/v1/agent/task-result", body, a.agentID, a.agentKey)
	if err != nil {
		return err
	}

	var ack struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(resp, &ack); err != nil {
		return fmt.Errorf("parse task-result response failed: %w", err)
	}
	if ack.Code != 0 {
		if ack.Message == "" {
			ack.Message = "unknown error"
		}
		return fmt.Errorf("task-result rejected: %s", ack.Message)
	}
	return nil
}

func (a *Agent) runTrafficCapture() {
	for {
		trafficConfig := a.captureConfigSnapshot()
		if err := a.prepareTrafficQualityForInterface(trafficConfig.Interface); err != nil {
			a.trafficStats.lastError.Store(err.Error())
			fmt.Printf("[probe] Invalid traffic interface: %v\n", err)
			if !a.waitTrafficRestart() {
				return
			}
			continue
		}
		capability := resolveCaptureCapability(selectCaptureEngine(trafficConfig.CaptureEngine))
		engine := capability.ActiveEngine
		fmt.Printf("[probe] Traffic capture on %s (engine=%s, bpf=%q, promiscuous=%v)\n",
			trafficConfig.Interface, engine, trafficConfig.BPFFilter, trafficConfig.Promiscuous)

		if capability.Status == "fallback" && capability.FallbackReason != "" {
			fmt.Printf("[probe] %s requested; using %s fallback: %s\n", capability.RequestedEngine, capability.ActiveEngine, capability.FallbackReason)
		}

		if engine == "pfring" {
			if err := a.runPFRingCapture(); err == nil {
				return
			} else {
				fmt.Printf("[mirror] PF_RING capture restarting: %v\n", err)
				if !a.waitTrafficRestart() {
					return
				}
				continue
			}
		}
		if engine == "af_packet" {
			if err := a.runAFPacketCapture(); err == nil {
				return
			} else {
				if a.isLocalMirrorMode() || a.trafficCaptureInterfaceChanged(atomicString(a.trafficStats.selectedInterface)) {
					fmt.Printf("[mirror] AF_PACKET capture restarting: %v\n", err)
					if !a.waitTrafficRestart() {
						return
					}
					continue
				}
				fmt.Printf("[probe] AF_PACKET capture unavailable: %v; falling back to procfs sampler\n", err)
			}
		}
		if engine == "pcap" {
			if err := a.runPCAPPacketCapture(); err != nil {
				fmt.Printf("[probe] PCAP capture unavailable: %v\n", err)
				if a.trafficCaptureInterfaceChanged(atomicString(a.trafficStats.selectedInterface)) && a.waitTrafficRestart() {
					continue
				}
			}
			return
		}
		a.runProcfsTrafficFallback()
		return
	}
}

func (a *Agent) waitTrafficRestart() bool {
	select {
	case <-a.ctx.Done():
		return false
	case <-a.restartTraffic:
		return true
	case <-time.After(time.Second):
		return true
	}
}

func (a *Agent) requestTrafficRestart() {
	select {
	case a.restartTraffic <- struct{}{}:
	default:
	}
}

func (a *Agent) trafficCaptureInterfaceChanged(interfaceName string) bool {
	configured := strings.TrimSpace(a.captureConfigSnapshot().Interface)
	return configured != "" && !strings.EqualFold(configured, "auto") && configured != strings.TrimSpace(interfaceName)
}

func (a *Agent) trafficCaptureEnabledOnCurrentInterface(interfaceName string) bool {
	config := a.captureConfigSnapshot()
	return config.Enabled && strings.TrimSpace(config.Interface) == strings.TrimSpace(interfaceName)
}

func selectCaptureEngine(configured string) string {
	switch strings.ToLower(strings.TrimSpace(configured)) {
	case "", "auto", "af_packet", "afpacket":
		if runtime.GOOS == "windows" {
			return "pcap"
		}
		return "af_packet"
	case "pcap", "npcap", "winpcap":
		return "pcap"
	case "ebpf", "socket_filter", "bpf":
		return "ebpf"
	case "pfring", "pf_ring":
		return "pfring"
	case "procfs", "fallback":
		return "procfs"
	default:
		return "af_packet"
	}
}

func resolveCaptureCapability(requested string) captureCapability {
	capability := captureCapability{
		RequestedEngine: requested,
		ActiveEngine:    requested,
		Status:          "active",
	}
	switch requested {
	case "ebpf":
		capability.ActiveEngine = "af_packet"
		capability.Status = "fallback"
		if isCentOS7Kernel(getKernelVersion()) {
			capability.FallbackReason = "centos7_kernel_ebpf_not_supported"
		} else {
			capability.FallbackReason = "full_ebpf_program_loader_not_implemented"
		}
	case "pfring":
		if !pfringAdapterCompiled() {
			capability.ActiveEngine = "af_packet"
			capability.Status = "fallback"
			capability.FallbackReason = "pfring_adapter_not_compiled"
		} else if !pfRingAvailable() {
			capability.ActiveEngine = "af_packet"
			capability.Status = "fallback"
			capability.FallbackReason = "pfring_kernel_module_unavailable"
		}
	case "procfs":
		capability.Status = "fallback"
		capability.FallbackReason = "packet_capture_disabled_or_unavailable"
	case "pcap":
		if runtime.GOOS != "windows" {
			capability.ActiveEngine = "af_packet"
			capability.Status = "fallback"
			capability.FallbackReason = "pcap_reserved_for_windows_agent"
		}
	}
	return capability
}

func isCentOS7Kernel(version string) bool {
	return strings.HasPrefix(strings.TrimSpace(version), "3.10.0-")
}

func pfRingAvailable() bool {
	return exists("/proc/net/pf_ring") || exists("/dev/pf_ring")
}

func (a *Agent) runProcfsTrafficFallback() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			if !a.captureConfigSnapshot().Enabled {
				continue
			}
			detector := newPortScanDetector()
			for _, obs := range a.procfsTrafficObservations() {
				_, publish := a.processCapturedObservation(detector, obs)
				if !publish {
					continue
				}
				if err := a.publishTrafficObservation(obs); err != nil {
					a.markTrafficPublishError(err)
					fmt.Printf("[probe] procfs flow publish failed: %v\n", err)
				} else {
					a.markTrafficPublishQuality()
				}
			}
		}
	}
}

type trafficStreamWriter interface {
	publish(ctx context.Context, stream string, payload map[string]interface{}, payloadType string) error
}

type spoolRecord struct {
	Version     int                    `json:"version"`
	RecordID    string                 `json:"record_id"`
	CreatedAt   string                 `json:"created_at"`
	Stream      string                 `json:"stream"`
	Type        string                 `json:"type"`
	Data        string                 `json:"data"`
	Values      map[string]interface{} `json:"values"`
	Attempts    int                    `json:"attempts,omitempty"`
	LastError   string                 `json:"last_error,omitempty"`
	DeliveredAt string                 `json:"delivered_at,omitempty"`
}

type redisXAddCloser interface {
	XAdd(ctx context.Context, args *redis.XAddArgs) *redis.StringCmd
	Close() error
}

type durableTrafficSpool struct {
	dir           string
	pendingDir    string
	tmpDir        string
	maxBytes      int64
	flushInterval time.Duration
	client        redisXAddCloser
	httpEndpoint  string
	agentID       string
	agentKey      string
	ctx           context.Context
	mu            chan struct{}
	closed        chan struct{}
	encrypted     *transport.EncryptedSpool
}

func newDurableTrafficSpool(ctx context.Context, cfg *Config) (*durableTrafficSpool, error) {
	if cfg == nil || !cfg.SpoolEnabled {
		return nil, nil
	}
	dir := strings.TrimSpace(cfg.SpoolDir)
	if dir == "" {
		dir = "/opt/ly-agent/data/spool"
	}
	spool := &durableTrafficSpool{
		dir:           dir,
		pendingDir:    filepath.Join(dir, "pending"),
		tmpDir:        filepath.Join(dir, "tmp"),
		maxBytes:      cfg.SpoolMaxBytes,
		flushInterval: time.Duration(cfg.SpoolFlushInterval) * time.Second,
		client:        redis.NewClient(redisOptions(cfg)),
		httpEndpoint:  strings.TrimRight(strings.TrimSpace(cfg.API), "/") + "/api/v1/agent/traffic-event",
		ctx:           ctx,
		mu:            make(chan struct{}, 1),
		closed:        make(chan struct{}),
	}
	if spool.maxBytes <= 0 {
		spool.maxBytes = 10 * 1024 * 1024 * 1024
	}
	if spool.flushInterval <= 0 {
		spool.flushInterval = time.Second
	}
	if err := os.MkdirAll(spool.pendingDir, 0o750); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(spool.tmpDir, 0o750); err != nil {
		return nil, err
	}
	if err := spool.recoverTempFiles(); err != nil {
		return nil, err
	}
	key, err := transport.DeriveSpoolKey("agent-traffic", os.Getenv("LYFLOW_TRANSPORT_SPOOL_KEY"), firstNonEmpty(cfg.RedisPassword, cfg.RedisLegacyPassword, cfg.AgentKey))
	if err != nil {
		return nil, fmt.Errorf("configure encrypted traffic spool: %w", err)
	}
	spool.encrypted, err = transport.NewEncryptedSpool(transport.SpoolConfig{
		Dir: filepath.Join(dir, "v2"), Key: key, MaxBytes: spool.maxBytes, MaxAge: 7 * 24 * time.Hour,
	})
	if err != nil {
		return nil, fmt.Errorf("create encrypted traffic spool: %w", err)
	}
	if err := spool.migrateLegacyRecords(); err != nil {
		return nil, err
	}
	go spool.run()
	return spool, nil
}

func (s *durableTrafficSpool) recoverTempFiles() error {
	tmpDir := s.tmpDir
	if tmpDir == "" {
		tmpDir = s.pendingDir
	}
	if tmpDir != s.pendingDir {
		if err := s.recoverTempFilesFromDir(s.pendingDir); err != nil {
			return err
		}
	}
	return s.recoverTempFilesFromDir(tmpDir)
}

func (s *durableTrafficSpool) recoverTempFilesFromDir(tmpDir string) error {
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tmp") {
			continue
		}
		tmpPath := filepath.Join(tmpDir, entry.Name())
		data, err := os.ReadFile(tmpPath)
		if err != nil {
			return err
		}
		var record spoolRecord
		if err := json.Unmarshal(bytes.TrimSpace(data), &record); err != nil {
			_ = os.Remove(tmpPath)
			continue
		}
		finalName := strings.TrimSuffix(entry.Name(), ".tmp")
		if finalName == "" || finalName == entry.Name() {
			finalName = sanitizeSpoolName(record.RecordID + "-" + record.Stream + ".wal")
		}
		if err := os.Rename(tmpPath, filepath.Join(s.pendingDir, finalName)); err != nil {
			return err
		}
	}
	return nil
}

func (s *durableTrafficSpool) Close() {
	select {
	case <-s.closed:
		return
	default:
		close(s.closed)
		_ = s.client.Close()
	}
}

func (s *durableTrafficSpool) publish(ctx context.Context, stream string, payload map[string]interface{}, payloadType string) error {
	stream = strings.TrimSpace(stream)
	if stream == "" {
		return fmt.Errorf("stream is empty for %s", payloadType)
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	record := spoolRecord{
		Version:   1,
		RecordID:  fmt.Sprintf("%d-%d-%d", time.Now().UTC().UnixNano(), os.Getpid(), atomic.AddUint64(&spoolRecordCounter, 1)),
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Stream:    stream,
		Type:      payloadType,
		Data:      string(data),
		Values: map[string]interface{}{
			"type": payloadType,
			"data": string(data),
		},
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if s.encrypted == nil {
		return fmt.Errorf("encrypted traffic spool is unavailable")
	}
	if err := s.encrypted.Append(ctx, transport.SpoolRecord{
		UID: record.RecordID, Stream: stream, MessageID: record.RecordID,
		Payload: encoded, CreatedAt: time.Now().UTC(),
	}); err != nil {
		return fmt.Errorf("append encrypted traffic spool: %w", err)
	}
	if s.client == nil && strings.TrimSpace(s.httpEndpoint) == "" {
		return nil
	}
	if err := s.replayEncrypted(ctx); err != nil {
		s.signalFlush()
		return err
	}
	return nil
}

func (s *durableTrafficSpool) run() {
	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-s.ctx.Done():
			return
		case <-s.mu:
			s.flushOnce()
		case <-ticker.C:
			s.flushOnce()
		}
	}
}

func (s *durableTrafficSpool) signalFlush() {
	select {
	case s.mu <- struct{}{}:
	default:
	}
}

func (s *durableTrafficSpool) flushOnce() {
	if s.encrypted != nil {
		if err := s.replayEncrypted(s.ctx); err != nil {
			fmt.Printf("[spool] encrypted flush paused: %v\n", err)
		}
		return
	}
	entries, err := os.ReadDir(s.pendingDir)
	if err != nil {
		fmt.Printf("[spool] read pending failed: %v\n", err)
		return
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() || strings.HasSuffix(entry.Name(), ".tmp") {
			continue
		}
		path := filepath.Join(s.pendingDir, entry.Name())
		if err := s.flushFile(path); err != nil {
			fmt.Printf("[spool] flush paused: %v\n", err)
			return
		}
	}
}

func (s *durableTrafficSpool) replayEncrypted(ctx context.Context) error {
	return s.encrypted.Replay(ctx, func(_ context.Context, encrypted transport.SpoolRecord) error {
		var record spoolRecord
		if err := json.Unmarshal(encrypted.Payload, &record); err != nil {
			return fmt.Errorf("decode encrypted traffic spool record: %w", err)
		}
		values := record.Values
		if len(values) == 0 {
			values = map[string]interface{}{"type": record.Type, "data": record.Data}
		}
		return s.deliver(record, values)
	})
}

func (s *durableTrafficSpool) migrateLegacyRecords() error {
	entries, err := os.ReadDir(s.pendingDir)
	if err != nil {
		return fmt.Errorf("read legacy traffic spool: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".wal") {
			continue
		}
		path := filepath.Join(s.pendingDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read legacy traffic spool record: %w", err)
		}
		var record spoolRecord
		if err := json.Unmarshal(bytes.TrimSpace(data), &record); err != nil {
			return fmt.Errorf("decode legacy traffic spool record: %w", err)
		}
		if err := s.encrypted.Append(s.ctx, transport.SpoolRecord{
			UID: record.RecordID, Stream: record.Stream, MessageID: record.RecordID,
			Payload: bytes.TrimSpace(data), CreatedAt: parseSpoolCreatedAt(record.CreatedAt),
		}); err != nil {
			return fmt.Errorf("encrypt legacy traffic spool record: %w", err)
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove migrated legacy traffic spool record: %w", err)
		}
	}
	return nil
}

func parseSpoolCreatedAt(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Now().UTC()
	}
	return parsed.UTC()
}

func (s *durableTrafficSpool) flushFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var record spoolRecord
	if err := json.Unmarshal(bytes.TrimSpace(data), &record); err != nil {
		return err
	}
	values := record.Values
	if len(values) == 0 {
		values = map[string]interface{}{"type": record.Type, "data": record.Data}
	}
	if err := s.deliver(record, values); err != nil {
		record.Attempts++
		record.LastError = err.Error()
		_ = writeSpoolRecord(path, record)
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return nil
}

func (s *durableTrafficSpool) deliver(record spoolRecord, values map[string]interface{}) error {
	stableValues := make(map[string]interface{}, len(values)+1)
	for key, value := range values {
		stableValues[key] = value
	}
	stableValues["event_uid"] = record.RecordID
	if strings.TrimSpace(s.httpEndpoint) != "" && strings.TrimSpace(s.agentID) != "" && strings.TrimSpace(s.agentKey) != "" {
		payload := map[string]interface{}{
			"agent_id": s.agentID,
			"stream":   record.Stream,
			"type":     record.Type,
			"data":     record.Data,
			"values":   stableValues,
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		_, err = httpPostAgent(s.httpEndpoint, body, s.agentID, s.agentKey)
		return err
	}
	return (transport.RetryPolicy{MaxAttempts: 4, BaseDelay: 50 * time.Millisecond, MaxDelay: time.Second, Jitter: 0.2}).Do(s.ctx, record.RecordID, func(ctx context.Context) error {
		if client, ok := s.client.(*redis.Client); ok {
			if err := transport.RegisterProducer(ctx, client, "agent-traffic"); err != nil {
				return err
			}
		}
		return s.client.XAdd(ctx, &redis.XAddArgs{Stream: record.Stream, Values: stableValues}).Err()
	}, nil)
}

func writeSpoolRecord(path string, record spoolRecord) error {
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(encoded, '\n'), 0o640)
}

func sanitizeSpoolName(name string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_")
	return replacer.Replace(name)
}

func dirSize(dir string) (int64, error) {
	var total int64
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return 0, err
		}
		if !info.IsDir() {
			total += info.Size()
		}
	}
	return total, nil
}

func (a *Agent) publishTrafficObservation(obs trafficObservation) error {
	redisAddr := strings.TrimSpace(a.cfg.Redis)
	if redisAddr == "" {
		return fmt.Errorf("redis address is empty")
	}
	spool, err := a.ensureTrafficSpool()
	if err != nil {
		return err
	}
	return a.publishTrafficObservationToStreams(spool, obs)
}

func (a *Agent) ensureTrafficSpool() (*durableTrafficSpool, error) {
	if !a.cfg.SpoolEnabled {
		return nil, fmt.Errorf("encrypted durable Agent spool is required")
	}
	a.trafficSpoolMu.Lock()
	defer a.trafficSpoolMu.Unlock()
	if a.trafficSpool == nil {
		spool, err := newDurableTrafficSpool(a.ctx, a.cfg)
		if err != nil {
			return nil, err
		}
		if a.isLocalMirrorMode() {
			spool.httpEndpoint = ""
		}
		a.trafficSpool = spool
	}
	a.trafficSpool.agentID = a.agentID
	a.trafficSpool.agentKey = a.agentKey
	return a.trafficSpool, nil
}

func (a *Agent) publishAgentStream(ctx context.Context, stream string, payload map[string]interface{}, payloadType string) error {
	spool, err := a.ensureTrafficSpool()
	if err != nil {
		return err
	}
	return spool.publish(ctx, stream, payload, payloadType)
}

func (a *Agent) publishTrafficObservationToStreams(writer trafficStreamWriter, obs trafficObservation) error {
	trafficConfig := a.captureConfigSnapshot()
	now := obs.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}
	serverHost := serverHostFromAPI(a.cfg.API)
	if serverHost == "" {
		serverHost = "127.0.0.1"
	}
	flowID := fmt.Sprintf("host-%s-%d", a.agentID, now.UnixNano())
	if a.isLocalMirrorMode() {
		flowID = fmt.Sprintf("mirror-%s-%d", trafficConfig.Interface, now.UnixNano())
	}
	appProtocol := obs.AppProtocol
	if appProtocol == "" {
		appProtocol = obs.Protocol
	}
	businessAction := businessActionForObservation(obs)
	retentionRef, _ := a.retainTrafficReference(flowID, obs, businessAction)
	payloadSummary := trafficPayloadSummary(obs, appProtocol, businessAction)
	captureSource := "agent"
	flowSource := obs.Source
	semanticSource := "ly-agent-business-semantics"
	sessionSource := "ly-agent-session-aggregate"
	displayName := ""
	probeKind := "终端探针抓包"
	if a.isLocalMirrorMode() {
		captureSource = "mirror"
		flowSource = "local-mirror-capture"
		semanticSource = "local-mirror-semantics"
		sessionSource = "local-mirror-session"
		displayName = "流量镜像分析"
		probeKind = "本机旁路抓包"
	}
	rawFlow := map[string]interface{}{
		"id":              flowID,
		"timestamp":       now.Format(time.RFC3339Nano),
		"sensor_id":       a.agentID,
		"agent_id":        a.agentID,
		"hostname":        a.hostname,
		"interface":       trafficConfig.Interface,
		"engine":          obs.Engine,
		"bpf_filter":      trafficConfig.BPFFilter,
		"promiscuous":     trafficConfig.Promiscuous,
		"src_ip":          obs.SrcIP,
		"dst_ip":          obs.DstIP,
		"src_port":        int64(obs.SrcPort),
		"dst_port":        int64(obs.DstPort),
		"protocol":        obs.Protocol,
		"app_protocol":    appProtocol,
		"http_host":       obs.HTTPHost,
		"http_method":     obs.HTTPMethod,
		"http_path":       obs.HTTPPath,
		"dns_query":       obs.DNSQuery,
		"tls_sni":         obs.TLSSNI,
		"business_action": businessAction,
		"payload":         payloadSummary,
		"message":         payloadSummary,
		"bytes_in":        int64(obs.BytesIn),
		"bytes_out":       int64(obs.BytesOut),
		"packets":         int64(obs.Packets),
		"duration_ms":     int64(obs.DurationMillis),
		"direction":       obs.Direction,
		"tcp_syn":         obs.TCPSYN,
		"tcp_ack":         obs.TCPACK,
		"tcp_rst":         obs.TCPRST,
		"tcp_fin":         obs.TCPFIN,
		"source":          flowSource,
		"capture_source":  captureSource,
	}
	if displayName != "" {
		rawFlow["display_name"] = displayName
		rawFlow["agent_display_name"] = displayName
		rawFlow["probe_name"] = displayName
		rawFlow["probe_kind"] = probeKind
	}
	if retentionRef != nil {
		rawFlow["raw_reference"] = retentionRef
	}
	if err := writer.publish(a.ctx, a.cfg.RawStream, rawFlow, "raw_flow"); err != nil {
		return err
	}
	trafficTelemetry := contracts.TelemetryEnvelope{
		SchemaVersion: contracts.TelemetrySchemaVersion,
		ID:            flowID,
		Category:      contracts.TelemetryTraffic,
		EventType:     "traffic.flow",
		ObservedAt:    now.UTC(),
		Source:        flowSource,
		Entities: contracts.EntityRef{
			AgentID:  a.agentID,
			HostID:   a.hostname,
			Hostname: a.hostname,
			SourceIP: obs.SrcIP,
			TargetIP: obs.DstIP,
		},
		RawReference: &contracts.RawReference{Stream: a.cfg.RawStream, MessageID: flowID},
		Fields:       rawFlow,
	}
	if a.cfg.TrafficTelemetryStream != "" {
		if err := writer.publish(a.ctx, a.cfg.TrafficTelemetryStream, structToMap(trafficTelemetry), "telemetry_traffic"); err != nil {
			fmt.Printf("[probe] traffic telemetry publish failed: %v\n", err)
		}
	}

	semanticFlow := map[string]interface{}{
		"id":              "semantic-" + flowID,
		"flow_id":         flowID,
		"timestamp":       now.Format(time.RFC3339Nano),
		"agent_id":        a.agentID,
		"sensor_id":       a.agentID,
		"hostname":        a.hostname,
		"interface":       trafficConfig.Interface,
		"engine":          obs.Engine,
		"bpf_filter":      trafficConfig.BPFFilter,
		"promiscuous":     trafficConfig.Promiscuous,
		"src_ip":          obs.SrcIP,
		"dst_ip":          obs.DstIP,
		"src_port":        int64(obs.SrcPort),
		"dst_port":        int64(obs.DstPort),
		"protocol":        obs.Protocol,
		"app_protocol":    appProtocol,
		"http_host":       obs.HTTPHost,
		"http_method":     obs.HTTPMethod,
		"http_path":       obs.HTTPPath,
		"dns_query":       obs.DNSQuery,
		"tls_sni":         obs.TLSSNI,
		"business_action": businessAction,
		"bytes_in":        int64(obs.BytesIn),
		"bytes_out":       int64(obs.BytesOut),
		"packets":         int64(obs.Packets),
		"duration_ms":     int64(obs.DurationMillis),
		"direction":       obs.Direction,
		"tcp_syn":         obs.TCPSYN,
		"tcp_ack":         obs.TCPACK,
		"tcp_rst":         obs.TCPRST,
		"tcp_fin":         obs.TCPFIN,
		"risk_score":      int64(0),
		"risk_level":      "low",
		"source":          semanticSource,
		"capture_source":  captureSource,
	}
	if displayName != "" {
		semanticFlow["display_name"] = displayName
		semanticFlow["agent_display_name"] = displayName
		semanticFlow["probe_name"] = displayName
		semanticFlow["probe_kind"] = probeKind
	}
	if retentionRef != nil {
		semanticFlow["raw_reference"] = retentionRef
	}
	if err := writer.publish(a.ctx, a.cfg.SemanticStream, semanticFlow, "semantic_flow"); err != nil {
		return err
	}

	if a.cfg.SessionEnabled {
		session := map[string]interface{}{
			"id":              fmt.Sprintf("session-%s-%s-%s-%s", a.agentID, obs.SrcIP, obs.DstIP, obs.Protocol),
			"timestamp":       now.Format(time.RFC3339Nano),
			"agent_id":        a.agentID,
			"sensor_id":       a.agentID,
			"hostname":        a.hostname,
			"interface":       trafficConfig.Interface,
			"engine":          obs.Engine,
			"bpf_filter":      trafficConfig.BPFFilter,
			"promiscuous":     trafficConfig.Promiscuous,
			"src_ip":          obs.SrcIP,
			"dst_ip":          obs.DstIP,
			"src_port":        int64(obs.SrcPort),
			"dst_port":        int64(obs.DstPort),
			"protocol":        obs.Protocol,
			"app_protocol":    appProtocol,
			"business_action": businessAction,
			"bytes_in":        int64(obs.BytesIn),
			"bytes_out":       int64(obs.BytesOut),
			"packets":         int64(obs.Packets),
			"duration_ms":     int64(obs.DurationMillis),
			"direction":       obs.Direction,
			"event_count":     int64(1),
			"mode":            "behavior_aggregate",
			"risk_level":      "low",
			"source":          sessionSource,
			"capture_source":  captureSource,
		}
		if displayName != "" {
			session["display_name"] = displayName
			session["agent_display_name"] = displayName
			session["probe_name"] = displayName
			session["probe_kind"] = probeKind
		}
		if err := writer.publish(a.ctx, a.cfg.SessionStream, session, "semantic_session"); err != nil {
			return err
		}
	}

	fmt.Printf("[probe] published telemetry: raw=%s semantic=%s session=%s sensor=%s iface=%s engine=%s\n",
		a.cfg.RawStream, a.cfg.SemanticStream, a.cfg.SessionStream, a.agentID, trafficConfig.Interface, obs.Engine)
	return nil

}

func (a *Agent) retainTrafficReference(flowID string, obs trafficObservation, businessAction string) (map[string]interface{}, error) {
	if !a.cfg.RetentionEnabled || !isRetentionWorthy(obs, businessAction) {
		return nil, nil
	}
	dir := strings.TrimSpace(a.cfg.RetentionDir)
	if dir == "" {
		dir = "/opt/ly-agent/data/packets"
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	ref := map[string]interface{}{
		"capture_ref":    flowID + ".json",
		"retention_type": "metadata_only",
		"path":           filepath.Join(dir, flowID+".json"),
		"max_bytes":      int64(4096),
		"cleanup_policy": "bounded-metadata-retention",
	}
	payload := map[string]interface{}{
		"flow_id":         flowID,
		"agent_id":        a.agentID,
		"hostname":        a.hostname,
		"business_action": businessAction,
		"observation":     obs,
		"reference":       ref,
		"created_at":      time.Now().UTC().Format(time.RFC3339Nano),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	if len(data) > 4096 {
		data = data[:4096]
	}
	return ref, os.WriteFile(ref["path"].(string), data, 0o640)
}

func isRetentionWorthy(obs trafficObservation, businessAction string) bool {
	switch businessAction {
	case "upload", "admin_access", "approval", "login":
		return true
	}
	domain := strings.ToLower(obs.HTTPHost + " " + obs.DNSQuery + " " + obs.TLSSNI)
	return strings.Contains(domain, ".xyz") || strings.Contains(domain, "malware") || strings.Contains(domain, "miner")
}

func structToMap(value interface{}) map[string]interface{} {
	data, err := json.Marshal(value)
	if err != nil {
		return map[string]interface{}{}
	}
	out := map[string]interface{}{}
	if err := json.Unmarshal(data, &out); err != nil {
		return map[string]interface{}{}
	}
	return out
}

func (a *Agent) observationFromPacket(packet gopacket.Packet, captureLength int, engine string) trafficObservation {
	obs := trafficObservation{
		Timestamp:      time.Now().UTC(),
		Source:         "ly-agent-packet-capture",
		Engine:         engine,
		Interface:      a.captureConfigSnapshot().Interface,
		SrcIP:          a.localIP,
		Packets:        1,
		BytesOut:       uint64(captureLength),
		DurationMillis: 1,
		Direction:      "egress",
	}

	var ip4Protocol layers.IPProtocol
	var ip6Protocol layers.IPProtocol
	if ip4 := packet.Layer(layers.LayerTypeIPv4); ip4 != nil {
		ip := ip4.(*layers.IPv4)
		obs.SrcIP = ip.SrcIP.String()
		obs.DstIP = ip.DstIP.String()
		ip4Protocol = ip.Protocol
	} else if ip6 := packet.Layer(layers.LayerTypeIPv6); ip6 != nil {
		ip := ip6.(*layers.IPv6)
		obs.SrcIP = ip.SrcIP.String()
		obs.DstIP = ip.DstIP.String()
		ip6Protocol = ip.NextHeader
	}

	var payload []byte
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		obs.Protocol = "TCP"
		obs.SrcPort = uint16(tcp.SrcPort)
		obs.DstPort = uint16(tcp.DstPort)
		obs.TCPSYN = tcp.SYN
		obs.TCPACK = tcp.ACK
		obs.TCPRST = tcp.RST
		obs.TCPFIN = tcp.FIN
		payload = tcp.Payload
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		obs.Protocol = "UDP"
		obs.SrcPort = uint16(udp.SrcPort)
		obs.DstPort = uint16(udp.DstPort)
		payload = udp.Payload
	} else if packet.Layer(layers.LayerTypeICMPv4) != nil {
		obs.Protocol = "ICMP"
		obs.AppProtocol = "ICMP"
	} else if packet.Layer(layers.LayerTypeICMPv6) != nil {
		obs.Protocol = "ICMPv6"
		obs.AppProtocol = "ICMPv6"
	} else if ip4Protocol == layers.IPProtocolICMPv4 {
		obs.Protocol = "ICMP"
		obs.AppProtocol = "ICMP"
	} else if ip6Protocol == layers.IPProtocolICMPv6 {
		obs.Protocol = "ICMPv6"
		obs.AppProtocol = "ICMPv6"
	}

	if obs.Protocol == "" {
		return trafficObservation{}
	}
	if a.localIP != "" {
		switch a.localIP {
		case obs.DstIP:
			obs.Direction = "ingress"
		case obs.SrcIP:
			obs.Direction = "egress"
		}
	}
	annotateApplication(&obs, payload)
	return obs
}

func (d *portScanDetector) observe(obs trafficObservation, a *Agent) map[string]interface{} {
	if d == nil || a == nil || !obs.TCPSYN || obs.TCPACK || !strings.EqualFold(obs.Protocol, "TCP") {
		return nil
	}
	if obs.SrcIP == "" || obs.DstIP == "" || obs.DstPort == 0 || obs.SrcIP == obs.DstIP {
		return nil
	}
	if a.localIP != "" && obs.DstIP != a.localIP {
		return nil
	}
	now := obs.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}
	d.prune(now)
	key := obs.SrcIP + "|" + obs.DstIP + "|TCP"
	entry := d.entries[key]
	if entry == nil && d.maxEntries > 0 && len(d.entries) >= d.maxEntries {
		return nil
	}
	if entry == nil || now.Sub(entry.firstSeen) > d.window {
		entry = &portScanEntry{firstSeen: now, ports: map[uint16]struct{}{}}
		d.entries[key] = entry
	}
	entry.lastSeen = now
	entry.srcPort = obs.SrcPort
	entry.dstPort = obs.DstPort
	entry.ports[obs.DstPort] = struct{}{}
	if len(entry.ports) < d.minPorts || now.Sub(entry.lastAlert) < d.window {
		return nil
	}
	entry.lastAlert = now
	ports := sortedPortList(entry.ports)
	severity := string(contracts.SeverityMedium)
	score := 70
	if len(ports) >= 50 {
		severity = string(contracts.SeverityHigh)
		score = 85
	}
	displayName := ""
	probeKind := "终端探针抓包"
	if a.isLocalMirrorMode() {
		displayName = "流量镜像分析"
		probeKind = "本机旁路抓包"
	}
	alertID := fmt.Sprintf("agent-port-scan-%s-%s-%d", sanitizeIDPart(obs.SrcIP), sanitizeIDPart(obs.DstIP), now.UnixNano())
	summary := fmt.Sprintf("TCP port scan detected: %s scanned %d ports on %s", obs.SrcIP, len(ports), obs.DstIP)
	metadata := map[string]interface{}{"interface": obs.Interface, "capture_interface": obs.Interface, "probe_kind": probeKind}
	return map[string]interface{}{
		"schema_version":     contracts.ComponentAlertSchemaVersion,
		"id":                 alertID,
		"category":           string(contracts.TelemetryTraffic),
		"source_engine":      string(contracts.SourceEngineAgent),
		"rule_id":            "traffic-port-scan-distinct-ports",
		"rule_name":          "Nmap-style TCP port scan",
		"severity":           severity,
		"score_hint":         int64(score),
		"stage_hint":         "TA0043 Reconnaissance",
		"confidence":         0.9,
		"occurred_at":        now.Format(time.RFC3339Nano),
		"timestamp":          now.Format(time.RFC3339Nano),
		"source":             "ly-agent-portscan-detector",
		"summary":            summary,
		"message":            summary,
		"event_type":         "traffic.port_scan",
		"agent_id":           a.agentID,
		"hostname":           a.hostname,
		"display_name":       displayName,
		"agent_display_name": displayName,
		"probe_name":         displayName,
		"src_ip":             obs.SrcIP,
		"dst_ip":             obs.DstIP,
		"src_port":           int64(entry.srcPort),
		"dst_port":           int64(entry.dstPort),
		"protocol":           "TCP",
		"app_protocol":       "TCP",
		"distinct_dst_ports": int64(len(ports)),
		"dst_ports":          ports,
		"first_seen":         entry.firstSeen.Format(time.RFC3339Nano),
		"last_seen":          entry.lastSeen.Format(time.RFC3339Nano),
		"interface":          obs.Interface,
		"capture_interface":  obs.Interface,
		"metadata":           metadata,
		"entities":           map[string]interface{}{"agent_id": a.agentID, "host_id": a.hostname, "hostname": a.hostname, "source_ip": obs.SrcIP, "target_ip": obs.DstIP},
		"tags":               []string{"traffic", "port_scan", "nmap", "reconnaissance"},
	}
}

func (d *portScanDetector) prune(now time.Time) {
	if d == nil || len(d.entries) == 0 || (!d.lastPrune.IsZero() && now.Sub(d.lastPrune) < d.window) {
		return
	}
	d.lastPrune = now
	maxAge := d.window * 2
	for key, entry := range d.entries {
		if entry == nil || now.Sub(entry.lastSeen) > maxAge {
			delete(d.entries, key)
		}
	}
}

func sortedPortList(ports map[uint16]struct{}) []int64 {
	out := make([]int64, 0, len(ports))
	for port := range ports {
		out = append(out, int64(port))
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sanitizeIDPart(value string) string {
	value = strings.ReplaceAll(value, ".", "-")
	value = strings.ReplaceAll(value, ":", "-")
	return value
}

func annotateApplication(obs *trafficObservation, payload []byte) {
	if obs == nil {
		return
	}
	if obs.SrcPort == 53 || obs.DstPort == 53 {
		obs.AppProtocol = "DNS"
		obs.DNSQuery = parseDNSQuery(payload)
		return
	}
	if method, path, host, ok := parseHTTPRequest(payload); ok {
		obs.AppProtocol = "HTTP"
		obs.HTTPMethod = method
		obs.HTTPPath = path
		obs.HTTPHost = host
		return
	}
	if obs.SrcPort == 443 || obs.DstPort == 443 {
		obs.AppProtocol = "TLS"
		obs.TLSSNI = parseTLSSNI(payload)
		return
	}
	if obs.AppProtocol == "" {
		obs.AppProtocol = obs.Protocol
	}
}

func parseHTTPRequest(payload []byte) (method, path, host string, ok bool) {
	if len(payload) == 0 || len(payload) > 8192 {
		return "", "", "", false
	}
	text := string(payload)
	lineEnd := strings.Index(text, "\r\n")
	if lineEnd <= 0 {
		return "", "", "", false
	}
	parts := strings.Fields(text[:lineEnd])
	if len(parts) < 2 || !isHTTPMethod(parts[0]) {
		return "", "", "", false
	}
	for _, line := range strings.Split(text[lineEnd+2:], "\r\n") {
		if line == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			host = strings.TrimSpace(line[len("host:"):])
			break
		}
	}
	return parts[0], parts[1], host, true
}

func isHTTPMethod(method string) bool {
	switch method {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS":
		return true
	default:
		return false
	}
}

func parseDNSQuery(payload []byte) string {
	if len(payload) < 13 {
		return ""
	}
	offset := 12
	labels := make([]string, 0, 4)
	for offset < len(payload) {
		length := int(payload[offset])
		offset++
		if length == 0 {
			break
		}
		if length&0xC0 != 0 || offset+length > len(payload) {
			return ""
		}
		labels = append(labels, string(payload[offset:offset+length]))
		offset += length
	}
	return strings.Join(labels, ".")
}

func parseTLSSNI(payload []byte) string {
	if len(payload) < 5 || payload[0] != 0x16 {
		return ""
	}
	recordLen := int(payload[3])<<8 | int(payload[4])
	if recordLen <= 0 || len(payload) < 5+recordLen || payload[5] != 0x01 {
		return ""
	}
	offset := 9 // record header + handshake type + 3-byte handshake length
	if len(payload) < offset+34 {
		return ""
	}
	offset += 2 + 32 // client version + random
	if offset >= len(payload) {
		return ""
	}
	sessionLen := int(payload[offset])
	offset += 1 + sessionLen
	if offset+2 > len(payload) {
		return ""
	}
	cipherLen := int(payload[offset])<<8 | int(payload[offset+1])
	offset += 2 + cipherLen
	if offset >= len(payload) {
		return ""
	}
	compressionLen := int(payload[offset])
	offset += 1 + compressionLen
	if offset+2 > len(payload) {
		return ""
	}
	extensionsLen := int(payload[offset])<<8 | int(payload[offset+1])
	offset += 2
	end := offset + extensionsLen
	if end > len(payload) {
		return ""
	}
	for offset+4 <= end {
		extType := int(payload[offset])<<8 | int(payload[offset+1])
		extLen := int(payload[offset+2])<<8 | int(payload[offset+3])
		offset += 4
		if offset+extLen > end {
			return ""
		}
		if extType == 0x0000 {
			return parseTLSServerNameExtension(payload[offset : offset+extLen])
		}
		offset += extLen
	}
	return ""
}

func parseTLSServerNameExtension(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	listLen := int(data[0])<<8 | int(data[1])
	offset := 2
	end := offset + listLen
	if end > len(data) {
		return ""
	}
	for offset+3 <= end {
		nameType := data[offset]
		nameLen := int(data[offset+1])<<8 | int(data[offset+2])
		offset += 3
		if offset+nameLen > end {
			return ""
		}
		if nameType == 0 {
			return string(data[offset : offset+nameLen])
		}
		offset += nameLen
	}
	return ""
}

func trafficPayloadSummary(obs trafficObservation, appProtocol, businessAction string) string {
	parts := []string{obs.Protocol, appProtocol, businessAction, obs.HTTPHost, obs.HTTPMethod, obs.HTTPPath, obs.DNSQuery, obs.TLSSNI}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return strings.Join(out, " ")
}

func businessActionForObservation(obs trafficObservation) string {
	if obs.HTTPPath != "" {
		path := strings.ToLower(obs.HTTPPath)
		switch {
		case strings.Contains(path, "login"):
			return "login"
		case strings.Contains(path, "upload"):
			return "upload"
		case strings.Contains(path, "approve") || strings.Contains(path, "approval"):
			return "approval"
		case strings.Contains(path, "admin") || strings.Contains(path, "manage"):
			return "admin_access"
		default:
			return "http_access"
		}
	}
	if obs.DNSQuery != "" {
		return "dns_query"
	}
	if obs.TLSSNI != "" || obs.AppProtocol == "TLS" {
		return "tls_connection"
	}
	return strings.ToLower(obs.Protocol) + "_flow"
}

func (a *Agent) procfsTrafficObservations() []trafficObservation {
	trafficConfig := a.captureConfigSnapshot()
	files := []struct {
		path     string
		protocol string
	}{
		{"/proc/net/tcp", "TCP"},
		{"/proc/net/udp", "UDP"},
	}
	observations := make([]trafficObservation, 0, 8)
	for _, file := range files {
		data, err := os.ReadFile(file.path)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for i := 1; i < len(lines) && len(observations) < 8; i++ {
			fields := strings.Fields(lines[i])
			if len(fields) < 3 {
				continue
			}
			srcIP, srcPort := parseProcNetAddr(fields[1])
			dstIP, dstPort := parseProcNetAddr(fields[2])
			if srcIP == "" || dstIP == "" || dstIP == "0.0.0.0" {
				continue
			}
			obs := trafficObservation{
				Timestamp:      time.Now().UTC(),
				Source:         "ly-agent-procfs-fallback",
				Engine:         "procfs",
				Interface:      trafficConfig.Interface,
				SrcIP:          srcIP,
				DstIP:          dstIP,
				SrcPort:        srcPort,
				DstPort:        dstPort,
				Protocol:       file.protocol,
				AppProtocol:    file.protocol,
				Packets:        1,
				DurationMillis: 1,
				Direction:      "egress",
			}
			observations = append(observations, obs)
		}
	}
	if len(observations) == 0 {
		serverHost := serverHostFromAPI(a.cfg.API)
		if serverHost == "" {
			serverHost = "127.0.0.1"
		}
		observations = append(observations, trafficObservation{
			Timestamp:      time.Now().UTC(),
			Source:         "ly-agent-procfs-fallback-empty-sample",
			Engine:         "procfs",
			Interface:      trafficConfig.Interface,
			SrcIP:          a.localIP,
			DstIP:          serverHost,
			DstPort:        8080,
			Protocol:       "TCP",
			AppProtocol:    "HTTP",
			HTTPHost:       serverHost,
			HTTPMethod:     "GET",
			HTTPPath:       "/health",
			Packets:        1,
			DurationMillis: 1,
			Direction:      "egress",
		})
	}
	return observations
}

func parseProcNetAddr(value string) (string, uint16) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 || len(parts[0]) != 8 {
		return "", 0
	}
	portValue, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0
	}
	ipHex := parts[0]
	bytes := make([]byte, 4)
	for i := 0; i < 4; i++ {
		v, err := strconv.ParseUint(ipHex[i*2:i*2+2], 16, 8)
		if err != nil {
			return "", 0
		}
		bytes[3-i] = byte(v)
	}
	return net.IPv4(bytes[0], bytes[1], bytes[2], bytes[3]).String(), uint16(portValue)
}

func (a *Agent) runHIDS() {
	strategy := detectStrategy()
	backend := NewRuntimeMonitorBackend(strategy)
	mode := "monitor"
	fmt.Printf("[hids] Monitoring (strategy: %s, mode: %s)\n", strategy, mode)
	a.publishLogAuditHeartbeat()
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			if !a.cfg.HIDSEnabled {
				continue
			}
			a.publishLogAuditHeartbeat()
			fmt.Printf("[hids] Running integrity check...\n")
			events := backend.Collect(a)
			for _, event := range events {
				if err := a.runtimePublisher.Publish(a.ctx, event); err != nil {
					fmt.Printf("[runtime] publish failed: %v\n", err)
				}
				if input, ok := wazuhInputFromRuntimeEvent(event); ok {
					a.publishLogAuditTelemetry(event, input)
					alert, err := componentAlertFromWazuh(input, a, contracts.RawReference{Path: xdrStringFromMap(event.Metadata, "log_path"), EventType: event.Type})
					if err != nil {
						fmt.Printf("[wazuh] log audit conversion failed: %v\n", err)
					} else if err := a.publishComponentAlert(alert); err != nil {
						fmt.Printf("[wazuh] log audit publish failed: %v\n", err)
					}
				}
			}
		}
	}
}

func (a *Agent) publishLogAuditHeartbeat() {
	if strings.TrimSpace(a.cfg.LogAuditTelemetryStream) == "" {
		return
	}
	now := time.Now().UTC()
	telemetry := contracts.TelemetryEnvelope{
		SchemaVersion: contracts.TelemetrySchemaVersion,
		ID:            fmt.Sprintf("log-audit-heartbeat-%s-%d", a.agentID, now.UnixNano()),
		Category:      contracts.TelemetryLogAudit,
		EventType:     "log.collector.heartbeat",
		ObservedAt:    now,
		ReceivedAt:    now,
		Source:        "agent-log-collector",
		Entities: contracts.EntityRef{
			AgentID:  a.agentID,
			HostID:   a.hostname,
			Hostname: a.hostname,
			TargetIP: a.localIP,
		},
		RawReference: &contracts.RawReference{Stream: "logs:raw"},
		Fields: map[string]interface{}{
			"agent_id": a.agentID,
			"hostname": a.hostname,
			"message":  "lyflow log audit collector heartbeat",
			"program":  "ly-agent",
		},
		Excerpt: "lyflow log audit collector heartbeat",
	}
	if err := a.publishAgentStream(a.ctx, "logs:raw", structToMap(telemetry), "log_raw"); err != nil {
		a.handleControlHealth(a.runtimeHealth.Degrade("observation_delivery_unavailable", false))
		fmt.Printf("[log-audit] raw heartbeat publish failed: %v\n", err)
	}
	if err := a.publishAgentStream(a.ctx, a.cfg.LogAuditTelemetryStream, structToMap(telemetry), "telemetry_log_audit"); err != nil {
		a.handleControlHealth(a.runtimeHealth.Degrade("observation_delivery_unavailable", false))
		fmt.Printf("[log-audit] telemetry heartbeat publish failed: %v\n", err)
	}
}

func (a *Agent) publishLogAuditTelemetry(event RuntimeEvent, input wazuhAlertInput) {
	if strings.TrimSpace(a.cfg.LogAuditTelemetryStream) == "" {
		return
	}
	observed := time.Now().UTC()
	if parsed, err := time.Parse(time.RFC3339Nano, event.OccurredAt); err == nil && !parsed.IsZero() {
		observed = parsed
	}
	message := firstNonEmpty(input.FullLog, event.Message)
	telemetry := contracts.TelemetryEnvelope{
		SchemaVersion: contracts.TelemetrySchemaVersion,
		ID:            fmt.Sprintf("log-audit-%s-%d", a.agentID, observed.UnixNano()),
		Category:      contracts.TelemetryLogAudit,
		EventType:     event.Type,
		ObservedAt:    observed,
		ReceivedAt:    time.Now().UTC(),
		Source:        "agent-auth-log-collector",
		Entities: contracts.EntityRef{
			AgentID:  a.agentID,
			HostID:   a.hostname,
			Hostname: a.hostname,
			TargetIP: a.localIP,
		},
		RawReference: &contracts.RawReference{Stream: "logs:raw", Path: input.Location, EventType: event.Type},
		Fields: map[string]interface{}{
			"agent_id": a.agentID,
			"hostname": a.hostname,
			"message":  message,
			"program":  input.Decoder,
			"rule_id":  input.RuleID,
		},
		Excerpt: truncateForMetadata(message, 280),
	}
	if err := a.publishAgentStream(a.ctx, "logs:raw", structToMap(telemetry), "log_raw"); err != nil {
		a.handleControlHealth(a.runtimeHealth.Degrade("observation_delivery_unavailable", false))
		fmt.Printf("[log-audit] raw event publish failed: %v\n", err)
	}
	if err := a.publishAgentStream(a.ctx, a.cfg.LogAuditTelemetryStream, structToMap(telemetry), "telemetry_log_audit"); err != nil {
		a.handleControlHealth(a.runtimeHealth.Degrade("observation_delivery_unavailable", false))
		fmt.Printf("[log-audit] telemetry event publish failed: %v\n", err)
	}
}

func (a *Agent) runAssetCollector() {
	fmt.Printf("[asset] Asset collection\n")
	a.collectFingerprint()
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.collectFingerprint()
		}
	}
}

func (a *Agent) runRASP() {
	fmt.Printf("[rasp] monitor-mode enabled; protection heartbeat active\n")
	a.publishRASPProtectionStatus()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.enforceRASPPolicyExpiry(time.Now().UTC())
			if !a.raspPolicyEnabled() {
				continue
			}
			a.publishRASPProtectionStatus()
		}
	}
}

func (a *Agent) publishRASPProtectionStatus() {
	if strings.TrimSpace(a.cfg.RASPTelemetryStream) == "" {
		return
	}
	now := time.Now().UTC()
	status := map[string]interface{}{
		"agent_id":       a.agentID,
		"hostname":       a.hostname,
		"status":         "protected",
		"mode":           "monitor",
		"policy_state":   "audit_only",
		"applications":   []string{"generic-local-bridge"},
		"hooks":          []string{"sql", "command", "file", "http"},
		"source":         "agent-rasp-probe-manager",
		"last_seen_at":   now.Format(time.RFC3339Nano),
		"updated_at":     now.Format(time.RFC3339Nano),
		"bridge_addr":    a.cfg.RASPBridgeAddr,
		"telemetry_key":  "telemetry:rasp",
		"control_health": a.runtimeHealth.Snapshot(),
	}
	if delivery, ok := a.raspBridgeHealthSnapshot(); ok {
		status["delivery"] = delivery
		if delivery.Status == controlHealthDegraded {
			status["status"] = "degraded"
		}
	}
	telemetry := contracts.TelemetryEnvelope{
		SchemaVersion: contracts.TelemetrySchemaVersion,
		ID:            fmt.Sprintf("rasp-protection-%s-%d", a.agentID, now.UnixNano()),
		Category:      contracts.TelemetryRASP,
		EventType:     "rasp.protection.heartbeat",
		ObservedAt:    now,
		ReceivedAt:    now,
		Source:        "agent-rasp-probe-manager",
		Entities: contracts.EntityRef{
			AgentID:  a.agentID,
			HostID:   a.hostname,
			Hostname: a.hostname,
			TargetIP: a.localIP,
		},
		Fields:  status,
		Excerpt: "RASP protection heartbeat",
	}
	if data, err := json.Marshal(status); err == nil {
		client := redis.NewClient(redisOptions(a.cfg))
		defer client.Close()
		if err := client.Set(a.ctx, "rasp:protection:"+a.agentID, string(data), 5*time.Minute).Err(); err != nil {
			a.handleControlHealth(a.runtimeHealth.Degrade("health_store_unavailable", false))
			fmt.Printf("[rasp] protection health store failed: %v\n", err)
		}
	} else {
		a.handleControlHealth(a.runtimeHealth.Degrade("health_encoding_failed", false))
		fmt.Printf("[rasp] protection health encode failed: %v\n", err)
	}
	if err := a.publishAgentStream(a.ctx, a.cfg.RASPTelemetryStream, structToMap(telemetry), "telemetry_rasp"); err != nil {
		a.handleControlHealth(a.runtimeHealth.Degrade("health_delivery_unavailable", false))
		fmt.Printf("[rasp] protection health publish failed: %v\n", err)
	}
}

func normalizeRASPBridgePayload(payload map[string]interface{}) {
	aliasStringField(payload, "query", "sql", "statement", "db_query")
	aliasStringField(payload, "command", "cmd", "cmdline", "command_line", "process_command")
	aliasStringField(payload, "cmdline", "command", "cmd", "command_line", "process_command")
	aliasStringField(payload, "path", "file", "filepath", "filename", "file_path")
	aliasStringField(payload, "url", "target", "uri", "request_url")
	aliasStringField(payload, "payload", "body", "request_body", "parameter", "params", "query", "command", "path", "url")
	aliasStringField(payload, "message", "payload", "query", "command", "cmdline", "path", "url")
	aliasStringField(payload, "http_path", "uri", "path")
	aliasStringField(payload, "http_host", "host", "hostname")
	if _, ok := payload["hook_type"]; !ok {
		if eventType := pickPayloadString(payload, "event_type", "type"); eventType != "" {
			payload["hook_type"] = eventType
		}
	}
}

func aliasStringField(payload map[string]interface{}, target string, sources ...string) {
	if strings.TrimSpace(pickPayloadString(payload, target)) != "" {
		return
	}
	for _, source := range sources {
		if value := pickPayloadString(payload, source); value != "" {
			payload[target] = value
			return
		}
	}
}

func pickPayloadString(payload map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, ok := payload[key]; ok {
			if s, ok := value.(string); ok && strings.TrimSpace(s) != "" {
				return s
			}
		}
	}
	return ""
}

func runtimeLanguageHint() string {
	switch runtime.GOOS {
	case "linux":
		return "golang"
	default:
		return "generic"
	}
}

func (a *Agent) collectFingerprint() {
	snapshot := map[string]interface{}{
		"agent_id":        a.agentID,
		"agent_key":       a.agentKey,
		"hostname":        a.hostname,
		"ip":              a.localIP,
		"os":              runtime.GOOS,
		"arch":            runtime.GOARCH,
		"kernel":          getKernelVersion(),
		"capabilities":    a.capabilityModel(),
		"interfaces":      collectInterfaces(),
		"listening_ports": collectListeningPorts(64),
		"performance":     collectPerformance(),
		"processes":       collectProcesses(20),
	}
	body, _ := json.Marshal(snapshot)
	if a.agentID != "" {
		if _, err := httpPost(a.cfg.API+"/api/v1/agent/snapshot", body); err != nil {
			fmt.Printf("[asset] Snapshot report failed: %v\n", err)
		}
	}
	fmt.Printf("[asset] Fingerprint: hostname=%s, os=%s, arch=%s, cpus=%d\n",
		a.hostname, runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
}

func collectInterfaces() []map[string]interface{} {
	var items []map[string]interface{}
	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		entry := map[string]interface{}{
			"name":  iface.Name,
			"mac":   iface.HardwareAddr.String(),
			"state": "down",
		}
		if iface.Flags&net.FlagUp != 0 {
			entry["state"] = "up"
		}
		addrs, _ := iface.Addrs()
		var ips []string
		for _, addr := range addrs {
			ips = append(ips, addr.String())
		}
		entry["ips"] = ips
		items = append(items, entry)
	}
	return items
}

func collectListeningPorts(limit int) []map[string]interface{} {
	if limit <= 0 {
		limit = 32
	}
	ports := make([]map[string]interface{}, 0, limit)
	ports = append(ports, collectProcNetPorts("/proc/net/tcp", "tcp", limit-len(ports))...)
	if len(ports) < limit {
		ports = append(ports, collectProcNetPorts("/proc/net/udp", "udp", limit-len(ports))...)
	}
	return ports
}

func collectProcNetPorts(path, protocol string, limit int) []map[string]interface{} {
	if limit <= 0 {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	items := make([]map[string]interface{}, 0, limit)
	for i, line := range strings.Split(string(data), "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if protocol == "tcp" && fields[3] != "0A" {
			continue
		}
		ip, port := parseProcNetAddr(fields[1])
		items = append(items, map[string]interface{}{
			"ip":       ip,
			"port":     int(port),
			"protocol": protocol,
			"state":    procNetState(protocol, fields[3]),
		})
		if len(items) >= limit {
			break
		}
	}
	return items
}

func procNetState(protocol, state string) string {
	if protocol == "udp" {
		return "open"
	}
	if state == "0A" {
		return "listen"
	}
	return strings.ToLower(state)
}

func collectPerformance() map[string]interface{} {
	memory := readMemInfo()
	if len(memory) == 0 {
		memory = readWindowsMemoryInfo()
	}
	perf := map[string]interface{}{
		"load_avg":  readLoadAvg(),
		"memory":    memory,
		"disk":      readDiskUsage("/"),
		"cpu_cores": runtime.NumCPU(),
	}
	if cpuPercent, ok := readWindowsCPUPercent(); ok {
		perf["cpu_usage_percent"] = cpuPercent
	}
	return perf
}

func readWindowsMemoryInfo() map[string]int64 {
	if runtime.GOOS != "windows" {
		return map[string]int64{}
	}
	if result := readWindowsMemoryInfoPowerShell(); len(result) > 0 {
		return result
	}
	out, err := hiddenCommand("wmic", "OS", "get", "FreePhysicalMemory,TotalVisibleMemorySize", "/Value").Output()
	if err != nil {
		return map[string]int64{}
	}
	result := map[string]int64{}
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(parts) != 2 {
			continue
		}
		value, _ := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
		switch strings.TrimSpace(parts[0]) {
		case "TotalVisibleMemorySize":
			result["MemTotal"] = value * 1024
		case "FreePhysicalMemory":
			result["MemAvailable"] = value * 1024
		}
	}
	return result
}

func readWindowsMemoryInfoPowerShell() map[string]int64 {
	out, err := hiddenCommand("powershell", "-NoProfile", "-Command", "$os=Get-CimInstance Win32_OperatingSystem; [string]::Format('{0},{1}', $os.TotalVisibleMemorySize, $os.FreePhysicalMemory)").Output()
	if err != nil {
		return map[string]int64{}
	}
	parts := strings.Split(strings.TrimSpace(string(out)), ",")
	if len(parts) != 2 {
		return map[string]int64{}
	}
	totalKB, _ := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
	freeKB, _ := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
	if totalKB <= 0 {
		return map[string]int64{}
	}
	return map[string]int64{"MemTotal": totalKB * 1024, "MemAvailable": freeKB * 1024}
}

func readWindowsCPUPercent() (float64, bool) {
	if runtime.GOOS != "windows" {
		return 0, false
	}
	out, err := hiddenCommand("powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average").Output()
	if err != nil {
		return 0, false
	}
	value, err := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

func readLoadAvg() []float64 {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return []float64{}
	}
	parts := strings.Fields(string(data))
	var values []float64
	for i := 0; i < len(parts) && i < 3; i++ {
		v, _ := strconv.ParseFloat(parts[i], 64)
		values = append(values, v)
	}
	return values
}

func readMemInfo() map[string]int64 {
	result := map[string]int64{}
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return result
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		if key == "MemTotal" || key == "MemAvailable" {
			v, _ := strconv.ParseInt(fields[1], 10, 64)
			result[key] = v * 1024
		}
	}
	return result
}

func collectProcesses(limit int) []map[string]interface{} {
	out, err := hiddenCommand("ps", "-eo", "pid,ppid,user,comm,args", "--no-headers").Output()
	if err != nil {
		return []map[string]interface{}{}
	}
	var processes []map[string]interface{}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "" || len(processes) >= limit {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		pid, _ := strconv.Atoi(fields[0])
		ppid, _ := strconv.Atoi(fields[1])
		processes = append(processes, map[string]interface{}{
			"pid":     pid,
			"ppid":    ppid,
			"user":    fields[2],
			"name":    fields[3],
			"cmdline": strings.Join(fields[4:], " "),
		})
	}
	return processes
}

type RuntimeEvent struct {
	AgentID          string                 `json:"agent_id"`
	Hostname         string                 `json:"hostname"`
	IP               string                 `json:"ip"`
	Type             string                 `json:"type"`
	Severity         string                 `json:"severity"`
	Strategy         string                 `json:"strategy"`
	Backend          string                 `json:"backend"`
	CapabilityStatus string                 `json:"capability_status"`
	SourceEvidence   string                 `json:"source_evidence"`
	Mode             string                 `json:"mode"`
	Message          string                 `json:"message"`
	OccurredAt       string                 `json:"occurred_at"`
	Metadata         map[string]interface{} `json:"metadata"`
}

type RuntimeMonitorBackend interface {
	Collect(a *Agent) []RuntimeEvent
}

type runtimeCollector interface {
	Collect(a *Agent, strategy string) []RuntimeEvent
}

type runtimeCompositeBackend struct {
	strategy   string
	collectors []runtimeCollector
	fallback   runtimeCollector
}

type runtimeFallbackBackend struct {
	backend string
}

type processSnapshot struct {
	User    string
	Name    string
	Cmdline string
}

type processDeltaCollector struct {
	previous    map[int]processSnapshot
	initialized bool
	maxTracked  int
	maxEvents   int
}

type authLogCollector struct {
	paths       []string
	offsets     map[string]int64
	initialized map[string]bool
	maxEvents   int
	readLimit   int64
}

type fileMetaState struct {
	size        int64
	modUnixNano int64
}

type fileSignalCollector struct {
	paths     []string
	state     map[string]fileMetaState
	maxEvents int
}

func NewRuntimeMonitorBackend(strategy string) RuntimeMonitorBackend {
	return &runtimeCompositeBackend{
		strategy: strategy,
		collectors: []runtimeCollector{
			newProcessDeltaCollector(256, 4),
			newAuthLogCollector([]string{"/var/log/auth.log", "/var/log/secure", "/var/log/messages"}, 4),
			newFileSignalCollector([]string{"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config", "/root/.ssh/authorized_keys", "/etc/crontab", "/etc/cron.d", "/etc/ld.so.preload", "/etc/systemd/system"}, 4),
		},
		fallback: &runtimeFallbackBackend{backend: fallbackBackendLabel(strategy)},
	}
}

func fallbackBackendLabel(strategy string) string {
	switch strategy {
	case "ebpf":
		return "ebpf-fallback"
	case "fanotify", "auditd":
		return strategy
	case "procfs":
		return "procfs"
	default:
		return "procfs-fallback"
	}
}

func (b *runtimeCompositeBackend) Collect(a *Agent) []RuntimeEvent {
	if a.agentID == "" {
		return nil
	}
	events := make([]RuntimeEvent, 0, 8)
	for _, collector := range b.collectors {
		events = append(events, collector.Collect(a, b.strategy)...)
	}
	if len(events) > 0 {
		return events
	}
	if b.fallback == nil {
		return nil
	}
	return b.fallback.Collect(a, b.strategy)
}

func (b *runtimeFallbackBackend) Collect(a *Agent, strategy string) []RuntimeEvent {
	return nil
}

func newProcessDeltaCollector(maxTracked, maxEvents int) *processDeltaCollector {
	if maxTracked <= 0 {
		maxTracked = 128
	}
	if maxEvents <= 0 {
		maxEvents = 3
	}
	return &processDeltaCollector{
		previous:   map[int]processSnapshot{},
		maxTracked: maxTracked,
		maxEvents:  maxEvents,
	}
}

func (c *processDeltaCollector) Collect(a *Agent, strategy string) []RuntimeEvent {
	snapshot := readProcessSnapshot(c.maxTracked)
	if len(snapshot) == 0 {
		return nil
	}
	if !c.initialized {
		c.previous = snapshot
		c.initialized = true
		return nil
	}

	newPIDs := make([]int, 0, len(snapshot))
	for pid := range snapshot {
		if _, known := c.previous[pid]; !known {
			newPIDs = append(newPIDs, pid)
		}
	}
	sort.Ints(newPIDs)

	events := make([]RuntimeEvent, 0, c.maxEvents)
	for _, pid := range newPIDs {
		sample := snapshot[pid]
		severity, signal := processSignal(sample)
		events = append(events, buildRuntimeMonitorEvent(
			a,
			strategy,
			"procfs-process-delta",
			"runtime.process.new",
			severity,
			fmt.Sprintf("new process observed: %s (pid=%d user=%s)", sample.Name, pid, sample.User),
			map[string]interface{}{
				"collector":      "procfs-process-delta",
				"pid":            pid,
				"user":           sample.User,
				"name":           sample.Name,
				"cmdline":        truncateForMetadata(sample.Cmdline, 220),
				"signal":         signal,
				"observed_total": len(snapshot),
			},
		))
		if len(events) >= c.maxEvents {
			break
		}
	}

	c.previous = snapshot
	return events
}

func readProcessSnapshot(maxTracked int) map[int]processSnapshot {
	out, err := hiddenCommand("ps", "-eo", "pid,user,comm,args", "--no-headers").Output()
	if err != nil {
		return nil
	}
	snapshot := make(map[int]processSnapshot, maxTracked)
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		snapshot[pid] = processSnapshot{
			User:    fields[1],
			Name:    fields[2],
			Cmdline: strings.Join(fields[3:], " "),
		}
		if len(snapshot) >= maxTracked {
			break
		}
	}
	return snapshot
}

func processSignal(sample processSnapshot) (severity string, signal string) {
	cmd := strings.ToLower(sample.Cmdline)
	criticalTokens := []string{
		"/dev/tcp/",
		"bash -i",
		"sh -i",
		"nc -e",
		"ncat -e",
		"socat tcp",
		"mkfifo",
		"chmod 777 /tmp",
	}
	if hidsContainsAny(cmd, criticalTokens) {
		return "high", "reverse-shell-or-dangerous-exec"
	}
	persistenceTokens := []string{
		"authorized_keys",
		"crontab",
		"/etc/cron",
		"systemctl enable",
		"systemd-run",
		"ld.so.preload",
		"/etc/rc.local",
	}
	if hidsContainsAny(cmd, persistenceTokens) {
		return "medium", "persistence-change"
	}
	credentialTokens := []string{
		"/etc/shadow",
		"/etc/passwd",
		"/etc/sudoers",
		"useradd ",
		"usermod ",
		"passwd ",
		"chpasswd",
	}
	if hidsContainsAny(cmd, credentialTokens) {
		return "high", "credential-or-account-change"
	}
	containerEscapeTokens := []string{
		"--privileged",
		"cap-add=all",
		"cap_sys_admin",
		"/var/run/docker.sock",
		"hostpid",
		"hostnetwork",
		"hostpath",
		"nsenter",
	}
	if hidsContainsAny(cmd, containerEscapeTokens) {
		return "high", "container-privilege-escalation"
	}
	suspiciousTokens := []string{
		"/dev/tcp/",
		"curl | sh",
		"wget | sh",
		"curl -fs",
		"wget http",
		"python -c",
		"perl -e",
		"php -r",
		"base64 -d",
		"openssl enc",
		"nohup ",
	}
	if hidsContainsAny(cmd, suspiciousTokens) {
		return "medium", "suspicious-command"
	}
	return "low", "new-process"
}

func newAuthLogCollector(paths []string, maxEvents int) *authLogCollector {
	if maxEvents <= 0 {
		maxEvents = 3
	}
	return &authLogCollector{
		paths:       paths,
		offsets:     map[string]int64{},
		initialized: map[string]bool{},
		maxEvents:   maxEvents,
		readLimit:   256 * 1024,
	}
}

func (c *authLogCollector) Collect(a *Agent, strategy string) []RuntimeEvent {
	events := make([]RuntimeEvent, 0, c.maxEvents)
	for _, path := range c.paths {
		fi, err := os.Stat(path)
		if err != nil {
			continue
		}

		offset := c.offsets[path]
		size := fi.Size()
		if !c.initialized[path] {
			c.initialized[path] = true
			c.offsets[path] = size
			continue
		}
		if size < offset {
			offset = 0
		}
		if size == offset {
			continue
		}

		lines, newOffset, err := readAppendedLines(path, offset, c.readLimit)
		if err != nil {
			continue
		}
		c.offsets[path] = newOffset

		for _, line := range lines {
			eventType, severity, signal, ok := classifyAuthSignal(line)
			if !ok {
				continue
			}
			events = append(events, buildRuntimeMonitorEvent(
				a,
				strategy,
				"auth-log-signal",
				eventType,
				severity,
				fmt.Sprintf("authentication signal detected: %s", signal),
				map[string]interface{}{
					"collector": "auth-log-signal",
					"signal":    signal,
					"log_path":  path,
					"log_line":  truncateForMetadata(strings.TrimSpace(line), 280),
				},
			))
			if len(events) >= c.maxEvents {
				return events
			}
		}
	}
	return events
}

func readAppendedLines(path string, offset int64, limit int64) ([]string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, offset, err
	}
	defer f.Close()

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, offset, err
	}
	data, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return nil, offset, err
	}

	lines := make([]string, 0)
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		lines = append(lines, trimmed)
	}
	return lines, offset + int64(len(data)), nil
}

func classifyAuthSignal(line string) (eventType, severity, signal string, ok bool) {
	l := strings.ToLower(line)
	switch {
	case hidsContainsAny(l, []string{"accepted password for root", "accepted publickey for root"}):
		return "runtime.auth.root_login", "high", "root-login", true
	case hidsContainsAny(l, []string{"sudo: pam_unix", "authentication failure", "incorrect password attempts"}) && strings.Contains(l, "sudo"):
		return "runtime.auth.sudo_failure", "medium", "sudo-auth-failure", true
	case hidsContainsAny(l, []string{"failed password", "authentication failure", "invalid user", "maximum authentication attempts", "preauth"}):
		return "runtime.auth.failure", "medium", "failed-auth", true
	case hidsContainsAny(l, []string{"useradd", "usermod", "groupadd", "gpasswd", "added user", "new user", "delete user", "userdel"}):
		return "runtime.auth.account_change", "high", "account-change", true
	case hidsContainsAny(l, []string{"sudo:", "session opened for user root", "su: pam_unix", "sudo su", "sudo -i"}):
		return "runtime.auth.privilege", "medium", "privilege-use", true
	case hidsContainsAny(l, []string{"cron", "crontab", "systemd", "timer"}) && hidsContainsAny(l, []string{"install", "reload", "started", "modified", "opened"}):
		return "runtime.auth.persistence", "medium", "persistence-scheduler", true
	default:
		return "", "", "", false
	}
}

func wazuhInputFromRuntimeEvent(event RuntimeEvent) (wazuhAlertInput, bool) {
	if xdrStringFromMap(event.Metadata, "collector") != "auth-log-signal" {
		return wazuhAlertInput{}, false
	}
	signal := xdrStringFromMap(event.Metadata, "signal")
	ruleID, ruleName, level, decoder := wazuhRuleForRuntimeSignal(signal, event.Type)
	if ruleID == "" {
		return wazuhAlertInput{}, false
	}
	timestamp, _ := time.Parse(time.RFC3339Nano, event.OccurredAt)
	return wazuhAlertInput{
		RuleID:    ruleID,
		RuleName:  ruleName,
		Level:     level,
		Decoder:   decoder,
		Location:  xdrStringFromMap(event.Metadata, "log_path"),
		FullLog:   firstNonEmpty(xdrStringFromMap(event.Metadata, "log_line"), event.Message),
		Timestamp: timestamp,
	}, true
}

func wazuhRuleForRuntimeSignal(signal, eventType string) (ruleID, ruleName string, level int, decoder string) {
	switch signal {
	case "root-login":
		return "5715", "Wazuh SSHD root login", 10, "sshd"
	case "sudo-auth-failure":
		return "5503", "Wazuh PAM authentication failure", 7, "pam"
	case "failed-auth":
		return "5716", "Wazuh SSHD authentication failed", 7, "sshd"
	case "account-change":
		return "5902", "Wazuh user account changed", 10, "syslog"
	case "privilege-use":
		return "5402", "Wazuh sudo privilege escalation", 7, "sudo"
	case "persistence-scheduler":
		return "5901", "Wazuh scheduled task persistence signal", 7, "syslog"
	default:
		if strings.HasPrefix(eventType, "runtime.auth.") {
			return "5700", "Wazuh authentication audit signal", 5, "syslog"
		}
		return "", "", 0, ""
	}
}

func xdrStringFromMap(values map[string]interface{}, key string) string {
	if values == nil {
		return ""
	}
	if value, ok := values[key]; ok {
		if s, ok := value.(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func newFileSignalCollector(paths []string, maxEvents int) *fileSignalCollector {
	if maxEvents <= 0 {
		maxEvents = 3
	}
	return &fileSignalCollector{
		paths:     paths,
		state:     map[string]fileMetaState{},
		maxEvents: maxEvents,
	}
}

func (c *fileSignalCollector) Collect(a *Agent, strategy string) []RuntimeEvent {
	events := make([]RuntimeEvent, 0, c.maxEvents)
	for _, path := range c.paths {
		fi, err := os.Stat(path)
		if err != nil {
			continue
		}

		current := fileMetaState{size: fi.Size(), modUnixNano: fi.ModTime().UnixNano()}
		previous, seen := c.state[path]
		c.state[path] = current
		if !seen {
			continue
		}
		if previous.size == current.size && previous.modUnixNano == current.modUnixNano {
			continue
		}

		events = append(events, buildRuntimeMonitorEvent(
			a,
			strategy,
			"file-metadata-fallback",
			"runtime.file.changed",
			fileSignalSeverity(path),
			fmt.Sprintf("sensitive file change observed: %s", path),
			map[string]interface{}{
				"collector":        "file-metadata-fallback",
				"path":             path,
				"previous_size":    previous.size,
				"current_size":     current.size,
				"current_modified": fi.ModTime().UTC().Format(time.RFC3339Nano),
			},
		))
		if len(events) >= c.maxEvents {
			break
		}
	}
	return events
}

func fileSignalSeverity(path string) string {
	p := strings.ToLower(path)
	if hidsContainsAny(p, []string{"shadow", "sudoers", "ld.so.preload"}) {
		return "high"
	}
	if hidsContainsAny(p, []string{"authorized_keys", "cron", "systemd", "sshd_config"}) {
		return "medium"
	}
	return "medium"
}

func hidsContainsAny(value string, tokens []string) bool {
	for _, token := range tokens {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}

func truncateForMetadata(value string, maxLen int) string {
	if maxLen <= 0 || len(value) <= maxLen {
		return value
	}
	return value[:maxLen] + "..."
}

func buildRuntimeMonitorEvent(a *Agent, strategy, backend, eventType, severity, message string, metadata map[string]interface{}) RuntimeEvent {
	if metadata == nil {
		metadata = map[string]interface{}{}
	}
	capabilityStatus := runtimeCapabilityStatus(strategy, backend)
	sourceEvidence := runtimeSourceEvidence(strategy, backend, metadata)
	metadata["runtime_enabled"] = a.cfg.HIDSEnabled
	metadata["source"] = "agent-runtime-monitor"
	metadata["capability_status"] = capabilityStatus
	metadata["source_evidence"] = sourceEvidence
	metadata["fallback_reason"] = runtimeFallbackReason(strategy, backend)
	metadata["risk_mode"] = "low"
	return RuntimeEvent{
		AgentID:          a.agentID,
		Hostname:         a.hostname,
		IP:               a.localIP,
		Type:             eventType,
		Severity:         severity,
		Strategy:         strategy,
		Backend:          backend,
		CapabilityStatus: capabilityStatus,
		SourceEvidence:   sourceEvidence,
		Mode:             "monitor",
		Message:          message,
		OccurredAt:       time.Now().UTC().Format(time.RFC3339Nano),
		Metadata:         metadata,
	}
}

func runtimeCapabilityStatus(strategy, backend string) string {
	if strategy == "unsupported" || strategy == "disabled" {
		return "unsupported_fallback"
	}
	if strings.HasSuffix(backend, "-fallback") || strings.Contains(backend, "fallback") {
		return "fallback"
	}
	return "active"
}

func runtimeFallbackReason(strategy, backend string) string {
	if !strings.Contains(backend, "fallback") {
		return ""
	}
	switch strategy {
	case "ebpf":
		return "full_ebpf_runtime_backend_not_implemented"
	case "auditd":
		return "auditd_backend_not_available_or_not_configured"
	case "fanotify":
		return "fanotify_backend_not_available_or_not_configured"
	case "unsupported":
		return "runtime_sensor_unsupported_on_this_os"
	case "disabled":
		return "runtime_backend_unavailable_no_event_emitted"
	default:
		return "runtime_backend_using_monitor_fallback"
	}
}

func runtimeSourceEvidence(strategy, backend string, metadata map[string]interface{}) string {
	if collector, ok := metadata["collector"].(string); ok && collector != "" {
		return collector
	}
	if path, ok := metadata["path"].(string); ok && path != "" {
		return path
	}
	return strategy + ":" + backend
}

func buildSyntheticRuntimeEvent(a *Agent, strategy, backend string) RuntimeEvent {
	return buildRuntimeMonitorEvent(
		a,
		strategy,
		backend,
		"runtime.monitor.sample",
		"low",
		"runtime monitor-mode fallback sample event",
		map[string]interface{}{
			"collector": "synthetic-fallback",
		},
	)
}

type RuntimeEventPublisher interface {
	Publish(ctx context.Context, event RuntimeEvent) error
}

type HTTPRuntimePublisher struct {
	agent *Agent
}

func NewHTTPRuntimePublisher(agent *Agent) RuntimeEventPublisher {
	return &HTTPRuntimePublisher{agent: agent}
}

func (p *HTTPRuntimePublisher) Publish(ctx context.Context, event RuntimeEvent) error {
	if err := p.agent.publishAgentStream(ctx, "alerts:runtime", structToMap(event), "runtime_event"); err != nil {
		return err
	}
	fmt.Printf("[runtime] published monitor event: type=%s backend=%s\n", event.Type, event.Backend)
	return nil
}

func detectStrategy() string {
	if runtime.GOOS != "linux" {
		return "unsupported"
	}
	if exists("/sys/kernel/debug/tracing") || exists("/sys/fs/bpf") {
		v := getKernelVersion()
		if strings.Contains(v, "el7") || strings.Contains(v, "centos7") {
			return "auditd"
		}
		if compareVer(v, "4.0.0") >= 0 {
			return "ebpf"
		}
	}
	if exists("/dev/fanotify") {
		return "fanotify"
	}
	return "disabled"
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func getKernelVersion() string {
	d, _ := os.ReadFile("/proc/version")
	parts := strings.Split(string(d), " ")
	if len(parts) >= 3 {
		return parts[2]
	}
	return "unknown"
}

func compareVer(v1, v2 string) int {
	p1 := parseV(v1)
	p2 := parseV(v2)
	for i := 0; i < len(p1) && i < len(p2); i++ {
		if p1[i] < p2[i] {
			return -1
		}
		if p1[i] > p2[i] {
			return 1
		}
	}
	if len(p1) < len(p2) {
		return -1
	}
	if len(p1) > len(p2) {
		return 1
	}
	return 0
}

func parseV(v string) []int {
	v = strings.TrimPrefix(v, "v")
	v = strings.Split(v, "-")[0]
	var r []int
	for _, p := range strings.Split(v, ".") {
		n := 0
		for _, c := range p {
			if c >= '0' && c <= '9' {
				n = n*10 + int(c-'0')
			} else {
				break
			}
		}
		r = append(r, n)
	}
	return r
}

func getLocalIP() string {
	addrs, _ := net.InterfaceAddrs()
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil && !ipNet.IP.IsLoopback() {
			return ipNet.IP.String()
		}
	}
	return "127.0.0.1"
}

func resolveTrafficInterface(cfg *Config) string {
	iface := strings.TrimSpace(cfg.TrafficInterface)
	if iface != "" && !strings.EqualFold(iface, "auto") {
		return iface
	}
	if strings.EqualFold(strings.TrimSpace(cfg.Mode), "local-mirror") || strings.EqualFold(strings.TrimSpace(cfg.Mode), "local_mirror") || strings.EqualFold(strings.TrimSpace(cfg.Mode), "mirror") {
		return ""
	}
	if runtime.GOOS == "windows" {
		return "auto"
	}

	if resolved, err := defaultRouteInterface(); err == nil && resolved != "" {
		return resolved
	}

	host := serverHostFromAPI(cfg.API)
	if host != "" {
		if resolved, err := routeInterfaceToHost(host); err == nil && resolved != "" {
			return resolved
		}
	}

	return "eth0"
}

func serverHostFromAPI(api string) string {
	raw := strings.TrimSpace(api)
	if raw == "" {
		return ""
	}

	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func routeInterfaceToHost(host string) (string, error) {
	output, err := hiddenCommand("ip", "route", "get", host).Output()
	if err != nil {
		return "", err
	}
	iface := parseRouteDev(string(output))
	if iface == "" {
		return "", fmt.Errorf("route interface not found")
	}
	return iface, nil
}

func defaultRouteInterface() (string, error) {
	output, err := hiddenCommand("ip", "route", "show", "default").Output()
	if err != nil {
		return "", err
	}
	iface := parseRouteDev(string(output))
	if iface == "" {
		return "", fmt.Errorf("default route interface not found")
	}
	return iface, nil
}

func parseRouteDev(output string) string {
	fields := strings.Fields(output)
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "dev" {
			return fields[i+1]
		}
	}
	return ""
}

func getEnv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func resolveConfigPath(args []string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == "--config" && i+1 < len(args) {
			if p := strings.TrimSpace(args[i+1]); p != "" {
				return p
			}
		}
		if strings.HasPrefix(args[i], "--config=") {
			if p := strings.TrimSpace(strings.TrimPrefix(args[i], "--config=")); p != "" {
				return p
			}
		}
	}

	if p := os.Getenv("CONFIG_FILE"); p != "" {
		return p
	}
	if p := os.Getenv("AGENT_CONFIG"); p != "" {
		return p
	}
	return defaultConfigFile
}

func stripYAMLComment(s string) string {
	inSingle := false
	inDouble := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch ch {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				return s[:i]
			}
		}
	}
	return s
}

func cleanYAMLValue(raw string) string {
	value := strings.TrimSpace(stripYAMLComment(raw))
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
			value = value[1 : len(value)-1]
		}
	}
	return value
}

func parseSimpleYAML(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	values := make(map[string]string)
	sections := make(map[int]string)
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			continue
		}

		indent := len(line) - len(strings.TrimLeft(line, " "))
		key := strings.TrimSpace(parts[0])
		value := cleanYAMLValue(parts[1])
		level := indent / 2

		for existing := range sections {
			if existing >= level {
				delete(sections, existing)
			}
		}

		if value == "" {
			sections[level] = key
			continue
		}

		pathParts := make([]string, 0, level+1)
		for i := 0; i < level; i++ {
			section, ok := sections[i]
			if !ok {
				continue
			}
			pathParts = append(pathParts, section)
		}
		pathParts = append(pathParts, key)
		values[strings.Join(pathParts, ".")] = value
	}

	return values, nil
}

func parseBoolOrDefault(raw string, fallback bool) bool {
	v, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return fallback
	}
	return v
}

func applyYAMLConfig(cfg *Config, yamlValues map[string]string) {
	if v := yamlValues["server.api"]; v != "" {
		cfg.API = v
	}
	if v := yamlValues["server.redis"]; v != "" {
		cfg.Redis = v
	}
	if v := yamlValues["server.insecure_skip_verify"]; v != "" {
		cfg.InsecureSkipVerify = parseBoolOrDefault(v, cfg.InsecureSkipVerify)
	}
	if v := yamlValues["agent.id"]; v != "" {
		cfg.AgentID = v
	}
	if v := yamlValues["agent.key"]; v != "" {
		cfg.AgentKey = v
	}
	if v := yamlValues["agent.heartbeat_interval"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.HeartbeatInterval = n
		}
	}
	if v := yamlValues["agent.log_level"]; v != "" {
		cfg.LogLevel = v
	}
	if v := yamlValues["agent.log_file"]; v != "" {
		cfg.LogFile = v
	}
	if v := yamlValues["traffic.enabled"]; v != "" {
		cfg.TrafficEnabled = parseBoolOrDefault(v, cfg.TrafficEnabled)
	}
	if v := yamlValues["traffic.interface"]; v != "" {
		cfg.TrafficInterface = v
	}
	if v := yamlValues["traffic.capture_engine"]; v != "" {
		cfg.CaptureEngine = v
	}
	if v := yamlValues["traffic.bpf_filter"]; v != "" {
		cfg.BPFFilter = v
	}
	if v := yamlValues["traffic.promiscuous"]; v != "" {
		cfg.Promiscuous = parseBoolOrDefault(v, cfg.Promiscuous)
	}
	if v := yamlValues["traffic.sample_every_n"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.TrafficSampleEveryN = n
		}
	}
	if v := yamlValues["traffic.max_events_per_second"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			cfg.MaxTrafficEventsPerSec = n
		}
	}
	if v := yamlValues["traffic.streams.raw"]; v != "" {
		cfg.RawStream = v
	}
	if v := yamlValues["traffic.streams.semantic"]; v != "" {
		cfg.SemanticStream = v
	}
	if v := yamlValues["traffic.streams.telemetry"]; v != "" {
		cfg.TrafficTelemetryStream = v
	}
	if v := yamlValues["session.enabled"]; v != "" {
		cfg.SessionEnabled = parseBoolOrDefault(v, cfg.SessionEnabled)
	}
	if v := yamlValues["session.stream"]; v != "" {
		cfg.SessionStream = v
	}
	if v := yamlValues["retention.enabled"]; v != "" {
		cfg.RetentionEnabled = parseBoolOrDefault(v, cfg.RetentionEnabled)
	}
	if v := yamlValues["retention.dir"]; v != "" {
		cfg.RetentionDir = v
	}
	if v := yamlValues["spool.enabled"]; v != "" {
		cfg.SpoolEnabled = parseBoolOrDefault(v, cfg.SpoolEnabled)
	}
	if v := yamlValues["spool.dir"]; v != "" {
		cfg.SpoolDir = v
	}
	if v := yamlValues["spool.max_bytes"]; v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			cfg.SpoolMaxBytes = n
		}
	}
	if v := yamlValues["spool.flush_interval_seconds"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.SpoolFlushInterval = n
		}
	}
	if v := yamlValues["asset.enabled"]; v != "" {
		cfg.AssetEnabled = parseBoolOrDefault(v, cfg.AssetEnabled)
	}
	if v := yamlValues["runtime.enabled"]; v != "" {
		cfg.HIDSEnabled = parseBoolOrDefault(v, cfg.HIDSEnabled)
	}
	if v := yamlValues["runtime.stream"]; v != "" {
		cfg.RuntimeStream = v
	}
	if v := yamlValues["runtime.telemetry_stream"]; v != "" {
		cfg.RuntimeTelemetryStream = v
	}
	if v := yamlValues["yara.command"]; v != "" {
		cfg.YARACommand = v
	}
	if v := yamlValues["yara.rules_path"]; v != "" {
		cfg.YARARulesPath = v
	}
	if v := yamlValues["yara.scan_paths"]; v != "" {
		cfg.YARAScanPaths = v
	}
	if v := yamlValues["yara.scan_interval_seconds"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.YARAScanIntervalSeconds = n
		}
	}
	if v := yamlValues["yara.scan_timeout_seconds"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.YARAScanTimeoutSeconds = n
		}
	}
	if v := yamlValues["rasp.enabled"]; v != "" {
		cfg.RASPEnabled = parseBoolOrDefault(v, cfg.RASPEnabled)
	}
	if v := yamlValues["rasp.stream"]; v != "" {
		cfg.RASPStream = v
	}
	if v := yamlValues["rasp.telemetry_stream"]; v != "" {
		cfg.RASPTelemetryStream = v
	}
	if v := yamlValues["rasp.bridge_addr"]; v != "" {
		cfg.RASPBridgeAddr = v
	}
	if v := yamlValues["rasp.bridge_token"]; v != "" {
		cfg.RASPBridgeToken = v
	}
	if v := yamlValues["rasp.policy_root"]; v != "" {
		cfg.RASPPolicyRootPath = v
	}
	if v := yamlValues["log_audit.telemetry_stream"]; v != "" {
		cfg.LogAuditTelemetryStream = v
	}
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("AGENT_ID"); v != "" {
		cfg.AgentID = v
	}
	if v := os.Getenv("AGENT_KEY"); v != "" {
		cfg.AgentKey = v
	}
	if v := os.Getenv("AGENT_ENROLL_TOKEN"); v != "" {
		cfg.EnrollmentToken = v
	}
	if v := os.Getenv("AGENT_MODE"); v != "" {
		cfg.Mode = v
	}
	if v := os.Getenv("LOCAL_MIRROR_MODE"); v != "" && parseBoolOrDefault(v, false) {
		cfg.Mode = "local-mirror"
	}
	if v := os.Getenv("API_SERVER"); v != "" {
		cfg.API = v
	}
	if v := os.Getenv("REDIS_SERVER"); v != "" {
		cfg.Redis = v
	}
	cfg.RedisUsername = os.Getenv("REDIS_ACL_USERNAME")
	cfg.RedisPassword = os.Getenv("REDIS_ACL_PASSWORD")
	cfg.RedisLegacyPassword = os.Getenv("REDIS_PASSWORD")
	if v := os.Getenv("API_INSECURE_SKIP_VERIFY"); v != "" {
		cfg.InsecureSkipVerify = parseBoolOrDefault(v, cfg.InsecureSkipVerify)
	}
	if v := os.Getenv("LOG_FILE"); v != "" {
		cfg.LogFile = v
	}
	if v := os.Getenv("TRAFFIC_ENABLED"); v != "" {
		cfg.TrafficEnabled = parseBoolOrDefault(v, cfg.TrafficEnabled)
	}
	if v := os.Getenv("TRAFFIC_INTERFACE"); v != "" {
		cfg.TrafficInterface = v
	}
	if v := os.Getenv("CAPTURE_ENGINE"); v != "" {
		cfg.CaptureEngine = v
	}
	if v := os.Getenv("BPF_FILTER"); v != "" {
		cfg.BPFFilter = v
	}
	if v := os.Getenv("PROMISCUOUS"); v != "" {
		cfg.Promiscuous = parseBoolOrDefault(v, cfg.Promiscuous)
	}
	if v := os.Getenv("TRAFFIC_MAX_EVENTS_PER_SECOND"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			cfg.MaxTrafficEventsPerSec = n
		}
	}
	if v := os.Getenv("TRAFFIC_SAMPLE_EVERY_N"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.TrafficSampleEveryN = n
		}
	}
	if v := os.Getenv("RAW_STREAM"); v != "" {
		cfg.RawStream = v
	}
	if v := os.Getenv("SEMANTIC_STREAM"); v != "" {
		cfg.SemanticStream = v
	}
	if v := os.Getenv("TELEMETRY_TRAFFIC_STREAM"); v != "" {
		cfg.TrafficTelemetryStream = v
	}
	if v := os.Getenv("TELEMETRY_RUNTIME_STREAM"); v != "" {
		cfg.RuntimeTelemetryStream = v
	}
	if v := os.Getenv("TELEMETRY_RASP_STREAM"); v != "" {
		cfg.RASPTelemetryStream = v
	}
	if v := os.Getenv("TELEMETRY_LOG_AUDIT_STREAM"); v != "" {
		cfg.LogAuditTelemetryStream = v
	}
	if v := os.Getenv("SESSION_STREAM"); v != "" {
		cfg.SessionStream = v
	}
	if v := os.Getenv("RETENTION_ENABLED"); v != "" {
		cfg.RetentionEnabled = parseBoolOrDefault(v, cfg.RetentionEnabled)
	}
	if v := os.Getenv("RETENTION_DIR"); v != "" {
		cfg.RetentionDir = v
	}
	if v := os.Getenv("SPOOL_ENABLED"); v != "" {
		cfg.SpoolEnabled = parseBoolOrDefault(v, cfg.SpoolEnabled)
	}
	if v := os.Getenv("SPOOL_DIR"); v != "" {
		cfg.SpoolDir = v
	}
	if v := os.Getenv("SPOOL_MAX_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			cfg.SpoolMaxBytes = n
		}
	}
	if v := os.Getenv("SPOOL_FLUSH_INTERVAL_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.SpoolFlushInterval = n
		}
	}
	if v := os.Getenv("HIDS_ENABLED"); v != "" {
		cfg.HIDSEnabled = parseBoolOrDefault(v, cfg.HIDSEnabled)
	}
	if v := os.Getenv("YARA_COMMAND"); v != "" {
		cfg.YARACommand = v
	}
	if v := os.Getenv("YARA_RULES_PATH"); v != "" {
		cfg.YARARulesPath = v
	}
	if v := os.Getenv("YARA_SCAN_PATHS"); v != "" {
		cfg.YARAScanPaths = v
	}
	if v := os.Getenv("YARA_SCAN_INTERVAL_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.YARAScanIntervalSeconds = n
		}
	}
	if v := os.Getenv("YARA_SCAN_TIMEOUT_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.YARAScanTimeoutSeconds = n
		}
	}
	if v := os.Getenv("YARA_MAX_FILE_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			cfg.YARAMaxFileBytes = n
		}
	}
	if v := os.Getenv("YARA_MAX_MATCHES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.YARAMaxMatches = n
		}
	}
	if v := os.Getenv("RASP_ENABLED"); v != "" {
		cfg.RASPEnabled = parseBoolOrDefault(v, cfg.RASPEnabled)
	}
	if v := os.Getenv("RASP_BRIDGE_ADDR"); v != "" {
		cfg.RASPBridgeAddr = v
	}
	if v := os.Getenv("LY_RASP_TOKEN"); v != "" {
		cfg.RASPBridgeToken = v
	}
	if v := os.Getenv("RASP_POLICY_ROOT"); v != "" {
		cfg.RASPPolicyRootPath = v
	}
	if v := os.Getenv("AGENT_BINARY_DIGEST"); v != "" {
		cfg.AgentBinaryDigestPath = v
	}
	if v := os.Getenv("AGENT_BINARY_ROOT"); v != "" {
		cfg.AgentBinaryRootPath = v
	}
	if v := os.Getenv("AGENT_CONFIG_SIGNATURE"); v != "" {
		cfg.AgentConfigSignaturePath = v
	}
	if v := os.Getenv("AGENT_CONFIG_ROOT"); v != "" {
		cfg.AgentConfigRootPath = v
	}
	if v := os.Getenv("AGENT_IDENTITY_CONFIG"); v != "" {
		cfg.AgentIdentityPath = v
	}
	if v := os.Getenv("AGENT_REQUIRE_BINARY_INTEGRITY"); v != "" {
		cfg.RequireAgentIntegrity = parseBoolOrDefault(v, cfg.RequireAgentIntegrity)
	}
	if v := os.Getenv("AGENT_REQUIRE_CONFIG_INTEGRITY"); v != "" {
		cfg.RequireConfigIntegrity = parseBoolOrDefault(v, cfg.RequireConfigIntegrity)
	}
	if v := os.Getenv("ASSET_ENABLED"); v != "" {
		cfg.AssetEnabled = parseBoolOrDefault(v, cfg.AssetEnabled)
	}
}

func httpClient(insecureSkipVerify bool, timeout time.Duration) *http.Client {
	transport := http.DefaultTransport
	if insecureSkipVerify {
		transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}

func httpPost(url string, body []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := httpClient(agentInsecureSkipVerify(), 30*time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	result, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(result)))
	}
	return result, nil
}

func httpPostAgent(url string, body []byte, agentID, agentKey string) ([]byte, error) {
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Lyflow-Agent-ID", agentID)
	req.Header.Set("Authorization", "Bearer "+agentKey)
	client := httpClient(agentInsecureSkipVerify(), 30*time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	response, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("agent HTTP POST %s: status %d: %s", url, resp.StatusCode, strings.TrimSpace(string(response)))
	}
	return response, nil
}

func agentInsecureSkipVerify() bool {
	return httpInsecureSkipVerify
}

func httpGet(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	client := httpClient(agentInsecureSkipVerify(), 10*time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	result, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(result)))
	}
	return result, nil
}

func fetchMirrorInterface(api string) string {
	config := fetchMirrorConfig(api)
	if !config.Enabled {
		return ""
	}
	return strings.TrimSpace(config.Interface)
}

type mirrorRuntimeConfig struct {
	Enabled   bool
	Interface string
}

func fetchMirrorConfig(api string) mirrorRuntimeConfig {
	api = strings.TrimRight(strings.TrimSpace(api), "/")
	if api == "" {
		return mirrorRuntimeConfig{Enabled: true}
	}
	body, err := httpGet(api + "/api/v1/traffic/mirror-interface")
	if err != nil {
		fmt.Printf("[mirror] mirror config unavailable: %v\n", err)
		return mirrorRuntimeConfig{Enabled: true}
	}
	var response struct {
		Data struct {
			Enabled   bool   `json:"enabled"`
			Interface string `json:"interface"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		fmt.Printf("[mirror] parse mirror config failed: %v\n", err)
		return mirrorRuntimeConfig{Enabled: true}
	}
	return mirrorRuntimeConfig{Enabled: response.Data.Enabled, Interface: strings.TrimSpace(response.Data.Interface)}
}

func setupLogging(cfg *Config) func() {
	if cfg == nil || strings.TrimSpace(cfg.LogFile) == "" {
		return func() {}
	}

	logDir := filepath.Dir(cfg.LogFile)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		log.Printf("[agent] warning: failed to create log directory %s: %v", logDir, err)
		return func() {}
	}

	logFile, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("[agent] warning: failed to open log file %s: %v", cfg.LogFile, err)
		return func() {}
	}

	log.SetOutput(io.MultiWriter(os.Stdout, logFile))
	return func() {
		if err := logFile.Close(); err != nil {
			log.Printf("[agent] warning: failed to close log file %s: %v", cfg.LogFile, err)
		}
	}
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	handled, err := runHealthcheckSubcommand(os.Args[1:], localMirrorWatchdogPath(), systemTrafficClock{})
	if handled {
		if err != nil {
			fmt.Fprintf(os.Stderr, "local-mirror healthcheck failed: %v\n", err)
			os.Exit(1)
		}
		return
	}
	fmt.Printf("\n=== ly-agent %s - Universal Security Agent ===\n\n", version)
	if ensurePlatformInstall() {
		return
	}

	cfg := &Config{
		API:                      "http://localhost:8080",
		Redis:                    "localhost:6379",
		HeartbeatInterval:        30,
		LogLevel:                 "info",
		LogFile:                  "/opt/ly-agent/logs/agent.log",
		TrafficEnabled:           true,
		TrafficInterface:         "auto",
		CaptureEngine:            "auto",
		BPFFilter:                "",
		Promiscuous:              true,
		TrafficSampleEveryN:      1,
		MaxTrafficEventsPerSec:   0,
		RawStream:                "flows:raw",
		SemanticStream:           "flows:semantic",
		SessionEnabled:           true,
		SessionStream:            "sessions:semantic",
		TrafficTelemetryStream:   "telemetry:traffic",
		RuntimeTelemetryStream:   "telemetry:runtime",
		RASPTelemetryStream:      "telemetry:rasp",
		LogAuditTelemetryStream:  "telemetry:log_audit",
		RetentionEnabled:         true,
		RetentionDir:             "/opt/ly-agent/data/packets",
		SpoolEnabled:             true,
		SpoolDir:                 "/opt/ly-agent/data/spool",
		SpoolMaxBytes:            10 * 1024 * 1024 * 1024,
		SpoolFlushInterval:       1,
		HIDSEnabled:              true,
		RuntimeStream:            "alerts:runtime",
		YARACommand:              "yara",
		YARARulesPath:            "/opt/ly-agent/yara/rules.yar",
		YARAScanPaths:            "/opt/ly-agent/yara/scan",
		YARAScanIntervalSeconds:  60,
		YARAScanTimeoutSeconds:   30,
		YARAMaxFileBytes:         256 * 1024 * 1024,
		YARAMaxMatches:           1000,
		RASPEnabled:              false,
		RASPStream:               "alerts:rasp",
		RASPBridgeAddr:           "127.0.0.1:17891",
		RASPBridgeToken:          getEnv("LY_RASP_TOKEN", ""),
		RASPPolicyRootPath:       getEnv("RASP_POLICY_ROOT", "/etc/lyflow/trust/policy-root.pem"),
		RASPMode:                 "monitor",
		AgentBinaryDigestPath:    getEnv("AGENT_BINARY_DIGEST", "/etc/lyflow/trust/agent-binary.digest.json"),
		AgentBinaryRootPath:      getEnv("AGENT_BINARY_ROOT", "/etc/lyflow/trust/agent-binary-root.pem"),
		AgentConfigPath:          getEnv("AGENT_CONFIG", defaultConfigFile),
		AgentConfigSignaturePath: getEnv("AGENT_CONFIG_SIGNATURE", "/etc/lyflow/trust/agent-config.digest.json"),
		AgentConfigRootPath:      getEnv("AGENT_CONFIG_ROOT", "/etc/lyflow/trust/agent-config-root.pem"),
		AgentIdentityPath:        getEnv("AGENT_IDENTITY_CONFIG", "/opt/ly-agent/etc/agent-identity.yaml"),
		RequireAgentIntegrity:    parseBoolOrDefault(getEnv("AGENT_REQUIRE_BINARY_INTEGRITY", "true"), true),
		RequireConfigIntegrity:   parseBoolOrDefault(getEnv("AGENT_REQUIRE_CONFIG_INTEGRITY", "true"), true),
		AssetEnabled:             true,
	}
	applyPlatformDefaults(cfg)

	configPath := resolveConfigPath(os.Args[1:])
	cfg.AgentConfigPath = configPath
	if yamlValues, err := parseSimpleYAML(configPath); err == nil {
		applyYAMLConfig(cfg, yamlValues)
	} else {
		log.Printf("[agent] config file not loaded (%s): %v", configPath, err)
	}
	if identityValues, err := parseSimpleYAML(cfg.AgentIdentityPath); err == nil {
		applyAgentIdentity(cfg, identityValues)
	}
	applyEnvOverrides(cfg)
	applyPlatformTrafficPolicy(cfg)
	httpInsecureSkipVerify = cfg.InsecureSkipVerify
	cfg.TrafficInterface = resolveTrafficInterface(cfg)
	logCleanup := setupLogging(cfg)
	defer logCleanup()
	fmt.Printf("[agent] Selected traffic interface: %s\n", cfg.TrafficInterface)
	startPlatformUI()

	agent := NewAgent(cfg)
	if err := agent.Start(); err != nil {
		log.Fatalf("Agent start failed: %v", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Println("\n[agent] Shutdown signal")
	agent.Stop()
	fmt.Println("[agent] Stopped")
}
