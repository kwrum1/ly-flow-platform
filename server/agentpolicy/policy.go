package agentpolicy

import "fmt"

type Policy struct {
	ID              string                 `json:"id"`
	Version         int                    `json:"version"`
	Traffic         TrafficPolicy          `json:"traffic"`
	RASP            RASPPolicy             `json:"rasp"`
	Runtime         RuntimePolicy          `json:"runtime"`
	Asset           AssetPolicy            `json:"asset"`
	Retention       RetentionPolicy        `json:"retention"`
	Streams         map[string]string      `json:"streams"`
	LastAppliedBy   string                 `json:"last_applied_by,omitempty"`
	LastAckVersion  int                    `json:"last_ack_version,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

type TrafficPolicy struct {
	Enabled       bool   `json:"enabled"`
	Interface     string `json:"interface"`
	CaptureEngine string `json:"capture_engine"`
	BPFFilter     string `json:"bpf_filter"`
	Promiscuous   bool   `json:"promiscuous"`
}

type RASPPolicy struct {
	Mode       string          `json:"mode"`
	Languages  map[string]bool `json:"languages"`
	BlockOnHit bool            `json:"block_on_hit"`
}

type RuntimePolicy struct {
	Enabled      bool     `json:"enabled"`
	Backend      string   `json:"backend"`
	IncludePaths []string `json:"include_paths"`
	ExcludePaths []string `json:"exclude_paths"`
}

type AssetPolicy struct {
	IntervalSeconds int  `json:"interval_seconds"`
	Processes       bool `json:"processes"`
	Performance     bool `json:"performance"`
}

type RetentionPolicy struct {
	EvidenceEnabled bool `json:"evidence_enabled"`
	MaxFileMB       int  `json:"max_file_mb"`
	RetainDays      int  `json:"retain_days"`
}

func DefaultPolicy(agentID string) Policy {
	return Policy{
		ID:      fmt.Sprintf("policy-%s", agentID),
		Version: 1,
		Traffic: TrafficPolicy{Enabled: true, Interface: "auto", CaptureEngine: "auto", BPFFilter: "tcp or udp", Promiscuous: true},
		RASP:    RASPPolicy{Mode: "monitor", Languages: map[string]bool{"python": true, "java": false}, BlockOnHit: false},
		Runtime: RuntimePolicy{Enabled: true, Backend: "auto", IncludePaths: []string{"/etc", "/var/log"}, ExcludePaths: []string{"/proc", "/sys"}},
		Asset:   AssetPolicy{IntervalSeconds: 60, Processes: true, Performance: true},
		Retention: RetentionPolicy{EvidenceEnabled: true, MaxFileMB: 128, RetainDays: 3},
		Streams: map[string]string{"raw": "flows:raw", "semantic": "flows:semantic", "runtime": "alerts:runtime", "rasp": "alerts:rasp"},
	}
}

func DriftDetected(policy Policy, lastAppliedVersion int) bool {
	return policy.Version > 0 && lastAppliedVersion > 0 && policy.Version != lastAppliedVersion
}
