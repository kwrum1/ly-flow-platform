package rasppolicy

import (
	"encoding/json"
	"time"
)

type Mode string

const (
	ModeOff     Mode = "off"
	ModeMonitor Mode = "monitor"
	ModeBlock   Mode = "block"
)

type FailBehavior string

const (
	FailMonitor FailBehavior = "monitor"
	FailDisable FailBehavior = "disable"
)

type Language string

const (
	LanguagePython Language = "python"
	LanguageJava   Language = "java"
)

type Selectors struct {
	AgentIDs  []string   `json:"agent_ids,omitempty"`
	Languages []Language `json:"languages,omitempty"`
}

type Limits struct {
	MaxEventsPerSecond         int     `json:"max_events_per_second"`
	MaxBlocksPerMinute         int     `json:"max_blocks_per_minute"`
	ReplayMinSamples           int     `json:"replay_min_samples"`
	ReplayMaxFalsePositiveRate float64 `json:"replay_max_false_positive_rate"`
}

type CanaryPolicy struct {
	RequiredACKs int `json:"required_acks"`
}

type RollbackPolicy struct {
	TargetVersion uint64    `json:"target_version"`
	Deadline      time.Time `json:"deadline"`
}

type Policy struct {
	ID           string         `json:"id"`
	Version      uint64         `json:"version"`
	Owner        string         `json:"owner"`
	Mode         Mode           `json:"mode"`
	Selectors    Selectors      `json:"selectors"`
	ExpiresAt    time.Time      `json:"expires_at"`
	FailBehavior FailBehavior   `json:"fail_behavior"`
	Limits       Limits         `json:"limits"`
	Canary       CanaryPolicy   `json:"canary"`
	Rollback     RollbackPolicy `json:"rollback"`
	AuditLink    string         `json:"audit_link"`
}

type SignedPolicy struct {
	Policy            Policy `json:"policy"`
	Signature         string `json:"signature"`
	SignerFingerprint string `json:"signer_fingerprint"`
}

type signedPayload struct {
	Policy            Policy `json:"policy"`
	SignerFingerprint string `json:"signer_fingerprint"`
}

func CanonicalBytes(policy Policy, signerFingerprint string) ([]byte, error) {
	return json.Marshal(signedPayload{Policy: policy, SignerFingerprint: signerFingerprint})
}
