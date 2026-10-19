// Package bench provides deterministic synthetic EventV2 generation and query
// latency summarization for capacity tests.
package bench

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

type GeneratorConfig struct {
	Start        time.Time
	Days         int
	EPS          float64
	PayloadBytes int
	Seed         int64
}

type Generator struct {
	config        GeneratorConfig
	count         int
	payload       json.RawMessage
	payloadDigest string
}

func NewGenerator(config GeneratorConfig) *Generator {
	if config.Start.IsZero() {
		config.Start = time.Now().UTC().Add(-time.Duration(config.Days) * 24 * time.Hour)
	}
	if config.Days <= 0 {
		config.Days = 30
	}
	if config.EPS <= 0 {
		config.EPS = 5
	}
	count := int(float64(config.Days) * 86400 * config.EPS)
	generator := &Generator{config: config, count: count}
	if config.PayloadBytes > 0 {
		size := config.PayloadBytes
		if size < 16 {
			size = 16
		}
		generator.payload = json.RawMessage(`{"bench":"` + strings.Repeat("x", size-12) + `"}`)
		digest := sha256.Sum256(generator.payload)
		generator.payloadDigest = hex.EncodeToString(digest[:])
	} else {
		digest := sha256.Sum256(nil)
		generator.payloadDigest = hex.EncodeToString(digest[:])
	}
	return generator
}

func (g *Generator) Count() int {
	return g.count
}

func (g *Generator) Config() GeneratorConfig {
	return g.config
}

// Event returns a valid, deterministic event. The event time is spread evenly
// across the configured window at the requested EPS.
func (g *Generator) Event(index int) contracts.EventV2 {
	offset := time.Duration(float64(index) / g.config.EPS * float64(time.Second))
	at := g.config.Start.Add(offset)
	uid := fmt.Sprintf("bench-%012d-%08x", index, uint32(g.config.Seed))
	source := []contracts.EventSource{
		contracts.SourceDPIEngine,
		contracts.SourceSuricata,
		contracts.SourceAgentRuntime,
		contracts.SourceWazuh,
		contracts.SourceAgentRASP,
	}[index%5]
	eventType := []string{"flow", "alert", "process", "file", "dns", "http", "auth"}[index%7]
	severity := []contracts.AlertSeverity{
		contracts.SeverityLow, contracts.SeverityMedium, contracts.SeverityHigh, contracts.SeverityCritical,
	}[index%4]
	tactic := []string{"TA0001", "TA0002", "TA0008", "TA0011", "TA0043"}[index%5]
	stage := contracts.StageForTactic(tactic)
	assetID := fmt.Sprintf("asset-%04d", index%2000)
	userID := fmt.Sprintf("user-%03d", index%500)
	srcIP := fmt.Sprintf("10.%d.%d.%d", (index/65536)%250+1, (index/256)%250+1, index%250+1)
	dstIP := fmt.Sprintf("172.16.%d.%d", (index/256)%250+1, index%250+1)
	rawID := fmt.Sprintf("raw-%012d", index)
	event := contracts.EventV2{
		SchemaVersion: contracts.SecurityEventSchemaV2,
		EventUID:      uid,
		CorrelationID: fmt.Sprintf("corr-%06d", index/100),
		TenantID:      "bench",
		Source:        source,
		EventType:     eventType,
		Timestamps: contracts.EventTimestamps{
			EventAt: at, ObservedAt: at, IngestedAt: at,
		},
		Entities: contracts.Entities{
			Asset: &contracts.AssetEntity{ID: assetID, IP: srcIP, Hostname: assetID},
			User:  &contracts.UserEntity{ID: userID},
			Network: &contracts.NetworkEntity{
				SrcIP: srcIP, DstIP: dstIP, SrcPort: 1024 + index%50000,
				DstPort: []int{80, 443, 53, 22}[index%4], Proto: []string{"tcp", "udp"}[index%2],
			},
		},
		Detection: contracts.Detection{
			RuleID: fmt.Sprintf("rule-%04d", index%200), RuleSource: "bench",
			Severity: severity, Confidence: 0.5, TacticID: tactic,
			TechniqueID: "T1059", Stage: stage,
		},
		Evidence: []contracts.EvidenceRef{{
			Type: contracts.EvidenceFlow, Ref: fmt.Sprintf("flow-%012d", index),
		}},
		Payload: g.payload,
		Raw: contracts.RawRef{
			NativeSchema: "bench.v1", NativeEventID: rawID, Adapter: "eventbench",
			PayloadSHA256: g.payloadDigest,
		},
		QualityFlags: []contracts.QualityFlag{contracts.QualityNormalized},
		Governance: contracts.GovernanceMetadata{
			Classification: contracts.ClassificationInternal,
			Retention: contracts.RetentionPolicy{
				PolicyID: "bench-30d", ExpiresAt: at.Add(30 * 24 * time.Hour),
			},
			Encryption: contracts.EncryptionMetadata{
				Required: true, Algorithm: contracts.EncryptionAlgorithmAES256GCM, KeyRef: "bench",
			},
			AccessPolicyID: "bench-access", DeletionPolicyID: "bench-delete", ExportPolicyID: "bench-export",
		},
	}
	return event
}
