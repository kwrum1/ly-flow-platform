package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lyflow/ly-flow-platform/contracts"
	"github.com/lyflow/ly-flow-platform/server/xdr/features"
	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

type activeXDRResult struct {
	chains   activeXDRChains
	checksum string
}

type shadowXDRResult struct {
	chains       shadowXDRChains
	checksum     string
	scoringInput *models.ShadowScoringDetail
}

type activeXDRChains []activeXDRRow
type shadowXDRChains []shadowXDRRow

type xdrRunResult struct {
	active       activeXDRChains
	shadow       shadowXDRChains
	scoringInput *models.ShadowScoringDetail
}

type xdrIncidentInput interface{ incidentChains() activeXDRChains }
type xdrSuppressionInput interface{ suppressionChains() activeXDRChains }
type xdrResponseCandidateInput interface{ responseCandidateChains() activeXDRChains }
type xdrActiveRouteResult interface {
	xdrIncidentInput
	xdrSuppressionInput
	xdrResponseCandidateInput
	activeChains() activeXDRChains
}
type xdrShadowRouteResult interface{ shadowChains() shadowXDRChains }

func (result activeXDRResult) activeChains() activeXDRChains            { return result.chains }
func (result activeXDRResult) incidentChains() activeXDRChains          { return result.chains }
func (result activeXDRResult) suppressionChains() activeXDRChains       { return result.chains }
func (result activeXDRResult) responseCandidateChains() activeXDRChains { return result.chains }
func (result shadowXDRResult) shadowChains() shadowXDRChains            { return result.chains }

type xdrGraphRuntime struct {
	pool    *pgxpool.Pool
	adapter *xdrCanonicalAdapter
	health  *xdrHealthTracker
	mu      sync.Mutex
}

func newXDRGraphRuntime(ctx context.Context, pool *pgxpool.Pool, adapter *xdrCanonicalAdapter) (*xdrGraphRuntime, error) {
	if pool == nil || adapter == nil {
		return nil, fmt.Errorf("XDR graph runtime requires Postgres and canonical adapter")
	}
	if err := ensureXDRMigrationSchema(ctx, pool); err != nil {
		return nil, err
	}
	health := newXDRHealthTracker()
	if err := restoreXDRCheckpointHealth(ctx, pool, health); err != nil {
		return nil, err
	}
	return &xdrGraphRuntime{pool: pool, adapter: adapter, health: health}, nil
}

func (runtime *xdrGraphRuntime) RunActive(ctx context.Context, events []contracts.CanonicalSecurityEvent, limit int) (activeXDRResult, error) {
	rows, checksum, err := runtime.run(ctx, models.AlgorithmV2Active, events, limit)
	if err != nil {
		return activeXDRResult{}, err
	}
	return activeXDRResult{chains: rows.active, checksum: checksum}, nil
}

func (runtime *xdrGraphRuntime) RunShadow(ctx context.Context, events []contracts.CanonicalSecurityEvent) (shadowXDRResult, error) {
	rows, checksum, err := runtime.run(ctx, models.AlgorithmV3Shadow, events, len(events))
	if err != nil {
		return shadowXDRResult{}, err
	}
	return shadowXDRResult{chains: rows.shadow, checksum: checksum, scoringInput: rows.scoringInput}, nil
}

func (runtime *xdrGraphRuntime) run(ctx context.Context, identity models.AlgorithmIdentity, events []contracts.CanonicalSecurityEvent, limit int) (xdrRunResult, string, error) {
	if identity == nil {
		return xdrRunResult{}, "", models.ErrUnknownAlgorithm
	}
	switch identity.(type) {
	case models.ActiveAlgorithmIdentity, models.ShadowAlgorithmIdentity:
	default:
		return xdrRunResult{}, "", fmt.Errorf("%T: %w", identity, models.ErrUnknownAlgorithm)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	canonicals, err := canonicalEventsToGraph(events)
	if err != nil {
		return xdrRunResult{}, "", err
	}
	nodes, edges := buildGraphEdges(ctx, canonicals, &Config{XDRV2MaxDepth: 6, XDRV2MaxPathsPerSeed: 50, XDRV2WindowHours: 24})
	hypotheses := boundedPathSearch(canonicals, edges, &Config{XDRV2MaxDepth: 6, XDRV2MaxPathsPerSeed: 50, XDRV2WindowHours: 24})
	checksum := checksumXDRGraph(nodes, edges, hypotheses)
	checkpoint := checksumCanonicalXDRInput(events)
	var scoringDetails []models.ShadowScoringDetail
	var scoringInput *models.ShadowScoringDetail
	switch identity.(type) {
	case models.ActiveAlgorithmIdentity:
	case models.ShadowAlgorithmIdentity:
		detail, err := features.Compute(features.Input{Events: events, GraphEvents: canonicals, Edges: edges, InputChecksum: checkpoint})
		if err != nil {
			return xdrRunResult{}, "", fmt.Errorf("compute shadow scoring input: %w", err)
		}
		scoringDetails = []models.ShadowScoringDetail{detail}
		scoringInput = &scoringDetails[0]
	default:
		return xdrRunResult{}, "", fmt.Errorf("%T: %w", identity, models.ErrUnknownAlgorithm)
	}
	snapshot := models.VersionedGraphSnapshot{
		TenantID: "default", Algorithm: identity, InputChecksum: checkpoint, GraphChecksum: checksum,
		Nodes: nodes, Edges: edges, Hypotheses: hypotheses, ScoringDetails: scoringDetails,
	}
	if err := persistVersionedXDRGraph(ctx, runtime.pool, snapshot); err != nil {
		runtime.health.failure(identity, err)
		return xdrRunResult{}, "", fmt.Errorf("persist %s graph: %w", identity, err)
	}
	runtime.health.success(identity, checkpoint, checksum)
	if identity.IncidentEligible() {
		return xdrRunResult{active: activeXDRRows(canonicals, hypotheses, limit)}, checksum, nil
	}
	return xdrRunResult{shadow: shadowXDRRowsWithDetail(canonicals, hypotheses, limit, scoringInput), scoringInput: scoringInput}, checksum, nil
}

func (runtime *xdrGraphRuntime) IngestRaw(ctx context.Context, identity models.AlgorithmIdentity, records [][]byte) error {
	events, err := runtime.decodeRaw(ctx, identity, records)
	if err != nil {
		return err
	}
	switch identity.(type) {
	case models.ActiveAlgorithmIdentity:
		_, err := runtime.RunActive(ctx, events, len(events))
		return err
	case models.ShadowAlgorithmIdentity:
		_, err := runtime.RunShadow(ctx, events)
		return err
	default:
		return fmt.Errorf("%T: %w", identity, models.ErrUnknownAlgorithm)
	}
}

func (runtime *xdrGraphRuntime) decodeRaw(ctx context.Context, identity models.AlgorithmIdentity, records [][]byte) ([]contracts.CanonicalSecurityEvent, error) {
	events := make([]contracts.CanonicalSecurityEvent, 0, len(records))
	var firstQuarantined error
	for _, record := range records {
		event, err := runtime.adapter.Decode(record)
		if err != nil {
			if persistErr := persistXDRQuarantine(ctx, runtime.pool, identity, record, err); persistErr != nil {
				runtime.health.failure(identity, persistErr)
				return nil, errorsJoinXDR(err, persistErr)
			}
			if firstQuarantined == nil {
				firstQuarantined = err
			}
			continue
		}
		events = append(events, event)
	}
	if len(records) > 0 && len(events) == 0 && firstQuarantined != nil {
		return nil, fmt.Errorf("all canonical XDR inputs quarantined: %w", firstQuarantined)
	}
	return events, nil
}

func (runtime *xdrGraphRuntime) Health() xdrRuntimeHealth {
	return runtime.health.snapshot(runtime.adapter.Health())
}

func canonicalEventsToGraph(events []contracts.CanonicalSecurityEvent) ([]*models.CanonicalEventV2, error) {
	sorted := append([]contracts.CanonicalSecurityEvent(nil), events...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Timestamps.ObservedAt.Equal(sorted[j].Timestamps.ObservedAt) {
			return sorted[i].EventUID < sorted[j].EventUID
		}
		return sorted[i].Timestamps.ObservedAt.Before(sorted[j].Timestamps.ObservedAt)
	})
	out := make([]*models.CanonicalEventV2, 0, len(sorted))
	for _, event := range sorted {
		if err := event.Validate(); err != nil {
			return nil, fmt.Errorf("validate canonical XDR event %s: %w", event.EventUID, err)
		}
		var payload map[string]interface{}
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			return nil, fmt.Errorf("decode canonical XDR payload %s: %w", event.EventUID, err)
		}
		if canonicalXDRInformational(event, payload) {
			continue
		}
		severity := strings.ToLower(string(event.Severity))
		stage := firstNonEmpty(normalizeXDRStage(xdrPickString(payload, "stage_hint")), inferXDRStage(payload))
		technique, tactic, mappedStage := inferCanonicalAttackMapping(event, payload)
		if mappedStage != "" {
			stage = mappedStage
		}
		out = append(out, &models.CanonicalEventV2{
			TenantID: "default", EventUID: event.EventUID, SourceComponent: canonicalXDRCategory(event.Provenance.Source),
			AgentID: event.Identity.AgentID, HostID: xdrPickString(payload, "host_id"), ObservedAt: event.Timestamps.ObservedAt,
			IngestedAt: event.Timestamps.IngestedAt, EventType: event.EventType, RawEvent: event.Payload,
			NormalizedSrcIP: xdrPickString(payload, "src_ip", "source_ip"), NormalizedDstIP: xdrPickString(payload, "dst_ip", "target_ip"),
			ActorIdentity: firstNonEmpty(xdrPickString(payload, "user", "details.user", "entities.user")), VictimAsset: firstNonEmpty(xdrPickString(payload, "hostname", "victim_asset", "entities.hostname"), event.Identity.PrincipalID),
			TechniqueID: technique, TacticID: tactic, StageHint: stage,
			StageConfidence: 1, RiskScore: float64(severityBaseScore(severity)), ConfidenceScore: 100,
			EvaluationVersion: models.EvalVersionV2, AttackMappingVersion: event.Attack.Version, CreatedAt: event.Timestamps.EventAt,
		})
	}
	return out, nil
}

func canonicalXDRCategory(source contracts.EventSource) string {
	switch source {
	case contracts.SourceAgentTraffic, contracts.SourceSuricata, contracts.SourceDPIEngine:
		return "traffic"
	case contracts.SourceAgentRASP:
		return "rasp"
	case contracts.SourceAgentLogAudit, contracts.SourceWazuh:
		return "log_audit"
	default:
		return "runtime"
	}
}

func deterministicXDRGraphChecksum(events []contracts.CanonicalSecurityEvent) string {
	canonicals, err := canonicalEventsToGraph(events)
	if err != nil {
		return ""
	}
	nodes, edges := buildGraphEdges(context.Background(), canonicals, &Config{})
	hypotheses := boundedPathSearch(canonicals, edges, &Config{})
	return checksumXDRGraph(nodes, edges, hypotheses)
}

func checksumCanonicalXDRInput(events []contracts.CanonicalSecurityEvent) string {
	identities := make([]string, 0, len(events))
	for _, event := range events {
		identities = append(identities, event.EventUID+"\x00"+event.Provenance.PayloadSHA256)
	}
	sort.Strings(identities)
	digest := sha256.Sum256([]byte(strings.Join(identities, "\n")))
	return hex.EncodeToString(digest[:])
}
