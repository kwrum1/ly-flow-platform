package models

import (
	"errors"
	"fmt"
)

var (
	ErrUnknownAlgorithm     = errors.New("unknown XDR algorithm")
	ErrInvalidGraphSnapshot = errors.New("invalid versioned graph snapshot")
)

type AlgorithmIdentity interface {
	fmt.Stringer
	IncidentEligible() bool
	algorithmIdentity()
}

type ActiveAlgorithmIdentity struct{}

func (ActiveAlgorithmIdentity) String() string         { return "v2-active" }
func (ActiveAlgorithmIdentity) IncidentEligible() bool { return true }
func (ActiveAlgorithmIdentity) algorithmIdentity()     {}

type ShadowAlgorithmIdentity struct{}

func (ShadowAlgorithmIdentity) String() string         { return "v3-shadow" }
func (ShadowAlgorithmIdentity) IncidentEligible() bool { return false }
func (ShadowAlgorithmIdentity) algorithmIdentity()     {}

var (
	AlgorithmV2Active ActiveAlgorithmIdentity
	AlgorithmV3Shadow ShadowAlgorithmIdentity
)

func ParseAlgorithmIdentity(raw string) (AlgorithmIdentity, error) {
	switch raw {
	case AlgorithmV2Active.String():
		return AlgorithmV2Active, nil
	case AlgorithmV3Shadow.String():
		return AlgorithmV3Shadow, nil
	default:
		return nil, fmt.Errorf("%q: %w", raw, ErrUnknownAlgorithm)
	}
}

type VersionedGraphSnapshot struct {
	TenantID       string
	Algorithm      AlgorithmIdentity
	InputChecksum  string
	GraphChecksum  string
	Nodes          []*GraphNodeV2
	Edges          []*GraphEdgeV2
	Hypotheses     []*ChainHypothesisV2
	ScoringDetails []ShadowScoringDetail
}

func (snapshot VersionedGraphSnapshot) Validate() error {
	if snapshot.TenantID == "" || snapshot.Algorithm == nil || snapshot.InputChecksum == "" || snapshot.GraphChecksum == "" {
		return ErrInvalidGraphSnapshot
	}
	for _, node := range snapshot.Nodes {
		if node == nil || node.TenantID != snapshot.TenantID {
			return ErrInvalidGraphSnapshot
		}
	}
	for _, edge := range snapshot.Edges {
		if edge == nil || edge.TenantID != snapshot.TenantID {
			return ErrInvalidGraphSnapshot
		}
	}
	for _, hypothesis := range snapshot.Hypotheses {
		if hypothesis == nil || hypothesis.TenantID != snapshot.TenantID {
			return ErrInvalidGraphSnapshot
		}
	}
	for _, detail := range snapshot.ScoringDetails {
		if snapshot.Algorithm.IncidentEligible() || detail.TenantID != snapshot.TenantID || detail.AlgorithmVersion != AlgorithmV3Shadow.String() || detail.InputChecksum != snapshot.InputChecksum || detail.DetailUID == "" || detail.DetailChecksum == "" {
			return ErrInvalidGraphSnapshot
		}
	}
	return nil
}
