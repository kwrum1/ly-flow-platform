package models

import (
	"errors"
	"testing"
)

func TestParseAlgorithmIdentity_returns_known_identity(t *testing.T) {
	// Given
	tests := []struct {
		name string
		raw  string
		want AlgorithmIdentity
	}{
		{name: "active", raw: "v2-active", want: AlgorithmV2Active},
		{name: "shadow", raw: "v3-shadow", want: AlgorithmV3Shadow},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			// When
			got, err := ParseAlgorithmIdentity(testCase.raw)

			// Then
			if err != nil {
				t.Fatalf("parse identity: %v", err)
			}
			if got.String() != testCase.want.String() {
				t.Fatalf("identity=%q, want %q", got, testCase.want)
			}
		})
	}
}

func TestParseAlgorithmIdentity_rejects_unknown_identity(t *testing.T) {
	// Given
	raw := "v4-future"

	// When
	identity, err := ParseAlgorithmIdentity(raw)

	// Then
	if !errors.Is(err, ErrUnknownAlgorithm) {
		t.Fatalf("error=%v", err)
	}
	if identity != nil {
		t.Fatalf("identity=%q", identity)
	}
}

func TestAlgorithmIdentity_uses_distinct_active_and_shadow_types(t *testing.T) {
	// Given / When
	active := AlgorithmV2Active
	shadow := AlgorithmV3Shadow

	// Then
	if _, ok := any(active).(ActiveAlgorithmIdentity); !ok {
		t.Fatalf("active identity type=%T", active)
	}
	if _, ok := any(shadow).(ShadowAlgorithmIdentity); !ok {
		t.Fatalf("shadow identity type=%T", shadow)
	}
}

func TestVersionedGraphSnapshot_rejects_mixed_tenant_rows(t *testing.T) {
	// Given
	snapshot := VersionedGraphSnapshot{
		TenantID:      "tenant-a",
		Algorithm:     AlgorithmV2Active,
		InputChecksum: "input",
		GraphChecksum: "graph",
		Nodes:         []*GraphNodeV2{{TenantID: "tenant-b", NodeUID: "node-1"}},
	}

	// When
	err := snapshot.Validate()

	// Then
	if !errors.Is(err, ErrInvalidGraphSnapshot) {
		t.Fatalf("error=%v", err)
	}
}
