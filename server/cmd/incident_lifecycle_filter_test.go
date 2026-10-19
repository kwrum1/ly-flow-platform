package main

import (
	"testing"

	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

func TestIncidentPathHasStrongEdge(t *testing.T) {
	cases := []struct {
		name string
		path *models.PathEvidence
		want bool
	}{
		{name: "nil path", path: nil, want: true},
		{name: "empty timeline", path: &models.PathEvidence{}, want: true},
		{
			name: "weak only",
			path: &models.PathEvidence{Timeline: []models.PathTimelineEntry{
				{EdgeType: models.EdgeTypeWeakSameIP},
				{EdgeType: models.EdgeTypeWeakSameIP},
			}},
			want: false,
		},
		{
			name: "verified transition",
			path: &models.PathEvidence{Timeline: []models.PathTimelineEntry{
				{EdgeType: models.EdgeTypeVerifiedAttackTransition},
			}},
			want: true,
		},
		{
			name: "weak plus verified",
			path: &models.PathEvidence{Timeline: []models.PathTimelineEntry{
				{EdgeType: models.EdgeTypeWeakSameIP},
				{EdgeType: models.EdgeTypeVerifiedAttackTransition},
			}},
			want: false,
		},
		{
			name: "same host",
			path: &models.PathEvidence{Timeline: []models.PathTimelineEntry{
				{EdgeType: models.EdgeTypeSameHost},
			}},
			want: true,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := incidentPathHasStrongEdge(testCase.path); got != testCase.want {
				t.Fatalf("got %v, want %v", got, testCase.want)
			}
		})
	}
}
