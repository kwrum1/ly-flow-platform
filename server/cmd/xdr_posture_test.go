package main

import (
	"testing"

	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

func TestXDRPostureIgnoresRejectedAndBoundsVolumeAdjustment(t *testing.T) {
	chains := make(activeXDRChains, 0, 31)
	for i := 0; i < 30; i++ {
		chains = append(chains, activeXDRRow{Score: 64, HypothesisStatus: models.HypothesisStatusCandidate})
	}
	chains = append(chains, activeXDRRow{Score: 100, HypothesisStatus: models.HypothesisStatusRejected})
	posture := xdrPostureFromChains(chains)
	if posture["active_chains"] != 30 || posture["risk_score"].(int64) >= 100 {
		t.Fatalf("posture=%#v", posture)
	}
	empty := xdrPostureFromChains(activeXDRChains{{Score: 100, HypothesisStatus: models.HypothesisStatusRejected}})
	if empty["active_chains"] != 0 || empty["risk_score"].(int64) != 0 {
		t.Fatalf("rejected posture=%#v", empty)
	}
}
