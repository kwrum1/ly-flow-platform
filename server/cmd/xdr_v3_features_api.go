package main

import "github.com/lyflow/ly-flow-platform/server/xdr/models"

type shadowXDRRow struct {
	activeXDRRow
	ScoringInput *models.ShadowScoringDetail `json:"scoring_input"`
}

func shadowXDRRows(events []*models.CanonicalEventV2, hypotheses []*models.ChainHypothesisV2, limit int) shadowXDRChains {
	return shadowXDRRowsWithDetail(events, hypotheses, limit, nil)
}

func shadowXDRRowsWithDetail(events []*models.CanonicalEventV2, hypotheses []*models.ChainHypothesisV2, limit int, detail *models.ShadowScoringDetail) shadowXDRChains {
	if len(events) < 2 {
		return shadowEventOnlyChains(events, detail)
	}
	if limit <= 0 || limit > len(hypotheses) {
		limit = len(hypotheses)
	}
	out := make(shadowXDRChains, 0, limit)
	for _, row := range buildActiveRows(events, hypotheses, models.AlgorithmV3Shadow, limit) {
		out = append(out, shadowXDRRow{activeXDRRow: row, ScoringInput: detail})
	}
	return out
}

func shadowEventOnlyChains(events []*models.CanonicalEventV2, detail *models.ShadowScoringDetail) shadowXDRChains {
	active := activeEventOnlyChains(events, models.AlgorithmV3Shadow)
	out := make(shadowXDRChains, 0, len(active))
	for _, row := range active {
		out = append(out, shadowXDRRow{activeXDRRow: row, ScoringInput: detail})
	}
	return out
}

func (row shadowXDRRow) jsonRow() map[string]interface{} {
	out := row.activeXDRRow.jsonRow()
	out["scoring_input"] = row.ScoringInput
	return out
}

func (rows shadowXDRChains) jsonRows() []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.jsonRow())
	}
	return out
}
