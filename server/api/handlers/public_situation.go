package handlers

import (
	"encoding/json"
	"net/http"
)

type PublicCountryAttack struct {
	SourceCountry string `json:"source_country"`
	TargetCountry string `json:"target_country"`
	SourceIP      string `json:"source_ip,omitempty"`
	TargetIP      string `json:"target_ip,omitempty"`
	Count         int    `json:"count"`
}

type PublicGlobalSituation struct {
	Attacks []PublicCountryAttack `json:"attacks"`
	Countries []string `json:"countries"`
	EmptyState *PublicEmptyState `json:"empty_state,omitempty"`
}

type PublicEmptyState struct {
	Reason string `json:"reason"`
	Message string `json:"message"`
}

func EmptyPublicGlobalSituation() PublicGlobalSituation {
	return PublicGlobalSituation{
		Attacks: []PublicCountryAttack{},
		Countries: []string{},
		EmptyState: &PublicEmptyState{
			Reason: "NO_ATTACK_EVENTS",
			Message: "暂无全球攻击态势数据",
		},
	}
}

func (h *Handler) PublicGlobalSituation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		ErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	json.NewEncoder(w).Encode(SuccessResponse(EmptyPublicGlobalSituation()))
}
