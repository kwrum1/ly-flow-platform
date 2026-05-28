package unified

import "time"

type ThreatIntelView string

const (
	ThreatIntelRASPApps ThreatIntelView = "rasp-apps"
	ThreatIntelRuntimeHosts ThreatIntelView = "runtime-hosts"
	ThreatIntelCombined ThreatIntelView = "combined"
)

type ThreatIntelItem struct {
	ID string `json:"id"`
	View ThreatIntelView `json:"view"`
	Source ModuleType `json:"source"`
	AssetID string `json:"asset_id,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Title string `json:"title"`
}

type ThreatIntelResponse struct {
	Items []ThreatIntelItem `json:"items"`
	Total int `json:"total"`
	EmptyState *ThreatIntelEmptyState `json:"empty_state,omitempty"`
}

type ThreatIntelEmptyState struct {
	Reason string `json:"reason"`
	Message string `json:"message"`
}

func EmptyThreatIntelResponse(view ThreatIntelView) ThreatIntelResponse {
	return ThreatIntelResponse{
		Items: []ThreatIntelItem{},
		Total: 0,
		EmptyState: &ThreatIntelEmptyState{Reason: "NO_THREAT_INTELLIGENCE", Message: "暂无威胁情报数据"},
	}
}

func MergeThreatIntel(raspItems, runtimeItems []ThreatIntelItem) []ThreatIntelItem {
	merged := make([]ThreatIntelItem, 0, len(raspItems)+len(runtimeItems))
	merged = append(merged, raspItems...)
	merged = append(merged, runtimeItems...)
	return merged
}
