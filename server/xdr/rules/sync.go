package rules

import "fmt"

type SyncSource struct {
	Name string `json:"name"`
	Label string `json:"label"`
	Updatable bool `json:"updatable"`
	Static bool `json:"static"`
	License string `json:"license"`
	Activation string `json:"activation"`
}

type SyncResult struct {
	Source string `json:"source"`
	DryRun bool `json:"dry_run"`
	Added int `json:"added"`
	Changed int `json:"changed"`
	Unchanged int `json:"unchanged"`
	Failed int `json:"failed"`
	Message string `json:"message"`
	RequiresApproval bool `json:"requires_approval"`
}

type LifecycleState struct {
	RuleID string `json:"rule_id"`
	Version int `json:"version"`
	Enabled bool `json:"enabled"`
	HitCount int64 `json:"hit_count"`
	Source string `json:"source"`
	Audit []string `json:"audit"`
}

func DefaultSyncSources() []SyncSource {
	return []SyncSource{
		{Name: "wazuh", Label: "Wazuh XDR", Updatable: true, License: "GPLv2", Activation: "operator_approval"},
		{Name: "suricata", Label: "ET Open / Suricata", Updatable: true, License: "ET Open", Activation: "operator_approval"},
		{Name: "sigma", Label: "Sigma", Updatable: true, License: "source_metadata", Activation: "operator_approval"},
		{Name: "hids", Label: "HIDS", Updatable: true, License: "internal", Activation: "operator_approval"},
		{Name: "rasp", Label: "RASP", Updatable: false, Static: true, License: "internal", Activation: "manual"},
	}
}

func DryRunSync(source string) (SyncResult, error) {
	if source == "rasp" {
		return SyncResult{}, fmt.Errorf("RASP rules are static and cannot be synced")
	}
	if source == "" {
		return SyncResult{}, fmt.Errorf("source is required")
	}
	return SyncResult{Source: source, DryRun: true, Added: 0, Changed: 0, Unchanged: 0, Failed: 0, Message: "dry-run completed", RequiresApproval: true}, nil
}

func EnableRule(state LifecycleState, actor string) LifecycleState {
	state.Enabled = true
	state.Audit = append(state.Audit, fmt.Sprintf("%s enabled v%d", actor, state.Version))
	return state
}

func RollbackRule(state LifecycleState, targetVersion int, actor string) (LifecycleState, error) {
	if targetVersion <= 0 || targetVersion >= state.Version {
		return state, fmt.Errorf("invalid rollback target")
	}
	state.Version = targetVersion
	state.Enabled = false
	state.Audit = append(state.Audit, fmt.Sprintf("%s rolled back to v%d", actor, targetVersion))
	return state, nil
}
