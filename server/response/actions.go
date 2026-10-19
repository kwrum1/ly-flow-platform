package response

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ActionKind is an executable response action.
type ActionKind string

const (
	ActionObserve          ActionKind = "observe"
	ActionBlockIP          ActionKind = "block_ip"
	ActionUnblockIP        ActionKind = "unblock_ip"
	ActionIsolateHost      ActionKind = "isolate_host"
	ActionHostUnisolate    ActionKind = "host_unisolate"
	ActionProcessKill      ActionKind = "process_kill"
	ActionFileDelete       ActionKind = "file_delete"
	ActionFileRestore      ActionKind = "file_restore"
	ActionAccountDisable   ActionKind = "account_disable"
	ActionAccountEnable    ActionKind = "account_enable"
	ActionNamespaceIsolate ActionKind = "namespace_isolate"
	ActionNamespaceRestore ActionKind = "namespace_restore"
)

type ActionRequest struct {
	IncidentID  string     `json:"incident_id"`
	AgentID     string     `json:"agent_id"`
	Action      ActionKind `json:"action"`
	Target      string     `json:"target"`
	Reason      string     `json:"reason"`
	RequestedBy string     `json:"requested_by"`
	TTLSeconds  int        `json:"ttl_seconds"`
}

type ActionRecord struct {
	ID           string                 `json:"id"`
	IncidentID   string                 `json:"incident_id,omitempty"`
	AgentID      string                 `json:"agent_id"`
	Action       ActionKind             `json:"action"`
	Target       string                 `json:"target"`
	Reason       string                 `json:"reason"`
	RequestedBy  string                 `json:"requested_by"`
	Risk         Risk                   `json:"risk"`
	Status       string                 `json:"status"`
	AutoApproved bool                   `json:"auto_approved"`
	CreatedAt    time.Time              `json:"created_at"`
	ExpiresAt    time.Time              `json:"expires_at"`
	ApprovedBy   string                 `json:"approved_by,omitempty"`
	ApprovedAt   *time.Time             `json:"approved_at,omitempty"`
	DispatchedAt *time.Time             `json:"dispatched_at,omitempty"`
	CompletedAt  *time.Time             `json:"completed_at,omitempty"`
	Result       map[string]interface{} `json:"result,omitempty"`
	Error        string                 `json:"error,omitempty"`
	RollbackOf   string                 `json:"rollback_of,omitempty"`
}

type ActionTask struct {
	TaskID     string                 `json:"task_id"`
	Action     ActionKind             `json:"action"`
	Target     string                 `json:"target"`
	IncidentID string                 `json:"incident_id,omitempty"`
	ResponseID string                 `json:"response_action_id"`
	TTLSeconds int                    `json:"ttl_seconds"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

type ActionManager struct {
	mu     sync.Mutex
	engine *Engine
	path   string
	now    func() time.Time
}

func NewActionManager(path string, policy Policy) (*ActionManager, error) {
	actions := []Action{
		{ID: string(ActionObserve), Name: "observe", Risk: RiskL1, Reversible: true},
		{ID: string(ActionBlockIP), Name: "block source IP", Risk: RiskL2, Reversible: true},
		{ID: string(ActionUnblockIP), Name: "unblock source IP", Risk: RiskL1, Reversible: true},
		{ID: string(ActionIsolateHost), Name: "isolate host", Risk: RiskL3, Reversible: true},
		{ID: string(ActionHostUnisolate), Name: "unisolate host", Risk: RiskL1, Reversible: true},
		{ID: string(ActionProcessKill), Name: "kill process", Risk: RiskL3, Reversible: false},
		{ID: string(ActionFileDelete), Name: "quarantine file", Risk: RiskL3, Reversible: true},
		{ID: string(ActionFileRestore), Name: "restore quarantined file", Risk: RiskL1, Reversible: true},
		{ID: string(ActionAccountDisable), Name: "expire account", Risk: RiskL3, Reversible: true},
		{ID: string(ActionAccountEnable), Name: "restore account", Risk: RiskL1, Reversible: true},
		{ID: string(ActionNamespaceIsolate), Name: "isolate container network", Risk: RiskL3, Reversible: true},
		{ID: string(ActionNamespaceRestore), Name: "restore container network", Risk: RiskL1, Reversible: true},
	}
	engine, err := New(policy, actions...)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(path) == "" {
		path = "/var/lib/lyflow/response/actions.json"
	}
	return &ActionManager{engine: engine, path: path, now: time.Now}, nil
}

func (manager *ActionManager) List() ([]ActionRecord, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	records, err := manager.load()
	if err != nil {
		return nil, err
	}
	return records, nil
}

func (manager *ActionManager) Create(request ActionRequest) (ActionRecord, error) {
	request.Target = strings.TrimSpace(request.Target)
	request.AgentID = strings.TrimSpace(request.AgentID)
	request.RequestedBy = strings.TrimSpace(request.RequestedBy)
	if request.Target == "" || request.AgentID == "" || request.RequestedBy == "" {
		return ActionRecord{}, ErrInvalidRequest
	}
	now := manager.now().UTC()
	policyRequest := Request{
		ID:          newActionID(now),
		ActionID:    string(request.Action),
		Target:      request.Target,
		RequestedBy: request.RequestedBy,
		Reason:      request.Reason,
		CreatedAt:   now,
	}
	decision, err := manager.engine.Evaluate(policyRequest, now)
	if err != nil {
		return ActionRecord{}, err
	}
	ttl := request.TTLSeconds
	if ttl <= 0 {
		ttl = 300
	}
	record := ActionRecord{
		ID:           policyRequest.ID,
		IncidentID:   strings.TrimSpace(request.IncidentID),
		AgentID:      request.AgentID,
		Action:       request.Action,
		Target:       request.Target,
		Reason:       strings.TrimSpace(request.Reason),
		RequestedBy:  request.RequestedBy,
		Risk:         decision.Risk,
		Status:       "pending_approval",
		AutoApproved: decision.AutoApproved,
		CreatedAt:    now,
		ExpiresAt:    now.Add(time.Duration(ttl) * time.Second),
	}
	if decision.AutoApproved {
		record.Status = "approved"
	}
	manager.mu.Lock()
	records, err := manager.load()
	if err != nil {
		manager.mu.Unlock()
		return ActionRecord{}, err
	}
	records = append(records, record)
	if err := manager.save(records); err != nil {
		manager.mu.Unlock()
		return ActionRecord{}, err
	}
	manager.mu.Unlock()
	return record, nil
}

func (manager *ActionManager) Approve(id, approver string) (ActionRecord, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	records, err := manager.load()
	if err != nil {
		return ActionRecord{}, err
	}
	for index := range records {
		record := &records[index]
		if record.ID != id {
			continue
		}
		if record.Status != "pending_approval" {
			return ActionRecord{}, fmt.Errorf("response action %s is not pending approval", id)
		}
		request := Request{ID: record.ID, ActionID: string(record.Action), Target: record.Target, RequestedBy: record.RequestedBy}
		if err := manager.engine.Approve(request, approver); err != nil {
			return ActionRecord{}, err
		}
		now := manager.now().UTC()
		record.Status = "approved"
		record.ApprovedBy = strings.TrimSpace(approver)
		record.ApprovedAt = &now
		if err := manager.save(records); err != nil {
			return ActionRecord{}, err
		}
		return *record, nil
	}
	return ActionRecord{}, fmt.Errorf("response action %s not found", id)
}

func (manager *ActionManager) PendingTasks(agentID string) ([]ActionTask, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	records, err := manager.load()
	if err != nil {
		return nil, err
	}
	now := manager.now().UTC()
	tasks := make([]ActionTask, 0)
	for index := range records {
		record := &records[index]
		if record.AgentID != agentID || record.Status != "approved" {
			continue
		}
		if !record.ExpiresAt.After(now) {
			record.Status = "expired"
			record.Error = "action approval expired"
			continue
		}
		record.Status = "dispatched"
		record.DispatchedAt = &now
		tasks = append(tasks, ActionTask{
			TaskID:     record.ID,
			Action:     record.Action,
			Target:     record.Target,
			IncidentID: record.IncidentID,
			ResponseID: record.ID,
			TTLSeconds: int(record.ExpiresAt.Sub(now).Seconds()),
			Metadata: map[string]interface{}{
				"reason": record.Reason, "risk": record.Risk,
			},
		})
	}
	if len(tasks) > 0 {
		if err := manager.save(records); err != nil {
			return nil, err
		}
	}
	return tasks, nil
}

func (manager *ActionManager) Complete(taskID, status string, result map[string]interface{}, errorMessage string) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	records, err := manager.load()
	if err != nil {
		return err
	}
	for index := range records {
		record := &records[index]
		if record.ID != taskID {
			continue
		}
		now := manager.now().UTC()
		record.CompletedAt = &now
		record.Result = result
		record.Error = errorMessage
		if strings.EqualFold(status, "ok") || strings.EqualFold(status, "success") {
			record.Status = "executed"
		} else {
			record.Status = "failed"
		}
		return manager.save(records)
	}
	return nil
}

func (manager *ActionManager) Rollback(id, requestedBy string) (ActionRecord, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	records, err := manager.load()
	if err != nil {
		return ActionRecord{}, err
	}
	for index := range records {
		record := records[index]
		if record.ID != id {
			continue
		}
		rollbackAction, ok := rollbackActionFor(record.Action)
		if !ok {
			return ActionRecord{}, fmt.Errorf("response action %s has no rollback adapter", id)
		}
		now := manager.now().UTC()
		rollback := ActionRecord{
			ID: newActionID(now), IncidentID: record.IncidentID, AgentID: record.AgentID,
			Action: rollbackAction, Target: record.Target, Reason: "rollback " + record.ID,
			RequestedBy: requestedBy, Risk: RiskL1, Status: "approved", AutoApproved: true,
			CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute), RollbackOf: record.ID,
		}
		records = append(records, rollback)
		record.Status = "rolled_back"
		records[index] = record
		if err := manager.save(records); err != nil {
			return ActionRecord{}, err
		}
		return rollback, nil
	}
	return ActionRecord{}, fmt.Errorf("response action %s not found", id)
}

func rollbackActionFor(action ActionKind) (ActionKind, bool) {
	switch action {
	case ActionBlockIP:
		return ActionUnblockIP, true
	case ActionFileDelete:
		return ActionFileRestore, true
	case ActionAccountDisable:
		return ActionAccountEnable, true
	case ActionIsolateHost:
		return ActionHostUnisolate, true
	case ActionNamespaceIsolate:
		return ActionNamespaceRestore, true
	default:
		return "", false
	}
}

func (manager *ActionManager) load() ([]ActionRecord, error) {
	data, err := os.ReadFile(manager.path)
	if errorsIsNotExist(err) {
		return []ActionRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	var records []ActionRecord
	if len(data) == 0 {
		return []ActionRecord{}, nil
	}
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("decode response actions: %w", err)
	}
	return records, nil
}

func (manager *ActionManager) save(records []ActionRecord) error {
	if err := os.MkdirAll(filepath.Dir(manager.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	tmp := manager.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, manager.path)
}

func newActionID(now time.Time) string {
	random := make([]byte, 4)
	_, _ = rand.Read(random)
	return fmt.Sprintf("ra-%d-%s", now.UnixNano(), hex.EncodeToString(random))
}

func errorsIsNotExist(err error) bool {
	return os.IsNotExist(err)
}
