package response

import (
	"path/filepath"
	"testing"
	"time"
)

func TestActionManagerApproveDispatchRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "actions.json")
	manager, err := NewActionManager(path, Policy{RequireDifferentApprover: true, ApprovalTTL: time.Minute})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	record, err := manager.Create(ActionRequest{
		AgentID: "agent-1", Action: ActionBlockIP, Target: "203.0.113.77",
		Reason: "test", RequestedBy: "user:1",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if record.Status != "pending_approval" || record.Risk != RiskL2 {
		t.Fatalf("unexpected record: %+v", record)
	}
	if _, err := manager.Approve(record.ID, "user:1"); err == nil {
		t.Fatal("same requester approval was accepted")
	}
	approved, err := manager.Approve(record.ID, "user:2")
	if err != nil || approved.Status != "approved" {
		t.Fatalf("approve: %+v %v", approved, err)
	}
	tasks, err := manager.PendingTasks("agent-1")
	if err != nil || len(tasks) != 1 || tasks[0].Action != ActionBlockIP {
		t.Fatalf("pending tasks: %+v %v", tasks, err)
	}
	if err := manager.Complete(record.ID, "ok", map[string]interface{}{"backend": "nft"}, ""); err != nil {
		t.Fatalf("complete: %v", err)
	}
	rollback, err := manager.Rollback(record.ID, "user:2")
	if err != nil || rollback.Action != ActionUnblockIP || rollback.Status != "approved" {
		t.Fatalf("rollback: %+v %v", rollback, err)
	}
}

func TestActionManagerAutoApprovesL2InsideWindow(t *testing.T) {
	manager, err := NewActionManager(filepath.Join(t.TempDir(), "actions.json"), Policy{
		AllowScheduledAuto: true, WindowStartHour: 0, WindowEndHour: 23, ApprovalTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	record, err := manager.Create(ActionRequest{AgentID: "agent-1", Action: ActionBlockIP, Target: "203.0.113.77", RequestedBy: "user:1"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if record.Status != "approved" || !record.AutoApproved {
		t.Fatalf("auto approval did not apply: %+v", record)
	}
	tasks, err := manager.PendingTasks("agent-1")
	if err != nil || len(tasks) != 1 {
		t.Fatalf("auto task dispatch: %+v %v", tasks, err)
	}
}

func TestActionManagerReversibleActionRollbackMapping(t *testing.T) {
	manager, err := NewActionManager(filepath.Join(t.TempDir(), "actions.json"), Policy{RequireDifferentApprover: true})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	tests := []struct {
		action   ActionKind
		rollback ActionKind
		target   string
	}{
		{ActionBlockIP, ActionUnblockIP, "203.0.113.77"},
		{ActionFileDelete, ActionFileRestore, "/tmp/lyflow-response/sample.txt"},
		{ActionAccountDisable, ActionAccountEnable, "lyflow-response-test"},
		{ActionIsolateHost, ActionHostUnisolate, "host-1"},
		{ActionNamespaceIsolate, ActionNamespaceRestore, "container-1"},
	}
	for _, test := range tests {
		record, err := manager.Create(ActionRequest{AgentID: "agent-1", Action: test.action, Target: test.target, RequestedBy: "user:1"})
		if err != nil {
			t.Fatalf("create %s: %v", test.action, err)
		}
		if _, err := manager.Approve(record.ID, "user:2"); err != nil {
			t.Fatalf("approve %s: %v", test.action, err)
		}
		rollback, err := manager.Rollback(record.ID, "user:2")
		if err != nil || rollback.Action != test.rollback {
			t.Fatalf("rollback %s = %+v, %v", test.action, rollback, err)
		}
	}
	if _, err := manager.Create(ActionRequest{AgentID: "agent-1", Action: ActionProcessKill, Target: "424242", RequestedBy: "user:1"}); err != nil {
		t.Fatalf("create process kill: %v", err)
	}
}

func TestActionManagerPersistsAutomationPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "actions.json")
	manager, err := NewActionManager(path, Policy{})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	updated, err := manager.UpdateAutomation(AutomationPolicy{
		Enabled: true, WindowStartHour: 0, WindowEndHour: 23,
		RequireDifferentApprover: true, ApprovalTTLMinutes: 15,
	})
	if err != nil || !updated.Enabled {
		t.Fatalf("update automation = %+v, %v", updated, err)
	}
	reloaded, err := NewActionManager(path, Policy{})
	if err != nil {
		t.Fatalf("reload manager: %v", err)
	}
	if !reloaded.Automation().Enabled || !reloaded.AutomationActive(time.Date(2026, 10, 20, 12, 0, 0, 0, time.FixedZone("Asia/Shanghai", 8*60*60))) {
		t.Fatalf("persisted automation not active: %+v", reloaded.Automation())
	}
}
