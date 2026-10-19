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
