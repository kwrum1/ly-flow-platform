package response

import (
	"errors"
	"testing"
	"time"
)

func actions() []Action {
	return []Action{
		{ID: "collect", Name: "collect evidence", Risk: RiskL1, Reversible: true},
		{ID: "isolate", Name: "isolate host", Risk: RiskL2, Reversible: true},
		{ID: "wipe", Name: "wipe host", Risk: RiskL3, Reversible: false},
	}
}

func TestL1AutoApproves(t *testing.T) {
	engine, err := New(Policy{}, actions()...)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	decision, err := engine.Evaluate(Request{ID: "r1", ActionID: "collect", Target: "host-1", RequestedBy: "alice"}, time.Now())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !decision.AutoApproved || decision.ApprovalRequired {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestL2RequiresApprovalOutsideWindow(t *testing.T) {
	engine, _ := New(Policy{AllowScheduledAuto: false}, actions()...)
	decision, err := engine.Evaluate(Request{ID: "r2", ActionID: "isolate", Target: "host-1", RequestedBy: "alice"}, time.Now())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !decision.ApprovalRequired || decision.AutoApproved {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestL2AutoInsideWindow(t *testing.T) {
	now := time.Date(2026, 10, 19, 2, 0, 0, 0, time.FixedZone("Asia/Shanghai", 8*60*60))
	engine, _ := New(Policy{AllowScheduledAuto: true, WindowStartHour: 1, WindowEndHour: 5}, actions()...)
	decision, err := engine.Evaluate(Request{ID: "r3", ActionID: "isolate", Target: "host-1", RequestedBy: "alice"}, now)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !decision.AutoApproved {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestL3AlwaysRequiresApproval(t *testing.T) {
	engine, _ := New(Policy{AllowScheduledAuto: true, WindowStartHour: 0, WindowEndHour: 23}, actions()...)
	decision, err := engine.Evaluate(Request{ID: "r4", ActionID: "wipe", Target: "host-1", RequestedBy: "alice"}, time.Now())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !decision.ApprovalRequired || decision.AutoApproved {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestFourEyes(t *testing.T) {
	engine, _ := New(Policy{RequireDifferentApprover: true}, actions()...)
	request := Request{ID: "r5", ActionID: "isolate", Target: "host-1", RequestedBy: "alice"}
	if err := engine.Approve(request, "alice"); !errors.Is(err, ErrFourEyes) {
		t.Fatalf("err = %v", err)
	}
	if err := engine.Approve(request, "bob"); err != nil {
		t.Fatalf("err = %v", err)
	}
}

func TestUnknownAction(t *testing.T) {
	engine, _ := New(Policy{}, actions()...)
	if _, err := engine.Evaluate(Request{ID: "r6", ActionID: "missing", Target: "host-1", RequestedBy: "alice"}, time.Now()); !errors.Is(err, ErrUnknownAction) {
		t.Fatalf("err = %v", err)
	}
}
