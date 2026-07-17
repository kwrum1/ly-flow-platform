package rulelifecycle

import (
	"context"
	"sync"

	"github.com/lyflow/ly-flow-platform/server/controlaudit"
)

type LedgerAudit struct {
	mu     sync.Mutex
	ledger *controlaudit.Ledger
}

func NewLedgerAudit(ledger *controlaudit.Ledger) *LedgerAudit {
	return &LedgerAudit{ledger: ledger}
}

func (a *LedgerAudit) Record(ctx context.Context, event AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	actor := event.Actor
	if actor == "" {
		actor = "anonymous"
	}
	_, err := a.ledger.Append(ctx, []controlaudit.Entry{{Actor: actor, Action: event.Action, Resource: event.Resource, Result: event.Result, Fields: event.Fields}})
	return err
}
