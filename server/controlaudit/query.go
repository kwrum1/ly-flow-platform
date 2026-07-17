package controlaudit

import (
	"context"
	"fmt"
)

func (l *Ledger) Query(ctx context.Context, role QueryRole) ([]Entry, error) {
	switch role {
	case QueryAuditor, QueryAdmin:
	case QueryViewer:
		return nil, ErrQueryForbidden
	default:
		return nil, ErrQueryForbidden
	}
	if err := l.Verify(ctx); err != nil {
		return nil, err
	}
	anchors, err := l.loadAnchors()
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0)
	for _, item := range anchors {
		batch, err := l.readBatch(item.BatchID)
		if err != nil {
			return nil, fmt.Errorf("query audit batch: %w", err)
		}
		for _, record := range batch.Records {
			entries = append(entries, Entry{Actor: record.Actor, Action: record.Action, Resource: record.Resource, Result: record.Result, Fields: record.Fields})
		}
	}
	return entries, nil
}
