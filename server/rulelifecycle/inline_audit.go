package rulelifecycle

import (
	"context"
	"errors"
)

type inlineFailureAudit struct {
	resource string
	stage    string
	cause    error
}

func (m *Manager) inlineFailure(ctx context.Context, actor Actor, failure inlineFailureAudit) error {
	fields := map[string]interface{}{"stage": failure.stage, "error_code": inlineErrorCode(failure.cause)}
	if auditErr := m.record(ctx, actor, "rule.source.inline.outcome", failure.resource, AuditResultFailed, fields); auditErr != nil {
		return auditErr
	}
	return failure.cause
}

func inlineErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrDigestMismatch):
		return "digest_mismatch"
	case errors.Is(err, ErrSizeLimit):
		return "size_limit"
	case errors.Is(err, ErrRevision):
		return "revision_conflict"
	case errors.Is(err, ErrCompile):
		return "parse_failed"
	default:
		return "inline_failed"
	}
}
