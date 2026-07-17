package main

import (
	"fmt"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

func canonicalComponentAlertPayload(alert contracts.ComponentAlert, ingestedAt time.Time) (contracts.CanonicalSecurityEvent, []byte, error) {
	event, err := alert.Canonical(contracts.PrincipalIdentity(alert.Entities.AgentID), ingestedAt)
	if err != nil {
		return contracts.CanonicalSecurityEvent{}, nil, fmt.Errorf("canonicalize component alert: %w", err)
	}
	payload, err := contracts.MarshalCanonical(event)
	if err != nil {
		return contracts.CanonicalSecurityEvent{}, nil, fmt.Errorf("encode canonical component alert: %w", err)
	}
	return event, payload, nil
}
